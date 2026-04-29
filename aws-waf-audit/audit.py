#!/usr/bin/env python3
"""AWS WAF read-only audit.

Inventories every WAFv2 Web ACL in an AWS account, the rules inside each ACL,
and the AWS resources each ACL is attached to (ALB, API Gateway, AppSync,
Cognito, App Runner, Verified Access, CloudFront). Optionally fetches per-rule
CloudWatch traffic counters for the last 24 hours.

Outputs:
  - JSON report (machine-readable, full detail)
  - Human-readable summary to stdout

Required IAM permissions (all read-only):
  - ec2:DescribeRegions
  - wafv2:ListWebACLs
  - wafv2:GetWebACL
  - wafv2:ListResourcesForWebACL
  - cloudfront:ListDistributions
  - cloudwatch:GetMetricStatistics            (only with --include-stats)

Usage:
  python audit.py
  python audit.py --profile my-profile --output waf.json
  python audit.py --regions us-east-1,eu-west-1 --include-stats
  python audit.py --include-stats --lookback-hours 168
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

CLOUDWATCH_NAMESPACE = "AWS/WAFV2"
CLOUDWATCH_PERIOD = 86400
DEFAULT_LOOKBACK_HOURS = 24

REGIONAL_RESOURCE_TYPES = [
    "APPLICATION_LOAD_BALANCER",
    "API_GATEWAY",
    "APPSYNC",
    "COGNITO_USER_POOL",
    "APP_RUNNER_SERVICE",
    "VERIFIED_ACCESS_INSTANCE",
]


@dataclass
class WafRule:
    name: str
    priority: int
    action: str
    rule_type: str
    metric_name: str
    statement: dict
    blocked: int | None = None
    allowed: int | None = None
    counted: int | None = None


@dataclass
class WafAcl:
    name: str
    id: str
    arn: str
    scope: str
    region: str
    rules: list[WafRule] = field(default_factory=list)
    associated_resources: list[str] = field(default_factory=list)
    total_blocked: int | None = None
    total_allowed: int | None = None


def parse_rule(raw: dict) -> WafRule:
    statement = raw.get("Statement", {}) or {}
    action_dict = raw.get("Action", {}) or {}
    override_action = raw.get("OverrideAction", {}) or {}
    visibility = raw.get("VisibilityConfig", {}) or {}

    if visibility.get("CloudWatchMetricsEnabled") and visibility.get("MetricName"):
        metric_name = visibility["MetricName"]
    else:
        metric_name = raw.get("Name", "")

    if "ManagedRuleGroupStatement" in statement or override_action:
        rule_type = "managed"
    elif "RateBasedStatement" in statement:
        rule_type = "rate_based"
    else:
        rule_type = "regular"

    if action_dict:
        action = next(iter(action_dict.keys()), "UNKNOWN").upper()
    elif override_action:
        action = next(iter(override_action.keys()), "NONE").upper()
    else:
        action = "NONE"

    return WafRule(
        name=raw.get("Name", ""),
        priority=raw.get("Priority", 0),
        action=action,
        rule_type=rule_type,
        metric_name=metric_name,
        statement=statement,
    )


def discover_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(
        Filters=[
            {"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}
        ]
    )
    return sorted(r["RegionName"] for r in response.get("Regions", []))


def list_web_acls(wafv2, scope: str) -> list[dict]:
    acls: list[dict] = []
    next_marker: str | None = None
    while True:
        kwargs = {"Scope": scope, "Limit": 100}
        if next_marker:
            kwargs["NextMarker"] = next_marker
        response = wafv2.list_web_acls(**kwargs)
        acls.extend(response.get("WebACLs", []))
        next_marker = response.get("NextMarker")
        if not next_marker:
            break
    return acls


def fetch_acl_rules(wafv2, name: str, acl_id: str, scope: str) -> list[WafRule]:
    response = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
    raw_rules = response.get("WebACL", {}).get("Rules", [])
    return [parse_rule(r) for r in raw_rules]


def list_regional_resources(wafv2, acl_arn: str) -> list[str]:
    resources: list[str] = []
    for resource_type in REGIONAL_RESOURCE_TYPES:
        try:
            response = wafv2.list_resources_for_web_acl(
                WebACLArn=acl_arn, ResourceType=resource_type
            )
            resources.extend(response.get("ResourceArns", []))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"WAFInvalidParameterException", "InvalidParameterValue"}:
                continue
            print(
                f"    warning: list_resources_for_web_acl failed "
                f"(type={resource_type}): {code or exc}",
                file=sys.stderr,
            )
    return resources


def list_cloudfront_associations(session: boto3.Session) -> dict[str, list[str]]:
    """Map CloudFront WebACL id -> list of distribution ARNs."""
    cf = session.client("cloudfront")
    paginator = cf.get_paginator("list_distributions")
    by_acl: dict[str, list[str]] = {}
    for page in paginator.paginate():
        items = page.get("DistributionList", {}).get("Items", []) or []
        for dist in items:
            web_acl_id = dist.get("WebACLId") or ""
            if not web_acl_id:
                continue
            by_acl.setdefault(web_acl_id, []).append(dist["ARN"])
    return by_acl


def time_window(hours: int) -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    return end - timedelta(hours=hours), end


def metric_sum(
    cw, acl_name: str, region: str, rule_name: str, metric: str, hours: int
) -> int:
    start, end = time_window(hours)
    try:
        response = cw.get_metric_statistics(
            Namespace=CLOUDWATCH_NAMESPACE,
            MetricName=metric,
            Dimensions=[
                {"Name": "WebACL", "Value": acl_name},
                {"Name": "Region", "Value": region},
                {"Name": "Rule", "Value": rule_name},
            ],
            StartTime=start,
            EndTime=end,
            Period=CLOUDWATCH_PERIOD,
            Statistics=["Sum"],
        )
        return int(sum(dp.get("Sum", 0) for dp in response.get("Datapoints", [])))
    except (ClientError, BotoCoreError) as exc:
        print(
            f"    warning: metric {metric} for {rule_name}: {exc}",
            file=sys.stderr,
        )
        return 0


def attach_rule_stats(cw, acl: WafAcl, hours: int) -> None:
    cw_region = "us-east-1" if acl.scope == "CLOUDFRONT" else acl.region
    for rule in acl.rules:
        rule.blocked = metric_sum(
            cw, acl.name, cw_region, rule.metric_name, "BlockedRequests", hours
        )
        rule.allowed = metric_sum(
            cw, acl.name, cw_region, rule.metric_name, "AllowedRequests", hours
        )
        rule.counted = metric_sum(
            cw, acl.name, cw_region, rule.metric_name, "CountedRequests", hours
        )
    acl.total_blocked = metric_sum(
        cw, acl.name, cw_region, "ALL", "BlockedRequests", hours
    )
    acl.total_allowed = metric_sum(
        cw, acl.name, cw_region, "ALL", "AllowedRequests", hours
    )


def audit_scope(
    session: boto3.Session,
    scope: str,
    region: str,
    cf_associations: dict[str, list[str]],
    include_stats: bool,
    lookback_hours: int,
) -> list[WafAcl]:
    wafv2 = session.client("wafv2", region_name=region)
    cw = session.client("cloudwatch", region_name=region) if include_stats else None
    audited: list[WafAcl] = []

    try:
        raw_acls = list_web_acls(wafv2, scope)
    except (ClientError, BotoCoreError) as exc:
        print(f"  error: list_web_acls failed ({scope}/{region}): {exc}", file=sys.stderr)
        return audited

    if not raw_acls:
        return audited

    print(f"  {scope} / {region}: {len(raw_acls)} ACL(s)")
    for raw in raw_acls:
        acl = WafAcl(
            name=raw["Name"],
            id=raw["Id"],
            arn=raw["ARN"],
            scope=scope,
            region=region,
        )
        try:
            acl.rules = fetch_acl_rules(wafv2, acl.name, acl.id, scope)
        except (ClientError, BotoCoreError) as exc:
            print(f"    error: get_web_acl({acl.name}): {exc}", file=sys.stderr)

        if scope == "REGIONAL":
            acl.associated_resources = list_regional_resources(wafv2, acl.arn)
        else:
            acl.associated_resources = cf_associations.get(acl.id, [])

        if include_stats and cw is not None:
            attach_rule_stats(cw, acl, lookback_hours)

        audited.append(acl)
        print(
            f"    - {acl.name} ({len(acl.rules)} rules, "
            f"{len(acl.associated_resources)} attached resources)"
        )

    return audited


def build_report(
    session: boto3.Session,
    regions: list[str],
    include_stats: bool,
    lookback_hours: int,
) -> list[WafAcl]:
    print(f"Scanning CLOUDFRONT scope (us-east-1)")
    cf_associations = list_cloudfront_associations(session)
    acls = audit_scope(
        session,
        "CLOUDFRONT",
        "us-east-1",
        cf_associations,
        include_stats,
        lookback_hours,
    )

    print(f"Scanning REGIONAL scope across {len(regions)} regions")
    for region in regions:
        acls.extend(
            audit_scope(
                session, "REGIONAL", region, {}, include_stats, lookback_hours
            )
        )
    return acls


def print_summary(acls: list[WafAcl], include_stats: bool) -> None:
    print()
    print("=" * 72)
    print(f"AWS WAF Audit Summary  ({len(acls)} Web ACL(s))")
    print("=" * 72)
    for acl in acls:
        print()
        print(f"[{acl.scope}] {acl.name}  ({acl.region})")
        print(f"  ARN: {acl.arn}")
        print(f"  Rules: {len(acl.rules)}")
        for rule in acl.rules:
            stats = ""
            if include_stats and rule.blocked is not None:
                stats = (
                    f"  blocked={rule.blocked} "
                    f"allowed={rule.allowed} counted={rule.counted}"
                )
            print(
                f"    - [{rule.priority:>3}] {rule.action:<5} "
                f"{rule.rule_type:<10} {rule.name}{stats}"
            )
        if include_stats and acl.total_blocked is not None:
            print(
                f"  Totals (24h): blocked={acl.total_blocked} "
                f"allowed={acl.total_allowed}"
            )
        print(f"  Attached resources ({len(acl.associated_resources)}):")
        for arn in acl.associated_resources:
            print(f"    - {arn}")
        if not acl.associated_resources:
            print("    (none — ACL is unattached)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--profile", help="AWS profile name (default: standard credential chain)"
    )
    parser.add_argument(
        "--regions",
        help="Comma-separated regions for REGIONAL scope (default: all opted-in)",
    )
    parser.add_argument(
        "--output",
        default=f"aws_waf_audit_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json",
        help="Path for the JSON report",
    )
    parser.add_argument(
        "--include-stats",
        action="store_true",
        help="Fetch per-rule CloudWatch traffic counters",
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=DEFAULT_LOOKBACK_HOURS,
        help="Hours of CloudWatch history when --include-stats is set",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    if args.regions:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    else:
        regions = discover_regions(session)

    acls = build_report(session, regions, args.include_stats, args.lookback_hours)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_id": session.client("sts").get_caller_identity()["Account"],
        "include_stats": args.include_stats,
        "lookback_hours": args.lookback_hours if args.include_stats else None,
        "web_acls": [asdict(a) for a in acls],
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print_summary(acls, args.include_stats)
    print()
    print(f"JSON report written to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
