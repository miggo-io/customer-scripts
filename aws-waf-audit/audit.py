#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["boto3>=1.34"]
# ///
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
  - wafv2:GetRuleGroup
  - wafv2:ListResourcesForWebACL
  - cloudfront:ListDistributions
  - cloudwatch:GetMetricStatistics            (only with --include-stats)
  - service-quotas:ListServiceQuotas          (Web ACL WCU limit lookup)
  - elasticloadbalancing:DescribeLoadBalancers (only with --resolve-dns)
  - appsync:GetGraphqlApi                     (only with --resolve-dns)
  - apprunner:DescribeService                 (only with --resolve-dns)
  - cognito-idp:DescribeUserPool              (only with --resolve-dns)
  - ec2:DescribeVerifiedAccessEndpoints       (only with --resolve-dns)

Usage:
  python audit.py
  python audit.py --profile my-profile --output waf.json
  python audit.py --regions us-east-1,eu-west-1 --include-stats
  python audit.py --default-region eu-west-1
  python audit.py --include-stats --lookback-hours 168
  python audit.py --resolve-dns
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

CLOUDWATCH_NAMESPACE = "AWS/WAFV2"
CLOUDWATCH_PERIOD = 86400
DEFAULT_REGION = "us-east-1"
DEFAULT_LOOKBACK_HOURS = 24
DEFAULT_WEB_ACL_WCU_LIMIT = 5000
WAFV2_SERVICE_CODE = "wafv2"
WEB_ACL_WCU_QUOTA_NAMES = {
    "CLOUDFRONT": (
        "Maximum number of web ACL capacity units in a web ACL in WAF for CloudFront"
    ),
    "REGIONAL": (
        "Maximum number of web ACL capacity units in a web ACL in WAF for regional"
    ),
}

# WAFv2 CLOUDFRONT scope is only available via the us-east-1 endpoint.
CLOUDFRONT_WAF_REGION = DEFAULT_REGION

REGIONAL_RESOURCE_TYPES = [
    "APPLICATION_LOAD_BALANCER",
    "API_GATEWAY",
    "APPSYNC",
    "COGNITO_USER_POOL",
    "APP_RUNNER_SERVICE",
    "VERIFIED_ACCESS_INSTANCE",
]

ELB_DESCRIBE_BATCH_SIZE = 20


@dataclass
class AssociatedResource:
    arn: str
    aws_hostname: str | None = None
    aliases: list[str] = field(default_factory=list)


@dataclass
class WafRule:
    name: str
    priority: int
    action: str
    rule_type: str
    metric_name: str
    statement: dict
    child_rules: list["WafRule"] = field(default_factory=list)
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
    capacity: int | None = None
    capacity_limit: int | None = None
    rules: list[WafRule] = field(default_factory=list)
    associated_resources: list[AssociatedResource] = field(default_factory=list)
    total_blocked: int | None = None
    total_allowed: int | None = None


def classify_rule_type(statement: dict) -> str:
    if "ManagedRuleGroupStatement" in statement:
        return "managed"
    if "RuleGroupReferenceStatement" in statement:
        return "custom_rule_group"
    if "RateBasedStatement" in statement:
        return "rate_based"
    return "regular"


def parse_rule(raw: dict) -> WafRule:
    statement = raw.get("Statement", {}) or {}
    action_dict = raw.get("Action", {}) or {}
    override_action = raw.get("OverrideAction", {}) or {}
    visibility = raw.get("VisibilityConfig", {}) or {}

    if visibility.get("CloudWatchMetricsEnabled") and visibility.get("MetricName"):
        metric_name = visibility["MetricName"]
    else:
        metric_name = raw.get("Name", "")

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
        rule_type=classify_rule_type(statement),
        metric_name=metric_name,
        statement=statement,
    )


def parse_rule_group_arn(arn: str) -> tuple[str, str, str]:
    """Return (name, scope, id) from a WAFv2 rule group ARN."""
    resource = arn.split(":", 5)[5]
    scope_part, _, name, rule_group_id = resource.split("/", 3)
    scope = "CLOUDFRONT" if scope_part == "global" else "REGIONAL"
    return name, scope, rule_group_id


def fetch_rule_group_rules(wafv2, arn: str) -> list[WafRule]:
    name, scope, rule_group_id = parse_rule_group_arn(arn)
    response = wafv2.get_rule_group(Name=name, Scope=scope, Id=rule_group_id)
    raw_rules = response.get("RuleGroup", {}).get("Rules", [])
    return [parse_rule(r) for r in raw_rules]


def expand_custom_rule_groups(wafv2, rules: list[WafRule]) -> None:
    """Fetch child rules for custom rule group references (one level only)."""
    for rule in rules:
        if rule.rule_type != "custom_rule_group":
            continue
        ref = rule.statement.get("RuleGroupReferenceStatement", {})
        arn = ref.get("ARN")
        if not arn:
            continue
        try:
            rule.child_rules = fetch_rule_group_rules(wafv2, arn)
        except (ClientError, BotoCoreError) as exc:
            print(
                f"    warning: get_rule_group({rule.name}): {exc}",
                file=sys.stderr,
            )


def discover_regions(
    session: boto3.Session, default_region: str = DEFAULT_REGION
) -> list[str]:
    ec2 = session.client("ec2", region_name=default_region)
    response = ec2.describe_regions(
        Filters=[
            {"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}
        ]
    )
    return sorted(r["RegionName"] for r in response.get("Regions", []))


def fetch_web_acl_capacity_limits(
    session: boto3.Session, region: str = DEFAULT_REGION
) -> dict[str, int]:
    """Return max WCUs per Web ACL for each WAF scope (account quota)."""
    limits = {scope: DEFAULT_WEB_ACL_WCU_LIMIT for scope in WEB_ACL_WCU_QUOTA_NAMES}
    sq = session.client("service-quotas", region_name=region)
    quotas: list[dict] = []
    try:
        paginator = sq.get_paginator("list_service_quotas")
        for page in paginator.paginate(ServiceCode=WAFV2_SERVICE_CODE):
            quotas.extend(page.get("Quotas", []))
    except (ClientError, BotoCoreError) as exc:
        print(
            f"warning: could not fetch Web ACL WCU limits via Service Quotas "
            f"({region}); using default {DEFAULT_WEB_ACL_WCU_LIMIT}: {exc}",
            file=sys.stderr,
        )
        return limits

    for scope, quota_name in WEB_ACL_WCU_QUOTA_NAMES.items():
        match = next((q for q in quotas if q.get("QuotaName") == quota_name), None)
        if match is None:
            print(
                f"warning: WCU quota not found for {scope} scope; "
                f"using default {DEFAULT_WEB_ACL_WCU_LIMIT}",
                file=sys.stderr,
            )
            continue
        limits[scope] = int(match["Value"])
    return limits


def format_capacity_usage(acl: WafAcl) -> str:
    if acl.capacity is None:
        return ""
    if acl.capacity_limit is not None:
        return f", {acl.capacity}/{acl.capacity_limit} WCUs"
    return f", {acl.capacity} WCUs"


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


def fetch_acl_details(
    wafv2, name: str, acl_id: str, scope: str
) -> tuple[list[WafRule], int | None]:
    response = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
    web_acl = response.get("WebACL", {}) or {}
    raw_rules = web_acl.get("Rules", [])
    rules = [parse_rule(r) for r in raw_rules]
    expand_custom_rule_groups(wafv2, rules)
    return rules, web_acl.get("Capacity")


def list_regional_resources(wafv2, acl_arn: str) -> list[AssociatedResource]:
    resources: list[AssociatedResource] = []
    for resource_type in REGIONAL_RESOURCE_TYPES:
        try:
            response = wafv2.list_resources_for_web_acl(
                WebACLArn=acl_arn, ResourceType=resource_type
            )
            resources.extend(
                AssociatedResource(arn=arn)
                for arn in response.get("ResourceArns", [])
            )
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


def list_cloudfront_index(
    session: boto3.Session,
) -> tuple[dict[str, list[str]], dict[str, AssociatedResource]]:
    """Map WebACLId -> distribution ARNs and distribution ARN -> DNS metadata."""
    cf = session.client("cloudfront")
    paginator = cf.get_paginator("list_distributions")
    by_acl: dict[str, list[str]] = {}
    by_arn: dict[str, AssociatedResource] = {}
    for page in paginator.paginate():
        items = page.get("DistributionList", {}).get("Items", []) or []
        for dist in items:
            arn = dist["ARN"]
            aliases = (dist.get("Aliases") or {}).get("Items") or []
            by_arn[arn] = AssociatedResource(
                arn=arn,
                aws_hostname=dist.get("DomainName"),
                aliases=list(aliases),
            )
            web_acl_id = dist.get("WebACLId") or ""
            if not web_acl_id:
                continue
            by_acl.setdefault(web_acl_id, []).append(arn)
    return by_acl, by_arn


def resource_service(arn: str) -> str:
    return arn.split(":")[2]


def parse_apigateway_hostname(arn: str) -> str | None:
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[2] != "apigateway":
        return None
    region = parts[3]
    resource = parts[5]
    segments = resource.strip("/").split("/")
    if len(segments) < 4 or segments[2] != "stages":
        return None
    api_id, stage = segments[1], segments[3]
    host = f"{api_id}.execute-api.{region}.amazonaws.com"
    return host if stage == "$default" else f"{host}/{stage}"


def resolve_alb_dns(session: boto3.Session, region: str, resources: list[AssociatedResource]) -> None:
    elbv2 = session.client("elbv2", region_name=region)
    arns = [res.arn for res in resources]
    for start in range(0, len(arns), ELB_DESCRIBE_BATCH_SIZE):
        chunk = arns[start : start + ELB_DESCRIBE_BATCH_SIZE]
        try:
            response = elbv2.describe_load_balancers(LoadBalancerArns=chunk)
        except (ClientError, BotoCoreError) as exc:
            print(
                f"    warning: describe_load_balancers({region}): {exc}",
                file=sys.stderr,
            )
            continue
        dns_by_arn = {
            lb["LoadBalancerArn"]: lb.get("DNSName")
            for lb in response.get("LoadBalancers", [])
        }
        for res in resources:
            if res.arn in dns_by_arn:
                res.aws_hostname = dns_by_arn[res.arn]


def resolve_appsync_dns(
    session: boto3.Session, region: str, resources: list[AssociatedResource]
) -> None:
    client = session.client("appsync", region_name=region)
    for res in resources:
        api_id = res.arn.rsplit("/", 1)[-1]
        try:
            response = client.get_graphql_api(apiId=api_id)
        except (ClientError, BotoCoreError) as exc:
            print(
                f"    warning: get_graphql_api({api_id}, {region}): {exc}",
                file=sys.stderr,
            )
            continue
        uris = response.get("graphqlApi", {}).get("uris", {}) or {}
        res.aws_hostname = uris.get("GRAPHQL") or uris.get("REALTIME")


def resolve_apprunner_dns(
    session: boto3.Session, region: str, resources: list[AssociatedResource]
) -> None:
    client = session.client("apprunner", region_name=region)
    for res in resources:
        try:
            response = client.describe_service(ServiceArn=res.arn)
        except (ClientError, BotoCoreError) as exc:
            print(
                f"    warning: describe_service({res.arn}): {exc}",
                file=sys.stderr,
            )
            continue
        res.aws_hostname = response.get("Service", {}).get("ServiceUrl")


def resolve_cognito_dns(
    session: boto3.Session, region: str, resources: list[AssociatedResource]
) -> None:
    client = session.client("cognito-idp", region_name=region)
    for res in resources:
        pool_id = res.arn.rsplit("/", 1)[-1]
        try:
            response = client.describe_user_pool(UserPoolId=pool_id)
        except (ClientError, BotoCoreError) as exc:
            print(
                f"    warning: describe_user_pool({pool_id}, {region}): {exc}",
                file=sys.stderr,
            )
            continue
        pool = response.get("UserPool", {}) or {}
        if pool.get("CustomDomain"):
            res.aliases.append(pool["CustomDomain"])
        domain_prefix = pool.get("Domain")
        if domain_prefix:
            res.aws_hostname = f"{domain_prefix}.auth.{region}.amazoncognito.com"


def resolve_verified_access_dns(
    session: boto3.Session, region: str, resources: list[AssociatedResource]
) -> None:
    ec2 = session.client("ec2", region_name=region)
    for res in resources:
        instance_id = res.arn.rsplit("/", 1)[-1]
        try:
            response = ec2.describe_verified_access_endpoints(
                Filters=[
                    {
                        "Name": "verified-access-instance-id",
                        "Values": [instance_id],
                    }
                ]
            )
        except (ClientError, BotoCoreError) as exc:
            print(
                f"    warning: describe_verified_access_endpoints"
                f"({instance_id}, {region}): {exc}",
                file=sys.stderr,
            )
            continue
        domains: list[str] = []
        for endpoint in response.get("VerifiedAccessEndpoints", []) or []:
            domain = endpoint.get("DomainName") or endpoint.get("EndpointDomain")
            if domain:
                domains.append(domain)
        if domains:
            res.aws_hostname = domains[0]
            res.aliases.extend(domains[1:])


def resolve_apigateway_dns(resources: list[AssociatedResource]) -> None:
    for res in resources:
        res.aws_hostname = parse_apigateway_hostname(res.arn)


def resolve_regional_resource_dns(
    session: boto3.Session, region: str, resources: list[AssociatedResource]
) -> None:
    by_service: dict[str, list[AssociatedResource]] = defaultdict(list)
    for res in resources:
        by_service[resource_service(res.arn)].append(res)

    if by_service["elasticloadbalancing"]:
        resolve_alb_dns(session, region, by_service["elasticloadbalancing"])
    if by_service["apigateway"]:
        resolve_apigateway_dns(by_service["apigateway"])
    if by_service["appsync"]:
        resolve_appsync_dns(session, region, by_service["appsync"])
    if by_service["apprunner"]:
        resolve_apprunner_dns(session, region, by_service["apprunner"])
    if by_service["cognito-idp"]:
        resolve_cognito_dns(session, region, by_service["cognito-idp"])
    if by_service["ec2"]:
        resolve_verified_access_dns(session, region, by_service["ec2"])


def apply_dns_resolution(
    session: boto3.Session,
    acls: list[WafAcl],
    cf_by_arn: dict[str, AssociatedResource],
) -> None:
    """Fill aws_hostname / aliases on attached resources (mutates ACLs in place)."""
    regional_by_region: dict[str, list[AssociatedResource]] = defaultdict(list)

    for acl in acls:
        resolved: list[AssociatedResource] = []
        for res in acl.associated_resources:
            if res.arn in cf_by_arn:
                resolved.append(cf_by_arn[res.arn])
            else:
                resolved.append(res)
                if acl.scope == "REGIONAL":
                    regional_by_region[acl.region].append(res)
        acl.associated_resources = resolved

    for region, resources in sorted(regional_by_region.items()):
        unique = {res.arn: res for res in resources}
        if unique:
            print(f"  Resolving DNS for {len(unique)} regional resource(s) in {region}")
            resolve_regional_resource_dns(session, region, list(unique.values()))


def associated_resource_to_dict(
    res: AssociatedResource, resolve_dns: bool
) -> dict:
    entry: dict = {"arn": res.arn}
    if not resolve_dns:
        return entry
    if res.aws_hostname:
        entry["aws_hostname"] = res.aws_hostname
    if res.aliases:
        entry["aliases"] = res.aliases
    return entry


def format_resource_dns(res: AssociatedResource) -> str:
    parts: list[str] = []
    if res.aws_hostname:
        parts.append(res.aws_hostname)
    if res.aliases:
        parts.append(f"aliases: {', '.join(res.aliases)}")
    return f" ({'; '.join(parts)})" if parts else ""


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
    cw_region = CLOUDFRONT_WAF_REGION if acl.scope == "CLOUDFRONT" else acl.region
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
    capacity_limits: dict[str, int],
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
            capacity_limit=capacity_limits.get(scope),
        )
        try:
            acl.rules, acl.capacity = fetch_acl_details(wafv2, acl.name, acl.id, scope)
        except (ClientError, BotoCoreError) as exc:
            print(f"    error: get_web_acl({acl.name}): {exc}", file=sys.stderr)

        if scope == "REGIONAL":
            acl.associated_resources = list_regional_resources(wafv2, acl.arn)
        else:
            distribution_arns = cf_associations.get(
                acl.arn, cf_associations.get(acl.id, [])
            )
            acl.associated_resources = [
                AssociatedResource(arn=arn) for arn in distribution_arns
            ]

        if include_stats and cw is not None:
            attach_rule_stats(cw, acl, lookback_hours)

        audited.append(acl)
        print(
            f"    - {acl.name} ({len(acl.rules)} rules{format_capacity_usage(acl)}, "
            f"{len(acl.associated_resources)} attached resources)"
        )

    return audited


def build_report(
    session: boto3.Session,
    regions: list[str],
    include_stats: bool,
    lookback_hours: int,
    capacity_limits: dict[str, int],
    resolve_dns: bool,
) -> list[WafAcl]:
    print(f"Scanning CLOUDFRONT scope ({CLOUDFRONT_WAF_REGION})")
    cf_associations, cf_by_arn = list_cloudfront_index(session)
    acls = audit_scope(
        session,
        "CLOUDFRONT",
        CLOUDFRONT_WAF_REGION,
        cf_associations,
        include_stats,
        lookback_hours,
        capacity_limits,
    )

    print(f"Scanning REGIONAL scope across {len(regions)} regions")
    for region in regions:
        acls.extend(
            audit_scope(
                session,
                "REGIONAL",
                region,
                {},
                include_stats,
                lookback_hours,
                capacity_limits,
            )
        )

    if resolve_dns:
        print("Resolving DNS for attached resources")
        apply_dns_resolution(session, acls, cf_by_arn)

    return acls


def rule_expression_entry(acl: WafAcl, rule: WafRule, *, parent_rule_name: str | None) -> dict:
    entry = {
        "acl_name": acl.name,
        "acl_arn": acl.arn,
        "acl_scope": acl.scope,
        "acl_region": acl.region,
        "rule_name": rule.name,
        "rule_priority": rule.priority,
        "rule_action": rule.action,
        "rule_type": rule.rule_type,
        "metric_name": rule.metric_name,
        "statement": rule.statement,
    }
    if parent_rule_name is not None:
        entry["parent_rule_name"] = parent_rule_name
    return entry


def flatten_rule_expressions(acls: list[WafAcl]) -> list[dict]:
    """Flatten every rule across every ACL into a single list with context."""
    flat: list[dict] = []
    for acl in acls:
        for rule in acl.rules:
            flat.append(rule_expression_entry(acl, rule, parent_rule_name=None))
            for child in rule.child_rules:
                flat.append(rule_expression_entry(acl, child, parent_rule_name=rule.name))
    return flat


def print_summary(acls: list[WafAcl], include_stats: bool, resolve_dns: bool) -> None:
    print()
    print("=" * 72)
    print(f"AWS WAF Audit Summary  ({len(acls)} Web ACL(s))")
    print("=" * 72)
    for acl in acls:
        print()
        print(f"[{acl.scope}] {acl.name}  ({acl.region})")
        print(f"  ARN: {acl.arn}")
        if acl.capacity is not None:
            if acl.capacity_limit is not None:
                print(f"  Capacity: {acl.capacity} / {acl.capacity_limit} WCUs")
            else:
                print(f"  Capacity: {acl.capacity} WCUs")
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
                f"{rule.rule_type:<18} {rule.name}{stats}"
            )
            for child in rule.child_rules:
                print(
                    f"        - [{child.priority:>3}] {child.action:<5} "
                    f"{child.rule_type:<18} {child.name}"
                )
        if include_stats and acl.total_blocked is not None:
            print(
                f"  Totals (24h): blocked={acl.total_blocked} "
                f"allowed={acl.total_allowed}"
            )
        print(f"  Attached resources ({len(acl.associated_resources)}):")
        for res in acl.associated_resources:
            dns = format_resource_dns(res) if resolve_dns else ""
            print(f"    - {res.arn}{dns}")
        if not acl.associated_resources:
            print("    (none — ACL is unattached)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--profile", help="AWS profile name (default: standard credential chain)"
    )
    parser.add_argument(
        "--default-region",
        default=DEFAULT_REGION,
        help=(
            f"AWS region for global API calls such as region discovery and "
            f"Service Quotas (default: {DEFAULT_REGION}). "
            f"CLOUDFRONT WAF scope is always scanned in {CLOUDFRONT_WAF_REGION}."
        ),
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
        "--resolve-dns",
        action="store_true",
        help=(
            "Resolve AWS hostnames and CloudFront alternate domain names "
            "for attached resources"
        ),
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
        regions = discover_regions(session, args.default_region)

    capacity_limits = fetch_web_acl_capacity_limits(session, args.default_region)
    print(
        "Web ACL WCU limits: "
        f"CLOUDFRONT={capacity_limits['CLOUDFRONT']}, "
        f"REGIONAL={capacity_limits['REGIONAL']}"
    )

    acls = build_report(
        session,
        regions,
        args.include_stats,
        args.lookback_hours,
        capacity_limits,
        args.resolve_dns,
    )

    web_acls_view: list[dict] = []
    for acl in acls:
        acl_dict = asdict(acl)
        acl_dict["associated_resources"] = [
            associated_resource_to_dict(res, args.resolve_dns)
            for res in acl.associated_resources
        ]
        for rule_dict in acl_dict["rules"]:
            rule_dict.pop("statement", None)
            for child_dict in rule_dict.get("child_rules") or []:
                child_dict.pop("statement", None)
        web_acls_view.append(acl_dict)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_id": session.client("sts").get_caller_identity()["Account"],
        "include_stats": args.include_stats,
        "resolve_dns": args.resolve_dns,
        "lookback_hours": args.lookback_hours if args.include_stats else None,
        "web_acls": web_acls_view,
        "rule_expressions": flatten_rule_expressions(acls),
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print_summary(acls, args.include_stats, args.resolve_dns)
    print()
    print(f"JSON report written to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
