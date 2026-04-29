# AWS WAF Audit Script

A standalone, **read-only** Python script that inventories every AWS WAFv2 Web ACL
in your account, the rules inside each ACL, and the AWS resources each ACL is
attached to. Output is a single JSON file plus a human-readable summary.

The script makes **no writes** to AWS. It only calls `List*`, `Get*`, and
`Describe*` APIs.

---

## What the script pulls

For every WAFv2 Web ACL in your account (both `REGIONAL` and `CLOUDFRONT` scopes,
across every opted-in region):

### ACL metadata
- ACL **name**, **ID**, **ARN**
- **Scope** (`REGIONAL` or `CLOUDFRONT`)
- **Region**

### Rules inside each ACL
For each rule:
- **Name** and **priority** (evaluation order inside the ACL)
- **Action** — `BLOCK`, `ALLOW`, `COUNT`, `CAPTCHA`, `CHALLENGE`, or `NONE`
  (`NONE` indicates a managed rule group with no override)
- **Rule type** — one of:
  - `regular` — custom rule (IP set, byte match, geo match, etc.)
  - `rate_based` — rate-limit rule
  - `managed` — AWS or marketplace Managed Rule Group
- **CloudWatch metric name** (from `VisibilityConfig`)
- **Statement** — the full rule definition as returned by `wafv2:GetWebACL`
  (the same JSON you'd see in the AWS console "Rule JSON" view)

### Attached resources (ACL → resource mapping)
The AWS resources that each Web ACL is currently protecting:
- For `REGIONAL` ACLs (via `wafv2:ListResourcesForWebACL`):
  - Application Load Balancers
  - API Gateway stages
  - AppSync GraphQL APIs
  - Cognito User Pools
  - App Runner services
  - Verified Access instances
- For `CLOUDFRONT` ACLs (via `cloudfront:ListDistributions`):
  - CloudFront distributions

ACLs with no attached resources are explicitly flagged in the output.

### Optional: traffic counters (`--include-stats`)
When this flag is set, the script also pulls **CloudWatch counters** for the
last 24 hours (configurable with `--lookback-hours`):
- Per rule: `BlockedRequests`, `AllowedRequests`, `CountedRequests`
- Per ACL: aggregated `BlockedRequests`, `AllowedRequests` (the `ALL` rule)

These come from the `AWS/WAFV2` CloudWatch namespace and reflect what your WAF
already reports natively — no new metrics are produced.

### What the script does **not** collect
- No request bodies, headers, IP addresses, or any sampled requests
- No customer traffic data beyond aggregated counters (only when `--include-stats`)
- No data from any service other than WAFv2, CloudFront, EC2 (regions), STS
  (account ID), and CloudWatch (only with `--include-stats`)
- No writes, modifications, or configuration changes of any kind

---

## Prerequisites

- **Python 3.9+**
- **Dependencies** (one package — `boto3`):
  ```bash
  pip install -r requirements.txt
  ```
- **AWS credentials** with the read-only permissions listed below, available
  via any standard mechanism:
  - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`)
  - Shared config / credentials file (`~/.aws/credentials`, optionally with `--profile`)
  - EC2 instance profile / ECS task role / IAM Identity Center

---

## Required IAM permissions

All actions are read-only. Minimal policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:ListResourcesForWebACL",
        "cloudfront:ListDistributions",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:GetMetricStatistics"
      ],
      "Resource": "*"
    }
  ]
}
```

The `cloudwatch:GetMetricStatistics` permission is only required if you run
the script with `--include-stats`; otherwise it can be omitted.

> **Tip:** the AWS-managed policy `ReadOnlyAccess` already covers all of these.

---

## Usage

```bash
# Default: scan every opted-in region, write JSON next to the script
python audit.py

# Use a named AWS profile
python audit.py --profile my-aws-profile

# Limit to specific regions (CLOUDFRONT scope is always scanned in us-east-1)
python audit.py --regions us-east-1,eu-west-1

# Include 24h CloudWatch traffic counters
python audit.py --include-stats

# Custom lookback (e.g., last 7 days)
python audit.py --include-stats --lookback-hours 168

# Custom output path
python audit.py --output /tmp/waf-audit.json
```

### CLI flags

| Flag | Description |
|------|-------------|
| `--profile PROFILE` | AWS profile name (default: standard credential chain) |
| `--regions REGIONS` | Comma-separated regions for `REGIONAL` scope (default: all opted-in regions) |
| `--output PATH` | Path for the JSON report (default: `aws_waf_audit_<UTC-timestamp>.json`) |
| `--include-stats` | Also fetch per-rule CloudWatch traffic counters |
| `--lookback-hours N` | Hours of CloudWatch history when `--include-stats` is set (default: 24) |

---

## Output

### JSON file

```jsonc
{
  "generated_at": "2026-04-29T12:34:56+00:00",
  "account_id": "123456789012",
  "include_stats": false,
  "lookback_hours": null,
  "web_acls": [
    {
      "name": "my-web-acl",
      "id": "abcd-1234-...",
      "arn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/...",
      "scope": "REGIONAL",
      "region": "us-east-1",
      "rules": [
        {
          "name": "block-bad-ips",
          "priority": 1,
          "action": "BLOCK",
          "rule_type": "regular",
          "metric_name": "block-bad-ips-metric",
          "statement": { "IPSetReferenceStatement": { "ARN": "..." } },
          "blocked": null,
          "allowed": null,
          "counted": null
        }
      ],
      "associated_resources": [
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/..."
      ],
      "total_blocked": null,
      "total_allowed": null
    }
  ]
}
```

When `--include-stats` is set, the `blocked`, `allowed`, `counted`,
`total_blocked`, and `total_allowed` fields are populated with integer counts.

### Stdout summary

A grouped, human-readable summary is printed during and after the scan, e.g.:

```
Scanning CLOUDFRONT scope (us-east-1)
  CLOUDFRONT / us-east-1: 1 ACL(s)
    - cf-acl (4 rules, 2 attached resources)
Scanning REGIONAL scope across 17 regions
  REGIONAL / us-east-1: 2 ACL(s)
    - alb-acl (6 rules, 1 attached resources)
    - unattached-acl (2 rules, 0 attached resources)
...

========================================================================
AWS WAF Audit Summary  (3 Web ACL(s))
========================================================================

[CLOUDFRONT] cf-acl  (us-east-1)
  ARN: arn:aws:wafv2:global:.../webacl/...
  Rules: 4
    - [  0] NONE  managed    AWS-AWSManagedRulesCommonRuleSet
    - [  1] BLOCK regular    block-bad-ips
    - [  2] COUNT rate_based rate-limit-rule
    ...
  Attached resources (2):
    - arn:aws:cloudfront::123456789012:distribution/EXXXXXX
    - arn:aws:cloudfront::123456789012:distribution/EYYYYYY
```

---

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `Unable to locate credentials` | No credentials in env / config. Run `aws configure` or set `AWS_PROFILE`. |
| `AccessDenied` on `wafv2:*` | The principal is missing one of the IAM actions above. |
| `ThrottlingException` warnings on stderr | Benign — the script logs the warning, treats the affected metric as 0, and continues. |
| Empty output despite known ACLs | Confirm credentials target the correct account (`aws sts get-caller-identity`) and that the regions you expect are opted-in. |
| Script hangs on a region | Use `--regions` to restrict the scan to known regions. |

---

## Privacy & safety

- The script reads configuration only — **no request data, headers, IPs, or
  bodies** are accessed.
- All data stays on the machine running the script. Nothing is uploaded
  anywhere; the JSON report is written locally to the path you choose.
- All API calls use the AWS-side credentials you provide and respect existing
  IAM policies, SCPs, and CloudTrail logging.
