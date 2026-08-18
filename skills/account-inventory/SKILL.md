---
name: account-inventory
description: Produce a complete inventory of the AWS services and resources in a scanned account, with counts and extent, using the CloudLedger server. Use when the user asks what services an account uses, how many of a resource there are, what is running in an account, or wants a resource inventory or service-usage breakdown of scan data. Requires the CloudLedger MCP server. Trigger: /account-inventory.
---

# Account inventory

Report which AWS services a scanned account uses and to what extent — accurate
counts, not a sample.

## The one rule that matters

**Inventory questions are answered by the summary and resource tools, never by
the security tools.** `get_security_assessment_data` and
`analyze_service_exposure` return *findings only* — a resource appears there
only if it triggered a check. Using them to count resources will undercount
badly (e.g. reporting 1 EC2 instance when the account has 9, because only one
had a finding). Always start from `get_scan_summary`.

## Workflow

### 1. Resolve the scan

Use the latest scan unless the user names a `scan_id` or account. Use
`list_scans` (it accepts an `account_number` filter) to find the right scan,
and state which account and scan date you are inventorying.

### 2. Get the authoritative counts

Call `get_scan_summary`. Its `resource_counts` object is the source of truth for
how many of each resource the account has (ec2_instances, vpcs, subnets,
security_groups, s3_buckets, iam_users, iam_roles, route53_hosted_zones,
route53_record_sets, prowler_findings, and so on). Report these counts directly.

A count of 0 means the account does not use that service — state it as "none",
not "unknown".

### 3. Add per-service detail where asked

For "to what extent" questions, enrich the headline counts with the dedicated
summaries and resource tools:
- `get_ec2_summary_by_account` — EC2 breakdown per account (types, states).
- `get_lambda_summary`, `get_workspaces_summary` — Lambda and WorkSpaces detail.
- `get_load_balancers`, `get_nat_gateways`, `get_internet_gateways`,
  `get_auto_scaling_groups` — networking and compute resources.
- `get_route53_zones` / `get_route53_records` — DNS footprint.
- `get_s3_lifecycle_policies` — S3 configuration.
- `get_organizations_structure`, `get_sso_permissions`,
  `get_directory_services`, `get_bedrock_resources`,
  `analyze_managed_services` (ElastiCache, OpenSearch, MSK, DynamoDB) — for
  broader service coverage.
- `find_unused_resources`, `analyze_tag_compliance` — usage quality, if the user
  wants it.

Only call the detail tools relevant to the question; do not dump all of them.

### 4. Report

Present a clear inventory: a table of services and their counts from
`get_scan_summary`, then the requested per-service detail. State the account,
scan date, and regions scanned. Distinguish services in use (count > 0) from
services not used (count 0 — "none").

## What not to do

- Do not infer counts from findings, exposure evidence, or the assessment
  tools — they are not an inventory.
- Do not describe a service with a 0 count as "usage unknown"; the scan checked
  and found none.
- Do not guess at services the tools do not cover; if a service is not in the
  summary or a resource tool, say so.
