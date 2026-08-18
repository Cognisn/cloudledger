---
name: tool-guide
description: Guide to choosing the right CloudLedger tools and task skills for a given question. Use when unsure which of the scanner's many tools to call, when a question spans several tools, or to route a request to the correct specialised skill (assessment, inventory, cost, security groups, attack paths). Requires the CloudLedger MCP server. Trigger: /tool-guide.
---

# Tool guide

The CloudLedger server exposes ~50 tools. This guide routes a question to
the right tool or specialised skill so you do not answer with the wrong data.
`get_security_check_catalogue` and the server's tool list are authoritative at
runtime; this guide is the map.

## First: is there a task skill for this?

Prefer the specialised skill when the request matches one — it encodes the full
workflow and the correct tool sequence:

| The user wants… | Use skill |
|---|---|
| A scored security assessment / report | **security-assessment** |
| What services/resources exist and how many | **account-inventory** |
| Cost breakdown, trends, or forecast | **cost-analysis** |
| A full security group audit and implications | **security-groups-review** |
| Attack paths / MITRE ATT&CK / "how could this be compromised" | **attack-path-analysis** |

If the request is a single focused lookup, go straight to the tool below.

## The routing rules that prevent wrong answers

1. **Inventory / "how many X" → summary tools, never the findings tools.**
   Use `get_scan_summary` (`resource_counts`) and the per-service summaries.
   `get_security_assessment_data` and `analyze_service_exposure` return findings
   only and will undercount resources badly.
2. **A security score is never returned by the server.** The tools return
   findings with advisory severities; scoring is done by the security-assessment
   skill's rubric.
3. **"None found" is not "unknown".** A 0 count or a `not_applicable` check means
   the account has none of that resource — state it as absent, not a gap.
4. **Organizations cost questions → `get_organizations_cost_breakdown`**, not
   `get_total_cost` alone, or the payer account looks like it dominates.
5. **Default to the latest scan** unless the user names a `scan_id`; use
   `list_scans` (accepts `account_number`) to find a specific account's scan.

## Tools by question

**Scans and inventory**
- `list_scans`, `get_scan_summary` — which scans exist; per-scan resource counts.
- `get_ec2_summary_by_account`, `get_lambda_summary`, `get_workspaces_summary` —
  per-service counts and detail.
- `compare_scans`, `get_ec2_changes`, `get_route53_changes` — change over time.

**Cost**
- `get_total_cost`, `get_cost_by_service`, `get_cost_trends`,
  `get_cost_comparison`, `get_organizations_cost_breakdown`.

**Security posture and findings**
- `get_security_assessment_data`, `get_security_check_catalogue`,
  `analyze_service_exposure` — the assessment evidence engine.
- `get_prowler_findings` — Prowler results (compliance frameworks).
- `find_public_s3_buckets`, `find_public_ec2_instances`,
  `find_publicly_accessible_databases` — specific public exposure.
- `analyze_encryption_coverage`, `analyze_iam_permissions`,
  `analyze_backup_coverage`, `analyze_tag_compliance` — targeted analyses.

**Network and security groups**
- `find_security_group_rules`, `find_security_group_violations` — the firewall.
- `get_vpc_architecture`, `get_vpc_topology_detailed`, `analyze_vpc_cidrs`,
  `get_route_tables`, `get_nat_gateways`, `get_internet_gateways` — VPC layout.
- `get_network_interfaces_with_public_ips`, `search_by_ip` — public edge and IP
  tracing.
- `analyze_network_connectivity`, `find_vpc_endpoint_opportunities`,
  `get_vpc_flow_log_coverage` — connectivity, endpoints, flow-log coverage.
- `get_route53_zones`, `get_route53_records` — DNS.

**Compute, storage, and services**
- `get_load_balancers`, `get_auto_scaling_groups`, `get_s3_lifecycle_policies`,
  `find_unused_resources`, `analyze_container_vulnerabilities`,
  `analyze_managed_services` (ElastiCache, OpenSearch, MSK, DynamoDB).

**Governance and identity**
- `get_iam_users`, `get_sso_permissions`, `get_organizations_structure`,
  `get_directory_services`, `get_bedrock_resources`,
  `analyze_cloudtrail_coverage`, `analyze_logging_coverage`.

## When a question spans several tools

Gather from the relevant tools, then synthesise — do not answer from the first
tool that returns something. If the question matches a task skill, use the skill
rather than assembling the sequence by hand.
