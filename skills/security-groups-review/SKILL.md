---
name: security-groups-review
description: Perform a complete review of every security group in a scanned AWS account and explain each group's exposure and implications, using the CloudLedger server. Use when the user wants a security group audit, a firewall review, to understand what a security group allows or exposes, which groups are overly permissive, or the network exposure implied by security group rules. Requires the CloudLedger MCP server. Trigger: /security-groups-review.
---

# Security groups review

Audit every security group in a scanned account and explain what each one
actually exposes — not just list rules, but say what they mean for risk.

## Tools

- `find_security_group_rules` — every security group and its ingress/egress
  rules. Returns `{security_groups, count}`. This is the full inventory.
- `find_security_group_violations` — groups with overly permissive rules on
  sensitive ports, pre-analysed. Returns `{summary, violations_by_port,
  security_groups_with_violations, recommendations}`.
- `analyze_service_exposure` (service `ec2`) — which instances are actually
  reachable through their attached groups, with the evidence chain.
- `get_network_interfaces_with_public_ips` — the ENIs that are internet-facing,
  to see which groups sit on a public edge. Returns `{network_interfaces, count}`.
- `get_vpc_architecture` / `get_vpc_topology_detailed` — where a group sits in
  the VPC, when the user wants topology context.
- `search_by_ip` — trace a specific CIDR or address through the groups.

## Workflow

### 1. Resolve the scan and get the full inventory

Use the latest scan unless the user names a `scan_id` or account (`list_scans`
accepts an `account_number` filter). Call `find_security_group_rules` for the
complete set of groups and their rules, and report the total count — this review
covers all of them, not a sample.

### 2. Surface the violations first

Call `find_security_group_violations`. Lead the review with these: groups open
to `0.0.0.0/0` or `::/0` on sensitive ports (SSH 22, RDP 3389, databases
3306/5432/1433/27017/6379, and all-traffic rules). Use `violations_by_port` to
show what is exposed where, and carry the tool's `recommendations` into your own.

### 3. Turn rules into implications — the point of the review

For each notable group, do not just restate the rule; explain the consequence:
- **World-open sensitive port** → a directly reachable attack surface. Name the
  service on the port and the likely attacker action (e.g. SSH brute force, an
  unauthenticated database connection).
- **All-traffic (`-1`) from `0.0.0.0/0`** → every service behind the group is
  exposed; treat as high severity regardless of what is attached today.
- **Default security group with rules** → applies to anything launched without
  an explicit group; unintended exposure.
- **Broad internal CIDRs (e.g. 10.0.0.0/8)** → lateral-movement surface; lower
  priority than world-open but note it for defence in depth.
- **Egress wide open** → note it as an exfiltration/uncontrolled-outbound path,
  distinct from ingress exposure.

### 4. Tie groups to what they actually protect

Cross-reference with `analyze_service_exposure` (ec2) and
`get_network_interfaces_with_public_ips`: a permissive group on an instance with
a public IP is live exposure; the same group on a private-only instance is
latent risk. Say which is which — a rule's severity depends on what sits behind
it and whether it is internet-reachable. Use `search_by_ip` if the user asks
about a specific source range.

### 5. Report

Produce:
- A summary: total groups, how many have violations, and the worst exposures.
- A per-group findings table for groups that matter: group id, VPC, the
  offending rule(s), what it exposes, whether anything internet-reachable sits
  behind it, and the fix.
- Prioritised remediation: world-open sensitive ports first, then all-traffic
  rules, then default-group and broad-internal cleanup. For each, give the
  concrete change (restrict to known CIDRs / a VPN / SSM Session Manager; remove
  the rule; empty the default group).

## What not to do

- Do not review only the violations and stop — the user asked for a complete
  review; account for every group, even if many are benign (summarise the benign
  ones briefly).
- Do not call a permissive group "critical" without checking whether anything
  internet-reachable is behind it; state the actual reachability.
- Do not invent rules; every claim comes from `find_security_group_rules` or the
  exposure tools.
