---
name: attack-path-analysis
description: Analyse plausible attack paths to compromise a scanned AWS account and explain them against the MITRE ATT&CK framework, using the CloudLedger server. Use when the user wants an attack-path analysis, threat modelling, MITRE ATT&CK mapping, adversary/red-team perspective, "how could this account be compromised", or the chained implications of the findings. Requires the CloudLedger MCP server. Trigger: /attack-path-analysis.
---

# Attack path analysis (MITRE ATT&CK)

Explain how an adversary could realistically compromise a scanned AWS account,
as chained attack paths mapped to MITRE ATT&CK tactics and techniques — not an
unordered list of findings.

The value is the **chain**: an internet-reachable instance is only the entry
point; the risk is what it leads to (a permissive role, an unencrypted database,
a public bucket). Build paths from entry to impact.

## Tools

Gather the raw material, then correlate it:
- `analyze_service_exposure` — the internet-reachable surface (EC2, Lambda,
  databases, entry points) with evidence chains. **The entry points.**
- `get_security_assessment_data` — the full findings set across identity,
  network, data, logging, service exposure. **The weaknesses to chain.**
- `analyze_iam_permissions` — over-privileged users/roles, admin/wildcard
  grants, missing MFA, stale keys. Returns `{summary, findings}`. **The
  escalation and lateral-movement fuel.**
- `find_public_ec2_instances`, `find_publicly_accessible_databases`,
  `find_public_s3_buckets` — specific exposed resources for concrete paths.
- `find_security_group_violations` — the network reachability that connects
  steps.
- `get_iam_users` — MFA and credential state for initial-access realism.

## Workflow

### 1. Resolve the scan

Latest scan unless the user names one (`list_scans` accepts `account_number`).
State the account and scan date.

### 2. Enumerate the ingredients by tactic

Load `references/attack-technique-map.md`. Sort the findings into ATT&CK
tactics using it:
- **Initial Access** — internet-reachable instances/functions/databases, public
  entry points, users without MFA.
- **Privilege Escalation / Credential Access** — instance roles and users with
  broad or wildcard IAM, stale access keys, root weaknesses, unsecured
  credentials.
- **Lateral Movement** — permissive internal security groups, network
  connectivity, shared roles.
- **Collection / Exfiltration / Impact** — public or unencrypted data stores,
  public buckets, missing logging that would hide the activity.

### 3. Build the chains — the core step

Construct concrete, end-to-end paths, each a sequence of ATT&CK techniques with
the specific resources that enable each hop. For example:

> **Path 1 — Public instance to data exfiltration**
> 1. *Initial Access* — T1190 Exploit Public-Facing Application / T1110 Brute
>    Force: instance `i-abc` has a public IP and SSH open to 0.0.0.0/0
>    (from `analyze_service_exposure`).
> 2. *Privilege Escalation* — T1078.004 Valid Accounts (Cloud): the instance's
>    role carries `AdministratorAccess` (from `analyze_iam_permissions`).
> 3. *Discovery* — T1580 Cloud Infrastructure Discovery: that role can enumerate
>    the account.
> 4. *Impact / Exfiltration* — T1537 Transfer Data to Cloud Account: an
>    unencrypted RDS instance and a public S3 bucket are reachable.
> 5. *Defence Evasion* — the account has no GuardDuty and no multi-region
>    CloudTrail, so the activity is unlikely to be detected.

Only assert a hop when the tools support it. If a step is plausible but
unconfirmed (e.g. a role's exact permissions weren't collected), say so and mark
that hop as inferred rather than proven.

### 4. Rank the paths

Order paths by realism and impact: fewest hops, confirmed at every step, ending
in the most damaging impact = highest priority. A single public database is a
shorter, sharper path than a multi-hop chain requiring several assumptions.

### 5. Report

Produce:
- A short adversary summary: the account's most exploitable entry points and
  what they ultimately reach.
- The ranked attack paths, each as a numbered ATT&CK-mapped chain with the
  specific resources and the tool evidence for each hop, and a note on detection
  (would GuardDuty/CloudTrail/Config catch it?).
- **Chokepoints**: the single fixes that break the most paths (e.g. "removing
  the instance role's AdministratorAccess breaks Paths 1, 3 and 4"). Lead
  remediation with these — they are worth more than fixing findings one by one.

## What not to do

- Do not present unordered findings; the deliverable is chains from entry to
  impact.
- Do not assert a hop the tools do not support; mark inferred steps clearly.
- Do not overstate: if the account has no internet-reachable surface, say the
  external attack paths are limited and pivot to insider/credential-based paths.
- Techniques and tactics are the ATT&CK lens for explanation; do not invent
  technique IDs — use the mapping reference, and describe a step plainly if no
  clean technique fits.
