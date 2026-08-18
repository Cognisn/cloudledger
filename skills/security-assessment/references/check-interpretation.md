# Check interpretation

Entries are keyed by `check_id` — the exact string the server emits.
`get_security_check_catalogue` is the runtime source of truth for the full set;
if a check appears in results that is not listed here, report it using its
server-supplied `recommendation` rather than dropping it.

Each entry gives business-impact framing so the report narrative is specific
rather than generic.

## identity_access

### identity.root_mfa_disabled

- **What it means:** The AWS account root user — which can do anything,
  including closing the account — has no multi-factor authentication.
- **Why this severity:** Critical. Root is unrecoverable if phished; a single
  password compromise is total account compromise. Fails CIS, PCI-DSS and
  essentially every framework.
- **Watch for:** This is binary and always critical when present. Confirm root
  is not used day to day either.

### identity.root_access_keys_present

- **What it means:** The root user has active long-lived access keys, giving
  unrestricted programmatic control of the account.
- **Why this severity:** Critical. Root keys cannot be scoped and are a prime
  target; if leaked (in code, a log, an image) the whole account is lost.
- **Watch for:** There is no legitimate steady-state use for root keys. Any
  active root key is a finding regardless of rotation age.

### identity.password_policy_missing_or_weak

- **What it means:** No IAM account password policy, or one with a minimum
  length below 14, so console passwords can be short or simple.
- **Why this severity:** High. Weak passwords are brute-forced or guessed;
  combined with a user lacking MFA this is a direct console-access path.
- **Watch for:** Absence of any policy is worse than a merely short minimum.
  Note whether reuse prevention and complexity are also missing.

### identity.console_users_without_mfa

- **What it means:** IAM users who can log into the console but have no active
  MFA device.
- **Why this severity:** High. Each is a password-only console login — the most
  common initial-access vector in real breaches.
- **Watch for:** The count and who they are. Privileged users without MFA are
  the sharpest risk; call them out individually.

### identity.stale_access_keys

- **What it means:** Active access keys that have not been rotated in over 90
  days.
- **Why this severity:** Medium. Long-lived keys widen the window in which a
  leaked credential stays valid and reduce the chance a compromise is noticed.
- **Watch for:** Very old keys (years) and keys on privileged principals. High
  counts suggest no rotation process exists at all.

### identity.inactive_users

- **What it means:** Users created over 90 days ago with no password or access
  key activity in the last 90 days.
- **Why this severity:** Low. Dormant accounts are unmonitored attack surface —
  standing credentials nobody would notice being used.
- **Watch for:** Inactive users who still hold broad permissions or active
  keys; those are worse than the low default suggests.

### identity.admin_wildcard_policies

- **What it means:** Customer-managed policies granting `Action:*` on
  `Resource:*` — effectively administrator rights.
- **Why this severity:** High. Wildcard-everything policies defeat least
  privilege; any principal they attach to can do anything, so one compromise
  is total.
- **Watch for:** The `attachment_count` in the evidence. An unattached wildcard
  policy is latent risk; an attached one is live.

### identity.administrator_access_attached

- **What it means:** The AWS managed `AdministratorAccess` policy is attached to
  users, roles or groups.
- **Why this severity:** Medium. Broad admin grants enlarge the blast radius of
  any single credential compromise; day-to-day use should be scoped.
- **Watch for:** How many principals, and whether they are humans or automation.
  Reserve admin for break-glass roles.

## network_exposure

### network.sg_world_open_sensitive_ports

- **What it means:** Security group ingress rules open to 0.0.0.0/0 or ::/0 on
  sensitive ports — SSH, RDP, or databases.
- **Why this severity:** Critical. These are the ports attackers scan for
  constantly; open to the world they are a direct route to compromise.
- **Watch for:** The evidence lists the exact ports and groups. Database ports
  (3306, 5432, 1433, 27017, 6379) open to the internet are especially urgent.

### network.sg_world_open_all_traffic

- **What it means:** Security group rules allowing all protocols and ports from
  the whole internet.
- **Why this severity:** High. An all-traffic world rule exposes every service
  behind that group; it is a blanket hole rather than a specific one.
- **Watch for:** What the group is attached to. All-traffic on a group in front
  of production workloads is close to critical in practice.

### network.default_sg_with_rules

- **What it means:** Default security groups that still contain ingress rules.
- **Why this severity:** Medium. Default groups are auto-attached to resources
  that omit an explicit group; rules on them apply where nobody intended.
- **Watch for:** Whether the default group's rules are permissive. AWS best
  practice is default groups with no rules at all.

### network.subnets_auto_assign_public_ip

- **What it means:** Subnets configured to auto-assign public IPs to instances
  launched in them.
- **Why this severity:** Low. Resources land on the public internet by default,
  making accidental exposure easy.
- **Watch for:** Whether workloads that should be private are launching here.
  Pair with the EC2 exposure findings.

### network.vpcs_without_flow_logs

- **What it means:** VPCs with no VPC Flow Log attached.
- **Why this severity:** Medium. Without flow logs there is no record of network
  traffic — investigations and intrusion detection are blind.
- **Watch for:** Production VPCs especially. This is a detective gap, not an open
  door, but it hampers every incident response.

## data_protection

### data.unencrypted_ebs_volumes

- **What it means:** EBS volumes without encryption at rest.
- **Why this severity:** High. Data on unencrypted volumes is exposed if a
  snapshot leaks or the underlying storage is mishandled; fails most compliance
  regimes.
- **Watch for:** The count and whether volumes are attached to sensitive
  workloads. Note that new volumes can be encrypted by default (see
  `data.ebs_default_encryption_off`).

### data.unencrypted_ebs_snapshots

- **What it means:** EBS snapshots without encryption at rest.
- **Why this severity:** High. Snapshots are easily copied and shared; an
  unencrypted snapshot is a portable copy of your data with no protection.
- **Watch for:** Snapshots that are shared or public are far worse — cross-check
  ownership.

### data.unencrypted_rds_instances

- **What it means:** RDS database instances without storage encryption.
- **Why this severity:** High. Databases concentrate the most sensitive data;
  unencrypted storage exposes it via snapshots or storage compromise, and
  breaches most data-protection frameworks.
- **Watch for:** Whether the instance is also publicly accessible (see
  `exposure.database_exposure`) — that combination is critical.

### data.s3_public_buckets

- **What it means:** S3 buckets whose policy status reports them as public.
- **Why this severity:** Critical. Public buckets are the classic source of
  mass data leaks — indexable, copyable, and often discovered by third parties
  first.
- **Watch for:** What the bucket holds. Any public bucket warrants immediate
  confirmation that exposure is intentional; almost always it is not.

### data.s3_buckets_without_pab

- **What it means:** Buckets with no bucket-level Public Access Block.
- **Why this severity:** Medium. Without a Public Access Block a bucket is one
  policy or ACL mistake away from being public.
- **Watch for:** High counts indicate the account-level block (below) is also
  missing — fixing that covers all buckets at once.

### data.account_pab_missing

- **What it means:** No account-wide S3 Public Access Block.
- **Why this severity:** High. The account-level block is the single control
  that prevents any bucket becoming public by accident; its absence removes the
  safety net for every bucket.
- **Watch for:** This is the highest-leverage S3 fix — one setting protects the
  whole account.

### data.kms_rotation_disabled

- **What it means:** Enabled customer-managed KMS keys with automatic rotation
  turned off.
- **Why this severity:** Low. Non-rotating keys increase the impact if key
  material is ever compromised and can breach stricter compliance baselines.
- **Watch for:** Keys protecting long-lived sensitive data benefit most from
  rotation.

### data.ebs_default_encryption_off

- **What it means:** Regions where new EBS volumes are not encrypted by default.
- **Why this severity:** Medium. Every new volume in the region starts
  unencrypted unless explicitly set, so the unencrypted-volume problem keeps
  recurring.
- **Watch for:** Regions with active workloads. Enabling this is a one-setting
  preventive fix per region.

## logging_monitoring

### logging.no_multi_region_cloudtrail

- **What it means:** No logging multi-region CloudTrail trail exists.
- **Why this severity:** High. CloudTrail is the account's audit record; without
  a multi-region trail, activity in some regions is unrecorded and forensics
  after an incident may be impossible.
- **Watch for:** Whether any trail exists at all. Single-region or stopped
  trails leave blind spots.

### logging.guardduty_not_enabled

- **What it means:** Regions where GuardDuty has no enabled detector.
- **Why this severity:** Medium. GuardDuty is the managed threat-detection
  service; where it is off, active threats (credential misuse, crypto-mining,
  reconnaissance) go unflagged.
- **Watch for:** Regions with workloads but no detector. Coverage should be
  every active region.

### logging.security_hub_not_enabled

- **What it means:** Regions where Security Hub is not enabled.
- **Why this severity:** Low. Security Hub consolidates findings and runs
  standards checks; without it there is no single security dashboard, though the
  underlying controls may still exist.
- **Watch for:** This is a visibility and aggregation gap rather than a direct
  exposure.

### logging.config_recorder_missing

- **What it means:** No recording AWS Config recorder in the account.
- **Why this severity:** Medium. AWS Config tracks configuration history and
  drift; without it there is no record of what changed when, hampering audits
  and change investigations.
- **Watch for:** Whether a recorder exists but is stopped versus never created —
  both are findings.

## service_exposure

### exposure.ec2_public_instances

- **What it means:** EC2 instances with public IPs whose attached security
  groups admit traffic from the internet.
- **Why this severity:** High. Each is a directly reachable attack surface; the
  risk sharpens when sensitive ports (SSH, RDP, databases) are open.
- **Watch for:** The evidence chain lists the open ports per instance. Sensitive
  ports open to 0.0.0.0/0 push this toward critical in the narrative; a large
  count of exposed instances widens the blast radius.

### exposure.lambda_public_functions

- **What it means:** Lambda functions invokable publicly — a function URL with
  auth type NONE, or a resource policy granting a `*` principal without
  conditions.
- **Why this severity:** High. A publicly invokable function is an unauthenticated
  entry point into your code and whatever it can reach (databases, secrets,
  internal services).
- **Watch for:** The evidence distinguishes an open function URL from an open
  resource policy. Confirm any public function is deliberately public and rate
  limited.

### exposure.database_exposure

- **What it means:** Databases and data stores exposed to the internet — RDS
  instances marked publicly accessible (worse when their port is world-open),
  OpenSearch domains outside a VPC, and ElastiCache clusters behind world-open
  security groups.
- **Why this severity:** Critical. A publicly reachable database is a direct
  path to your most sensitive data and a leading cause of large breaches.
- **Watch for:** The `port_world_open` flag in the evidence — a public RDS whose
  port is also world-open is immediately exploitable. Cross-reference with
  `data.unencrypted_rds_instances`.

### exposure.public_entry_points

- **What it means:** The account's internet-facing surface: internet-facing load
  balancers, API Gateway stages, and enabled CloudFront distributions.
- **Why this severity:** Informational. This is an inventory, not a fault — every
  account has intended public entry points. It never deducts from the score.
- **Watch for:** Entry points that should not be public, and whether each is
  fronted by WAF (`waf_attached` in the evidence) and authenticated. Use it to
  confirm the intended surface matches reality.
