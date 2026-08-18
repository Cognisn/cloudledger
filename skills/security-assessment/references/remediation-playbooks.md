# Remediation playbooks

These are instructional. The scanner never mutates AWS, and the client running
this skill must not either — present the fix for a human to apply. Entries are
keyed by `check_id`. Commands assume the AWS CLI configured for the target
account and region.

## identity_access

### identity.root_mfa_disabled

- **Fix:** Sign in as root, open the Security Credentials page, and enable an MFA
  device (hardware key preferred, virtual authenticator acceptable). Console:
  IAM → root user → Multi-factor authentication → Assign MFA device.
- **Caveats:** Store the device and recovery codes securely. Root MFA cannot be
  set via a scoped IAM user; it must be done as root.

### identity.root_access_keys_present

- **Fix:** Delete the root access keys. Console: root user → Security
  Credentials → Access keys → Delete. Replace any programmatic use with an IAM
  role or a scoped IAM user.
- **Caveats:** Confirm nothing depends on the root keys before deleting;
  migrate that workload to a scoped credential first.

### identity.password_policy_missing_or_weak

- **Fix:** Set a strong account password policy:
  `aws iam update-account-password-policy --minimum-password-length 14
  --require-symbols --require-numbers --require-uppercase-characters
  --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24`.
- **Caveats:** Existing passwords are not forced to change until next rotation;
  consider requiring a reset for non-compliant users.

### identity.console_users_without_mfa

- **Fix:** Enable MFA for each listed user. Console: IAM → Users → <user> →
  Security credentials → Assign MFA device. Enforce with a policy that denies
  actions unless MFA is present.
- **Caveats:** Coordinate with users before enforcing a deny-without-MFA policy
  so nobody is locked out mid-session.

### identity.stale_access_keys

- **Fix:** Rotate the key: create a new one
  (`aws iam create-access-key --user-name <user>`), update the consumer, then
  deactivate and delete the old key
  (`aws iam update-access-key --user-name <user> --access-key-id <old> --status Inactive`
  then `delete-access-key`). Prefer replacing static keys with short-lived role
  credentials.
- **Caveats:** Deactivate before deleting and confirm the new key works, so a
  broken consumer can be rolled back.

### identity.inactive_users

- **Fix:** Confirm the user is genuinely unused, then remove console access and
  deactivate/delete their access keys, or delete the user entirely. Console: IAM
  → Users → <user>.
- **Caveats:** Check for automation or break-glass use before deletion; disable
  first, delete after a grace period.

### identity.admin_wildcard_policies

- **Fix:** Replace the wildcard statement with least-privilege actions and
  resources. Draft a scoped policy from the principal's actual usage (CloudTrail
  or IAM Access Analyzer policy generation), test, then detach the wildcard
  policy.
- **Caveats:** Scope incrementally and verify workloads still function before
  removing the broad grant.

### identity.administrator_access_attached

- **Fix:** Detach `AdministratorAccess` from day-to-day principals and reserve it
  for a break-glass role gated by MFA and logging:
  `aws iam detach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`
  (or `detach-role-policy` / `detach-group-policy`). Grant scoped policies for
  routine work.
- **Caveats:** Ensure a controlled admin path remains (a break-glass role) before
  detaching from everyone.

## network_exposure

### network.sg_world_open_sensitive_ports

- **Fix:** Restrict the offending ingress rules to known CIDRs, a VPN range, or
  replace direct access with SSM Session Manager. Remove the world rule:
  `aws ec2 revoke-security-group-ingress --group-id <sg> --protocol tcp
  --port <port> --cidr 0.0.0.0/0`, then add a scoped rule.
- **Caveats:** Confirm no production dependency on the open rule before
  revoking; stage during a change window.

### network.sg_world_open_all_traffic

- **Fix:** Remove the all-traffic world rule and replace it with specific
  protocol/port rules scoped to required sources:
  `aws ec2 revoke-security-group-ingress --group-id <sg> --ip-permissions
  'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'`, then add narrow rules.
- **Caveats:** Identify every service relying on the group before removing the
  blanket rule so nothing breaks silently.

### network.default_sg_with_rules

- **Fix:** Strip all ingress and egress rules from the default security group so
  it grants nothing, and attach purpose-built groups to resources instead.
  Revoke each rule with `aws ec2 revoke-security-group-ingress` /
  `revoke-security-group-egress`.
- **Caveats:** Confirm no resource is relying on the default group's rules;
  give those resources an explicit group first.

### network.subnets_auto_assign_public_ip

- **Fix:** Disable auto-assignment on subnets that should be private:
  `aws ec2 modify-subnet-attribute --subnet-id <subnet> --no-map-public-ip-on-launch`.
- **Caveats:** Existing instances keep their public IPs; this only affects new
  launches. Reassign or remove public IPs on running instances separately.

### network.vpcs_without_flow_logs

- **Fix:** Enable VPC Flow Logs to CloudWatch Logs or S3:
  `aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc>
  --traffic-type ALL --log-destination-type cloud-watch-logs
  --log-group-name <group> --deliver-logs-permission-arn <role-arn>`.
- **Caveats:** Flow logs incur storage cost; set a retention policy on the log
  group or lifecycle rule on the bucket.

## data_protection

### data.unencrypted_ebs_volumes

- **Fix:** Snapshot the volume, create an encrypted copy of the snapshot
  (`aws ec2 copy-snapshot --source-snapshot-id <snap> --encrypted
  --kms-key-id <key>`), create a new volume from it, and swap it onto the
  instance.
- **Caveats:** Requires detaching/attaching and a brief downtime for the
  workload. Encryption cannot be added to a volume in place.

### data.unencrypted_ebs_snapshots

- **Fix:** Create an encrypted copy and remove the plaintext original:
  `aws ec2 copy-snapshot --source-snapshot-id <snap> --encrypted
  --kms-key-id <key>`, then `aws ec2 delete-snapshot --snapshot-id <snap>`.
- **Caveats:** Check the snapshot is not shared or referenced by an AMI before
  deleting the original.

### data.unencrypted_rds_instances

- **Fix:** RDS storage encryption cannot be toggled in place. Take a snapshot,
  copy it with encryption enabled (`aws rds copy-db-snapshot
  --source-db-snapshot-identifier <snap> --target-db-snapshot-identifier
  <snap>-enc --kms-key-id <key>`), then restore
  (`aws rds restore-db-instance-from-db-snapshot`) and cut over.
- **Caveats:** Requires a maintenance window and endpoint cut-over. Plan the
  restore before deleting the plaintext instance.

### data.s3_public_buckets

- **Fix:** Unless the bucket is deliberately a public website, apply a Public
  Access Block and remove the public policy/ACL:
  `aws s3api put-public-access-block --bucket <bucket>
  --public-access-block-configuration
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.
- **Caveats:** Confirm no legitimate public workload (static site, public
  dataset) depends on the access before locking it down.

### data.s3_buckets_without_pab

- **Fix:** Apply a bucket-level Public Access Block to each bucket (same command
  as above). Prefer also enabling the account-level block (see
  `data.account_pab_missing`) to cover everything at once.
- **Caveats:** As above, verify no intended public access first.

### data.account_pab_missing

- **Fix:** Enable the account-wide S3 Public Access Block:
  `aws s3control put-public-access-block --account-id <account>
  --public-access-block-configuration
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.
- **Caveats:** This overrides bucket-level settings and blocks all public
  access account-wide; confirm no bucket must remain public before enabling.

### data.kms_rotation_disabled

- **Fix:** Enable annual rotation on each customer-managed key:
  `aws kms enable-key-rotation --key-id <key>`.
- **Caveats:** Rotation applies to symmetric customer-managed keys; imported key
  material and asymmetric keys are handled differently.

### data.ebs_default_encryption_off

- **Fix:** Enable EBS encryption by default in each affected region:
  `aws ec2 enable-ebs-encryption-by-default --region <region>`.
- **Caveats:** Applies to newly created volumes only; existing unencrypted
  volumes must be remediated separately.

## logging_monitoring

### logging.no_multi_region_cloudtrail

- **Fix:** Create a multi-region trail with log file validation:
  `aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket>
  --is-multi-region-trail --enable-log-file-validation`, then
  `aws cloudtrail start-logging --name org-trail`.
- **Caveats:** Secure the destination bucket (its own Public Access Block and a
  restrictive policy); in AWS Organizations prefer an organisation trail.

### logging.guardduty_not_enabled

- **Fix:** Enable a GuardDuty detector in each active region:
  `aws guardduty create-detector --enable --region <region>`. In Organizations,
  enable via the delegated administrator so coverage is automatic.
- **Caveats:** GuardDuty is billed per analysed event/volume; enable in every
  region with workloads, not only the primary.

### logging.security_hub_not_enabled

- **Fix:** Enable Security Hub in each region:
  `aws securityhub enable-security-hub --region <region>`, and subscribe to the
  standards you need (CIS, AWS Foundational).
- **Caveats:** Standards checks incur cost per check; enable the standards that
  match your compliance obligations.

### logging.config_recorder_missing

- **Fix:** Enable AWS Config recording: set up a configuration recorder and
  delivery channel (Console: Config → Set up), or via CLI
  `aws configservice put-configuration-recorder` and
  `put-delivery-channel`, then `start-configuration-recorder`.
- **Caveats:** Config bills per configuration item recorded; scope the recording
  group and set S3 lifecycle rules on the delivery bucket.

## service_exposure

### exposure.ec2_public_instances

- **Fix:** For each exposed instance, remove the public IP where it is not
  required (place behind a load balancer or NAT), and tighten the attached
  security groups to scoped sources — see
  `network.sg_world_open_sensitive_ports`. Prefer SSM Session Manager over
  public SSH/RDP.
- **Caveats:** Removing a public IP changes connectivity; ensure an alternative
  access path (bastion, SSM, load balancer) is in place first.

### exposure.lambda_public_functions

- **Fix:** Set the function URL auth type to `AWS_IAM`
  (`aws lambda update-function-url-config --function-name <fn>
  --auth-type AWS_IAM`), or remove the URL if unused
  (`aws lambda delete-function-url-config --function-name <fn>`). For open
  resource policies, remove the `*`-principal statement
  (`aws lambda remove-permission --function-name <fn> --statement-id <sid>`).
- **Caveats:** Confirm any intended public invocation is genuinely required and
  add throttling/authorisation before leaving a function reachable.

### exposure.database_exposure

- **Fix:** Set the database to not publicly accessible
  (`aws rds modify-db-instance --db-instance-identifier <db>
  --no-publicly-accessible --apply-immediately`), move it into private subnets,
  and restrict its security group to application sources. For OpenSearch, move
  the domain into a VPC; for ElastiCache, scope its security groups.
- **Caveats:** Changing public accessibility and subnets affects connectivity;
  ensure application access via private networking is established first.

### exposure.public_entry_points

- **Fix:** This is an inventory, not a defect. For each entry point, confirm it
  is intended, authenticated, and fronted by WAF where appropriate. Attach a WAF
  web ACL to internet-facing load balancers, API Gateway stages, and CloudFront
  distributions that lack one.
- **Caveats:** No action is required for legitimate, protected entry points;
  focus on any that should not be public or that lack a WAF.
