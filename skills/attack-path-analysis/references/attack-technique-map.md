# Scanner findings → MITRE ATT&CK mapping

Map the scanner's findings to ATT&CK tactics and techniques (Enterprise matrix,
IaaS/Cloud platform). Use these to label each hop in an attack path. Technique
IDs are stable references; if a finding does not fit any listed technique, label
the step in plain language rather than inventing an ID.

ATT&CK is a lens for explanation, not a scoring system — the scanner's severities
and the path's realism drive prioritisation.

## Initial Access

| Finding / signal (tool) | Technique |
|---|---|
| Internet-facing instance, service, or entry point (`analyze_service_exposure`, `find_public_ec2_instances`) | T1190 Exploit Public-Facing Application |
| SSH/RDP open to 0.0.0.0/0 on a reachable host (`find_security_group_violations`) | T1110 Brute Force; T1133 External Remote Services |
| Publicly invokable Lambda / function URL with no auth (`analyze_service_exposure` lambda) | T1190 Exploit Public-Facing Application |
| Users without MFA, weak password policy (`analyze_iam_permissions`, `get_iam_users`) | T1078 Valid Accounts |
| Publicly accessible database (`find_publicly_accessible_databases`) | T1190; T1078 Valid Accounts |

## Execution / Persistence

| Finding / signal | Technique |
|---|---|
| Compromised instance with an attached role | T1651 Cloud Administration Command |
| Ability to create users/keys via broad IAM (`analyze_iam_permissions`) | T1136.003 Create Account: Cloud Account |
| Long-lived / stale access keys (`analyze_iam_permissions`) | T1098.001 Account Manipulation: Additional Cloud Credentials |

## Privilege Escalation

| Finding / signal | Technique |
|---|---|
| Role or user with AdministratorAccess or `Action:* Resource:*` (`analyze_iam_permissions`) | T1078.004 Valid Accounts: Cloud Accounts |
| Policy allowing iam:* / privilege-granting actions | T1548 Abuse Elevation Control Mechanism; T1098 Account Manipulation |

## Credential Access

| Finding / signal | Technique |
|---|---|
| Root access keys present, root MFA disabled (`get_security_assessment_data` identity) | T1078 Valid Accounts (root) |
| Secrets reachable from a compromised host / unsecured credentials | T1552 Unsecured Credentials |
| Access to credential report / IAM enumeration | T1087.004 Account Discovery: Cloud Account |

## Discovery

| Finding / signal | Technique |
|---|---|
| Broad read/list permissions on a compromised principal | T1580 Cloud Infrastructure Discovery; T1526 Cloud Service Discovery |
| Network reachability enabling scanning (`find_security_group_violations`, `analyze_network_connectivity`) | T1046 Network Service Discovery |

## Lateral Movement

| Finding / signal | Technique |
|---|---|
| Permissive internal security groups between hosts (`find_security_group_rules`, `find_security_group_violations`) | T1021 Remote Services |
| Shared or assumable roles across resources/accounts | T1078.004 Valid Accounts: Cloud Accounts |
| Transit gateway / VPN connectivity broadening reach (`analyze_network_connectivity`) | T1021 Remote Services |

## Collection / Exfiltration

| Finding / signal | Technique |
|---|---|
| Public S3 buckets (`find_public_s3_buckets`) | T1530 Data from Cloud Storage Object |
| Data reachable by a compromised role | T1213 Data from Information Repositories |
| Copy data to attacker-controlled account/store | T1537 Transfer Data to Cloud Account |

## Impact

| Finding / signal | Technique |
|---|---|
| Unencrypted data stores exposed (`get_security_assessment_data` data) | T1485 Data Destruction; T1486 Data Encrypted for Impact (ransomware) |
| Ability to delete/alter resources via broad IAM | T1485 Data Destruction |

## Defence Evasion (detection gaps that make paths viable)

| Finding / signal | Technique |
|---|---|
| No multi-region CloudTrail (`get_security_assessment_data` logging) | T1562.008 Impair Defenses: Disable/Modify Cloud Logs |
| GuardDuty / Security Hub not enabled | T1562 Impair Defenses (reduced detection) |
| No VPC flow logs | T1562.008 (reduced network visibility) |

Treat detection gaps as multipliers: a path through an account with no logging
or threat detection is far more likely to succeed undetected. Always note, per
path, whether the account's monitoring would catch it.
