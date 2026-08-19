"""
MCP tool definitions for CloudLedger.

This module defines the tools (query interfaces) exposed by the MCP server.
Uses Australian English in all documentation and comments.
"""

from typing import List, Dict, Any


def get_tools() -> List[Dict[str, Any]]:
    """
    Get list of MCP tools provided by CloudLedger.

    Returns:
        List of tool definitions
    """
    tools = [
        {
            "name": "list_scans",
            "description": "List all AWS scans or scans for a specific account",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_number": {
                        "type": "string",
                        "description": "Filter by AWS account number (optional)",
                    }
                },
            },
        },
        {
            "name": "get_scan_summary",
            "description": "Get summary of resources collected in a specific scan",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan ID to get summary for",
                    }
                },
                "required": ["scan_id"],
            },
        },
        {
            "name": "find_public_s3_buckets",
            "description": "Find S3 buckets that may be publicly accessible",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    }
                },
            },
        },
        {
            "name": "find_public_ec2_instances",
            "description": "Find EC2 instances filtered by IP address type: public (has public IP), private (no public IP, only private), or all instances. Supports pagination for large result sets and summary mode for aggregated counts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    },
                    "region": {
                        "type": "string",
                        "description": "Filter by AWS region (optional)",
                    },
                    "ip_type": {
                        "type": "string",
                        "description": "Filter by IP address type (optional): public (instances with public IPs), private (instances without public IPs), all (all instances)",
                        "enum": ["public", "private", "all"],
                        "default": "public",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 100, max: 1000). Use for pagination.",
                        "default": 100,
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Number of results to skip for pagination (default: 0)",
                        "default": 0,
                    },
                    "summary_mode": {
                        "type": "boolean",
                        "description": "Return only aggregated counts instead of full details (default: false). Use when only statistics are needed.",
                        "default": False,
                    },
                },
            },
        },
        {
            "name": "find_security_group_rules",
            "description": "Find security groups and analyse their rules",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    },
                    "allow_all_ingress": {
                        "type": "boolean",
                        "description": "Filter for security groups allowing ingress from 0.0.0.0/0 (optional)",
                        "default": False,
                    },
                },
            },
        },
        {
            "name": "search_by_ip",
            "description": "Search for AWS resources by IP address or CIDR range",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "IP address to search for",
                    },
                    "cidr_range": {
                        "type": "string",
                        "description": "CIDR range to search for",
                    },
                },
            },
        },
        {
            "name": "get_vpc_architecture",
            "description": "Get detailed VPC architecture including subnets, security groups, and instances",
            "parameters": {
                "type": "object",
                "properties": {
                    "vpc_id": {
                        "type": "string",
                        "description": "VPC ID to get architecture for",
                    },
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    },
                },
                "required": ["vpc_id"],
            },
        },
        {
            "name": "get_iam_users",
            "description": "Get IAM users with optional filtering",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    },
                    "no_mfa_only": {
                        "type": "boolean",
                        "description": "Return only users without MFA enabled (optional)",
                        "default": False,
                    },
                },
            },
        },
        {
            "name": "get_prowler_findings",
            "description": 'Get Prowler security findings with comprehensive summarisation and optional filtering. Prowler performs automated security assessments against AWS best practices, compliance frameworks (CIS, PCI-DSS, GDPR, HIPAA, etc.), and security standards. Returns detailed findings with an always-included summary containing: severity breakdown (critical/high/medium/low/informational), status distribution, top failing services, top failing check types, compliance framework coverage, and actionable insights (e.g., "10 CRITICAL findings require immediate attention"). Use summary_mode=true to get only the summary without detailed findings.',
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (case-insensitive): CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL (optional)",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                    },
                    "status": {
                        "type": "string",
                        "description": "Filter by check status (optional): PASS (security check passed, no issue), FAIL (security issue or misconfiguration detected), WARNING (potential concern identified)",
                        "enum": ["PASS", "FAIL", "WARNING"],
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of findings to return (default: 100, max: 1000). Use for pagination.",
                        "default": 100,
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Number of findings to skip for pagination (default: 0)",
                        "default": 0,
                    },
                    "summary_mode": {
                        "type": "boolean",
                        "description": "Return only the comprehensive summary without detailed findings (default: false). Summary includes severity breakdown, top failing services, compliance coverage, and actionable insights. Normal mode returns both summary and detailed findings.",
                        "default": False,
                    },
                },
            },
        },
        {
            "name": "compare_scans",
            "description": "Compare resource counts between two scans to identify changes",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id_1": {"type": "string", "description": "First scan ID"},
                    "scan_id_2": {"type": "string", "description": "Second scan ID"},
                },
                "required": ["scan_id_1", "scan_id_2"],
            },
        },
        {
            "name": "get_load_balancers",
            "description": "Get load balancers (ALB/NLB/Classic) for a scan",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID to query"},
                    "vpc_id": {
                        "type": "string",
                        "description": "Filter by VPC ID (optional)",
                    },
                    "load_balancer_type": {
                        "type": "string",
                        "description": "Filter by type: application, network, classic, gateway (optional)",
                    },
                },
                "required": ["scan_id"],
            },
        },
        {
            "name": "get_nat_gateways",
            "description": "Get NAT gateways for a scan",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID to query"},
                    "vpc_id": {
                        "type": "string",
                        "description": "Filter by VPC ID (optional)",
                    },
                },
                "required": ["scan_id"],
            },
        },
        {
            "name": "get_route_tables",
            "description": "Get route tables for a scan",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID to query"},
                    "vpc_id": {
                        "type": "string",
                        "description": "Filter by VPC ID (optional)",
                    },
                },
                "required": ["scan_id"],
            },
        },
        {
            "name": "get_internet_gateways",
            "description": "Get internet gateways for a scan",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID to query"}
                },
                "required": ["scan_id"],
            },
        },
        {
            "name": "get_auto_scaling_groups",
            "description": "Get Auto Scaling groups for a scan",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID to query"},
                    "region": {
                        "type": "string",
                        "description": "Filter by region (optional)",
                    },
                },
                "required": ["scan_id"],
            },
        },
        {
            "name": "get_network_interfaces_with_public_ips",
            "description": "Get network interfaces that have public IP addresses",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID to query"},
                    "vpc_id": {
                        "type": "string",
                        "description": "Filter by VPC ID (optional)",
                    },
                },
                "required": ["scan_id"],
            },
        },
        {
            "name": "get_ec2_summary_by_account",
            "description": "Get EC2 instance types breakdown by account for most recent scans",
            "parameters": {"type": "object", "properties": {}},
        },
        {
            "name": "get_ec2_changes",
            "description": "Get EC2 instance changes across all scans to track state and configuration changes over time",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_number": {
                        "type": "string",
                        "description": "Filter by account number (optional)",
                    }
                },
            },
        },
        {
            "name": "get_vpc_topology_detailed",
            "description": "Get detailed VPC topology including EC2 instances, Load Balancers, NAT Gateways, IGWs, Route Tables, and all associated resources",
            "parameters": {
                "type": "object",
                "properties": {
                    "vpc_id": {
                        "type": "string",
                        "description": "VPC ID to get detailed topology for",
                    },
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    },
                },
                "required": ["vpc_id"],
            },
        },
        {
            "name": "get_workspaces_summary",
            "description": "Get WorkSpaces summary by account and VPC, including state and configuration details",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    },
                    "account_number": {
                        "type": "string",
                        "description": "Filter by account number (optional)",
                    },
                },
            },
        },
        {
            "name": "get_s3_lifecycle_policies",
            "description": "Get S3 buckets with lifecycle policy details and configurations",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    }
                },
            },
        },
        {
            "name": "get_lambda_summary",
            "description": "Get Lambda functions with VPC integration details, triggers, and configurations",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    },
                    "vpc_integrated_only": {
                        "type": "boolean",
                        "description": "Return only VPC-integrated functions (optional)",
                        "default": False,
                    },
                },
            },
        },
        {
            "name": "get_route53_zones",
            "description": "Get Route53 hosted zones organised by account",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional)",
                    }
                },
            },
        },
        {
            "name": "get_route53_records",
            "description": "Get DNS records for a specific Route53 hosted zone",
            "parameters": {
                "type": "object",
                "properties": {
                    "hosted_zone_id": {
                        "type": "string",
                        "description": "Hosted zone ID to get records for",
                    },
                    "record_type": {
                        "type": "string",
                        "description": "Filter by record type (A, AAAA, CNAME, etc.) (optional)",
                    },
                },
                "required": ["hosted_zone_id"],
            },
        },
        {
            "name": "get_route53_changes",
            "description": "Get Route53 zone and DNS configuration changes across scans to track modifications over time",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_number": {
                        "type": "string",
                        "description": "Filter by account number (optional)",
                    }
                },
            },
        },
        {
            "name": "get_vpc_flow_log_coverage",
            "description": "Analyse VPC Flow Log coverage to identify which VPCs have flow logs enabled and which do not",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID to analyse"}
                },
                "required": ["scan_id"],
            },
        },
        {
            "name": "get_total_cost",
            "description": "Get total cost across all or specific accounts for the past 12 months. Includes AWS Organizations awareness - automatically detects and flags master/payer accounts in Organizations environments, and provides context explaining that master account costs are direct costs only (not consolidated billing totals). For detailed Organizations cost analysis with member account breakdown, use get_organizations_cost_breakdown instead. Returns per-account costs, totals, and Organizations context when applicable.",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_number": {
                        "type": "string",
                        "description": "Filter by specific account number (optional)",
                    },
                    "months": {
                        "type": "integer",
                        "description": "Number of months to include (default: 12)",
                        "default": 12,
                    },
                },
            },
        },
        {
            "name": "get_cost_by_service",
            "description": "Get cost breakdown by AWS service for all or specific accounts",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_number": {
                        "type": "string",
                        "description": "Filter by specific account number (optional)",
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Return top N services by cost (default: 20)",
                        "default": 20,
                    },
                },
            },
        },
        {
            "name": "get_cost_trends",
            "description": "Get cost trends over time with monthly breakdown, optionally filtered by account or service",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_number": {
                        "type": "string",
                        "description": "Filter by specific account number (optional)",
                    },
                    "service_name": {
                        "type": "string",
                        "description": "Filter by specific service name (optional)",
                    },
                },
            },
        },
        {
            "name": "get_cost_comparison",
            "description": "Compare costs between accounts with detailed service breakdown",
            "parameters": {"type": "object", "properties": {}},
        },
        {
            "name": "analyze_vpc_cidrs",
            "description": "Analyse VPC CIDR block allocations across accounts to identify overlaps, conflicts, and utilisation. This tool helps with network planning by detecting overlapping IP ranges between VPCs, calculating CIDR utilisation within each VPC (how much of the address space is allocated to subnets), and providing detailed subnet breakdowns. Use this to identify potential VPC peering conflicts, plan new CIDR allocations, or audit existing network architecture.",
            "parameters": {
                "type": "object",
                "properties": {
                    "vpc_id": {
                        "type": "string",
                        "description": "Filter analysis to a specific VPC ID (optional). If not provided, analyses all VPCs across all accounts.",
                    },
                    "scan_id": {
                        "type": "string",
                        "description": "Filter to a specific scan ID (optional). Useful for point-in-time analysis of a particular scan.",
                    },
                },
            },
        },
        {
            "name": "find_unused_resources",
            "description": "Find unused AWS resources that are consuming cost. This tool identifies unattached EBS volumes, unassociated Elastic IP addresses, old EBS snapshots (default >90 days), and stopped EC2 instances (which still incur EBS storage costs). Returns detailed information for each unused resource with estimated monthly cost savings. Use this for cost optimisation and identifying resources safe for deletion.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "resource_type": {
                        "type": "string",
                        "description": "Filter by specific resource type (optional). Options: ebs_volume, elastic_ip, ebs_snapshot, ec2_stopped. If not provided, returns all unused resources.",
                        "enum": [
                            "ebs_volume",
                            "elastic_ip",
                            "ebs_snapshot",
                            "ec2_stopped",
                        ],
                    },
                    "age_days": {
                        "type": "integer",
                        "description": "Minimum age in days for snapshots to be considered old (default: 90)",
                        "default": 90,
                    },
                },
            },
        },
        {
            "name": "analyze_encryption_coverage",
            "description": "Analyse encryption coverage across AWS resources to assess security posture and compliance. Checks encryption status for EBS volumes, EBS snapshots, RDS instances, and S3 buckets. Returns overall encryption percentage, breakdown by resource type, and detailed list of all unencrypted resources with severity ratings (CRITICAL for unencrypted RDS databases, HIGH for unencrypted S3 buckets). Use this for security audits, compliance reporting (GDPR, HIPAA, PCI-DSS), and identifying security gaps.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "account_number": {
                        "type": "string",
                        "description": "Filter by specific AWS account number (optional). If not provided, analyses all accounts.",
                    },
                },
            },
        },
        {
            "name": "find_publicly_accessible_databases",
            "description": "Find RDS database instances that are configured to be publicly accessible (publicly_accessible = true). Returns detailed information about each database including endpoint, VPC configuration, security groups, encryption status, and Multi-AZ configuration. Flags public databases as CRITICAL severity since they may be accessible from the internet. Use this for security audits, compliance checks, and identifying critical security risks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "region": {
                        "type": "string",
                        "description": "Filter by AWS region (optional). If not provided, searches all regions.",
                    },
                },
            },
        },
        {
            "name": "analyze_iam_permissions",
            "description": "Analyse IAM users, roles, and policies for security issues and overly permissive access. Detects AdministratorAccess policies (Action: *, Resource: *), dangerous wildcard permissions (s3:*, ec2:*, iam:*, rds:*), users without MFA enabled, unused access keys, and long-lived access keys (>90 days). Returns findings categorised by severity (CRITICAL, HIGH, MEDIUM) with specific recommendations. Use this for least privilege analysis, security audits, and IAM compliance reviews.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "check_type": {
                        "type": "string",
                        "description": "Filter by specific check type (optional). Options: admin (AdministratorAccess policies), wildcards (dangerous wildcard permissions), unused (unused users/roles), keys (access key issues), mfa (MFA status). If not provided, runs all checks.",
                        "enum": ["admin", "wildcards", "unused", "keys", "mfa"],
                    },
                },
            },
        },
        {
            "name": "analyze_backup_coverage",
            "description": "Analyse backup coverage across AWS resources to identify data protection gaps. Checks for RDS instances without automated backups (backup_retention_period = 0). Returns overall protection percentage, count of unprotected resources, and detailed list of RDS instances missing automated backups with CRITICAL severity. Use this for disaster recovery planning, compliance validation (backup requirements), and identifying data protection gaps.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    }
                },
            },
        },
        {
            "name": "find_security_group_violations",
            "description": "Find security group violations on sensitive ports with public internet access (0.0.0.0/0). Detects unrestricted access on critical ports including SSH (22), RDP (3389), MySQL (3306), PostgreSQL (5432), SQL Server (1433), MongoDB (27017), Redis (6379), Elasticsearch (9200), and other sensitive services. Returns violations categorised by severity (CRITICAL for SSH/RDP/databases, HIGH for caching, MEDIUM for alternative HTTP ports) with specific port and protocol details. Use this for security audits, compliance checks (CIS benchmarks), and identifying critical security risks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    }
                },
            },
        },
        {
            "name": "analyze_tag_compliance",
            "description": "Analyse tag compliance across AWS resources to ensure governance and cost tracking standards. Checks for required tags (default: Environment, Owner, CostCentre, Project) on EC2 instances, RDS instances, EBS volumes, S3 buckets, ECS clusters, EKS clusters, ECR repositories, and Load Balancers. Returns compliance percentage, breakdown by resource type, and detailed list of non-compliant resources with missing tags. Use this for governance audits, cost allocation validation, and enforcing tagging policies.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "required_tags": {
                        "type": "array",
                        "description": 'List of required tag keys to check for (default: ["Environment", "Owner", "CostCentre", "Project"])',
                        "items": {"type": "string"},
                        "default": ["Environment", "Owner", "CostCentre", "Project"],
                    },
                },
            },
        },
        {
            "name": "analyze_container_vulnerabilities",
            "description": "Analyse container vulnerabilities from Amazon ECR image scans. Parses image scan findings for CRITICAL, HIGH, MEDIUM, and LOW severity vulnerabilities. Returns total vulnerability counts by severity, breakdown by repository, and detailed list of vulnerable images with severity rankings. Supports severity threshold filtering (e.g., show only CRITICAL/HIGH). Use this for container security audits, vulnerability management, compliance validation, and prioritising remediation efforts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "severity_threshold": {
                        "type": "string",
                        "description": "Minimum severity level to report (default: MEDIUM). Options: CRITICAL (only critical), HIGH (high and above), MEDIUM (medium and above), LOW (all vulnerabilities)",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        "default": "MEDIUM",
                    },
                },
            },
        },
        {
            "name": "find_vpc_endpoint_opportunities",
            "description": "Find VPC endpoint opportunities for cost savings and improved network performance. Identifies VPCs that could benefit from AWS PrivateLink VPC endpoints for services like S3 (Gateway endpoint - free), ECR (Interface endpoint - $0.01/hour), and ECS (Interface endpoint - $0.01/hour). Analyses VPC workloads (EC2 instances, ECS services, EKS clusters) to estimate data transfer cost savings from using VPC endpoints instead of NAT gateways. Returns potential monthly savings per VPC and specific endpoint recommendations. Use this for cost optimisation, network architecture planning, and improving data transfer performance.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    }
                },
            },
        },
        # Phase 3: Governance, Logging & Advanced Services Query Tools
        {
            "name": "get_organizations_structure",
            "description": "Retrieve AWS Organizations structure including organizational units (OUs) and member accounts. Provides a comprehensive view of the organization hierarchy, showing the master account, all child accounts, their status, and the OU structure. Returns organisation ID, ARN, feature set (ALL or CONSOLIDATED_BILLING), all organisational units with parent relationships, and all member accounts with their status and join method. Use this for organisation governance documentation, account inventory, OU structure analysis, and understanding organisation topology.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    }
                },
            },
        },
        {
            "name": "get_sso_permissions",
            "description": "Get AWS SSO/Identity Center permission sets and their assignments to accounts. Shows all permission sets configured in Identity Center, including managed policies, inline policies, session duration settings, and which accounts/principals have access. Returns permission set details with attached policies and a complete mapping of permission set assignments to accounts and principals (users/groups). Use this for access auditing, permission set documentation, identifying over-privileged access, and SSO governance.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "account_id": {
                        "type": "string",
                        "description": "Filter assignments for a specific AWS account ID (optional)",
                    },
                },
            },
        },
        {
            "name": "analyze_cloudtrail_coverage",
            "description": "Analyze AWS CloudTrail coverage and compliance across all regions. Identifies CloudTrail configuration gaps, encryption status, log validation settings, and multi-region trail coverage. Detects trails with logging disabled (HIGH severity), missing log file validation (MEDIUM), lack of KMS encryption (MEDIUM), and missing CloudWatch Logs integration. Returns trail details, compliance metrics (multi-region trails, organisation trails, KMS encryption), regions covered, and specific compliance issues with severity levels. Use this for security auditing, compliance reporting (CIS, PCI-DSS, HIPAA), detecting logging gaps, and ensuring CloudTrail best practices.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    }
                },
            },
        },
        {
            "name": "analyze_logging_coverage",
            "description": "Analyze CloudWatch Logs and AWS Config coverage across the environment. Provides insights into log group configurations, retention policies, KMS encryption status, total stored data, Config recorder status, and compliance rule results. Returns CloudWatch Log Groups with retention and encryption details, total stored data in GB, Config recorder status (recording/not recording), and Config rule compliance status (compliant/non-compliant counts). Use this for logging governance, cost optimisation (identify log groups without retention), security auditing (encryption coverage), and Config compliance monitoring.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    }
                },
            },
        },
        {
            "name": "get_bedrock_resources",
            "description": "Get Amazon Bedrock AI/ML resources including foundation models, guardrails, agents, and knowledge bases. Shows all Bedrock resources deployed across regions, including model availability (Anthropic Claude, Amazon Titan, Meta Llama, etc.), guardrail configurations, agent definitions, and knowledge base configurations. Returns models by provider with input/output modalities and lifecycle status, guardrails with content policies, knowledge bases with storage configurations, and agents with foundation model selections. Use this for Bedrock resource inventory, AI/ML governance, model usage analysis, and documenting generative AI infrastructure.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "region": {
                        "type": "string",
                        "description": "Filter by specific AWS region (optional). E.g., us-east-1, eu-west-1",
                    },
                },
            },
        },
        {
            "name": "analyze_network_connectivity",
            "description": "Analyze network connectivity infrastructure including Transit Gateways, VPN connections, and AWS Direct Connect. Provides a comprehensive view of hybrid and multi-VPC connectivity setups, showing Transit Gateway configurations, VPN connection status and types, and Direct Connect connections with bandwidth and location details. Returns connectivity types in use, active vs available connections, Transit Gateway ownership, VPN tunnel details, and Direct Connect provider information. Use this for network architecture documentation, hybrid cloud connectivity analysis, network topology mapping, and identifying redundancy/failover configurations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    }
                },
            },
        },
        {
            "name": "get_directory_services",
            "description": "Get AWS Directory Service configurations including Managed AD, Simple AD, and AD Connector directories. Shows directory types, sizes (Small/Large), editions (Standard/Enterprise), SSO enablement status, and access URLs. Returns directory details with VPC settings, DNS IP addresses, directory stage (Active/Creating), and SSO integration status. Breaks down directories by type and size for easy analysis. Use this for Active Directory inventory, SSO integration auditing, directory service planning, and cost optimisation (directory sizing).",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "region": {
                        "type": "string",
                        "description": "Filter by specific AWS region (optional). E.g., us-east-1, eu-west-1",
                    },
                },
            },
        },
        {
            "name": "analyze_managed_services",
            "description": "Analyze managed database and data services including ElastiCache (Redis/Memcached), OpenSearch, Amazon MSK (Kafka), and DynamoDB. Provides comprehensive inventory of managed services with configuration details, encryption status, billing modes, and cluster sizes. Returns ElastiCache clusters by engine type with encryption coverage, OpenSearch domains with version and endpoint details, MSK clusters with Kafka versions and broker counts, and DynamoDB tables with billing mode analysis (Provisioned vs On-Demand). Includes encryption coverage metrics for security compliance. Use this for managed service inventory, encryption auditing, cost analysis (DynamoDB billing modes), and database/data platform documentation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    },
                    "region": {
                        "type": "string",
                        "description": "Filter by specific AWS region (optional). E.g., us-east-1, eu-west-1",
                    },
                },
            },
        },
        {
            "name": "get_organizations_cost_breakdown",
            "description": 'PREFERRED TOOL for AWS Organizations/Control Tower environments when answering "which account costs the most?" or comparing account costs. This query addresses the common issue where the master/payer account appears to have the highest costs by clearly separating master account DIRECT costs (resources in the master account only) from member account costs (actual per-account usage). Automatically identifies which MEMBER account has the highest actual usage. Use this tool when: (1) asking which account incurs the most cost, (2) comparing costs between accounts in Organizations environments, (3) needing to understand cost distribution across an Organisation structure. Returns: organization info, master account direct costs with clear labeling, member account costs sorted by usage, cost summary with totals excluding master account, and interpretation explaining that master account costs are direct costs only (not consolidated billing totals). Essential for accurate cost analysis in Organizations environments.',
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Filter by specific scan ID (optional). If not provided, uses the most recent scan.",
                    }
                },
            },
        },
        {
            "name": "get_security_assessment_data",
            "description": (
                "Run the native security checks against a scan and return "
                "deterministic findings grouped by category (identity_access, "
                "network_exposure, data_protection, logging_monitoring, "
                "service_exposure), plus a not_evaluated list describing "
                "coverage gaps and Prowler finding counts when a Prowler scan "
                "exists. Severities are ADVISORY facts only: calculating a "
                "security score, weighting findings and building the report "
                "are the responsibility of the MCP client, directed by its "
                "skills. Use get_security_check_catalogue to enumerate all "
                "checks and get_prowler_findings for Prowler detail."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan to assess (optional; defaults to the latest scan)",
                    },
                    "category": {
                        "type": "string",
                        "enum": [
                            "identity_access",
                            "network_exposure",
                            "data_protection",
                            "logging_monitoring",
                            "service_exposure",
                        ],
                        "description": "Restrict the run to one category (optional)",
                    },
                },
            },
        },
        {
            "name": "analyze_service_exposure",
            "description": (
                "Correlate collected inventory into service exposure evidence "
                "chains: EC2 instances with public IPs whose security groups "
                "admit internet traffic, publicly invokable Lambda functions, "
                "exposed databases and data stores, and the public entry "
                "point inventory (load balancers, API Gateway stages, "
                "CloudFront). Each finding carries the full evidence chain. "
                "Severities are ADVISORY; scoring is the MCP client's "
                "responsibility."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan to analyse (optional; defaults to the latest scan)",
                    },
                    "service": {
                        "type": "string",
                        "enum": ["ec2", "lambda", "databases", "entry_points"],
                        "description": "Restrict to one service area (optional)",
                    },
                },
            },
        },
        {
            "name": "get_security_check_catalogue",
            "description": (
                "Machine-readable catalogue of every native security check: "
                "check_id, category, what it detects, advisory default "
                "severity, recommendation and the collected tables it depends "
                "on. Intended as the reference for skills that direct scoring "
                "methodology and report structure."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
        {
            "name": "search_scans_by_tag",
            "description": "Find scans matching a tag, case-insensitively, newest first",
            "parameters": {
                "type": "object",
                "properties": {
                    "tag": {
                        "type": "string",
                        "description": "Tag to search for",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of scans to return (default: 100, max: 1000)",
                        "default": 100,
                    },
                },
                "required": ["tag"],
            },
        },
        {
            "name": "list_scan_tags",
            "description": "List all distinct tags across all scans, with the number of scans carrying each tag",
            "parameters": {"type": "object", "properties": {}},
        },
    ]

    for tool in tools:
        if "All timestamps are UTC" not in tool["description"]:
            tool["description"] = (
                tool["description"].rstrip() + " All timestamps are UTC (ISO 8601)."
            )

    return tools


def get_tool_by_name(name: str) -> Dict[str, Any]:
    """
    Get a specific tool definition by name.

    Args:
        name: Tool name

    Returns:
        Tool definition or None if not found
    """
    tools = get_tools()
    for tool in tools:
        if tool["name"] == name:
            return tool
    return None
