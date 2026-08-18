# MCP API Reference

## Overview

This document provides complete reference documentation for all MCP query tools available in the CloudLedger.

## Tool Categories

The CloudLedger provides 30+ query tools organized into three phases:

- **Phase 1**: Core Infrastructure (10 tools)
- **Phase 2**: Containers & Application Services (8 tools)  
- **Phase 3**: Governance, Logging & Advanced Services (8 tools)

## Phase 1: Core Infrastructure Tools

### get_scan_summary

Get summary information about AWS scans.

**Parameters:**
- scan_id (string, optional): Specific scan ID to query

**Returns:** Scan metadata, account information, resource counts, scan duration

**Example:** "Show me a summary of the latest scan"

### query_ec2_instances

Query EC2 instances with flexible filtering.

**Parameters:**
- scan_id (string, optional): Filter by scan
- account_name (string, optional): Filter by account
- region (string, optional): Filter by region
- state (string, optional): Filter by state (running, stopped, etc.)

**Returns:** EC2 instance details including instance type, state, IPs, security groups, tags

### query_s3_buckets

Query S3 buckets and analyze security configurations.

**Parameters:**
- scan_id (string, optional): Filter by scan
- account_name (string, optional): Filter by account
- public_only (boolean, optional): Show only publicly accessible buckets

**Returns:** Bucket configurations, public access settings, encryption status, versioning

### query_security_groups

Query security groups and analyze firewall rules.

**Parameters:**
- scan_id (string, optional): Filter by scan
- vpc_id (string, optional): Filter by VPC
- port (integer, optional): Filter by port number

**Returns:** Security group rules, ingress/egress configurations, associated resources

### query_iam_resources

Query IAM users, roles, and policies.

**Parameters:**
- scan_id (string, optional): Filter by scan
- resource_type (string, optional): users, roles, or policies

**Returns:** IAM resource details, policies, trust relationships, last activity

### analyze_network_topology

Analyze VPC network architecture and component relationships.

**Parameters:**
- scan_id (string, optional): Filter by scan
- vpc_id (string, optional): Specific VPC to analyze

**Returns:** VPC topology, subnets, route tables, gateways, network flow

### get_cost_analysis

Analyze AWS costs over time with service-level breakdown.

**Parameters:**
- scan_id (string, optional): Filter by scan
- service_name (string, optional): Filter by AWS service
- months (integer, optional): Number of months to analyze

**Returns:** Cost trends, service breakdown, month-over-month changes

### find_public_resources

Identify publicly accessible AWS resources.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Public EC2 instances, S3 buckets, RDS databases, load balancers

### compare_configurations

Compare resource configurations between different scans.

**Parameters:**
- scan_id_1 (string, required): First scan to compare
- scan_id_2 (string, required): Second scan to compare
- resource_type (string, optional): Specific resource type

**Returns:** Configuration differences, added/removed resources, changes

### search_by_ip

Find resources by IP address or CIDR range.

**Parameters:**
- scan_id (string, optional): Filter by scan
- ip_address (string, required): IP or CIDR to search

**Returns:** Resources matching IP criteria

## Phase 2: Container & Application Tools

### query_ecs_resources

Query ECS clusters, services, and task definitions.

**Parameters:**
- scan_id (string, optional): Filter by scan
- cluster_name (string, optional): Filter by cluster

**Returns:** ECS configurations, running tasks, service details

### query_eks_clusters

Query EKS Kubernetes clusters and node groups.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** EKS cluster details, version, networking, node groups

### query_ecr_repositories

Query ECR repositories and container images.

**Parameters:**
- scan_id (string, optional): Filter by scan
- repository_name (string, optional): Filter by repository

**Returns:** Repository configurations, images, scan results

### analyze_container_security

Analyze container security configurations and vulnerabilities.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Image vulnerabilities, scan findings, security configurations

### query_api_gateway

Query API Gateway REST and HTTP APIs.

**Parameters:**
- scan_id (string, optional): Filter by scan
- api_type (string, optional): REST or HTTP

**Returns:** API configurations, endpoints, stages, authorizers

### query_cloudfront

Query CloudFront CDN distributions.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Distribution configurations, origins, caching, SSL

### analyze_serverless_architecture

Analyze Lambda functions and API Gateway integrations.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Serverless architecture, functions, APIs, event sources

### get_container_vulnerabilities

Get ECR image vulnerability scan results.

**Parameters:**
- scan_id (string, optional): Filter by scan
- severity (string, optional): Filter by severity level

**Returns:** Vulnerability details, CVEs, affected images

## Phase 3: Governance & Advanced Tools

### get_organizations_structure

Get AWS Organizations hierarchy and account structure.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Organization structure, OUs, member accounts

### get_sso_permissions

Get AWS SSO permission sets and assignments.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Permission sets, account assignments, policies

### analyze_cloudtrail_coverage

Analyze CloudTrail audit logging coverage.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Trail configurations, multi-region status, compliance issues

### analyze_logging_coverage

Analyze overall logging coverage across services.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** CloudTrail, CloudWatch, VPC Flow Logs, S3 access logs

### get_bedrock_resources

Get Amazon Bedrock AI/ML resources.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Foundation models, guardrails, knowledge bases, agents

### analyze_network_connectivity

Analyze advanced network connectivity options.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Transit Gateways, VPN connections, Direct Connect

### get_directory_services

Get AWS Directory Service configurations.

**Parameters:**
- scan_id (string, optional): Filter by scan

**Returns:** Directory configurations, AD details, DNS settings

### analyze_managed_services

Analyze managed database and caching services.

**Parameters:**
- scan_id (string, optional): Filter by scan
- service_type (string, optional): elasticache, opensearch, msk, dynamodb

**Returns:** Managed service configurations, performance settings

## Common Parameters

### scan_id

Most tools accept optional scan_id parameter:
- If not provided: Uses most recent scan
- If provided: Queries specific historical scan

### account_name

Filter results by AWS account name:
- Exact match on account_name field from scan_metadata

### region

Filter results by AWS region:
- Accepts standard AWS region codes (us-east-1, ap-southeast-2, etc.)

## Security Assessment Tools

These three tools produce deterministic security **evidence**: findings with
facts and recommendations. Each finding carries a `default_severity`, which is
an **advisory fact only**. Calculating a security score, weighting findings and
structuring the report are the responsibility of the MCP client, directed by
its skills — the server never computes a score.

### get_security_assessment_data

Run the native security checks against a scan and return findings grouped by
category.

**Parameters:**
- scan_id (string, optional): Scan to assess; defaults to the latest scan
- category (string, optional): Restrict to one of `identity_access`, `network_exposure`, `data_protection`, `logging_monitoring`, `service_exposure`

**Returns:** An object with:
- `scan_id`: the scan assessed
- `categories`: findings grouped by category; each check has `check_id`, `status` (`findings`/`clean`/`not_evaluated`), `default_severity`, `recommendation`, and a `findings` list of affected resources with evidence
- `not_evaluated`: checks that could not run, each with a `not_evaluated_reason` (for example, the required data was not collected) — this is the coverage-gap report
- `prowler`: `{ available, failed_by_severity, detail_tool }` — Prowler failed-finding counts when a Prowler scan exists, for the client to blend per its skills
- `scoring_note`: a reminder that scoring is the client's responsibility

**Example:** "Assess the security posture of the latest scan"

### analyze_service_exposure

Correlate collected inventory into service exposure evidence chains.

**Parameters:**
- scan_id (string, optional): Scan to analyse; defaults to the latest scan
- service (string, optional): Restrict to one of `ec2`, `lambda`, `databases`, `entry_points`

**Returns:** An object with `scan_id` and `services`, where each service maps to
a check result whose findings carry the full evidence chain (for example, an
over-exposed EC2 instance lists its public IP, each attached security group, and
the world-open rules and sensitive ports). A service whose data was not
collected degrades to `not_evaluated` rather than failing the call.

**Example:** "Which EC2 instances are over-exposed to the internet?"

### get_security_check_catalogue

Return a machine-readable catalogue of every native check.

**Parameters:** none

**Returns:** `{ checks, count }`, where each check lists its `check_id`,
`category`, `title`, what it `detects`, `default_severity`, `recommendation`,
and `data_dependencies` (the collected tables it needs). This is the reference
the skills suite uses to direct tool use and scoring.

**Example:** "List every security check the scanner can run"

## Response Format

All tools return structured data including:
- Summary statistics
- Detailed resource lists
- Compliance/security findings
- Related resources

## Next Steps

See query_examples.md for practical usage examples.
