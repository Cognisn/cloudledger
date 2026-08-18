# Database Schema Documentation

## Overview

The CloudLedger database uses SQLite to store comprehensive AWS infrastructure data. The schema includes 70+ tables covering all major AWS services organized into three phases.

## Core Tables

### scan_metadata
Stores metadata about each scan execution.
- scan_id (PRIMARY KEY) - Unique identifier
- account_name, account_number - Account information  
- scan_timestamp - When scan executed
- scan_status - in_progress, completed, failed
- prowler_level - Security scan level (1-3)

## Phase 1: Core Infrastructure (24 tables)

Compute: ec2_instances, auto_scaling_groups, lambda_functions
Networking: vpcs, subnets, security_groups, load_balancers, nat_gateways, internet_gateways, route_tables, network_interfaces, elastic_ips
Storage: s3_buckets, ebs_volumes, ebs_snapshots
Database: rds_instances
IAM: iam_users, iam_roles, iam_policies
DNS: route53_hosted_zones, route53_record_sets
Other: kms_keys, cost_data, prowler_findings, workspaces, vpc_flow_logs

## Phase 2: Containers & Application Services (11 tables)

Containers: ecs_clusters, ecs_services, ecs_task_definitions, eks_clusters, eks_node_groups, ecr_repositories, ecr_images
API/CDN: api_gateway_rest_apis, api_gateway_http_apis, api_gateway_stages, cloudfront_distributions

## Phase 3: Governance, Logging & Advanced Services (23 tables)

Organization: organizations, organizational_units, organization_accounts, sso_permission_sets, sso_assignments
Logging: cloudtrail_trails, cloudwatch_log_groups, config_recorders, config_rules
AI/ML: bedrock_models, bedrock_guardrails, bedrock_knowledge_bases, bedrock_agents
Networking: directory_services, transit_gateways, vpn_connections, direct_connect_connections
Managed Services: elasticache_clusters, opensearch_domains, msk_clusters, dynamodb_tables

## Data Types

- TEXT: Strings, IDs, ARNs
- INTEGER: Counts, booleans (0/1)
- REAL: Costs, durations
- TIMESTAMP: ISO 8601 format
- JSON TEXT: Complex nested data

## Next Steps

See api_reference.md and query_examples.md for usage information.
