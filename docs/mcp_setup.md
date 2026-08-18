# MCP Server Setup Guide

## Overview

The Model Context Protocol (MCP) Server provides a query interface to historical AWS scan data. It allows you to query infrastructure information, analyze security configurations, track changes over time, and generate documentation through natural language queries.

## Prerequisites

- Completed scanner installation and at least one successful scan
- SQLite database with scan data
- Python 3.12+ environment

## What is MCP?

Model Context Protocol (MCP) is an open standard that enables seamless integration between AI applications (like Claude Desktop) and external data sources. The CloudLedger MCP server allows Claude to query your AWS infrastructure data directly.

## MCP Server Components

The MCP server consists of:
- **Server Implementation** (src/cloudledger/mcp/server.py) - MCP protocol handler
- **Query Handlers** (src/cloudledger/mcp/queries.py) - Database query logic
- **Tool Definitions** (src/cloudledger/mcp/tools.py) - Available query tools

## Starting the MCP Server

### Method 1: Direct Execution

Start the server directly from command line:

```bash
uv run cloudledger-mcp /path/to/cloudledger.db
```

### Method 2: Claude Desktop Integration

For Claude Desktop integration, see claude_desktop_setup.md

## Available Query Tools

The MCP server provides 30+ query tools organized by category:

### Phase 1: Core Infrastructure (10 tools)
- `get_scan_summary` - Get scan metadata and statistics
- `query_ec2_instances` - Query EC2 instances
- `query_s3_buckets` - Query S3 buckets
- `query_security_groups` - Query security groups
- `query_iam_resources` - Query IAM users, roles, policies
- `analyze_network_topology` - Analyze VPC network architecture
- `get_cost_analysis` - Analyze AWS costs over time
- `find_public_resources` - Identify publicly accessible resources
- `compare_configurations` - Compare configurations between scans
- `search_by_ip` - Find resources by IP address or CIDR

### Phase 2: Containers & Applications (8 tools)
- `query_ecs_resources` - Query ECS clusters, services, tasks
- `query_eks_clusters` - Query EKS clusters and node groups
- `query_ecr_repositories` - Query ECR repositories and images
- `analyze_container_security` - Analyze container security
- `query_api_gateway` - Query API Gateway REST/HTTP APIs
- `query_cloudfront` - Query CloudFront distributions
- `analyze_serverless_architecture` - Analyze Lambda and API Gateway
- `get_container_vulnerabilities` - Get ECR image scan results

### Phase 3: Governance & Advanced (8 tools)
- `get_organizations_structure` - Get AWS Organizations hierarchy
- `get_sso_permissions` - Get SSO permission sets and assignments
- `analyze_cloudtrail_coverage` - Analyze CloudTrail logging
- `analyze_logging_coverage` - Analyze overall logging coverage
- `get_bedrock_resources` - Get Bedrock AI/ML resources
- `analyze_network_connectivity` - Analyze network connectivity
- `get_directory_services` - Get Directory Services configuration
- `analyze_managed_services` - Analyze managed services (ElastiCache, OpenSearch, MSK, DynamoDB)

### Security assessment (3 tools)
These tools produce deterministic security findings as evidence. Severities
are advisory facts only: calculating a score and building the report are the
responsibility of the MCP client (see api_reference.md).
- `get_security_assessment_data` - Run the native security checks and return findings grouped by category, coverage gaps, and Prowler linkage
- `analyze_service_exposure` - Correlate inventory into service exposure evidence (over-exposed EC2, Lambda, databases, public entry points)
- `get_security_check_catalogue` - Machine-readable catalogue of every native check and its data dependencies

## Configuration

### Database Path

The MCP server needs to know where your scan database is located. You can specify this in two ways:

1. **Command-line argument**:
   ```bash
   uv run cloudledger-mcp /path/to/cloudledger.db
   ```

2. **Claude Desktop config** (see claude_desktop_setup.md)

## Testing the MCP Server

### Test Query Tools

You can test query tools using the MCP inspector or Claude Desktop:

1. **Start the server**:
   ```bash
   uv run cloudledger-mcp ~/scans/cloudledger.db
   ```

2. **Example queries** (see query_examples.md for more):
   - "Show me a summary of the latest scan"
   - "Which S3 buckets are publicly accessible?"
   - "Find all EC2 instances in production account"
   - "Analyze CloudTrail coverage across all accounts"

## Common Use Cases

### Security Auditing
- Identify publicly accessible resources
- Analyze security group rules
- Review IAM permissions
- Check CloudTrail and logging coverage
- Find unencrypted resources

### Documentation Generation
- Generate network topology diagrams
- Document IAM roles and policies
- Create service inventory reports
- Map DNS records and Route53 zones

### Cost Analysis
- Track spending trends over time
- Compare costs between accounts
- Identify cost optimization opportunities
- Analyze service-level costs

### Compliance Reporting
- Track configuration changes
- Generate compliance reports
- Monitor security findings
- Document organizational structure

## Troubleshooting

### Issue: "Database not found"

**Cause**: Database path is incorrect or file doesn't exist

**Solution**:
1. Verify database path is correct
2. Check database file exists: `ls -la /path/to/cloudledger.db`
3. Ensure you've run at least one scan

### Issue: "No data returned"

**Cause**: Database is empty or no matching scan data

**Solution**:
1. Check database has scans: "Show me scan summary"
2. Verify scan completed successfully
3. Check query parameters are correct

## Next Steps

- **Claude Desktop Integration**: See claude_desktop_setup.md
- **Query Examples**: See query_examples.md for practical examples
- **API Reference**: See api_reference.md for complete tool documentation
