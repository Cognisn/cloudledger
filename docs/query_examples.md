# Query Examples

## Overview

This document provides practical examples of queries you can make using the CloudLedger MCP server through Claude Desktop.

## Security Queries

### Finding Public Resources

- Show me all publicly accessible resources
- Which S3 buckets are publicly accessible?
- Which EC2 instances have public IP addresses?

### Security Groups

- Which security groups allow SSH access from anywhere?
- Show me security groups with 0.0.0.0/0 access
- Which security groups allow traffic on port 3389?

### IAM Security

- Which IAM users do not have MFA enabled?
- Show me all IAM roles and their trust relationships

### CloudTrail

- Analyze CloudTrail coverage across all accounts
- Which regions do not have CloudTrail logging enabled?

## Network Queries

### IP Searches

- Find all resources with IP address 10.0.1.50
- Which resources are in the 172.16.0.0/12 range?

### Topology

- Show me the network topology for VPC vpc-abc123
- Which subnets are public vs private?

## Cost Analysis

### Trends

- Show me cost trends for the last 12 months
- Which AWS services cost the most?

### Optimization

- Which EBS volumes are not attached to instances?
- Show me stopped EC2 instances

## Infrastructure

### Compute

- Show me all running EC2 instances
- List all Lambda functions using Python 3.9

### Storage

- Show me all S3 buckets and their sizes
- Which S3 buckets do not have versioning enabled?

### Databases

- Show me all RDS database instances
- Which RDS instances are not Multi-AZ?

## Containers

### ECS/EKS

- Show me all ECS clusters and their services
- What versions are my EKS clusters running?

### Images

- Which container images have security vulnerabilities?

## Governance

### Organizations

- Show me our AWS Organizations structure
- List all member accounts in the organization

### SSO

- Show me all SSO permission sets
- List all SSO account assignments

## Compliance

### Encryption

- Which S3 buckets are not encrypted?
- Show me unencrypted EBS volumes

### Config

- Show me all AWS Config rules
- Which Config rules are in non-compliant state?

## Historical Comparisons

- Compare the last two scans
- Show me new EC2 instances since last week

## Next Steps

See scanner_usage.md, mcp_setup.md, and api_reference.md for more information.
