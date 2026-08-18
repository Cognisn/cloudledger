# Scanner Usage Guide

## Overview

The CloudLedger is a comprehensive tool for collecting infrastructure data and performing security assessments across AWS accounts. It supports two scanning modes: interactive and CSV batch mode.

## Prerequisites

- Completed installation (see installation.md)
- AWS temporary credentials (ASIA tokens) from AWS Access Portal
- SQLite database path for storing scan results

## Command Structure

The scanner uses a modular CLI interface:

```bash
uv run cloudledger [COMMAND] [OPTIONS]
```

## Available Commands

### scan - Run AWS Infrastructure Scan

Primary command for scanning AWS accounts and collecting infrastructure data.

```bash
uv run cloudledger scan --database <path> [OPTIONS]
```

**Required Options:**
- `--database PATH`: Path to SQLite database file (will be created if it doesn't exist)

**Optional Options:**
- `--csv PATH`: Path to CSV file with account credentials (enables batch mode)
- `--log-level LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR) - default: INFO
- `--regions REGIONS`: Comma-separated list of regions to scan (default: all regions)

### create-example-csv - Generate CSV Template

Creates an example CSV file showing the required format for batch scanning.

```bash
uv run cloudledger create-example-csv --output <path>
```

**Optional Options:**
- `--output PATH`: Output path for example CSV file (default: example_accounts.csv)

## Security Assessment Data

Alongside the infrastructure inventory, each scan collects the data needed to
assess the account's security posture:

- **Account security posture**: IAM account summary (root MFA, root access
  keys), the account password policy, and the account-level S3 Public Access
  Block.
- **IAM credential report**: per-user MFA status, console access, and access
  key ages and last-used dates.
- **Per-region security services**: GuardDuty, Security Hub, IAM Access
  Analyzer, and EBS default-encryption status in every scanned region.
- **Lambda exposure**: function URL configurations and resource policies, to
  identify publicly invokable functions.
- **S3 public access**: per-bucket Public Access Block and policy status.

Missing permissions are logged and skipped; they never fail a scan. This data
is surfaced through the security assessment MCP tools (see mcp_setup.md and
api_reference.md). Scans taken before this data was added remain queryable —
checks that depend on uncollected data report `not_evaluated` rather than
failing.

## Next Steps

- **MCP Server Setup**: See mcp_setup.md for querying scan data
- **Claude Desktop Integration**: See claude_desktop_setup.md
- **Database Schema**: See database_schema.md for table structures
- **Query Examples**: See query_examples.md for common queries
