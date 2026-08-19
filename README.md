# CloudLedger

Multi-account AWS security scanning and infrastructure ledger with an MCP server for querying scan history.

> **Status: pre-release.** CloudLedger is under active development and is not yet published to PyPI. The commands below describe the intended 0.1.0 release; expect gaps until then.

## Overview

CloudLedger performs security assessments and collects detailed infrastructure information across multiple AWS accounts, building a historical ledger of every scan. It integrates [Prowler](https://github.com/prowler-cloud/prowler) for automated security checks against CIS Benchmarks, PCI-DSS, GDPR, HIPAA, and other frameworks, and exposes the collected data through a Model Context Protocol (MCP) stdio server so it can be queried in natural language from Claude Desktop, Claude Code, or any other MCP client.

## Features

### Scanner
- **Security assessment**: Prowler integration for framework-based automated checks, plus built-in exposure, identity, and network assessments
- **Service inventory**: identification of all AWS services in use across all regions
- **Network architecture**: VPC configurations including subnets, route tables, internet gateways, NAT gateways
- **Compute, storage, and identity**: EC2, load balancers, Auto Scaling groups, S3 buckets with public-exposure analysis, IAM users, roles, and policies
- **DNS**: Route53 hosted zones and record sets
- **Scan tagging**: tag scans at scan time or retrospectively, and search the ledger by tag from the CLI or the MCP tools
- **AWS Organisation awareness**: interactive scans capture organisation membership and the managing (control-tower) account, offer to scan the management account if the ledger has no record of it, and link member accounts to their management account
- **Historical ledger**: every scan is stored with timestamps for comparison and drift analysis

### Storage
- **SQLite** out of the box (default location in the platform data directory, managed by konfig), or
- **PostgreSQL**, **MySQL**, or **MSSQL** via optional extras, configured once with `cloudledger setup`; connection credentials are stored securely in the operating system keyring

### MCP server
- **Security queries**: publicly accessible S3 buckets, EC2 instances with public IPs, overly permissive security groups
- **Network queries**: locate accounts containing specific IP addresses or CIDR ranges, map VPC architectures
- **Configuration queries**: compare configurations between scan dates, track drift
- **Tag and organisation queries**: search scans by tag, list tags, resolve organisation relationships

## Requirements

- [uv](https://docs.astral.sh/uv/) (manages Python and all dependencies)
- Python 3.12 (installed automatically by uv; 3.13+ is not supported because Prowler pins numpy 2.0.2)
- AWS credentials (temporary session tokens recommended)
- Internet connectivity for AWS API access

## Installation

From PyPI (once published):

```bash
# Run ad hoc without installing
uvx cloudledger --help

# Or install as a tool
uv tool install cloudledger

# With a server database backend
uv tool install "cloudledger[postgres]"   # or [mysql], [mssql], [all-db]
```

From source:

```bash
git clone https://github.com/Cognisn/cloudledger.git
cd cloudledger
uv sync
```

## Quick start

```bash
# One-off configuration: choose SQLite or a server backend
cloudledger setup

# Interactive scan of a single account (database defaults to the
# platform data directory; override with --database)
cloudledger scan --tag client-acme --tag q3-review

# Batch scanning from CSV
cloudledger create-example-csv --output accounts.csv
cloudledger scan --csv accounts.csv

# Work with tags
cloudledger tag list
cloudledger tag find client-acme
cloudledger tag add <scan-id> follow-up

# Start the MCP server (stdio); reads the configured database by default
cloudledger-mcp
```

When running from a source checkout, prefix commands with `uv run`.

### Querying via MCP

With the MCP server connected to an MCP client, the ledger answers natural-language questions such as:

- "Show me all publicly accessible S3 buckets"
- "Find EC2 instances with public IP addresses in us-east-1"
- "List all scans tagged client-acme"
- "Which accounts belong to the organisation managed by account 123456789012?"
- "Compare resource counts between the two most recent scans of this account"

## Security considerations

- Designed for temporary credentials; no long-term credentials are stored
- Read-only AWS API access
- Database passwords are held in the operating system keyring, never in plain-text configuration
- CSV files containing credentials should be stored with restricted permissions, deleted after use, and never committed to version control

This tool is designed for authorised security assessments only. Ensure you have proper authorisation before scanning AWS accounts.

## Development

```bash
uv sync
uv run pytest            # SQLite-backed tests
uv run pytest -m db      # opt-in backend integration tests (run `docker compose up -d` first to start the postgres/mysql/mssql containers)
```

Contributions should use Australian English in comments and documentation, include unit tests for new features, and keep `CHANGELOG.md` current under the Unreleased heading.

## Licence

MIT Licence. See [LICENSE](LICENSE) for details.
