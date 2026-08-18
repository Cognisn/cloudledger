# Installation Guide

## Overview

This guide provides detailed installation instructions for the CloudLedger and MCP Server. The CloudLedger is a comprehensive tool for scanning AWS infrastructure and security configurations, with an integrated Model Context Protocol (MCP) server for querying historical scan data.

## System Requirements

### Operating System
- **Linux**: Ubuntu 20.04+ / Debian 11+ / RHEL 8+ / Amazon Linux 2
- **macOS**: macOS 11 (Big Sur) or later  
- **Windows**: Windows 10/11 or Windows Server 2019+

### Python Requirements
- **[uv](https://docs.astral.sh/uv/)** (required — manages Python and all dependencies)
- **Python 3.12** (installed automatically by uv if not already present)

**Note**: Python 3.13 and later are not currently supported. Prowler pins
numpy 2.0.2, which does not provide wheels beyond CPython 3.12.

### System Resources
- **CPU**: 2+ cores recommended
- **RAM**: 4GB minimum, 8GB+ recommended for large environments
- **Disk Space**:
  - 500MB for application and dependencies
  - Variable for database (depends on number of accounts/resources)
  - Example: 50 AWS accounts ≈ 2-5GB database

### Network Requirements
- Internet connectivity for AWS API access
- Access to AWS service endpoints (via direct connection or proxy)
- Ports: Outbound HTTPS (443) to AWS regions

## Installation Methods

### Install uv (once, if not already installed)

```bash
# macOS and Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Method 1: Clone from GitHub (Recommended)

```bash
# Clone the repository
git clone https://github.com/Cognisn/cloudledger.git
cd cloudledger

# Create the environment and install everything from the lockfile
uv sync

# Verify installation
uv run cloudledger --version
```

### Method 2: Extract from ZIP Archive

```bash
# Extract the archive
unzip cloudledger.zip
cd cloudledger

# Create the environment and install everything from the lockfile
uv sync

# Verify installation
uv run cloudledger --version
```

`uv sync` reads `pyproject.toml` and `uv.lock`, provisions Python 3.12 in a
local `.venv/`, and installs every dependency at its locked version. There is
no separate pip or virtualenv step.

## Next Steps

- **Scanner Usage**: See scanner_usage.md
- **MCP Setup**: See mcp_setup.md
- **Claude Desktop**: See claude_desktop_setup.md
