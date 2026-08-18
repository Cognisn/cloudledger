# Claude Desktop Integration Guide

## Overview

This guide walks through integrating the CloudLedger MCP server with Claude Desktop, allowing you to query your AWS infrastructure data through natural language conversations with Claude.

## Prerequisites

- Claude Desktop application installed
- CloudLedger installed with `uv sync` (see installation.md)
- CloudLedger with completed scans
- SQLite database with scan data

## Configuration File Location

Claude Desktop's MCP server configuration is stored in:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

## Configuration Example

Edit the configuration file to add the CloudLedger MCP server:

```json
{
  "mcpServers": {
    "cloudledger": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/cloudledger",
        "cloudledger-mcp",
        "/path/to/your/cloudledger.db"
      ]
    }
  }
}
```

**Note**: Claude Desktop launches MCP servers without your shell's PATH, so
`uv` may not be found by name. If the server fails to start, use the full
path to the uv binary as the `command` value — find it with `which uv`
(commonly `~/.local/bin/uv`, written out in full, for example
`/Users/yourname/.local/bin/uv`).

## Using the MCP Server

Once configured, you can ask Claude questions about your AWS infrastructure:

- "Show me a summary of my latest AWS scan"
- "Which S3 buckets are publicly accessible?"
- "Find all EC2 instances in the production account"
- "Analyze my CloudTrail coverage"

## Troubleshooting

### MCP Server Not Appearing

1. Check configuration file syntax (validate JSON)
2. Verify all paths are correct
3. Check Claude Desktop logs

### Server Fails to Start

1. Ensure dependencies are installed: run `uv sync` in the project directory
2. Use the full path to the uv binary as `command` (see note above)
3. Verify the `--directory` argument points at the project root
4. Check `mcp_server.log` next to the database file for startup errors

## Next Steps

- **Query Examples**: See query_examples.md for more query patterns
- **API Reference**: See api_reference.md for complete tool documentation
