"""
MCP server implementation for CloudLedger.

This module provides an MCP server that exposes query capabilities
over historical AWS scan data.
Uses Australian English in all documentation and comments.
"""

import logging
import asyncio
import json
from pathlib import Path

# MCP SDK imports
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    logging.warning("MCP SDK not available. Please install: pip install mcp")

from ..database.operations import DatabaseOperations
from .queries import QueryHandler
from .tools import get_tools

logger = logging.getLogger(__name__)


# Global server instance
app = Server("cloudledger")

# Global database operations and query handler (will be set in main)
db_ops: DatabaseOperations = None
query_handler: QueryHandler = None


@app.list_tools()
async def list_tools() -> list[Tool]:
    """
    List available MCP tools.

    Returns:
        List of Tool objects
    """
    tools_data = get_tools()

    mcp_tools = []
    for tool_data in tools_data:
        mcp_tools.append(
            Tool(
                name=tool_data["name"],
                description=tool_data["description"],
                inputSchema=tool_data["parameters"],
            )
        )

    logger.debug(f"Listed {len(mcp_tools)} tools")
    return mcp_tools


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """
    Handle tool calls from MCP client.

    Args:
        name: Tool name
        arguments: Tool arguments

    Returns:
        List of TextContent with results
    """
    logger.info(f"Tool called: {name} with arguments: {arguments}")

    try:
        # Handle query through query handler
        result = query_handler.handle_query(name, arguments)

        # Convert result to JSON string
        result_json = json.dumps(result, indent=2, default=str)

        return [TextContent(type="text", text=result_json)]

    except Exception as e:
        logger.error(f"Error handling tool {name}: {e}", exc_info=True)
        error_result = {"error": str(e), "tool": name}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def main(database_path: str) -> None:
    """
    Main entry point for MCP server.

    Args:
        database_path: Path to SQLite database file
    """
    global db_ops, query_handler

    from ..utils.logging_config import setup_logging

    # Setup logging
    log_path = Path(database_path).parent / "mcp_server.log"
    setup_logging(
        log_file=str(log_path),
        log_level="INFO",
        console_output=False,  # Don't output to console for MCP
    )

    logger.info(f"Starting MCP server with database: {database_path}")

    # Verify database exists
    db_path = Path(database_path)
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {database_path}")

    # Initialise database operations and query handler
    db_ops = DatabaseOperations(str(db_path))
    query_handler = QueryHandler(db_ops)

    logger.info("Database operations initialised")

    # Run MCP server with stdio transport
    try:
        async with stdio_server() as (read_stream, write_stream):
            logger.info("MCP server stdio transport established")
            await app.run(
                read_stream, write_stream, app.create_initialization_options()
            )
    except Exception as e:
        logger.error(f"MCP server error: {e}", exc_info=True)
        raise


def run() -> None:
    """
    Synchronous console entry point for the MCP server.

    Parses the database path from the command line and runs the
    asynchronous server. Used by the cloudledger-mcp console script.
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: cloudledger-mcp <database_path>", file=sys.stderr)
        sys.exit(1)

    asyncio.run(main(sys.argv[1]))


if __name__ == "__main__":
    run()
