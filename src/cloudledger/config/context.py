"""
konfig application context wiring for CloudLedger.

Centralises settings, secrets, and logging so both entry points (the CLI
and the MCP stdio server) share one configuration surface.
Uses Australian English in all documentation and comments.
"""

import os
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Optional

from konfig import AppContext
from konfig.paths import data_dir

APP_NAME = "CloudLedger"
ENV_PREFIX = "CLOUDLEDGER"
APP_ID = "cloudledger"

# Lowest-precedence defaults; config files and environment override these.
DEFAULTS = {
    "logging": {
        "level": "INFO",
    },
}


def app_version() -> str:
    """Return the installed package version, or a placeholder when unpackaged."""
    try:
        return version("cloudledger")
    except PackageNotFoundError:
        return "0.0.0"


def default_database_path() -> Path:
    """Return the platform-conventional default SQLite database path."""
    return data_dir(APP_ID) / "cloudledger.db"


def resolve_database_path(cli_value: Optional[str], settings) -> Path:
    """Resolve the database path: CLI option, then settings, then platform default."""
    if cli_value:
        return Path(cli_value)
    configured = settings.get("database.path")
    if configured:
        return Path(configured)
    return default_database_path()


def create_app_context(
    *,
    console_output: str,
    log_level: Optional[str] = None,
) -> AppContext:
    """Build the CloudLedger konfig AppContext.

    The console output mode is an entry-point invariant (the CLI owns its
    console via rich; the MCP server may log to stderr only), and an
    explicit --log-level flag must beat configuration files. AppContext
    reads the logging settings during entry, before the runtime layer can
    be written, so both values are injected through konfig's environment
    layer, which outranks the config files.
    """
    os.environ[f"{ENV_PREFIX}__LOGGING__CONSOLE_OUTPUT"] = console_output
    if log_level:
        os.environ[f"{ENV_PREFIX}__LOGGING__LEVEL"] = log_level.upper()
    return AppContext(
        name=APP_NAME,
        version=app_version(),
        env_prefix=ENV_PREFIX,
        defaults=DEFAULTS,
    )
