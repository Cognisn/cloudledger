"""
Configuration wiring for CloudLedger (konfig-backed).

Uses Australian English in all documentation and comments.
"""

from .context import (
    APP_ID,
    APP_NAME,
    ENV_PREFIX,
    create_app_context,
    default_database_path,
    resolve_database_path,
)

__all__ = [
    "APP_ID",
    "APP_NAME",
    "ENV_PREFIX",
    "create_app_context",
    "default_database_path",
    "resolve_database_path",
]
