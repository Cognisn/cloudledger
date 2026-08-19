"""
Configuration wiring for CloudLedger (konfig-backed).

Uses Australian English in all documentation and comments.
"""

from .context import (
    APP_ID,
    APP_NAME,
    ENV_PREFIX,
    build_database_url,
    create_app_context,
    default_database_path,
    mask_target,
    resolve_database_target,
)

__all__ = [
    "APP_ID",
    "APP_NAME",
    "ENV_PREFIX",
    "build_database_url",
    "create_app_context",
    "default_database_path",
    "mask_target",
    "resolve_database_target",
]
