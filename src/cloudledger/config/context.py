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
from urllib.parse import quote_plus

import sqlalchemy as sa
from konfig import AppContext
from konfig.paths import data_dir

APP_NAME = "CloudLedger"
ENV_PREFIX = "CLOUDLEDGER"
APP_ID = "cloudledger"

# Backends resolved via a SQLAlchemy server URL rather than a local file.
_SERVER_BACKENDS = {
    "postgres": "postgresql+psycopg",
    "mysql": "mysql+pymysql",
    "mssql": "mssql+pyodbc",
}

_DEFAULT_ODBC_DRIVER = "ODBC Driver 18 for SQL Server"

# Lowest-precedence defaults; config files and environment override these.
DEFAULTS = {
    "logging": {
        "level": "INFO",
    },
}


def app_version() -> str:
    """Return the installed package version, or a placeholder when unpackaged."""
    try:
        return version("cognisn-cloudledger")
    except PackageNotFoundError:
        return "0.0.0"


def default_database_path() -> Path:
    """Return the platform-conventional default SQLite database path."""
    return data_dir(APP_ID) / "cloudledger.db"


def _require_setting(settings, key: str) -> str:
    """Return a required setting value, raising ValueError naming the key when absent."""
    value = settings.get(key)
    if not value:
        raise ValueError(f"Missing required setting: {key}")
    return value


def build_database_url(settings, secrets) -> str:
    """Build a SQLAlchemy database URL for a configured server backend.

    Reads the ``database.*`` settings and resolves ``database.password``:
    a value starting with ``secret://`` is looked up in the secrets store
    (the remainder of the URI is the secret name); any other value is used
    literally. The password (and, for mssql, the ODBC driver name) is
    percent-encoded with ``quote_plus`` before assembly. Raises
    ``ValueError`` naming the first missing required setting.
    """
    backend = _require_setting(settings, "database.backend")
    host = _require_setting(settings, "database.host")
    port = _require_setting(settings, "database.port")
    database = _require_setting(settings, "database.database")
    username = _require_setting(settings, "database.username")
    password_setting = _require_setting(settings, "database.password")

    if password_setting.startswith("secret://"):
        secret_name = password_setting[len("secret://") :]
        password = secrets.get(secret_name)
        if password is None:
            raise ValueError(f"Database password secret '{secret_name}' is not set")
    else:
        password = password_setting
    encoded_password = quote_plus(password)

    scheme = _SERVER_BACKENDS.get(backend)
    if scheme is None:
        raise ValueError(f"Unsupported database backend: {backend}")

    url = f"{scheme}://{username}:{encoded_password}@{host}:{port}/{database}"
    if backend == "mssql":
        driver = settings.get("database.odbc_driver", _DEFAULT_ODBC_DRIVER)
        url += f"?driver={quote_plus(driver)}&TrustServerCertificate=yes"
    return url


def resolve_database_target(cli_value: Optional[str], settings, secrets) -> str:
    """Resolve the database target: CLI value, then configured backend, then default.

    An explicit CLI/argv value (a filesystem path or a full URL) passes
    through unchanged. Otherwise, the configured backend decides: a server
    backend builds a SQLAlchemy URL from settings and secrets; ``sqlite``
    uses ``database.path`` when set. Absent any configuration, the
    platform-conventional default SQLite database path is used.
    """
    if cli_value:
        return cli_value
    backend = settings.get("database.backend")
    if backend in _SERVER_BACKENDS:
        return build_database_url(settings, secrets)
    if backend == "sqlite":
        configured = settings.get("database.path")
        if configured:
            return configured
    return str(default_database_path())


def mask_target(target: str) -> str:
    """Return a display-safe form of a resolved database target.

    A SQLAlchemy URL's password component, if present, is replaced with
    ``***`` so the target is safe to log or print. A plain filesystem path,
    or any string SQLAlchemy cannot parse as a URL, is returned unchanged.
    """
    try:
        url = sa.engine.make_url(target)
    except Exception:
        return target
    return url.render_as_string(hide_password=True)


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
