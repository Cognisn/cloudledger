"""
Interactive setup command for CloudLedger database configuration.

Walks the operator through choosing a database backend, collecting the
required connection details, persisting them via konfig, and verifying
the resulting target before creating the schema.
Uses Australian English in all documentation and comments.
"""

import sys
from typing import Optional, Tuple
from urllib.parse import quote_plus

import click
import sqlalchemy as sa
from konfig.paths import config_dir, default_config_file
from rich.console import Console

from ..config.context import (
    APP_ID,
    _DEFAULT_ODBC_DRIVER,
    create_app_context,
    default_database_path,
    mask_target,
    resolve_database_target,
)
from ..database.engine import make_engine
from ..database.schema import DatabaseSchema

console = Console()

_SECRET_NAME = "cloudledger.db.password"
_BACKENDS = ["sqlite", "postgres", "mysql", "mssql"]
_DEFAULT_PORTS = {"postgres": 5432, "mysql": 3306, "mssql": 1433}


def _ensure_user_config_file_exists() -> None:
    """Create an empty user config file if none exists yet.

    konfig only discovers a config file that is already present on disk;
    persisting a setting for the first time otherwise fails with
    ``RuntimeError`` because no file path is configured for the user
    scope. Creating an empty file up front lets the very first ``setup``
    run persist values successfully.
    """
    if default_config_file(APP_ID) is not None:
        return
    path = config_dir(APP_ID) / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")


def _password_display(ctx) -> str:
    """Return the display string for the stored database password secret.

    A keyring lookup failure (for example a locked or unavailable OS
    keyring) must not crash setup, so it is treated as "not set".
    """
    try:
        stored = ctx.secrets.get(_SECRET_NAME) is not None
    except Exception:
        stored = False
    return "<stored in keyring>" if stored else "<not set>"


def _display_current_config(ctx) -> str:
    """Print the current database configuration and return the current backend."""
    backend = ctx.settings.get("database.backend") or "sqlite"
    console.print("\n[bold]Current configuration[/bold]")
    console.print(f"  Backend: {backend}")
    if backend == "sqlite":
        path = ctx.settings.get("database.path") or str(default_database_path())
        console.print(f"  Path: {path}")
    else:
        console.print(f"  Host: {ctx.settings.get('database.host', '')}")
        console.print(f"  Port: {ctx.settings.get('database.port', '')}")
        console.print(f"  Database: {ctx.settings.get('database.database', '')}")
        console.print(f"  Username: {ctx.settings.get('database.username', '')}")
        console.print(f"  Password: {_password_display(ctx)}")
        if backend == "mssql":
            driver = ctx.settings.get("database.odbc_driver", _DEFAULT_ODBC_DRIVER)
            console.print(f"  ODBC driver: {driver}")
    return backend


def _prompt_sqlite(ctx) -> str:
    """Prompt for the sqlite path, persist it, and return the resolved target."""
    current_path = ctx.settings.get("database.path") or str(default_database_path())
    path = click.prompt("Database file path", default=current_path)
    ctx.settings.set("database.backend", "sqlite", persist="user")
    ctx.settings.set("database.path", path, persist="user")
    return path


def _prompt_server(ctx, backend: str) -> Tuple[str, str]:
    """Prompt for server connection details, persist them, and test-resolve the target.

    Returns the resolved target and the plaintext password, so the caller
    can scrub the raw password from any connection-test error message.
    """
    current_port = ctx.settings.get("database.port") or _DEFAULT_PORTS[backend]
    host = click.prompt(
        "Database host", default=ctx.settings.get("database.host", "localhost")
    )
    port = click.prompt("Database port", default=current_port, type=int)
    database = click.prompt(
        "Database name", default=ctx.settings.get("database.database", "")
    )
    username = click.prompt(
        "Database username", default=ctx.settings.get("database.username", "")
    )
    password = click.prompt(
        "Database password", hide_input=True, confirmation_prompt=True
    )

    ctx.settings.set("database.backend", backend, persist="user")
    ctx.settings.set("database.host", host, persist="user")
    ctx.settings.set("database.port", port, persist="user")
    ctx.settings.set("database.database", database, persist="user")
    ctx.settings.set("database.username", username, persist="user")

    if backend == "mssql":
        current_driver = ctx.settings.get("database.odbc_driver", _DEFAULT_ODBC_DRIVER)
        driver = click.prompt("ODBC driver", default=current_driver)
        ctx.settings.set("database.odbc_driver", driver, persist="user")

    ctx.secrets.set(_SECRET_NAME, password)
    ctx.settings.set("database.password", f"secret://{_SECRET_NAME}", persist="user")

    target = resolve_database_target(None, ctx.settings, ctx.secrets)
    return target, password


def _test_connection(target: str, password: Optional[str]) -> bool:
    """Test the connection to ``target``, returning True on success.

    On failure, prints the masked target, the exception's class name, and
    a masked message. The raw password is scrubbed from the driver's own
    error text (which may embed it) before anything is printed.
    """
    console.print(f"\nTesting connection to {mask_target(target)}...")
    try:
        engine = make_engine(target)
        with engine.connect() as conn:
            conn.execute(sa.text("SELECT 1"))
    except Exception as e:
        message = str(e)
        if password:
            message = message.replace(password, "***")
            message = message.replace(quote_plus(password), "***")
        console.print(f"[red]✗[/red] Connection test failed for {mask_target(target)}")
        console.print(f"[red]{type(e).__name__}:[/red] {message}")
        return False
    console.print("[green]✓[/green] Connection successful")
    return True


@click.command()
def setup_command() -> None:
    """Interactively configure the CloudLedger database connection."""
    _ensure_user_config_file_exists()
    with create_app_context(console_output="none") as ctx:
        current_backend = _display_current_config(ctx)

        backend = click.prompt(
            "\nDatabase backend",
            type=click.Choice(_BACKENDS),
            default=current_backend,
        )

        password: Optional[str] = None
        if backend == "sqlite":
            target = _prompt_sqlite(ctx)
        else:
            target, password = _prompt_server(ctx, backend)

        if not _test_connection(target, password):
            sys.exit(1)

        DatabaseSchema(target).initialise_database()
        console.print(
            f"[green]✓[/green] Database schema created: {mask_target(target)}"
        )
