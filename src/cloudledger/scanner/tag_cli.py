"""
CLI commands for retrospective scan tagging.

Provides the `tag` command group: add, remove, list, and find. Uses
Australian English in all documentation and comments.
"""

import sys
from pathlib import Path
from typing import Tuple

import click
from rich.console import Console
from rich.table import Table

from ..config.context import create_app_context, mask_target, resolve_database_target
from ..database.operations import DatabaseOperations
from ..database.schema import DatabaseSchema

console = Console()


def _open_database(database: str) -> DatabaseOperations:
    """Resolve the database target, verify it exists, and return operations.

    Mirrors the pattern used by `delete_scan`: an explicit or configured
    target is resolved via konfig, existence is checked for local SQLite
    files only, and any displayed target is masked.
    """
    if "://" not in database and not Path(database).exists():
        console.print(f"[red]✗[/red] Database not found: {mask_target(database)}")
        sys.exit(1)

    db_schema = DatabaseSchema(database)
    db_schema.initialise_database()
    return DatabaseOperations(database)


@click.group(name="tag")
def tag_group():
    """Manage tags on scans."""
    pass


@tag_group.command(name="add")
@click.argument("scan_id", metavar="SCAN_ID")
@click.argument("tags", metavar="TAG...", nargs=-1, required=True)
@click.option(
    "--database",
    default=None,
    type=click.Path(),
    help="Path to SQLite database file (default: configured or platform data location)",
)
def add(scan_id: str, tags: Tuple[str, ...], database: str):
    """Add one or more tags to a scan."""
    with create_app_context(console_output="none") as ctx:
        database = resolve_database_target(database, ctx.settings, ctx.secrets)
        db_ops = _open_database(database)

        try:
            added = db_ops.add_tags(scan_id, list(tags))
        except ValueError as e:
            console.print(f"[red]✗[/red] {e}")
            sys.exit(1)

        if added:
            console.print(f"[green]✓[/green] Added tags: {', '.join(added)}")
        else:
            console.print("[yellow]No new tags added (all were duplicates or empty)[/yellow]")


@tag_group.command(name="remove")
@click.argument("scan_id", metavar="SCAN_ID")
@click.argument("tags", metavar="TAG...", nargs=-1, required=True)
@click.option(
    "--database",
    default=None,
    type=click.Path(),
    help="Path to SQLite database file (default: configured or platform data location)",
)
def remove(scan_id: str, tags: Tuple[str, ...], database: str):
    """Remove one or more tags from a scan."""
    with create_app_context(console_output="none") as ctx:
        database = resolve_database_target(database, ctx.settings, ctx.secrets)
        db_ops = _open_database(database)

        removed_count = db_ops.remove_tags(scan_id, list(tags))
        console.print(f"[green]✓[/green] Removed {removed_count} tag(s) from scan {scan_id}")


@tag_group.command(name="list")
@click.option(
    "--database",
    default=None,
    type=click.Path(),
    help="Path to SQLite database file (default: configured or platform data location)",
)
def list_cmd(database: str):
    """List all tags in use, with the number of scans carrying each."""
    with create_app_context(console_output="none") as ctx:
        database = resolve_database_target(database, ctx.settings, ctx.secrets)
        db_ops = _open_database(database)

        tags = db_ops.list_tags()

        if not tags:
            console.print("[yellow]No tags found in database.[/yellow]")
            return

        table = Table(title="Tags")
        table.add_column("Tag", style="cyan")
        table.add_column("Scan Count", justify="right", style="green")

        for entry in tags:
            table.add_row(entry["tag"], str(entry["scan_count"]))

        console.print(table)


@tag_group.command(name="find")
@click.argument("tag", metavar="TAG")
@click.option(
    "--database",
    default=None,
    type=click.Path(),
    help="Path to SQLite database file (default: configured or platform data location)",
)
def find(tag: str, database: str):
    """Find scans carrying the given tag (case-insensitive)."""
    with create_app_context(console_output="none") as ctx:
        database = resolve_database_target(database, ctx.settings, ctx.secrets)
        db_ops = _open_database(database)

        scans = db_ops.find_scans_by_tag(tag)

        if not scans:
            console.print(f"[yellow]No scans found with tag '{tag}'.[/yellow]")
            return

        table = Table(title=f"Scans tagged '{tag}'")
        table.add_column("Scan ID", style="yellow")
        table.add_column("Account Name", style="green")
        table.add_column("Account Number", style="blue")
        table.add_column("Timestamp", style="magenta")
        table.add_column("Status", style="white")
        table.add_column("Tags", style="cyan")

        for scan in scans:
            table.add_row(
                scan["scan_id"],
                scan.get("account_name", "N/A"),
                scan.get("account_number", "N/A"),
                str(scan.get("scan_timestamp", "N/A")),
                scan.get("scan_status", "N/A"),
                ", ".join(scan.get("tags", [])),
            )

        console.print(table)
