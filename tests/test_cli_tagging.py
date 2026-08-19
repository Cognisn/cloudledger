"""
Tests for CLI scan tagging: the `scan --tag` option and the `tag` command
group (add, remove, list, find).

Uses Australian English in all documentation and comments.
"""

from datetime import datetime, UTC

from click.testing import CliRunner

from cloudledger.database.models import ScanMetadata
from cloudledger.database.operations import DatabaseOperations
from cloudledger.database.schema import DatabaseSchema
from cloudledger.scanner.cli import cli


def _seed_db(tmp_path) -> str:
    """Create a database with one scan (id "s1") and return its path."""
    path = str(tmp_path / "tagging.db")
    DatabaseSchema(path).initialise_database()
    ops = DatabaseOperations(path)
    ops.insert_scan_metadata(
        ScanMetadata(
            scan_id="s1",
            account_name="a",
            account_number="123456789012",
            scan_timestamp=datetime.now(UTC),
            prowler_level="1",
            regions_scanned=["ap-southeast-2"],
            scan_status="completed",
        )
    )
    return path


def test_scan_help_shows_tag_option():
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--tag" in result.output


def test_tag_add_then_list_shows_tags_with_counts(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    db_path = _seed_db(tmp_path)

    add_result = CliRunner().invoke(
        cli, ["tag", "add", "s1", "alpha", "Beta", "--database", db_path]
    )
    assert add_result.exit_code == 0

    list_result = CliRunner().invoke(cli, ["tag", "list", "--database", db_path])
    assert list_result.exit_code == 0
    assert "alpha" in list_result.output
    assert "Beta" in list_result.output
    assert "1" in list_result.output


def test_tag_find_is_case_insensitive(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    db_path = _seed_db(tmp_path)

    CliRunner().invoke(cli, ["tag", "add", "s1", "alpha", "Beta", "--database", db_path])

    find_result = CliRunner().invoke(cli, ["tag", "find", "beta", "--database", db_path])
    assert find_result.exit_code == 0
    assert "s1" in find_result.output


def test_tag_add_reports_missing_database(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    missing = tmp_path / "absent.db"

    result = CliRunner().invoke(
        cli, ["tag", "add", "s1", "x", "--database", str(missing)]
    )
    assert result.exit_code == 1
    assert "database not found" in result.output.lower()


def test_tag_remove_removes_tag(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    db_path = _seed_db(tmp_path)

    CliRunner().invoke(cli, ["tag", "add", "s1", "alpha", "--database", db_path])

    remove_result = CliRunner().invoke(
        cli, ["tag", "remove", "s1", "ALPHA", "--database", db_path]
    )
    assert remove_result.exit_code == 0

    list_result = CliRunner().invoke(cli, ["tag", "list", "--database", db_path])
    assert "alpha" not in list_result.output.lower()


def test_tag_add_unknown_scan_reports_error(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    db_path = _seed_db(tmp_path)

    result = CliRunner().invoke(
        cli, ["tag", "add", "unknown-scan", "x", "--database", db_path]
    )
    assert result.exit_code == 1
    assert "scan not found" in result.output.lower()
