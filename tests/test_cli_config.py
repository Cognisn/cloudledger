"""
Tests for CLI database-path resolution and konfig wiring.

Uses Australian English in all documentation and comments.
"""

from click.testing import CliRunner

from cloudledger.scanner.cli import cli


def test_scan_database_option_is_optional():
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--database" in result.output
    assert "[required]" not in result.output


def test_delete_scan_database_option_is_optional():
    result = CliRunner().invoke(cli, ["delete-scan", "--help"])
    assert result.exit_code == 0
    assert "--database" in result.output
    assert "[required]" not in result.output


def test_delete_scan_reports_missing_database(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    missing = tmp_path / "absent.db"
    result = CliRunner().invoke(cli, ["delete-scan", "--database", str(missing)])
    assert result.exit_code == 1
    assert "database not found" in result.output.lower()
