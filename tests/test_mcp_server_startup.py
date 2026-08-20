"""
Tests for MCP server start-up path resolution and stdout hygiene.

Uses Australian English in all documentation and comments.
"""

import asyncio

import pytest

from cloudledger.config.context import app_version
from cloudledger.mcp import server


def test_main_raises_for_missing_explicit_database(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    missing = tmp_path / "absent.db"
    with pytest.raises(FileNotFoundError):
        asyncio.run(server.main(str(missing)))
    # konfig must never write to stdout: it is reserved for MCP JSON-RPC.
    assert capsys.readouterr().out == ""
    # The old bespoke logging module wrote mcp_server.log beside the
    # database path; konfig logging must not do this.
    assert not (missing.parent / "mcp_server.log").exists()


def test_initialization_options_carry_the_cloudledger_version():
    # The handshake must report CloudLedger's version, not the mcp library's.
    options = server.app.create_initialization_options()
    assert options.server_version == app_version()


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_run_help_prints_usage_and_exits_cleanly(flag, capsys):
    with pytest.raises(SystemExit) as excinfo:
        server.run([flag])
    assert excinfo.value.code == 0
    assert "usage" in capsys.readouterr().out.lower()
