"""
Tests for MCP server start-up path resolution and stdout hygiene.

Uses Australian English in all documentation and comments.
"""

import asyncio

import pytest

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
