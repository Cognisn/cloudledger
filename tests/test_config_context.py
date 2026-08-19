"""
Tests for the konfig application context wiring.

Uses Australian English in all documentation and comments.
"""

import os
from pathlib import Path

from cloudledger.config import context as ctx_mod
from cloudledger.config.context import (
    APP_ID,
    create_app_context,
    default_database_path,
    resolve_database_path,
)


class _FakeSettings:
    """Minimal stand-in exposing the get() surface used by the resolver."""

    def __init__(self, values):
        self._values = values

    def get(self, key, default=None):
        return self._values.get(key, default)


def test_default_database_path_uses_platform_data_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(ctx_mod, "data_dir", lambda app_id: tmp_path / app_id)
    assert default_database_path() == tmp_path / APP_ID / "cloudledger.db"


def test_resolve_database_path_prefers_cli_value():
    settings = _FakeSettings({"database.path": "/configured/db.db"})
    assert resolve_database_path("/cli/db.db", settings) == Path("/cli/db.db")


def test_resolve_database_path_falls_back_to_settings():
    settings = _FakeSettings({"database.path": "/configured/db.db"})
    assert resolve_database_path(None, settings) == Path("/configured/db.db")


def test_resolve_database_path_defaults_to_data_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(ctx_mod, "data_dir", lambda app_id: tmp_path / app_id)
    assert resolve_database_path(None, _FakeSettings({})) == (
        tmp_path / APP_ID / "cloudledger.db"
    )


def test_create_app_context_configures_logging_via_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CLOUDLEDGER__LOGGING__CONSOLE_OUTPUT", raising=False)
    monkeypatch.delenv("CLOUDLEDGER__LOGGING__LEVEL", raising=False)
    with create_app_context(console_output="none", log_level="debug") as ctx:
        assert os.environ["CLOUDLEDGER__LOGGING__CONSOLE_OUTPUT"] == "none"
        assert os.environ["CLOUDLEDGER__LOGGING__LEVEL"] == "DEBUG"
        assert ctx.settings.get("logging.console_output") == "none"
        assert ctx.settings.get("logging.level") == "DEBUG"


def test_create_app_context_level_defaults_to_info(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CLOUDLEDGER__LOGGING__LEVEL", raising=False)
    with create_app_context(console_output="stderr") as ctx:
        assert ctx.settings.get("logging.level") == "INFO"
        assert "CLOUDLEDGER__LOGGING__LEVEL" not in os.environ
