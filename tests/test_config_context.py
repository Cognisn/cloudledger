"""
Tests for the konfig application context wiring.

Uses Australian English in all documentation and comments.
"""

import os

import pytest

from cloudledger.config import context as ctx_mod
from cloudledger.config.context import (
    APP_ID,
    build_database_url,
    create_app_context,
    default_database_path,
    mask_target,
    resolve_database_target,
)


class _FakeSettings:
    """Minimal stand-in exposing the get() surface used by the resolver."""

    def __init__(self, values):
        self._values = values

    def get(self, key, default=None):
        return self._values.get(key, default)


class _FakeSecrets:
    """Minimal stand-in exposing the get() surface used by the resolver."""

    def __init__(self, values):
        self._values = values

    def get(self, name):
        return self._values.get(name)


def test_default_database_path_uses_platform_data_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(ctx_mod, "data_dir", lambda app_id: tmp_path / app_id)
    assert default_database_path() == tmp_path / APP_ID / "cloudledger.db"


def test_resolve_target_prefers_cli_value():
    settings = _FakeSettings({"database.path": "/configured/db.db"})
    assert (
        resolve_database_target("/cli/db.db", settings, _FakeSecrets({}))
        == "/cli/db.db"
    )


def test_resolve_target_falls_back_to_settings():
    settings = _FakeSettings(
        {"database.backend": "sqlite", "database.path": "/configured/db.db"}
    )
    assert (
        resolve_database_target(None, settings, _FakeSecrets({})) == "/configured/db.db"
    )


def test_resolve_target_defaults_to_data_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(ctx_mod, "data_dir", lambda app_id: tmp_path / app_id)
    assert resolve_database_target(None, _FakeSettings({}), _FakeSecrets({})) == (
        str(tmp_path / APP_ID / "cloudledger.db")
    )


def test_build_url_postgres():
    settings = _FakeSettings(
        {
            "database.backend": "postgres",
            "database.host": "db.example.com",
            "database.port": 5432,
            "database.database": "ledger",
            "database.username": "cl",
            "database.password": "secret://cloudledger.db.password",
        }
    )
    secrets = _FakeSecrets({"cloudledger.db.password": "p@ss w0rd"})
    assert build_database_url(settings, secrets) == (
        "postgresql+psycopg://cl:p%40ss+w0rd@db.example.com:5432/ledger"
    )


def test_build_url_postgres_literal_password():
    settings = _FakeSettings(
        {
            "database.backend": "postgres",
            "database.host": "db.example.com",
            "database.port": 5432,
            "database.database": "ledger",
            "database.username": "cl",
            "database.password": "literalpw",
        }
    )
    assert build_database_url(settings, _FakeSecrets({})) == (
        "postgresql+psycopg://cl:literalpw@db.example.com:5432/ledger"
    )


def test_build_url_mssql_includes_driver():
    settings = _FakeSettings(
        {
            "database.backend": "mssql",
            "database.host": "h",
            "database.port": 1433,
            "database.database": "d",
            "database.username": "u",
            "database.password": "secret://cloudledger.db.password",
        }
    )
    secrets = _FakeSecrets({"cloudledger.db.password": "x"})
    url = build_database_url(settings, secrets)
    assert url.startswith("mssql+pyodbc://u:x@h:1433/d?driver=ODBC+Driver+18")
    assert "TrustServerCertificate=yes" in url


def test_resolve_target_cli_wins():
    assert (
        resolve_database_target("/tmp/x.db", _FakeSettings({}), _FakeSecrets({}))
        == "/tmp/x.db"
    )


def test_resolve_target_url_backend(monkeypatch):
    settings = _FakeSettings(
        {
            "database.backend": "mysql",
            "database.host": "h",
            "database.port": 3306,
            "database.database": "d",
            "database.username": "u",
            "database.password": "secret://cloudledger.db.password",
        }
    )
    assert resolve_database_target(
        None, settings, _FakeSecrets({"cloudledger.db.password": "p"})
    ) == ("mysql+pymysql://u:p@h:3306/d")


def test_resolve_target_sqlite_default(monkeypatch, tmp_path):
    monkeypatch.setattr(ctx_mod, "data_dir", lambda app_id: tmp_path / app_id)
    assert resolve_database_target(None, _FakeSettings({}), _FakeSecrets({})) == (
        str(tmp_path / APP_ID / "cloudledger.db")
    )


def test_build_url_missing_secret_raises():
    settings = _FakeSettings(
        {
            "database.backend": "postgres",
            "database.host": "db.example.com",
            "database.port": 5432,
            "database.database": "ledger",
            "database.username": "cl",
            "database.password": "secret://cloudledger.db.password",
        }
    )
    with pytest.raises(ValueError, match="cloudledger.db.password"):
        build_database_url(settings, _FakeSecrets({}))


def test_mask_target_hides_password_in_url():
    url = "postgresql+psycopg://cl:p%40ss+w0rd@db.example.com:5432/ledger"
    masked = mask_target(url)
    assert "p%40ss" not in masked
    assert "***" in masked
    assert masked.startswith("postgresql+psycopg://cl:***@db.example.com:5432/ledger")


def test_mask_target_returns_plain_path_unchanged():
    assert mask_target("/tmp/x.db") == "/tmp/x.db"


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
