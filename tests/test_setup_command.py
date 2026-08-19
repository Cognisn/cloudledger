"""
Tests for the interactive ``cloudledger setup`` command.

Uses Australian English in all documentation and comments.
"""

import socket

import yaml
from click.testing import CliRunner
from konfig.paths import config_dir

from cloudledger.database.schema import DatabaseSchema
from cloudledger.scanner import setup_cmd as setup_cmd_mod
from cloudledger.scanner.cli import cli

_SECRET_NAME = "cloudledger.db.password"


def _unused_local_port() -> int:
    """Return a TCP port on localhost with nothing listening on it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _RecordingSettings:
    """Minimal settings stand-in that records what is persisted."""

    def __init__(self, values=None):
        self._values = dict(values or {})
        self.persisted = {}

    def get(self, key, default=None):
        return self._values.get(key, default)

    def set(self, key, value, *, persist=None):
        self._values[key] = value
        if persist:
            self.persisted[key] = value


class _RecordingSecrets:
    """Minimal secrets stand-in that records what is stored."""

    def __init__(self):
        self.stored = {}

    def get(self, key):
        return self.stored.get(key)

    def set(self, key, value):
        self.stored[key] = value


class _FakeAppContext:
    """Context-manager stub exposing recorder settings/secrets."""

    def __init__(self, settings, secrets):
        self.settings = settings
        self.secrets = secrets

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_setup_help_exits_zero():
    result = CliRunner().invoke(cli, ["setup", "--help"])
    assert result.exit_code == 0
    assert "setup" in result.output.lower()


def test_setup_sqlite_flow_creates_schema_and_persists_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    db_path = tmp_path / "data" / "mydb.sqlite"

    result = CliRunner().invoke(cli, ["setup"], input=f"sqlite\n{db_path}\n")

    assert result.exit_code == 0, result.output
    assert "schema created" in result.output.lower()

    # Schema was actually created at the chosen path.
    assert db_path.exists()
    assert DatabaseSchema(str(db_path)).get_schema_version() == 1

    # Non-secret settings were persisted to the user config file.
    config_file = config_dir("cloudledger") / "config.yaml"
    assert config_file.exists()
    data = yaml.safe_load(config_file.read_text())
    assert data["database"]["backend"] == "sqlite"
    assert data["database"]["path"] == str(db_path)


def test_setup_sqlite_rerun_reuses_current_path_as_default(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    db_path = tmp_path / "data" / "mydb.sqlite"

    first = CliRunner().invoke(cli, ["setup"], input=f"sqlite\n{db_path}\n")
    assert first.exit_code == 0, first.output

    # Re-running with blank input accepts the previously configured backend
    # and path as prompt defaults.
    second = CliRunner().invoke(cli, ["setup"], input="\n\n")
    assert second.exit_code == 0, second.output
    assert str(db_path) in second.output


def test_setup_server_flow_reports_connection_failure_and_masks_password(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    settings = _RecordingSettings()
    secrets = _RecordingSecrets()

    def fake_create_app_context(*, console_output, log_level=None):
        return _FakeAppContext(settings, secrets)

    monkeypatch.setattr(setup_cmd_mod, "create_app_context", fake_create_app_context)

    unreachable_port = _unused_local_port()
    password = "s3cr3t-p@ss"

    user_input = "\n".join(
        [
            "postgres",
            "localhost",
            str(unreachable_port),
            "clouddb",
            "cluser",
            password,
            password,
        ]
    ) + "\n"

    result = CliRunner().invoke(cli, ["setup"], input=user_input)

    assert result.exit_code == 1
    assert "connection" in result.output.lower()
    assert "schema created" not in result.output.lower()

    # The raw password never appears in any printed output.
    assert password not in result.output

    # Settings and secrets were still persisted before the failed test.
    assert secrets.stored[_SECRET_NAME] == password
    assert settings.persisted["database.password"] == f"secret://{_SECRET_NAME}"
    assert settings.persisted["database.backend"] == "postgres"
    assert settings.persisted["database.host"] == "localhost"
    assert settings.persisted["database.port"] == unreachable_port
