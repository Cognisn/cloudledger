"""
Opt-in integration tests against real server backends.

These tests are excluded from the default run (see the `db` marker in
`pyproject.toml`) and only exercise a database that is genuinely reachable:
`_reachable` skips the test outright when the connection attempt fails for
any reason, including a driver that is not installed. Bring the fixture
containers up first with `docker compose up -d` (see `docker-compose.yml`),
then run `uv run pytest -m db`.

Each backend URL is built through `build_database_url` against fake
settings/secrets stand-ins so the builder itself gets exercised end to end,
not just the round trip that follows. Uses Australian English in all
documentation and comments.
"""

from datetime import datetime

import pytest

from cloudledger.config.context import build_database_url
from cloudledger.database.engine import make_engine
from cloudledger.database.models import ScanMetadata, VPC
from cloudledger.database.operations import DatabaseOperations
from cloudledger.database.schema import DatabaseSchema
from cloudledger.database.tables import metadata
from cloudledger.mcp.queries import QueryHandler

pytestmark = pytest.mark.db


class _FakeSettings:
    """Minimal stand-in exposing the get() surface used by the URL builder."""

    def __init__(self, values):
        self._values = values

    def get(self, key, default=None):
        return self._values.get(key, default)


class _FakeSecrets:
    """Minimal stand-in exposing the get() surface used by the URL builder."""

    def __init__(self, values):
        self._values = values

    def get(self, name):
        return self._values.get(name)


# Fixed literals -- nothing here is derived from the current clock.
SCAN_ID = "integration-scan-001"
ACCOUNT_NAME = "Integration Test Account"
ACCOUNT_NUMBER = "111122223333"
SCAN_TIMESTAMP = datetime.fromisoformat("2026-08-01T00:00:00+00:00")
VPC_ID = "vpc-integration-001"
REGION = "ap-southeast-2"
CIDR_BLOCK = "10.0.0.0/16"

# Ports match the fixture services in docker-compose.yml.
POSTGRES_URL = build_database_url(
    _FakeSettings(
        {
            "database.backend": "postgres",
            "database.host": "localhost",
            "database.port": 55432,
            "database.database": "cloudledger",
            "database.username": "cloudledger",
            "database.password": "secret://cloudledger.integration.password",
        }
    ),
    _FakeSecrets({"cloudledger.integration.password": "cloudledger"}),
)

MYSQL_URL = build_database_url(
    _FakeSettings(
        {
            "database.backend": "mysql",
            "database.host": "localhost",
            "database.port": 53306,
            "database.database": "cloudledger",
            "database.username": "cloudledger",
            "database.password": "secret://cloudledger.integration.password",
        }
    ),
    _FakeSecrets({"cloudledger.integration.password": "cloudledger"}),
)

# mssql: no fixture database is created by docker-compose.yml (only the SA
# login), so the round trip runs against the server's built-in `master`
# database. TrustServerCertificate handling comes from build_database_url
# itself, exercising that part of the builder too.
MSSQL_URL = build_database_url(
    _FakeSettings(
        {
            "database.backend": "mssql",
            "database.host": "localhost",
            "database.port": 51433,
            "database.database": "master",
            "database.username": "sa",
            "database.password": "CloudLedger!Test1",
        }
    ),
    _FakeSecrets({}),
)


def _reachable(url: str) -> None:
    """Skip the calling test unless `url` is genuinely connectable.

    Catches any exception -- a missing driver import, an unreachable host,
    authentication failure, and so on -- and turns it into a skip rather
    than a failure, so the opt-in suite is silent when no containers are
    running.
    """
    try:
        engine = make_engine(url)
        with engine.connect():
            pass
    except (
        Exception
    ) as exc:  # noqa: BLE001 - deliberately broad: any failure means skip
        pytest.skip(f"backend not reachable: {exc}")


@pytest.mark.parametrize(
    "url",
    [POSTGRES_URL, MYSQL_URL, MSSQL_URL],
    ids=["postgres", "mysql", "mssql"],
)
def test_backend_round_trip(url):
    """Initialise the schema, insert fixture rows, and query them back."""
    _reachable(url)

    db_ops = DatabaseOperations(url)
    try:
        DatabaseSchema(url).initialise_database()

        db_ops.insert_scan_metadata(
            ScanMetadata(
                scan_id=SCAN_ID,
                account_name=ACCOUNT_NAME,
                account_number=ACCOUNT_NUMBER,
                scan_timestamp=SCAN_TIMESTAMP,
                prowler_level="2",
                regions_scanned=[REGION],
                scan_status="completed",
                scan_duration_seconds=42.0,
            )
        )
        db_ops.insert_vpcs(
            [
                VPC(
                    scan_id=SCAN_ID,
                    vpc_id=VPC_ID,
                    region=REGION,
                    cidr_block=CIDR_BLOCK,
                    state="available",
                    is_default=False,
                    instance_tenancy="default",
                    tags={"Name": "integration-vpc"},
                )
            ]
        )

        handler = QueryHandler(db_ops)

        scans_result = handler.handle_query("list_scans", {})
        assert any(scan["scan_id"] == SCAN_ID for scan in scans_result["scans"])

        vpc_result = handler.handle_query("get_vpc_architecture", {"vpc_id": VPC_ID})
        assert vpc_result["vpc"]["vpc_id"] == VPC_ID
        assert vpc_result["vpc"]["cidr_block"] == CIDR_BLOCK
        assert vpc_result["vpc"]["region"] == REGION
    finally:
        metadata.drop_all(db_ops.engine)
