"""
Stored-format regression tests: the SQLAlchemy rewrite must keep the exact
value formats the legacy layer wrote (0/1 booleans, JSON text payloads).

Uses Australian English in all documentation and comments.
"""

import json
import sqlite3
from datetime import datetime, UTC
from pathlib import Path

import pytest

from cloudledger.database.models import ScanMetadata, VPC
from cloudledger.database.operations import DatabaseOperations
from cloudledger.database.schema import DatabaseSchema


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "fmt.db")
    DatabaseSchema(path).initialise_database()
    return path


def _fetchone(path, sql):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(sql).fetchone()
    conn.close()
    return row


def test_vpc_stored_formats(db):
    ops = DatabaseOperations(db)
    ops.insert_scan_metadata(
        ScanMetadata(
            scan_id="s1",
            account_name="a",
            account_number="123456789012",
            scan_timestamp=datetime.now(UTC),
            prowler_level="1",
            regions_scanned=["ap-southeast-2"],
            scan_status="in_progress",
        )
    )
    ops.insert_vpcs(
        [
            VPC(
                scan_id="s1",
                vpc_id="vpc-1",
                region="ap-southeast-2",
                cidr_block="10.0.0.0/16",
                state="available",
                is_default=True,
                dhcp_options_id="d-1",
                instance_tenancy="default",
                tags={"Name": "x"},
                raw_data={"VpcId": "vpc-1"},
            )
        ]
    )
    row = _fetchone(db, "SELECT * FROM vpcs")
    assert row["is_default"] == 1                     # boolean stored as integer
    assert json.loads(row["tags"]) == {"Name": "x"}   # JSON stored as text
    assert isinstance(row["tags"], str)
