"""Tests for the shared assessment test fixtures."""

from tests.assessment_fixtures import SCAN_ID, make_db, execute, rows


def test_make_db_creates_schema_with_scan(tmp_path):
    db_path = make_db(tmp_path)
    scans = rows(db_path, "SELECT scan_id FROM scan_metadata")
    assert [r["scan_id"] for r in scans] == [SCAN_ID]


def test_execute_inserts(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO vpcs (scan_id, vpc_id, region, cidr_block, state,"
        " is_default, instance_tenancy) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (SCAN_ID, "vpc-1", "ap-southeast-2", "10.0.0.0/16", "available", 0, "default"),
    )
    assert len(rows(db_path, "SELECT * FROM vpcs")) == 1
