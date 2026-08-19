"""Tests for the not_applicable / not_evaluated distinction."""

from cloudledger.assessment.registry import dependency_state
from cloudledger.assessment.registry import run_checks
from cloudledger.database.engine import make_engine
from tests.assessment_fixtures import SCAN_ID, make_db, execute


def test_dependency_state_absent_empty_present(tmp_path):
    db_path = make_db(tmp_path)
    engine = make_engine(db_path)
    with engine.connect() as conn:
        # Missing table
        assert dependency_state(conn, ["no_such_table"], SCAN_ID) == "absent"
        # Present but no rows
        assert dependency_state(conn, ["ec2_instances"], SCAN_ID) == "empty"
    execute(
        db_path,
        "INSERT INTO ec2_instances (scan_id, instance_id, region,"
        " instance_type, state, availability_zone, launch_time)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            "i-1",
            "ap-southeast-2",
            "t3.micro",
            "running",
            "ap-southeast-2a",
            "2024-01-01T00:00:00+00:00",
        ),
    )
    with engine.connect() as conn:
        assert dependency_state(conn, ["ec2_instances"], SCAN_ID) == "present"


def test_empty_inventory_check_is_not_applicable(tmp_path):
    """An empty resource table yields not_applicable, counted as covered."""
    db_path = make_db(tmp_path)  # no rds_instances rows
    result = run_checks(make_engine(db_path), SCAN_ID, category="data_protection")
    checks = {c["check_id"]: c for c in result["categories"]["data_protection"]}
    rds = checks["data.unencrypted_rds_instances"]
    assert rds["status"] == "not_applicable"
    assert "none found" in rds["not_applicable_reason"]
    # not_applicable belongs in the category (covered), not the gap list
    assert "data.unencrypted_rds_instances" not in {
        c["check_id"] for c in result["not_evaluated"]
    }
