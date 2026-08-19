"""Tests for the assessment check registry."""

import pytest

from cloudledger.assessment.types import Finding
from cloudledger.assessment.registry import (
    CheckMeta,
    get_catalogue,
    make_result,
    register,
    run_checks,
    CHECKS,
)
from cloudledger.database.engine import make_engine
from tests.assessment_fixtures import SCAN_ID, make_db

TEST_META = CheckMeta(
    check_id="test.always_finds",
    category="identity_access",
    title="Test check",
    detects="A synthetic condition for registry tests",
    default_severity="high",
    recommendation="Do the thing",
    data_dependencies=["scan_metadata"],
)


@pytest.fixture(autouse=True)
def clean_registry():
    """Remove test checks from the shared registry after each test."""
    yield
    CHECKS.pop("test.always_finds", None)
    CHECKS.pop("test.never_ran", None)


def test_register_and_catalogue():
    @register(TEST_META)
    def check(conn, scan_id):
        return make_result(TEST_META)

    entries = [c for c in get_catalogue() if c["check_id"] == "test.always_finds"]
    assert entries[0]["category"] == "identity_access"
    assert entries[0]["default_severity"] == "high"
    assert entries[0]["data_dependencies"] == ["scan_metadata"]


def test_run_checks_groups_by_category_and_status(tmp_path):
    @register(TEST_META)
    def check(conn, scan_id):
        return make_result(
            TEST_META,
            findings=[
                Finding(
                    resource_id="res-1",
                    resource_type="test",
                    region=None,
                    evidence={"why": "because"},
                )
            ],
        )

    engine = make_engine(make_db(tmp_path))
    result = run_checks(engine, SCAN_ID, category="identity_access")
    checks = result["categories"]["identity_access"]
    mine = [c for c in checks if c["check_id"] == "test.always_finds"]
    assert mine[0]["status"] == "findings"
    assert mine[0]["findings"][0]["resource_id"] == "res-1"


def test_not_evaluated_is_surfaced(tmp_path):
    meta = CheckMeta(
        check_id="test.never_ran",
        category="identity_access",
        title="Never ran",
        detects="x",
        default_severity="low",
        recommendation="y",
        data_dependencies=["account_security_posture"],
    )

    @register(meta)
    def check(conn, scan_id):
        return make_result(meta, not_evaluated_reason="posture not collected")

    engine = make_engine(make_db(tmp_path))
    result = run_checks(engine, SCAN_ID, category="identity_access")
    skipped = [c for c in result["not_evaluated"] if c["check_id"] == "test.never_ran"]
    assert skipped[0]["not_evaluated_reason"] == "posture not collected"


def test_latest_scan_resolution_and_unknown_scan(tmp_path):
    engine = make_engine(make_db(tmp_path))
    result = run_checks(engine, None)
    assert result["scan_id"] == SCAN_ID
    with pytest.raises(ValueError):
        run_checks(engine, "no-such-scan")
