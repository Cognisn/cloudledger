"""Tests for the security assessment MCP tools."""

import json

from cloudledger.database.operations import DatabaseOperations
from cloudledger.mcp.queries import QueryHandler
from cloudledger.mcp.tools import get_tools
from tests.assessment_fixtures import SCAN_ID, make_db, execute


def _handler(db_path):
    return QueryHandler(DatabaseOperations(db_path))


def test_tools_are_registered():
    names = {t["name"] for t in get_tools()}
    assert {
        "get_security_assessment_data",
        "analyze_service_exposure",
        "get_security_check_catalogue",
    } <= names
    assessment_tool = next(
        t for t in get_tools() if t["name"] == "get_security_assessment_data"
    )
    assert "advisory" in assessment_tool["description"].lower()


def test_assessment_data_returns_categories_and_coverage(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO account_security_posture (scan_id, account_summary,"
        " password_policy_exists) VALUES (?, ?, ?)",
        (SCAN_ID, json.dumps({"AccountMFAEnabled": 0}), 0),
    )
    result = _handler(db_path).handle_query(
        "get_security_assessment_data", {"scan_id": SCAN_ID}
    )
    assert result["scan_id"] == SCAN_ID
    identity = {c["check_id"]: c for c in result["categories"]["identity_access"]}
    assert identity["identity.root_mfa_disabled"]["status"] == "findings"
    assert isinstance(result["not_evaluated"], list)
    assert result["prowler"]["available"] is False
    assert result["scoring_note"]


def test_assessment_prowler_linkage_counts(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO prowler_findings (scan_id, check_id, check_title,"
        " severity, status, service_name, check_type)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (SCAN_ID, "iam_1", "IAM check", "high", "FAIL", "iam", "security"),
    )
    result = _handler(db_path).handle_query(
        "get_security_assessment_data", {"scan_id": SCAN_ID}
    )
    assert result["prowler"]["available"] is True
    assert result["prowler"]["failed_by_severity"] == {"high": 1}


def test_service_exposure_dispatch(tmp_path):
    db_path = make_db(tmp_path)
    result = _handler(db_path).handle_query(
        "analyze_service_exposure", {"scan_id": SCAN_ID, "service": "ec2"}
    )
    assert list(result["services"].keys()) == ["ec2"]


def test_catalogue_lists_all_checks(tmp_path):
    db_path = make_db(tmp_path)
    result = _handler(db_path).handle_query("get_security_check_catalogue", {})
    ids = {c["check_id"] for c in result["checks"]}
    assert "identity.root_mfa_disabled" in ids
    assert "exposure.ec2_public_instances" in ids
    assert result["count"] == len(result["checks"])


def test_unknown_scan_returns_error_shape(tmp_path):
    db_path = make_db(tmp_path)
    result = _handler(db_path).handle_query(
        "get_security_assessment_data", {"scan_id": "no-such-scan"}
    )
    assert "error" in result
