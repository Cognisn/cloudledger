"""Tests for identity and access checks."""

import json

from cloudledger.assessment.registry import run_checks
from tests.assessment_fixtures import SCAN_ID, make_db, execute


def _insert_posture(db_path, summary, policy=None, policy_exists=False):
    execute(
        db_path,
        "INSERT INTO account_security_posture (scan_id, account_summary,"
        " password_policy, password_policy_exists) VALUES (?, ?, ?, ?)",
        (
            SCAN_ID,
            json.dumps(summary),
            json.dumps(policy) if policy else None,
            1 if policy_exists else 0,
        ),
    )


def _insert_report_row(
    db_path,
    user,
    password_enabled=None,
    mfa_active=0,
    key1_active=0,
    key1_rotated=None,
    password_last_used=None,
    key1_last_used=None,
    created="2020-01-01T00:00:00+00:00",
):
    execute(
        db_path,
        "INSERT INTO iam_credential_report (scan_id, user_name,"
        " user_creation_time, password_enabled, password_last_used,"
        " mfa_active, access_key_1_active, access_key_1_last_rotated,"
        " access_key_1_last_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            user,
            created,
            password_enabled,
            password_last_used,
            mfa_active,
            key1_active,
            key1_rotated,
            key1_last_used,
        ),
    )


def _checks(db_path):
    result = run_checks(db_path, SCAN_ID, category="identity_access")
    evaluated = {
        c["check_id"]: c for c in result["categories"].get("identity_access", [])
    }
    skipped = {c["check_id"]: c for c in result["not_evaluated"]}
    return evaluated, skipped


def test_root_mfa_disabled_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_posture(db_path, {"AccountMFAEnabled": 0})
    evaluated, _ = _checks(db_path)
    check = evaluated["identity.root_mfa_disabled"]
    assert check["status"] == "findings"
    assert check["findings"][0]["resource_id"] == "root"


def test_root_mfa_enabled_is_clean(tmp_path):
    db_path = make_db(tmp_path)
    _insert_posture(db_path, {"AccountMFAEnabled": 1})
    evaluated, _ = _checks(db_path)
    assert evaluated["identity.root_mfa_disabled"]["status"] == "clean"


def test_posture_missing_is_not_evaluated(tmp_path):
    db_path = make_db(tmp_path)
    _, skipped = _checks(db_path)
    assert "identity.root_mfa_disabled" in skipped


def test_weak_password_policy_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_posture(
        db_path,
        {"AccountMFAEnabled": 1},
        policy={"MinimumPasswordLength": 8},
        policy_exists=True,
    )
    evaluated, _ = _checks(db_path)
    check = evaluated["identity.password_policy_missing_or_weak"]
    assert check["status"] == "findings"
    assert check["findings"][0]["evidence"]["minimum_password_length"] == 8


def test_console_user_without_mfa_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_posture(db_path, {"AccountMFAEnabled": 1})
    _insert_report_row(db_path, "alice", password_enabled=1, mfa_active=0)
    _insert_report_row(db_path, "bob", password_enabled=1, mfa_active=1)
    evaluated, _ = _checks(db_path)
    check = evaluated["identity.console_users_without_mfa"]
    assert [f["resource_id"] for f in check["findings"]] == ["alice"]


def test_stale_access_key_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_posture(db_path, {"AccountMFAEnabled": 1})
    _insert_report_row(
        db_path,
        "old-key-user",
        key1_active=1,
        key1_rotated="2020-01-01T00:00:00+00:00",
    )
    evaluated, _ = _checks(db_path)
    check = evaluated["identity.stale_access_keys"]
    assert check["findings"][0]["resource_id"] == "old-key-user"
    assert check["findings"][0]["evidence"]["age_days"] > 90


def test_admin_wildcard_policy_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_posture(db_path, {"AccountMFAEnabled": 1})
    document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    execute(
        db_path,
        "INSERT INTO iam_policies (scan_id, policy_arn, policy_name, policy_id,"
        " path, default_version_id, attachment_count,"
        " permissions_boundary_usage_count, is_attachable, create_date,"
        " update_date, policy_document)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            "arn:aws:iam::123456789012:policy/god",
            "god",
            "ANPAEXAMPLE",
            "/",
            "v1",
            1,
            0,
            1,
            "2020-01-01T00:00:00+00:00",
            "2020-01-01T00:00:00+00:00",
            json.dumps(document),
        ),
    )
    evaluated, _ = _checks(db_path)
    check = evaluated["identity.admin_wildcard_policies"]
    assert check["findings"][0]["resource_id"] == "arn:aws:iam::123456789012:policy/god"
