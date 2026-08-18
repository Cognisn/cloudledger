"""Tests for data protection and logging/monitoring checks."""

import json

from cloudledger.assessment.registry import run_checks
from tests.assessment_fixtures import SCAN_ID, make_db, execute


def _category(db_path, category):
    result = run_checks(db_path, SCAN_ID, category=category)
    return {c["check_id"]: c for c in result["categories"].get(category, [])}


def _insert_volume(db_path, volume_id, encrypted):
    execute(
        db_path,
        "INSERT INTO ebs_volumes (scan_id, volume_id, region, size,"
        " volume_type, encrypted, state, create_time, availability_zone)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            volume_id,
            "ap-southeast-2",
            100,
            "gp3",
            encrypted,
            "in-use",
            "2024-01-01T00:00:00+00:00",
            "ap-southeast-2a",
        ),
    )


def _insert_trail(db_path, name, multi_region, is_logging):
    execute(
        db_path,
        "INSERT INTO cloudtrail_trails (scan_id, trail_name, trail_arn,"
        " region, s3_bucket_name, is_multi_region_trail, is_logging)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            name,
            f"arn:aws:cloudtrail:ap-southeast-2:123456789012:trail/{name}",
            "ap-southeast-2",
            "trail-bucket",
            multi_region,
            is_logging,
        ),
    )


def test_unencrypted_ebs_volume_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_volume(db_path, "vol-plain", 0)
    _insert_volume(db_path, "vol-enc", 1)
    checks = _category(db_path, "data_protection")
    check = checks["data.unencrypted_ebs_volumes"]
    assert [f["resource_id"] for f in check["findings"]] == ["vol-plain"]


def test_public_s3_bucket_flags(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO s3_public_access (scan_id, bucket_name,"
        " public_access_block, policy_is_public) VALUES (?, ?, ?, ?)",
        (SCAN_ID, "open-bucket", None, 1),
    )
    checks = _category(db_path, "data_protection")
    public = checks["data.s3_public_buckets"]
    assert [f["resource_id"] for f in public["findings"]] == ["open-bucket"]
    without_pab = checks["data.s3_buckets_without_pab"]
    assert [f["resource_id"] for f in without_pab["findings"]] == ["open-bucket"]


def test_account_pab_missing_flags(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO account_security_posture (scan_id, account_summary,"
        " password_policy_exists, account_public_access_block)"
        " VALUES (?, ?, ?, ?)",
        (SCAN_ID, json.dumps({"AccountMFAEnabled": 1}), 0, None),
    )
    checks = _category(db_path, "data_protection")
    check = checks["data.account_pab_missing"]
    assert check["status"] == "findings"


def test_no_multi_region_trail_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_trail(db_path, "single-region", 0, 1)
    checks = _category(db_path, "logging_monitoring")
    check = checks["logging.no_multi_region_cloudtrail"]
    assert check["status"] == "findings"


def test_multi_region_trail_is_clean(tmp_path):
    db_path = make_db(tmp_path)
    _insert_trail(db_path, "org-trail", 1, 1)
    checks = _category(db_path, "logging_monitoring")
    assert checks["logging.no_multi_region_cloudtrail"]["status"] == "clean"


def test_guardduty_disabled_region_flags(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO region_security_services (scan_id, region,"
        " guardduty_enabled, security_hub_enabled, ebs_encryption_by_default)"
        " VALUES (?, ?, ?, ?, ?)",
        (SCAN_ID, "ap-southeast-2", 0, 0, 0),
    )
    logging_checks = _category(db_path, "logging_monitoring")
    guardduty = logging_checks["logging.guardduty_not_enabled"]
    assert [f["resource_id"] for f in guardduty["findings"]] == ["ap-southeast-2"]
    data_checks = _category(db_path, "data_protection")
    ebs_default = data_checks["data.ebs_default_encryption_off"]
    assert [f["resource_id"] for f in ebs_default["findings"]] == ["ap-southeast-2"]
