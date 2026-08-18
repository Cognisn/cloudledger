"""
Tests for account security posture collection and storage.

Uses Australian English in all documentation and comments.
"""

import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cloudledger.database.models import (
    AccountSecurityPosture,
    IAMCredentialReportEntry,
)
from cloudledger.database.operations import DatabaseOperations
from cloudledger.scanner.aws_collector import AWSCollector
from tests.assessment_fixtures import SCAN_ID, make_db, rows

CREDENTIAL_REPORT_CSV = (
    b"user,arn,user_creation_time,password_enabled,password_last_used,"
    b"mfa_active,access_key_1_active,access_key_1_last_rotated,"
    b"access_key_1_last_used_date,access_key_2_active,"
    b"access_key_2_last_rotated,access_key_2_last_used_date\n"
    b"<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,"
    b"not_supported,2026-01-01T00:00:00+00:00,false,true,"
    b"2020-01-01T00:00:00+00:00,N/A,false,N/A,N/A\n"
    b"alice,arn:aws:iam::123456789012:user/alice,2021-01-01T00:00:00+00:00,"
    b"true,2026-06-01T00:00:00+00:00,true,false,N/A,N/A,false,N/A,N/A\n"
)


def _make_collector(iam_client, s3control_client, sts_client):
    collector = AWSCollector.__new__(AWSCollector)
    collector.scan_id = SCAN_ID
    collector.regions = ["ap-southeast-2"]
    session = MagicMock()
    session.client.side_effect = lambda name, **kw: {
        "iam": iam_client,
        "s3control": s3control_client,
        "sts": sts_client,
    }[name]
    collector.session = session
    return collector


def _happy_clients():
    iam = MagicMock()
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}
    }
    iam.get_account_password_policy.return_value = {
        "PasswordPolicy": {"MinimumPasswordLength": 8}
    }
    iam.generate_credential_report.return_value = {"State": "COMPLETE"}
    iam.get_credential_report.return_value = {"Content": CREDENTIAL_REPORT_CSV}
    s3control = MagicMock()
    s3control.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    return iam, s3control, sts


def test_collects_posture_and_credential_report():
    collector = _make_collector(*_happy_clients())
    posture, entries = collector.collect_account_security_posture()
    assert posture.account_summary["AccountMFAEnabled"] == 0
    assert posture.password_policy_exists is True
    assert posture.password_policy["MinimumPasswordLength"] == 8
    assert posture.account_public_access_block["BlockPublicAcls"] is True
    names = [e.user_name for e in entries]
    assert names == ["<root_account>", "alice"]
    root = entries[0]
    assert root.mfa_active is False
    assert root.access_key_1_active is True
    alice = entries[1]
    assert alice.password_enabled is True
    assert alice.access_key_1_last_rotated is None


def test_missing_password_policy_is_recorded_not_failed():
    iam, s3control, sts = _happy_clients()
    iam.get_account_password_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchEntity", "Message": "no policy"}},
        "GetAccountPasswordPolicy",
    )
    collector = _make_collector(iam, s3control, sts)
    posture, _ = collector.collect_account_security_posture()
    assert posture.password_policy_exists is False
    assert posture.password_policy is None


def test_denied_credential_report_leaves_posture_intact():
    iam, s3control, sts = _happy_clients()
    iam.generate_credential_report.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "GenerateCredentialReport",
    )
    collector = _make_collector(iam, s3control, sts)
    posture, entries = collector.collect_account_security_posture()
    assert posture is not None
    assert entries == []


def test_insert_and_read_back(tmp_path):
    db_path = make_db(tmp_path)
    db_ops = DatabaseOperations(db_path)
    posture = AccountSecurityPosture(
        scan_id=SCAN_ID,
        account_summary={"AccountMFAEnabled": 1},
        password_policy=None,
        password_policy_exists=False,
        account_public_access_block={"BlockPublicAcls": False},
    )
    db_ops.insert_account_security_posture([posture])
    db_ops.insert_iam_credential_report(
        [
            IAMCredentialReportEntry(
                scan_id=SCAN_ID,
                user_name="alice",
                arn="arn:aws:iam::123456789012:user/alice",
                password_enabled=True,
                mfa_active=False,
                access_key_1_active=False,
                access_key_2_active=False,
            )
        ]
    )
    stored = rows(db_path, "SELECT * FROM account_security_posture")
    assert json.loads(stored[0]["account_summary"])["AccountMFAEnabled"] == 1
    assert stored[0]["password_policy_exists"] == 0
    report = rows(db_path, "SELECT * FROM iam_credential_report")
    assert report[0]["user_name"] == "alice"
    assert report[0]["mfa_active"] == 0
