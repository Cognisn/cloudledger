"""Tests for per-region security service status collection and storage."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cloudledger.database.models import RegionSecurityServices
from cloudledger.database.operations import DatabaseOperations
from cloudledger.scanner.aws_collector import AWSCollector
from tests.assessment_fixtures import SCAN_ID, make_db, rows


def _make_collector(clients_by_name):
    collector = AWSCollector.__new__(AWSCollector)
    collector.scan_id = SCAN_ID
    collector.regions = ["ap-southeast-2"]
    session = MagicMock()
    session.client.side_effect = lambda name, **kw: clients_by_name[name]
    collector.session = session
    return collector


def _happy_clients():
    guardduty = MagicMock()
    guardduty.list_detectors.return_value = {"DetectorIds": ["det-1"]}
    guardduty.get_detector.return_value = {
        "Status": "ENABLED",
        "FindingPublishingFrequency": "SIX_HOURS",
    }
    securityhub = MagicMock()
    securityhub.describe_hub.return_value = {
        "HubArn": "arn:aws:securityhub:ap-southeast-2:123456789012:hub/default"
    }
    ec2 = MagicMock()
    ec2.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": False}
    analyzer = MagicMock()
    analyzer.list_analyzers.return_value = {
        "analyzers": [{"name": "acct", "type": "ACCOUNT", "status": "ACTIVE"}]
    }
    return {
        "guardduty": guardduty,
        "securityhub": securityhub,
        "ec2": ec2,
        "accessanalyzer": analyzer,
    }


def test_collects_all_service_states():
    collector = _make_collector(_happy_clients())
    record = collector.collect_region_security_services("ap-southeast-2")
    assert record.guardduty_enabled is True
    assert record.security_hub_enabled is True
    assert record.ebs_encryption_by_default is False
    assert record.access_analyzers[0]["name"] == "acct"


def test_security_hub_not_enabled_is_false_not_none():
    clients = _happy_clients()
    clients["securityhub"].describe_hub.side_effect = ClientError(
        {"Error": {"Code": "InvalidAccessException", "Message": "not subscribed"}},
        "DescribeHub",
    )
    collector = _make_collector(clients)
    record = collector.collect_region_security_services("ap-southeast-2")
    assert record.security_hub_enabled is False


def test_access_denied_records_unknown():
    clients = _happy_clients()
    clients["guardduty"].list_detectors.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        "ListDetectors",
    )
    collector = _make_collector(clients)
    record = collector.collect_region_security_services("ap-southeast-2")
    assert record.guardduty_enabled is None


def test_no_guardduty_detector_is_disabled():
    clients = _happy_clients()
    clients["guardduty"].list_detectors.return_value = {"DetectorIds": []}
    collector = _make_collector(clients)
    record = collector.collect_region_security_services("ap-southeast-2")
    assert record.guardduty_enabled is False


def test_insert_and_read_back(tmp_path):
    db_path = make_db(tmp_path)
    DatabaseOperations(db_path).insert_region_security_services(
        [
            RegionSecurityServices(
                scan_id=SCAN_ID,
                region="ap-southeast-2",
                guardduty_enabled=True,
                security_hub_enabled=None,
                ebs_encryption_by_default=False,
                access_analyzers=[{"name": "acct"}],
            )
        ]
    )
    stored = rows(db_path, "SELECT * FROM region_security_services")
    assert stored[0]["guardduty_enabled"] == 1
    assert stored[0]["security_hub_enabled"] is None
    assert stored[0]["ebs_encryption_by_default"] == 0
