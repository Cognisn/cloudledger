"""Tests for per-bucket S3 public access collection."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cloudledger.database.models import S3PublicAccess
from cloudledger.database.operations import DatabaseOperations
from cloudledger.scanner.aws_collector import AWSCollector
from tests.assessment_fixtures import SCAN_ID, make_db, rows


def _make_collector(s3_client):
    collector = AWSCollector.__new__(AWSCollector)
    collector.scan_id = SCAN_ID
    collector.regions = ["ap-southeast-2"]
    session = MagicMock()
    session.client.return_value = s3_client
    collector.session = session
    return collector


def _s3_client():
    client = MagicMock()
    client.list_buckets.return_value = {
        "Buckets": [{"Name": "open-bucket"}, {"Name": "locked-bucket"}]
    }

    def get_pab(Bucket):
        if Bucket == "locked-bucket":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        raise ClientError(
            {
                "Error": {
                    "Code": "NoSuchPublicAccessBlockConfiguration",
                    "Message": "none",
                }
            },
            "GetPublicAccessBlock",
        )

    client.get_public_access_block.side_effect = get_pab

    def get_policy_status(Bucket):
        if Bucket == "open-bucket":
            return {"PolicyStatus": {"IsPublic": True}}
        raise ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "none"}},
            "GetBucketPolicyStatus",
        )

    client.get_bucket_policy_status.side_effect = get_policy_status
    return client


def test_collects_pab_and_policy_status():
    collector = _make_collector(_s3_client())
    records = collector.collect_s3_public_access()
    by_name = {r.bucket_name: r for r in records}
    assert by_name["open-bucket"].public_access_block is None
    assert by_name["open-bucket"].policy_is_public is True
    assert by_name["locked-bucket"].public_access_block["BlockPublicAcls"] is True
    assert by_name["locked-bucket"].policy_is_public is None


def test_insert_and_read_back(tmp_path):
    db_path = make_db(tmp_path)
    DatabaseOperations(db_path).insert_s3_public_access(
        [
            S3PublicAccess(
                scan_id=SCAN_ID,
                bucket_name="open-bucket",
                public_access_block=None,
                policy_is_public=True,
            )
        ]
    )
    stored = rows(db_path, "SELECT * FROM s3_public_access")
    assert stored[0]["bucket_name"] == "open-bucket"
    assert stored[0]["policy_is_public"] == 1
    assert stored[0]["public_access_block"] is None
