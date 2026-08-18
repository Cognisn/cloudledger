"""Tests for Lambda exposure (function URLs and resource policies) collection."""

import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cloudledger.database.models import LambdaExposure
from cloudledger.database.operations import DatabaseOperations
from cloudledger.scanner.aws_collector import AWSCollector
from tests.assessment_fixtures import SCAN_ID, make_db, rows


def _make_collector(lambda_client):
    collector = AWSCollector.__new__(AWSCollector)
    collector.scan_id = SCAN_ID
    collector.regions = ["ap-southeast-2"]
    session = MagicMock()
    session.client.return_value = lambda_client
    collector.session = session
    return collector


def _lambda_client():
    client = MagicMock()
    functions_page = {
        "Functions": [
            {
                "FunctionName": "public-fn",
                "FunctionArn": "arn:aws:lambda:ap-southeast-2:123456789012:function:public-fn",
            },
            {
                "FunctionName": "private-fn",
                "FunctionArn": "arn:aws:lambda:ap-southeast-2:123456789012:function:private-fn",
            },
        ]
    }
    fn_paginator = MagicMock()
    fn_paginator.paginate.return_value = [functions_page]
    client.get_paginator.return_value = fn_paginator

    def url_configs(FunctionName):
        if FunctionName == "public-fn":
            return {
                "FunctionUrlConfigs": [
                    {
                        "AuthType": "NONE",
                        "FunctionUrl": "https://abc.lambda-url.ap-southeast-2.on.aws/",
                    }
                ]
            }
        return {"FunctionUrlConfigs": []}

    client.list_function_url_configs.side_effect = url_configs

    def get_policy(FunctionName):
        if FunctionName == "public-fn":
            return {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "lambda:InvokeFunctionUrl",
                            }
                        ]
                    }
                )
            }
        raise ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "no policy"}},
            "GetPolicy",
        )

    client.get_policy.side_effect = get_policy
    return client


def test_collects_url_config_and_policy():
    collector = _make_collector(_lambda_client())
    records = collector.collect_lambda_exposure("ap-southeast-2")
    by_name = {r.function_name: r for r in records}
    assert by_name["public-fn"].url_auth_type == "NONE"
    assert by_name["public-fn"].resource_policy["Statement"][0]["Principal"] == "*"
    assert by_name["private-fn"].url_auth_type is None
    assert by_name["private-fn"].resource_policy is None


def test_insert_and_read_back(tmp_path):
    db_path = make_db(tmp_path)
    DatabaseOperations(db_path).insert_lambda_exposure(
        [
            LambdaExposure(
                scan_id=SCAN_ID,
                region="ap-southeast-2",
                function_name="public-fn",
                function_arn="arn:aws:lambda:ap-southeast-2:123456789012:function:public-fn",
                url_config={"AuthType": "NONE"},
                url_auth_type="NONE",
                resource_policy={"Statement": []},
            )
        ]
    )
    stored = rows(db_path, "SELECT * FROM lambda_exposure")
    assert stored[0]["url_auth_type"] == "NONE"
    assert json.loads(stored[0]["url_config"])["AuthType"] == "NONE"
