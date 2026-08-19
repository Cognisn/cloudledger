"""
Tests that the security group, VPC and subnet collectors paginate.

Uses Australian English in all documentation and comments.
"""

from unittest.mock import MagicMock

from cloudledger.scanner.aws_collector import AWSCollector


def _collector_with_fake_ec2(paginator_pages_by_op):
    """
    Build an AWSCollector without touching boto3, whose EC2 client
    returns canned paginated pages per operation name.
    """
    collector = AWSCollector.__new__(AWSCollector)
    collector.scan_id = "scan-test"
    collector.regions = ["ap-southeast-2"]

    ec2_client = MagicMock()

    def get_paginator(op_name):
        paginator = MagicMock()
        paginator.paginate.return_value = paginator_pages_by_op[op_name]
        return paginator

    ec2_client.get_paginator.side_effect = get_paginator

    session = MagicMock()
    session.client.return_value = ec2_client
    collector.session = session
    return collector


def test_collect_security_groups_spans_pages():
    pages = [
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-1",
                    "GroupName": "one",
                    "VpcId": "vpc-1",
                    "Description": "first",
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                    "Tags": [],
                },
            ]
        },
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-2",
                    "GroupName": "two",
                    "VpcId": "vpc-1",
                    "Description": "second",
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                    "Tags": [],
                },
            ]
        },
    ]
    collector = _collector_with_fake_ec2({"describe_security_groups": pages})
    groups = collector.collect_security_groups("ap-southeast-2")
    assert [g.group_id for g in groups] == ["sg-1", "sg-2"]


def test_collect_vpcs_spans_pages():
    pages = [
        {
            "Vpcs": [
                {
                    "VpcId": "vpc-1",
                    "CidrBlock": "10.0.0.0/16",
                    "State": "available",
                    "IsDefault": False,
                    "InstanceTenancy": "default",
                    "Tags": [],
                }
            ]
        },
        {
            "Vpcs": [
                {
                    "VpcId": "vpc-2",
                    "CidrBlock": "10.1.0.0/16",
                    "State": "available",
                    "IsDefault": False,
                    "InstanceTenancy": "default",
                    "Tags": [],
                }
            ]
        },
    ]
    collector = _collector_with_fake_ec2({"describe_vpcs": pages})
    vpcs = collector.collect_vpcs("ap-southeast-2")
    assert [v.vpc_id for v in vpcs] == ["vpc-1", "vpc-2"]


def test_collect_subnets_spans_pages():
    pages = [
        {
            "Subnets": [
                {
                    "SubnetId": "subnet-1",
                    "VpcId": "vpc-1",
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": "ap-southeast-2a",
                    "AvailableIpAddressCount": 250,
                    "MapPublicIpOnLaunch": False,
                    "State": "available",
                    "Tags": [],
                }
            ]
        },
        {
            "Subnets": [
                {
                    "SubnetId": "subnet-2",
                    "VpcId": "vpc-1",
                    "CidrBlock": "10.0.2.0/24",
                    "AvailabilityZone": "ap-southeast-2b",
                    "AvailableIpAddressCount": 250,
                    "MapPublicIpOnLaunch": True,
                    "State": "available",
                    "Tags": [],
                }
            ]
        },
    ]
    collector = _collector_with_fake_ec2({"describe_subnets": pages})
    subnets = collector.collect_subnets("ap-southeast-2")
    assert [s.subnet_id for s in subnets] == ["subnet-1", "subnet-2"]
