"""Tests for security group helpers and network exposure checks."""

import json

from cloudledger.assessment.sg_rules import world_open_rules
from cloudledger.assessment.registry import run_checks
from cloudledger.database.engine import make_engine
from tests.assessment_fixtures import SCAN_ID, make_db, execute

SSH_WORLD_OPEN = [
    {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
]
ALL_TRAFFIC_OPEN = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
INTERNAL_ONLY = [
    {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
    }
]


def _insert_sg(db_path, group_id, name, ingress):
    execute(
        db_path,
        "INSERT INTO security_groups (scan_id, group_id, group_name, vpc_id,"
        " region, description, ingress_rules) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            group_id,
            name,
            "vpc-1",
            "ap-southeast-2",
            "test",
            json.dumps(ingress),
        ),
    )


def _checks(db_path):
    result = run_checks(make_engine(db_path), SCAN_ID, category="network_exposure")
    return {c["check_id"]: c for c in result["categories"].get("network_exposure", [])}


def test_world_open_rules_flags_sensitive_port():
    rules = world_open_rules(SSH_WORLD_OPEN)
    assert rules[0]["cidr"] == "0.0.0.0/0"
    assert rules[0]["sensitive_ports"] == [{"port": 22, "service": "SSH"}]


def test_world_open_rules_ignores_internal_cidrs():
    assert world_open_rules(INTERNAL_ONLY) == []


def test_world_open_rules_all_traffic():
    rules = world_open_rules(ALL_TRAFFIC_OPEN)
    assert rules[0]["protocol"] == "-1"
    assert {"port": 22, "service": "SSH"} in rules[0]["sensitive_ports"]


def test_sg_sensitive_port_check_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_sg(db_path, "sg-open", "open", SSH_WORLD_OPEN)
    _insert_sg(db_path, "sg-internal", "internal", INTERNAL_ONLY)
    checks = _checks(db_path)
    check = checks["network.sg_world_open_sensitive_ports"]
    assert [f["resource_id"] for f in check["findings"]] == ["sg-open"]
    assert (
        check["findings"][0]["evidence"]["rules"][0]["sensitive_ports"][0]["service"]
        == "SSH"
    )


def test_default_sg_with_rules_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_sg(db_path, "sg-default", "default", INTERNAL_ONLY)
    checks = _checks(db_path)
    check = checks["network.default_sg_with_rules"]
    assert [f["resource_id"] for f in check["findings"]] == ["sg-default"]


def test_subnet_auto_assign_public_ip_flags(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO subnets (scan_id, subnet_id, vpc_id, region, cidr_block,"
        " availability_zone, available_ip_count, map_public_ip, state)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            "subnet-pub",
            "vpc-1",
            "ap-southeast-2",
            "10.0.1.0/24",
            "ap-southeast-2a",
            250,
            1,
            "available",
        ),
    )
    checks = _checks(db_path)
    check = checks["network.subnets_auto_assign_public_ip"]
    assert [f["resource_id"] for f in check["findings"]] == ["subnet-pub"]


def test_vpc_without_flow_logs_flags(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO vpcs (scan_id, vpc_id, region, cidr_block, state,"
        " is_default, instance_tenancy) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            "vpc-nolog",
            "ap-southeast-2",
            "10.0.0.0/16",
            "available",
            0,
            "default",
        ),
    )
    checks = _checks(db_path)
    check = checks["network.vpcs_without_flow_logs"]
    assert [f["resource_id"] for f in check["findings"]] == ["vpc-nolog"]
