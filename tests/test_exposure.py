"""Tests for service exposure correlations."""

import json

import pytest

from cloudledger.assessment.exposure import run_exposure
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
MYSQL_WORLD_OPEN = [
    {
        "IpProtocol": "tcp",
        "FromPort": 3306,
        "ToPort": 3306,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
]
INTERNAL_ONLY = [
    {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
    }
]


def _insert_sg(db_path, group_id, ingress):
    execute(
        db_path,
        "INSERT INTO security_groups (scan_id, group_id, group_name, vpc_id,"
        " region, description, ingress_rules) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            group_id,
            group_id,
            "vpc-1",
            "ap-southeast-2",
            "test",
            json.dumps(ingress),
        ),
    )


def _insert_instance(db_path, instance_id, public_ip, sg_ids):
    execute(
        db_path,
        "INSERT INTO ec2_instances (scan_id, instance_id, region,"
        " instance_type, state, availability_zone, launch_time, public_ip,"
        " security_groups) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            instance_id,
            "ap-southeast-2",
            "t3.micro",
            "running",
            "ap-southeast-2a",
            "2024-01-01T00:00:00+00:00",
            public_ip,
            json.dumps(sg_ids),
        ),
    )


def test_public_instance_with_open_sg_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_sg(db_path, "sg-open", SSH_WORLD_OPEN)
    _insert_sg(db_path, "sg-closed", INTERNAL_ONLY)
    _insert_instance(db_path, "i-exposed", "3.3.3.3", ["sg-open"])
    _insert_instance(db_path, "i-shielded", "4.4.4.4", ["sg-closed"])
    _insert_instance(db_path, "i-private", None, ["sg-open"])
    result = run_exposure(make_engine(db_path), SCAN_ID, service="ec2")
    findings = result["services"]["ec2"]["findings"]
    assert [f["resource_id"] for f in findings] == ["i-exposed"]
    evidence = findings[0]["evidence"]
    assert evidence["public_ip"] == "3.3.3.3"
    assert evidence["open_security_groups"][0]["group_id"] == "sg-open"
    assert (
        evidence["open_security_groups"][0]["rules"][0]["sensitive_ports"][0]["service"]
        == "SSH"
    )


def test_lambda_none_auth_url_flags(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO lambda_exposure (scan_id, region, function_name,"
        " function_arn, url_auth_type, resource_policy)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (SCAN_ID, "ap-southeast-2", "open-fn", "arn:open-fn", "NONE", None),
    )
    execute(
        db_path,
        "INSERT INTO lambda_exposure (scan_id, region, function_name,"
        " function_arn, url_auth_type, resource_policy)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            "ap-southeast-2",
            "star-fn",
            "arn:star-fn",
            None,
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "lambda:InvokeFunction",
                        }
                    ]
                }
            ),
        ),
    )
    result = run_exposure(make_engine(db_path), SCAN_ID, service="lambda")
    findings = result["services"]["lambda"]["findings"]
    ids = {f["resource_id"] for f in findings}
    assert ids == {"open-fn", "star-fn"}


def test_public_rds_with_open_port_flags(tmp_path):
    db_path = make_db(tmp_path)
    _insert_sg(db_path, "sg-db", MYSQL_WORLD_OPEN)
    execute(
        db_path,
        "INSERT INTO rds_instances (scan_id, db_instance_identifier, region,"
        " db_instance_arn, engine, engine_version, db_instance_class,"
        " allocated_storage, storage_type, multi_az, publicly_accessible,"
        " encrypted, backup_retention_period, db_instance_status,"
        " endpoint_port, vpc_security_groups)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            "db-open",
            "ap-southeast-2",
            "arn:aws:rds:ap-southeast-2:123456789012:db:db-open",
            "mysql",
            "8.0",
            "db.t3.micro",
            20,
            "gp3",
            0,
            1,
            1,
            7,
            "available",
            3306,
            json.dumps(["sg-db"]),
        ),
    )
    result = run_exposure(make_engine(db_path), SCAN_ID, service="databases")
    findings = result["services"]["databases"]["findings"]
    assert findings[0]["resource_id"] == "db-open"
    assert findings[0]["evidence"]["port_world_open"] is True


def test_entry_points_inventory(tmp_path):
    db_path = make_db(tmp_path)
    execute(
        db_path,
        "INSERT INTO load_balancers (scan_id, load_balancer_name,"
        " load_balancer_arn, load_balancer_type, region, scheme, state,"
        " dns_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            SCAN_ID,
            "public-alb",
            "arn:aws:elasticloadbalancing:ap-southeast-2:123456789012:loadbalancer/app/public-alb/abc",
            "application",
            "ap-southeast-2",
            "internet-facing",
            "active",
            "public-alb.example.aws",
        ),
    )
    result = run_exposure(make_engine(db_path), SCAN_ID, service="entry_points")
    findings = result["services"]["entry_points"]["findings"]
    assert findings[0]["resource_id"] == "public-alb"
    assert findings[0]["evidence"]["entry_point_type"] == "load_balancer"


def test_unknown_service_raises(tmp_path):
    db_path = make_db(tmp_path)
    with pytest.raises(ValueError):
        run_exposure(make_engine(db_path), SCAN_ID, service="mainframe")


def test_missing_table_degrades_to_not_evaluated(tmp_path):
    """
    A scan taken before this feature lacks the new tables. An absent table is
    a genuine coverage gap: the service degrades to not_evaluated (with a
    'scan predates this data' reason), not a sunk call.
    """
    db_path = make_db(tmp_path)
    with __import__("sqlite3").connect(db_path) as conn:
        conn.execute("DROP TABLE lambda_exposure")
        conn.commit()
    result = run_exposure(make_engine(db_path), SCAN_ID, service="lambda")
    assert result["services"]["lambda"]["status"] == "not_evaluated"
    assert (
        "scan predates this data"
        in result["services"]["lambda"]["not_evaluated_reason"]
    )


def test_empty_table_is_not_applicable(tmp_path):
    """
    A present-but-empty table means the collector ran and the account has none
    of the resource: not_applicable (scanned, none found), not a coverage gap.
    """
    db_path = make_db(tmp_path)  # fresh schema, no lambda_exposure rows
    result = run_exposure(make_engine(db_path), SCAN_ID, service="lambda")
    svc = result["services"]["lambda"]
    assert svc["status"] == "not_applicable"
    assert "none found" in svc["not_applicable_reason"]
