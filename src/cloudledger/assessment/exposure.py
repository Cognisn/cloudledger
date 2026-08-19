"""
Service exposure correlations: the cross-resource evidence chains that
single-table checks cannot see.

Security group references on EC2 instances, RDS instances and ElastiCache
clusters are stored as plain lists of group ID strings by the collectors.
Uses Australian English in all documentation and comments.
"""

import json
from typing import Dict, List, Optional

import sqlalchemy as sa

from .registry import (
    CheckMeta,
    make_result,
    make_not_applicable,
    register,
    resolve_scan_id,
    dependency_state,
    CHECKS,
)
from .sg_rules import world_open_rules
from .types import Finding


def _world_rules_by_group(conn, scan_id) -> Dict[str, list]:
    """Map of security group id to its world-open ingress rules."""
    result = {}
    for row in conn.execute(
        sa.text(
            "SELECT group_id, ingress_rules FROM security_groups"
            " WHERE scan_id = :scan_id"
        ),
        {"scan_id": scan_id},
    ).mappings():
        ingress = json.loads(row["ingress_rules"]) if row["ingress_rules"] else []
        rules = world_open_rules(ingress)
        if rules:
            result[row["group_id"]] = rules
    return result


def _group_ids(stored: Optional[str]) -> List[str]:
    """Parse a stored security group reference list (plain ID strings)."""
    if not stored:
        return []
    try:
        parsed = json.loads(stored)
    except (TypeError, ValueError):
        return []
    ids = []
    for item in parsed:
        if isinstance(item, str):
            ids.append(item)
        elif isinstance(item, dict):
            ids.append(
                item.get("GroupId")
                or item.get("VpcSecurityGroupId")
                or item.get("SecurityGroupId")
            )
    return [i for i in ids if i]


EC2_PUBLIC = CheckMeta(
    check_id="exposure.ec2_public_instances",
    category="service_exposure",
    title="EC2 instances reachable from the internet",
    detects="Running instances with public IPs whose attached security groups admit internet traffic",
    default_severity="high",
    recommendation="Remove public IPs where possible; restrict security group ingress to known sources",
    data_dependencies=["ec2_instances", "security_groups"],
)


@register(EC2_PUBLIC)
def check_ec2_public(conn, scan_id):
    state = dependency_state(conn, ["ec2_instances"], scan_id)
    if state == "absent":
        return make_result(
            EC2_PUBLIC,
            not_evaluated_reason="ec2_instances not collected (scan predates this data)",
        )
    if state == "empty":
        return make_not_applicable(
            EC2_PUBLIC, "no EC2 instances in this account (scanned, none found)"
        )
    open_groups = _world_rules_by_group(conn, scan_id)
    findings = []
    instance_rows = conn.execute(
        sa.text(
            "SELECT instance_id, region, public_ip, security_groups, state"
            " FROM ec2_instances WHERE scan_id = :scan_id AND public_ip IS NOT NULL"
            " AND public_ip != ''"
        ),
        {"scan_id": scan_id},
    ).mappings()
    for row in instance_rows:
        exposed = [
            {"group_id": group_id, "rules": open_groups[group_id]}
            for group_id in _group_ids(row["security_groups"])
            if group_id in open_groups
        ]
        if exposed:
            findings.append(
                Finding(
                    resource_id=row["instance_id"],
                    resource_type="ec2_instance",
                    region=row["region"],
                    evidence={
                        "public_ip": row["public_ip"],
                        "state": row["state"],
                        "open_security_groups": exposed,
                    },
                )
            )
    return make_result(EC2_PUBLIC, findings=findings)


LAMBDA_PUBLIC = CheckMeta(
    check_id="exposure.lambda_public_functions",
    category="service_exposure",
    title="Publicly invokable Lambda functions",
    detects="Function URLs with auth type NONE, or resource policies granting a * principal without conditions",
    default_severity="high",
    recommendation="Require AWS_IAM auth on function URLs; scope resource policies to known principals or add source conditions",
    data_dependencies=["lambda_exposure"],
)


def _policy_has_open_principal(policy_json: Optional[str]) -> bool:
    if not policy_json:
        return False
    try:
        policy = json.loads(policy_json)
    except (TypeError, ValueError):
        return False
    statements = policy.get("Statement", [])
    statements = [statements] if isinstance(statements, dict) else statements
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        is_star = principal == "*" or (
            isinstance(principal, dict) and principal.get("AWS") == "*"
        )
        if is_star and not statement.get("Condition"):
            return True
    return False


@register(LAMBDA_PUBLIC)
def check_lambda_public(conn, scan_id):
    state = dependency_state(conn, ["lambda_exposure"], scan_id)
    if state == "absent":
        return make_result(
            LAMBDA_PUBLIC,
            not_evaluated_reason="lambda_exposure not collected (scan predates this data)",
        )
    if state == "empty":
        return make_not_applicable(
            LAMBDA_PUBLIC, "no Lambda functions in this account (scanned, none found)"
        )
    findings = []
    function_rows = conn.execute(
        sa.text(
            "SELECT function_name, function_arn, region, url_auth_type,"
            " url_config, resource_policy FROM lambda_exposure"
            " WHERE scan_id = :scan_id"
        ),
        {"scan_id": scan_id},
    ).mappings()
    for row in function_rows:
        reasons = {}
        if row["url_auth_type"] == "NONE":
            url = (
                json.loads(row["url_config"]).get("FunctionUrl")
                if row["url_config"]
                else None
            )
            reasons["function_url_auth"] = "NONE"
            reasons["function_url"] = url
        if _policy_has_open_principal(row["resource_policy"]):
            reasons["resource_policy_principal"] = "*"
        if reasons:
            findings.append(
                Finding(
                    resource_id=row["function_name"],
                    resource_type="lambda_function",
                    region=row["region"],
                    evidence={"function_arn": row["function_arn"], **reasons},
                )
            )
    return make_result(LAMBDA_PUBLIC, findings=findings)


DATABASES = CheckMeta(
    check_id="exposure.database_exposure",
    category="service_exposure",
    title="Databases and data stores exposed to the internet",
    detects=(
        "Publicly accessible RDS instances (worse when their port is world-open),"
        " OpenSearch domains outside a VPC, and ElastiCache clusters behind"
        " world-open security groups"
    ),
    default_severity="critical",
    recommendation="Disable public accessibility, move data stores into private subnets and restrict their security groups",
    data_dependencies=[
        "rds_instances",
        "opensearch_domains",
        "elasticache_clusters",
        "security_groups",
    ],
)


@register(DATABASES)
def check_database_exposure(conn, scan_id):
    state = dependency_state(
        conn, ["rds_instances", "opensearch_domains", "elasticache_clusters"], scan_id
    )
    if state == "absent":
        return make_result(
            DATABASES,
            not_evaluated_reason="database resources not collected (scan predates this data)",
        )
    if state == "empty":
        return make_not_applicable(
            DATABASES,
            "no RDS, OpenSearch or ElastiCache resources in this account (scanned, none found)",
        )
    open_groups = _world_rules_by_group(conn, scan_id)
    findings = []

    for row in conn.execute(
        sa.text(
            "SELECT db_instance_identifier, region, engine, endpoint_port,"
            " vpc_security_groups FROM rds_instances"
            " WHERE scan_id = :scan_id AND publicly_accessible = 1"
        ),
        {"scan_id": scan_id},
    ).mappings():
        group_ids = _group_ids(row["vpc_security_groups"])
        port = row["endpoint_port"]
        port_open = (
            any(
                any(
                    rule["from_port"] is None
                    or (rule["from_port"] <= port <= rule["to_port"])
                    for rule in open_groups.get(group_id, [])
                )
                for group_id in group_ids
                if group_id in open_groups
            )
            if port
            else False
        )
        findings.append(
            Finding(
                resource_id=row["db_instance_identifier"],
                resource_type="rds_instance",
                region=row["region"],
                evidence={
                    "engine": row["engine"],
                    "publicly_accessible": True,
                    "endpoint_port": port,
                    "port_world_open": port_open,
                    "security_groups": group_ids,
                },
            )
        )

    for row in conn.execute(
        sa.text(
            "SELECT domain_name, region, vpc_id, endpoint FROM opensearch_domains"
            " WHERE scan_id = :scan_id AND (vpc_id IS NULL OR vpc_id = '')"
        ),
        {"scan_id": scan_id},
    ).mappings():
        findings.append(
            Finding(
                resource_id=row["domain_name"],
                resource_type="opensearch_domain",
                region=row["region"],
                evidence={
                    "vpc_id": None,
                    "endpoint": row["endpoint"],
                    "public_endpoint": True,
                },
            )
        )

    for row in conn.execute(
        sa.text(
            "SELECT cache_cluster_id, region, engine, security_groups"
            " FROM elasticache_clusters WHERE scan_id = :scan_id"
        ),
        {"scan_id": scan_id},
    ).mappings():
        world_open = [
            group_id
            for group_id in _group_ids(row["security_groups"])
            if group_id in open_groups
        ]
        if world_open:
            findings.append(
                Finding(
                    resource_id=row["cache_cluster_id"],
                    resource_type="elasticache_cluster",
                    region=row["region"],
                    evidence={
                        "engine": row["engine"],
                        "world_open_security_groups": world_open,
                    },
                )
            )

    return make_result(DATABASES, findings=findings)


ENTRY_POINTS = CheckMeta(
    check_id="exposure.public_entry_points",
    category="service_exposure",
    title="Public entry point inventory",
    detects=(
        "The account's internet-facing surface: internet-facing load balancers,"
        " API Gateway stages and enabled CloudFront distributions"
    ),
    default_severity="informational",
    recommendation="Review each entry point; confirm it is intended, authenticated and fronted by WAF where appropriate",
    data_dependencies=[
        "load_balancers",
        "api_gateway_stages",
        "cloudfront_distributions",
    ],
)


@register(ENTRY_POINTS)
def check_entry_points(conn, scan_id):
    state = dependency_state(
        conn,
        ["load_balancers", "api_gateway_stages", "cloudfront_distributions"],
        scan_id,
    )
    if state == "absent":
        return make_result(
            ENTRY_POINTS,
            not_evaluated_reason="entry point resources not collected (scan predates this data)",
        )
    if state == "empty":
        return make_not_applicable(
            ENTRY_POINTS,
            "no load balancers, API Gateway stages or CloudFront distributions in this account (scanned, none found)",
        )
    findings = []

    for row in conn.execute(
        sa.text(
            "SELECT load_balancer_name, region, load_balancer_type, dns_name,"
            " listeners FROM load_balancers WHERE scan_id = :scan_id"
            " AND scheme = 'internet-facing'"
        ),
        {"scan_id": scan_id},
    ).mappings():
        findings.append(
            Finding(
                resource_id=row["load_balancer_name"],
                resource_type="load_balancer",
                region=row["region"],
                evidence={
                    "entry_point_type": "load_balancer",
                    "load_balancer_type": row["load_balancer_type"],
                    "dns_name": row["dns_name"],
                    "listeners": (
                        json.loads(row["listeners"]) if row["listeners"] else []
                    ),
                },
            )
        )

    for row in conn.execute(
        sa.text(
            "SELECT api_id, stage_name, region, api_type, web_acl_arn"
            " FROM api_gateway_stages WHERE scan_id = :scan_id"
        ),
        {"scan_id": scan_id},
    ).mappings():
        findings.append(
            Finding(
                resource_id=f"{row['api_id']}/{row['stage_name']}",
                resource_type="api_gateway_stage",
                region=row["region"],
                evidence={
                    "entry_point_type": "api_gateway_stage",
                    "api_type": row["api_type"],
                    "waf_attached": bool(row["web_acl_arn"]),
                },
            )
        )

    for row in conn.execute(
        sa.text(
            "SELECT distribution_id, domain_name, web_acl_id"
            " FROM cloudfront_distributions WHERE scan_id = :scan_id AND enabled = 1"
        ),
        {"scan_id": scan_id},
    ).mappings():
        findings.append(
            Finding(
                resource_id=row["distribution_id"],
                resource_type="cloudfront_distribution",
                region=None,
                evidence={
                    "entry_point_type": "cloudfront_distribution",
                    "domain_name": row["domain_name"],
                    "waf_attached": bool(row["web_acl_id"]),
                },
            )
        )

    return make_result(ENTRY_POINTS, findings=findings)


SERVICE_CHECKS = {
    "ec2": "exposure.ec2_public_instances",
    "lambda": "exposure.lambda_public_functions",
    "databases": "exposure.database_exposure",
    "entry_points": "exposure.public_entry_points",
}


def run_exposure(
    engine: sa.Engine, scan_id: Optional[str], service: Optional[str] = None
) -> Dict:
    """Run the exposure correlations for one service area or all of them."""
    if service is not None and service not in SERVICE_CHECKS:
        raise ValueError(
            f"Unknown service '{service}'; expected one of {sorted(SERVICE_CHECKS)}"
        )
    selected = {service: SERVICE_CHECKS[service]} if service else SERVICE_CHECKS

    with engine.connect() as conn:
        resolved = resolve_scan_id(conn, scan_id)
        services = {}
        for name, check_id in selected.items():
            meta, fn = CHECKS[check_id]
            try:
                result = fn(conn, resolved)
            except Exception as e:  # a missing table must not sink the call
                result = make_result(meta, not_evaluated_reason=f"check error: {e}")
            services[name] = result.to_dict()
        return {"scan_id": resolved, "services": services}
