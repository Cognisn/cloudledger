"""
Network exposure checks.
Uses Australian English in all documentation and comments.
"""

import json

from .registry import (
    CheckMeta,
    make_result,
    make_not_applicable,
    register,
    dependency_state,
)
from .types import Finding
from .sg_rules import world_open_rules


def _empty_or_absent(conn, scan_id, meta, table, resource_label):
    """
    Return the appropriate result for a missing/empty inventory table, or None
    when the table has rows (so the check should proceed).
    """
    state = dependency_state(conn, [table], scan_id)
    if state == "absent":
        return make_result(
            meta,
            not_evaluated_reason=f"{table} not collected (scan predates this data)",
        )
    if state == "empty":
        return make_not_applicable(
            meta, f"no {resource_label} in this account (scanned, none found)"
        )
    return None


def _security_groups(conn, scan_id):
    return conn.execute(
        "SELECT group_id, group_name, vpc_id, region, ingress_rules"
        " FROM security_groups WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()


def _sg_world_rules(row):
    ingress = json.loads(row["ingress_rules"]) if row["ingress_rules"] else []
    return world_open_rules(ingress)


SG_SENSITIVE = CheckMeta(
    check_id="network.sg_world_open_sensitive_ports",
    category="network_exposure",
    title="Security groups open to the internet on sensitive ports",
    detects="Ingress rules from 0.0.0.0/0 or ::/0 reaching SSH, RDP, database or search ports",
    default_severity="critical",
    recommendation="Restrict sensitive ports to known CIDRs, a VPN or SSM Session Manager",
    data_dependencies=["security_groups"],
)


@register(SG_SENSITIVE)
def check_sg_sensitive_ports(conn, scan_id):
    blocked = _empty_or_absent(
        conn, scan_id, SG_SENSITIVE, "security_groups", "security groups"
    )
    if blocked:
        return blocked
    groups = _security_groups(conn, scan_id)
    findings = []
    for row in groups:
        rules = [r for r in _sg_world_rules(row) if r["sensitive_ports"]]
        if rules:
            findings.append(
                Finding(
                    resource_id=row["group_id"],
                    resource_type="security_group",
                    region=row["region"],
                    evidence={
                        "group_name": row["group_name"],
                        "vpc_id": row["vpc_id"],
                        "rules": rules,
                    },
                )
            )
    return make_result(SG_SENSITIVE, findings=findings)


SG_ALL_TRAFFIC = CheckMeta(
    check_id="network.sg_world_open_all_traffic",
    category="network_exposure",
    title="Security groups open to the internet for all traffic",
    detects="Ingress rules allowing all protocols from 0.0.0.0/0 or ::/0",
    default_severity="high",
    recommendation="Replace all-traffic rules with specific protocol and port rules",
    data_dependencies=["security_groups"],
)


@register(SG_ALL_TRAFFIC)
def check_sg_all_traffic(conn, scan_id):
    blocked = _empty_or_absent(
        conn, scan_id, SG_ALL_TRAFFIC, "security_groups", "security groups"
    )
    if blocked:
        return blocked
    groups = _security_groups(conn, scan_id)
    findings = []
    for row in groups:
        rules = [r for r in _sg_world_rules(row) if r["protocol"] == "-1"]
        if rules:
            findings.append(
                Finding(
                    resource_id=row["group_id"],
                    resource_type="security_group",
                    region=row["region"],
                    evidence={"group_name": row["group_name"], "rules": rules},
                )
            )
    return make_result(SG_ALL_TRAFFIC, findings=findings)


DEFAULT_SG = CheckMeta(
    check_id="network.default_sg_with_rules",
    category="network_exposure",
    title="Default security groups containing rules",
    detects="Default security groups with any ingress rules configured",
    default_severity="medium",
    recommendation="Remove all rules from default security groups; use purpose-built groups",
    data_dependencies=["security_groups"],
)


@register(DEFAULT_SG)
def check_default_sg(conn, scan_id):
    blocked = _empty_or_absent(
        conn, scan_id, DEFAULT_SG, "security_groups", "security groups"
    )
    if blocked:
        return blocked
    groups = _security_groups(conn, scan_id)
    findings = []
    for row in groups:
        if row["group_name"] != "default":
            continue
        ingress = json.loads(row["ingress_rules"]) if row["ingress_rules"] else []
        if ingress:
            findings.append(
                Finding(
                    resource_id=row["group_id"],
                    resource_type="security_group",
                    region=row["region"],
                    evidence={
                        "vpc_id": row["vpc_id"],
                        "ingress_rule_count": len(ingress),
                    },
                )
            )
    return make_result(DEFAULT_SG, findings=findings)


PUBLIC_SUBNETS = CheckMeta(
    check_id="network.subnets_auto_assign_public_ip",
    category="network_exposure",
    title="Subnets auto-assigning public IPs",
    detects="Subnets with MapPublicIpOnLaunch enabled",
    default_severity="low",
    recommendation="Disable automatic public IP assignment; assign public IPs deliberately",
    data_dependencies=["subnets"],
)


@register(PUBLIC_SUBNETS)
def check_public_subnets(conn, scan_id):
    blocked = _empty_or_absent(conn, scan_id, PUBLIC_SUBNETS, "subnets", "subnets")
    if blocked:
        return blocked
    subnet_rows = conn.execute(
        "SELECT subnet_id, vpc_id, region, cidr_block FROM subnets"
        " WHERE scan_id = ? AND map_public_ip = 1",
        (scan_id,),
    ).fetchall()
    findings = [
        Finding(
            resource_id=row["subnet_id"],
            resource_type="subnet",
            region=row["region"],
            evidence={
                "vpc_id": row["vpc_id"],
                "cidr_block": row["cidr_block"],
                "map_public_ip_on_launch": True,
            },
        )
        for row in subnet_rows
    ]
    return make_result(PUBLIC_SUBNETS, findings=findings)


FLOW_LOGS = CheckMeta(
    check_id="network.vpcs_without_flow_logs",
    category="network_exposure",
    title="VPCs without flow logs",
    detects="VPCs with no VPC Flow Log attached",
    default_severity="medium",
    recommendation="Enable VPC Flow Logs for traffic visibility and incident response",
    data_dependencies=["vpcs", "vpc_flow_logs"],
)


@register(FLOW_LOGS)
def check_vpcs_without_flow_logs(conn, scan_id):
    blocked = _empty_or_absent(conn, scan_id, FLOW_LOGS, "vpcs", "VPCs")
    if blocked:
        return blocked
    vpc_rows = conn.execute(
        "SELECT vpc_id, region, cidr_block FROM vpcs WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    logged = {
        row["resource_id"]
        for row in conn.execute(
            "SELECT resource_id FROM vpc_flow_logs WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    }
    findings = [
        Finding(
            resource_id=row["vpc_id"],
            resource_type="vpc",
            region=row["region"],
            evidence={"cidr_block": row["cidr_block"], "flow_logs": False},
        )
        for row in vpc_rows
        if row["vpc_id"] not in logged
    ]
    return make_result(FLOW_LOGS, findings=findings)
