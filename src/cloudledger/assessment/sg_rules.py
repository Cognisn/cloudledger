"""
Security group rule parsing helpers shared by network checks and the
service exposure correlations.
Uses Australian English in all documentation and comments.
"""

from typing import Any, Dict, List

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}

WORLD_CIDRS = ("0.0.0.0/0", "::/0")


def _world_cidrs_in_rule(rule: Dict[str, Any]) -> List[str]:
    cidrs = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
    cidrs += [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])]
    return [c for c in cidrs if c in WORLD_CIDRS]


def _sensitive_ports_in_range(from_port, to_port) -> List[Dict[str, Any]]:
    if from_port is None or to_port is None:
        # All-traffic rule: every sensitive port is reachable.
        return [{"port": p, "service": s} for p, s in SENSITIVE_PORTS.items()]
    return [
        {"port": p, "service": s}
        for p, s in SENSITIVE_PORTS.items()
        if from_port <= p <= to_port
    ]


def world_open_rules(ingress_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return the ingress rules reachable from the whole internet, with any
    sensitive ports each rule exposes.
    """
    results = []
    for rule in ingress_rules or []:
        for cidr in _world_cidrs_in_rule(rule):
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")
            results.append(
                {
                    "protocol": rule.get("IpProtocol"),
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                    "sensitive_ports": _sensitive_ports_in_range(from_port, to_port),
                }
            )
    return results
