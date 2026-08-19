"""
Logging and monitoring checks.
Uses Australian English in all documentation and comments.
"""

import sqlalchemy as sa

from .registry import CheckMeta, make_result, register
from .types import Finding

MULTI_REGION_TRAIL = CheckMeta(
    check_id="logging.no_multi_region_cloudtrail",
    category="logging_monitoring",
    title="No multi-region CloudTrail",
    detects="No logging multi-region CloudTrail trail exists",
    default_severity="high",
    recommendation="Create a multi-region trail with log file validation enabled",
    data_dependencies=["cloudtrail_trails"],
)


@register(MULTI_REGION_TRAIL)
def check_multi_region_trail(conn, scan_id):
    total = conn.execute(
        sa.text("SELECT COUNT(*) FROM cloudtrail_trails WHERE scan_id = :scan_id"),
        {"scan_id": scan_id},
    ).scalar()
    if not total:
        return make_result(
            MULTI_REGION_TRAIL, not_evaluated_reason="CloudTrail trails not collected"
        )
    active = conn.execute(
        sa.text(
            "SELECT COUNT(*) FROM cloudtrail_trails WHERE scan_id = :scan_id"
            " AND is_multi_region_trail = 1 AND is_logging = 1"
        ),
        {"scan_id": scan_id},
    ).scalar()
    if active:
        return make_result(MULTI_REGION_TRAIL)
    return make_result(
        MULTI_REGION_TRAIL,
        findings=[
            Finding(
                resource_id="account",
                resource_type="cloudtrail",
                region=None,
                evidence={"multi_region_logging_trails": 0, "total_trails": total},
            )
        ],
    )


def _region_service_check(conn, scan_id, meta, column, service_name):
    total = conn.execute(
        sa.text(
            "SELECT COUNT(*) FROM region_security_services WHERE scan_id = :scan_id"
        ),
        {"scan_id": scan_id},
    ).scalar()
    if not total:
        return make_result(
            meta, not_evaluated_reason="region security services not collected"
        )
    matched = conn.execute(
        sa.text(
            f"SELECT region FROM region_security_services"
            f" WHERE scan_id = :scan_id AND {column} = 0"
        ),
        {"scan_id": scan_id},
    ).mappings()
    findings = [
        Finding(
            resource_id=row["region"],
            resource_type="region",
            region=row["region"],
            evidence={service_name: False},
        )
        for row in matched
    ]
    return make_result(meta, findings=findings)


GUARDDUTY = CheckMeta(
    check_id="logging.guardduty_not_enabled",
    category="logging_monitoring",
    title="GuardDuty not enabled",
    detects="Regions where GuardDuty has no enabled detector",
    default_severity="medium",
    recommendation="Enable GuardDuty in every active region, ideally via the organisation",
    data_dependencies=["region_security_services"],
)


@register(GUARDDUTY)
def check_guardduty(conn, scan_id):
    return _region_service_check(
        conn, scan_id, GUARDDUTY, "guardduty_enabled", "guardduty_enabled"
    )


SECURITY_HUB = CheckMeta(
    check_id="logging.security_hub_not_enabled",
    category="logging_monitoring",
    title="Security Hub not enabled",
    detects="Regions where Security Hub is not enabled",
    default_severity="low",
    recommendation="Enable Security Hub for consolidated findings and standards checks",
    data_dependencies=["region_security_services"],
)


@register(SECURITY_HUB)
def check_security_hub(conn, scan_id):
    return _region_service_check(
        conn, scan_id, SECURITY_HUB, "security_hub_enabled", "security_hub_enabled"
    )


CONFIG_RECORDER = CheckMeta(
    check_id="logging.config_recorder_missing",
    category="logging_monitoring",
    title="AWS Config recorder missing or stopped",
    detects="No recording AWS Config recorder in the account",
    default_severity="medium",
    recommendation="Enable AWS Config recording for configuration history and drift detection",
    data_dependencies=["config_recorders"],
)


@register(CONFIG_RECORDER)
def check_config_recorder(conn, scan_id):
    # Zero collected recorders is itself the finding: an account with
    # Config enabled always returns recorder rows.
    total = conn.execute(
        sa.text("SELECT COUNT(*) FROM config_recorders WHERE scan_id = :scan_id"),
        {"scan_id": scan_id},
    ).scalar()
    recording = conn.execute(
        sa.text(
            "SELECT COUNT(*) FROM config_recorders"
            " WHERE scan_id = :scan_id AND is_recording = 1"
        ),
        {"scan_id": scan_id},
    ).scalar()
    if not total:
        return make_result(
            CONFIG_RECORDER,
            findings=[
                Finding(
                    resource_id="account",
                    resource_type="config",
                    region=None,
                    evidence={"config_recorders": 0},
                )
            ],
        )
    if recording:
        return make_result(CONFIG_RECORDER)
    return make_result(
        CONFIG_RECORDER,
        findings=[
            Finding(
                resource_id="account",
                resource_type="config",
                region=None,
                evidence={"config_recorders": total, "recording": 0},
            )
        ],
    )
