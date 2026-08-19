"""
Identity and access checks.

All severities are advisory defaults; the MCP client scores.
Uses Australian English in all documentation and comments.
"""

import json
from datetime import datetime, UTC
from typing import Optional

import sqlalchemy as sa

from .registry import (
    CheckMeta,
    make_result,
    make_not_applicable,
    register,
    dependency_state,
)
from .types import Finding

STALE_DAYS = 90


def _posture(conn, scan_id) -> Optional[dict]:
    row = (
        conn.execute(
            sa.text(
                "SELECT * FROM account_security_posture WHERE scan_id = :scan_id"
                " ORDER BY id DESC LIMIT 1"
            ),
            {"scan_id": scan_id},
        )
        .mappings()
        .fetchone()
    )
    return dict(row) if row else None


def _report_rows(conn, scan_id) -> list:
    return (
        conn.execute(
            sa.text("SELECT * FROM iam_credential_report WHERE scan_id = :scan_id"),
            {"scan_id": scan_id},
        )
        .mappings()
        .all()
    )


def _age_days(timestamp: Optional[str]) -> Optional[int]:
    """Days since an ISO-8601 timestamp; None when unparseable or absent."""
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (datetime.now(UTC) - parsed).days


ROOT_MFA = CheckMeta(
    check_id="identity.root_mfa_disabled",
    category="identity_access",
    title="Root account MFA disabled",
    detects="The account root user has no MFA device enabled",
    default_severity="critical",
    recommendation="Enable a hardware or virtual MFA device on the root user immediately",
    data_dependencies=["account_security_posture"],
)


@register(ROOT_MFA)
def check_root_mfa(conn, scan_id):
    posture = _posture(conn, scan_id)
    if posture is None or not posture.get("account_summary"):
        return make_result(
            ROOT_MFA, not_evaluated_reason="account security posture not collected"
        )
    summary = json.loads(posture["account_summary"])
    if "AccountMFAEnabled" not in summary:
        return make_result(
            ROOT_MFA, not_evaluated_reason="IAM account summary unavailable"
        )
    if summary["AccountMFAEnabled"] == 0:
        return make_result(
            ROOT_MFA,
            findings=[
                Finding(
                    resource_id="root",
                    resource_type="iam_root",
                    region=None,
                    evidence={"account_mfa_enabled": 0},
                )
            ],
        )
    return make_result(ROOT_MFA)


ROOT_KEYS = CheckMeta(
    check_id="identity.root_access_keys_present",
    category="identity_access",
    title="Root account access keys present",
    detects="The root user has active long-lived access keys",
    default_severity="critical",
    recommendation="Delete root access keys; use IAM roles or users for programmatic access",
    data_dependencies=["iam_credential_report", "account_security_posture"],
)


@register(ROOT_KEYS)
def check_root_access_keys(conn, scan_id):
    for row in _report_rows(conn, scan_id):
        if row["user_name"] == "<root_account>":
            if row["access_key_1_active"] or row["access_key_2_active"]:
                return make_result(
                    ROOT_KEYS,
                    findings=[
                        Finding(
                            resource_id="root",
                            resource_type="iam_root",
                            region=None,
                            evidence={
                                "access_key_1_active": bool(row["access_key_1_active"]),
                                "access_key_2_active": bool(row["access_key_2_active"]),
                            },
                        )
                    ],
                )
            return make_result(ROOT_KEYS)
    posture = _posture(conn, scan_id)
    if posture and posture.get("account_summary"):
        summary = json.loads(posture["account_summary"])
        if "AccountAccessKeysPresent" in summary:
            if summary["AccountAccessKeysPresent"]:
                return make_result(
                    ROOT_KEYS,
                    findings=[
                        Finding(
                            resource_id="root",
                            resource_type="iam_root",
                            region=None,
                            evidence={
                                "account_access_keys_present": summary[
                                    "AccountAccessKeysPresent"
                                ]
                            },
                        )
                    ],
                )
            return make_result(ROOT_KEYS)
    return make_result(
        ROOT_KEYS,
        not_evaluated_reason="credential report and account summary unavailable",
    )


PASSWORD_POLICY = CheckMeta(
    check_id="identity.password_policy_missing_or_weak",
    category="identity_access",
    title="Password policy missing or weak",
    detects="No IAM account password policy, or minimum length below 14",
    default_severity="high",
    recommendation="Configure an account password policy with minimum length 14, complexity and reuse prevention",
    data_dependencies=["account_security_posture"],
)


@register(PASSWORD_POLICY)
def check_password_policy(conn, scan_id):
    posture = _posture(conn, scan_id)
    if posture is None:
        return make_result(
            PASSWORD_POLICY,
            not_evaluated_reason="account security posture not collected",
        )
    if not posture["password_policy_exists"]:
        return make_result(
            PASSWORD_POLICY,
            findings=[
                Finding(
                    resource_id="account",
                    resource_type="iam_account",
                    region=None,
                    evidence={"password_policy_exists": False},
                )
            ],
        )
    policy = (
        json.loads(posture["password_policy"]) if posture["password_policy"] else {}
    )
    minimum = policy.get("MinimumPasswordLength", 0)
    if minimum < 14:
        return make_result(
            PASSWORD_POLICY,
            findings=[
                Finding(
                    resource_id="account",
                    resource_type="iam_account",
                    region=None,
                    evidence={
                        "minimum_password_length": minimum,
                        "required_minimum": 14,
                    },
                )
            ],
        )
    return make_result(PASSWORD_POLICY)


USERS_WITHOUT_MFA = CheckMeta(
    check_id="identity.console_users_without_mfa",
    category="identity_access",
    title="Console users without MFA",
    detects="IAM users with console passwords but no active MFA device",
    default_severity="high",
    recommendation="Enable MFA for every user with console access",
    data_dependencies=["iam_credential_report"],
)


@register(USERS_WITHOUT_MFA)
def check_users_without_mfa(conn, scan_id):
    report = _report_rows(conn, scan_id)
    if not report:
        return make_result(
            USERS_WITHOUT_MFA, not_evaluated_reason="credential report not collected"
        )
    findings = [
        Finding(
            resource_id=row["user_name"],
            resource_type="iam_user",
            region=None,
            evidence={"password_enabled": True, "mfa_active": False},
        )
        for row in report
        if row["user_name"] != "<root_account>"
        and row["password_enabled"] == 1
        and not row["mfa_active"]
    ]
    return make_result(USERS_WITHOUT_MFA, findings=findings)


STALE_KEYS = CheckMeta(
    check_id="identity.stale_access_keys",
    category="identity_access",
    title="Access keys not rotated",
    detects=f"Active access keys not rotated in over {STALE_DAYS} days",
    default_severity="medium",
    recommendation="Rotate access keys at least every 90 days, or replace with short-lived credentials",
    data_dependencies=["iam_credential_report"],
)


@register(STALE_KEYS)
def check_stale_access_keys(conn, scan_id):
    report = _report_rows(conn, scan_id)
    if not report:
        return make_result(
            STALE_KEYS, not_evaluated_reason="credential report not collected"
        )
    findings = []
    for row in report:
        for key_number in (1, 2):
            if not row[f"access_key_{key_number}_active"]:
                continue
            age = _age_days(row[f"access_key_{key_number}_last_rotated"])
            if age is not None and age > STALE_DAYS:
                findings.append(
                    Finding(
                        resource_id=row["user_name"],
                        resource_type="iam_user",
                        region=None,
                        evidence={"access_key": key_number, "age_days": age},
                    )
                )
    return make_result(STALE_KEYS, findings=findings)


INACTIVE_USERS = CheckMeta(
    check_id="identity.inactive_users",
    category="identity_access",
    title="Inactive IAM users",
    detects=f"Users with no password or access key activity in over {STALE_DAYS} days",
    default_severity="low",
    recommendation="Disable or remove credentials for users no longer in active use",
    data_dependencies=["iam_credential_report"],
)


@register(INACTIVE_USERS)
def check_inactive_users(conn, scan_id):
    report = _report_rows(conn, scan_id)
    if not report:
        return make_result(
            INACTIVE_USERS, not_evaluated_reason="credential report not collected"
        )
    findings = []
    for row in report:
        if row["user_name"] == "<root_account>":
            continue
        created_age = _age_days(row["user_creation_time"])
        if created_age is None or created_age <= STALE_DAYS:
            continue
        usage_ages = [
            _age_days(row["password_last_used"]),
            _age_days(row["access_key_1_last_used"]),
            _age_days(row["access_key_2_last_used"]),
        ]
        used_recently = any(a is not None and a <= STALE_DAYS for a in usage_ages)
        if not used_recently:
            findings.append(
                Finding(
                    resource_id=row["user_name"],
                    resource_type="iam_user",
                    region=None,
                    evidence={
                        "days_since_last_activity": min(
                            (a for a in usage_ages if a is not None), default=None
                        )
                    },
                )
            )
    return make_result(INACTIVE_USERS, findings=findings)


ADMIN_WILDCARDS = CheckMeta(
    check_id="identity.admin_wildcard_policies",
    category="identity_access",
    title="Policies allowing all actions on all resources",
    detects="Customer-managed policies with Effect Allow, Action * and Resource *",
    default_severity="high",
    recommendation="Replace wildcard policies with least-privilege statements",
    data_dependencies=["iam_policies"],
)


def _statement_is_wildcard(statement: dict) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    actions = statement.get("Action", [])
    resources = statement.get("Resource", [])
    actions = [actions] if isinstance(actions, str) else actions
    resources = [resources] if isinstance(resources, str) else resources
    return "*" in actions and "*" in resources


@register(ADMIN_WILDCARDS)
def check_admin_wildcard_policies(conn, scan_id):
    state = dependency_state(conn, ["iam_policies"], scan_id)
    if state == "absent":
        return make_result(
            ADMIN_WILDCARDS,
            not_evaluated_reason="iam_policies not collected (scan predates this data)",
        )
    if state == "empty":
        return make_not_applicable(
            ADMIN_WILDCARDS, "no IAM policies in this account (scanned, none found)"
        )
    policy_rows = conn.execute(
        sa.text(
            "SELECT policy_arn, policy_name, policy_document, attachment_count"
            " FROM iam_policies WHERE scan_id = :scan_id"
        ),
        {"scan_id": scan_id},
    ).mappings()
    findings = []
    for row in policy_rows:
        if not row["policy_document"]:
            continue
        try:
            document = json.loads(row["policy_document"])
        except (TypeError, ValueError):
            continue
        statements = document.get("Statement", [])
        statements = [statements] if isinstance(statements, dict) else statements
        if any(_statement_is_wildcard(s) for s in statements):
            findings.append(
                Finding(
                    resource_id=row["policy_arn"],
                    resource_type="iam_policy",
                    region=None,
                    evidence={
                        "policy_name": row["policy_name"],
                        "attachment_count": row["attachment_count"],
                    },
                )
            )
    return make_result(ADMIN_WILDCARDS, findings=findings)


ADMIN_ATTACHED = CheckMeta(
    check_id="identity.administrator_access_attached",
    category="identity_access",
    title="AdministratorAccess policy attached",
    detects="The AWS managed AdministratorAccess policy is attached to users, roles or groups",
    default_severity="medium",
    recommendation="Limit AdministratorAccess to break-glass roles; use scoped policies day to day",
    data_dependencies=["iam_policies"],
)


@register(ADMIN_ATTACHED)
def check_administrator_access(conn, scan_id):
    state = dependency_state(conn, ["iam_policies"], scan_id)
    if state == "absent":
        return make_result(
            ADMIN_ATTACHED,
            not_evaluated_reason="iam_policies not collected (scan predates this data)",
        )
    if state == "empty":
        return make_not_applicable(
            ADMIN_ATTACHED, "no IAM policies in this account (scanned, none found)"
        )
    policy_rows = conn.execute(
        sa.text(
            "SELECT policy_arn, policy_name, attachment_count, attached_users,"
            " attached_roles, attached_groups FROM iam_policies"
            " WHERE scan_id = :scan_id AND policy_name = 'AdministratorAccess'"
        ),
        {"scan_id": scan_id},
    ).mappings()
    findings = []
    for row in policy_rows:
        if row["attachment_count"] and row["attachment_count"] > 0:
            findings.append(
                Finding(
                    resource_id=row["policy_arn"],
                    resource_type="iam_policy",
                    region=None,
                    evidence={
                        "attachment_count": row["attachment_count"],
                        "attached_users": row["attached_users"],
                        "attached_roles": row["attached_roles"],
                        "attached_groups": row["attached_groups"],
                    },
                )
            )
    return make_result(ADMIN_ATTACHED, findings=findings)
