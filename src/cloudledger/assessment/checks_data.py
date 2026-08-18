"""
Data protection checks.
Uses Australian English in all documentation and comments.
"""

from .registry import (
    CheckMeta,
    dependency_state,
    make_not_applicable,
    make_result,
    register,
)
from .types import Finding


def _simple_rows_check(
    conn,
    scan_id,
    meta,
    table,
    where,
    columns,
    evidence_fn,
    resource_column,
    resource_type,
    region_column=None,
    resource_label=None,
):
    """
    Shared shape for resource-inventory checks: findings for rows matching the
    WHERE clause; otherwise classified by dependency state.

    When ``resource_label`` is given, an empty (but present) table means the
    account has none of that resource — a not_applicable result (scanned, none
    found), which is covered and never deducts. A missing table means the scan
    predates the collector — a genuine not_evaluated gap. When ``resource_label``
    is None, an empty table is treated as not_evaluated (used for account-level
    data that is always applicable, e.g. per-region enablement).
    """
    state = dependency_state(conn, [table], scan_id)
    if state == "absent":
        return make_result(
            meta,
            not_evaluated_reason=f"{table} not collected (scan predates this data)",
        )
    if state == "empty":
        if resource_label is not None:
            return make_not_applicable(
                meta, f"no {resource_label} in this account (scanned, none found)"
            )
        return make_result(meta, not_evaluated_reason=f"{table} not collected")
    matched = conn.execute(
        f"SELECT {columns} FROM {table} WHERE scan_id = ? AND {where}", (scan_id,)
    ).fetchall()
    findings = [
        Finding(
            resource_id=row[resource_column],
            resource_type=resource_type,
            region=row[region_column] if region_column else None,
            evidence=evidence_fn(row),
        )
        for row in matched
    ]
    return make_result(meta, findings=findings)


UNENCRYPTED_VOLUMES = CheckMeta(
    check_id="data.unencrypted_ebs_volumes",
    category="data_protection",
    title="Unencrypted EBS volumes",
    detects="EBS volumes without encryption at rest",
    default_severity="high",
    recommendation="Enable EBS encryption; migrate data to encrypted volumes",
    data_dependencies=["ebs_volumes"],
)


@register(UNENCRYPTED_VOLUMES)
def check_unencrypted_volumes(conn, scan_id):
    return _simple_rows_check(
        conn,
        scan_id,
        UNENCRYPTED_VOLUMES,
        table="ebs_volumes",
        where="encrypted = 0",
        columns="volume_id, region, size, state, attached_instance_id",
        evidence_fn=lambda r: {
            "size_gb": r["size"],
            "state": r["state"],
            "attached_instance_id": r["attached_instance_id"],
        },
        resource_column="volume_id",
        resource_type="ebs_volume",
        region_column="region",
        resource_label="EBS volumes",
    )


UNENCRYPTED_SNAPSHOTS = CheckMeta(
    check_id="data.unencrypted_ebs_snapshots",
    category="data_protection",
    title="Unencrypted EBS snapshots",
    detects="EBS snapshots without encryption at rest",
    default_severity="high",
    recommendation="Copy snapshots with encryption enabled and remove the plaintext originals",
    data_dependencies=["ebs_snapshots"],
)


@register(UNENCRYPTED_SNAPSHOTS)
def check_unencrypted_snapshots(conn, scan_id):
    return _simple_rows_check(
        conn,
        scan_id,
        UNENCRYPTED_SNAPSHOTS,
        table="ebs_snapshots",
        where="encrypted = 0",
        columns="snapshot_id, region, volume_id, volume_size",
        evidence_fn=lambda r: {
            "volume_id": r["volume_id"],
            "volume_size_gb": r["volume_size"],
        },
        resource_column="snapshot_id",
        resource_type="ebs_snapshot",
        region_column="region",
        resource_label="EBS snapshots",
    )


UNENCRYPTED_RDS = CheckMeta(
    check_id="data.unencrypted_rds_instances",
    category="data_protection",
    title="Unencrypted RDS instances",
    detects="RDS instances without storage encryption",
    default_severity="high",
    recommendation="Restore to an encrypted instance from a snapshot; encryption cannot be enabled in place",
    data_dependencies=["rds_instances"],
)


@register(UNENCRYPTED_RDS)
def check_unencrypted_rds(conn, scan_id):
    return _simple_rows_check(
        conn,
        scan_id,
        UNENCRYPTED_RDS,
        table="rds_instances",
        where="encrypted = 0",
        columns="db_instance_identifier, region, engine, publicly_accessible",
        evidence_fn=lambda r: {
            "engine": r["engine"],
            "publicly_accessible": bool(r["publicly_accessible"]),
        },
        resource_column="db_instance_identifier",
        resource_type="rds_instance",
        region_column="region",
        resource_label="RDS instances",
    )


S3_PUBLIC = CheckMeta(
    check_id="data.s3_public_buckets",
    category="data_protection",
    title="Publicly accessible S3 buckets",
    detects="Buckets whose policy status reports IsPublic",
    default_severity="critical",
    recommendation="Apply a Public Access Block and remove public bucket policies unless deliberately published",
    data_dependencies=["s3_public_access"],
)


@register(S3_PUBLIC)
def check_s3_public(conn, scan_id):
    return _simple_rows_check(
        conn,
        scan_id,
        S3_PUBLIC,
        table="s3_public_access",
        where="policy_is_public = 1",
        columns="bucket_name, policy_is_public",
        evidence_fn=lambda r: {"policy_is_public": True},
        resource_column="bucket_name",
        resource_type="s3_bucket",
        resource_label="S3 buckets",
    )


S3_NO_PAB = CheckMeta(
    check_id="data.s3_buckets_without_pab",
    category="data_protection",
    title="S3 buckets without a Public Access Block",
    detects="Buckets with no bucket-level Public Access Block configuration",
    default_severity="medium",
    recommendation="Enable all four Public Access Block settings on every bucket",
    data_dependencies=["s3_public_access"],
)


@register(S3_NO_PAB)
def check_s3_no_pab(conn, scan_id):
    return _simple_rows_check(
        conn,
        scan_id,
        S3_NO_PAB,
        table="s3_public_access",
        where="public_access_block IS NULL",
        columns="bucket_name",
        evidence_fn=lambda r: {"public_access_block": None},
        resource_column="bucket_name",
        resource_type="s3_bucket",
        resource_label="S3 buckets",
    )


ACCOUNT_PAB = CheckMeta(
    check_id="data.account_pab_missing",
    category="data_protection",
    title="Account-level S3 Public Access Block missing",
    detects="No account-wide S3 Public Access Block configuration",
    default_severity="high",
    recommendation="Enable the account-level Public Access Block in S3 settings",
    data_dependencies=["account_security_posture"],
)


@register(ACCOUNT_PAB)
def check_account_pab(conn, scan_id):
    row = conn.execute(
        "SELECT account_public_access_block FROM account_security_posture"
        " WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
        (scan_id,),
    ).fetchone()
    if row is None:
        return make_result(
            ACCOUNT_PAB, not_evaluated_reason="account security posture not collected"
        )
    if row["account_public_access_block"] is None:
        return make_result(
            ACCOUNT_PAB,
            findings=[
                Finding(
                    resource_id="account",
                    resource_type="s3_account",
                    region=None,
                    evidence={"account_public_access_block": None},
                )
            ],
        )
    return make_result(ACCOUNT_PAB)


KMS_ROTATION = CheckMeta(
    check_id="data.kms_rotation_disabled",
    category="data_protection",
    title="Customer KMS keys without rotation",
    detects="Enabled customer-managed KMS keys with rotation disabled",
    default_severity="low",
    recommendation="Enable annual automatic rotation on customer-managed keys",
    data_dependencies=["kms_keys"],
)


@register(KMS_ROTATION)
def check_kms_rotation(conn, scan_id):
    return _simple_rows_check(
        conn,
        scan_id,
        KMS_ROTATION,
        table="kms_keys",
        where="key_manager = 'CUSTOMER' AND enabled = 1 AND rotation_enabled = 0",
        columns="key_id, region, aliases",
        evidence_fn=lambda r: {"aliases": r["aliases"], "rotation_enabled": False},
        resource_column="key_id",
        resource_type="kms_key",
        region_column="region",
        resource_label="KMS keys",
    )


EBS_DEFAULT_ENCRYPTION = CheckMeta(
    check_id="data.ebs_default_encryption_off",
    category="data_protection",
    title="EBS encryption by default disabled",
    detects="Regions where new EBS volumes are not encrypted by default",
    default_severity="medium",
    recommendation="Enable EBS encryption by default in every active region",
    data_dependencies=["region_security_services"],
)


@register(EBS_DEFAULT_ENCRYPTION)
def check_ebs_default_encryption(conn, scan_id):
    return _simple_rows_check(
        conn,
        scan_id,
        EBS_DEFAULT_ENCRYPTION,
        table="region_security_services",
        where="ebs_encryption_by_default = 0",
        columns="region",
        evidence_fn=lambda r: {"ebs_encryption_by_default": False},
        resource_column="region",
        resource_type="region",
        region_column="region",
    )
