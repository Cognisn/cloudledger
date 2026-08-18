"""
Check registry for the assessment evidence engine.

Checks register themselves with metadata; run_checks executes them against
a scan and groups results. Severities are advisory facts only.
Uses Australian English in all documentation and comments.
"""

import sqlite3
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .types import CheckResult, Finding

CATEGORIES = (
    "identity_access",
    "network_exposure",
    "data_protection",
    "logging_monitoring",
    "service_exposure",
)

CheckFn = Callable[[sqlite3.Connection, str], CheckResult]


@dataclass
class CheckMeta:
    """Static metadata describing a registered check."""

    check_id: str
    category: str
    title: str
    detects: str
    default_severity: str
    recommendation: str
    data_dependencies: List[str] = field(default_factory=list)


CHECKS: Dict[str, Tuple[CheckMeta, CheckFn]] = {}


def register(meta: CheckMeta):
    """Decorator registering a check function under its metadata."""

    def decorator(fn: CheckFn) -> CheckFn:
        CHECKS[meta.check_id] = (meta, fn)
        return fn

    return decorator


def make_result(
    meta: CheckMeta,
    findings: Optional[List[Finding]] = None,
    not_evaluated_reason: Optional[str] = None,
) -> CheckResult:
    """Build a CheckResult from check metadata without restating it."""
    if not_evaluated_reason is not None:
        status = "not_evaluated"
        findings = []
    elif findings:
        status = "findings"
    else:
        status = "clean"
        findings = []
    return CheckResult(
        check_id=meta.check_id,
        category=meta.category,
        status=status,
        default_severity=meta.default_severity,
        recommendation=meta.recommendation,
        findings=findings,
        not_evaluated_reason=not_evaluated_reason,
    )


def make_not_applicable(meta: CheckMeta, reason: str) -> CheckResult:
    """
    Build a not_applicable result: the collector ran and the account has none
    of this resource (scanned, none found). Covered, never deducts — distinct
    from not_evaluated, which means the data was never collected.
    """
    return CheckResult(
        check_id=meta.check_id,
        category=meta.category,
        status="not_applicable",
        default_severity=meta.default_severity,
        recommendation=meta.recommendation,
        findings=[],
        not_applicable_reason=reason,
    )


def dependency_state(
    conn: sqlite3.Connection, tables: List[str], scan_id: str
) -> str:
    """
    Classify a check's data dependency for a scan.

    Returns:
        "absent"  — every dependency table is missing (this scan predates the
                    collector, so the answer is genuinely unknown).
        "empty"   — at least one table exists but no rows for this scan (the
                    collector ran and the account has none of the resource).
        "present" — at least one table has rows for this scan.
    """
    present_tables = 0
    total_rows = 0
    for table in tables:
        try:
            count = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0]
        except sqlite3.OperationalError:
            continue  # table absent from this scan's schema
        present_tables += 1
        total_rows += count
    if present_tables == 0:
        return "absent"
    return "present" if total_rows > 0 else "empty"


def resolve_scan_id(conn: sqlite3.Connection, scan_id: Optional[str]) -> str:
    """Return the requested scan_id, or the latest scan when None."""
    cursor = conn.cursor()
    if scan_id:
        row = cursor.execute(
            "SELECT scan_id FROM scan_metadata WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            raise ValueError(f"Scan not found: {scan_id}")
        return scan_id
    row = cursor.execute(
        "SELECT scan_id FROM scan_metadata ORDER BY scan_timestamp DESC LIMIT 1"
    ).fetchone()
    if not row:
        raise ValueError("No scans in database")
    return row[0]


def run_checks(
    db_path: str,
    scan_id: Optional[str],
    category: Optional[str] = None,
) -> Dict:
    """
    Run all registered checks (optionally one category) against a scan.

    Returns findings grouped by category plus a list of checks that could
    not be evaluated, so the client always knows its coverage gaps.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        resolved = resolve_scan_id(conn, scan_id)
        categories: Dict[str, List[Dict]] = {}
        not_evaluated: List[Dict] = []

        for meta, fn in CHECKS.values():
            if category and meta.category != category:
                continue
            try:
                result = fn(conn, resolved)
            except Exception as e:  # a broken check must not sink the report
                result = make_result(meta, not_evaluated_reason=f"check error: {e}")
            payload = result.to_dict()
            if result.status == "not_evaluated":
                not_evaluated.append(payload)
            else:
                categories.setdefault(meta.category, []).append(payload)

        return {
            "scan_id": resolved,
            "categories": categories,
            "not_evaluated": not_evaluated,
        }
    finally:
        conn.close()


def get_catalogue() -> List[Dict]:
    """Machine-readable catalogue of every registered check."""
    return [
        {
            "check_id": meta.check_id,
            "category": meta.category,
            "title": meta.title,
            "detects": meta.detects,
            "default_severity": meta.default_severity,
            "recommendation": meta.recommendation,
            "data_dependencies": meta.data_dependencies,
        }
        for meta, _ in CHECKS.values()
    ]
