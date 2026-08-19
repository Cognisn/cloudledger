"""
Tests for scan tag operations: add, remove, list and lookup by tag.

Uses Australian English in all documentation and comments.
"""

from datetime import datetime, UTC

import pytest

from cloudledger.database.models import ScanMetadata
from cloudledger.database.operations import DatabaseOperations
from cloudledger.database.schema import DatabaseSchema


def _scan_metadata(**overrides):
    defaults = dict(
        scan_id="s1",
        account_name="a",
        account_number="123456789012",
        scan_timestamp=datetime.now(UTC),
        prowler_level="1",
        regions_scanned=["ap-southeast-2"],
        scan_status="in_progress",
    )
    defaults.update(overrides)
    return ScanMetadata(**defaults)


@pytest.fixture
def db_ops(tmp_path):
    path = str(tmp_path / "tags.db")
    DatabaseSchema(path).initialise_database()
    ops = DatabaseOperations(path)
    ops.insert_scan_metadata(_scan_metadata(scan_id="s1"))
    ops.insert_scan_metadata(_scan_metadata(scan_id="s2"))
    return ops


def test_add_and_get_tags_case_preserved(db_ops):
    added = db_ops.add_tags("s1", ["Client-Acme", "  q3-review  ", ""])
    assert added == ["Client-Acme", "q3-review"]
    assert db_ops.get_tags_for_scan("s1") == ["Client-Acme", "q3-review"]


def test_add_tags_dedupes_case_insensitively(db_ops):
    db_ops.add_tags("s1", ["Prod"])
    assert db_ops.add_tags("s1", ["prod", "PROD", "new"]) == ["new"]
    assert db_ops.get_tags_for_scan("s1") == ["new", "Prod"]


def test_add_tags_unknown_scan_raises(db_ops):
    with pytest.raises(ValueError, match="Scan not found"):
        db_ops.add_tags("nope", ["x"])


def test_remove_tags_case_insensitive(db_ops):
    db_ops.add_tags("s1", ["Alpha", "beta"])
    assert db_ops.remove_tags("s1", ["ALPHA", "missing"]) == 1
    assert db_ops.get_tags_for_scan("s1") == ["beta"]


def test_list_tags_counts_scans(db_ops):
    db_ops.add_tags("s1", ["shared", "only-one"])
    db_ops.add_tags("s2", ["Shared"])
    tags = {t["tag"]: t["scan_count"] for t in db_ops.list_tags()}
    assert tags["only-one"] == 1
    assert list(tags) == sorted(tags, key=str.lower)
    assert 2 in tags.values()  # the shared/Shared group counts both scans


def test_find_scans_by_tag(db_ops):
    db_ops.add_tags("s1", ["Engagement-X", "extra"])
    db_ops.add_tags("s2", ["engagement-x"])
    scans = db_ops.find_scans_by_tag("ENGAGEMENT-X")
    assert {s["scan_id"] for s in scans} == {"s1", "s2"}
    s1 = next(s for s in scans if s["scan_id"] == "s1")
    assert set(s1["tags"]) == {"Engagement-X", "extra"}
