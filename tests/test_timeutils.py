"""
Tests for UTC time serialisation helpers.

Uses Australian English in all documentation and comments.
"""

from datetime import datetime, timedelta, timezone

from cloudledger.utils.timeutils import to_utc_iso, utc_now_iso


def test_utc_now_iso_carries_utc_offset():
    value = utc_now_iso()
    assert value.endswith("+00:00")
    assert datetime.fromisoformat(value).tzinfo is not None


def test_to_utc_iso_converts_aware_datetimes():
    plus_ten = timezone(timedelta(hours=10))
    dt = datetime(2026, 8, 19, 10, 0, 0, tzinfo=plus_ten)
    assert to_utc_iso(dt) == "2026-08-19T00:00:00+00:00"


def test_to_utc_iso_assumes_naive_is_utc():
    assert to_utc_iso(datetime(2026, 8, 19, 10, 0, 0)) == "2026-08-19T10:00:00+00:00"
