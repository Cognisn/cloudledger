"""
UTC time serialisation helpers.

CloudLedger stores every application-generated timestamp as an ISO-8601
string carrying an explicit UTC offset (`+00:00`), so stored values are
unambiguous regardless of the host's local timezone. Uses Australian
English in all documentation and comments.
"""

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """Return the current instant as an ISO-8601 string with a UTC offset."""
    return datetime.now(timezone.utc).isoformat()


def to_utc_iso(dt: datetime) -> str:
    """Serialise a datetime to an ISO-8601 string with a UTC offset.

    Naive datetimes are assumed to already be UTC; aware datetimes are
    converted to UTC before serialisation.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()
