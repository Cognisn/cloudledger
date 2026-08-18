"""
Shared fixtures for assessment engine tests.

Creates a schema-initialised SQLite database seeded with one scan row.
Uses Australian English in all documentation and comments.
"""

import sqlite3
from datetime import datetime, UTC
from pathlib import Path

from cloudledger.database.schema import DatabaseSchema
from cloudledger.database.models import ScanMetadata
from cloudledger.database.operations import DatabaseOperations

SCAN_ID = "scan-assess-0001"


def make_db(tmp_path) -> str:
    """Create an initialised database with one scan row; return its path."""
    db_path = str(Path(tmp_path) / "assessment_test.db")
    DatabaseSchema(db_path).initialise_database()
    db_ops = DatabaseOperations(db_path)
    db_ops.insert_scan_metadata(ScanMetadata(
        scan_id=SCAN_ID,
        account_name="test-account",
        account_number="123456789012",
        scan_timestamp=datetime.now(UTC),
        regions_scanned=["ap-southeast-2"],
        scan_status="completed",
    ))
    return db_path


def execute(db_path: str, sql: str, params: tuple = ()) -> None:
    """Run a single INSERT/UPDATE statement against the test database."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(sql, params)
        conn.commit()


def rows(db_path: str, sql: str, params: tuple = ()) -> list:
    """Run a SELECT and return sqlite3.Row results."""
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(sql, params).fetchall()
