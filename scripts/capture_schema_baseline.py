"""
Capture a JSON snapshot of the database schema produced by DatabaseSchema.

Run once against the legacy DDL to freeze the baseline the SQLAlchemy
metadata must reproduce. Uses Australian English in all comments.
"""

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cloudledger.database.schema import DatabaseSchema


def snapshot_schema(db_path: str) -> dict:
    """Return {tables: {name: {columns, indexes, foreign_keys}}} for a database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    tables = {}
    names = [
        r["name"]
        for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    for name in names:
        cols = [
            {
                "name": c["name"],
                "type": c["type"].upper(),
                "notnull": c["notnull"],
                "default": c["dflt_value"],
                "pk": c["pk"],
            }
            for c in cur.execute(f"PRAGMA table_info('{name}')")
        ]
        indexes = {}
        for idx in cur.execute(f"PRAGMA index_list('{name}')"):
            if idx["name"].startswith("sqlite_autoindex"):
                continue
            indexes[idx["name"]] = [
                i["name"] for i in cur.execute(f"PRAGMA index_info('{idx[1]}')")
            ]
        fks = [
            {"table": fk["table"], "from": fk["from"], "to": fk["to"]}
            for fk in cur.execute(f"PRAGMA foreign_key_list('{name}')")
        ]
        tables[name] = {"columns": cols, "indexes": indexes, "foreign_keys": fks}
    conn.close()
    return {"tables": tables}


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "baseline.db")
        DatabaseSchema(db).initialise_database()
        out = Path(__file__).parent.parent / "tests" / "fixtures" / "schema_baseline.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(snapshot_schema(db), indent=2, sort_keys=True))
        print(f"Baseline written: {out}")
