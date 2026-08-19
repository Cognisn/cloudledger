"""
Schema equivalence harness: the schema produced by DatabaseSchema must match
the frozen baseline captured from the legacy hand-written DDL.

TIMESTAMP columns are declared as Text in the SQLAlchemy metadata (ISO-string
storage, unchanged behaviour); the comparison normalises the baseline
accordingly. Uses Australian English in all comments.
"""

import importlib.util
import json
import tempfile
from pathlib import Path

import pytest

from cloudledger.database.schema import DatabaseSchema

BASELINE = json.loads(
    (Path(__file__).parent / "fixtures" / "schema_baseline.json").read_text()
)

# Declared-type normalisation applied to the BASELINE side (see module docstring).
TYPE_NORMALISATION = {"TIMESTAMP": "TEXT"}


def _normalise(table: dict) -> dict:
    out = json.loads(json.dumps(table))
    for col in out["columns"]:
        col["type"] = TYPE_NORMALISATION.get(col["type"], col["type"])
    return out


def _current_snapshot() -> dict:
    spec = importlib.util.spec_from_file_location(
        "capture_schema_baseline",
        Path(__file__).parent.parent / "scripts" / "capture_schema_baseline.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    snapshot_schema = mod.snapshot_schema

    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "current.db")
        DatabaseSchema(db).initialise_database()
        return snapshot_schema(db)


CURRENT = None


def setup_module(module):
    global CURRENT
    CURRENT = _current_snapshot()


def test_table_set_is_complete():
    assert set(CURRENT["tables"]) == set(BASELINE["tables"])


@pytest.mark.parametrize("table", sorted(BASELINE["tables"]))
def test_table_matches_baseline(table):
    assert table in CURRENT["tables"], f"missing table {table}"
    assert _normalise(CURRENT["tables"][table]) == _normalise(BASELINE["tables"][table])
