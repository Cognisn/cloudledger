"""
Query-output equivalence harness: every MCP tool call in
`mcp_query_fixtures.CALL_MATRIX` must reproduce the frozen baseline captured
from the legacy raw-sqlite3 `QueryHandler` implementation.

This is the gate later tasks (rewriting `mcp/queries.py` onto SQLAlchemy
Core) must keep green: their output, once volatile keys are normalised, must
match this baseline entry for entry. Uses Australian English in all
comments.
"""

import json
import tempfile
from pathlib import Path

import pytest

from cloudledger.database.operations import DatabaseOperations
from cloudledger.mcp.queries import QueryHandler

from tests.mcp_query_fixtures import CALL_MATRIX, VOLATILE_KEYS, seed_database

BASELINE = json.loads(
    (Path(__file__).parent / "fixtures" / "query_baseline.json").read_text()
)


def _normalise(value):
    """Recursively replace any dict key in VOLATILE_KEYS, at any depth, with a placeholder."""
    if isinstance(value, dict):
        return {
            key: ("<volatile>" if key in VOLATILE_KEYS else _normalise(val))
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    return value


HANDLER = None


def setup_module(module):
    """Seed a database once per test session and build the query handler against it."""
    global HANDLER
    tmp_dir = tempfile.mkdtemp()
    db_path = str(Path(tmp_dir) / "query_equivalence.db")
    seed_database(db_path)
    HANDLER = QueryHandler(DatabaseOperations(db_path))


def _entry_ids():
    return [f"{i:03d}:{name}" for i, (name, _params) in enumerate(CALL_MATRIX)]


@pytest.mark.parametrize(
    ("key", "tool_name", "params"),
    [(f"{i:03d}:{name}", name, params) for i, (name, params) in enumerate(CALL_MATRIX)],
    ids=_entry_ids(),
)
def test_query_matches_baseline(key, tool_name, params):
    assert key in BASELINE, f"baseline missing entry {key}"
    output = _normalise(HANDLER.handle_query(tool_name, params))
    assert output == BASELINE[key]
