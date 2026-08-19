"""
Capture a JSON snapshot of MCP query-tool outputs against the legacy
raw-sqlite3 QueryHandler.

Run once against the legacy `mcp/queries.py` implementation to freeze the
baseline that later SQLAlchemy Core rewrites must reproduce. Uses Australian
English in all comments.
"""

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))

from cloudledger.database.operations import DatabaseOperations
from cloudledger.mcp.queries import QueryHandler


def _load_fixtures():
    spec = importlib.util.spec_from_file_location(
        "mcp_query_fixtures",
        Path(__file__).parent.parent / "tests" / "mcp_query_fixtures.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def capture(db_path: str, fixtures) -> dict:
    """Run every CALL_MATRIX entry through handle_query and return the normalised results."""
    db_ops = DatabaseOperations(db_path)
    handler = QueryHandler(db_ops)

    baseline = {}
    for index, (tool_name, params) in enumerate(fixtures.CALL_MATRIX):
        key = f"{index:03d}:{tool_name}"
        output = handler.handle_query(tool_name, params)
        baseline[key] = fixtures._normalise(output, fixtures.VOLATILE_KEYS)
    return baseline


if __name__ == "__main__":
    fixtures = _load_fixtures()

    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "query_baseline.db")
        fixtures.seed_database(db)
        baseline = capture(db, fixtures)

        out = (
            Path(__file__).parent.parent / "tests" / "fixtures" / "query_baseline.json"
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(baseline, indent=2, sort_keys=True))
        print(f"Baseline written: {out}")
        print(f"Entries: {len(baseline)}")
