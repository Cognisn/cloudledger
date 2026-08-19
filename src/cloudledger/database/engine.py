"""
Database engine factory for CloudLedger.

Builds SQLAlchemy engines from either a filesystem path (SQLite) or a full
database URL. Server backends are enabled for users by the setup command in
a later phase; this factory is already URL-capable.
Uses Australian English in all documentation and comments.
"""

from pathlib import Path

import sqlalchemy as sa


def make_engine(target: str) -> sa.Engine:
    """Return an engine for a SQLite file path or an SQLAlchemy database URL.

    A plain path is treated as a SQLite database file and its parent
    directory is created if missing, matching the legacy behaviour of
    the schema initialiser.
    """
    if "://" in target:
        return sa.create_engine(target)
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    return sa.create_engine(f"sqlite:///{path}")
