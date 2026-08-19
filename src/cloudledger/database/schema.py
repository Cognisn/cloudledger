"""
Database schema management for CloudLedger.

The schema itself is declared in tables.py as SQLAlchemy Core metadata;
this module creates it and tracks the schema version, preserving the
legacy public surface. Uses Australian English in all documentation
and comments.
"""

import logging
from datetime import datetime, UTC

import sqlalchemy as sa

from .engine import make_engine
from .tables import metadata, t_schema_version

logger = logging.getLogger(__name__)


class DatabaseSchema:
    """Manages database schema creation and versioning."""

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str):
        """Initialise the schema manager for a database path or URL."""
        self.db_path = db_path
        self._engine = make_engine(db_path)

    def initialise_database(self) -> None:
        """Create all tables and indices if they do not exist."""
        logger.info(f"Initialising database at {self.db_path}")
        metadata.create_all(self._engine)
        with self._engine.begin() as conn:
            existing = conn.execute(
                sa.select(sa.func.max(t_schema_version.c.version))
            ).scalar()
            if existing is None:
                conn.execute(
                    t_schema_version.insert().values(
                        version=self.SCHEMA_VERSION,
                        applied_at=datetime.now(UTC).isoformat(),
                    )
                )
        logger.info("Database initialisation complete")

    def get_schema_version(self):
        """Return the recorded schema version, or None before initialisation."""
        try:
            with self._engine.connect() as conn:
                return conn.execute(
                    sa.select(sa.func.max(t_schema_version.c.version))
                ).scalar()
        except sa.exc.OperationalError:
            return None
