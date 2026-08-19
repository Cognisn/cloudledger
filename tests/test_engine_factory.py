"""
Tests for the database engine factory.

Uses Australian English in all documentation and comments.
"""

from cloudledger.database.engine import make_engine


def test_plain_path_becomes_sqlite_url(tmp_path):
    db = tmp_path / "x.db"
    engine = make_engine(str(db))
    assert engine.url.drivername == "sqlite"
    assert engine.url.database == str(db)


def test_url_passes_through(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'y.db'}")
    assert engine.url.drivername == "sqlite"


def test_parent_directory_created(tmp_path):
    db = tmp_path / "nested" / "dir" / "z.db"
    make_engine(str(db))
    assert db.parent.exists()
