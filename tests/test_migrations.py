"""The schema is built two ways: create_all in tests and on SQLite, alembic on a
real database. If those drift, a deployment ends up with a schema the code does
not expect. These tests assert they cannot.
"""

import tempfile

import pytest
from sqlalchemy import create_engine, inspect

pytest.importorskip("alembic")

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from redstackpro.api import db
from redstackpro.api.migrate_db import _config, upgrade_to_head


def _sqlite_url():
    return "sqlite+pysqlite:///" + tempfile.mktemp(suffix=".db")


def test_config_preserves_percent_in_url():
    """A url can carry a percent (a percent-encoded windows sqlite path or a db
    password). Python 3.14 configparser rejects a bare % on set, so _config must
    hand the original url straight back. This guards a real startup upgrade, not
    just the test path."""
    url = "postgresql+psycopg://u:p%40ss@h:5432/d"
    cfg = _config(url)
    assert cfg.get_main_option("sqlalchemy.url") == url


def test_migrations_leave_nothing_for_autogenerate():
    """Upgrade a fresh database to head, then ask alembic what it would still
    change to match the models. Anything it finds is drift between the baseline
    migration and db.py."""
    url = _sqlite_url()
    upgrade_to_head(url)
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            diffs = compare_metadata(context, db.Base.metadata)
    finally:
        engine.dispose()
    assert diffs == [], "migrations and models drifted: %r" % (diffs,)


def test_migrations_and_create_all_build_the_same_tables():
    """The coarse check behind the autogenerate one: both paths produce the same
    tables and columns, so a test that runs on create_all is testing the schema a
    deployment gets from alembic."""
    migrated = create_engine(_sqlite_url())
    built = create_engine(_sqlite_url())
    try:
        upgrade_to_head(migrated.url.render_as_string(hide_password=False))
        db.Base.metadata.create_all(built)

        m, b = inspect(migrated), inspect(built)
        assert set(m.get_table_names()) - {"alembic_version"} == \
            set(b.get_table_names())
        for table in b.get_table_names():
            assert {c["name"] for c in m.get_columns(table)} == \
                {c["name"] for c in b.get_columns(table)}, table
    finally:
        migrated.dispose()
        built.dispose()
