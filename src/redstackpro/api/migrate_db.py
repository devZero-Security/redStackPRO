"""Schema migrations for a real database.

Named migrate_db to keep it apart from migrate.py, which migrates topology documents
between schema versions. This one is about database tables.

create_all builds the schema for SQLite, where there is nothing to stand up and a
test throws the database away between runs. A real database is owned by
migrations instead, so a column added later reaches a deployment that already has
data rather than being silently skipped by create_all. See 0017 and 0023.

The alembic config is built in code rather than read from alembic.ini, so a
deployed package can upgrade itself without the repo's ini on disk. env.py still
supplies the target metadata and, when the CLI is used instead, the url.
"""

from pathlib import Path

from alembic import command
from alembic.config import Config

MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def _config(url):
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def upgrade_to_head(url):
    """Bring the database at url up to the latest revision."""
    command.upgrade(_config(url), "head")
