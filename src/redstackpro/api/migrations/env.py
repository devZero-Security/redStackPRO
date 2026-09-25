"""Alembic environment.

Metadata and URL both come from the application, not from alembic.ini: the URL
from REDSTACKPRO_DATABASE_URL, the same variable make_engine reads, and the target
metadata from the models. So autogenerate compares against the live models and an
upgrade runs against the same database the app opens. See 0023.

Batch mode is on because SQLite cannot ALTER a column in place, and a migration
that works on Postgres but not on the SQLite used in tests is a migration that
was never really tested.
"""

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from redstackpro.api import db

config = context.config

# A programmatic caller (the app's startup upgrade) sets the url on the config.
# The alembic CLI leaves it unset in alembic.ini, so it falls back to the same
# environment variable make_engine reads.
url = (config.get_main_option("sqlalchemy.url")
       or os.environ.get("REDSTACKPRO_DATABASE_URL", db.DEFAULT_URL))
config.set_main_option("sqlalchemy.url", url)

target_metadata = db.Base.metadata


def run_migrations_offline():
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=url.startswith("sqlite"),
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
