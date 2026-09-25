#!/usr/bin/env python3
"""Bring the database schema up to the latest revision.

    REDSTACKPRO_DATABASE_URL=postgresql+psycopg://... python3 tools/migrate.py

create_app upgrades the schema on startup, which suits a single instance. Running
this as a separate deploy step is the safer shape when several instances start at
once, so the migration runs once rather than racing. See 0023.

Nothing here holds a cloud credential or reaches a target environment. It touches
your database and nothing else. See 0001.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from redstackpro.api import db
from redstackpro.api.migrate_db import upgrade_to_head

if __name__ == "__main__":
    url = os.environ.get("REDSTACKPRO_DATABASE_URL", db.DEFAULT_URL)
    print("upgrading %s" % url)
    upgrade_to_head(url)
    print("at head")
