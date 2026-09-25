#!/usr/bin/env python3
"""Run the API locally.

    python3 tools/serve.py
    REDSTACKPRO_DATABASE_URL=postgresql+psycopg://... python3 tools/serve.py

SQLite by default so there is nothing to stand up. Postgres in deployment, where
the schema is brought to head on startup. To run migrations as a separate deploy
step instead, see tools/migrate.py. Interactive docs at
http://127.0.0.1:8000/docs

redStackPRO never holds cloud credentials and never runs Terraform. See 0001.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import uvicorn

from redstackpro.api import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host="127.0.0.1", port=8000)
