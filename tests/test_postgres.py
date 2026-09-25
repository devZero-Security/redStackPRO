"""The one test that runs the schema against a real Postgres.

The rest of the suite uses SQLite, where create_app builds the schema with
create_all. A real backend takes the other branch: alembic upgrade to head. If
the baseline migration is wrong for Postgres, or the JSON columns do not behave,
this is where it shows rather than in a deployment.

Skipped unless REDSTACKPRO_TEST_DATABASE_URL points at a non-SQLite database, which
only the postgres CI job sets. See 0023.
"""

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import shipped
from redstackpro.api import create_app

URL = os.environ.get("REDSTACKPRO_TEST_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not URL or URL.startswith("sqlite"),
    reason="REDSTACKPRO_TEST_DATABASE_URL is not set to a non-sqlite database")

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "src/redstackpro/schema/topology/examples/0.4.0"
V1 = "/api/v1"


def test_create_app_migrates_then_serves_on_postgres():
    """create_app on a non-sqlite backend runs the migrations, then the schema
    has to actually carry a topology and a compile: a create writes the topology, a
    revision, and a JSON document; a compile writes and reads a JSON file map."""
    app = create_app(URL)
    try:
        assert app.state.engine.dialect.name != "sqlite"
        client = TestClient(app)
        # The example ships one field short on purpose (RDR001), so stand in for the
        # operator the way the rest of the suite and the CLI do, or the compile below
        # refuses and this reads as a database failure.
        document = shipped.deployable(
            json.loads((EXAMPLES / "redstack.json").read_text()))

        created = client.post(V1 + "/topologies",
                              json={"name": "pg", "document": document})
        assert created.status_code == 201, created.text
        topology_id = created.json()["id"]

        fetched = client.get(V1 + "/topologies/%s" % topology_id)
        assert fetched.status_code == 200
        assert fetched.json()["document"]["schema_version"]

        compiled = client.post(V1 + "/compile",
                               json={"document": document, "provider": "aws"})
        assert compiled.status_code == 200, compiled.text
        compile_id = compiled.json()["compile_id"]

        archive = client.get(V1 + "/compile/%s/archive" % compile_id)
        assert archive.status_code == 200
        assert archive.headers["content-type"] == "application/zip"
    finally:
        app.state.engine.dispose()
