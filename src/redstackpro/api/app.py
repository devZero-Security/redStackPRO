"""The application.

redStackPRO generates code and does not deploy it. Nothing here holds cloud
credentials, runs Terraform, or reaches a target environment. See 0001.
"""

import json
import os
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..migrate import LATEST, migrate
from . import db, routes
from .routes import TAGS
from .principal import LOCAL_ORG_ID, LOCAL_PRINCIPAL, LOCAL_USER_ID

# A fixed id so a restart re-seeds the same blueprint rather than a second one.
# Reserved range, well clear of the generated hex ids. See 0025.
BLUEPRINT_REDSTACK_ID = "00000000000000000000000000000010"


def seed(session_factory):
    """One org, one admin. The columns exist from the first migration because
    retrofitting org scoping means touching every table and every query. See
    0009."""
    with session_factory() as sess:
        if sess.get(db.Org, LOCAL_ORG_ID) is None:
            sess.add(db.Org(id=LOCAL_ORG_ID, name="local"))
        if sess.get(db.User, LOCAL_USER_ID) is None:
            sess.add(db.User(id=LOCAL_USER_ID, org_id=LOCAL_ORG_ID,
                             email="local@localhost", role="admin"))
        sess.commit()


def _ensure_schema(engine):
    """SQLite builds the schema straight from the models: there is nothing to
    stand up and a test throws the database away. A real database is owned by
    migrations, so a schema change reaches a deployment that already has data
    instead of being skipped by create_all. A test asserts the two cannot drift.
    See 0023.

    A non-SQLite backend is upgraded on startup, which is convenient for a single
    instance self hosted deployment and is the wrong shape for several instances
    starting at once. That tradeoff is in 0023."""
    if engine.dialect.name == "sqlite":
        db.Base.metadata.create_all(engine)
    else:
        from .migrate_db import upgrade_to_head
        upgrade_to_head(engine.url.render_as_string(hide_password=False))


def seed_blueprints(session_factory):
    """A starter to clone from, seeded once. It belongs to no person, so owner_id
    is null; is_blueprint is what makes it readable by anyone. Idempotent on the
    fixed id, so a restart does not stack copies. See 0025.

    The document is migrated to the current schema on the way in, the same as any
    ingested document, so the seed does not go stale when the schema moves."""
    example = (Path(__file__).resolve().parents[1]
               / "schema/topology/examples" / LATEST / "redstack.json")
    if not example.is_file():
        return
    with session_factory() as sess:
        if sess.get(db.Topology, BLUEPRINT_REDSTACK_ID) is not None:
            return
        document = migrate(json.loads(example.read_text(encoding="utf-8")))
        topology = db.Topology(
            id=BLUEPRINT_REDSTACK_ID,
            org_id=LOCAL_ORG_ID,
            owner_id=None,
            name="redStack starter",
            mode=document.get("mode", "ops"),
            visibility="org",
            schema_version=document["schema_version"],
            version=1,
            is_blueprint=True,
        )
        sess.add(topology)
        sess.flush()
        revision = db.TopologyRevision(topology_id=topology.id, version=1,
                                    author_id=None, document=document)
        sess.add(revision)
        sess.flush()
        topology.current_revision_id = revision.id
        # The starter is published at its seeded revision, so a clone gets the
        # curated topology rather than nothing. See 0028.
        topology.published_revision_id = revision.id
        sess.commit()


def _static_dir():
    """The built canvas to serve, or None. REDSTACKPRO_STATIC_DIR overrides the
    repo-relative frontend/dist; without a build the API stays headless (dev uses vite)."""
    env = os.environ.get("REDSTACKPRO_STATIC_DIR")
    candidate = Path(env) if env else (
        Path(__file__).resolve().parents[3] / "frontend" / "dist")
    return candidate if candidate.is_dir() else None


def create_app(database_url=None, principal=None):
    engine = db.make_engine(database_url)
    _ensure_schema(engine)
    session_factory = db.make_session_factory(engine)
    seed(session_factory)
    seed_blueprints(session_factory)

    app = FastAPI(
        title="redStackPRO",
        version="0.4.0",
        description=(
            "Composition layer for red team infrastructure and cyber ranges. "
            "Build a topology from nodes and edges, get back a complete working "
            "directory of Terraform and Ansible that you run from your own "
            "machine.\n\n"
            "redStackPRO never holds cloud credentials and never runs the IaC "
            "engine. Two entry points exist for validation and compile: one "
            "keyed by a stored topology for the canvas, one taking a document "
            "inline for agents, which stores nothing.\n\n"
            "Errors carry a machine readable `code`, prose in `message`, and a "
            "`details` object. A failed compile puts every finding in "
            "`details.findings`."
        ),
        openapi_tags=TAGS,
    )
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.principal = principal or LOCAL_PRINCIPAL

    def get_session():
        sess = session_factory()
        try:
            yield sess
        finally:
            sess.close()

    app.dependency_overrides[routes.session] = get_session
    app.include_router(routes.router, prefix="/api/v1")

    @app.exception_handler(StarletteHTTPException)
    def structured_errors(request, exc):
        """Structured errors, not status codes alone. A raw string detail from
        FastAPI gets wrapped so every error has the same shape."""
        detail = exc.detail
        if not isinstance(detail, dict):
            detail = {"code": "error", "message": str(detail), "details": {}}
        return JSONResponse(status_code=exc.status_code, content=detail)

    @app.get("/api/v1/health", tags=["system"])
    def health():
        return {"status": "ok", "schema_version": LATEST}

    # Mounted last so the API router and /docs keep precedence.
    static_dir = _static_dir()
    if static_dir is not None:
        app.mount("/", StaticFiles(directory=static_dir, html=True),
                  name="canvas")

    return app


@contextmanager
def temporary_app(**kwargs):
    app = create_app(**kwargs)
    try:
        yield app
    finally:
        app.state.engine.dispose()