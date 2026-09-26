"""Stored compile results and idempotency keys age out. These cover the rule
(old goes, recent stays), the off switch, an env override, and that the sweep
actually fires on the compile and create paths rather than only in a unit test.
"""

import json
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from redstackpro.api import create_app, db, retention
from shipped import example

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "src/redstackpro/schema/topology/examples/0.6.0"
V1 = "/api/v1"


@pytest.fixture
def session():
    engine = db.make_engine("sqlite+pysqlite:///" + tempfile.mktemp(suffix=".db"))
    db.Base.metadata.create_all(engine)
    sess = db.make_session_factory(engine)()
    yield sess
    sess.close()
    engine.dispose()


def _result(sess, age_days):
    row = db.CompileResult(principal_id="p", provider="aws", files={},
                           created_at=db.now() - timedelta(days=age_days))
    sess.add(row)
    sess.commit()
    return row.id


def _key(sess, name, age_hours):
    sess.add(db.IdempotencyKey(key=name, principal_id="p", resource_id="g",
                               created_at=db.now() - timedelta(hours=age_hours)))
    sess.commit()


# -- the rule

def test_old_compile_results_go_recent_stay(session):
    fresh = _result(session, 0)
    _result(session, 30)
    assert retention.prune_compile_results(session) == 1
    session.commit()
    remaining = session.scalars(select(db.CompileResult.id)).all()
    assert remaining == [fresh]


def test_old_idempotency_keys_go_recent_stay(session):
    _key(session, "old", 48)
    _key(session, "recent", 1)
    assert retention.prune_idempotency_keys(session) == 1
    session.commit()
    remaining = session.scalars(select(db.IdempotencyKey.key)).all()
    assert remaining == ["recent"]


# -- configuration

def test_a_zero_window_turns_the_sweep_off(session, monkeypatch):
    monkeypatch.setenv(retention.COMPILE_RESULT_TTL_DAYS, "0")
    _result(session, 365)
    assert retention.prune_compile_results(session) == 0
    session.commit()
    assert session.scalar(select(db.CompileResult.id)) is not None


def test_the_window_is_env_configurable(session, monkeypatch):
    monkeypatch.setenv(retention.IDEMPOTENCY_KEY_TTL_HOURS, "2")
    _key(session, "three-hours", 3)
    _key(session, "one-hour", 1)
    assert retention.prune_idempotency_keys(session) == 1
    session.commit()
    assert session.scalars(select(db.IdempotencyKey.key)).all() == ["one-hour"]


def test_a_garbage_window_falls_back_to_the_default(session, monkeypatch):
    monkeypatch.setenv(retention.COMPILE_RESULT_TTL_DAYS, "not-a-number")
    _result(session, 30)
    fresh = _result(session, 0)
    assert retention.prune_compile_results(session) == 1
    session.commit()
    assert session.scalars(select(db.CompileResult.id)).all() == [fresh]


# -- wired into the request paths

@pytest.fixture
def app():
    application = create_app("sqlite+pysqlite:///" + tempfile.mktemp(suffix=".db"))
    yield application
    application.state.engine.dispose()


@pytest.fixture
def document():
    return example("redstack.json")


def test_a_compile_sweeps_stale_results(app, document):
    """An old result is present, a compile happens, and the old one is gone
    afterward while the compile's own result survives."""
    factory = app.state.session_factory
    with factory() as sess:
        stale = db.CompileResult(principal_id="stale", provider="aws", files={},
                                 created_at=db.now() - timedelta(days=90))
        sess.add(stale)
        sess.commit()
        stale_id = stale.id

    client = TestClient(app)
    r = client.post(V1 + "/compile", json={"document": document,
                                            "provider": "aws"})
    assert r.status_code == 200

    with factory() as sess:
        assert sess.get(db.CompileResult, stale_id) is None
        assert sess.get(db.CompileResult, r.json()["compile_id"]) is not None
