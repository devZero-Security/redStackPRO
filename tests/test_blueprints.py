"""Blueprints are starter topologies to clone from. A seeded system one has no owner
and is readable by anyone; a team can publish its own. A clone is a private copy.
See 0025.
"""

import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from redstackpro.api import create_app
from redstackpro.api.app import BLUEPRINT_REDSTACK_ID
from redstackpro.api.principal import Principal

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "src/redstackpro/schema/topology/examples/0.4.0"
V1 = "/api/v1"


@pytest.fixture
def client():
    app = create_app("sqlite+pysqlite:///" + tempfile.mktemp(suffix=".db"))
    yield TestClient(app)
    app.state.engine.dispose()


@pytest.fixture
def document():
    return json.loads((EXAMPLES / "redstack.json").read_text())


def _blueprints(client):
    r = client.get(V1 + "/blueprints")
    assert r.status_code == 200
    return r.json()


def test_the_starter_is_seeded_as_a_blueprint(client):
    starters = _blueprints(client)
    assert len(starters) == 1
    only = starters[0]
    assert only["is_blueprint"] is True
    assert only["owner_id"] is None
    # No person owns it, so no person can edit it in place.
    assert only["editable"] is False


def test_the_topology_list_does_not_show_blueprints(client):
    assert _blueprints(client)                      # a blueprint exists
    assert client.get(V1 + "/topologies").json() == []  # and is not a topology


def test_a_blueprint_is_readable_despite_having_no_owner(client):
    bid = _blueprints(client)[0]["id"]
    r = client.get(V1 + "/topologies/%s" % bid)
    assert r.status_code == 200
    assert r.json()["document"]["schema_version"]


def test_cloning_makes_a_private_copy_owned_by_the_caller(client):
    blueprint = _blueprints(client)[0]
    r = client.post(V1 + "/blueprints/%s/clone" % blueprint["id"])
    assert r.status_code == 201
    clone = r.json()
    assert clone["id"] != blueprint["id"]
    assert clone["is_blueprint"] is False
    assert clone["visibility"] == "private"
    assert clone["owner_id"] is not None
    assert clone["editable"] is True

    # The clone shows up as a topology, the blueprint still does not.
    topologies = client.get(V1 + "/topologies").json()
    assert [g["id"] for g in topologies] == [clone["id"]]

    # Same topology, independent copy.
    cloned_doc = client.get(V1 + "/topologies/%s" % clone["id"]).json()["document"]
    blueprint_doc = client.get(
        V1 + "/topologies/%s" % blueprint["id"]).json()["document"]
    assert cloned_doc == blueprint_doc


def test_cloning_a_non_blueprint_is_not_found(client, document):
    created = client.post(V1 + "/topologies",
                          json={"name": "mine", "document": document})
    topology_id = created.json()["id"]
    r = client.post(V1 + "/blueprints/%s/clone" % topology_id)
    assert r.status_code == 404


def test_publish_then_unpublish_toggles_membership(client, document):
    created = client.post(V1 + "/topologies",
                          json={"name": "team template", "document": document})
    topology_id = created.json()["id"]
    assert topology_id not in [b["id"] for b in _blueprints(client)]

    published = client.post(V1 + "/topologies/%s/publish" % topology_id)
    assert published.status_code == 200
    assert published.json()["is_blueprint"] is True
    assert topology_id in [b["id"] for b in _blueprints(client)]
    # A published topology leaves the plain topology list.
    assert topology_id not in [g["id"] for g in client.get(V1 + "/topologies").json()]

    client.post(V1 + "/topologies/%s/unpublish" % topology_id)
    assert topology_id not in [b["id"] for b in _blueprints(client)]
    assert topology_id in [g["id"] for g in client.get(V1 + "/topologies").json()]


# A blueprint a team publishes is scoped to that team's org, unlike the seeded
# system starter which has no owner and is global. See 0028.

def test_a_published_blueprint_is_scoped_to_its_org(document):
    db_url = "sqlite+pysqlite:///" + tempfile.mktemp(suffix=".db")
    owner = TestClient(create_app(db_url))          # the local org, admin
    topology_id = owner.post(
        V1 + "/topologies", json={"name": "team template", "document": document}
    ).json()["id"]
    owner.post(V1 + "/topologies/%s/publish" % topology_id)

    outsider = TestClient(create_app(db_url, principal=Principal(
        id="u-outsider", org_id="org-elsewhere", kind="human", role="member")))
    listed = [b["id"] for b in outsider.get(V1 + "/blueprints").json()]
    # The system starter is global; the team's blueprint is not theirs to see.
    assert BLUEPRINT_REDSTACK_ID in listed
    assert topology_id not in listed
    # And it is unreadable and unclonable, the same as a topology they cannot read.
    assert outsider.get(V1 + "/topologies/%s" % topology_id).status_code == 404
    assert outsider.post(V1 + "/blueprints/%s/clone" % topology_id).status_code == 404


# Publishing pins the revision a clone gets, so the owner can keep editing the
# live topology without moving what the next clone reads. See 0028.

def _clone_document(client, blueprint_id):
    clone = client.post(V1 + "/blueprints/%s/clone" % blueprint_id).json()
    return client.get(V1 + "/topologies/%s" % clone["id"]).json()["document"]


def test_editing_after_publish_does_not_change_what_a_clone_gets(client, document):
    created = client.post(
        V1 + "/topologies", json={"name": "template", "document": document}).json()
    topology_id = created["id"]
    pinned_name = document["name"]

    published = client.post(V1 + "/topologies/%s/publish" % topology_id).json()

    edited = {**document, "name": "edited after publish"}
    bumped = client.put(V1 + "/topologies/%s" % topology_id,
                        json={"document": edited, "version": published["version"]})
    assert bumped.status_code == 200

    # The clone carries the revision that was published, not the later edit.
    assert _clone_document(client, topology_id)["name"] == pinned_name


def test_republishing_moves_the_pin_to_the_current_revision(client, document):
    created = client.post(
        V1 + "/topologies", json={"name": "template", "document": document}).json()
    topology_id = created["id"]

    first = client.post(V1 + "/topologies/%s/publish" % topology_id).json()
    revised = {**document, "name": "second version"}
    client.put(V1 + "/topologies/%s" % topology_id,
               json={"document": revised, "version": first["version"]})

    # Re-publishing releases the current revision as the new template.
    client.post(V1 + "/topologies/%s/publish" % topology_id)
    assert _clone_document(client, topology_id)["name"] == "second version"
