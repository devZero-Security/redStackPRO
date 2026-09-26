"""The API is the whole surface: every UI action goes through it, and the agent
harness submits documents to it. The tests that matter are the ones covering
what 0009 and 0010 decided, not the happy path.
"""

import json
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from redstackpro.api import create_app, db
from redstackpro.api.principal import LOCAL_ORG_ID, Principal
from shipped import example
from sqlalchemy import select

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "src/redstackpro/schema/topology/examples/0.6.0"
V1 = "/api/v1"


@pytest.fixture
def app():
    url = "sqlite+pysqlite:///" + tempfile.mktemp(suffix=".db")
    application = create_app(url)
    yield application
    application.state.engine.dispose()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def document():
    return example("redstack.json")


@pytest.fixture
def topology_id(client, document):
    r = client.post(V1 + "/topologies", json={"name": "redStack",
                                          "document": document})
    assert r.status_code == 201
    return r.json()["id"]


def as_principal(app, **kwargs):
    base = dict(id="other", org_id=LOCAL_ORG_ID, kind="human", role="member")
    base.update(kwargs)
    app.state.principal = Principal(**base)


# -- basics

def test_health(client):
    assert client.get(V1 + "/health").json()["status"] == "ok"


def test_create_and_read(client, document):
    r = client.post(V1 + "/topologies", json={"name": "x", "document": document})
    assert r.status_code == 201
    body = r.json()
    assert body["version"] == 1
    assert body["visibility"] == "private"

    got = client.get(V1 + "/topologies/" + body["id"]).json()
    assert got["document"]["schema_version"] == "0.6.0"


def test_document_without_schema_version_is_rejected(client):
    r = client.post(V1 + "/topologies", json={"name": "x", "document": {"nodes": []}})
    assert r.status_code == 422
    assert r.json()["code"] == "invalid_request"


def test_errors_are_structured_not_bare_strings(client):
    body = client.get(V1 + "/topologies/nope").json()
    assert set(body) == {"code", "message", "details"}
    assert body["code"] == "not_found"


# -- migration on ingest

def test_an_old_document_is_migrated_on_create(client):
    old = json.loads((ROOT / "src/redstackpro/schema/topology/examples/0.1.0/redstack.json").read_text())
    r = client.post(V1 + "/topologies", json={"name": "old", "document": old})
    assert r.status_code == 422, "0.1.0 cannot be migrated without a prefix"
    assert "prefix" in r.json()["message"]


# -- compare and swap

def test_update_bumps_the_version(client, topology_id, document):
    r = client.put(V1 + "/topologies/" + topology_id,
                   json={"document": document, "version": 1})
    assert r.status_code == 200
    assert r.json()["version"] == 2


def test_stale_write_is_a_conflict(client, topology_id, document):
    client.put(V1 + "/topologies/" + topology_id,
               json={"document": document, "version": 1})
    r = client.put(V1 + "/topologies/" + topology_id,
                   json={"document": document, "version": 1})
    assert r.status_code == 409
    assert r.json()["code"] == "conflict"
    assert r.json()["details"]["current_version"] == 2


def test_every_save_is_a_revision(client, topology_id, document):
    for version in (1, 2, 3):
        client.put(V1 + "/topologies/" + topology_id,
                   json={"document": document, "version": version})
    revisions = client.get(V1 + "/topologies/%s/revisions" % topology_id).json()
    assert len(revisions["revisions"]) == 4
    assert sum(r["current"] for r in revisions["revisions"]) == 1


# -- idempotency

def test_idempotency_key_does_not_create_twice(client, document):
    headers = {"Idempotency-Key": "abc123"}
    first = client.post(V1 + "/topologies", json={"name": "x", "document": document},
                        headers=headers)
    second = client.post(V1 + "/topologies", json={"name": "x", "document": document},
                         headers=headers)
    assert first.json()["id"] == second.json()["id"]
    assert len(client.get(V1 + "/topologies").json()) == 1


# -- visibility and sharing

def test_private_topology_is_invisible_to_others(app, client, topology_id):
    as_principal(app)
    assert client.get(V1 + "/topologies/" + topology_id).status_code == 404
    assert client.get(V1 + "/topologies").json() == []


def test_org_visible_topology_is_readable(app, client, topology_id, document):
    client.put(V1 + "/topologies/" + topology_id,
               json={"document": document, "version": 1, "visibility": "org"})
    as_principal(app)
    assert client.get(V1 + "/topologies/" + topology_id).status_code == 200


def test_org_visible_topology_is_read_only(app, client, topology_id, document):
    client.put(V1 + "/topologies/" + topology_id,
               json={"document": document, "version": 1, "visibility": "org"})
    as_principal(app)
    r = client.put(V1 + "/topologies/" + topology_id,
                   json={"document": document, "version": 2})
    assert r.status_code == 403
    assert "Duplicate it" in r.json()["message"]


def test_reuse_is_by_copy(app, client, topology_id, document):
    client.put(V1 + "/topologies/" + topology_id,
               json={"document": document, "version": 1, "visibility": "org"})
    as_principal(app)
    r = client.post(V1 + "/topologies/%s/duplicate" % topology_id)
    assert r.status_code == 201
    copy = r.json()
    assert copy["id"] != topology_id
    assert copy["owner_id"] == "other"
    assert copy["visibility"] == "private", "a copy is not shared by default"
    assert copy["version"] == 1


def test_a_copy_is_independent(app, client, topology_id, document):
    """No link back to the source, so the owner flipping it private or leaving
    the org affects nobody's copy."""
    r = client.post(V1 + "/topologies/%s/duplicate" % topology_id)
    copy_id = r.json()["id"]
    client.put(V1 + "/topologies/" + topology_id,
               json={"document": document, "version": 1, "name": "renamed"})
    assert client.get(V1 + "/topologies/" + copy_id).json()["topology"]["name"] \
        == "redStack (copy)"


def test_admin_sees_everything_in_the_org(app, client, topology_id):
    as_principal(app, role="admin")
    assert len(client.get(V1 + "/topologies").json()) == 1


def test_another_org_sees_nothing(app, client, topology_id):
    as_principal(app, org_id="different", role="admin")
    assert client.get(V1 + "/topologies").json() == []
    assert client.get(V1 + "/topologies/" + topology_id).status_code == 404


# -- validation

def test_validate_reports_findings(client, topology_id):
    body = client.post(V1 + "/topologies/%s/validate" % topology_id).json()
    assert body["valid"] is True
    assert body["warnings"] >= 1


def test_validate_against_a_provider_catches_capability_gaps(client, topology_id):
    body = client.post(V1 + "/topologies/%s/validate?provider=proxmox"
                       % topology_id).json()
    assert body["valid"] is False
    assert any(f["code"] == "CAP002" for f in body["findings"])


def test_agent_submits_a_document_without_storing_it(client, document):
    """Post a whole topology, get failures with reasons, iterate. That loop is
    the agent interface. See architecture.md."""
    document["edges"] = [e for e in document["edges"] if e["role"] != "manages"]
    body = client.post(V1 + "/validate", json={"document": document}).json()
    assert body["valid"] is False
    assert any(f["code"] == "MGT001" for f in body["findings"])
    assert client.get(V1 + "/topologies").json() == [], "nothing was stored"


def test_findings_carry_prose_and_values(client, document):
    document["edges"] = [e for e in document["edges"] if e["role"] != "manages"]
    finding = next(f for f in
                   client.post(V1 + "/validate",
                               json={"document": document}).json()["findings"]
                   if f["code"] == "MGT001")
    assert finding["message"] != finding["template"]
    assert finding["target_ids"]
    assert finding["remedy"]


# -- compile

def test_compile_returns_a_file_map(client, topology_id):
    body = client.post(V1 + "/topologies/%s/compile" % topology_id).json()
    paths = {f["path"] for f in body["files"]}
    assert "terraform/main.tf" in paths
    assert "ansible/inventory.yml" in paths
    assert body["compile_id"]


def test_compile_refuses_an_invalid_topology(client, document):
    document["edges"] = [e for e in document["edges"] if e["role"] != "manages"]
    r = client.post(V1 + "/compile", json={"document": document})
    assert r.status_code == 422
    assert r.json()["details"]["findings"]


def test_compile_rejects_an_unknown_provider(client, topology_id):
    r = client.post(V1 + "/topologies/%s/compile?provider=digitalocean" % topology_id)
    assert r.status_code == 422
    assert "digitalocean" in r.json()["message"]


def test_archive_is_the_same_files_as_the_map(client, topology_id):
    """The zip is a formatter over the file map, so the two cannot disagree.
    See 0010."""
    body = client.post(V1 + "/topologies/%s/compile" % topology_id).json()
    archive = client.get(V1 + "/compile/%s/archive" % body["compile_id"])
    assert archive.headers["content-type"] == "application/zip"

    with zipfile.ZipFile(BytesIO(archive.content)) as zf:
        assert set(zf.namelist()) == {f["path"] for f in body["files"]}
        first = body["files"][0]
        assert zf.read(first["path"]).decode() == first["contents"]


def test_archive_is_not_readable_by_another_principal(app, client, topology_id):
    body = client.post(V1 + "/topologies/%s/compile" % topology_id).json()
    as_principal(app)
    r = client.get(V1 + "/compile/%s/archive" % body["compile_id"])
    assert r.status_code == 404


def test_no_credentials_in_the_compiled_output(client, topology_id):
    body = client.post(V1 + "/topologies/%s/compile" % topology_id).json()
    joined = "\n".join(f["contents"] for f in body["files"])
    # No PEM key or certificate material in the export. Match the PEM header, not a
    # bare "BEGIN", so legitimate T-SQL (BEGIN TRY / BEGIN CATCH in a vuln role)
    # does not trip the scan while every private key / cert block still does.
    assert "-----BEGIN" not in joined
    assert 'ssh_public_key = ""' in joined


# -- registry

def test_palette_is_served_from_the_registry(client):
    groups = client.get(V1 + "/registry/palette").json()["groups"]
    kinds = {e["kind"] for g in groups.values() for e in g}
    assert "teamserver" in kinds
    assert all(e["icon"] for g in groups.values() for e in g)


def test_range_palette_carries_the_range_kinds(client):
    groups = client.get(V1 + "/registry/palette?mode=haven").json()["groups"]
    kinds = {e["kind"] for g in groups.values() for e in g}
    assert {"domain", "dc", "srv", "wks", "fw"} <= kinds
    assert "teamserver" not in kinds


def test_providers_report_what_they_cannot_do(client):
    providers = {p["name"]: p for p in
                 client.get(V1 + "/registry/providers").json()["providers"]}
    assert "public_address" not in providers["proxmox"]["capabilities"]
    assert providers["proxmox"]["unsupported"][0]["reason"]


# -- the export has to be runnable

def test_compiled_export_includes_the_static_modules(client, topology_id):
    """Without the modules tree `terraform init` fails, and the download button
    is the product. See 0010."""
    body = client.post(V1 + "/topologies/%s/compile" % topology_id).json()
    paths = {f["path"] for f in body["files"]}
    assert "terraform/modules/gcp/host/main.tf" in paths
    assert "terraform/modules/gcp/network/main.tf" in paths
    assert "terraform/modules/gcp/segment/main.tf" in paths


def test_compiled_export_includes_the_roles_and_the_runbook(client, topology_id):
    body = client.post(V1 + "/topologies/%s/compile" % topology_id).json()
    paths = {f["path"] for f in body["files"]}
    assert "ansible/roles/redstackpro.redirector/tasks/main.yml" in paths
    assert "ansible/roles/redstackpro.teamserver/tasks/c2-mythic.yml" in paths
    assert "ansible/requirements.yml" in paths
    assert "tf_inventory.py" in paths
    assert "README.md" in paths


def test_every_role_the_playbook_names_is_present(client, topology_id):
    """A play referencing a role that is not in the export fails at syntax
    check, before anything runs."""
    files = {f["path"]: f["contents"]
             for f in client.post(V1 + "/topologies/%s/compile"
                                  % topology_id).json()["files"]}
    import yaml
    for play in yaml.safe_load(files["ansible/site.yml"]):
        for entry in play["roles"]:
            # A conditional role is a mapping rather than a bare name. The
            # shipper is one, because shipping follows the logs_to edge and not
            # the group the play targets.
            role = entry["role"] if isinstance(entry, dict) else entry
            assert "ansible/roles/%s/tasks/main.yml" % role in files, role


def test_only_the_target_providers_modules_are_included(client, topology_id):
    body = client.post(V1 + "/topologies/%s/compile" % topology_id).json()
    paths = {f["path"] for f in body["files"]}
    assert not any("/modules/aws/" in p or "/modules/proxmox/" in p
                   for p in paths)


# -- pagination and delete (0026)

def test_topology_list_pages_without_overlap(client, document):
    ids = set()
    for i in range(3):
        r = client.post(V1 + "/topologies",
                        json={"name": "g%d" % i, "document": document})
        ids.add(r.json()["id"])

    first = client.get(V1 + "/topologies?limit=2").json()
    second = client.get(V1 + "/topologies?limit=2&offset=2").json()
    assert len(first) == 2
    assert len(second) == 1
    seen = {g["id"] for g in first} | {g["id"] for g in second}
    assert seen == ids, "the two pages should cover every topology exactly once"


def test_a_bad_page_bound_is_rejected(client):
    assert client.get(V1 + "/topologies?limit=0").status_code == 422
    assert client.get(V1 + "/topologies?offset=-1").status_code == 422


def test_revisions_page_newest_first(client, topology_id, document):
    for _ in range(2):
        current = client.get(
            V1 + "/topologies/%s" % topology_id).json()["topology"]["version"]
        client.put(V1 + "/topologies/%s" % topology_id,
                   json={"document": document, "version": current})

    revs = client.get(
        V1 + "/topologies/%s/revisions?limit=2" % topology_id).json()["revisions"]
    assert [r["version"] for r in revs] == [3, 2]


def test_delete_removes_the_topology_and_its_revisions(client, app, topology_id):
    assert client.delete(V1 + "/topologies/%s" % topology_id).status_code == 204
    assert client.get(V1 + "/topologies/%s" % topology_id).status_code == 404
    assert topology_id not in [g["id"] for g in client.get(V1 + "/topologies").json()]

    with app.state.session_factory() as sess:
        rows = sess.scalars(select(db.TopologyRevision).where(
            db.TopologyRevision.topology_id == topology_id)).all()
        assert rows == [], "revisions should cascade with the topology"


def test_delete_is_owner_only(client, app, document):
    shared = client.post(V1 + "/topologies", json={
        "name": "shared", "document": document, "visibility": "org"}).json()
    as_principal(app, id="intruder")
    # A member of the org can read it but not delete it.
    assert client.delete(V1 + "/topologies/%s" % shared["id"]).status_code == 403
