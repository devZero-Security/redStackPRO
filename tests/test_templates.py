"""The shipped canvas templates (frontend/public) are a product surface: a
person picks one and builds on it, so a malformed one is a broken first
impression. These lint them so a hand-edit or a schema change cannot ship a
template that fails validation or violates the range model. The GOAD family is
also checked against the model: each range has a jumpbox to operate it, a
wazuh/elastic agent implies the manager box that installs it, and joins/trusts
land on the right kinds. See 0047 and the GOAD extensions.
"""

import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "frontend/public"
SCHEMA = json.loads((ROOT / "schema/topology/0.4.0.json").read_text())

RANGE_HOST_KINDS = {"dc", "srv", "wks", "fw"}
SIEM_EDRS = {"wazuh", "elastic"}
MODE_PREFIX = {"ops": "red", "range": "cyb"}


def _templates():
    docs = []
    # Recursive: the GOAD range templates live in the goad/ subdirectory.
    for path in sorted(PUBLIC.rglob("*.json")):
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict) and "nodes" in doc:
            docs.append(pytest.param(doc, id=path.name))
    return docs


TEMPLATES = _templates()


def test_templates_are_present():
    # Guard against the glob silently matching nothing, which would make every
    # per-template test vacuously pass.
    assert len(TEMPLATES) >= 7


@pytest.mark.parametrize("doc", TEMPLATES)
def test_template_matches_schema(doc):
    jsonschema.Draft202012Validator(SCHEMA).validate(doc)


@pytest.mark.parametrize("doc", TEMPLATES)
def test_template_is_referentially_sound(doc):
    ids = [n["id"] for n in doc["nodes"]]
    assert len(ids) == len(set(ids)), "duplicate node id"
    known = set(ids)
    for edge in doc["edges"]:
        assert edge["source"] in known, edge["id"]
        assert edge["target"] in known, edge["id"]


@pytest.mark.parametrize("doc", TEMPLATES)
def test_mode_and_prefix_agree(doc):
    mode = doc.get("mode", "ops")
    assert doc["prefix"] == MODE_PREFIX[mode]


@pytest.mark.parametrize("doc", TEMPLATES)
def test_a_range_has_a_jumpbox_to_operate_it(doc):
    if doc.get("mode") != "range":
        pytest.skip("ops template")
    assert any(n["kind"] == "jumpbox" for n in doc["nodes"])


@pytest.mark.parametrize("doc", TEMPLATES)
def test_an_agent_edr_implies_its_manager_box(doc):
    # The wazuh and elastic EDRs are the GOAD extensions: an agent on a host
    # comes with a standalone manager the extension installs. A template with
    # the agent but no SIEM box would draw an agent reporting to nothing.
    kinds = {n["kind"] for n in doc["nodes"]}
    edrs = {n.get("overlay", {}).get("edr") for n in doc["nodes"]}
    if edrs & SIEM_EDRS:
        assert "siem" in kinds


@pytest.mark.parametrize("doc", TEMPLATES)
def test_joins_and_trusts_land_on_the_right_kinds(doc):
    kind = {n["id"]: n["kind"] for n in doc["nodes"]}
    for edge in doc["edges"]:
        if edge["role"] == "joins":
            assert kind[edge["source"]] in RANGE_HOST_KINDS, edge["id"]
            assert kind[edge["target"]] == "domain", edge["id"]
        elif edge["role"] == "trusts":
            assert kind[edge["source"]] == "domain", edge["id"]
            assert kind[edge["target"]] == "domain", edge["id"]


@pytest.mark.parametrize("doc", TEMPLATES)
def test_hardening_values_are_in_the_schema_enum(doc):
    allowed = set(
        SCHEMA["$defs"]["overlay_range_host"]["properties"]["hardening"]["items"]["enum"]
    )
    for node in doc["nodes"]:
        for value in node.get("overlay", {}).get("hardening", []):
            assert value in allowed, value


def test_every_shipped_template_stops_itself():
    """A range deployed and forgotten bills until someone remembers it, and the
    person most likely to forget is the one trying the product for the first
    time. Michael's call 2026-09-13 after goad full turned out to be the one
    range with nothing to stop it.

    auto_stop is implemented for GCP and Azure; AWS gained it the same day. It is
    still ignored by proxmox and esxi, which are on-prem and bill nothing, so the
    field being present costs them nothing either.
    """
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "frontend/public"
    missing = []
    for path in sorted(root.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        # Only whole canvases; a fragment with no nodes is not a template.
        if not doc.get("nodes"):
            continue
        stop = doc.get("auto_stop") or {}
        if not stop.get("enabled"):
            missing.append(path.name)
    assert not missing, (
        "these shipped templates never stop themselves: %s. Add auto_stop, or a "
        "user who tries them pays for a weekend." % ", ".join(missing))
