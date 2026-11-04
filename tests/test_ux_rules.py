"""The 0.10.0 UX pass on the validator: the schema check, the field path a
finding carries for the canvas, the info severity, and the rules that catch a
value which compiles but does nothing or breaks the deploy. Each rule has a case
that fires and one that does not.
"""

import json
from pathlib import Path

import pytest

from redstackpro.findings import finding

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "src/redstackpro/schema/topology/0.7.0.json")
                    .read_text(encoding="utf-8"))
DEFS = SCHEMA["$defs"]


# -- the finding shape

def test_a_field_finding_serializes_its_path():
    d = finding("SCH001", "error", ["rd01"], "{path} bad", path="tls.cert_source",
                field="tls.cert_source").to_dict()
    assert d["field"] == "tls.cert_source"
    assert d["message"] == "tls.cert_source bad"


def test_a_finding_without_a_field_keeps_its_old_shape():
    d = finding("X001", "error", ["a"], "bad").to_dict()
    assert "field" not in d


def test_info_is_a_severity():
    assert finding("X001", "info", ["a"], "note").severity == "info"
    with pytest.raises(ValueError):
        finding("X001", "notice", ["a"], "note")


# -- the schema as the canvas reads it

def _untitled(node, path):
    out = []
    if isinstance(node, dict):
        for key, spec in (node.get("properties") or {}).items():
            if "title" not in spec:
                out.append("/".join(path + [key]))
            out += _untitled(spec, path + [key])
        if isinstance(node.get("items"), dict):
            out += _untitled(node["items"], path + ["[]"])
    return out


def test_every_property_has_a_title():
    gaps = _untitled(SCHEMA, ["root"])
    for name, spec in DEFS.items():
        gaps += _untitled(spec, [name])
    assert not gaps, gaps


def test_the_shared_defs_carry_a_title_and_help():
    # The Inspector resolves $ref, so a field that is only a $ref shows these.
    for name in ("identifier", "cidr", "ipv4", "port", "public_address"):
        assert DEFS[name].get("title"), name
        assert DEFS[name].get("description"), name


def test_values_that_broke_the_deploy_are_gone_from_the_enums():
    rd = DEFS["overlay_redirector"]["properties"]["tls"]["properties"]
    assert "provided" not in rd["cert_source"]["enum"]
    assert "splunk" not in DEFS["overlay_collector"]["properties"]["sink"]["enum"]
    assert "splunk" not in DEFS["overlay_siem"]["properties"]["product"]["enum"]


LINUX = ("debian_13", "debian_12", "ubuntu_2204", "ubuntu_2004")


def test_every_named_linux_os_maps_to_an_image_on_each_cloud():
    from redstackpro.terraform import aws, azure, gcp
    range_os = DEFS["overlay_range_host"]["properties"]["os"]["enum"]
    siem_os = DEFS["overlay_siem"]["properties"]["os"]["enum"]
    for os in LINUX:
        assert os in range_os and os in siem_os, os
        assert os in gcp.LINUX_IMAGES, os
        assert os in aws.LINUX_IMAGES, os
        assert os in azure.LINUX_IMAGES, os
    assert set(siem_os) == set(LINUX)


# -- SCH001, the schema applied inside validate()

from redstackpro import validate  # noqa: E402
from shipped import example  # noqa: E402


def _sch(doc):
    return [f for f in validate(doc) if f.code == "SCH001"]


def _node(doc, kind):
    return next(n for n in doc["nodes"] if n["kind"] == kind)


def test_a_clean_document_has_no_schema_finding():
    assert not _sch(example("redstack.json"))


@pytest.mark.parametrize("mutate, target, field, words", [
    (lambda d: d.update(prefix="R_T"), "topology", "prefix",
     "1 to 8 lowercase letters"),
    (lambda d: _node(d, "segment")["overlay"].update(cidr="10.30.0.0"),
     "mgmt-sub01", "cidr", "CIDR form"),
    (lambda d: _node(d, "segment")["overlay"].update(cidr="10.30.10.5/24"),
     "mgmt-sub01", "cidr", "10.30.10.0/24"),
    (lambda d: _node(d, "redirector")["overlay"].update(
        hostname="https://cdn.x.net/"), "apache-rd01", "hostname", "no scheme"),
    (lambda d: _node(d, "redirector")["overlay"]["gating"].update(
        header_name="X Request Id"), "apache-rd01", "gating.header_name",
     "X-Request-Id"),
    (lambda d: _node(d, "redirector")["overlay"]["tls"].update(
        cert_source="provided"), "apache-rd01", "tls.cert_source",
     "must be one of letsencrypt, self_signed"),
    (lambda d: _node(d, "collector")["overlay"].pop("sink"), "open-log01", "sink",
     "is required"),
    (lambda d: _node(d, "collector")["overlay"].update(sink="splunk"),
     "open-log01", "sink", "must be one of"),
    (lambda d: d.update(auto_stop={"enabled": True, "at": "25:00"}), "topology",
     "auto_stop.at", "HH:MM"),
])
def test_a_bad_value_is_one_finding_naming_its_field(mutate, target, field, words):
    doc = example("redstack.json")
    mutate(doc)
    found = _sch(doc)
    assert len(found) == 1, [f.message for f in found]
    f = found[0]
    assert f.severity == "error"
    assert f.target_ids == (target,)
    assert f.field == field
    assert words in f.message
    assert f.message.startswith(field + " on ")


def test_a_fronts_edge_field_is_reported_on_the_edge():
    doc = example("redstack.json")
    edge = next(e for e in doc["edges"] if e["role"] == "fronts")
    edge["uri_prefix"] = "api/v1"
    edge["listen_port"] = "443"
    found = {f.field: f for f in _sch(doc)}
    assert set(found) == {"uri_prefix", "listen_port"}
    assert found["uri_prefix"].target_ids == (edge["id"],)
    assert "Example: /cdn/assets" in found["uri_prefix"].message
    assert "must be a whole number" in found["listen_port"].message


def test_a_field_no_kind_has_is_reported_once_per_key():
    doc = example("redstack.json")
    node = _node(doc, "collector")
    node["name"] = "RT-LOG"
    node["overlay"]["colour"] = "red"
    found = sorted(f.field for f in _sch(doc))
    assert found == ["colour", "name"]


def test_a_range_internal_ip_and_hostname_are_checked():
    doc = json.loads((ROOT / "frontend/public/goad/goad-light.json").read_text())
    dc = _node(doc, "dc")
    dc["overlay"]["internal_ip"] = "10.30.10.300"
    dc["overlay"]["hostname"] = "kingslanding-keep"
    found = {f.field: f for f in _sch(doc)}
    assert set(found) == {"internal_ip", "hostname"}
    # A range names hosts by bare id.
    assert found["hostname"].message.startswith("hostname on %s:" % dc["id"])


def test_problems_another_rule_reports_are_not_repeated():
    doc = example("redstack.json")
    jb = _node(doc, "jumpbox")
    jb["overlay"]["access_mode"] = "wireguard"
    jb["overlay"]["operators"] = [{"handle": "Bad Name"}]
    _node(doc, "redirector")["overlay"]["hostname"] = ""
    codes = [f.code for f in validate(doc)]
    assert "VPN005" in codes and "RDR001" in codes
    assert not _sch(doc)


def test_a_document_missing_ids_reports_instead_of_raising():
    doc = example("minimal.json")
    doc["nodes"][0].pop("id")
    found = validate(doc)
    assert [f.code for f in found] == ["SCH001"]
    assert found[0].target_ids == ("topology",)
    assert found[0].field == "nodes.0.id"


def test_an_unknown_schema_version_is_one_finding():
    doc = example("minimal.json")
    doc["schema_version"] = "9.9.9"
    found = _sch(doc)
    assert len(found) == 1 and found[0].field == "schema_version"


def test_an_older_document_is_checked_against_its_own_version():
    doc = json.loads((ROOT / "src/redstackpro/schema/topology/examples/0.6.0/"
                      "redstack.json").read_text())
    assert doc["schema_version"] == "0.6.0"
    assert not _sch(doc)


def test_the_api_serializes_the_field_path(tmp_path):
    from fastapi.testclient import TestClient
    from redstackpro.api import create_app
    app = create_app("sqlite+pysqlite:///" + str(tmp_path / "t.db"))
    try:
        doc = example("redstack.json")
        _node(doc, "redirector")["overlay"]["tls"]["cert_source"] = "provided"
        body = TestClient(app).post("/api/v1/validate",
                                    json={"document": doc}).json()
        sch = [f for f in body["findings"] if f["code"] == "SCH001"]
        assert sch == [{
            "code": "SCH001", "severity": "error",
            "target_ids": ["apache-rd01"],
            "template": "{path} on {node}: {reason}.",
            "values": {"path": "tls.cert_source", "node": "off-apache-rd01",
                       "reason": "must be one of letsencrypt, self_signed"},
            "message": "tls.cert_source on off-apache-rd01: must be one of "
                       "letsencrypt, self_signed.",
            "remedy": "Pick one of the listed values.",
            "field": "tls.cert_source",
        }]
        assert body["valid"] is False and body["infos"] == 0
    finally:
        app.state.engine.dispose()
