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
