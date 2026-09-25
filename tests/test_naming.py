"""Naming is composed, never stored. Anything derived from a node has to agree
with everything else derived from that node, which is the failure 0016 fixes.
"""

import json
import re
from pathlib import Path

import pytest

from redstackpro import validate
from redstackpro.ansible import generate as generate_ansible
from redstackpro.migrate import LATEST, MigrationError, migrate
from redstackpro.naming import compose, platform_account, tf_ref, too_long
from redstackpro.terraform import generate as generate_terraform

ROOT = Path(__file__).resolve().parent.parent


def codes(topology, **kw):
    return {f.code for f in validate(topology, **kw) if f.severity == "error"}


# -- composition

def test_compose_and_ref():
    assert compose("rt", "ts-01") == "rt-ts-01"
    assert tf_ref("rt", "ts-01") == "rt_ts_01"


def test_netbios_limit():
    assert not too_long("rt", "ts-01")
    assert too_long("operator12", "dc-01")


# -- rules

def test_nam001_wrong_abbreviation(redstack, registry):
    for node in redstack["nodes"]:
        if node["id"] == "myth-ts01":
            node["id"] = "myth-srv01"
    for edge in redstack["edges"]:
        for end in ("source", "target"):
            if edge[end] == "myth-ts01":
                edge[end] = "myth-srv01"
    assert "NAM001" in codes(redstack, registry=registry)


def test_nam002_host_needs_an_ordinal(redstack, registry):
    for node in redstack["nodes"]:
        if node["id"] == "myth-ts01":
            node["id"] = "myth-ts"
    for edge in redstack["edges"]:
        for end in ("source", "target"):
            if edge[end] == "myth-ts01":
                edge[end] = "myth-ts"
    assert "NAM002" in codes(redstack, registry=registry)


def test_containers_also_carry_a_tag_and_ordinal(redstack, registry):
    """The old container label affordance is gone: a segment id needs the sub
    kind tag and a two digit ordinal, the same as a host. c2-sub01 is legal; a
    bare label like dmz fails both NAM001 and NAM002."""
    assert "NAM001" not in codes(redstack, registry=registry)
    assert "NAM002" not in codes(redstack, registry=registry)
    for node in redstack["nodes"]:
        if node["id"] == "c2-sub01":
            node["id"] = "dmz"
    for edge in redstack["edges"]:
        for end in ("source", "target"):
            if edge[end] == "c2-sub01":
                edge[end] = "dmz"
    errors = codes(redstack, registry=registry)
    assert "NAM001" in errors
    assert "NAM002" in errors


def test_nam003_too_long_for_netbios(redstack, registry):
    redstack["prefix"] = "operator12"
    assert "NAM003" in codes(redstack, registry=registry)


# -- the prefix reaches everything

def test_prefix_flows_into_both_generators(redstack):
    redstack["prefix"] = "op7"
    ansible = generate_ansible(redstack)
    terraform = generate_terraform(redstack)

    assert "ansible/host_vars/op7-myth-ts01.yml" in ansible
    assert 'module "op7_myth_ts01"' in terraform["terraform/main.tf"]
    assert '"op7-myth-ts01"' in terraform["terraform/outputs.tf"]


def test_placeholder_keys_match_terraform_output_keys(redstack):
    """A mismatch here means tf_inventory silently fills nothing.

    Two namespaces resolve: a host token keys into redstackpro_addresses by
    node, and an "@settings" token names a field of redstackpro_settings, the
    apply-time answers the topology does not carry.
    """
    ansible = generate_ansible(redstack)
    outputs = generate_terraform(redstack)["terraform/outputs.tf"]
    settings_block = outputs.split('output "redstackpro_settings"')[-1]

    tokens = set()
    for text in ansible.values():
        tokens |= set(re.findall(r"<<tf:([^:>]+):([^:>]+)>>", text))
    assert tokens
    for key, field in tokens:
        if key == "@settings":
            assert 'output "redstackpro_settings"' in outputs, \
                "@settings tokens need a redstackpro_settings output"
            assert field in settings_block, \
                "@settings.%s has no field in redstackpro_settings" % field
        else:
            assert '"%s"' % key in outputs, "%s has no terraform output" % key


def test_firewall_tags_match_host_module_tags(redstack):
    terraform = generate_terraform(redstack)
    tags = set(re.findall(r'node_id\s+= "([^"]+)"', terraform["terraform/main.tf"]))
    used = set(re.findall(r'_tags\s+= \[([^\]]+)\]', terraform["terraform/firewall.tf"]))
    referenced = set()
    for group in used:
        referenced |= {t.strip().strip('"') for t in group.split(",")}
    assert referenced <= tags, "firewall references a tag no host carries"


# -- migration

def test_migration_moves_0_1_0_forward():
    old = json.loads(
        (ROOT / "schema/topology/examples/0.1.0/redstack.json").read_text())
    # Steps chain, so a 0.1.0 document comes out at whatever is current rather
    # than at the next version along.
    assert migrate(old, to="0.2.0", prefix="rt")["schema_version"] == "0.2.0"
    new = migrate(old, prefix="rt")
    assert new["schema_version"] == LATEST
    assert new["prefix"] == "rt"
    assert all("name" not in n for n in new["nodes"])
    assert {n["id"] for n in new["nodes"]} >= {"myth-ts01", "apache-rd01", "c2-sub01"}


def test_migration_rewrites_edge_endpoints():
    old = json.loads(
        (ROOT / "schema/topology/examples/0.1.0/minimal.json").read_text())
    new = migrate(old, prefix="rt")
    ids = {n["id"] for n in new["nodes"]}
    for edge in new["edges"]:
        assert edge["source"] in ids
        assert edge["target"] in ids


def test_migration_refuses_to_guess_the_prefix():
    old = json.loads(
        (ROOT / "schema/topology/examples/0.1.0/minimal.json").read_text())
    with pytest.raises(MigrationError):
        migrate(old)


def test_migrated_documents_validate(registry):
    for name in ("minimal", "redstack", "parallel-chains"):
        old = json.loads(
            (ROOT / ("schema/topology/examples/0.1.0/%s.json" % name)).read_text())
        new = migrate(old, prefix="rt")
        errors = codes(new, registry=registry)
        # RDR001 is expected here: the legacy examples predate it and carry a
        # placeholder redirector domain, and migration cannot invent a domain the
        # operator owns. A migrated document legitimately needs a human to set one
        # before it compiles, which is the whole point of the rule.
        assert errors <= {"NAM002", "RDR001"}, "%s: %s" % (name, errors)


# -- palette

def test_every_kind_has_display_metadata(registry):
    for kind, spec in registry.kinds.items():
        display = spec.get("display") or {}
        for field in ("label", "icon", "group", "color"):
            assert display.get(field), "%s is missing display.%s" % (kind, field)


def test_palette_groups_by_declared_group(registry):
    palette = registry.palette("ops")
    assert set(palette) == {
        "topology", "redirector", "teamservers", "management", "operator"}
    kinds = {e["kind"] for group in palette.values() for e in group}
    ops_kinds = {k for k, s in registry.kinds.items()
                 if "ops" in s.get("modes", ["ops"])}
    assert kinds == ops_kinds


def test_range_palette_carries_the_range_kinds(registry):
    palette = registry.palette("range")
    kinds = {e["kind"] for group in palette.values() for e in group}
    # the range-specific kinds, plus the shared containers
    assert {"domain", "dc", "srv", "wks", "fw"} <= kinds
    assert {"network", "segment"} <= kinds
    # ops-only kinds do not appear on the range canvas
    assert "teamserver" not in kinds
    assert "redirector" not in kinds


def test_platform_account_is_one_name_per_canvas_by_mode():
    """The single platform account (P1.7): blueop on a defensive range, redop on
    an offensive ops platform, redop as the conservative default for an unset or
    unknown mode."""
    assert platform_account("range") == "blueop"
    assert platform_account("ops") == "redop"
    assert platform_account(None) == "redop"
    assert platform_account("anything-else") == "redop"


def test_palette_carries_the_abbreviation(registry):
    """The canvas proposes the next free id from this, so it has to be here
    rather than hardcoded alongside the icons."""
    entry = next(e for g in registry.palette().values() for e in g
                 if e["kind"] == "teamserver")
    assert entry["abbrev"] == "ts"
