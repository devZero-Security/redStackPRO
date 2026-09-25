"""The default id scheme (0016, 0044).

The derivation maps repeat the registry's kind tags in three places (registry
data, this backend module, the frontend copy). This pins the backend copy to the
registry so they cannot drift, and checks that renumber produces valid ids that
cascade through edges.
"""

import json
from pathlib import Path

from redstackpro import validate
from redstackpro.idscheme import KIND_TAG, renumber
from redstackpro.registry import Registry
from shipped import example

ROOT = Path(__file__).resolve().parent.parent


def test_kind_tags_match_the_registry():
    reg = Registry(ROOT / "src/redstackpro/schema/registry")
    for kind, spec in reg.kinds.items():
        assert KIND_TAG[kind] == spec["abbrev"], kind
    # every kind is covered, so a new kind cannot slip in untagged
    assert set(KIND_TAG) == set(reg.kinds)


def test_renumber_puts_the_redstack_on_the_scheme():
    doc = example("redstack.json")
    # renumber derives the slug from each node's kind, overlay, and membership,
    # not from its current id, so this checks the derivation itself.
    out = renumber(doc)
    ids = {n["id"] for n in out["nodes"]}
    assert {"main-net01", "rdir-net01", "mgmt-sub01", "c2-sub01", "rdir-sub01"} <= ids
    assert {"jump-bx01", "apache-rd01", "myth-ts01", "sliv-ts01", "adpx-ts01"} <= ids
    assert {"open-log01", "kali-op01", "win-op01"} <= ids


def test_renumber_cascades_and_validates():
    doc = example("redstack.json")
    out = renumber(doc)
    ids = {n["id"] for n in out["nodes"]}
    for edge in out["edges"]:
        assert edge["source"] in ids, edge
        assert edge["target"] in ids, edge
    reg = Registry(ROOT / "src/redstackpro/schema/registry")
    errors = {f.code for f in validate(out, registry=reg) if f.severity == "error"}
    assert errors == set(), errors


def test_renumber_is_idempotent():
    doc = example("redstack.json")
    once = renumber(doc)
    twice = renumber(once)
    assert [n["id"] for n in once["nodes"]] == [n["id"] for n in twice["nodes"]]
