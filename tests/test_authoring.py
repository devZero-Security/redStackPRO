"""set_redirector_hostname is the operator's keystroke that RDR001 requires - the
domain a redirector answers on, which the shipped examples leave blank on purpose.
A single name covers the common one-redirector shape; a per-redirector map covers
split-horizon and rollover, where two redirectors front one C2 under different
names and one shared name would be a routing conflict rather than a shorthand.
"""

import pytest

from redstackpro.authoring import set_redirector_hostname


def _doc(*redirector_ids):
    nodes = [{"id": "jump", "kind": "jumpbox"}]
    nodes += [{"id": i, "kind": "redirector"} for i in redirector_ids]
    return {"nodes": nodes}


def _hostname(doc, node_id):
    for n in doc["nodes"]:
        if n["id"] == node_id:
            return (n.get("overlay") or {}).get("hostname")
    raise AssertionError(node_id)


def test_a_single_name_covers_every_redirector():
    doc = set_redirector_hostname(_doc("rd01", "rd02"), "cdn.example.com")
    assert _hostname(doc, "rd01") == "cdn.example.com"
    assert _hostname(doc, "rd02") == "cdn.example.com"


def test_a_map_names_each_redirector_on_its_own():
    # The split-horizon shape: two doors, two names, so the C2 profile and the
    # redirector agree on which name reaches which teamserver.
    doc = set_redirector_hostname(
        _doc("apa-rd01", "ngx-rd02"),
        {"apa-rd01": "static.example.com", "ngx-rd02": "status.example.com"})
    assert _hostname(doc, "apa-rd01") == "static.example.com"
    assert _hostname(doc, "ngx-rd02") == "status.example.com"


def test_a_map_missing_a_redirector_refuses():
    # Leaving one unnamed would compile a topology that still refuses on RDR001, or
    # worse deploys a redirector with no name. Better to say which one, now.
    with pytest.raises(ValueError, match="ngx-rd02"):
        set_redirector_hostname(_doc("apa-rd01", "ngx-rd02"),
                                {"apa-rd01": "static.example.com"})


def test_a_map_naming_a_stranger_refuses():
    # A typo'd node id would otherwise be silently ignored, leaving the real
    # redirector unnamed and the compile refusing for a reason that reads unrelated.
    with pytest.raises(ValueError, match="typo-rd"):
        set_redirector_hostname(_doc("apa-rd01"),
                                {"apa-rd01": "a.example.com",
                                 "typo-rd": "b.example.com"})


def test_a_topology_with_no_redirector_is_left_alone():
    doc = set_redirector_hostname({"nodes": [{"id": "jump", "kind": "jumpbox"}]},
                                  "cdn.example.com")
    assert all("hostname" not in (n.get("overlay") or {}) for n in doc["nodes"])
