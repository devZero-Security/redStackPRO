"""Every rule needs a fixture that makes it fire.

A validator with no negative tests is a validator that silently stops working.
"""

import json

import pytest

from redstackpro import validate, is_valid


def codes(topology, **kw):
    return {f.code for f in validate(topology, **kw)}


def errors(topology, **kw):
    return {f.code for f in validate(topology, **kw) if f.severity == "error"}


# -- the committed examples

def test_minimal_is_clean(minimal):
    assert is_valid(minimal)


def test_redstack_is_clean(redstack):
    assert is_valid(redstack)


def test_redstack_clean_on_gcp(redstack, registry):
    assert is_valid(redstack, provider="gcp", registry=registry)


def test_redstack_fails_on_proxmox(redstack, registry):
    assert "CAP002" in errors(redstack, provider="proxmox", registry=registry)


# -- referential

def test_ref001_dangling_edge(minimal):
    minimal["edges"][0]["target"] = "does-not-exist"
    assert "REF001" in errors(minimal)


def test_ref002_duplicate_id(minimal):
    minimal["nodes"].append(dict(minimal["nodes"][0]))
    assert "REF002" in errors(minimal)


# -- endpoints

def test_end002_fronts_wrong_kinds(minimal):
    for e in minimal["edges"]:
        if e["role"] == "fronts":
            e["source"] = "jump-bx01"
    assert "END002" in errors(minimal)


# -- cardinality

def test_car001_unattached_host(minimal):
    minimal["edges"] = [e for e in minimal["edges"] if e["id"] != "e-myth-ts01-c2-sub01-attached"]
    assert "CAR001" in errors(minimal)


def test_car002_segment_in_two_networks(minimal):
    minimal["edges"].append({"id": "extra", "role": "attached",
                             "source": "c2-sub01", "target": "main-net01"})
    assert "CAR002" in errors(minimal)


def test_car004_two_collectors(redstack):
    redstack["nodes"].append({
        "id": "open-log02", "kind": "collector", "name": "RT-LOG-02",
        "overlay": {"sink": "opensearch"}})
    redstack["edges"] += [
        {"id": "att2", "role": "attached", "source": "open-log02", "target": "mgmt-sub01"},
        {"id": "dup", "role": "logs_to", "source": "myth-ts01", "target": "open-log02"}]
    assert "CAR004" in errors(redstack)


def test_car005_two_managers(minimal):
    minimal["nodes"].append({
        "id": "jump-bx02", "kind": "jumpbox", "name": "RT-JUMP-02",
        "overlay": {"services": ["ssh"]}})
    minimal["edges"] += [
        {"id": "j2att", "role": "attached", "source": "jump-bx02", "target": "mgmt-sub01"},
        {"id": "j2mgmt", "role": "manages", "source": "jump-bx02", "target": "main-net01"}]
    assert "CAR005" in errors(minimal)


def test_car007_unfronted_teamserver_warns(minimal):
    minimal["edges"] = [e for e in minimal["edges"] if e["role"] != "fronts"]
    assert "CAR007" in codes(minimal)
    assert is_valid(minimal), "an unfronted teamserver is a warning, not an error"


def test_car008_ui_c2_without_gui_operator_warns(redstack):
    # redstack runs a mythic teamserver and ships a Windows operator, so it is clean.
    assert "CAR008" not in codes(redstack)
    # Drop the Windows operator: a Kali operator is SSH only, so nothing can open
    # the mythic web UI. This is exactly what stranded the operator on the harbor run.
    win_ops = {n["id"] for n in redstack["nodes"]
               if n["kind"] == "operator" and (n.get("overlay") or {}).get("os") == "windows"}
    assert win_ops, "fixture should ship a Windows operator"
    redstack["nodes"] = [n for n in redstack["nodes"] if n["id"] not in win_ops]
    redstack["edges"] = [e for e in redstack["edges"]
                         if e["source"] not in win_ops and e["target"] not in win_ops]
    assert "CAR008" in codes(redstack)
    assert is_valid(redstack), "a UI C2 without a GUI operator is a warning, not an error"


def test_rng009_user_flaw_declared_as_host_vuln_warns():
    """Kerberoasting on a host is a no-op (it is a user flaw), so the compiler
    warns rather than silently planting nothing. It stays valid: a warning, not
    an error. See F-dual-modeling."""
    topology = {
        "schema_version": "0.4.0", "mode": "range", "name": "T", "prefix": "cyb",
        "nodes": [
            {"id": "net01", "kind": "network", "overlay": {"cidr": "192.168.0.0/16"}},
            {"id": "sub01", "kind": "segment",
             "overlay": {"cidr": "192.168.56.0/24", "egress": "allowed", "exposure": "local"}},
            {"id": "d", "kind": "domain",
             "overlay": {"fqdn": "t.lab", "netbios": "T",
                         "users": [{"username": "a", "privilege": "domain_admin"}]}},
            {"id": "dc01", "kind": "dc", "overlay": {"vulns": ["kerberoasting"]}},
        ],
        "edges": [
            {"id": "e1", "role": "attached", "source": "sub01", "target": "net01"},
            {"id": "e2", "role": "attached", "source": "dc01", "target": "sub01"},
            {"id": "e3", "role": "joins", "source": "dc01", "target": "d"},
        ],
    }
    assert "RNG009" in codes(topology)
    assert "RNG009" not in errors(topology), "a no-op host vuln is a warning, not an error"


def test_shipped_labs_have_no_user_flaw_host_vulns():
    """The bug RNG009 catches must not be present in any shipped GOAD lab."""
    import glob
    import os
    root = os.path.join(os.path.dirname(__file__), "..", "frontend", "public", "goad")
    for path in glob.glob(os.path.join(root, "*.json")):
        topology = json.loads(open(path, encoding="utf-8").read())
        assert "RNG009" not in codes(topology), os.path.basename(path)


# -- management and exposure

def test_mgt001_no_management_path(minimal):
    minimal["edges"] = [e for e in minimal["edges"] if e["role"] != "manages"]
    assert "MGT001" in errors(minimal)


def test_exp002_teamserver_exposed(minimal):
    """A teamserver holding an address, which is now the host's own field
    rather than a fact about the segment it landed in. See 0021."""
    for n in minimal["nodes"]:
        if n["id"] == "c2-sub01":
            n["overlay"]["exposure"] = "internet"
        if n["id"] == "myth-ts01":
            n["overlay"]["public_address"] = True
    assert "EXP002" in errors(minimal)


def test_a_permissive_segment_alone_exposes_nothing(minimal):
    """The whole point of the ceiling. A teamserver in a segment that permits
    public addresses is fine as long as it did not take one, which is what lets
    a jumpbox and the hosts behind it share a segment."""
    for n in minimal["nodes"]:
        if n["id"] == "c2-sub01":
            n["overlay"]["exposure"] = "internet"
    assert "EXP002" not in errors(minimal)


def test_exp001_a_jumpbox_that_declined_an_address(minimal):
    """Reachable is now something a host says, so it can say no by mistake.

    EXP001 alone, not MGT001 as well: the managed hosts still have a manages
    edge, and saying so twice would make the second finding noise. The topology is
    already refused."""
    for n in minimal["nodes"]:
        if n["id"] == "jump-bx01":
            n["overlay"]["public_address"] = False
    found = errors(minimal)
    assert "EXP001" in found
    assert not is_valid(minimal)


def test_exp005_an_address_the_segment_forbids(minimal):
    """Ignoring it would mean a topology that reads as exposed and deploys as
    unreachable, which is the failure the ceiling was meant to prevent."""
    for n in minimal["nodes"]:
        if n["id"] == "myth-ts01":
            n["overlay"]["public_address"] = True
    assert "EXP005" in errors(minimal)


def test_a_jumpbox_may_share_a_segment_with_what_it_fronts(redstack, registry):
    """The shape 0021 exists for: one management segment holding the jumpbox
    and the operator boxes, which 0.2.0 could not express at all."""
    nodes = {n["id"]: n for n in redstack["nodes"]}
    nodes["mgmt-sub01"]["overlay"]["exposure"] = "internet"
    redstack["nodes"] = [n for n in redstack["nodes"] if n["id"] != "subnet-ops"]
    for edge in redstack["edges"]:
        if edge["target"] == "subnet-ops":
            edge["target"] = "mgmt-sub01"
    redstack["edges"] = [e for e in redstack["edges"] if e["source"] != "subnet-ops"]

    assert errors(redstack, registry=registry) == set(), \
        "the topology layer has no objection to this"


def test_exp003_no_egress_blocks_install(minimal):
    for n in minimal["nodes"]:
        if n["id"] == "c2-sub01":
            n["overlay"]["egress"] = "none"
    assert "EXP003" in errors(minimal)


# -- provider

def test_network001_cross_provider_fronts(minimal):
    minimal["nodes"].append({
        "id": "main-net02", "kind": "network", "name": "RT-NET-2",
        "overlay": {"cidr": "10.99.0.0/16", "provider": "aws"}})
    for n in minimal["nodes"]:
        if n["id"] == "main-net01":
            n["overlay"]["provider"] = "gcp"
    for e in minimal["edges"]:
        if e["id"] == "e-c2-sub01-main-net01-attached":
            e["target"] = "main-net02"
    assert "NET001" in errors(minimal)


def test_network002_cross_network_management(minimal):
    minimal["nodes"].append({
        "id": "main-net02", "kind": "network", "name": "RT-NET-2",
        "overlay": {"cidr": "10.99.0.0/16"}})
    minimal["edges"].append({"id": "far", "role": "manages",
                             "source": "jump-bx01", "target": "main-net02"})
    assert "NET002" in errors(minimal)


# -- ordering

def test_ord001_cycle(redstack):
    redstack["edges"].append({"id": "cyc", "role": "logs_to",
                              "source": "open-log01", "target": "open-log01"})
    assert "ORD001" in errors(redstack)


# -- the finding contract

def test_finding_shape(minimal):
    minimal["edges"] = [e for e in minimal["edges"] if e["role"] != "manages"]
    f = next(f for f in validate(minimal) if f.code == "MGT001")
    d = f.to_dict()
    assert set(d) == {"code", "severity", "target_ids", "template",
                      "values", "message", "remedy"}
    assert d["message"] != d["template"], "values should have been substituted"
    assert d["target_ids"]


def test_finding_rejects_empty_targets():
    from redstackpro import finding
    with pytest.raises(ValueError):
        finding("X", "error", [], "nothing")


def test_frt002_two_upstreams_on_one_prefix(redstack):
    """The first rewrite rule matches and the second never fires, so a beacon to
    the second teamserver silently gets the wrong backend."""
    for edge in redstack["edges"]:
        if edge["id"] == "e-apache-rd01-sliv-ts01-fronts":
            edge["uri_prefix"] = "/api/v1"
    assert "FRT002" in errors(redstack)


def test_a_redirector_may_front_many_teamservers(redstack):
    """redStack's own shape. It is a warning about blast radius, not an error."""
    assert is_valid(redstack)
    assert "CAR006" in codes(redstack)


def test_cap003_is_retired_and_a_mixed_segment_is_no_longer_flagged():
    """CAP003 is gone on purpose. It warned that on AWS an internet subnet routing
    to the gateway for its addressed member left the unaddressed members without a
    NAT route. The AWS backend no longer builds that shape: an addressed host goes
    in the network's own public subnet, so the segment's subnet routes at the NAT
    for everyone else. The rule had also never fired, being gated on
    exposure == "internet" while every shipped template uses "local". See 0054."""
    from redstackpro import validate as validate_module
    assert not hasattr(validate_module, "cap003_mixed_exposure_segment")


def test_the_shipped_examples_compile_everywhere(redstack, registry):
    """Nothing shipped is single provider: the blueprint has no errors on GCP or
    AWS. The one internet segment renders with Cloud NAT on GCP and as a gateway
    subnet on AWS. See 0039."""
    for provider in ("gcp", "aws"):
        assert errors(redstack, provider=provider, registry=registry) == set()


# -- peering (0029)

def _two_networks(cidr_a="10.10.0.0/16", cidr_b="10.20.0.0/16"):
    """A jumpbox in network-a managing network-b, the cross-network case. Valid enough
    that NET002 and LOG001 are the interesting findings; other rules may also
    fire, so the tests check membership rather than the full set."""
    return {
        "schema_version": "0.4.0", "mode": "ops", "name": "t", "prefix": "rt",
        "nodes": [
            {"id": "network-a", "kind": "network", "overlay": {"cidr": cidr_a}},
            {"id": "network-b", "kind": "network", "overlay": {"cidr": cidr_b}},
            {"id": "subnet-a", "kind": "segment", "overlay": {
                "cidr": "10.10.1.0/24", "egress": "allowed",
                "exposure": "internet", "tier": "management"}},
            {"id": "subnet-b", "kind": "segment", "overlay": {
                "cidr": "10.20.1.0/24", "egress": "allowed",
                "exposure": "local", "tier": "c2"}},
            {"id": "jump-bx01", "kind": "jumpbox", "overlay": {}},
        ],
        "edges": [
            {"id": "e1", "role": "attached", "source": "subnet-a", "target": "network-a"},
            {"id": "e2", "role": "attached", "source": "subnet-b", "target": "network-b"},
            {"id": "e3", "role": "attached", "source": "jump-bx01", "target": "subnet-a"},
            {"id": "e4", "role": "manages", "source": "jump-bx01", "target": "network-b"},
        ],
    }


def _peer(a="network-a", b="network-b", eid="e-peer"):
    return {"id": eid, "role": "peers", "source": a, "target": b}


def test_end005_peers_wrong_kinds():
    g = _two_networks()
    g["edges"].append(_peer(a="network-a", b="subnet-b"))   # network to segment
    assert "END005" in errors(g)


def test_network002_blocks_cross_network_management_without_peering():
    assert "NET002" in errors(_two_networks())


def test_a_peers_edge_clears_the_cross_network_management_error():
    g = _two_networks()
    g["edges"].append(_peer())
    assert "NET002" not in errors(g)


def _cross_network_fronts():
    # A redirector in network-a fronts a teamserver in network-b.
    g = _two_networks()
    g["nodes"] += [
        {"id": "nginx-rd01", "kind": "redirector", "overlay": {"server": "nginx"}},
        {"id": "myth-ts01", "kind": "teamserver", "overlay": {"c2": "mythic"}},
    ]
    g["edges"] += [
        {"id": "e-rdir-subnet", "role": "attached", "source": "nginx-rd01", "target": "subnet-a"},
        {"id": "e-myth-ts01-c2-sub01-attached", "role": "attached", "source": "myth-ts01", "target": "subnet-b"},
        {"id": "e-fronts", "role": "fronts", "source": "nginx-rd01", "target": "myth-ts01",
         "protocol": "https", "listen_port": 443, "upstream_port": 443, "uri_prefix": "/x"},
    ]
    return g


def test_net003_blocks_cross_network_fronts_without_peering():
    assert "NET003" in errors(_cross_network_fronts())


def test_a_peers_edge_clears_the_cross_network_fronts_error():
    g = _cross_network_fronts()
    g["edges"].append(_peer())
    assert "NET003" not in errors(g)


def test_peering_is_not_transitive():
    # network-a peers network-b, network-b peers network-c, but the jumpbox in network-a managing
    # network-c still fails: A to B and B to C is not A to C.
    g = _two_networks()
    g["nodes"].append({"id": "network-c", "kind": "network",
                       "overlay": {"cidr": "10.30.0.0/16"}})
    g["edges"][-1]["target"] = "network-c"               # jump manages network-c now
    g["edges"] += [_peer(a="network-a", b="network-b", eid="e-ab"),
                   _peer(a="network-b", b="network-c", eid="e-bc")]
    assert "NET002" in errors(g)


def test_peer001_self_peer():
    g = _two_networks()
    g["edges"].append(_peer(a="network-a", b="network-a"))
    assert "PEER001" in errors(g)


def test_peer002_duplicate_peer():
    g = _two_networks()
    g["edges"] += [_peer(eid="e-p1"), _peer(a="network-b", b="network-a", eid="e-p2")]
    assert "PEER002" in errors(g)


def test_peer003_overlapping_cidrs():
    g = _two_networks(cidr_b="10.10.0.0/16")         # same range as network-a
    g["edges"].append(_peer())
    assert "PEER003" in errors(g)


def test_cap004_peering_renders_on_the_clouds_not_proxmox(registry):
    g = _two_networks()
    g["edges"].append(_peer())
    assert "CAP004" not in errors(g, provider="gcp", registry=registry)
    assert "CAP004" not in errors(g, provider="aws", registry=registry)
    assert "CAP004" in errors(g, provider="proxmox", registry=registry)


def test_log001_clears_across_peered_networks():
    g = _two_networks()
    g["nodes"].append({"id": "open-log01", "kind": "collector", "overlay": {
        "sink": "opensearch", "shipper": "filebeat", "ingest_port": 5044,
        "tls": True}})
    # The collector lives in network-b, the jumpbox in network-a ships to it.
    g["edges"] += [
        {"id": "e-log-subnet", "role": "attached", "source": "open-log01", "target": "subnet-b"},
        {"id": "e-logs", "role": "logs_to", "source": "jump-bx01", "target": "open-log01"},
    ]
    assert "LOG001" in errors(g)                      # not peered
    g["edges"].append(_peer())
    assert "LOG001" not in errors(g)                  # peered


# -- range model (RNG rules only fire in range mode)

def _range():
    """A tiny valid range: one network, one subnet, one domain with a DC that
    joins it. Clean under the RNG rules, a base to break one at a time."""
    return {
        "schema_version": "0.4.0", "mode": "range", "name": "r", "prefix": "cyb",
        "nodes": [
            {"id": "net01", "kind": "network", "overlay": {"cidr": "10.0.0.0/16"}},
            {"id": "sub01", "kind": "segment",
             "overlay": {"cidr": "10.0.1.0/24", "egress": "allowed", "exposure": "local"}},
            {"id": "dom", "kind": "domain", "overlay": {"fqdn": "sk.local", "netbios": "SK"}},
            {"id": "dc01", "kind": "dc", "overlay": {"hostname": "dc01"}},
        ],
        "edges": [
            {"id": "e1", "role": "attached", "source": "sub01", "target": "net01"},
            {"id": "e2", "role": "attached", "source": "dc01", "target": "sub01"},
            {"id": "e3", "role": "joins", "source": "dc01", "target": "dom"},
        ],
    }


def test_a_base_range_is_clean_of_rng_findings():
    assert not {c for c in codes(_range()) if c.startswith("RNG")}


def test_net004_internal_ip_must_be_inside_its_segment():
    g = _range()
    dc = next(n for n in g["nodes"] if n["id"] == "dc01")
    dc["overlay"]["internal_ip"] = "10.0.1.10"
    assert "NET004" not in errors(g)                  # inside 10.0.1.0/24
    dc["overlay"]["internal_ip"] = "10.0.2.10"
    assert "NET004" in errors(g)                       # outside the segment


def test_net005_duplicate_internal_ip_in_one_segment():
    g = _range()
    g["nodes"].append({"id": "srv01", "kind": "srv",
                       "overlay": {"hostname": "srv01", "internal_ip": "10.0.1.10"}})
    g["edges"].append({"id": "e4", "role": "attached", "source": "srv01", "target": "sub01"})
    assert "NET005" not in errors(g)                   # nothing else pinned yet
    g["nodes"][3]["overlay"]["internal_ip"] = "10.0.1.10"  # dc01 collides with srv01
    assert "NET005" in errors(g)
    g["nodes"][3]["overlay"]["internal_ip"] = "10.0.1.11"
    assert "NET005" not in errors(g)                   # distinct again


def test_net006_reserved_range_is_provider_specific(registry):
    """AWS and Azure reserve the first four addresses of a subnet, GCP only the
    first two, so the same pin is an error on one target and fine on another.
    Pinning .2 is exactly the bug that failed every AWS apply while GCP had been
    deploying it happily for months."""
    g = _range()
    dc = next(n for n in g["nodes"] if n["id"] == "dc01")

    dc["overlay"]["internal_ip"] = "10.0.1.2"
    assert "NET006" in errors(g, provider="aws", registry=registry)
    assert "NET006" in errors(g, provider="azure", registry=registry)
    assert "NET006" not in errors(g, provider="gcp", registry=registry)

    # .4 clears every provider's head reservation.
    dc["overlay"]["internal_ip"] = "10.0.1.4"
    for provider in ("aws", "azure", "gcp", "proxmox", "esxi"):
        assert "NET006" not in errors(g, provider=provider, registry=registry)

    # The tail is reserved too: .255 is broadcast in a /24, and GCP also holds
    # back the second-to-last.
    dc["overlay"]["internal_ip"] = "10.0.1.255"
    assert "NET006" in errors(g, provider="aws", registry=registry)
    dc["overlay"]["internal_ip"] = "10.0.1.254"
    assert "NET006" in errors(g, provider="gcp", registry=registry)
    assert "NET006" not in errors(g, provider="aws", registry=registry)


def test_shipped_labs_avoid_every_provider_reserved_range(registry):
    """Every stock lab must compile for every provider. The GOAD family shipped a
    jumpbox pinned to 192.168.56.2, which AWS and Azure both refuse, so no lab
    may regress into a reserved band again."""
    import glob
    import os
    root = os.path.join(os.path.dirname(__file__), "..", "frontend", "public", "goad")
    for path in sorted(glob.glob(os.path.join(root, "*.json"))):
        topology = json.loads(open(path, encoding="utf-8").read())
        for provider in ("aws", "azure", "gcp"):
            assert "NET006" not in errors(topology, provider=provider,
                                          registry=registry), \
                "%s on %s" % (os.path.basename(path), provider)


def test_rng001_member_joins_no_domain():
    g = _range()
    g["nodes"].append({"id": "srv01", "kind": "srv", "overlay": {"hostname": "srv01"}})
    g["edges"].append({"id": "e4", "role": "attached", "source": "srv01", "target": "sub01"})
    assert "RNG001" in codes(g)                       # srv01 joins nothing
    g["edges"].append({"id": "e5", "role": "joins", "source": "srv01", "target": "dom"})
    assert "RNG001" not in codes(g)                   # now it joins


def test_rng001_is_range_only():
    # An ops document never runs the range rules, even with an unjoined host.
    g = _range()
    g["mode"] = "ops"
    g["nodes"].append({"id": "srv01", "kind": "srv", "overlay": {}})
    assert "RNG001" not in codes(g)


def test_rng002_domain_without_dc():
    g = _range()
    g["nodes"].append({"id": "dom2", "kind": "domain",
                       "overlay": {"fqdn": "b.local", "netbios": "B"}})
    assert "RNG002" in codes(g)                       # dom2 has no DC
    # A member server does not satisfy it; only a DC does.
    g["nodes"].append({"id": "srv01", "kind": "srv", "overlay": {}})
    g["edges"].append({"id": "e4", "role": "joins", "source": "srv01", "target": "dom2"})
    assert "RNG002" in codes(g)
    g["nodes"].append({"id": "dc02", "kind": "dc", "overlay": {}})
    g["edges"].append({"id": "e5", "role": "joins", "source": "dc02", "target": "dom2"})
    assert "RNG002" not in codes(g)


def test_rng003_self_trust_is_an_error():
    g = _range()
    g["edges"].append({"id": "t1", "role": "trusts", "source": "dom", "target": "dom",
                       "trust_type": "external", "direction": "bidirectional"})
    assert "RNG003" in errors(g)


def test_rng004_siem_without_product():
    g = _range()
    g["nodes"].append({"id": "siem01", "kind": "siem", "overlay": {"hostname": "s"}})
    g["edges"].append({"id": "e4", "role": "attached", "source": "siem01", "target": "sub01"})
    assert "RNG004" in codes(g)                       # no product
    g["nodes"][-1]["overlay"]["product"] = "wazuh"
    assert "RNG004" not in codes(g)


def test_rng008_duplicate_siem_product_warns():
    g = _range()
    # A Wazuh box and an ELK box coexist: a host reports to both, no warning.
    for i, prod in enumerate(("wazuh", "elk")):
        sid = "siem%02d" % i
        g["nodes"].append({"id": sid, "kind": "siem",
                           "overlay": {"product": prod, "hostname": prod}})
        g["edges"].append({"id": "es%d" % i, "role": "attached",
                           "source": sid, "target": "sub01"})
    assert "RNG008" not in codes(g)                    # different products fine
    # A second box of the same product is ambiguous: warn.
    g["nodes"].append({"id": "siem02", "kind": "siem",
                       "overlay": {"product": "elk", "hostname": "elk2"}})
    g["edges"].append({"id": "es2", "role": "attached",
                       "source": "siem02", "target": "sub01"})
    assert "RNG008" in codes(g)                         # two ELK boxes conflict


def test_rng005_domain_with_users_needs_an_admin():
    g = _range()
    dom = next(n for n in g["nodes"] if n["kind"] == "domain")
    dom.setdefault("overlay", {})["users"] = [
        {"username": "a.one", "privilege": "user"},
        {"username": "b.two", "privilege": "user"},
    ]
    assert "RNG005" in codes(g)                       # no admin among them
    dom["overlay"]["users"][0]["privilege"] = "domain_admin"
    assert "RNG005" not in codes(g)
    # An empty user list does not warn; the domain simply has no population yet.
    dom["overlay"]["users"] = []
    assert "RNG005" not in codes(g)


def test_rng006_duplicate_domain_fqdn_is_an_error():
    g = _range()
    g["nodes"].append({"id": "dom2", "kind": "domain",
                       "overlay": {"fqdn": "sk.local", "netbios": "SK2"}})
    assert "RNG006" in errors(g)                      # same fqdn as dom
    g["nodes"][-1]["overlay"]["fqdn"] = "other.local"
    assert "RNG006" not in codes(g)


def test_rng007_duplicate_username_is_an_error():
    g = _range()
    dom = next(n for n in g["nodes"] if n["kind"] == "domain")
    dom.setdefault("overlay", {})["users"] = [
        {"username": "a.one", "privilege": "domain_admin"},
        {"username": "A.One", "privilege": "user"},
    ]
    assert "RNG007" in errors(g)                      # case-insensitive collision
    dom["overlay"]["users"][1]["username"] = "b.two"
    assert "RNG007" not in codes(g)


def test_the_range_templates_are_clean_of_range_errors():
    import json, glob, os
    root = os.path.dirname(os.path.dirname(__file__))
    # Recursive: the GOAD range templates live in the goad/ subdirectory.
    for f in glob.glob(os.path.join(root, "frontend/public/**/*.json"), recursive=True):
        doc = json.loads(open(f).read())
        if doc.get("mode") != "range":
            continue
        errs = [c for c in errors(doc) if c.startswith("RNG")]
        assert errs == [], f"{os.path.basename(f)} has range errors: {errs}"


def test_rdr002_warns_when_a_hero_video_has_no_source(redstack):
    """The knob that looked applied and did nothing.

    Every other cover asset has a keyless fallback, so turning it on always
    produces something. A hero clip has none -- free-licence libraries carry
    documentary footage, and the libraries with real b-roll want a credit on
    the page, which is the one thing a cover page cannot show. So a pack is the
    only source, and decoy_video without decoy_asset_pack compiled, deployed
    and rendered while doing nothing at all.

    A warning rather than an error: the hero falls back to the still planned
    alongside the clip, so nothing is broken. The operator is simply not
    getting what they asked for and should hear it in the canvas.
    """
    rdir = next(n for n in redstack["nodes"] if n["kind"] == "redirector")
    gating = rdir["overlay"].setdefault("gating", {})

    assert "RDR002" not in codes(redstack)

    gating["decoy_video"] = True
    assert "RDR002" in codes(redstack)
    assert "RDR002" not in errors(redstack), "a still hero is not a broken page"

    # A pack is the thing that can actually satisfy it, so a pack clears it.
    gating["decoy_asset_pack"] = "/opt/cover-assets"
    assert "RDR002" not in codes(redstack)

    # Whitespace is not a directory. Left unchecked this is the same silent
    # no-op wearing a different hat.
    gating["decoy_asset_pack"] = "   "
    assert "RDR002" in codes(redstack)

    # And the warning belongs only to the redirector that asked for the video.
    gating["decoy_asset_pack"] = "/opt/cover-assets"
    gating["decoy_video"] = False
    assert "RDR002" not in codes(redstack)


def test_rdr001_demands_a_real_domain_whatever_the_certificate_source(redstack):
    """A domain cannot be generated the way the gating header value is: a human has
    to register one and point it at the redirector. Shipping a plausible placeholder
    hid that until deploy, where it surfaced as the redirector blocking on "create an
    A record for cdn.example-lure.com" -- unfollowable, because satisfying it needed a
    topology edit rather than a DNS edit. So refuse at compile, and refuse it for a self
    signed redirector too: the certificate is a separate question from the name, and
    every profile, URL and solution step is written in terms of the name."""
    rdir = next(n for n in redstack["nodes"] if n["kind"] == "redirector")

    # The fixture supplies the hostname the shipped example deliberately omits.
    assert rdir["overlay"]["hostname"]
    assert "RDR001" not in codes(redstack)

    for cert in ("letsencrypt", "self_signed", "provided"):
        rdir["overlay"]["tls"] = {"cert_source": cert}

        rdir["overlay"].pop("hostname", None)
        assert "RDR001" in errors(redstack), "no hostname, %s" % cert

        rdir["overlay"]["hostname"] = "cdn.redops.design"
        assert "RDR001" not in codes(redstack), "real domain, %s" % cert

        # A placeholder is refused too: a beacon that calls a domain you do not own
        # never comes back, and self signed does not make that any less true.
        for placeholder in ("cdn.example-lure.com", "cdn.example.com", "CHANGE-ME"):
            rdir["overlay"]["hostname"] = placeholder
            assert "RDR001" in errors(redstack), "%s, %s" % (placeholder, cert)
        rdir["overlay"]["hostname"] = "cdn.redops.design"


def test_every_shipped_redirector_example_demands_a_hostname_first():
    """The inverse of the usual "examples must be valid" test, and deliberate: an
    example carrying a redirector is one field short of compiling, and that field is
    the domain. Nothing else may be missing, so the operator sets one thing and
    builds. A shipped hostname would be a placeholder nobody owns, which is the
    failure this replaces."""
    import glob
    import os
    seen = 0
    for pattern in ("frontend/public/*.json", "src/redstackpro/schema/topology/examples/0.4.0/*.json"):
        root = os.path.join(os.path.dirname(__file__), "..", pattern)
        for path in sorted(glob.glob(root)):
            name = os.path.basename(path)
            topology = json.loads(open(path, encoding="utf-8").read())
            if "nodes" not in topology:
                continue
            found = errors(topology)
            if not any(n.get("kind") == "redirector" for n in topology["nodes"]):
                assert not found, name
                continue
            seen += 1
            assert found == {"RDR001"}, name
            # And supplying just the domain is enough to compile it.
            for node in topology["nodes"]:
                if node.get("kind") == "redirector":
                    node.setdefault("overlay", {})["hostname"] = "cdn.redops.design"
            assert not errors(topology), name
    assert seen, "no shipped example carries a redirector"
