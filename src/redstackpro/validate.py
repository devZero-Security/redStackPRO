"""Topology layer validation.

Rules are documented in docs/validation.md. JSON Schema covers document shape;
everything here is topology semantics. The compiler refuses to run on any error.

Each rule is a function taking a Context and yielding Findings. Adding a rule
means adding a function and listing it in RULES.
"""

import ipaddress

from .findings import finding
from .migrate import PUBLIC_BY_DEFAULT
from .naming import abbrev_of, compose, ordinal_of, too_long
from .registry import Registry


class Context:
    """Resolved views over a topology document. Built once, read by every rule."""

    def __init__(self, topology, registry=None):
        self.topology = topology
        self.registry = registry
        self.prefix = topology.get("prefix", "red")
        self.nodes = {n["id"]: n for n in topology.get("nodes", [])}
        self.edges = list(topology.get("edges", []))

        self.by_role = {}
        for e in self.edges:
            self.by_role.setdefault(e["role"], []).append(e)

    # -- kind helpers

    def kind(self, node_id):
        n = self.nodes.get(node_id)
        return n["kind"] if n else None

    def name(self, node_id):
        """The rendered name. Composed, never stored. See 0016."""
        return compose(self.prefix, node_id)

    def of_kind(self, *kinds):
        return [n for n in self.nodes.values() if n["kind"] in kinds]

    def is_host(self, node_id):
        # A domain is a logical container like a network or a segment, not a
        # machine: it becomes AD configuration on a controller, never a host in
        # the inventory. Excluding it here keeps it out of every host view at
        # once, so the Ansible groups, host_vars, and play order never try to
        # provision it. See goad-native-recreation.
        return self.kind(node_id) not in ("network", "segment", "domain", None)

    def hosts(self):
        return [n for n in self.nodes.values() if self.is_host(n["id"])]

    def overlay(self, node_id, field, default=None):
        n = self.nodes.get(node_id) or {}
        return n.get("overlay", {}).get(field, default)

    # -- topology helpers

    def segments_of(self, host_id):
        return [e["target"] for e in self.by_role.get("attached", [])
                if e["source"] == host_id and self.kind(e["target"]) == "segment"]

    def network_of_segment(self, segment_id):
        for e in self.by_role.get("attached", []):
            if e["source"] == segment_id and self.kind(e["target"]) == "network":
                return e["target"]
        return None

    def networks_of(self, host_id):
        out = []
        for seg in self.segments_of(host_id):
            net = self.network_of_segment(seg)
            if net:
                out.append(net)
        return out

    def exposure(self, host_id):
        """Most permissive exposure across the host's segments.

        This is the ceiling, not a fact about the host. A segment with exposure
        internet permits a public address; whether this host takes one is
        `public_address`. See 0021.
        """
        order = {"none": 0, "local": 1, "internet": 2}
        best = None
        for seg in self.segments_of(host_id):
            val = self.overlay(seg, "exposure")
            if best is None or order.get(val, 0) > order.get(best, 0):
                best = val
        return best

    def public_address(self, host_id):
        """Whether this host actually holds a public address.

        The one place that answers it, so the validator and both compiler
        backends cannot disagree about which hosts are reachable.
        """
        node = self.nodes.get(host_id) or {}
        asked = (node.get("overlay") or {}).get("public_address")
        if asked is None:
            asked = node.get("kind") in PUBLIC_BY_DEFAULT
        # The segment is the ceiling. A host asking for an address where the
        # segment does not permit one does not get it, and EXP005 says so
        # rather than letting it pass quietly.
        return bool(asked) and self.exposure(host_id) == "internet"

    def managed_scopes(self):
        """Node ids named as the target of a manages edge, mapped to jumpbox."""
        out = {}
        for e in self.by_role.get("manages", []):
            out.setdefault(e["target"], []).append(e["source"])
        return out

    def manager_of(self, host_id):
        """The jumpbox managing this host, or None. Returns one id: CAR005
        already errors when a scope has more than one manager."""
        scopes = self.managed_scopes()
        for seg in self.segments_of(host_id):
            if seg in scopes:
                return scopes[seg][0]
            net = self.network_of_segment(seg)
            if net and net in scopes:
                return scopes[net][0]
        return None

    # -- peering

    def peers_of(self, network_id):
        """Networks directly peered with this one, both directions since a peers
        edge is bidirectional. Peering is not transitive on any cloud here: A to B
        and B to C does not give A to C, so this is direct adjacency, not a closure.
        See 0029."""
        out = set()
        for e in self.by_role.get("peers", []):
            if e["source"] == network_id and self.kind(e["target"]) == "network":
                out.add(e["target"])
            if e["target"] == network_id and self.kind(e["source"]) == "network":
                out.add(e["source"])
        return out

    def networks_reachable_from(self, network_ids):
        """The given networks plus the ones directly peered with any of them. This
        is the set a host in those networks can reach on a private address."""
        reachable = set(network_ids)
        for net in list(network_ids):
            reachable |= self.peers_of(net)
        return reachable


def self_name(ctx, node):
    return ctx.name(node["id"])


# ---------------------------------------------------------------- naming

def nam001_id_matches_kind(ctx):
    reg = ctx.registry
    if reg is None:
        return
    # Range naming (the cyb prefix and slug scheme) is deferred to custom range
    # authoring; the shipped GOAD templates keep their canonical names. See 0047.
    if ctx.topology.get("mode") == "haven":
        return
    for node in ctx.nodes.values():
        spec = reg.kinds.get(node["kind"])
        if not spec:
            continue
        expected = spec.get("abbrev")
        if expected and abbrev_of(node["id"]) != expected:
            yield finding(
                "NAM001", "error", [node["id"]],
                "{id} is a {kind}, so its id must carry the kind tag "
                "{expected}, as <slug>-{expected}<ordinal>.",
                remedy="Rename it to <slug>-%s01 or the next free ordinal."
                       % expected,
                id=node["id"], kind=node["kind"], expected=expected)


def nam002_two_digit_ordinal(ctx):
    reg = ctx.registry
    if reg is None:
        return
    if ctx.topology.get("mode") == "haven":
        return
    for node in ctx.nodes.values():
        spec = reg.kinds.get(node["kind"])
        if not spec:
            continue
        ordinal = ordinal_of(node["id"])
        if len(ordinal) != 2:
            yield finding(
                "NAM002", "error", [node["id"]],
                "{id} must end in a two digit ordinal. The slug carries the "
                "meaning; the ordinal keeps sibling ids distinct.",
                remedy="Rename it to %s01 or the next free ordinal."
                       % (abbrev_of(node["id"]) or node["id"]),
                id=node["id"])


def nam003_netbios_length(ctx):
    if ctx.topology.get("mode") == "haven":
        return
    for node in ctx.nodes.values():
        # A network or a segment never becomes a host, so it has no NetBIOS name
        # to truncate. The rule is about machines in the inventory.
        if node.get("kind") in ("network", "segment"):
            continue
        if too_long(ctx.prefix, node["id"]):
            yield finding(
                "NAM003", "error", [node["id"]],
                "{name} is {length} characters. Windows truncates NetBIOS names "
                "at 15, so this host would answer to a different name than the "
                "one in the inventory.",
                remedy="Shorten the topology prefix or the node id.",
                name=ctx.name(node["id"]),
                length=len(ctx.name(node["id"])))


# ---------------------------------------------------------------- referential

def ref001_dangling_endpoints(ctx):
    for e in ctx.edges:
        for end in ("source", "target"):
            if e[end] not in ctx.nodes:
                yield finding(
                    "REF001", "error", [e["id"]],
                    "Edge {edge} points at {missing}, which is not a node in this topology.",
                    remedy="Delete the edge or add the missing node.",
                    edge=e["id"], missing=e[end])


def ref002_duplicate_ids(ctx):
    seen = {}
    for n in ctx.topology.get("nodes", []):
        seen.setdefault(n["id"], 0)
        seen[n["id"]] += 1
    for e in ctx.edges:
        seen.setdefault(e["id"], 0)
        seen[e["id"]] += 1
    for ident, count in seen.items():
        if count > 1:
            yield finding(
                "REF002", "error", [ident],
                "The id {ident} is used {count} times. Ids are unique across nodes and edges.",
                remedy="Rename all but one.",
                ident=ident, count=count)


# ---------------------------------------------------------------- endpoints

_ENDPOINTS = {
    "attached": [("host", "segment"), ("segment", "network")],
    "fronts": [("redirector", "teamserver")],
    "logs_to": [("host", "collector")],
    "manages": [("jumpbox", "network"), ("jumpbox", "segment")],
    "peers": [("network", "network")],
}

_CODES = {"attached": "END001", "fronts": "END002",
          "logs_to": "END003", "manages": "END004", "peers": "END005"}


def _matches(ctx, node_id, slot):
    if slot == "host":
        return ctx.is_host(node_id)
    return ctx.kind(node_id) == slot


def end_endpoint_kinds(ctx):
    for e in ctx.edges:
        role = e["role"]
        allowed = _ENDPOINTS.get(role)
        if not allowed:
            continue
        if e["source"] not in ctx.nodes or e["target"] not in ctx.nodes:
            continue
        if any(_matches(ctx, e["source"], s) and _matches(ctx, e["target"], t)
               for s, t in allowed):
            continue
        yield finding(
            _CODES[role], "error", [e["id"], e["source"], e["target"]],
            "A {role} edge runs {expected}. This one runs {src_kind} to {dst_kind}.",
            remedy="Redraw it between the right kinds, or change the role.",
            role=role,
            expected=" or ".join("%s to %s" % p for p in allowed),
            src_kind=ctx.kind(e["source"]), dst_kind=ctx.kind(e["target"]))


# ---------------------------------------------------------------- cardinality

def car001_host_unattached(ctx):
    if ctx.topology.get("mode") == "haven":
        return
    for n in ctx.hosts():
        if not ctx.segments_of(n["id"]):
            yield finding(
                "CAR001", "error", [n["id"]],
                "{name} is not attached to a segment.",
                remedy="Draw an attached edge from it to a segment.",
                name=self_name(ctx, n))


def car002_segment_network(ctx):
    for n in ctx.of_kind("segment"):
        nets = [e["target"] for e in ctx.by_role.get("attached", [])
                if e["source"] == n["id"] and ctx.kind(e["target"]) == "network"]
        if len(nets) != 1:
            yield finding(
                "CAR002", "error", [n["id"]],
                "{name} attaches to {count} networks. A segment lives in exactly one.",
                remedy="Attach it to one network.",
                name=self_name(ctx, n), count=len(nets))


def car003_primary_attachment(ctx):
    for n in ctx.hosts():
        atts = [e for e in ctx.by_role.get("attached", [])
                if e["source"] == n["id"]]
        if len(atts) < 2:
            continue
        primaries = [e for e in atts if e.get("primary", True)]
        if len(primaries) != 1:
            yield finding(
                "CAR003", "error", [n["id"]],
                "{name} is multihomed with {count} primary attachments. Exactly one is primary.",
                remedy="Set primary false on all but one attachment.",
                name=self_name(ctx, n), count=len(primaries))


def car004_one_log_sink(ctx):
    counts = {}
    for e in ctx.by_role.get("logs_to", []):
        counts.setdefault(e["source"], []).append(e["target"])
    for src, targets in counts.items():
        if len(targets) > 1:
            yield finding(
                "CAR004", "error", [src] + targets,
                "{name} ships logs to {count} collectors. A host has at most one.",
                remedy="Remove the extra logs_to edges.",
                name=ctx.name(src), count=len(targets))


def car005_one_manager(ctx):
    for scope, managers in ctx.managed_scopes().items():
        if len(managers) > 1:
            yield finding(
                "CAR005", "error", [scope] + managers,
                "{name} is managed by {count} jumpboxes. ProxyJump cannot pick one.",
                remedy="Keep one manages edge for this scope.",
                name=ctx.name(scope), count=len(managers))


def car006_shared_redirector(ctx):
    """One redirector fronting several teamservers is normal, and is redStack's
    own shape. It is worth noting only because it concentrates blast radius: a
    takedown of that host cuts every chain behind it."""
    counts = {}
    for e in ctx.by_role.get("fronts", []):
        counts.setdefault(e["source"], []).append(e["target"])
    for src, targets in sorted(counts.items()):
        if len(set(targets)) > 2:
            yield finding(
                "CAR006", "warning", [src] + sorted(set(targets)),
                "{name} fronts {count} teamservers, so losing it cuts all of "
                "them at once.",
                remedy="Acceptable. Split across redirectors if the chains are "
                       "meant to fail independently.",
                name=ctx.name(src), count=len(set(targets)))


def frt002_prefix_collision(ctx):
    """Two upstreams behind one redirector cannot share a prefix: the first
    rewrite rule matches and the second never fires."""
    seen = {}
    for e in ctx.by_role.get("fronts", []):
        prefix = e.get("uri_prefix")
        if not prefix:
            continue
        key = (e["source"], prefix)
        if key in seen and seen[key] != e["target"]:
            yield finding(
                "FRT002", "error", [e["source"], seen[key], e["target"]],
                "{name} routes {prefix} to two teamservers. The first rule "
                "matches and the second never fires.",
                remedy="Give each upstream its own prefix.",
                name=ctx.name(e["source"]), prefix=prefix)
        seen[key] = e["target"]


def frt001_pool_disagrees(ctx):
    """A rollover pool serves one C2 profile, so every redirector in it has to
    demand the same header and route the same prefix. Otherwise a beacon works
    through one redirector and gets the decoy page through another."""
    pools = {}
    for edge in ctx.by_role.get("fronts", []):
        pools.setdefault(edge["target"], []).append(edge)

    for teamserver, edges in sorted(pools.items()):
        if len(edges) < 2:
            continue
        for field, get in (
            ("uri_prefix", lambda e: e.get("uri_prefix")),
            ("gating header", lambda e: (
                ctx.overlay(e["source"], "gating", {}) or {}).get("header_name")),
            ("gating value", lambda e: (
                ctx.overlay(e["source"], "gating", {}) or {}).get("header_value")),
        ):
            values = {get(e) for e in edges}
            if len(values) > 1:
                yield finding(
                    "FRT001", "error",
                    [teamserver] + [e["id"] for e in edges],
                    "The redirectors fronting {name} disagree on {field}: {values}. "
                    "A beacon would work through one and get the decoy through "
                    "another.",
                    remedy="Make every fronts edge into this teamserver match.",
                    name=ctx.name(teamserver), field=field,
                    values=", ".join(repr(v) for v in sorted(values, key=str)))


def car007_teamserver_unfronted(ctx):
    fronted = {e["target"] for e in ctx.by_role.get("fronts", [])}
    for n in ctx.of_kind("teamserver"):
        if n["id"] not in fronted:
            yield finding(
                "CAR007", "warning", [n["id"]],
                "{name} has no redirector in front of it, so it has no inbound path.",
                remedy="Draw a fronts edge from a redirector, or remove it.",
                name=self_name(ctx, n))


def car008_ui_c2_needs_gui_operator(ctx):
    """A web-UI C2 (Mythic, Adaptix) needs an operator that can open its interface.
    A Kali operator is reached over SSH only unless it carries desktop:true (xrdp
    over a Guacamole RDP tile), so a topology whose teamserver runs Mythic or
    Adaptix but has no Windows operator and no desktop Kali operator has no way to
    drive the C2 as shipped. A warning, not an error: the range still deploys, the
    operator just cannot open the UI. See minimal-uses-sliver."""
    ui_c2 = {"mythic", "adaptix"}
    driven = [n for n in ctx.of_kind("teamserver")
              if ((n.get("overlay") or {}).get("c2")) in ui_c2]
    if not driven:
        return
    if any(((n.get("overlay") or {}).get("os")) == "windows"
           or bool((n.get("overlay") or {}).get("desktop"))
           for n in ctx.of_kind("operator")):
        return
    for n in driven:
        yield finding(
            "CAR008", "warning", [n["id"]],
            "{name} runs {c2}, a web-UI C2, but the topology has no operator that "
            "can open it (a plain Kali operator is SSH only).",
            remedy="Add a Windows operator, set desktop:true on a Kali operator, "
                   "or use a headless C2 such as Sliver.",
            name=self_name(ctx, n),
            c2=((n.get("overlay") or {}).get("c2")))


# ---------------------------------------------------------------- management

def mgt001_unreachable_host(ctx):
    if ctx.topology.get("mode") == "haven":
        return
    for n in ctx.hosts():
        if n["kind"] == "jumpbox":
            continue
        if ctx.manager_of(n["id"]):
            continue
        # Directly reachable means it holds an address, not that its segment
        # would permit one. A host with no address in an internet segment is
        # exactly as unreachable as one in a local segment. See 0021.
        if ctx.public_address(n["id"]):
            continue
        yield finding(
            "MGT001", "error", [n["id"]],
            "{name} has no management path. Nothing manages its segment or network, "
            "and it is not directly reachable.",
            remedy="Draw a manages edge from a jumpbox to its network.",
            name=self_name(ctx, n))


def net002_cross_network_management(ctx):
    """A jumpbox can manage a scope in another network only if a peers edge joins
    the two. Without one there is no transport between the routing domains, so the
    ProxyJump path does not exist. See 0029."""
    for e in ctx.by_role.get("manages", []):
        jump, scope = e["source"], e["target"]
        if jump not in ctx.nodes or scope not in ctx.nodes:
            continue
        jump_nets = set(ctx.networks_of(jump))
        scope_net = (scope if ctx.kind(scope) == "network"
                     else ctx.network_of_segment(scope))
        if scope_net and scope_net not in ctx.networks_reachable_from(jump_nets):
            yield finding(
                "NET002", "error", [e["id"], jump, scope],
                "{jump} manages {scope}, but they are in different routing domains "
                "and no peers edge joins them.",
                remedy="Peer the two networks, or put a jumpbox in that network.",
                jump=ctx.name(jump), scope=ctx.name(scope))


def net003_cross_network_fronts(ctx):
    """A redirector can front a teamserver in another network only if a peers edge
    joins the two, the same rule manages and logs_to follow. The redirector opens
    the upstream connection, so without a peering there is no route and the
    cross-network firewall rule names a CIDR that nothing can reach. See 0030."""
    for e in ctx.by_role.get("fronts", []):
        rdir, ts = e["source"], e["target"]
        if rdir not in ctx.nodes or ts not in ctx.nodes:
            continue
        rdir_nets = set(ctx.networks_of(rdir))
        ts_nets = set(ctx.networks_of(ts))
        if ctx.networks_reachable_from(rdir_nets) & ts_nets:
            continue
        yield finding(
            "NET003", "error", [e["id"], rdir, ts],
            "{rdir} fronts {ts}, but they are in different routing domains "
            "and no peers edge joins them.",
            remedy="Peer the two networks, or put the redirector in the "
                   "teamserver's network.",
            rdir=ctx.name(rdir), ts=ctx.name(ts))


def net004_internal_ip_outside_segment(ctx):
    """A host's pinned internal_ip must fall inside the cidr of the segment it
    sits in, or the address terraform is told to assign is not even reachable
    from its own subnet at apply time. See goad-fidelity-build (P1.6, locking
    range internal IPs to GOAD's canonical octets)."""
    for n in ctx.hosts():
        ip = ctx.overlay(n["id"], "internal_ip")
        if not ip:
            continue
        segs = ctx.segments_of(n["id"])
        if not segs:
            continue
        cidr = ctx.overlay(segs[0], "cidr")
        if not cidr:
            continue
        try:
            in_segment = (ipaddress.ip_address(ip)
                          in ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            # A malformed address is a schema-shape problem (the pattern in
            # $defs.ipv4 already rejects it there); not this rule's job.
            continue
        if not in_segment:
            yield finding(
                "NET004", "error", [n["id"]],
                "{name} pins internal_ip {ip}, which is outside its segment's "
                "{cidr}.",
                remedy="Set internal_ip to an address inside the segment's cidr.",
                name=ctx.name(n["id"]), ip=ip, cidr=cidr)


def net005_duplicate_internal_ip(ctx):
    """Two hosts in the same segment pinned to the same internal_ip collide at
    apply time: whichever host's resource claims the address second either
    fails or silently steals it from the first."""
    by_segment = {}
    for n in ctx.hosts():
        ip = ctx.overlay(n["id"], "internal_ip")
        if not ip:
            continue
        for seg in ctx.segments_of(n["id"]):
            by_segment.setdefault(seg, {}).setdefault(ip, []).append(n["id"])
    for seg, by_ip in by_segment.items():
        for ip, host_ids in by_ip.items():
            if len(host_ids) > 1:
                yield finding(
                    "NET005", "error", host_ids,
                    "{ip} is pinned on more than one host in {seg}: {names}.",
                    remedy="Give each host a distinct internal_ip.",
                    ip=ip, seg=ctx.name(seg),
                    names=", ".join(ctx.name(h) for h in host_ids))


def net006_internal_ip_in_reserved_range(ctx, provider):
    """A pinned internal_ip must sit outside the addresses the target provider
    reserves at each end of a subnet, or terraform is refused at apply.

    This is provider-specific, so the same topology can be legal on one target and
    rejected by another: AWS and Azure reserve the first four addresses of every
    subnet, GCP only the first two. That asymmetry is exactly how the stock GOAD
    labs shipped a jumpbox pinned to .2 that deployed on GCP for months and then
    failed every AWS apply with "Address 192.168.56.2 is in subnet's reserved
    address range". Catching it at compile turns a failure two minutes into an
    apply, after a NAT gateway and five instances already exist, into an error
    the canvas shows before anything is built. See 0055.
    """
    if not ctx.registry:
        return
    head, tail = ctx.registry.reserved_addresses(provider)
    for n in ctx.hosts():
        ip = ctx.overlay(n["id"], "internal_ip")
        if not ip:
            continue
        segs = ctx.segments_of(n["id"])
        if not segs:
            continue
        cidr = ctx.overlay(segs[0], "cidr")
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Malformed values are the schema's problem, and an address outside
            # the segment entirely is NET004's.
            continue
        if addr not in net:
            continue
        offset = int(addr) - int(net.network_address)
        last = net.num_addresses - 1
        if offset >= head and offset <= last - tail:
            continue
        first_free = net.network_address + head
        yield finding(
            "NET006", "error", [n["id"]],
            "{name} pins internal_ip {ip}, which {provider} reserves in "
            "{cidr}. It holds back the first {head} addresses and the last "
            "{tail}.",
            remedy="Pin an address from %s upwards, or clear internal_ip and "
                   "let the provider assign one." % first_free,
            name=ctx.name(n["id"]), ip=ip, provider=provider, cidr=cidr,
            head=head, tail=tail)


def rdr001_redirector_hostname_unset(ctx):
    """A redirector must answer on a name the operator actually controls.

    Nothing can generate this the way the gating header value is generated: a domain
    has to be registered and pointed at the redirector's address by a human. Shipping
    a plausible-looking placeholder made that invisible until deploy time, where it
    surfaced as the redirector blocking on "create an A record for
    cdn.example-lure.com" -- a record nobody can create, because nobody owns that
    domain. Worse, the instruction was unfollowable: satisfying it needed a topology
    edit, not a DNS edit.

    So refuse at compile instead. Failing in the canvas costs seconds and says
    exactly what to do; failing at deploy costs the whole build and misdirects.

    A hostname is required whatever the certificate source. Self signed narrows the
    question to a certificate the beacon will not trust, but it does not remove the
    need for a name: the implant profile, the gated URL an operator hands out, and
    every solution step are all written in terms of the domain. Asking for one
    field before the first compile is cheap, and it is the only way to be sure the
    operator chose the name rather than inheriting one from a template.
    """
    for node in ctx.of_kind("redirector"):
        hostname = (ctx.overlay(node["id"], "hostname") or "").strip()
        looks_placeholder = any(
            marker in hostname.lower()
            for marker in ("example", "change-me", "changeme", "your-domain"))
        if hostname and not looks_placeholder:
            continue
        if hostname:
            yield finding(
                "RDR001", "error", [node["id"]],
                "{name} still carries the placeholder domain {hostname}. A beacon "
                "would call a domain you do not own.",
                remedy="Set the domain to an FQDN you control and point it at this "
                       "redirector's address before deploying.",
                name=ctx.name(node["id"]), hostname=hostname)
        else:
            yield finding(
                "RDR001", "error", [node["id"]],
                "{name} has no domain set. A redirector is the one host in the range "
                "that answers to the internet by name, so the domain is yours to "
                "choose before anything is built.",
                remedy="Set the domain to an FQDN you control and point it at this "
                       "redirector's address. Keep tls.cert_source letsencrypt to "
                       "have a real certificate issued for it, or set self_signed "
                       "if you would rather not.",
                name=ctx.name(node["id"]))


def rdr002_decoy_video_without_a_pack(ctx):
    """A hero video was asked for and there is no source that can supply one.

    Every other asset on the cover page has a keyless fallback, so turning a
    knob on always produces something. The video slot does not, and the reason
    is the corpus rather than the plumbing: free-licence libraries carry
    documentary footage, not short quiet brand-free b-roll, and the libraries
    that carry b-roll want a visible credit on the page -- which is precisely
    what a cover page cannot show. So the operator's own pack is the only
    source, and `decoy_video` without `decoy_asset_pack` cannot do anything at
    all.

    Which made it the worst kind of setting: one that looks applied. It
    compiled, it deployed, the page rendered, and the only trace was a line on
    the redirector's stderr that nobody reads unless something already looks
    wrong. Exactly the class this codebase keeps finding -- a check or a knob
    whose name promises more than it does.

    A warning and not an error, because the page is genuinely fine without it:
    the hero falls back to the photograph planned alongside the clip. Nothing
    is broken. The operator simply is not getting the thing they asked for, and
    is entitled to be told so while the topology is still in front of them.
    """
    for node in ctx.of_kind("redirector"):
        gating = ctx.overlay(node["id"], "gating", {}) or {}
        if not gating.get("decoy_video"):
            continue
        if (gating.get("decoy_asset_pack") or "").strip():
            continue
        yield finding(
            "RDR002", "warning", [node["id"]],
            "{name} asks for a cover page hero video, but a clip can only come "
            "from an asset pack and none is set. The hero will fall back to a "
            "still.",
            remedy="Put a video.mp4 or video.webm on the redirector and set "
                   "decoy_asset_pack to the directory holding it, or turn "
                   "decoy_video off.",
            name=ctx.name(node["id"]))


def boot001_wireguard_bootstrap(ctx):
    for n in ctx.of_kind("jumpbox"):
        if ctx.overlay(n["id"], "transport", "ssh") != "wireguard":
            continue
        yield finding(
            "BOOT001", "warning", [n["id"]],
            "{name} manages over WireGuard, so the export needs a two stage play order. "
            "Ansible cannot configure WireGuard over WireGuard.",
            remedy="Bootstrap runs on private addresses; the tunnel is the path afterward.",
            name=self_name(ctx, n))


# ---------------------------------------------------------------- vpn access

# The multi-user VPN access layer: how operators reach an artie range and who
# they are. Fields live on the jumpbox overlay (access_mode, vpn_port,
# vpn_protocol, operators). See vpn-multiuser-spec.

def _jumpbox_access(node):
    ov = node.get("overlay") or {}
    return (ov.get("access_mode", "public"),
            ov.get("vpn_protocol", "udp"),
            ov.get("operators") or [])


def vpn001_wireguard_tcp(ctx):
    """WireGuard runs over udp only, so access_mode wireguard with vpn_protocol
    tcp names a listener that cannot exist. An error: the export would render an
    unreachable tunnel. OpenVPN is the mode that takes tcp."""
    for n in ctx.of_kind("jumpbox"):
        mode, proto, _ = _jumpbox_access(n)
        if mode == "wireguard" and proto == "tcp":
            yield finding(
                "VPN001", "error", [n["id"]],
                "{name} sets access_mode wireguard with vpn_protocol tcp, but "
                "WireGuard is udp only.",
                remedy="Set vpn_protocol udp, or use access_mode openvpn for tcp.",
                name=self_name(ctx, n))


def vpn002_vpn_access_is_artie_only(ctx):
    """A VPN access mode and the operator roster are artie concepts: the attack
    canvas fronts a team over a tunnel, while a haven range keeps the public
    portal. A warning, since the fields do no harm on haven, they are ignored."""
    if ctx.topology.get("mode") != "haven":
        return
    for n in ctx.of_kind("jumpbox"):
        mode, _, operators = _jumpbox_access(n)
        if mode in ("wireguard", "openvpn") or operators:
            yield finding(
                "VPN002", "warning", [n["id"]],
                "{name} declares VPN access or an operator roster, which are artie "
                "features. A haven range keeps the public portal, so these are "
                "ignored here.",
                remedy="Move the multi-user VPN access to an artie topology, or "
                       "clear these fields.",
                name=self_name(ctx, n))


def vpn003_vpn_without_operators(ctx):
    """A VPN access mode with no operators declared. The tunnel stands up, but
    only the shared break-glass admin holds a credential, so no per-user access
    is provisioned. A warning: a valid single-admin range, just probably not what
    a team meant to build. Haven is already covered by VPN002."""
    if ctx.topology.get("mode") == "haven":
        return
    for n in ctx.of_kind("jumpbox"):
        mode, _, operators = _jumpbox_access(n)
        if mode in ("wireguard", "openvpn") and not operators:
            yield finding(
                "VPN003", "warning", [n["id"]],
                "{name} enables {mode} access but declares no operators, so only "
                "the shared break-glass admin will have a credential.",
                remedy="Add operators to provision a per-user account and VPN "
                       "credential for each, or leave as is for single-admin access.",
                name=self_name(ctx, n), mode=mode)


def vpn004_duplicate_operator_handle(ctx):
    """Two operators sharing a handle. The handle keys the portal account and the
    VPN credential, so a duplicate collides at apply and the second account cannot
    be created. An error, the same shape as RNG007 for domain usernames."""
    for n in ctx.of_kind("jumpbox"):
        _, _, operators = _jumpbox_access(n)
        seen = {}
        for op in operators:
            handle = (op.get("handle") or "").lower()
            if handle:
                seen[handle] = seen.get(handle, 0) + 1
        dupes = sorted(h for h, c in seen.items() if c > 1)
        if dupes:
            yield finding(
                "VPN004", "error", [n["id"]],
                "{name} has duplicate operator handles: {dupes}.",
                remedy="A handle is one per operator; rename or remove the copies.",
                name=self_name(ctx, n), dupes=", ".join(dupes))


# ---------------------------------------------------------------- peering

def peer001_self_peer(ctx):
    for e in ctx.by_role.get("peers", []):
        if e["source"] == e["target"]:
            yield finding(
                "PEER001", "error", [e["id"], e["source"]],
                "{name} is peered with itself, which is not a connection.",
                remedy="Peer it with a different network, or delete the edge.",
                name=ctx.name(e["source"]))


def peer002_duplicate_peer(ctx):
    seen = {}
    for e in ctx.by_role.get("peers", []):
        if e["source"] == e["target"]:
            continue
        seen.setdefault(frozenset((e["source"], e["target"])), []).append(e["id"])
    for pair, ids in seen.items():
        if len(ids) > 1:
            a, b = sorted(pair)
            yield finding(
                "PEER002", "error", sorted(ids) + [a, b],
                "{a} and {b} are peered more than once. One connection joins two "
                "networks.",
                remedy="Keep one peers edge between them.",
                a=ctx.name(a), b=ctx.name(b))


def peer003_cidr_overlap(ctx):
    """Peering with overlapping CIDRs fails at apply, because a host cannot tell
    which side an address in the shared range belongs to. See 0029."""
    for e in ctx.by_role.get("peers", []):
        a, b = e["source"], e["target"]
        if a == b or a not in ctx.nodes or b not in ctx.nodes:
            continue
        ca, cb = ctx.overlay(a, "cidr"), ctx.overlay(b, "cidr")
        if not ca or not cb:
            continue
        try:
            na = ipaddress.ip_network(ca, strict=False)
            nb = ipaddress.ip_network(cb, strict=False)
        except ValueError:
            continue
        if na.overlaps(nb):
            yield finding(
                "PEER003", "error", [e["id"], a, b],
                "{a} ({ca}) and {b} ({cb}) are peered but their CIDRs overlap. "
                "Peering with overlapping ranges fails at apply.",
                remedy="Give the two networks non-overlapping CIDRs.",
                a=ctx.name(a), b=ctx.name(b), ca=ca, cb=cb)


# ---------------------------------------------------------------- exposure

_MUST_EXPOSE = ("jumpbox", "redirector")
_MUST_NOT_EXPOSE = ("teamserver", "collector", "operator")


def exp001_underexposed(ctx):
    """A kind that exists to be reached, that nothing outside can reach.

    Two ways to get here now: the segment does not permit an address, or it does
    and the host declined one. The message says which, because the remedy is
    different. See 0021.
    """
    # A range is an isolated lab: its jumpbox sits on a local subnet and is
    # reached through the provider, not a public address. The exposure rules are
    # an ops concept, so they do not apply to range mode.
    if ctx.topology.get("mode") == "haven":
        return
    for n in ctx.hosts():
        if n["kind"] not in _MUST_EXPOSE:
            continue
        if ctx.public_address(n["id"]):
            continue
        if ctx.exposure(n["id"]) != "internet":
            yield finding(
                "EXP001", "error", [n["id"]],
                "{name} is a {kind} but sits in a segment with exposure "
                "{exposure}, so it cannot hold a public address.",
                remedy="Set the segment exposure to internet.",
                name=self_name(ctx, n), kind=n["kind"],
                exposure=ctx.exposure(n["id"]))
        else:
            yield finding(
                "EXP001", "error", [n["id"]],
                "{name} is a {kind} with public_address false, so nothing "
                "outside can reach it.",
                remedy="Set public_address true on this host.",
                name=self_name(ctx, n), kind=n["kind"],
                exposure=ctx.exposure(n["id"]))


def exp002_overexposed(ctx):
    """A kind that must not be reachable, holding an address.

    In 0.2.0 this was a property of the segment, so the remedy was to split one.
    It is the host's own field now, so the remedy is to change it and the
    segment can stay shared. That is the whole point of 0021.
    """
    for n in ctx.hosts():
        if n["kind"] not in _MUST_NOT_EXPOSE:
            continue
        if ctx.public_address(n["id"]):
            yield finding(
                "EXP002", "error", [n["id"]],
                "{name} is a {kind} holding a public address. Public addresses "
                "belong only on redirectors and jumpboxes.",
                remedy="Set public_address false on this host.",
                name=self_name(ctx, n), kind=n["kind"])


def exp005_address_the_segment_forbids(ctx):
    """Asking for an address where the segment permits none.

    Silently ignoring it would mean a topology that reads as exposed and deploys as
    unreachable, which is the failure the ceiling was meant to prevent rather
    than introduce.
    """
    # Range mode is an isolated lab; exposure is an ops concept. See exp001.
    if ctx.topology.get("mode") == "haven":
        return
    for n in ctx.hosts():
        asked = (n.get("overlay") or {}).get("public_address")
        if asked is None:
            asked = n["kind"] in PUBLIC_BY_DEFAULT
        if not asked:
            continue
        if ctx.exposure(n["id"]) == "internet":
            continue
        yield finding(
            "EXP005", "error", [n["id"]],
            "{name} asks for a public address but its segment has exposure "
            "{exposure}, which permits none. The segment is the ceiling.",
            remedy="Set the segment exposure to internet, or public_address "
                   "false on this host.",
            name=self_name(ctx, n), exposure=ctx.exposure(n["id"]))


def exp003_no_egress_install(ctx):
    for n in ctx.hosts():
        for seg in ctx.segments_of(n["id"]):
            if ctx.overlay(seg, "egress") == "none":
                yield finding(
                    "EXP003", "error", [n["id"], seg],
                    "{name} sits in {seg}, which has no egress, but it needs package "
                    "installation. Nothing in 0.1.0 installs offline.",
                    remedy="Set egress allowed, or stage artifacts, which is not built.",
                    name=self_name(ctx, n), seg=ctx.name(seg))


# ---------------------------------------------------------------- collector

def log001_unreachable_collector(ctx):
    for e in ctx.by_role.get("logs_to", []):
        src, dst = e["source"], e["target"]
        if src not in ctx.nodes or dst not in ctx.nodes:
            continue
        src_nets = set(ctx.networks_of(src))
        dst_nets = set(ctx.networks_of(dst))
        # Same network, or the sender's network is peered with the collector's.
        # Push over TCP needs the sender to open the connection, and a peers edge
        # is what carries it across the boundary. See 0029.
        if ctx.networks_reachable_from(src_nets) & dst_nets:
            continue
        yield finding(
            "LOG001", "error", [e["id"], src, dst],
            "{src} ships logs to {dst}, but they are in different routing domains.",
            remedy="Put the collector in a network the senders can reach, or peer "
                   "the two networks.",
            src=ctx.name(src), dst=ctx.name(dst))


def log002_plaintext(ctx):
    for n in ctx.of_kind("collector"):
        if ctx.overlay(n["id"], "tls", True) is False:
            yield finding(
                "LOG002", "warning", [n["id"]],
                "{name} accepts log shipping without TLS.",
                remedy="Set tls true unless there is a reason.",
                name=self_name(ctx, n))


# LOG003 (a collector sharing a segment with the jumpbox belongs in its own
# tier) is deliberately gone. redStack runs the collector in the one internal
# segment alongside the jumpbox and the operator boxes, and that is the shipped
# shape, so warning about it every time was noise. See 0039.


# ---------------------------------------------------------------- provider

def cap_provider_capabilities(ctx, provider):
    reg = ctx.registry
    caps = reg.capabilities(provider)
    for n in ctx.nodes.values():
        for req in reg.requirements_for(n):
            if req in caps:
                continue
            container = reg.kinds[n["kind"]]["category"] == "container"
            reason = reg.unsupported_reason(provider, req) or ""
            yield finding(
                "CAP002" if container else "CAP001", "error", [n["id"]],
                "{name} needs {req}, which {provider} does not provide. {reason}",
                remedy="Choose another provider, or change the field that raises it.",
                name=ctx.name(n["id"]), req=req, provider=provider, reason=reason)


# CAP003 (a mixed-exposure segment) is deliberately GONE. It warned that on AWS
# an internet subnet routing to the gateway for its addressed member left the
# unaddressed members with no NAT route. The AWS backend no longer builds that
# shape: an addressed host is placed in the network's own public subnet, so the
# segment's subnet is free to route at the NAT for everyone else. The rule's
# premise was dissolved by that change, and it had never fired anyway -- it was
# gated on exposure == "internet" while every shipped template uses "local".
# Its docstring also described the opposite of the real failure. See 0054.


def cap004_network_peering(ctx, provider):
    """A peers edge against a provider that does not render network peering. gcp
    and aws both do; proxmox cannot peer at all. The reason travels from the
    provider registry. See 0029, 0030, and 0031."""
    peers = ctx.by_role.get("peers", [])
    if not peers or "network_peering" in ctx.registry.capabilities(provider):
        return
    reason = ctx.registry.unsupported_reason(provider, "network_peering") or ""
    for e in peers:
        yield finding(
            "CAP004", "error", [e["id"], e["source"], e["target"]],
            "{a} and {b} are peered, which {provider} does not render. {reason}",
            remedy="Target a provider that renders network peering, such as gcp.",
            a=ctx.name(e["source"]), b=ctx.name(e["target"]),
            provider=provider, reason=reason)


def net001_cross_provider_edge(ctx):
    for e in ctx.edges:
        if e["role"] not in ("fronts", "logs_to"):
            continue
        if e["source"] not in ctx.nodes or e["target"] not in ctx.nodes:
            continue
        def provider_of(host):
            return {ctx.overlay(net, "provider")
                    for net in ctx.networks_of(host)} - {None}
        a, b = provider_of(e["source"]), provider_of(e["target"])
        if a and b and a != b:
            yield finding(
                "NET001", "error", [e["id"], e["source"], e["target"]],
                "{src} and {dst} resolve to different providers. Cross-provider "
                "transport is not implemented.",
                remedy="Pin both networks to one provider.",
                src=ctx.name(e["source"]), dst=ctx.name(e["target"]))


# ---------------------------------------------------------------- range model

# Range findings name nodes by their bare id: range templates keep canonical
# names (kingslanding, not cyb-kingslanding), and the canvas labels them the
# same way, so a finding should read as the canvas does. See 0047.

# The domain-member host kinds. A firewall is not domain joined, so it is not
# expected to carry a joins edge.
_RANGE_MEMBERS = ("dc", "srv", "wks")


def rng001_member_joins_no_domain(ctx):
    """A domain member with no joins edge. In an AD range a DC or member server
    that joins nothing is incomplete: it is drawn but part of no domain."""
    if ctx.topology.get("mode") != "haven":
        return
    joined = {e["source"] for e in ctx.by_role.get("joins", [])}
    for n in ctx.of_kind(*_RANGE_MEMBERS):
        if n["id"] not in joined:
            yield finding(
                "RNG001", "warning", [n["id"]],
                "{name} joins no domain.",
                remedy="Join it to a domain from the inspector, or draw a joins edge to one.",
                name=n["id"])


def rng002_domain_without_dc(ctx):
    """A domain that no domain controller joins. A domain needs a DC to exist;
    one with only member servers is not yet a working domain."""
    if ctx.topology.get("mode") != "haven":
        return
    dc_domains = {e["target"] for e in ctx.by_role.get("joins", [])
                  if ctx.kind(e["source"]) == "dc"}
    for n in ctx.of_kind("domain"):
        if n["id"] not in dc_domains:
            yield finding(
                "RNG002", "warning", [n["id"]],
                "{name} has no domain controller.",
                remedy="Add a dc that joins it.",
                name=n["id"])


def rng003_self_trust(ctx):
    """A trust from a domain to itself. A trust runs between two different
    domains; a self-trust is meaningless and would not provision."""
    if ctx.topology.get("mode") != "haven":
        return
    for e in ctx.by_role.get("trusts", []):
        if e["source"] == e["target"]:
            yield finding(
                "RNG003", "error", [e["id"], e["source"]],
                "{name} trusts itself.",
                remedy="A trust runs between two different domains.",
                name=e["source"])


# Techniques that are properties of a domain ACCOUNT, not tasks a host applies.
# They are realized by flagging a user (users[].flaws), so declaring them in a
# host's overlay.vulns plants nothing: the host role has no task for them and the
# dc role only reads the user flaws. goad-wazuh shipped kerberoasting and
# weak_password on hosts this way, and the lab's headline detections silently
# never deployed. Keep this set in step with the catalog's user:* goad mappings.
USER_FLAW_VULNS = {
    "kerberoasting", "asreproasting", "weak_password", "password_in_description",
}


def rng009_user_flaw_as_host_vuln(ctx):
    """A host declares a technique that only exists as a user flaw. It is a
    no-op there and plants nothing; the technique must be set on a domain user's
    flaws instead. Caught as a warning because the run still succeeds, just
    without the attack the author intended. See PAI F-dual-modeling."""
    if ctx.topology.get("mode") != "haven":
        return
    for n in ctx.hosts():
        declared = set(ctx.overlay(n["id"], "vulns") or [])
        stray = sorted(declared & USER_FLAW_VULNS)
        for vuln in stray:
            yield finding(
                "RNG009", "warning", [n["id"]],
                "{name} declares {vuln}, but that is an account property, not a "
                "host task, so it plants nothing here.",
                remedy="Set it on a domain user's flaws (with spns/weak_password "
                       "as needed) instead of the host's vulns.",
                name=ctx.name(n["id"]), vuln=vuln)


def rng005_domain_without_admin(ctx):
    """A domain that has user accounts but none with a domain-admin privilege.
    A lab domain needs at least one privileged account as the escalation target;
    a population with no admin has no top of the ladder to reach."""
    if ctx.topology.get("mode") != "haven":
        return
    for n in ctx.of_kind("domain"):
        users = ctx.overlay(n["id"], "users") or []
        if not users:
            continue
        if not any(u.get("privilege") in ("domain_admin", "enterprise_admin")
                   for u in users):
            yield finding(
                "RNG005", "warning", [n["id"]],
                "{name} has users but no domain or enterprise admin.",
                remedy="Set one account's privilege to domain_admin.",
                name=n["id"])


def rng006_duplicate_domain_fqdn(ctx):
    """Two domains that share an fqdn. They cannot both stand up; this is a
    compile blocker, not a warning, because the run would fail on the second."""
    if ctx.topology.get("mode") != "haven":
        return
    seen = {}
    for n in ctx.of_kind("domain"):
        fqdn = (ctx.overlay(n["id"], "fqdn") or "").lower()
        if not fqdn:
            continue
        seen.setdefault(fqdn, []).append(n["id"])
    for fqdn, ids in seen.items():
        if len(ids) > 1:
            yield finding(
                "RNG006", "error", ids,
                "{count} domains share the fqdn {fqdn}.",
                remedy="Give each domain a distinct fqdn.",
                count=len(ids), fqdn=fqdn)


def rng007_duplicate_username(ctx):
    """Two users in one domain with the same username. A sAMAccountName is unique
    within a domain, so the second account cannot be created."""
    if ctx.topology.get("mode") != "haven":
        return
    for n in ctx.of_kind("domain"):
        seen = {}
        for u in ctx.overlay(n["id"], "users") or []:
            name = (u.get("username") or "").lower()
            if name:
                seen[name] = seen.get(name, 0) + 1
        dupes = sorted(name for name, c in seen.items() if c > 1)
        if dupes:
            yield finding(
                "RNG007", "error", [n["id"]],
                "{name} has duplicate usernames: {dupes}.",
                remedy="A username is unique within a domain; rename or remove the copies.",
                name=n["id"], dupes=", ".join(dupes))


def rng004_siem_without_product(ctx):
    """A SIEM box with no telemetry product set. The product decides what the
    box collects, so an unset one is an incomplete appliance."""
    if ctx.topology.get("mode") != "haven":
        return
    for n in ctx.of_kind("siem"):
        if not ctx.overlay(n["id"], "product"):
            yield finding(
                "RNG004", "warning", [n["id"]],
                "{name} has no telemetry product set.",
                remedy="Set its product to wazuh, elk, or splunk.",
                name=n["id"])


def rng008_multiple_siem(ctx):
    """Two SIEM boxes with the same product. A Windows host reports to every SIEM
    box the range has, one agent per product, so different products (a Wazuh box
    and an ELK box) coexist fine. Two boxes of the same product are ambiguous:
    the agents can only target one, so the second box would receive nothing."""
    if ctx.topology.get("mode") != "haven":
        return
    by_product = {}
    for s in ctx.of_kind("siem"):
        by_product.setdefault(
            s.get("overlay", {}).get("product", ""), []).append(s["id"])
    for product, ids in sorted(by_product.items()):
        if len(ids) > 1:
            yield finding(
                "RNG008", "warning", ids,
                "The range has {count} SIEM boxes with the same product "
                "({product}). A host's agent can target only one of them, so the "
                "others receive nothing.",
                remedy="Use one box per SIEM product, or different products.",
                count=len(ids), product=product or "unset")


# ---------------------------------------------------------------- ordering

def ord001_dependency_cycle(ctx):
    deps = {}
    for e in ctx.by_role.get("fronts", []):
        deps.setdefault(e["source"], set()).add(e["target"])
    for e in ctx.by_role.get("logs_to", []):
        deps.setdefault(e["source"], set()).add(e["target"])

    state = {}

    def walk(node, stack):
        if state.get(node) == "done":
            return None
        if state.get(node) == "open":
            return stack[stack.index(node):]
        state[node] = "open"
        stack.append(node)
        for nxt in deps.get(node, ()):
            cycle = walk(nxt, stack)
            if cycle:
                return cycle
        stack.pop()
        state[node] = "done"
        return None

    for node in list(deps):
        cycle = walk(node, [])
        if cycle:
            yield finding(
                "ORD001", "error", cycle,
                "Address dependency cycle: {chain}. Ordering cannot be derived.",
                remedy="Break the cycle. The topology is wrong, not the ordering logic.",
                chain=" -> ".join(ctx.name(c) for c in cycle))
            return


RULES = [
    nam001_id_matches_kind,
    nam002_two_digit_ordinal,
    nam003_netbios_length,
    ref001_dangling_endpoints,
    ref002_duplicate_ids,
    end_endpoint_kinds,
    car001_host_unattached,
    car002_segment_network,
    car003_primary_attachment,
    car004_one_log_sink,
    car005_one_manager,
    car006_shared_redirector,
    frt002_prefix_collision,
    car007_teamserver_unfronted,
    car008_ui_c2_needs_gui_operator,
    frt001_pool_disagrees,
    rdr001_redirector_hostname_unset,
    rdr002_decoy_video_without_a_pack,
    mgt001_unreachable_host,
    net002_cross_network_management,
    net003_cross_network_fronts,
    net004_internal_ip_outside_segment,
    net005_duplicate_internal_ip,
    boot001_wireguard_bootstrap,
    vpn001_wireguard_tcp,
    vpn002_vpn_access_is_artie_only,
    vpn003_vpn_without_operators,
    vpn004_duplicate_operator_handle,
    peer001_self_peer,
    peer002_duplicate_peer,
    peer003_cidr_overlap,
    exp001_underexposed,
    exp002_overexposed,
    exp003_no_egress_install,
    exp005_address_the_segment_forbids,
    log001_unreachable_collector,
    log002_plaintext,
    net001_cross_provider_edge,
    rng001_member_joins_no_domain,
    rng002_domain_without_dc,
    rng003_self_trust,
    rng004_siem_without_product,
    rng005_domain_without_admin,
    rng006_duplicate_domain_fqdn,
    rng007_duplicate_username,
    rng008_multiple_siem,
    rng009_user_flaw_as_host_vuln,
    ord001_dependency_cycle,
]


def validate(topology, provider=None, registry=None):
    """Returns a list of Findings, errors first, then by code.

    provider runs the capability rules, which need the registry.
    """
    reg = registry
    if provider and reg is None:
        reg = Registry()
    ctx = Context(topology, reg)

    findings = []
    for rule in RULES:
        findings.extend(rule(ctx))
    if provider:
        findings.extend(cap_provider_capabilities(ctx, provider))
        findings.extend(cap004_network_peering(ctx, provider))
        findings.extend(net006_internal_ip_in_reserved_range(ctx, provider))

    order = {"error": 0, "warning": 1}
    findings.sort(key=lambda f: (order[f.severity], f.code, f.target_ids))
    return findings


def is_valid(topology, provider=None, registry=None):
    return not any(f.severity == "error"
                   for f in validate(topology, provider, registry))
