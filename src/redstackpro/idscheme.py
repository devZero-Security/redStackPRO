"""The default id scheme.

A node's id is derived from what it is and what it holds: a purpose slug, the
kind tag, and a two digit ordinal (myth-ts01, main-net01, c2-sub01). See 0016.

    slug     what it is or holds     myth for a Mythic teamserver, main for the
                                     network the management tier sits in
    tag      the kind, fixed         ts, op, bx, rd, log, net, sub
    ordinal  keeps siblings apart    01, 02, ...

`renumber` rewrites every id in a document to this scheme and cascades the
change through edge endpoints. Migration runs it so an old document comes out
with modern names; the fixtures are generated with it; the canvas mirrors it in
frontend/src/topology.js so a node the person adds gets the same id live. Because
the maps below repeat the registry's kind tags, test_idscheme pins the two
together so they cannot drift.
"""

# kind -> the trailing tag that identifies it. Mirrors registry abbrev.
KIND_TAG = {
    "network": "net",
    "segment": "sub",
    "teamserver": "ts",
    "operator": "op",
    "jumpbox": "bx",
    "redirector": "rd",
    "collector": "log",
    # range mode (0047)
    "domain": "dom",
    "dc": "dc",
    "srv": "srv",
    "wks": "wks",
    "fw": "fw",
    "siem": "siem",
    "appliance": "appl",
}

# host kind -> (overlay field the subtype reads, value -> slug). A jumpbox has
# no varying subtype, so it takes a fixed slug.
SUBTYPE = {
    "teamserver": ("c2", {
        "mythic": "myth",
        "sliver": "sliv",
        "adaptix": "adpx",
        "cobalt_strike": "cs",
    }),
    "operator": ("os", {
        "windows": "win",
        "kali": "kali",
        "debian": "deb",
    }),
    "redirector": ("server", {
        "nginx": "nginx",
        "apache": "apache",
    }),
    "collector": ("sink", {
        "opensearch": "open",
        "elasticsearch": "elk",
        "splunk": "splk",
    }),
    # range mode: a member server reads its role and a SIEM its product, so a
    # dropped host names itself the way a Red Infra box does (sql-srv01,
    # wazuh-siem01), not a bare srv01.
    "srv": ("role", {
        "sql": "sql",
        "web": "web",
        "fileshare": "file",
        "adcs": "adcs",
    }),
    "siem": ("product", {
        "wazuh": "wazuh",
        "elk": "elk",
        "splunk": "splk",
    }),
}
JUMPBOX_SLUG = "jump"

# host kind -> the family that decides the purpose of the container holding it.
FAMILY = {
    "redirector": "rdir",
    "teamserver": "c2",
    "jumpbox": "mgmt",
    "operator": "mgmt",
    "collector": "mgmt",
}
# When a container holds more than one family, the most sensitive wins.
FAMILY_ORDER = ("mgmt", "c2", "rdir")

# family -> slug, per container kind. A network with any management is "main";
# the same family names a subnet "mgmt".
NETWORK_PURPOSE = {"mgmt": "main", "c2": "c2", "rdir": "rdir"}
SEGMENT_PURPOSE = {"mgmt": "mgmt", "c2": "c2", "rdir": "rdir"}


def host_slug(node):
    kind = node["kind"]
    if kind == "jumpbox":
        return JUMPBOX_SLUG
    field, table = SUBTYPE.get(kind, (None, {}))
    if field is None:
        return ""
    return table.get((node.get("overlay") or {}).get(field), "")


def _dominant(families):
    for fam in FAMILY_ORDER:
        if fam in families:
            return fam
    return None


def container_slug(kind, families):
    fam = _dominant(families)
    if fam is None:
        return ""
    table = NETWORK_PURPOSE if kind == "network" else SEGMENT_PURPOSE
    return table[fam]


def compose_id(slug, tag, ordinal):
    core = "%s%02d" % (tag, ordinal)
    return "%s-%s" % (slug, core) if slug else core


def edge_id(source, target, role):
    """The canvas builds edge ids this way, so a generated document and a hand
    drawn one agree."""
    return ("e-%s-%s-%s" % (source, target, role)).replace("_", "-")


def _families(nodes, parent):
    """Families rolled up to the segment that holds each host, then to the
    network that holds each segment."""
    seg = {}
    net = {}
    for node in nodes:
        fam = FAMILY.get(node["kind"])
        if fam is None:
            continue
        holder = parent.get(node["id"])
        if holder is not None:
            seg.setdefault(holder, set()).add(fam)
    for seg_id, fams in seg.items():
        holder = parent.get(seg_id)
        if holder is not None:
            net.setdefault(holder, set()).update(fams)
    return seg, net


def renumber(doc):
    """Rewrite every id to the default scheme and cascade endpoints. Pure."""
    nodes = doc.get("nodes", [])
    edges = doc.get("edges", [])

    parent = {e["source"]: e["target"]
              for e in edges if e.get("role") == "attached"}
    seg_fam, net_fam = _families(nodes, parent)

    def slug_for(node):
        kind = node["kind"]
        if kind == "network":
            return container_slug("network", net_fam.get(node["id"], set()))
        if kind == "segment":
            return container_slug("segment", seg_fam.get(node["id"], set()))
        return host_slug(node)

    counters = {}
    id_map = {}
    for node in nodes:
        tag = KIND_TAG[node["kind"]]
        slug = slug_for(node)
        key = (slug, tag)
        counters[key] = counters.get(key, 0) + 1
        id_map[node["id"]] = compose_id(slug, tag, counters[key])

    out = dict(doc)
    out["nodes"] = [{**n, "id": id_map[n["id"]]} for n in nodes]
    out["edges"] = []
    for edge in edges:
        new = dict(edge)
        new["source"] = id_map.get(edge["source"], edge["source"])
        new["target"] = id_map.get(edge["target"], edge["target"])
        new["id"] = edge_id(new["source"], new["target"], new["role"])
        out["edges"].append(new)
    return out
