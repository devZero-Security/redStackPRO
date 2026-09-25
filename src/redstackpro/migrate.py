"""Document migrations.

Every topology carries `schema_version` and the model changes, so migrations exist
from the first release. A migration is a function from one version to the next,
applied in sequence. See architecture.md.

    migrate(doc)              -> latest
    migrate(doc, to="0.2.0")  -> that version

Migrations never guess. If a document cannot be moved forward without inventing
information, they raise.
"""

LATEST = "0.4.0"

# What a host gets when it says nothing. A jumpbox and a redirector are what
# something outside is meant to reach; nothing else is. See 0021.
PUBLIC_BY_DEFAULT = ("jumpbox", "redirector")


class MigrationError(Exception):
    pass


def _0_1_0_to_0_2_0(doc, prefix=None):
    """Names collapse into ids, and the instance prefix moves to the topology.

    0.1.0 carried both `id` and `name` on every node, with the compiler reading
    one in some places and the other in others. 0.2.0 has one identifier and
    composes the rendered name from a topology level prefix. See 0016.

    Old ids carried the prefix inline (rt-ts-01). The migration lifts the shared
    leading token out to `prefix` and strips it from every id and every edge
    endpoint.
    """
    nodes = doc.get("nodes", [])
    if not nodes:
        raise MigrationError("cannot infer a prefix from a topology with no nodes")

    if prefix is None:
        raise MigrationError(
            "this migration needs an explicit prefix. 0.1.0 ids were "
            "inconsistent, with hosts carrying the prefix inline and containers "
            "not, so inferring it would be guessing. Pass prefix=.")

    def strip(node_id):
        """0.1.0 was inconsistent: hosts carried the prefix inline and
        containers did not. Strip only where present. That inconsistency is
        part of why 0016 exists."""
        head, _, rest = node_id.partition("-")
        return rest if head == prefix and rest else node_id

    out = dict(doc)
    out["schema_version"] = "0.2.0"
    out["prefix"] = prefix

    out["nodes"] = []
    for node in nodes:
        new = {k: v for k, v in node.items() if k != "name"}
        new["id"] = strip(node["id"])
        out["nodes"].append(new)

    out["edges"] = []
    for edge in doc.get("edges", []):
        new = dict(edge)
        for end in ("source", "target"):
            new[end] = strip(edge[end])
        out["edges"].append(new)

    return out


def _0_2_0_to_0_3_0(doc, prefix=None):
    """Exposure becomes a ceiling and each host says whether it takes an address.

    In 0.2.0 a host was exposed because its segment was, so a jumpbox and the
    operator boxes behind it could not share a segment: one field had to be both
    internet and local. 0.3.0 makes the segment a ceiling and moves the fact to
    the host. See 0021.

    Read as 0.3.0 without this, a 0.2.0 document silently loses every public
    address, because absent means the per kind default and the default for most
    kinds is false. So the migration writes the value that was implied: every
    host in a segment with exposure internet was exposed, and that is what it
    carried.

    Nothing merges segments here. A 0.2.0 topology split them because the model
    forced it, and undoing that is an edit to a topology rather than a
    migration, so the choice stays with whoever owns the topology.
    """
    segments = {n["id"]: n for n in doc.get("nodes", [])
                if n.get("kind") == "segment"}

    # Attachment is what puts a host in a segment. See 0007.
    parent = {e["source"]: e["target"] for e in doc.get("edges", [])
              if e.get("role") == "attached"}

    out = dict(doc)
    out["schema_version"] = "0.3.0"
    out["nodes"] = []

    for node in doc.get("nodes", []):
        new = dict(node)
        if node.get("kind") not in ("network", "segment"):
            segment = segments.get(parent.get(node["id"]))
            exposed = (segment or {}).get("overlay", {}).get("exposure") == "internet"
            overlay = dict(node.get("overlay") or {})
            # Only where it differs from the default this kind would take
            # anyway, so a migrated document is not noisier than a hand written
            # one.
            if exposed != (node.get("kind") in PUBLIC_BY_DEFAULT):
                overlay["public_address"] = exposed
            new["overlay"] = overlay
        out["nodes"].append(new)

    return out


def _0_3_0_to_0_4_0(doc, prefix=None):
    """The peers role arrives, and nothing existing has to move.

    peers is a network to network edge and a new role value; it adds vocabulary
    rather than changing what a 0.3.0 document already carries. No 0.3.0 topology has
    a peers edge, so there is nothing to transform. The version bump is the whole
    migration. See 0029.
    """
    out = dict(doc)
    out["schema_version"] = "0.4.0"
    return out


MIGRATIONS = {
    "0.1.0": ("0.2.0", _0_1_0_to_0_2_0),
    "0.2.0": ("0.3.0", _0_2_0_to_0_3_0),
    "0.3.0": ("0.4.0", _0_3_0_to_0_4_0),
}


def migrate(doc, to=LATEST, prefix=None):
    version = doc.get("schema_version")
    if version is None:
        raise MigrationError("document carries no schema_version")

    seen = [version]
    steps = 0
    while version != to:
        step = MIGRATIONS.get(version)
        if step is None:
            raise MigrationError(
                "no migration from %s; path so far %s" % (version, " to ".join(seen)))
        _next, fn = step
        doc = fn(doc, prefix)
        version = _next
        steps += 1
        seen.append(version)

    # Old ids used a different grammar (ts-01, subnet-c2); the current scheme
    # puts a purpose slug first and the kind tag last. Bring a document that was
    # actually moved forward onto the current scheme so it validates and reads
    # like a freshly authored one. A document already at the target is left
    # alone, so hand chosen names on a current document are never rewritten.
    if to == LATEST and steps:
        from .idscheme import renumber
        doc = renumber(doc)
    return doc
