"""SCH001: the topology document checked against its JSON schema.

The rules in validate.py assume a document of the right shape. Without this a
bad value (a prefix with an underscore, a cidr with no mask, a hostname with a
scheme) compiled cleanly and failed later in Terraform or Ansible.

One finding per real problem. A node and an edge are each checked against the
one definition their kind or role selects, so a bad field reports once instead
of once per branch of the schema's oneOf. Where another rule already reports a
problem with better words (VPN005, VPN006, RNG012, RDR001), it is left to that
rule.
"""

import ipaddress
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

from .findings import finding

SCHEMA_DIR = Path(__file__).resolve().parent / "schema" / "topology"

# The target a document-level finding points at, since it has no node.
TOPOLOGY_TARGET = "topology"

# A pattern's plain meaning and an example, keyed by the pattern itself so the
# table holds for every schema version that reuses it.
_OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
PATTERNS = {
    "^[a-z0-9][a-z0-9-]*$": (
        "must be lowercase letters, digits and hyphens, starting with a letter "
        "or digit", "myth-ts01"),
    "^[a-z][a-z0-9]{0,7}$": (
        "must be 1 to 8 lowercase letters or digits, starting with a letter",
        "off"),
    "^(%s\\.){3}%s/(3[0-2]|[12]?[0-9])$" % (_OCTET, _OCTET): (
        "must be an IPv4 address range in CIDR form", "10.30.10.0/24"),
    "^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$": (
        "must be an IPv4 address range in CIDR form", "10.30.10.0/24"),
    "^(%s\\.){3}%s$" % (_OCTET, _OCTET): (
        "must be an IPv4 address", "10.30.10.5"),
    "^([0-9]{1,3}\\.){3}[0-9]{1,3}$": (
        "must be an IPv4 address", "10.30.10.5"),
    "^[A-Za-z0-9][A-Za-z0-9-]{0,14}$": (
        "must be 1 to 15 letters, digits or hyphens, starting with a letter or "
        "digit", "kingslanding"),
    "^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+"
    "[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]$": (
        "must be a domain name with no scheme, path or port", "cdn.example.net"),
    "^/[a-z0-9][a-z0-9/_-]*$": (
        "must start with a slash, then lowercase letters, digits, slash, "
        "underscore or hyphen", "/cdn/assets"),
    "^[A-Za-z][A-Za-z0-9-]*$": (
        "must be letters, digits and hyphens, starting with a letter",
        "X-Request-Id"),
    "^([01][0-9]|2[0-3]):[0-5][0-9]$": (
        "must be a 24 hour time, HH:MM", "20:00"),
}

# Examples for a required field the schema gives no enum or pattern for.
EXAMPLES = {
    "fqdn": "corp.local", "username": "jaime.lannister", "principal": "IT",
    "target": "jaime.lannister", "right": "GenericAll", "handle": "mike",
    "name": "gmsaDragon", "services": "ssh, guacamole", "listen_port": "443",
    "x": "0", "y": "0",
}

_TYPES = {
    "string": "text", "integer": "a whole number", "number": "a number",
    "boolean": "true or false", "array": "a list", "object": "a JSON object",
    "null": "empty",
}

# Problems a rule in validate.py already reports, as (field, validator) with
# "*" for any index or any validator.
_OWNED = {
    ("operators.*.handle", "pattern"): "VPN005",
    ("operators.*.handle", "maxLength"): "VPN005",
    ("operators.*.role", "pattern"): "VPN006",
    ("operators.*.role", "maxLength"): "VPN006",
    ("vulns_vars", "type"): "RNG012",
}

# Lower sorts first: the one finding kept for a path is the most basic problem.
_PRIORITY = {"required": 0, "additionalProperties": 1, "unevaluatedProperties": 1,
             "type": 2, "const": 3, "enum": 3}


# The versions this release ships. A document's schema_version is looked up
# here, never joined into a path, since it comes straight from the request.
_VERSIONS = {p.stem: p for p in SCHEMA_DIR.glob("*.json")}


def known_versions():
    return sorted(_VERSIONS)


@lru_cache(maxsize=None)
def _load(version):
    return json.loads(_VERSIONS[version].read_text(encoding="utf-8"))


def schema_for(version):
    """The schema for a version, or None when this release has no such version.
    Each document is checked against its own version: the API migrates to the
    latest before it validates, and a CLI run on an older file is held to the
    rules of the version it says it is."""
    if not isinstance(version, str) or version not in _VERSIONS:
        return None
    return _load(version)


# Bounded: kind and role come from the request too.
@lru_cache(maxsize=256)
def _validator(version, scope, name):
    """A validator for the document root (nodes and edges unchecked), or for one
    node kind or edge role: the base definition plus the one branch it selects."""
    schema = schema_for(version)
    defs = schema.get("$defs", {})
    if scope == "root":
        root = dict(schema)
        root["properties"] = dict(schema.get("properties", {}))
        for key in ("nodes", "edges"):
            if key in root["properties"]:
                root["properties"][key] = {"type": "array"}
        return Draft202012Validator(root)
    branch = "%s_%s" % (scope, name)
    parts = [{"$ref": "#/$defs/%s_base" % scope}]
    sub = {"$defs": defs, "allOf": parts}
    if branch in defs:
        parts.append({"$ref": "#/$defs/%s" % branch})
        sub["unevaluatedProperties"] = False
    return Draft202012Validator(sub)


def _known_keys(version, scope, name):
    defs = schema_for(version).get("$defs", {})
    keys = set(defs.get("%s_base" % scope, {}).get("properties", {}))
    keys |= set(defs.get("%s_%s" % (scope, name), {}).get("properties", {}))
    return keys


def _dotted(parts):
    return ".".join(str(p) for p in parts)


def _owned(path, validator):
    generic = ".".join("*" if isinstance(p, int) else str(p) for p in path)
    return (generic, validator) in _OWNED


def _resolve(spec, defs):
    if isinstance(spec, dict) and "$ref" in spec:
        target = defs.get(spec["$ref"].rsplit("/", 1)[-1], {})
        merged = dict(target)
        merged.update({k: v for k, v in spec.items() if k != "$ref"})
        return merged
    return spec if isinstance(spec, dict) else {}


def _example_for(key, spec, defs):
    spec = _resolve(spec, defs)
    if spec.get("enum"):
        return str(spec["enum"][0])
    if spec.get("pattern") in PATTERNS:
        return PATTERNS[spec["pattern"]][1]
    return EXAMPLES.get(key, "")


def _plain(error, defs, what, known=()):
    """[(path, validator, reason, example)] for one error. A required or an
    extra-field error can name several fields, so it can give several rows.
    what names the thing checked ("a collector"); known is its field set, for an
    unevaluatedProperties error, whose own schema lists none."""
    path = list(error.absolute_path)
    kind = error.validator
    schema = error.schema if isinstance(error.schema, dict) else {}

    if kind == "required":
        props = schema.get("properties", {})
        missing = [r for r in error.validator_value
                   if isinstance(error.instance, dict) and r not in error.instance]
        return [(path + [m], kind, "is required",
                 _example_for(m, props.get(m, {}), defs)) for m in missing]
    if kind in ("additionalProperties", "unevaluatedProperties"):
        allowed = set(schema.get("properties", {})) or set(known)
        extra = [k for k in (error.instance or {}) if k not in allowed]
        return [(path + [k], kind, "is not a field %s has" % what, "")
                for k in extra]
    if kind == "enum":
        values = ", ".join(str(v) for v in error.validator_value)
        return [(path, kind, "must be one of %s" % values, "")]
    if kind == "const":
        return [(path, kind, "must be %s" % error.validator_value, "")]
    if kind == "type":
        wanted = error.validator_value
        wanted = wanted if isinstance(wanted, list) else [wanted]
        return [(path, kind, "must be %s" % " or ".join(
            _TYPES.get(t, t) for t in wanted), "")]
    if kind == "pattern":
        reason, example = PATTERNS.get(
            error.validator_value, ("does not have the expected format", ""))
        return [(path, kind, reason, example)]
    if kind in ("minimum", "maximum"):
        if schema.get("minimum") == 1 and schema.get("maximum") == 65535:
            return [(path, kind, "must be a port from 1 to 65535", "443")]
        word = "at least" if kind == "minimum" else "at most"
        return [(path, kind, "must be %s %s" % (word, error.validator_value), "")]
    if kind == "minLength":
        if error.validator_value == 1:
            return [(path, kind, "must not be empty", "")]
        return [(path, kind, "must be at least %d characters"
                 % error.validator_value, "")]
    if kind == "maxLength":
        return [(path, kind, "must be at most %d characters"
                 % error.validator_value, "")]
    if kind == "minItems":
        n = error.validator_value
        return [(path, kind, "must list at least %s" % (
            "one entry" if n == 1 else "%d entries" % n), "")]
    if kind == "uniqueItems":
        return [(path, kind, "lists the same value twice", "")]
    return [(path, kind, error.message, "")]


_REMEDIES = {
    "required": "Set it.",
    "additionalProperties": "Remove it. Nothing reads it.",
    "unevaluatedProperties": "Remove it. Nothing reads it.",
    "enum": "Pick one of the listed values.",
    "const": "Set it to the value shown.",
    "type": "Change it to the kind of value shown.",
    "pattern": "Change it to match the example.",
    "minimum": "Use a value in the range shown.",
    "maximum": "Use a value in the range shown.",
    "minLength": "Fill it in.",
    "maxLength": "Shorten it.",
    "minItems": "Add an entry.",
    "uniqueItems": "Remove the repeat.",
}


# Where a document-level field is edited, for the remedy.
_WHERE = {
    "auto_stop": "It is under Auto-stop in Topology settings, shown when nothing "
                 "is selected.",
    "prefix": "It is in the top bar.",
    "name": "It is in the top bar.",
}


def _findings(code, errors, defs, target, label, strip, known=(),
              lead=()):
    """Turn raw errors into one finding per path. The field path is given
    relative to strip (overlay), and lead is put in front of it when the target
    is the topology rather than the node itself."""
    rows = []
    for error in errors:
        for path, kind, reason, example in _plain(error, defs, label["what"],
                                                  known):
            rel = path[len(strip):] if path[:len(strip)] == strip else path
            if _owned(rel, kind):
                continue
            if (kind == "pattern" and error.instance == ""
                    and rel == ["hostname"] and label.get("kind") == "redirector"):
                continue  # RDR001 reports an empty domain
            rows.append((_PRIORITY.get(kind, 4), path, rel, kind, reason, example))
    rows.sort(key=lambda r: (_dotted(r[1]), r[0]))
    seen = set()
    for _, path, rel, kind, reason, example in rows:
        key = _dotted(path)
        if key in seen:
            continue
        seen.add(key)
        field = _dotted(list(lead) + rel) or key
        template = ("{path} on {node}: {reason}. Example: {example}."
                    if example else "{path} on {node}: {reason}.")
        values = {"path": field, "node": label["name"], "reason": reason}
        if example:
            values["example"] = example
        remedy = _REMEDIES.get(kind, "Fix the value.")
        if target == TOPOLOGY_TARGET and not lead and rel[:1]:
            remedy = " ".join(filter(None, [remedy, _WHERE.get(str(rel[0]))]))
        yield finding(code, "error", [target], template, remedy=remedy,
                      field=field, **values)


def _network_address(value):
    """The network a cidr with host bits set means, e.g. 10.30.10.0/24 for
    10.30.10.5/24, or None when the value is fine or not a cidr at all. The
    clouds take a network address only."""
    try:
        ipaddress.ip_network(value, strict=True)
        return None
    except ValueError:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return None


def _article(word):
    return ("an %s" if word[:1] in "aeiou" else "a %s") % word


def check(topology, name_of, code="SCH001"):
    """Schema findings for a document, under code. name_of(node_id) gives the
    display name a finding uses for a node."""
    if not isinstance(topology, dict):
        yield finding(code, "error", [TOPOLOGY_TARGET],
                      "The document is not a JSON object.",
                      remedy="Load a topology file.")
        return
    version = topology.get("schema_version")
    schema = schema_for(version)
    if schema is None:
        reason = ("is required" if version is None else
                  "must be one of %s" % ", ".join(known_versions()))
        yield finding(code, "error", [TOPOLOGY_TARGET],
                      "{path} on {node}: {reason}.",
                      remedy="Set the schema version this file was written for.",
                      field="schema_version", path="schema_version",
                      node="the topology", reason=reason)
        return
    defs = schema.get("$defs", {})
    top = {"name": "the topology", "what": "the topology", "kind": None}
    yield from _findings(
        code, _validator(version, "root", "").iter_errors(topology), defs,
        TOPOLOGY_TARGET, top, [])

    nodes = topology.get("nodes")
    for i, node in enumerate(nodes if isinstance(nodes, list) else []):
        kind = node.get("kind") if isinstance(node, dict) else None
        kind_key = kind if isinstance(kind, str) else ""
        has_id = isinstance(node, dict) and isinstance(node.get("id"), str)
        label = {"name": name_of(node["id"]) if has_id else "node %d" % (i + 1),
                 "what": _article(kind_key) if kind_key else "a node",
                 "kind": kind}
        # A node with no id has nothing to point at, so the finding points at
        # the topology and its field path says which node.
        target = node["id"] if has_id else TOPOLOGY_TARGET
        lead = () if has_id else ("nodes", i)
        yield from _findings(
            code, _validator(version, "node", kind_key).iter_errors(node), defs,
            target, label, ["overlay"], _known_keys(version, "node", kind_key),
            lead)
        overlay = node.get("overlay") if isinstance(node, dict) else None
        if has_id and kind in ("network", "segment") and isinstance(overlay, dict):
            cidr = overlay.get("cidr")
            fixed = _network_address(cidr) if isinstance(cidr, str) else None
            if fixed:
                yield finding(
                    code, "error", [node["id"]],
                    "{path} on {node}: {reason}. Example: {example}.",
                    remedy="Use the network address of the range.",
                    field="cidr", path="cidr", node=label["name"],
                    reason="%s has bits set past its mask, so it is not a "
                           "network address" % cidr,
                    example=fixed)

    edges = topology.get("edges")
    for i, edge in enumerate(edges if isinstance(edges, list) else []):
        role = edge.get("role") if isinstance(edge, dict) else None
        role_key = role if isinstance(role, str) else ""
        has_id = isinstance(edge, dict) and isinstance(edge.get("id"), str)
        ends = [name_of(edge[k]) if isinstance(edge, dict)
                and isinstance(edge.get(k), str) else "?"
                for k in ("source", "target")]
        what = "a %s edge" % role_key if role_key else "an edge"
        label = {"name": "the %s edge %s to %s" % (role_key or "unnamed", *ends),
                 "what": what, "kind": None}
        target = edge["id"] if has_id else TOPOLOGY_TARGET
        lead = () if has_id else ("edges", i)
        yield from _findings(
            code, _validator(version, "edge", role_key).iter_errors(edge), defs,
            target, label, [], _known_keys(version, "edge", role_key), lead)
