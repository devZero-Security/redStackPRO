#!/usr/bin/env python3
"""Registry inspection: palette, capability matrix, consistency check.

    python -m redstackpro.tools.registry                      capability matrix
    python -m redstackpro.tools.registry --provider proxmox   one provider, verbose
    python -m redstackpro.tools.registry --palette            what the canvas offers
    python -m redstackpro.tools.registry --palette defense

The registry itself lives in the package at redstackpro/schema/registry/ as data.
See 0013.
"""

import argparse
import json
import sys
from pathlib import Path

from redstackpro import Registry

# Resolved from the package (schema ships as package data), not the CWD.
_SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schema" / "topology"
SCHEMA = _SCHEMA_ROOT / "0.6.0.json"
EXAMPLES = _SCHEMA_ROOT / "examples" / "0.6.0"


def sanity(reg):
    """The registry and the document schema have to agree. Two files that would
    otherwise drift, so this exits rather than warns."""
    schema = json.loads(SCHEMA.read_text())
    defs = schema["$defs"]

    schema_kinds = set(defs["node_base"]["properties"]["kind"]["enum"])
    if schema_kinds != set(reg.kinds):
        sys.exit("kind mismatch: schema %s, registry %s"
                 % (sorted(schema_kinds), sorted(reg.kinds)))

    schema_roles = set(defs["edge_base"]["properties"]["role"]["enum"])
    if schema_roles != set(reg.roles):
        sys.exit("role mismatch: schema %s, registry %s"
                 % (sorted(schema_roles), sorted(reg.roles)))

    declared = {c for p in reg.providers for c in reg.capabilities(p)}
    needed = {r["name"] for k in reg.kinds.values()
              for r in k.get("requirements", [])}
    orphan = needed - declared
    if orphan:
        sys.exit("requirements no provider declares: %s" % sorted(orphan))

    for kind, spec in reg.kinds.items():
        if not spec.get("abbrev"):
            sys.exit("%s declares no abbrev" % kind)
        display = spec.get("display") or {}
        missing = [f for f in ("label", "icon", "group", "color")
                   if not display.get(f)]
        if missing:
            sys.exit("%s is missing display fields: %s" % (kind, missing))

    print("registry: %d kinds, %d roles, %d providers, consistent with %s\n"
          % (len(reg.kinds), len(reg.roles), len(reg.providers), SCHEMA.stem))


def check(reg, topology, provider):
    """Capability gaps for one topology against one provider."""
    caps = reg.capabilities(provider)
    prefix = topology.get("prefix", "rt")
    findings = []
    for node in topology["nodes"]:
        for req in reg.requirements_for(node):
            if req in caps:
                continue
            container = reg.kinds[node["kind"]]["category"] == "container"
            reason = reg.unsupported_reason(provider, req) or ""
            name = "%s-%s" % (prefix, node["id"])
            prose = "%s needs %s, which %s does not provide." % (
                name, req, provider)
            if reason:
                prose += " " + reason
            findings.append(("CAP002" if container else "CAP001", name, req, prose))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", help="check one provider verbosely")
    ap.add_argument("--palette", metavar="MODE", nargs="?", const="offense",
                    help="print the canvas palette for a mode")
    args = ap.parse_args()

    reg = Registry()

    if args.palette:
        palette = reg.palette(args.palette)
        if not palette:
            print("no kinds declared for mode %r" % args.palette)
            return
        for group, entries in palette.items():
            print(group)
            for e in entries:
                print("    %-14s %-6s %-26s %s"
                      % (e["label"], e["abbrev"], e["icon"], e["color"]))
        return

    sanity(reg)

    topologies = [(p.stem, json.loads(p.read_text()))
              for p in sorted(EXAMPLES.glob("*.json"))]
    providers = [args.provider] if args.provider else sorted(reg.providers)

    if args.provider:
        for name, topology in topologies:
            findings = check(reg, topology, args.provider)
            print("%s on %s" % (name, args.provider))
            if not findings:
                print("    no capability gaps\n")
                continue
            for code, node, req, prose in findings:
                print("    %s  %s" % (code, prose))
            print()
        return

    width = max(len(n) for n, _ in topologies) + 2
    print("%-*s%s" % (width, "", "  ".join("%-9s" % p for p in providers)))
    for name, topology in topologies:
        cells = ["%-9s" % ("ok" if not check(reg, topology, p) else
                           "%d gaps" % len(check(reg, topology, p)))
                 for p in providers]
        print("%-*s%s" % (width, name, "  ".join(cells)))
    print("\nrun with --provider <name> for the detail")


if __name__ == "__main__":
    main()
