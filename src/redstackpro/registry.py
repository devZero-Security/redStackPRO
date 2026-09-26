"""Node kind registry loader.

The topology document holds user-supplied values only. Derived overlay fields and
per-kind requirements live in schema/registry/ as data. See 0013.
"""

from pathlib import Path

import yaml

# Resolve from the package, not the CWD: schema/ ships as package data, so the
# app no longer has to be run from the repo root. See 0013.
DEFAULT_ROOT = Path(__file__).resolve().parent / "schema" / "registry"


class Registry:
    def __init__(self, root=DEFAULT_ROOT):
        self.kinds = {}
        for path in sorted((root / "kinds").glob("*.yaml")):
            k = yaml.safe_load(path.read_text())
            self.kinds[k["kind"]] = k

        self.providers = {}
        for path in sorted((root / "providers").glob("*.yaml")):
            p = yaml.safe_load(path.read_text())
            self.providers[p["provider"]] = p

        self.roles = {
            r["role"]: r
            for r in yaml.safe_load((root / "roles.yaml").read_text())["roles"]
        }

    def palette(self, mode="artie"):
        """What the canvas offers, grouped. The canvas reads this rather than
        hardcoding kinds, so pro can add kinds by dropping files in. See 0013.

        Returns {group: [entry]} with entries ordered as declared.
        """
        groups = {}
        for kind, spec in self.kinds.items():
            if mode not in spec.get("modes", ["artie"]):
                continue
            display = spec.get("display") or {}
            groups.setdefault(display.get("group", "other"), []).append({
                "kind": kind,
                "abbrev": spec["abbrev"],
                "category": spec["category"],
                "label": display.get("label", kind),
                "blurb": display.get("blurb", ""),
                "icon": display.get("icon"),
                "color": display.get("color"),
            })
        # Topology leads, because a network and a subnet are what everything else
        # nests in; the rest follow a declared order, then anything unlisted.
        order = ["topology", "domains", "hosts", "redirector", "teamservers",
                 "management", "operator", "operational", "access", "network"]
        rank = lambda g: (order.index(g) if g in order else len(order), g)
        return {g: sorted(v, key=lambda e: e["label"])
                for g, v in sorted(groups.items(), key=lambda kv: rank(kv[0]))}

    def capabilities(self, provider):
        return set(self.providers[provider].get("capabilities", []))

    def reserved_addresses(self, provider):
        """How many addresses each provider holds back at the bottom and top of
        every subnet, as (head, tail). A host pinned into either band is refused
        at apply, and the bands differ per provider: AWS and Azure take the first
        four, GCP only the first two. Absent metadata falls back to the
        conservative floor of network address plus gateway. See net006.
        """
        spec = self.providers[provider].get("reserved_addresses") or {}
        return spec.get("head", 2), spec.get("tail", 1)

    def unsupported_reason(self, provider, name):
        for entry in self.providers[provider].get("unsupported", []):
            if entry["name"] == name:
                return " ".join(entry["reason"].split())
        return None

    def requirements_for(self, node):
        """Requirements that apply given this node's overlay values.

        `when` is equality on a single overlay field. Deliberately not an
        expression language: if a case needs more, the node kind should split.
        """
        kind = self.kinds.get(node["kind"])
        if kind is None:
            raise KeyError("no registry entry for kind %r" % node["kind"])
        overlay = node.get("overlay", {})
        applicable = []
        for req in kind.get("requirements", []):
            when = req.get("when")
            if when is None:
                applicable.append(req["name"])
                continue
            if len(when) != 1:
                raise ValueError(
                    "%s: `when` takes exactly one field, got %r"
                    % (node["kind"], when))
            field, value = next(iter(when.items()))
            if overlay.get(field) == value:
                applicable.append(req["name"])
        return applicable
