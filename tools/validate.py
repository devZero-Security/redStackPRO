#!/usr/bin/env python3
"""Run the validator over the worked examples.

    python tools/validate.py
    python tools/validate.py --provider proxmox
    python tools/validate.py schema/topology/examples/0.1.0/redstack.json --json
"""

import argparse
import glob
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import _report
from redstackpro import Registry, validate
from redstackpro.authoring import set_redirector_hostname

EXAMPLES = "schema/topology/examples/0.4.0/*.json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="topology documents; defaults to the examples")
    ap.add_argument("--provider", help="also run capability rules against this provider")
    ap.add_argument("--json", action="store_true", help="machine readable output")
    # Every example with a redirector is one field short on purpose: RDR001 holds the
    # compile until a person supplies a domain they own. Without this the run reports
    # that, correctly, and exits 1. Pass it to validate the rest of the topology the way
    # a person would after filling the inspector field.
    ap.add_argument("--hostname",
                    help="domain to give every redirector, as the canvas would")
    args = ap.parse_args()

    paths = args.paths or sorted(glob.glob(EXAMPLES))
    if not paths:
        sys.exit("no topologies found; run from the repo root")

    registry = Registry() if args.provider else None
    worst = 0
    out = {}

    for path in paths:
        topology = json.loads(Path(path).read_text())
        if args.hostname:
            set_redirector_hostname(topology, args.hostname)
        findings = validate(topology, provider=args.provider, registry=registry)
        out[path] = [f.to_dict() for f in findings]

        if args.json:
            continue

        errors = sum(1 for f in findings if f.severity == "error")
        warnings = len(findings) - errors
        print("%s  %s" % (Path(path).stem, _report.summary(errors, warnings)))
        _report.render(findings)
        print()
        worst = max(worst, 1 if errors else 0)

    if args.json:
        print(json.dumps(out, indent=2))
    sys.exit(worst)


if __name__ == "__main__":
    main()
