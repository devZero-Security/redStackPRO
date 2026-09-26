#!/usr/bin/env python3
"""Run the validator over the worked examples.

    redstackpro validate
    redstackpro validate --provider proxmox
    redstackpro validate <topology> --json
"""

import argparse
import glob
import json
import sys
from pathlib import Path

from redstackpro import Registry, validate
from redstackpro.authoring import set_redirector_hostname

from . import _report

# Resolved from the package: the shipped examples travel with the install, so the
# default run no longer depends on the CWD being the repo root.
EXAMPLES = str(Path(__file__).resolve().parents[1]
               / "schema" / "topology" / "examples" / "0.5.0" / "*.json")


def configure(ap):
    ap.add_argument("paths", nargs="*", help="topology documents; defaults to the examples")
    ap.add_argument("--provider", help="also run capability rules against this provider")
    ap.add_argument("--json", action="store_true", help="machine readable output")
    # Every example with a redirector is one field short on purpose: RDR001 holds the
    # compile until a person supplies a domain they own. Without this the run reports
    # that, correctly, and exits 1. Pass it to validate the rest of the topology the way
    # a person would after filling the inspector field.
    ap.add_argument("--hostname",
                    help="domain to give every redirector, as the canvas would")
    return ap


def run(args):
    paths = args.paths or sorted(glob.glob(EXAMPLES))
    if not paths:
        sys.exit("no topologies found")

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


def main(argv=None):
    run(configure(argparse.ArgumentParser()).parse_args(argv))


if __name__ == "__main__":
    main()
