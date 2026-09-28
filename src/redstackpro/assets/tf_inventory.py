#!/usr/bin/env python3
"""Fill redStackPRO address placeholders from terraform output.

Addresses do not exist until apply, so redStackPRO emits <<tf:node_id:field>> tokens
and this fills them in place. Run after `terraform apply`, before `ansible-playbook`.

    python3 tools/tf_inventory.py
    python3 tools/tf_inventory.py --tf-dir terraform --ansible-dir ansible
    python3 tools/tf_inventory.py --dry-run

Expects a terraform output named redstackpro_addresses shaped as:

    { "rt-ts-01": { "private_address": "10.30.20.4", "public_address": null } }

A second output, redstackpro_settings, carries deploy-time answers the topology
does not hold because the operator supplies them at apply -- reachable as the
reserved pseudo-node "@settings", so <<tf:@settings:operator_source_ranges>>
fills the same way an address does. It is optional: an export generated before
the output existed still fills its addresses, and only tokens that name it go
unresolved.

Re-running is safe even when the addresses changed. The first fill records each
token-bearing file's pristine text in a `.tf_sources.json` manifest at the run
root, and every run fills from that manifest. Without this, a second deploy in a
directory whose files were already substituted (a re-used export, or one whose
cloud handed out different IPs on the new apply) would find no `<<tf:` tokens
left and silently keep the stale addresses -- pointing a play at the wrong host.
The manifest lives at the root, not under ansible/, so it never trips the
"unfilled placeholders" grep deploy.sh runs over ansible/host_vars.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

TOKEN = re.compile(r"<<tf:([^:>]+):([^:>]+)>>")

# Where deploy-time settings land in the lookup table. Reserved, and not a legal
# node id, so it can never shadow a host.
SETTINGS = "@settings"


def terraform_output(tf_dir, name, optional=False):
    try:
        raw = subprocess.run(
            ["terraform", "output", "-json", name],
            cwd=tf_dir, capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        sys.exit("terraform not on PATH")
    except subprocess.CalledProcessError as exc:
        if optional:
            return {}
        sys.exit("terraform output failed: %s" % exc.stderr.strip())
    return json.loads(raw)


def lookup_table(tf_dir):
    """Addresses by node, plus deploy-time settings under a reserved key."""
    table = terraform_output(tf_dir, "redstackpro_addresses")
    table[SETTINGS] = terraform_output(
        tf_dir, "redstackpro_settings", optional=True)
    return table


def substitute(text, addresses, unresolved):
    def replace(match):
        node_id, field = match.group(1), match.group(2)
        value = addresses.get(node_id, {}).get(field)
        if not value:
            unresolved.add("%s.%s" % (node_id, field))
            return match.group(0)
        return value
    return TOKEN.sub(replace, text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tf-dir", default="terraform")
    ap.add_argument("--ansible-dir", default="ansible")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change, write nothing")
    ap.add_argument("--manifest", default=".tf_sources.json",
                    help="where the pristine token'd sources are recorded")
    args = ap.parse_args()

    ansible_dir = Path(args.ansible_dir)
    if not ansible_dir.is_dir():
        sys.exit("no such directory: %s" % ansible_dir)

    addresses = lookup_table(args.tf_dir)
    unresolved = set()
    touched = 0

    # The pristine, token'd text of every file we have ever filled, so a re-run
    # refills from the tokens rather than from already-substituted addresses.
    manifest_path = Path(args.manifest)
    manifest = {}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # The Ansible tree, plus the mode briefing at the export root, which carries
    # the same <<tf:...>> address tokens. Named by mode (DEFENSE-/OFFENSE-BRIEFING.md),
    # so it is found by the *-BRIEFING.md glob rather than a fixed name.
    paths = list(ansible_dir.rglob("*.yml"))
    paths += sorted(Path(".").glob("*-BRIEFING.md"))

    for path in sorted(paths):
        key = path.as_posix()
        if key in manifest:
            source = manifest[key]
        else:
            source = path.read_text(encoding="utf-8")
            if "<<tf:" not in source:
                continue
            manifest[key] = source
        filled = substitute(source, addresses, unresolved)
        touched += 1
        if not args.dry_run:
            path.write_text(filled, encoding="utf-8")
        print("%s %s" % ("would fill" if args.dry_run else "filled", path))

    if manifest and not args.dry_run:
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    if not touched:
        print("no placeholders found; already filled?")

    if unresolved:
        print("\nunresolved, left as placeholders:")
        for item in sorted(unresolved):
            print("    %s" % item)
        sys.exit(1)


if __name__ == "__main__":
    main()
