#!/usr/bin/env python3
"""Fill redStackPRO address placeholders from terraform output.

Addresses do not exist until apply, so redStackPRO emits <<tf:node_id:field>> tokens
and this fills them in place. Run after `terraform apply`, before `ansible-playbook`.

    python3 tools/tf_inventory.py
    python3 tools/tf_inventory.py --tf-dir terraform --ansible-dir ansible
    python3 tools/tf_inventory.py --dry-run

Expects a terraform output named redstackpro_addresses shaped as:

    { "rt-ts-01": { "private_address": "10.30.20.4", "public_address": null } }
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

TOKEN = re.compile(r"<<tf:([^:>]+):([^:>]+)>>")


def terraform_addresses(tf_dir):
    try:
        raw = subprocess.run(
            ["terraform", "output", "-json", "redstackpro_addresses"],
            cwd=tf_dir, capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        sys.exit("terraform not on PATH")
    except subprocess.CalledProcessError as exc:
        sys.exit("terraform output failed: %s" % exc.stderr.strip())
    return json.loads(raw)


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
    args = ap.parse_args()

    ansible_dir = Path(args.ansible_dir)
    if not ansible_dir.is_dir():
        sys.exit("no such directory: %s" % ansible_dir)

    addresses = terraform_addresses(args.tf_dir)
    unresolved = set()
    touched = 0

    # The Ansible tree, plus the range briefing at the export root, which carries
    # the same <<tf:...>> address tokens.
    paths = list(ansible_dir.rglob("*.yml"))
    briefing = Path("RANGE-BRIEFING.md")
    if briefing.is_file():
        paths.append(briefing)

    for path in sorted(paths):
        original = path.read_text(encoding="utf-8")
        if "<<tf:" not in original:
            continue
        filled = substitute(original, addresses, unresolved)
        touched += 1
        if not args.dry_run:
            path.write_text(filled, encoding="utf-8")
        print("%s %s" % ("would fill" if args.dry_run else "filled", path))

    if not touched:
        print("no placeholders found; already filled?")

    if unresolved:
        print("\nunresolved, left as placeholders:")
        for item in sorted(unresolved):
            print("    %s" % item)
        sys.exit(1)


if __name__ == "__main__":
    main()
