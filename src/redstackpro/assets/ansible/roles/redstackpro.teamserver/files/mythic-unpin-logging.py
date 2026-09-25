#!/usr/bin/env python3
"""Remove the per-service log-driver pin from Mythic's generated compose file.

mythic-cli writes `logging: driver: json-file` onto every service it generates.
A per-service driver beats the daemon default, so a host configured to send
container output to the journal never gets Mythic's, and the shipper's journald
inputs for mythic_server and basic_logger collect nothing. Every other service
on the box reports normally, which is what makes it hard to notice: the C2
index simply has no mythic in it.

Edits YAML rather than grepping the text out, because the pin is a nested
mapping and a line-based delete leaves its `options:` children behind as
orphans, which makes the compose file invalid rather than unpinned.

Prints "stripped N services" when it changed something and "already unpinned"
when it did not, so the calling task can decide whether a recreate is needed
rather than recreating containers on every converge.
"""
import sys

import yaml


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "docker-compose.yml"
    with open(path, encoding="utf-8") as handle:
        document = yaml.safe_load(handle)

    services = (document or {}).get("services") or {}
    stripped = [name for name, spec in services.items()
                if isinstance(spec, dict) and spec.pop("logging", None) is not None]

    if not stripped:
        print("already unpinned")
        return 0

    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(document, handle, sort_keys=False, default_flow_style=False)
    print("stripped %d services: %s" % (len(stripped), ", ".join(sorted(stripped))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
