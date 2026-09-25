#!/usr/bin/env python3
"""Compile a topology into a working directory.

    redstackpro compile <topology> -o build/
    redstackpro compile <topology> --list

A formatter over the same file map the API returns, so the CLI and the download
button cannot produce different output. See 0010.
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

from redstackpro import Registry, validate
from redstackpro.authoring import set_redirector_hostname
from redstackpro.export import compile_topology
from redstackpro.terraform import GenerationError

from . import _report


def configure(ap):
    ap.add_argument("topology")
    ap.add_argument("-o", "--out", default="build")
    ap.add_argument("--provider", default="gcp")
    ap.add_argument("--region", default=None,
                    help="cloud region for the deploy; overrides a region on "
                         "the document and the per-provider default")
    ap.add_argument("--list", action="store_true",
                    help="print the file map and write nothing")
    # A shipped example carrying a redirector arrives one field short on purpose, so
    # a tool driving the pipeline has to supply the domain the way a person would in
    # the canvas inspector before pressing Compile. The rule is unchanged: without
    # this, or a hostname already on the document, the compile still refuses.
    # Bare `--hostname cdn.example.com` names every redirector; `--hostname
    # node=name`, repeated, names them one at a time, which the split-horizon and
    # rollover shapes need because two redirectors front one C2 under different
    # names. A single shared name there is a routing conflict, not a shorthand.
    ap.add_argument("--hostname", action="append", default=[],
                    help="domain to give every redirector, or node=domain "
                         "(repeatable) to name them one at a time")
    return ap


def run(args, error):
    # `error` is the parser's .error: prints usage and exits, whether the parser
    # is the standalone one or the `redstackpro compile` subparser.
    document = json.loads(Path(args.topology).read_text())
    if args.hostname:
        paired = [h for h in args.hostname if "=" in h]
        if paired and len(paired) != len(args.hostname):
            error("--hostname takes either one bare domain or only node=domain pairs")
        try:
            if paired:
                set_redirector_hostname(document,
                                        dict(h.split("=", 1) for h in paired))
            else:
                set_redirector_hostname(document, args.hostname[-1])
        except ValueError as exc:
            # A per-redirector map that misses one or names a stranger is a typo
            # in the command, not a compiler fault. Say which, the way the
            # generation error below does, rather than with a traceback.
            error(str(exc))
    try:
        files = compile_topology(document, Registry(), provider=args.provider,
                              region=args.region)
    except GenerationError as exc:
        # The compiler refuses on an invalid topology and says only that. It is
        # right to refuse, but a traceback naming no cause is the wrong way to
        # say so to a person who just ran the command in the README. Ask the
        # validator what is actually wrong and print it the way validate.py
        # would, since the answer is a field they have to fill in.
        sys.stderr.write("%s: %s\n" % (Path(args.topology).stem, exc))
        findings = validate(document, provider=args.provider, registry=Registry())
        errors, _ = _report.render(findings, out=lambda line:
                                   sys.stderr.write(line + "\n"))
        if not errors:
            # Refused for a reason the validator does not report. Do not
            # swallow it; that is a compiler bug and the traceback is evidence.
            raise
        sys.exit(1)

    if args.list:
        for path in sorted(files):
            print("%7d  %s" % (len(files[path]), path))
        print("\n%d files" % len(files))
        return

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    for path, contents in sorted(files.items()):
        target = out / path
        target.parent.mkdir(parents=True, exist_ok=True)
        # Force LF: the generated files are shell/python/yaml meant to run on the
        # Linux jumpbox, and text-mode write on Windows would translate to CRLF,
        # which makes `bash deploy.sh` die on `$'\r'`. See the CRLF deploy bug.
        target.write_text(contents, encoding="utf-8", newline="\n")

    print("wrote %d files to %s" % (len(files), out))


def main(argv=None):
    ap = configure(argparse.ArgumentParser())
    run(ap.parse_args(argv), ap.error)


if __name__ == "__main__":
    main()
