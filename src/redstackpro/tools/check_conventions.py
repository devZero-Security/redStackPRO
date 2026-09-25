#!/usr/bin/env python3
"""Check the rules in the project conventions that a person would otherwise have to remember.

    python -m redstackpro.tools.check_conventions

Three of them. None is a style preference: the dash rule is a house convention
that applies to generated output as well as source, the second is the one
mistake in this repo that would actually matter, and the third is the one a
reader meets instead of the writer.
"""

import re
import subprocess
import sys
from pathlib import Path

# tools now lives at src/redstackpro/tools/; the repo root is three parents up.
ROOT = Path(__file__).resolve().parents[3]

# No em dashes or en dashes in any output, including generated docs and
# comments. the project conventions.
#
# By codepoint, because the rule applies to this file too and writing the
# characters here would make the checker fail on itself.
DASHES = {chr(0x2013): "en dash", chr(0x2014): "em dash"}

# Never commit credentials, tfvars with real values, or engagement data.
# the project conventions. These belong in a password manager or an encrypted file.
NEVER_TRACKED = (".pem", ".key", ".tfstate", ".env")
NEVER_TRACKED_NAMES = ("inventory.local",)

# A relative markdown link that resolves to nothing. The decision log is a web
# of cross references and the docs are the half of this project a reader meets
# first, so a link that 404s is a defect in the thing being read, not a typo.
# It is also invisible to the person who writes it, since they know where the
# file is. Two were live when this check was added: a record that moved
# directories, and a filename that changed after it was linked.
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
EXTERNAL = ("http://", "https://", "mailto:", "#")

# Binary and vendored trees, which are not ours to hold to the convention.
SKIP_DIRS = {".git", "node_modules", "dist", "build", ".venv", ".venv-win",
             "__pycache__", ".pytest_cache"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
                 ".zip", ".pdf", ".lock"}


def tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                         capture_output=True, text=True, check=True)
    return [Path(p) for p in out.stdout.split("\0") if p]


def dash_problems(name, text):
    """Every em dash and en dash in `text`, as reader-facing lines."""
    problems = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for char, label in DASHES.items():
            if char in line:
                problems.append(
                    "%s:%d has an %s. No em dashes or en dashes in any "
                    "output, including generated docs and comments."
                    % (name, line_number, label))
    return problems


def link_problems(name, text, parent):
    """Relative markdown links in `text` that resolve to nothing under `parent`.

    Scanned over the whole document rather than line by line. Link text wraps in
    a hand-written paragraph, and an image's alt text is a whole sentence, so a
    per-line scan simply does not see those links: the check passes and the link
    was never looked at. That blind spot was live, and it was found by pointing a
    wrapped image link at a file that does not exist and watching the checker
    report that conventions hold.
    """
    problems = []
    for match in MARKDOWN_LINK.finditer(text):
        target = match.group(1)
        if target.startswith(EXTERNAL):
            continue
        # Strip an anchor: the file has to exist, the heading is the renderer's
        # problem.
        target = target.split("#")[0]
        if not target:
            continue
        if not (parent / target).exists():
            line_number = text.count("\n", 0, match.start()) + 1
            problems.append(
                "%s:%d links to %s, which does not exist. A reader following "
                "it gets a 404; the writer never sees it."
                % (name, line_number, target))
    return problems


def main():
    problems = []
    checked = 0

    for rel in tracked_files():
        if set(rel.parts) & SKIP_DIRS or rel.suffix.lower() in SKIP_SUFFIXES:
            continue

        if rel.suffix.lower() in NEVER_TRACKED or rel.name in NEVER_TRACKED_NAMES:
            problems.append(
                "%s is tracked. Credentials, key material, and engagement data "
                "belong in a password manager or an encrypted file, never in "
                "this repo." % rel.as_posix())
            continue
        if rel.suffix == ".tfvars" and rel.name != "example.tfvars":
            problems.append(
                "%s is tracked. A tfvars file with real values is exactly what "
                "must not be committed." % rel.as_posix())
            continue

        path = ROOT / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        checked += 1

        problems.extend(dash_problems(rel.as_posix(), text))
        if rel.suffix.lower() == ".md":
            problems.extend(link_problems(rel.as_posix(), text, path.parent))

    print("checked %d tracked text files" % checked)
    if problems:
        print("\nproblems")
        for problem in problems:
            print(" -", problem)
        return 1
    print("conventions hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
