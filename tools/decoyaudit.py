#!/usr/bin/env python3
"""Audit the decoy cover sites' imagery against the live image source.

    tools/decoyaudit.py terms              which search terms still return usable photographs
    tools/decoyaudit.py fill [--vertical X] fetch every vertical and report what filled
    tools/decoyaudit.py sheet --out FILE    fetch and lay the heroes out as one contact sheet

Why this is a tool and not a test: every answer here depends on what a third
party holds today, so it cannot run in the suite without making the suite depend
on the network and on Wikimedia's editorial decisions. The unit tests hold the
shape of the catalog and the behaviour of the filters; this holds the thing
neither can see, which is whether the terms still find anything.

It exists because that failure is silent. A term that stops returning results
does not error: the slot simply falls back to drawn artwork, the page still
renders, the deploy still succeeds, and the cover quietly gets worse. Nine of
eighty-one terms were dead when this was first run, and nothing had reported it.

The other thing only a person can do is look. `sheet` exists because every real
defect in this feature was found by looking at the pictures rather than by
reading the code: a real pharmacy's signage under an invented brand, a derelict
building over the words "banking you can rely on", an oil painting of a market
stall, a 360 degree panorama with its paths curving away at both edges.
"""
import argparse
import glob
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from redstackpro import decoyassets  # noqa: E402

ROLE = os.path.join(os.path.dirname(decoyassets.__file__), "assets", "ansible",
                    "roles", "redstackpro.redirector")
FETCHER = os.path.join(ROLE, "files", "rsp-decoy-fetch.py")

# A term returning fewer than this cannot vary between two redirectors, which is
# the property the whole design rests on: the same handful of candidates means
# the same photographs, which means a shared asset hash.
THIN = 4


def _fetcher():
    import importlib.util
    spec = importlib.util.spec_from_file_location("rsp_decoy_fetch", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def audit_terms(out=sys.stdout):
    """Every term, and how many photographs survive the filters for it."""
    fetch = _fetcher()
    dead, thin, ok = [], [], 0
    for vertical, pools in sorted(decoyassets._catalog()["imagery"].items()):
        for pool, terms in sorted(pools.items()):
            for term in terms:
                try:
                    found = len(fetch.search(term, 900))
                except Exception as exc:
                    out.write("  %-11s %-7s %-34s ERROR %s\n"
                              % (vertical, pool, term, exc))
                    continue
                if found == 0:
                    dead.append((vertical, pool, term))
                elif found < THIN:
                    thin.append((vertical, pool, term, found))
                else:
                    ok += 1
    out.write("dead terms (nothing usable): %d\n" % len(dead))
    for vertical, pool, term in dead:
        out.write("  %-11s %-7s %s\n" % (vertical, pool, term))
    out.write("thin terms (under %d, cannot vary between redirectors): %d\n"
              % (THIN, len(thin)))
    for vertical, pool, term, found in thin:
        out.write("  %-11s %-7s %-34s %d\n" % (vertical, pool, term, found))
    out.write("healthy: %d\n" % ok)
    # A dead term is a real defect and should fail a check; a thin one is a
    # warning, because a small pool still produces a correct page.
    return 1 if dead else 0


def fetch_all(work, only=None, out=sys.stdout):
    """Run the real fetcher for every vertical. Returns {vertical: summary}."""
    results = {}
    verticals = [only] if only else sorted(decoyassets._catalog()["sites"])
    for key in verticals:
        target = os.path.join(work, key)
        os.makedirs(target, exist_ok=True)
        for stale in glob.glob(os.path.join(target, "*.jpg")):
            os.remove(stale)
        plan = decoyassets.for_decoy("audit/%s" % key, key)
        if plan is None:
            continue
        plan_path = os.path.join(target, "plan.json")
        with open(plan_path, "w", encoding="utf-8") as handle:
            json.dump(plan, handle)
        done = subprocess.run(
            [sys.executable, FETCHER, "--plan", plan_path, "--out", target],
            capture_output=True, text=True, encoding="utf-8")
        if done.returncode != 0:
            out.write("%-12s FETCH FAILED rc=%d\n" % (key, done.returncode))
            continue
        summary = json.loads(done.stdout)
        summary["planned_photos"] = len(
            [s for s in plan["slots"] if s["kind"] == "photo"])
        summary["dir"] = target
        results[key] = summary
    return results


def audit_fill(work, only=None, out=sys.stdout):
    results = fetch_all(work, only, out)
    out.write("%-12s %-7s %-8s %9s  %s\n"
              % ("vertical", "photos", "credits", "page kB", "hero from"))
    for key, summary in sorted(results.items()):
        photos = [n for n in summary["assets"] if not n.startswith("face")]
        size = sum(os.path.getsize(f)
                   for f in glob.glob(os.path.join(summary["dir"], "*.jpg"))) / 1024
        out.write("%-12s %-7s %-8d %9.0f  %s\n"
                  % (key, "%d/%d" % (len(photos), summary["planned_photos"]),
                     len(summary["credits"]), size,
                     summary.get("sources", {}).get("hero", "(drawn)")))
    return 0


def contact_sheet(work, path, out=sys.stdout):
    """Every vertical's hero in one image, so a person can judge them at once."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        out.write("contact sheet needs Pillow\n")
        return 2
    fetch_all(work, None, out)
    keys = sorted(os.path.basename(d) for d in glob.glob(os.path.join(work, "*"))
                  if os.path.isdir(d))
    width, height, pad, cols = 440, 176, 26, 3
    rows = (len(keys) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * width, rows * (height + pad)), "#111418")
    draw = ImageDraw.Draw(sheet)
    for index, key in enumerate(keys):
        x, y = (index % cols) * width, (index // cols) * (height + pad)
        draw.text((x + 6, y + 7), key.upper(), fill="#7fd1ff")
        hero = os.path.join(work, key, "hero.jpg")
        if os.path.exists(hero):
            with Image.open(hero) as image:
                image = image.convert("RGB")
                image.thumbnail((width - 8, height - 4))
                sheet.paste(image, (x + 4, y + pad - 4))
        else:
            draw.text((x + 10, y + pad + 60), "(drawn fallback)", fill="#888888")
    sheet.save(path)
    out.write("wrote %s (%dx%d, %d verticals)\n"
              % (path, sheet.size[0], sheet.size[1], len(keys)))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["terms", "fill", "sheet"])
    parser.add_argument("--vertical", help="only this decoy id")
    parser.add_argument("--work", default=os.path.join(
        os.path.expanduser("~"), ".redstackpro", "decoyaudit"),
        help="where fetched images are kept between runs")
    parser.add_argument("--out", default="decoy-heroes.png",
                        help="contact sheet path, for sheet")
    args = parser.parse_args(argv)
    os.makedirs(args.work, exist_ok=True)
    if args.mode == "terms":
        return audit_terms()
    if args.mode == "fill":
        return audit_fill(args.work, args.vertical)
    return contact_sheet(args.work, args.out)


if __name__ == "__main__":
    sys.exit(main())
