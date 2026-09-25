#!/usr/bin/env python3
"""Procedurally drawn artwork for the redirector's decoy site.

This is the FLOOR of the cover page's imagery, not the whole of it. Photographs
are fetched by the redirector at deploy time (see decoyassets.py and the role's
rsp-decoy-fetch.py); everything here fills whatever slot a photograph did not.
A redirector with no egress, a blocked image source, or an unlucky search still
serves a complete and coherent page, and that is this module's job.

Why it is drawn rather than shipped, which is still true and still the reason:

  Hot-linking a CDN means every visitor's browser tells a third party the
  redirector's hostname, in the Referer, before anyone has decided whether that
  visitor should have been told anything. It also means the cover degrades to
  broken image icons the moment that host is blocked, which is worse than a
  page with no pictures at all.

  Bundling a fixed set of images makes their hashes a signature. The whole
  point of the cover profiles (see frontend/src/profiles.js) is that two
  redirectors do not share a fingerprint, and a stock photo shipped with every
  deployment is the easiest artefact in the world to hash-match. It would be a
  fingerprint we added on purpose.

Neither objection is an objection to photographs as such: both are about the
VISITOR'S BROWSER reaching a third party, and about shipping the same bytes
twice. Fetching on the host and serving locally avoids both, which is what 0059
decided and why photographs now exist alongside this.

So the art is drawn, from a seed, at compile time. Every build produces
different geometry, nothing is fetched, nothing is licensed, and the whole set
costs a few kilobytes of inline SVG.

Everything here is deterministic in `seed`: the same seed gives the same
artwork, which keeps a build reproducible, while a fresh seed per export keeps
two ranges from looking alike.
"""
import colorsys
import hashlib
import os
import random

import yaml

# The role's own catalog is the source of truth for a decoy's palette and for
# how many services and testimonials it has, so the artwork is read from there
# rather than from a second table that would drift away from it.
_VARS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "assets", "ansible", "roles", "redstackpro.redirector", "vars", "main.yml",
)
_CACHE = {}


def _rng(seed, salt=""):
    """A generator keyed on the seed and a salt naming what is being drawn.

    Salting per element matters: without it the hero and the first service icon
    would be drawn from the same opening draws of one stream, and would move in
    step whenever the seed changed.
    """
    digest = hashlib.sha256(("%s/%s" % (seed, salt)).encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _hex_to_rgb(value):
    value = value.lstrip("#")
    return tuple(int(value[i:i + 2], 16) / 255 for i in (0, 2, 4))


def _rgb_to_hex(rgb):
    return "#%02x%02x%02x" % tuple(max(0, min(255, round(c * 255))) for c in rgb)


def shade(color, lighten=0.0, saturate=0.0, rotate=0.0):
    """Move a colour in HLS space.

    The palettes in the role's vars give one accent per vertical. Everything
    drawn here is derived from it rather than from a second hardcoded palette,
    so the artwork belongs to the site it sits on instead of looking bolted to
    it.
    """
    h, l, s = colorsys.rgb_to_hls(*_hex_to_rgb(color))
    h = (h + rotate) % 1.0
    l = max(0.0, min(1.0, l + lighten))
    s = max(0.0, min(1.0, s + saturate))
    return _rgb_to_hex(colorsys.hls_to_rgb(h, l, s))


def _uid(seed, salt):
    """A short id unique to this piece of artwork.

    Gradients need an id to be referenced by, and these SVGs are inlined into
    one document -- the logo appears in the header and again in the footer. A
    fixed id would be duplicated, which is invalid, and every reference would
    resolve to whichever element came first. Cheap to avoid, hard to notice
    once it is wrong.
    """
    return "a" + hashlib.sha256(("%s/%s" % (seed, salt)).encode("utf-8")).hexdigest()[:8]


def _svg(width, height, body, extra=""):
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" '
        'preserveAspectRatio="xMidYMid slice" role="img" aria-hidden="true"%s>%s</svg>'
        % (width, height, extra, body)
    )


def logo(seed, accent, brand, idsalt="logo"):
    """A monogram mark: the brand's initials on a rounded tile.

    Initials rather than a drawn symbol because a symbol that means nothing is
    the thing that looks generated. Initials are what a small business actually
    has when it has no designer.

    `idsalt` changes ONLY the gradient's id, not the geometry, so the same mark
    can be inlined twice on one page -- the header and the footer both carry it
    -- without duplicating an id. The shape is still drawn from the plain
    "logo" stream, so both copies look identical.
    """
    rng = _rng(seed, "logo")
    letters = "".join(word[0] for word in brand.split()[:2]).upper() or "R"
    deep = shade(accent, lighten=-0.12, saturate=0.05)
    gid = _uid(seed, idsalt)
    body = (
        '<defs><linearGradient id="%s" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/>'
        "</linearGradient></defs>"
        '<rect width="64" height="64" rx="%d" fill="url(#%s)"/>'
        '<text x="32" y="41" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" '
        'font-size="%d" font-weight="700" fill="#ffffff">%s</text>'
        % (gid, accent, deep, rng.choice([12, 14, 16, 20]), gid,
           26 if len(letters) > 1 else 30, letters)
    )
    return _svg(64, 64, body)


def hero(seed, accent, tint):
    """The wide banner behind the opening headline.

    Layered translucent blobs over a gradient: abstract enough to sit under
    text, structured enough not to read as noise.
    """
    rng = _rng(seed, "hero")
    a = shade(accent, lighten=-0.05)
    b = shade(accent, rotate=rng.uniform(-0.08, 0.08), lighten=0.12, saturate=-0.1)
    shapes = []
    for i in range(rng.randint(4, 6)):
        cx = rng.randint(-60, 780)
        cy = rng.randint(-40, 400)
        r = rng.randint(90, 240)
        opacity = round(rng.uniform(0.07, 0.20), 3)
        shapes.append(
            '<circle cx="%d" cy="%d" r="%d" fill="%s" opacity="%s"/>'
            % (cx, cy, r, "#ffffff" if i % 2 else tint, opacity)
        )
    # A couple of long diagonals, which is what stops it reading as bubbles.
    for _ in range(rng.randint(1, 3)):
        y = rng.randint(40, 320)
        shapes.append(
            '<path d="M-20 %d L740 %d" stroke="#ffffff" stroke-width="%d" '
            'opacity="0.10" fill="none"/>' % (y, y - rng.randint(40, 160), rng.randint(18, 54))
        )
    gid = _uid(seed, "hero")
    body = (
        '<defs><linearGradient id="%s" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/>'
        "</linearGradient></defs>"
        '<rect width="720" height="360" fill="url(#%s)"/>%s'
        % (gid, a, b, gid, "".join(shapes))
    )
    return _svg(720, 360, body)


def service_icon(seed, index, accent):
    """A small glyph for a service card. Geometric, one per card, all clearly
    from the same family so three of them sit together."""
    rng = _rng(seed, "icon/%d" % index)
    soft = shade(accent, lighten=0.34, saturate=-0.25)
    kind = rng.randrange(5)
    if kind == 0:
        mark = ('<circle cx="24" cy="24" r="11" fill="none" stroke="%s" stroke-width="3.5"/>'
                '<path d="M24 17v14M17 24h14" stroke="%s" stroke-width="3.5" stroke-linecap="round"/>'
                % (accent, accent))
    elif kind == 1:
        mark = ('<path d="M14 30l7-8 6 6 8-11" fill="none" stroke="%s" stroke-width="3.5" '
                'stroke-linecap="round" stroke-linejoin="round"/>' % accent)
    elif kind == 2:
        mark = ('<rect x="14" y="14" width="20" height="20" rx="5" fill="none" '
                'stroke="%s" stroke-width="3.5"/><path d="M20 24h8" stroke="%s" '
                'stroke-width="3.5" stroke-linecap="round"/>' % (accent, accent))
    elif kind == 3:
        mark = ('<path d="M24 13l9 5v9c0 6-4 9-9 11-5-2-9-5-9-11v-9z" fill="none" '
                'stroke="%s" stroke-width="3.5" stroke-linejoin="round"/>' % accent)
    else:
        mark = ('<path d="M15 32V22M24 32V16M33 32V26" stroke="%s" stroke-width="4" '
                'stroke-linecap="round"/>' % accent)
    return _svg(48, 48, '<rect width="48" height="48" rx="12" fill="%s"/>%s' % (soft, mark))


def avatar(seed, name, accent):
    """A testimonial portrait, as initials on a tinted disc.

    The fallback for a portrait slot, used when no generated face was fetched.
    Initials rather than a photograph found by search: searching a free-licence
    library for faces returns identifiable real people, and one of those under
    an invented quote at a business that does not exist is a line not worth
    crossing. A generated face depicts nobody and is preferred when available
    (see decoyassets.FACE_SOURCE); initials are what a page falls back to, and
    plenty of real small sites use exactly this.
    """
    rng = _rng(seed, "avatar/%s" % name)
    initials = "".join(part[0] for part in name.split()[:2]).upper() or "A"
    hue = shade(accent, rotate=rng.uniform(-0.22, 0.22), lighten=0.06)
    body = (
        '<circle cx="40" cy="40" r="40" fill="%s"/>'
        '<text x="40" y="51" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" '
        'font-size="30" font-weight="600" fill="#ffffff">%s</text>' % (hue, initials)
    )
    return _svg(80, 80, body)


def band(seed, accent):
    """The wide tinted strip behind the mission statement."""
    rng = _rng(seed, "band")
    deep = shade(accent, lighten=-0.24, saturate=0.08)
    shapes = "".join(
        '<path d="M%d 200 Q %d %d %d 200 Z" fill="#ffffff" opacity="%s"/>'
        % (rng.randint(-100, 500), rng.randint(0, 720), rng.randint(-60, 120),
           rng.randint(260, 900), round(rng.uniform(0.04, 0.10), 3))
        for _ in range(rng.randint(3, 5))
    )
    return _svg(720, 200, '<rect width="720" height="200" fill="%s"/>%s' % (deep, shapes))


def minimap(seed, accent):
    """A stylised street grid for the location section. Blocks and roads, no
    real geography and no tile server to call."""
    rng = _rng(seed, "map")
    pale = shade(accent, lighten=0.40, saturate=-0.35)
    road = shade(accent, lighten=0.26, saturate=-0.30)
    blocks = []
    for x in range(0, 360, 60):
        for y in range(0, 240, 60):
            if rng.random() < 0.78:
                blocks.append(
                    '<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="#ffffff" '
                    'opacity="%s"/>' % (x + 6, y + 6, rng.randint(28, 46),
                                        rng.randint(26, 44), round(rng.uniform(0.5, 0.95), 2))
                )
    roads = "".join(
        '<path d="M0 %d h360" stroke="%s" stroke-width="7"/>' % (y, road)
        for y in range(30, 240, 60)
    ) + "".join(
        '<path d="M%d 0 v240" stroke="%s" stroke-width="7"/>' % (x, road)
        for x in range(30, 360, 60)
    )
    pin = ('<circle cx="180" cy="120" r="13" fill="%s"/>'
           '<circle cx="180" cy="120" r="5" fill="#ffffff"/>' % accent)
    return _svg(360, 240,
                '<rect width="360" height="240" fill="%s"/>%s%s%s'
                % (pale, roads, "".join(blocks), pin))


def _catalog():
    if not _CACHE:
        with open(_VARS, encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)
        _CACHE["sites"] = loaded.get("redstackpro_decoy_sites") or {}
        _CACHE["sections"] = loaded.get("redstackpro_decoy_sections") or {}
    return _CACHE


def for_decoy(seed, decoy):
    """The artwork for one decoy id, or None if there is nothing to draw.

    `none` is a real, supported value of gating.decoy -- a redirector can be
    configured to serve no cover site at all -- so an unknown or absent id is
    answered with None rather than an exception. A build must not fail because
    somebody turned the decoy off.
    """
    if not decoy or decoy == "none":
        return None
    cat = _catalog()
    site = cat["sites"].get(decoy)
    if site is None:
        return None
    merged = dict(site)
    merged.update(cat["sections"].get(decoy) or {})
    return build(seed, merged)


def build(seed, site):
    """Every piece of artwork one decoy site needs, keyed for the template.

    Returned as plain strings so the Ansible layer can carry them as ordinary
    variables and the template can inline them with `| safe`. Inline, not files:
    an <img src> would be another request and another thing to install, and
    these are small enough that the page carries them.
    """
    accent = site.get("accent", "#2c6fb5")
    card = site.get("card", "#ffffff")
    services = site.get("services") or []
    testimonials = site.get("testimonials") or []
    brand = site.get("brand", "Site")
    return {
        "logo": logo(seed, accent, brand),
        # The same mark for the footer, differing only in its gradient id.
        "logo_footer": logo(seed, accent, brand, idsalt="logo-footer"),
        "hero": hero(seed, accent, card),
        "band": band(seed, accent),
        "map": minimap(seed, accent),
        "icons": [service_icon(seed, i, accent) for i in range(max(3, len(services)))],
        "avatars": [avatar(seed, t.get("name", "A B"), accent) for t in testimonials],
    }
