#!/usr/bin/env python3
"""The decoy site's photographic assets: planned here, fetched at deploy time.

This sits alongside decoyart.py rather than replacing it, and the split is the
whole design.

decoyart draws the cover page's artwork as inline SVG. That was the right answer
to "where do the pictures come from" while the only two candidates were
hot-linking a CDN (which tells that CDN the redirector's hostname, in the
Referer, for every visitor) and bundling a fixed set of files (whose hashes
become the fingerprint the cover profiles exist to avoid). Both objections are
about the *visitor's browser* reaching a third party, and about *shipping the
same bytes twice*.

Neither objection touches the photographs themselves, because where an asset is
fetched from and when it is fetched are independent choices. Fetch at deploy
time, re-encode, and serve from the redirector's own origin, and every property
survives:

  No Referer leak, because no visitor ever touches a third party.
  No broken cover the day the image host is blocked, because by then the bytes
  are already on the redirector.
  Hashes still differ per deployment, because each redirector picks different
  source images and the thumbnailer re-encodes them.
  Nothing heavy crosses Ansible; the redirector spends its own egress.

So this module produces a *plan* -- which slots a cover page has, how big each
one is, and what to search for -- and the role's decoy-assets.yml executes it on
the host. The plan is deterministic in `seed` so a compile is reproducible, and
different per seed so two redirectors in one range do not look alike.

Every slot is optional by construction. A slot whose fetch fails is simply
absent, and the template falls back to the drawn SVG for that one element. That
is why decoyart stays: it is the floor, not the previous attempt. A redirector
with no egress at all still serves a complete, coherent cover page.

Licensing is a hard filter, not a preference. A cover page cannot carry a credit
line -- it is both a tell and the thing that makes a page read as generated --
so only public-domain and CC0 material is eligible. Anything that would owe
attribution is rejected at the source, which is why the good keyword APIs
(Pexels, Unsplash) are reachable only through an operator-supplied pack, where
the obligation is the operator's to discharge and the content licence, not the
API terms, is what governs.
"""
import hashlib
import os
import random

import yaml

# Same catalog the artwork reads, for the same reason: one source of truth for
# what a decoy is, rather than a second table that drifts away from it.
_VARS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "assets", "ansible", "roles", "redstackpro.redirector", "vars", "main.yml",
)
_CACHE = {}

# Slot geometry. These are the sizes the page actually displays at, doubled for
# the sake of a high-density screen, and they are requested from the source
# rather than downloaded large and shrunk: the Commons thumbnailer resizes
# server-side via iiurlwidth, so asking for the right size costs one parameter
# and saves both the bandwidth and an image library on the redirector.
HERO = ("hero", 1600, 640)
INTRO = ("intro", 900, 720)
SERVICE = ("service", 600, 420)
FACE = ("face", 256, 256)
VIDEO = ("video", 1280, 720)

# A face is the one slot that cannot be sourced by keyword search, and the
# reason is worth keeping written down. Keyword-searching a free-licence photo
# library for portraits returns identifiable real people -- academics,
# politicians, conference speakers -- and putting one of those under an invented
# quote at a company that does not exist is a different and worse thing than
# using a model-released stock photo. A generated face depicts nobody, so it is
# the only portrait source that is honest here.
FACE_SOURCE = "generated"


def _rng(seed, salt=""):
    digest = hashlib.sha256(("%s/%s" % (seed, salt)).encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _catalog():
    if not _CACHE:
        with open(_VARS, encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)
        _CACHE["sites"] = loaded.get("redstackpro_decoy_sites") or {}
        _CACHE["sections"] = loaded.get("redstackpro_decoy_sections") or {}
        _CACHE["imagery"] = loaded.get("redstackpro_decoy_imagery") or {}
    return _CACHE


def _pick(rng, pool, count):
    """`count` distinct terms from `pool`, cycling only if the pool is short.

    Distinct matters: three service cards showing three photographs found by the
    same search term is the tell that the page was filled by a machine.
    """
    if not pool:
        return []
    if count <= len(pool):
        return rng.sample(list(pool), count)
    out = list(pool)
    rng.shuffle(out)
    while len(out) < count:
        out.append(rng.choice(list(pool)))
    return out[:count]


def slots(seed, decoy, services=3, faces=3, video=False):
    """The asset slots one cover page has, in the order the page uses them.

    Each slot is a plain dict the role loops over, carrying everything the fetch
    needs and nothing it does not: a name (which becomes the filename), the
    pixel size to request, the kind of source that can satisfy it, and the
    search terms for the ones that are searched.
    """
    cat = _catalog()
    imagery = cat["imagery"].get(decoy) or {}
    scene = imagery.get("scene") or []
    detail = imagery.get("detail") or []

    rng = _rng(seed, "slots/%s" % decoy)
    out = []

    name, width, height = HERO
    out.append({
        "name": name, "width": width, "height": height,
        "kind": "photo", "terms": _pick(rng, scene, 1),
    })

    name, width, height = INTRO
    out.append({
        "name": name, "width": width, "height": height,
        "kind": "photo", "terms": _pick(rng, detail, 1),
    })

    name, width, height = SERVICE
    for index, term in enumerate(_pick(rng, detail + scene, max(0, services))):
        out.append({
            "name": "%s-%d" % (name, index), "width": width, "height": height,
            "kind": "photo", "terms": [term],
        })

    name, width, height = FACE
    for index in range(max(0, faces)):
        out.append({
            "name": "%s-%d" % (name, index), "width": width, "height": height,
            "kind": "face", "terms": [],
        })

    if video:
        name, width, height = VIDEO
        out.append({
            "name": name, "width": width, "height": height,
            "kind": "video", "terms": _pick(rng, scene, 1),
        })

    return out


def for_decoy(seed, decoy, video=False):
    """The asset plan for one decoy id, or None if there is nothing to fetch.

    `none` is a supported value of gating.decoy, and an unknown id must not
    raise: a build cannot fail because somebody turned the cover site off. Same
    contract as decoyart.for_decoy, deliberately, so the caller treats them
    alike.
    """
    if not decoy or decoy == "none":
        return None
    cat = _catalog()
    site = cat["sites"].get(decoy)
    if site is None:
        return None
    section = cat["sections"].get(decoy) or {}
    plan = slots(
        seed, decoy,
        services=len(section.get("services") or []) or 3,
        faces=len(section.get("testimonials") or []),
        video=video,
    )
    if not plan:
        return None
    return {
        # Carried through to the host so a re-run of the role fetches the same
        # images rather than churning the page on every converge.
        "seed": hashlib.sha256(("%s/%s" % (seed, decoy)).encode("utf-8")).hexdigest()[:16],
        "slots": plan,
    }
