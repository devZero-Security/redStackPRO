#!/usr/bin/env python3
"""Fetch the decoy cover site's photographs, on the redirector, at deploy time.

Run with a plan produced by redstackpro/decoyassets.py:

    rsp-decoy-fetch.py --plan /path/plan.json --out /var/www/.../assets

Why this runs here rather than at compile time: the bytes never cross Ansible,
the redirector spends its own egress, and the images differ per deployment
because each host picks its own. Why it serves them locally afterwards: no
visitor's browser ever touches a third party, so the cover leaks no hostname in
a Referer and does not break the day the source is blocked.

Standard library only, on purpose. This runs on a host whose job is to look
unremarkable, and a pip install is both a failure mode and a thing to explain.
The one optional import is PIL, which does three jobs: cropping a photograph to
its slot, re-encoding it so two redirectors never serve identical bytes, and
rejecting monochrome results. Without it photographs are kept at the size the
thumbnailer returned and cropped by CSS, the colour check passes everything,
and portraits are skipped in favour of drawn initials.

TWO RULES GOVERN THE EXIT CODE, and they are opposites on purpose:

  A slot that cannot be filled is NOT a failure. The cover page is designed to
  degrade -- every missing slot falls back to drawn SVG -- so a blocked egress
  or an unlucky search must not fail a deploy.

  A broken invocation IS a failure. An unreadable plan, an unwritable output
  directory, or a plan with no slots means the caller is wrong about something,
  and exiting 0 there would be a checker that cannot fail.
"""
import argparse
import hashlib
import io
import json
import os
import random
import re
import shutil
import sys
import urllib.parse
import urllib.request

API = "https://commons.wikimedia.org/w/api.php"
FACE_URL = "https://thispersondoesnotexist.com/random-person.jpeg"

# A real contact point, because Wikimedia asks for one and a request without it
# is the first thing they rate-limit. It names the tool, not the deployment.
UA = "redStackPRO/0.4 decoy-asset-fetch (+https://redstackpro.dev)"

# Licences that need no credit at all. Kept separate from the ones that do,
# because these cost nothing: no credits entry, no obligation, no trace.
FREE = ("cc0", "pd", "public domain", "cc-pd", "pdm", "no restrictions")

# Licences that are usable provided the credit is given. This is where the
# modern photographs are: filtering to public domain AND recent selects almost
# only US government work, which is how a fictional bank came to be illustrated
# with an Oval Office handshake between identifiable heads of state. The CC-BY
# family is ordinary photographers photographing ordinary offices and clinics.
#
# The credit does NOT go on the cover page, which is what made this look
# impossible at first. It goes on a credits page linked from the footer, the
# way a real small business site carries one -- an extra mundane inner page,
# which if anything reads as more authentic rather than less.
#
# BY-SA is included and its share-alike clause is met by the credits page
# naming the licence that the cropped image is therefore also under. Cropping
# is an adaptation, so this is a real obligation and not a formality. See 0059.
CREDITED = ("cc-by", "cc by")

# Checked BEFORE the prefix match above, because "cc-by-nc-3.0" and
# "cc-by-nd-4.0" both begin with "cc-by" and a prefix test alone accepts them.
# Neither is usable here and the reasons differ: NonCommercial forbids the use,
# and NoDerivatives forbids the crop this script performs on every photograph.
# A test holds both, because the prefix bug is invisible until someone looks.
REFUSED = ("-nc", "-nd", " nc", " nd", "noncommercial", "noderiv")

TIMEOUT = 30


def _get(url, binary=False):
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        payload = response.read()
    return payload if binary else json.loads(payload.decode("utf-8"))


def _text(raw):
    """Commons returns several of these fields as HTML. Reduce to plain text.

    The credits page is built from these, and an unescaped `<a>` out of a
    third-party record would be markup injected straight into a page we serve.
    """
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", raw or "")).strip()


def _usable(meta):
    """Whether a Commons result can be published, and what credit it owes.

    Returns (False, None), (True, None) for something needing no credit, or
    (True, {...}) carrying everything the credits page has to state.

    Checked here even though the search already asked for a licence filter.
    `haslicense:` is a search heuristic and the record is the ground truth; if
    the operator's meaning ever shifts we still do not publish an image whose
    terms we have not actually read.
    """
    licence = (meta.get("License", {}).get("value") or "").lower()
    if not licence:
        return False, None
    if any(bad in licence for bad in REFUSED):
        return False, None
    if any(licence.startswith(ok) for ok in FREE):
        return True, None
    if any(licence.startswith(ok) for ok in CREDITED):
        artist = _text(meta.get("Artist", {}).get("value"))
        if not artist:
            # A credit we cannot actually give is not a credit. Refused rather
            # than published with the photographer left blank.
            return False, None
        # Commons titles often carry the source library's own id on the end
        # ("... Chicago, IL - 54189583876"). Left in, that number is exactly the
        # sort of artefact that says a page was filled from an image library.
        # Any punctuation separator, rather than a list of dash characters.
        # Writing the dashes out would put a literal en dash in the tree, which
        # the house style forbids and which is invisible in review, and the
        # class is the better pattern anyway: it catches every dash, a bullet
        # and a slash without anyone having to enumerate them.
        title = re.sub(r"\s*[^\w\s]\s*\d{6,}\s*$", "",
                       _text(meta.get("ObjectName", {}).get("value")))
        return True, {
            "artist": artist,
            "title": title[:90],
            "licence": _text(meta.get("LicenseShortName", {}).get("value")) or licence,
            "url": _text(meta.get("LicenseUrl", {}).get("value")),
        }
    # Anything else -- non-commercial, no-derivatives, GFDL, unknown -- is out.
    return False, None


# The oldest a photograph can be and still pass as this year's website. The
# public-domain corpus is overwhelmingly archival -- Library of Congress plates,
# Historic American Buildings Survey negatives, press photographs from the
# 1970s -- because almost everything shot recently is CC-BY or restricted.
# Measured on real searches: median year 1905 for lecture halls, 1977 for
# hospital corridors, 1993 for lobbies. Without this filter a bank's cover page
# led with a gutted building carrying a visible archive negative number, which
# is far worse than the drawn gradient it replaced.
OLDEST = 2005


# Commons is an ENCYCLOPEDIC image library, not a stock one. Its photographs
# are of newsworthy things and newsworthy people, so a search for a meeting room
# returns real officials in real meetings -- an IAEA director general appeared
# on a fictional bank's cover page this way, insignia and all. Licence and date
# filters do nothing about it, because the problem is the corpus, not the terms.
#
# Its category tree is the thing that can be filtered on: 17 of 40 results for
# "office meeting room" carry a category naming people, visits or ceremonies,
# and rejecting those leaves 23 usable. Measured.
#
# Negative search terms were tried first and are WORSE THAN USELESS: adding
# "-meeting -conference -visit" to that same query returned zero results
# instead of 23, because the words appear in the useful records too.
PEOPLE = re.compile(
    r"\b(people|persons?|portraits?|politicians?|officials?|visits?|meetings?"
    r"|ceremon\w*|delegat\w*|diplomat\w*|presidents?|ministers?|ambassador\w*"
    r"|speakers?|conferences?|awards?|signing|handshak\w*|staff)\b", re.I)


# Things that are not a photograph of a working business, in two groups.
#
# NOT A PHOTOGRAPH AT ALL. A search for a food market returned a seventeenth
# century oil painting of a market stall, which passed the licence filter (the
# scan is freely licensed), the date filter (the scan is recent) and the colour
# filter (oil paint is not monochrome). Nothing else here can tell a painting
# from a photograph.
#
# A MUSEUM PIECE. A search for a printing press returned exhibits in the Museum
# Plantin-Moretus, which is how a news site came to lead with a letterpress
# under glass. Seven of twenty-five results for that term were museum objects.
#
# Centuries are matched only up to the nineteenth: "20th-century architecture"
# is an ordinary modern building and rejecting it would cost far more than it
# saves.
#
# DELIBERATELY ABSENT: "sculpture". Measured, it is a false positive -- three of
# the flagged results for "marble lobby interior" were good modern hotel and
# courthouse lobbies that happen to contain one. Rejecting on it throws away
# exactly the photographs the search is for.
ARTWORK = re.compile(
    r"\b(paintings?|drawings?|engravings?|lithograph\w*|etchings?|woodcuts?"
    r"|frescos?|illustrations?|manuscripts?|tapestr\w*|sketches|prints? by"
    r"|museums?|antiques?"
    r"|(?:1?[0-9])(?:st|nd|rd|th)[- ]century)\b", re.I)


# A panorama survives every numeric check and still looks wrong. An
# equirectangular or fisheye frame is often cropped to about 2:1 before it
# reaches Commons, so it sits inside the aspect band while its paths and walls
# curve away at both edges; a campus shot and an office lobby both reached a
# cover page that way. Commons categorises them, which is the only reliable
# signal available here.
#
# The decades catch the other half of the same problem: a photograph of a place
# in the 1900s can carry a recent date, because the date on the record is when
# the scan or the colourisation was made rather than when the shutter opened.
# A colourised Edwardian market reached a cover page past both the date filter
# and the colour filter for exactly this reason.
WRONG_FRAME = re.compile(
    r"(panoram\w*|equirect\w*|photospheres?|fisheye|spherical"
    r"|360\s*(?:degree|°)?\s*(?:panorama|photograph)\w*"
    r"|colou?ri[sz]ed"
    r"|in the (?:18|19)\d0s)", re.I)


def artwork(page):
    """Whether a result is a picture of a thing rather than a photograph of a
    working place, or a frame that will not survive being cropped to a slot.
    Read from categories and title, same as peopled()."""
    haystack = " ".join(
        [page.get("title", "")]
        + [c.get("title", "") for c in page.get("categories") or []])
    return bool(ARTWORK.search(haystack) or WRONG_FRAME.search(haystack))


def peopled(page):
    """Whether a result looks like a photograph of identifiable people.

    Read from the categories rather than the image, because nothing here can
    look at a picture. Errs towards rejection: an empty slot falls back to
    drawn artwork, and a real named person illustrating a business that does
    not exist is the one failure with a cost outside our own deployment.
    """
    haystack = " ".join(
        [page.get("title", "")]
        + [c.get("title", "") for c in page.get("categories") or []])
    return bool(PEOPLE.search(haystack))


def year(meta):
    """The year a Commons record claims, or None.

    Populated on every result seen so far, but treated as optional: a missing
    date must not silently reject an image, and must not silently accept one
    either -- that choice belongs to the caller.
    """
    for key in ("DateTimeOriginal", "DateTime"):
        raw = meta.get(key, {}).get("value") or ""
        found = re.search(r"(1[89]\d\d|20\d\d)", re.sub(r"<[^>]+>", "", raw))
        if found:
            return int(found.group(1))
    return None


def search(terms, width):
    """Free-licence landscape candidates for one search term, best fit first.

    Ranked by how close the source's shape is to the slot's, because the page
    crops with object-fit: cover and a wildly tall source survives that as a
    narrow vertical strip of a photograph. This is the aspect-ratio trap that
    shows up every time an image meets a fixed box, so it is handled at the
    point of choosing rather than left to CSS.
    """
    query = urllib.parse.urlencode({
        "action": "query", "format": "json", "generator": "search",
        # No haslicense: filter any more. It restricts results to material
        # needing no credit, and measured against real searches that is almost
        # entirely archival or US government work -- the corpus that produced a
        # derelict building and an Oval Office handshake. With the credits page
        # discharging attribution, the CC-BY family is eligible and is where the
        # ordinary modern photographs are. _usable() does the filtering instead.
        "gsrsearch": "filetype:bitmap %s" % terms,
        "gsrnamespace": "6", "gsrlimit": "40",
        # Categories come back in the same call: they are what the people
        # filter reads, and a second round trip per candidate would triple the
        # deploy's requests against a host that asks to be treated gently.
        "prop": "imageinfo|categories",
        "iiprop": "url|size|extmetadata", "iiurlwidth": str(width),
        "cllimit": "max", "clshow": "!hidden",
    })
    pages = _get("%s?%s" % (API, query)).get("query", {}).get("pages", {})
    out = []
    for page in pages.values():
        info = (page.get("imageinfo") or [{}])[0]
        meta = info.get("extmetadata", {})
        if not info.get("thumburl"):
            continue
        ok, credit = _usable(meta)
        if not ok or peopled(page) or artwork(page):
            continue
        # An undated record is refused along with an old one. On a cover page
        # the cost of an archival photograph is high and the cost of an empty
        # slot is nil, because the drawn artwork fills it.
        taken = year(meta)
        if taken is None or taken < OLDEST:
            continue
        source_w, source_h = info.get("width") or 0, info.get("height") or 0
        if not source_w or not source_h:
            continue
        aspect = source_w / source_h
        # Both ends matter. Too tall and object-fit: cover leaves a narrow strip
        # of the picture. Too wide and it is a panorama: a campus shot came back
        # as a 360 degree image whose paths curve away on both sides, which is
        # unmistakable once it is cropped into a hero band. Only the lower bound
        # existed at first, which is how the panorama got through.
        if not 1.15 <= aspect <= 2.4:
            continue
        out.append((aspect, info["thumburl"], credit))
    return out


def pick(candidates, seed, target):
    """Choose one candidate: closest in shape, then seeded among the near ties.

    Taking the single best fit every time would make every redirector searching
    a given term serve the same photograph, which is the asset-hash fingerprint
    this whole design exists to avoid. Taking a uniformly random one ignores
    shape. So: rank by fit, then pick from the leading few.
    """
    if not candidates:
        return None
    ranked = sorted(candidates, key=lambda c: abs(c[0] - target))
    shortlist = ranked[:max(3, len(ranked) // 3)]
    return random.Random(seed).choice(shortlist)


def fit(path, width, height, seed=None):
    """Crop to the slot's shape, resize to it, and re-encode. In place.

    Three things at once, which is why it is worth the optional dependency:

      Weight. The thumbnailer resizes by width and leaves the height to the
      source, so a 1600-wide hero off a 3:2 photograph arrives 1600x1067 and
      costs about 380 kB to display a 1600x640 band. Measured, not guessed.
      Shape. Cropping here rather than in CSS means the file on disk is the
      picture the page shows, so nothing is downloaded to be thrown away.
      Fingerprint. A re-encode at a seeded quality means two redirectors that
      happened to choose the same source photograph still do not serve the same
      bytes, which is the property the drawn artwork had for free.

    Returns False if PIL is absent or the image is unreadable. Callers decide
    what that means: a photograph is kept at full size, a portrait is dropped.
    """
    try:
        from PIL import Image
    except ImportError:
        return False
    try:
        with Image.open(path) as image:
            image = image.convert("RGB")
            source_w, source_h = image.size
            target = width / height
            if source_w / source_h > target:
                crop = int(source_h * target)
                left = (source_w - crop) // 2
                image = image.crop((left, 0, left + crop, source_h))
            else:
                crop = int(source_w / target)
                top = (source_h - crop) // 2
                image = image.crop((0, top, source_w, top + crop))
            if image.size[0] > width:
                image = image.resize((width, height), Image.LANCZOS)
            quality = random.Random(seed).randint(78, 88) if seed else 82
            image.save(path, "JPEG", quality=quality, optimize=True)
        return True
    except Exception:
        return False


# What each kind of slot will accept out of an operator's pack, and the split
# is not cosmetic. A single shared list let a pack's hero.mp4 satisfy the hero
# photograph slot, which the template then rendered inside an <img> -- a broken
# picture across the top of the cover page, from a pack that looked correct in
# a directory listing. The reverse held too: a video.jpg satisfied the video
# slot and went into a <video> element that plays nothing.
#
# So a slot accepts only what its element can display.
PACK_EXTENSIONS = {
    "photo": (".jpg", ".jpeg", ".png", ".webp"),
    "face": (".jpg", ".jpeg", ".png", ".webp"),
    "video": (".mp4", ".webm"),
}


def from_pack(slot, pack, out):
    """An operator-supplied file for this slot, if the pack holds a usable one.

    The pack wins over anything fetched. An operator who has put real imagery
    for the target's own industry in front of us knows better than a keyword
    search does, and a file they chose carries a licence they have already
    decided they can satisfy.
    """
    if not pack or not os.path.isdir(pack):
        return None
    for ext in PACK_EXTENSIONS.get(slot.get("kind"), PACK_EXTENSIONS["photo"]):
        source = os.path.join(pack, slot["name"] + ext)
        if os.path.isfile(source):
            target = os.path.join(out, slot["name"] + ext)
            shutil.copyfile(source, target)
            # No credit from us: the operator chose this file and holds
            # whatever licence it carries.
            return os.path.basename(target), None, "pack"
    return None


def colourful(payload, floor=28):
    """Whether a downloaded image has enough colour to pass as a modern photo.

    Public-domain material skews heavily historical, because almost everything
    photographed recently is CC-BY or restricted. Left unfiltered, roughly half
    of what a search returns is monochrome, and a bank whose every picture is a
    1930s black-and-white plate is a worse tell than a drawn gradient: nobody
    believes it is this year's site. Measured at 10 of 22 on the first live run.

    Needs PIL. Without it the check passes everything, which is the same
    degradation every other optional step here takes.
    """
    try:
        from PIL import Image, ImageStat
    except ImportError:
        return True
    try:
        with Image.open(io.BytesIO(payload)) as image:
            stat = ImageStat.Stat(image.convert("RGB").convert("HSV"))
        return stat.mean[1] >= floor
    except Exception:
        return True


def fetch_photo(slot, seed, out):
    terms = " ".join(slot.get("terms") or [])
    if not terms:
        return None
    candidates = search(terms, slot["width"])
    target = slot["width"] / max(1, slot["height"])
    # Walk the shortlist rather than committing to one candidate, because
    # whether an image is monochrome is only knowable after downloading it.
    # Bounded, so a search that returns nothing usable still ends.
    chosen = payload = None
    tried = []
    for attempt in range(4):
        candidate = pick([c for c in candidates if c[1] not in tried],
                         "%s/%s/%d" % (seed, slot["name"], attempt), target)
        if not candidate:
            break
        tried.append(candidate[1])
        body = _get(candidate[1], binary=True)
        if colourful(body):
            chosen, payload = candidate, body
            break
        # Keep the first one as a fallback: a monochrome photograph still beats
        # an empty slot, and some verticals genuinely have little else.
        if payload is None:
            chosen, payload = candidate, body
    if not chosen:
        return None
    # Written only once the bytes are in hand. Opening first creates the file,
    # so a transfer that raises half way leaves a zero-byte JPEG sitting in the
    # web root -- served as a broken image by anything that globs the directory
    # instead of reading this function's answer.
    name = slot["name"] + ".jpg"
    path = os.path.join(out, name)
    with open(path, "wb") as handle:
        handle.write(payload)
    # Best effort: without PIL the photograph is still correct, just heavier and
    # cropped by CSS instead. A cover page is not worth failing a deploy over.
    fit(path, slot["width"], slot["height"], seed="%s/%s" % (seed, slot["name"]))
    return name, chosen[2], terms


def fetch_face(slot, out):
    """A generated portrait, which depicts no real person.

    Deliberately not a keyword search. Searching a free-licence library for
    portraits returns identifiable real people, and a recognisable face under an
    invented quote at a company that does not exist is a different and worse
    thing than a stock model. Skipped entirely if it cannot be shrunk, because
    the source is a fixed 1024x1024 at roughly half a megabyte and three of
    those on one page costs more than the portraits are worth.
    """
    payload = _get(FACE_URL, binary=True)
    name = slot["name"] + ".jpg"
    path = os.path.join(out, name)
    with open(path, "wb") as handle:
        handle.write(payload)
    if not fit(path, slot["width"], slot["height"], seed=slot["name"]):
        os.remove(path)
        return None
    # A generated face depicts nobody and is owed to nobody.
    return name, None, "generated"


def unsourced_video(slot, pack):
    """Say why a video slot is empty. There is no automatic source for one.

    Every other slot has a keyless fallback because still photographs under a
    free licence are abundant. Hero-loop video is not: a free-licence library
    of short, quiet, brand-free b-roll does not exist. Commons carries video,
    but it is documentary footage -- lectures, ceremonies, wildlife -- which is
    the same corpus problem the photographs had and worse, because a clip
    cannot be filtered on categories the way a still can be sampled and
    checked. The libraries that do have b-roll want their API terms discharged
    with a visible credit on the page, and a cover page that credits a stock
    library is telling the visitor what it is.

    So the pack is the only source, and the operator supplying it is also the
    person who can answer the question a keyword search cannot: what this
    particular target's industry actually looks like on film.

    An empty video slot costs nothing. The hero falls back to the photograph
    that was planned alongside it, and then to drawn artwork, so the page is
    whole either way. Said on stderr so the deploy log gives the reason rather
    than leaving an operator to wonder why the clip they asked for is absent.
    """
    wanted = " or ".join(slot["name"] + ext for ext in PACK_EXTENSIONS["video"])
    if pack:
        sys.stderr.write(
            "slot %s unfilled: no %s in the asset pack %s\n"
            % (slot["name"], wanted, pack))
    else:
        sys.stderr.write(
            "slot %s unfilled: a hero video comes only from an asset pack, and "
            "none was given. Set gating.decoy_asset_pack to a directory holding "
            "%s.\n" % (slot["name"], wanted))
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--pack", default="")
    args = parser.parse_args(argv)

    # A broken invocation must not look like a quiet success. See the module
    # docstring: this is the half that is allowed to fail.
    try:
        with open(args.plan, encoding="utf-8") as handle:
            plan = json.load(handle)
    except (OSError, ValueError) as exc:
        sys.stderr.write("cannot read plan: %s\n" % exc)
        return 2
    slots = plan.get("slots") or []
    if not slots:
        sys.stderr.write("plan has no slots\n")
        return 2
    try:
        os.makedirs(args.out, exist_ok=True)
    except OSError as exc:
        sys.stderr.write("cannot create %s: %s\n" % (args.out, exc))
        return 2

    seed = plan.get("seed") or hashlib.sha256(b"decoy").hexdigest()[:16]
    landed = {}
    sources = {}
    credits = []
    for slot in slots:
        try:
            got = from_pack(slot, args.pack, args.out)
            if got is None and slot.get("kind") == "photo":
                got = fetch_photo(slot, seed, args.out)
            elif got is None and slot.get("kind") == "face":
                got = fetch_face(slot, args.out)
            elif got is None and slot.get("kind") == "video":
                got = unsourced_video(slot, args.pack)
            if got:
                name, credit, source = got
                landed[slot["name"]] = name
                sources[slot["name"]] = source
                if credit:
                    credits.append(credit)
        except Exception as exc:
            # A slot that cannot be filled is not a failure: the template falls
            # back to drawn artwork for this one element and the page is still
            # whole. Recorded on stderr so a deploy log says what was missed.
            sys.stderr.write("slot %s unfilled: %s\n" % (slot.get("name"), exc))

    # Deduplicated: one photographer can supply two slots, and a credits page
    # that names them twice looks like the generated thing it is.
    seen, unique = set(), []
    for credit in credits:
        key = (credit["artist"], credit["title"])
        if key not in seen:
            seen.add(key)
            unique.append(credit)
    json.dump({"assets": landed, "credits": unique, "sources": sources,
               "count": len(landed), "planned": len(slots)},
              sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
