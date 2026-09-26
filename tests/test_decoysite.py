"""The cover page itself, rendered from the role's own template.

Everything else about the decoy site is tested one layer away from the page: the
artwork is checked as SVG strings, the plan as dicts, the fetcher as files on
disk. None of that says whether the HTML those three produce is coherent, and
the hero is where they meet -- three independent sources filling one band, each
the fallback for the one above it.

That band is also where the failures have been. A clip the template never
referenced sat in the web root serving nobody. A pack video satisfied the
photograph slot and went into an <img>. Both looked correct in every test that
did not render the page, because the defect was in the seam rather than in any
of the parts.

So this renders the real template with the real catalog and reads the result.
Jinja is skipped rather than required: Ansible renders this in production, so
jinja2 is a test convenience here and not a product dependency.
"""
import os
import re

import pytest
import yaml

from redstackpro import decoyart

jinja2 = pytest.importorskip("jinja2")


ROLE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "redstackpro", "assets", "ansible", "roles", "redstackpro.redirector",
)


def _catalog():
    with open(os.path.join(ROLE, "vars", "main.yml"), encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def render(images=None, decoy="healthcare"):
    """The index page of one cover site, with the given assets having landed."""
    catalog = _catalog()
    site = catalog["redstackpro_decoy_sites"][decoy]
    # StrictUndefined, because the default is why the first live deploy of this
    # template failed. Ansible's templating raises on a missing key -- "object
    # of type 'dict' has no attribute 'video'" -- while plain Jinja returns a
    # falsy Undefined, so `{% if photo.video %}` quietly took the fallback
    # branch in every test here and killed the task in production.
    #
    # That inverted the thing this file exists to check: the missing-slot path
    # is the designed behaviour, and it was the only path that could not work.
    # Strict mode makes the test at least as unforgiving as the deploy.
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.join(ROLE, "templates")),
        autoescape=False,
        undefined=jinja2.StrictUndefined,
    )
    page = next(p for p in site["pages"] if p["slug"] == "index")
    return env.get_template("decoy-site.html.j2").render(
        site=site,
        page=page,
        sections=catalog["redstackpro_decoy_sections"][decoy],
        art=decoyart.for_decoy("seed-a", decoy),
        redstackpro_decoy_images=images or {},
        redstackpro_decoy_credits=[],
    )


def fetched(html):
    """Every URL the browser would actually request for this page.

    Deliberately not a search for "http". An inline SVG carries
    xmlns="http://www.w3.org/2000/svg", which is a namespace name that nothing
    resolves, so a test matching it fails on correct code and says the opposite
    of what it means. That mistake has been made here before.
    """
    return re.findall(r'(?:\bsrc|\bposter|\bhref|xlink:href)\s*=\s*"([^"]*)"', html)


def render_404(decoy="healthcare"):
    """The 404, built the way the role builds it: straight from the catalog's
    `notfound` block, which carries no slug."""
    catalog = _catalog()
    site = catalog["redstackpro_decoy_sites"][decoy]
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.join(ROLE, "templates")),
        autoescape=False,
        undefined=jinja2.StrictUndefined,
    )
    return env.get_template("decoy-site.html.j2").render(
        site=site,
        page=site["notfound"],
        sections=catalog["redstackpro_decoy_sections"][decoy],
        art=decoyart.for_decoy("seed-a", decoy),
        redstackpro_decoy_images={},
        redstackpro_decoy_credits=[],
    )


@pytest.mark.parametrize("decoy", ["healthcare", "cdn", "finance"])
def test_the_404_renders_although_it_has_no_slug(decoy):
    """The page a scanner is most likely to see, and the one that could not be
    written.

    `notfound` is not a navigable page, so the catalog gives it no slug. Under
    plain Jinja `page.slug` is a falsy Undefined and the comparison is simply
    false; under Ansible it raises, and the task -- and the deploy -- fails.
    Every page dict here comes from the catalog rather than being invented, so
    a vertical whose notfound block drifts is caught too.
    """
    html = render_404(decoy)
    assert "slug" not in _catalog()["redstackpro_decoy_sites"][decoy]["notfound"]
    assert _catalog()["redstackpro_decoy_sites"][decoy]["notfound"]["heading"] in html
    # The inner-page layout, not the landing page: no hero on a 404.
    assert '<div class="hero">' not in html


# --------------------------------------------------------------------------
# The hero, layer by layer


def test_with_nothing_fetched_the_hero_is_drawn():
    """The floor. A redirector with no egress at all still serves a whole page,
    which is why the drawn artwork was kept rather than replaced."""
    html = render()
    assert "<video" not in html
    assert '<div class="hero-art">' in html
    assert "<svg" in html
    # No scrim: the drawn hero is a dark gradient by construction, so the white
    # headline reads on it without one.
    assert '<div class="scrim">' not in html


def test_a_photograph_covers_the_drawn_hero_and_gets_a_scrim():
    """A photograph carries no guarantee that white type will read on it."""
    html = render({"hero": "hero.jpg"})
    assert '<img src="/assets/hero.jpg"' in html
    assert '<div class="scrim">' in html
    assert "<video" not in html


def test_a_clip_covers_the_photograph_and_uses_it_as_the_poster():
    """The poster is what makes the band whole while the clip buffers, and what
    a browser declining to autoplay falls back to."""
    html = render({"hero": "hero.jpg", "video": "video.mp4"})
    assert '<source src="/assets/video.mp4"' in html
    assert 'poster="/assets/hero.jpg"' in html
    # The still stays underneath rather than being replaced by the clip, so
    # every layer below the video is still there to be uncovered.
    assert '<img src="/assets/hero.jpg"' in html


def test_a_clip_with_no_photograph_has_no_poster_and_keeps_the_drawn_hero():
    """A poster attribute pointing at a file that was never fetched is a broken
    request on every load."""
    html = render({"video": "video.mp4"})
    assert "poster=" not in html
    assert "<svg" in html
    assert '<div class="scrim">' in html, "a clip needs the scrim as much as a photo"


def test_a_clip_is_muted_looping_and_inline():
    """Not decoration. Muted is what makes autoplay permitted at all, so an
    unmuted hero simply does not play; playsinline stops a phone taking the
    whole page over with a fullscreen player; loop is what makes it a hero
    rather than a clip that plays once and freezes on its last frame."""
    html = render({"hero": "hero.jpg", "video": "video.mp4"})
    tag = re.search(r"<video[^>]*>", html).group(0)
    for attribute in ("autoplay", "muted", "loop", "playsinline"):
        assert attribute in tag, tag


def test_the_clip_type_follows_the_file():
    """A webm announced as mp4 is refused by the browser without explanation."""
    assert 'type="video/webm"' in render({"video": "video.webm"})
    assert 'type="video/mp4"' in render({"video": "video.mp4"})


def test_a_photographic_hero_drifts():
    """The cheap way to have a moving hero. It rides the photograph the host
    already fetched, so it costs no clip, no licence and no bytes, and stays
    different per deployment because the photograph is."""
    html = render({"hero": "hero.jpg"})
    assert "@keyframes hero-drift" in html
    assert re.search(r"\.hero-art img\s*\{[^}]*animation:\s*hero-drift", html)


def test_the_drift_is_fast_enough_to_see():
    """The property two versions got wrong while every test passed.

    "Is it animating" was the wrong question. Both rejected versions animated,
    were measurable in a browser, and moved the photograph a visible number of
    pixels on paper -- and neither could be seen by the person looking at the
    page. Slow is the intent; imperceptible is a defect.

    The floor is set ABOVE both versions that were rejected on sight rather
    than just below the current one, so this encodes the verdict instead of
    merely pinning today's numbers:

        0.0026 / s   38s across a 10% zoom   rejected
        0.0071 / s   24s across a 17% zoom   rejected
        0.0156 / s   18s across a 28% zoom   accepted
    """
    html = render({"hero": "hero.jpg"})
    seconds = float(re.search(r"animation:\s*hero-drift\s+([\d.]+)s", html).group(1))
    scales = [float(s) for s in re.findall(
        r"transform:\s*scale\(([\d.]+)\)", html)]
    assert len(scales) == 2, scales
    rate = abs(scales[1] - scales[0]) / seconds
    assert rate >= 0.010, (
        "%.4f scale per second is a rate already rejected as invisible" % rate)


def test_the_drift_runs_at_a_constant_speed():
    """The cause of the second rejection, and it was the easing rather than the
    numbers. On an infinite alternate animation ease-in-out takes the velocity
    to zero at BOTH ends and holds it near zero for seconds either side, so
    whether the hero appears to move depends on when somebody looks at it. A
    peak-velocity figure flatters that; a constant one does not."""
    html = render({"hero": "hero.jpg"})
    timing = re.search(r"animation:\s*hero-drift\s+[\d.]+s\s+(\S+)", html).group(1)
    assert timing == "linear", timing


def test_the_drift_never_drags_an_edge_into_the_band():
    """Both ends of the animation scale above 1, and that is the whole trick.

    At scale 1 the photograph exactly fills the band, so any translate at all
    pulls a strip of background into view along one edge. The overflow held in
    hand at each end has to exceed the distance travelled at that end, or the
    hero shows a bare edge for part of every cycle -- which is the kind of
    defect that only appears half way through an animation and so survives
    every screenshot.
    """
    html = render({"hero": "hero.jpg"})
    frames = re.search(r"@keyframes hero-drift\s*\{(.+?)\n\}", html, re.S).group(1)
    # The percent sign is optional: a zero offset is legally written bare, and
    # a test that insisted on "0%" would be dictating spelling rather than
    # checking the property it exists for.
    steps = re.findall(
        r"(?:from|to)\s*\{\s*transform:\s*scale\(([\d.]+)\)"
        r"\s*translate3d\(([-\d.]+)%?,\s*([-\d.]+)%?", frames)
    assert len(steps) == 2, frames
    for scale, dx, dy in steps:
        scale, dx, dy = float(scale), abs(float(dx)), abs(float(dy))
        assert scale > 1, "scale %s exposes the edge before it even moves" % scale
        # Overflow on each side, as a share of the element, against the
        # distance travelled. translate resolves in the scaled frame, so the
        # shift on screen is scale * the percentage written.
        overflow = (scale - 1) / 2 * 100
        assert scale * dx < overflow, "horizontal drift %s%% exceeds %s%%" % (dx, overflow)
        assert scale * dy < overflow, "vertical drift %s%% exceeds %s%%" % (dy, overflow)


def test_reduced_motion_stops_the_drift_as_well_as_the_clip():
    """Two sources of motion in one band, so the preference has to reach both.
    Hiding the clip while leaving the photograph panning underneath honours the
    setting in the markup and ignores it on screen."""
    html = render({"hero": "hero.jpg"})
    block = re.search(r"@media \(prefers-reduced-motion: reduce\)\s*\{(.+?)\n\}",
                      html, re.S).group(1)
    assert re.search(r"\.hero-art img\s*\{\s*animation:\s*none", block), block


def test_reduced_motion_uncovers_the_still():
    """A site that ignores the preference is a site built carelessly, and this
    page is trying to read as one somebody maintains."""
    html = render({"hero": "hero.jpg", "video": "video.mp4"})
    assert re.search(
        r"prefers-reduced-motion:\s*reduce[^}]*\{\s*\.hero-video\s*\{\s*display:\s*none",
        html), "the clip is not hidden for reduced motion"


# --------------------------------------------------------------------------
# The telephone number, shown one way and dialled another


@pytest.mark.parametrize("decoy,shown,dialled", [
    ("healthcare", "+1 (503) 611-0164", "tel:+15036110164"),
    ("news", "+44 113 496 0139", "tel:+441134960139"),
])
def test_the_number_is_shown_with_separators_and_dialled_without(
        decoy, shown, dialled):
    """Two different jobs for one value. A reader needs the brackets and the
    dash to see a phone number rather than a run of digits; a tel: link needs
    them gone. Deriving the second from the first is what stops the two
    drifting apart the next time a number changes."""
    html = render(decoy=decoy)
    assert shown in html, "the displayed number lost its formatting"
    assert dialled in html, "the dialled number kept a separator"


def test_every_vertical_dials_only_digits():
    """The catalog is hand-edited, so this is the check that catches a number
    typed in some new shape rather than the two spot cases above."""
    catalog = _catalog()
    for decoy in catalog["redstackpro_decoy_sites"]:
        if decoy not in catalog["redstackpro_decoy_sections"]:
            continue
        for link in re.findall(r'href="tel:([^"]*)"', render(decoy=decoy)):
            assert re.fullmatch(r"\+\d{10,15}", link), (decoy, link)


# --------------------------------------------------------------------------
# The property the whole design exists for


@pytest.mark.parametrize("images", [
    {},
    {"hero": "hero.jpg", "intro": "intro.jpg"},
    {"hero": "hero.jpg", "video": "video.mp4", "face-0": "face-0.jpg"},
])
def test_the_rendeart_page_reaches_nothing(images):
    """No visitor's browser touches a third party, whatever landed.

    This is the reason the assets are fetched at deploy time and served from
    the redirector's own origin: a hot-linked cover page tells the image host
    this redirector's hostname in the Referer of every single visit, and breaks
    the day that host is blocked. The video slot is the newest way to lose it,
    because a clip is the one asset an operator would be tempted to embed.
    """
    for url in fetched(render(images)):
        assert not url.startswith(("http://", "https://", "//")), url
