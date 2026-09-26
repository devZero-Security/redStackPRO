"""The decoy cover artwork: drawn, seeded, and self-contained.

Three properties are worth guarding, and they are the three reasons this is
generated rather than a folder of stock images:

  It must be deterministic, so a build is reproducible.
  It must differ per seed, so no asset hash identifies a redStackPRO
  redirector, and so two redirectors in one range do not look alike.
  It must reach nothing. A cover page that fetches from a third party tells
  that party the redirector's hostname for every visitor.
"""
import re

import pytest
import yaml

from redstackpro import decoyart
from redstackpro.ansible import AnsiblePlan


SITE = {
    "brand": "Meridian Health Portal",
    "accent": "#1d7a8c",
    "card": "#ffffff",
    "services": [{}, {}, {}],
    "testimonials": [{"name": "Dana Reyes"}, {"name": "Sam Okafor"},
                     {"name": "Ivy Chen"}],
}


def _all_svg(art):
    for value in art.values():
        if isinstance(value, str):
            yield value
        else:
            for item in value:
                yield item


def test_same_seed_draws_the_same_artwork():
    """Reproducibility: re-running a compile on one topology must not churn."""
    assert decoyart.build("seed-a", SITE) == decoyart.build("seed-a", SITE)


def test_a_different_seed_draws_different_artwork():
    """The anti-fingerprint property. If this ever fails, every deployment is
    shipping byte-identical art and its hash identifies the tool."""
    a = decoyart.build("seed-a", SITE)
    b = decoyart.build("seed-b", SITE)
    assert a["hero"] != b["hero"]
    assert a["band"] != b["band"]
    assert a["map"] != b["map"]


def test_nothing_is_fetched_from_anywhere():
    """Nothing in the artwork causes a request.

    The check is on the attributes a browser FETCHES -- src, href, xlink:href,
    @import, <image> -- and on url() references, which must be local fragments.

    It deliberately does not grep for "http". The svg element carries
    xmlns="http://www.w3.org/2000/svg", which is a namespace name and is never
    resolved by anything; a test that matched it would fail on correct code and
    say the opposite of what it means.
    """
    for svg in _all_svg(decoyart.build("seed-a", SITE)):
        assert "@import" not in svg
        assert "<image" not in svg
        assert not re.search(r'\b(?:xlink:href|href|src)\s*=', svg), svg[:120]
        for ref in re.findall(r"url\(([^)]*)\)", svg):
            assert ref.startswith("#"), ref


def test_every_gradient_id_is_unique_within_a_build():
    """Two SVGs inlined in one document must not share an element id: every
    reference would resolve to whichever came first. The logo is the one drawn
    twice, in the header and the footer."""
    art = decoyart.build("seed-a", SITE)
    ids = []
    for svg in _all_svg(art):
        ids += re.findall(r'id="([^"]+)"', svg)
    assert len(ids) == len(set(ids)), ids
    assert art["logo"] != art["logo_footer"]


def test_the_two_logos_differ_only_in_their_id():
    """Same mark, different id. If the geometry diverged the footer would carry
    a visibly different logo from the header."""
    art = decoyart.build("seed-a", SITE)
    strip = lambda svg: re.sub(r"a[0-9a-f]{8}", "ID", svg)  # noqa: E731
    assert strip(art["logo"]) == strip(art["logo_footer"])


def test_an_icon_is_drawn_for_every_service():
    art = decoyart.build("seed-a", dict(SITE, services=[{}] * 5))
    assert len(art["icons"]) == 5


def test_an_avatar_is_drawn_for_every_testimonial():
    art = decoyart.build("seed-a", SITE)
    assert len(art["avatars"]) == len(SITE["testimonials"])


@pytest.mark.parametrize("decoy", ["none", "", None, "no-such-vertical"])
def test_a_missing_or_disabled_decoy_draws_nothing(decoy):
    """`none` is a supported value of gating.decoy, so turning the cover site
    off must not fail a build."""
    assert decoyart.for_decoy("seed", decoy) is None


def test_every_catalog_vertical_can_be_drawn():
    """Each decoy the role ships has a palette the generator can read and
    sections to size the icons and avatars from."""
    sites = decoyart._catalog()["sites"]
    assert sites, "the decoy catalog is empty"
    for key in sites:
        art = decoyart.for_decoy("seed", key)
        assert art, key
        assert art["icons"] and art["avatars"], key


def test_the_catalog_and_the_sections_cover_the_same_verticals():
    """The template reads both for every page it renders, so a vertical present
    in one and missing from the other is a deploy-time failure."""
    cat = decoyart._catalog()
    assert set(cat["sites"]) == set(cat["sections"])


def test_the_artwork_stays_small():
    """It is inlined into every page, so it has to stay in the kilobytes. A
    regression here would be someone embedding a raster."""
    total = sum(len(svg) for svg in _all_svg(decoyart.build("seed-a", SITE)))
    assert total < 40_000, total


def _redirector_topology():
    return {
        "schema_version": "0.6.0",
        "mode": "artie",
        "name": "art",
        "prefix": "art",
        "nodes": [
            {"id": "net01", "kind": "network", "overlay": {"cidr": "10.30.0.0/16"}},
            {"id": "sub01", "kind": "segment",
             "overlay": {"cidr": "10.30.0.0/24", "exposure": "internet"}},
            {"id": "rd01", "kind": "redirector",
             "overlay": {"hostname": "cdn.example-owned.test",
                         "gating": {"decoy": "finance"}}},
        ],
        "edges": [
            {"id": "e1", "role": "attached", "source": "sub01", "target": "net01"},
            {"id": "e2", "role": "attached", "source": "rd01", "target": "sub01"},
        ],
    }


def test_a_redirector_carries_its_artwork_in_host_vars():
    plan = AnsiblePlan(_redirector_topology())
    art = plan.host_vars["art-rd01"]["redstackpro_decoy_art"]
    assert set(art) >= {"logo", "logo_footer", "hero", "band", "map",
                        "icons", "avatars"}


def test_two_builds_of_one_topology_draw_different_artwork():
    """The seed is a per-build nonce, so the same topology exported twice does not
    produce the same pictures. This is what keeps the art off a signature."""
    topology = _redirector_topology()
    first = AnsiblePlan(topology).host_vars["art-rd01"]["redstackpro_decoy_art"]
    second = AnsiblePlan(topology).host_vars["art-rd01"]["redstackpro_decoy_art"]
    assert first["hero"] != second["hero"]


def test_a_redirector_with_the_decoy_off_carries_no_artwork():
    topology = _redirector_topology()
    topology["nodes"][2]["overlay"]["gating"]["decoy"] = "none"
    plan = AnsiblePlan(topology)
    assert "redstackpro_decoy_art" not in plan.host_vars["art-rd01"]


# No number on a cover page may be capable of ringing anyone. An arbitrary
# invented number does not clear that bar: it is somebody's actual line.
#
# US: a real area code for the city, then an exchange ENDING IN 11. Codes of
# that shape (211, 311, 611, 711, 811) are service codes in the North American
# plan and are never assigned as a central office code, so the number cannot
# reach a subscriber while still reading as an ordinary one. Deliberately not
# the 555-01XX fiction block, which is reserved but announces itself.
#
# UK: Ofcom publishes per-city drama ranges, which are held back explicitly.
# Only the cities listed here have one, which is why the catalog's UK sites sit
# in these cities and not others.
UNREACHABLE_NUMBER = re.compile(
    r"^\+1 \(\d{3}\) [2-9]11-\d{4}$"
    r"|^\+44 (?:113|114|115|116|117|118|121|131|141|151|161) 496 0\d{3}$")

# Which area code belongs to the city in the address beside it. Checked as a
# pair because the failure this guards against is a number and an address that
# are each plausible alone and contradict each other on the page.
AREA_CODE_CITY = {
    "503": ("Portland", "Beaverton"), "518": ("Albany",), "704": ("Charlotte",),
    "608": ("Madison",), "828": ("Asheville",), "303": ("Denver",),
    "113": ("Leeds",), "114": ("Sheffield",), "117": ("Bristol",),
    "118": ("Reading",), "151": ("Liverpool",),
}


def test_the_sections_name_no_real_contact_details():
    """Everything on a cover page is invented, and the phone numbers are the one
    field where "invented" is not enough on its own: an arbitrary number is
    somebody's actual line. Each one has to be structurally incapable of
    reaching a subscriber, so a curious visitor cannot ring a stranger."""
    sections = decoyart._catalog()["sections"]
    for key, block in sections.items():
        assert UNREACHABLE_NUMBER.match(block["phone"]), (key, block["phone"])
        assert "555" not in block["phone"], (key, block["phone"])
        assert block["address"], key
        for field in ("services", "testimonials", "stats"):
            assert len(block[field]) == 3, (key, field)


def test_every_area_code_matches_the_city_in_its_own_address():
    """A local number is only more convincing than a toll-free one while it is
    actually local. A Portland address over a Charlotte area code is a detail
    that costs nothing to get right and reads as wrong to anyone who knows the
    city, which on a cover page is the only reader who matters."""
    sections = decoyart._catalog()["sections"]
    checked = 0
    for key, block in sections.items():
        found = re.search(r"\((\d{3})\)|^\+44 (\d{3})", block["phone"])
        code = found.group(1) or found.group(2)
        cities = AREA_CODE_CITY[code]
        address = " ".join(block["address"])
        assert any(city in address for city in cities), (key, code, address)
        checked += 1
    # Without this the loop passes by finding nothing, which is the shape of
    # checker this repo keeps catching.
    assert checked == len(sections) and checked >= 12, checked


def test_the_role_vars_stay_valid_yaml():
    """The catalog is hand-edited data, and a broken quote there fails at deploy
    rather than at compile, which is the worst place to find it."""
    with open(decoyart._VARS, encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    assert loaded["redstackpro_decoy_sites"]
    assert loaded["redstackpro_decoy_sections"]
