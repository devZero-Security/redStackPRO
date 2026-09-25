"""The decoy cover photographs: planned offline, fetched on the host, optional.

The properties worth guarding are the ones that let this coexist with the drawn
artwork rather than replace it:

  The plan is deterministic in the seed, so a compile is reproducible, and
  different per seed, so two redirectors do not serve the same photographs.
  Nothing it produces owes an attribution, because a cover page cannot carry a
  credit line.
  Every slot is optional. A page with no photographs at all must render exactly
  the page the drawn artwork rendered before photographs existed.
  The fetcher fails loudly on a broken invocation and quietly on an empty
  result, which are opposite polarities on purpose.
"""
import importlib.util
import io
import json
import os
import re

import pytest
import yaml

from redstackpro import decoyassets
from redstackpro.ansible import AnsiblePlan


FETCHER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "redstackpro", "assets", "ansible", "roles",
    "redstackpro.redirector", "files", "rsp-decoy-fetch.py",
)


def _fetcher():
    spec = importlib.util.spec_from_file_location("rsp_decoy_fetch", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fetch = _fetcher()


# --------------------------------------------------------------------------
# The plan


def test_the_same_seed_plans_the_same_assets():
    assert decoyassets.for_decoy("s", "healthcare") == decoyassets.for_decoy("s", "healthcare")


def test_a_different_seed_plans_different_assets():
    """The anti-fingerprint property, at the level this module controls.

    Two redirectors must not search the same terms in the same order, or they
    would tend to land on the same photographs however good the later ranking.
    """
    a = decoyassets.for_decoy("alpha", "healthcare")
    b = decoyassets.for_decoy("bravo", "healthcare")
    assert a != b
    assert a["seed"] != b["seed"]


@pytest.mark.parametrize("decoy", ["none", None, "", "not-a-vertical"])
def test_an_absent_or_unknown_decoy_plans_nothing(decoy):
    """A build must not fail because somebody turned the cover site off."""
    assert decoyassets.for_decoy("seed", decoy) is None


def test_every_vertical_has_imagery_and_every_imagery_entry_has_a_vertical():
    """Both directions, by name. A vertical with no terms plans photographs it
    can never fill; a terms block with no vertical is dead data."""
    cat = decoyassets._catalog()
    assert set(cat["sites"]) == set(cat["imagery"])


def test_every_imagery_pool_is_populated_and_plain_ascii():
    """ASCII because a stray non-Latin character in a search term is invisible
    in review and silently returns nothing. That happened while writing this."""
    for vertical, pools in decoyassets._catalog()["imagery"].items():
        for pool in ("scene", "detail"):
            terms = pools.get(pool) or []
            assert len(terms) >= 3, "%s/%s is too thin" % (vertical, pool)
            for term in terms:
                assert term.isascii(), "%s/%s: %r" % (vertical, pool, term)
                assert term.strip() == term and term


def test_no_search_term_asks_for_a_subject_that_carries_signage():
    """Found by looking at a render, not by reading the terms.

    "hospital building exterior" returned a photograph of a real pharmacy with
    its name across the front, which then appeared under an invented brand on
    the cover page -- exactly what 0041 forbids ("no page imitates a real
    organisation, brand, or domain"). Storefronts, facades, packaged products
    and mastheads reliably carry someone's real branding; interiors, details and
    materials do not. This cannot catch every case, so it holds the line at the
    vocabulary that made it happen.
    """
    banned = re.compile(
        r"\b(exterior|facade|storefront|shopfront|signage|billboard|skyline"
        r"|newspaper stack|magazine|terminal|logo|brand)\b", re.I)
    for vertical, pools in decoyassets._catalog()["imagery"].items():
        for pool, terms in pools.items():
            for term in terms:
                assert not banned.search(term), \
                    "%s/%s: %r asks for a subject that tends to carry real branding" \
                    % (vertical, pool, term)


def test_no_vertical_repeats_a_search_term():
    """A duplicate silently narrows a pool without looking narrower.

    This happened: replacing a signage-prone term with one the pool already
    held left education's scene pool reading as three terms and behaving as
    two. Checked within each pool and across the two, because a term serving as
    both the wide shot and the close-up is the same defect.
    """
    for vertical, pools in decoyassets._catalog()["imagery"].items():
        seen = []
        for pool, terms in pools.items():
            assert len(terms) == len(set(terms)), "%s/%s repeats a term" % (vertical, pool)
            seen += terms
        assert len(seen) == len(set(seen)), \
            "%s uses one term in both pools: %s" % (
                vertical, [t for t in seen if seen.count(t) > 1])


@pytest.mark.parametrize("kind", ["artwork", "museum piece"])
def test_pictures_of_things_are_rejected(kind):
    """Not every freely licensed image is a photograph of a working business.

    A food search returned a seventeenth century oil painting of a market
    stall, which passed the licence filter (the scan is freely licensed), the
    date filter (the scan is recent) and the colour filter (oil paint is not
    monochrome). A news search returned letterpresses in the Museum
    Plantin-Moretus, seven of twenty-five results for that term.
    """
    cats = {"artwork": ["Category:Still life paintings"],
            "museum piece": ["Category:Printing presses in the Museum Plantin-Moretus"]}[kind]
    assert fetch.artwork({"title": "File:x.jpg",
                          "categories": [{"title": c} for c in cats]})


@pytest.mark.parametrize("category", [
    "Category:360° panoramas",
    "Category:Panoramic postcards of the United States",
    "Category:Equirectangular projection",
    "Category:Colorized photographs",
    "Category:Cornell University in the 1900s",
])
def test_frames_that_cannot_survive_a_crop_are_rejected(category):
    """Two ways a picture passes every numeric check and still looks wrong.

    A panorama is usually cropped to about 2:1 before it reaches Commons, so it
    sits inside the aspect band while its paths curve away at both edges. A
    campus shot and an office lobby both reached a cover page that way, and the
    aspect cap could not see either.

    A colourised Edwardian market got past the date filter because the date on
    the record is when the scan was made, and past the colour filter because
    somebody had added the colour.
    """
    assert fetch.artwork({"title": "File:x.jpg",
                          "categories": [{"title": category}]})


@pytest.mark.parametrize("category", [
    "Category:Hotel lobbies in Germany",
    "Category:Sculpture",
    "Category:20th-century architecture",
    "Category:21st-century office buildings",
    "Category:Office interiors",
    "Category:Buildings completed in 2019",
])
def test_modern_places_are_not_mistaken_for_artworks(category):
    """The false positives that bound the filter.

    Sculpture is deliberately absent from it: measured, three of the flagged
    results for a marble lobby were good modern hotel and courthouse lobbies
    that happen to contain one, and rejecting on it throws away exactly the
    photographs the search is for. Centuries match only up to the nineteenth,
    because 20th-century architecture is an ordinary building.
    """
    assert not fetch.artwork({"title": "File:x.jpg",
                              "categories": [{"title": category}]})


def test_a_page_does_not_search_one_term_three_times():
    """Three service cards found by one search term is the tell that a machine
    filled the page."""
    for vertical in decoyassets._catalog()["sites"]:
        plan = decoyassets.for_decoy("seed", vertical)
        terms = [s["terms"][0] for s in plan["slots"] if s["name"].startswith("service")]
        assert len(set(terms)) == len(terms), vertical


def test_faces_are_never_given_search_terms():
    """The rule this module exists to hold: a portrait is generated, never
    found. Searching a free-licence library for faces returns identifiable real
    people, and one of those under an invented quote is the line not to cross.
    """
    plan = decoyassets.for_decoy("seed", "healthcare")
    faces = [s for s in plan["slots"] if s["kind"] == "face"]
    assert faces
    for slot in faces:
        assert slot["terms"] == []


def test_the_plan_matches_the_catalog_it_is_built_from():
    cat = decoyassets._catalog()
    section = cat["sections"]["healthcare"]
    plan = decoyassets.for_decoy("seed", "healthcare")
    kinds = [s["kind"] for s in plan["slots"]]
    assert kinds.count("face") == len(section["testimonials"])
    assert len([n for n in plan["slots"] if n["name"].startswith("service")]) \
        == len(section["services"])


def test_video_is_off_unless_asked_for():
    assert not [s for s in decoyassets.for_decoy("s", "food")["slots"]
                if s["kind"] == "video"]
    assert [s for s in decoyassets.for_decoy("s", "food", video=True)["slots"]
            if s["kind"] == "video"]


# --------------------------------------------------------------------------
# The licence filter


@pytest.mark.parametrize("licence", ["cc0", "pd", "public domain", "cc-pd-mark"])
def test_licences_needing_no_credit_owe_nothing(licence):
    ok, credit = fetch._usable({"License": {"value": licence}})
    assert ok and credit is None


@pytest.mark.parametrize("licence", ["cc-by-sa-4.0", "cc-by-2.0", "cc-by-4.0"])
def test_the_cc_by_family_is_usable_and_owes_a_credit(licence):
    """Where the modern photographs are. Filtering to public domain AND recent
    selects almost only US government work, which is how a fictional bank came
    to be illustrated with an Oval Office handshake. The credit is discharged on
    a footer-linked credits page rather than on the cover itself."""
    ok, credit = fetch._usable({
        "License": {"value": licence},
        "Artist": {"value": '<a href="/x">Jo Vance</a>'},
        "ObjectName": {"value": "Meeting room"},
        "LicenseShortName": {"value": licence.upper()},
        "LicenseUrl": {"value": "https://creativecommons.org/licenses/by/4.0/"},
    })
    assert ok
    # Stripped of the markup Commons wraps it in: this text is interpolated
    # into a page we serve, so a third-party record must not carry tags into it.
    assert credit["artist"] == "Jo Vance"
    assert credit["licence"] and credit["url"]


def test_a_source_library_id_is_trimmed_off_the_title():
    """Commons titles often end with the source library's own id. Left in, that
    number is exactly the artefact that says a page was filled from a stock
    search rather than written by whoever runs the business."""
    ok, credit = fetch._usable({
        "License": {"value": "cc-by-4.0"}, "Artist": {"value": "Jo"},
        "ObjectName": {"value": "Atrium, Wacker Drive, Chicago, IL - 54189583876"}})
    assert ok and credit["title"] == "Atrium, Wacker Drive, Chicago, IL"


def test_a_credit_that_cannot_name_anyone_is_refused():
    """A credit we cannot actually give is not a credit, so the image is
    refused rather than published with the photographer left blank."""
    ok, credit = fetch._usable({"License": {"value": "cc-by-4.0"},
                                "Artist": {"value": ""}})
    assert not ok and credit is None


@pytest.mark.parametrize("licence", [
    "cc-by-nc-3.0", "cc-by-nd-4.0", "gfdl", "fair use", "attribution required",
])
def test_licences_we_cannot_satisfy_are_refused(licence):
    """The negative control for the licensing position. Non-commercial and
    no-derivatives cannot be satisfied by a credits page: one forbids the use
    and the other forbids the crop."""
    ok, credit = fetch._usable({"License": {"value": licence},
                                "Artist": {"value": "Someone"}})
    assert not ok and credit is None


def test_an_empty_licence_record_is_refused():
    """Absent metadata is not permission."""
    assert fetch._usable({}) == (False, None)
    assert fetch._usable({"License": {"value": ""}}) == (False, None)


# --------------------------------------------------------------------------
# The fetcher's two failure polarities


def test_a_broken_plan_is_a_failure(tmp_path, capsys):
    """Loud half: the caller is wrong about something and must hear it."""
    assert fetch.main(["--plan", str(tmp_path / "nope.json"),
                       "--out", str(tmp_path / "out")]) == 2


def test_a_plan_with_no_slots_is_a_failure(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"seed": "x", "slots": []}), encoding="utf-8")
    assert fetch.main(["--plan", str(path), "--out", str(tmp_path / "out")]) == 2


def test_a_slot_that_cannot_be_filled_is_not_a_failure(tmp_path, monkeypatch):
    """Quiet half: a blocked egress degrades the page, it does not fail the
    deploy. This is the property that lets every template use be a fallback."""
    def boom(*args, **kwargs):
        raise OSError("no egress")
    monkeypatch.setattr(fetch, "_get", boom)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(decoyassets.for_decoy("s", "healthcare")), encoding="utf-8")
    out = tmp_path / "out"
    assert fetch.main(["--plan", str(path), "--out", str(out)]) == 0
    assert not list(out.glob("*.jpg"))


def test_the_summary_names_what_landed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    path = tmp_path / "plan.json"
    plan = decoyassets.for_decoy("s", "healthcare")
    path.write_text(json.dumps(plan), encoding="utf-8")
    fetch.main(["--plan", str(path), "--out", str(tmp_path / "out")])
    summary = json.loads(capsys.readouterr().out)
    assert summary["assets"] == {} and summary["count"] == 0
    assert summary["planned"] == len(plan["slots"])


def test_the_operator_pack_wins_over_a_search(tmp_path, monkeypatch):
    """A file the operator chose carries a licence they have already decided
    they can satisfy, and imagery they picked beats a keyword guess."""
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("the pack should have answered first")))
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "hero.jpg").write_bytes(b"operator bytes")
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"seed": "s", "slots": [
        {"name": "hero", "width": 100, "height": 50, "kind": "photo", "terms": ["x"]}]}),
        encoding="utf-8")
    out = tmp_path / "out"
    assert fetch.main(["--plan", str(path), "--out", str(out), "--pack", str(pack)]) == 0
    assert (out / "hero.jpg").read_bytes() == b"operator bytes"


# --------------------------------------------------------------------------
# The video slot, which only a pack can fill


def _video_plan():
    return {"seed": "s", "slots": [
        {"name": "video", "width": 1280, "height": 720, "kind": "video",
         "terms": ["x"]}]}


def test_a_pack_video_fills_the_video_slot(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("a video slot must never reach a search")))
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "video.mp4").write_bytes(b"operator clip")
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(_video_plan()), encoding="utf-8")
    out = tmp_path / "out"
    assert fetch.main(["--plan", str(path), "--out", str(out),
                       "--pack", str(pack)]) == 0
    assert (out / "video.mp4").read_bytes() == b"operator clip"


def test_a_video_slot_with_no_pack_is_not_a_failure(tmp_path, capsys):
    """The designed degradation: the hero falls back to the still planned
    alongside the clip, so an absent pack costs nothing but the video."""
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(_video_plan()), encoding="utf-8")
    out = tmp_path / "out"
    assert fetch.main(["--plan", str(path), "--out", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["assets"] == {}


def test_an_unfilled_video_slot_says_why(tmp_path, capsys):
    """The silent half of the original defect. A knob that does nothing must at
    least leave a reason in the deploy log naming the setting that fixes it."""
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(_video_plan()), encoding="utf-8")
    fetch.main(["--plan", str(path), "--out", str(tmp_path / "out")])
    assert "decoy_asset_pack" in capsys.readouterr().err


@pytest.mark.parametrize("filename,slot_kind", [
    # A video file satisfying a photograph slot went into an <img> element,
    # which is a broken picture across the top of the cover page. A still
    # satisfying the video slot went into a <video> that plays nothing.
    ("hero.mp4", "photo"),
    ("video.jpg", "video"),
])
def test_a_pack_file_cannot_fill_a_slot_that_cannot_display_it(
        tmp_path, monkeypatch, filename, slot_kind):
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (_ for _ in ()).throw(
        OSError("no egress")))
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / filename).write_bytes(b"wrong kind")
    name = filename.rsplit(".", 1)[0]
    out = tmp_path / "out"
    got = fetch.from_pack(
        {"name": name, "kind": slot_kind, "width": 10, "height": 10},
        str(pack), str(out))
    assert got is None
    assert not out.exists() or not list(out.iterdir())


def test_every_slot_kind_the_plan_emits_can_be_filled_from_a_pack():
    """Binds the two halves together. A new slot kind added to the plan with no
    entry here would silently accept photograph extensions, which is how the
    video slot came to accept a JPEG in the first place."""
    kinds = {s["kind"] for s in decoyassets.for_decoy("s", "food", video=True)["slots"]}
    assert kinds <= set(fetch.PACK_EXTENSIONS)


def test_a_candidate_is_chosen_from_more_than_one_photograph():
    """Ranking by fit alone would make every redirector searching a term serve
    the identical photograph, which is the asset hash this design avoids."""
    candidates = [(1.5 + i * 0.01, "u%d" % i, "t%d" % i) for i in range(30)]
    chosen = {fetch.pick(candidates, "seed-%d" % i, 1.5)[1] for i in range(40)}
    assert len(chosen) > 1


def test_a_search_with_no_candidates_picks_nothing():
    assert fetch.pick([], "seed", 1.5) is None


def test_the_search_does_not_ask_commons_to_restrict_the_licence(monkeypatch):
    """The haslicense: filter is deliberately gone.

    It restricts results to material owing no credit, and measured against real
    searches that is almost entirely archival or US government work. With the
    credits page discharging attribution the CC-BY family is eligible, and
    _usable() does the filtering where the record can actually be read.
    """
    seen = {}

    def capture(url, binary=False):
        seen["url"] = url
        return {"query": {"pages": {}}}
    monkeypatch.setattr(fetch, "_get", capture)
    fetch.search("hospital corridor", 1600)
    assert "haslicense" not in seen["url"]
    assert "iiurlwidth=1600" in seen["url"]
    # The record fields the licence decision is made from must be requested, or
    # every result arrives unjudgeable and the filter silently passes nothing.
    assert "extmetadata" in seen["url"]


def test_a_tall_source_is_rejected_before_it_is_downloaded(monkeypatch):
    """The aspect-ratio trap, handled at the point of choosing. A 1600x2844
    portrait survives object-fit: cover as a narrow vertical strip."""
    monkeypatch.setattr(fetch, "_get", _results({
        "tall": (1600, 2844, "cc0", "2019"),
        "wide": (1600, 1067, "cc0", "2019"),
    }))
    urls = [c[1] for c in fetch.search("anything", 1600)]
    assert urls == ["https://x/wide.jpg"]


def test_archival_photographs_are_rejected_before_they_are_downloaded(monkeypatch):
    """The public-domain corpus is overwhelmingly archival, because almost
    everything photographed recently is CC-BY or restricted. Unfiltered, a bank
    cover page led with a gutted building carrying a visible archive negative
    number, under the words "Banking you can rely on". Measured medians on real
    searches: 1905 for lecture halls, 1977 for hospital corridors, 1993 for
    lobbies. An old photograph is worse than an empty slot, because the drawn
    artwork fills an empty slot and nothing rescues the wrong photograph."""
    monkeypatch.setattr(fetch, "_get", _results({
        "archive": (1600, 1067, "pd", "1948"),
        "recent": (1600, 1067, "cc0", "2021"),
    }))
    assert [c[1] for c in fetch.search("anything", 1600)] == ["https://x/recent.jpg"]


@pytest.mark.parametrize("categories,rejected", [
    (["Category:Visits of Rafael Grossi"], True),
    (["Category:Signing ceremonies"], True),
    (["Category:Portraits of men"], True),
    (["Category:Conferences in Vienna"], True),
    (["Category:Office interiors", "Category:Chairs"], False),
    ([], False),
])
def test_photographs_of_identifiable_people_are_rejected(categories, rejected):
    """Commons is an encyclopedic library, not a stock one, so a search for a
    meeting room returns real officials in real meetings. An IAEA director
    general reached a fictional bank's cover page this way, insignia and all,
    past both the licence and the date filters -- the corpus is the problem,
    not the terms. Read from categories, because nothing here can look at an
    image."""
    page = {"title": "File:Something.jpg",
            "categories": [{"title": c} for c in categories]}
    assert fetch.peopled(page) is rejected


def test_a_people_photograph_never_reaches_the_candidate_list(monkeypatch):
    """The filter is wired into search, not merely available to it."""
    def pages(url, binary=False):
        meta = {"License": {"value": "cc-by-4.0"}, "Artist": {"value": "Jo"},
                "DateTimeOriginal": {"value": "2021"}}
        return {"query": {"pages": {
            "1": {"title": "File:Summit.jpg",
                  "categories": [{"title": "Category:Signing ceremonies"}],
                  "imageinfo": [{"thumburl": "https://x/people.jpg",
                                 "width": 1600, "height": 1067,
                                 "extmetadata": meta}]},
            "2": {"title": "File:Room.jpg",
                  "categories": [{"title": "Category:Office interiors"}],
                  "imageinfo": [{"thumburl": "https://x/room.jpg",
                                 "width": 1600, "height": 1067,
                                 "extmetadata": meta}]}}}}
    monkeypatch.setattr(fetch, "_get", pages)
    assert [c[1] for c in fetch.search("anything", 1600)] == ["https://x/room.jpg"]


def test_the_search_asks_for_the_categories_it_filters_on(monkeypatch):
    """A filter reading a field the query never requested rejects nothing and
    looks like it works. That failure mode has shipped here before."""
    seen = {}

    def capture(url, binary=False):
        seen["url"] = url
        return {"query": {"pages": {}}}
    monkeypatch.setattr(fetch, "_get", capture)
    fetch.search("anything", 1600)
    assert "categories" in seen["url"]


def test_an_undated_record_is_refused(monkeypatch):
    """Refused rather than waved through: on a cover page the cost of an
    archival photograph is high and the cost of an empty slot is nil."""
    monkeypatch.setattr(fetch, "_get", _results({
        "nodate": (1600, 1067, "cc0", None),
    }))
    assert fetch.search("anything", 1600) == []


@pytest.mark.parametrize("raw,expected", [
    ("2019-04-02 11:20:31", 2019),
    ("<span class='x'>circa 1948</span>", 1948),
    ("", None),
    ("no digits here", None),
])
def test_the_year_is_read_out_of_the_record(raw, expected):
    assert fetch.year({"DateTimeOriginal": {"value": raw}}) == expected


# --------------------------------------------------------------------------
# The compiler and the template


def _results(items):
    """A fake Commons response. `items` maps a name to (w, h, licence, year)."""
    def pages(url, binary=False):
        out = {}
        for i, (name, (w, h, licence, when)) in enumerate(items.items()):
            meta = {"License": {"value": licence},
                    "Artist": {"value": "Jo Vance"},
                    "LicenseShortName": {"value": licence.upper()}}
            if when is not None:
                meta["DateTimeOriginal"] = {"value": when}
            out[str(i)] = {"title": name, "imageinfo": [{
                "thumburl": "https://x/%s.jpg" % name,
                "width": w, "height": h, "extmetadata": meta}]}
        return {"query": {"pages": out}}
    return pages


def _topology(decoy="healthcare"):
    """The same shape test_decoyart.py compiles, so the two sets of host vars
    are asserted against one topology rather than two that could drift."""
    return {
        "version": "0.4.0",
        "name": "assets",
        "prefix": "red",
        "nodes": [
            {"id": "net01", "kind": "network", "overlay": {"cidr": "10.30.0.0/16"}},
            {"id": "sub01", "kind": "segment",
             "overlay": {"cidr": "10.30.0.0/24", "exposure": "internet"}},
            {"id": "rd01", "kind": "redirector",
             "overlay": {"hostname": "cdn.example-owned.test",
                         "gating": {"decoy": decoy}}},
        ],
        "edges": [
            {"id": "e1", "role": "attached", "source": "sub01", "target": "net01"},
            {"id": "e2", "role": "attached", "source": "rd01", "target": "sub01"},
        ],
    }


def test_a_redirector_is_given_an_asset_plan():
    vars_ = AnsiblePlan(_topology()).host_vars["red-rd01"]
    assert vars_["redstackpro_decoy_assets"]["slots"]
    # The drawn artwork is still shipped: it is the floor the photographs fall
    # back to, not the thing they replace.
    assert vars_["redstackpro_decoy_art"]


def test_a_redirector_with_no_cover_site_is_given_no_plan():
    vars_ = AnsiblePlan(_topology("none")).host_vars["red-rd01"]
    assert "redstackpro_decoy_assets" not in vars_


def test_two_builds_of_one_topology_plan_different_photographs():
    first = AnsiblePlan(_topology()).host_vars["red-rd01"]["redstackpro_decoy_assets"]
    second = AnsiblePlan(_topology()).host_vars["red-rd01"]["redstackpro_decoy_assets"]
    assert first != second
