"""tools/check_conventions.py gates the repo, and nothing was gating it.

It ran in CI against the real tree only, so its rules were exercised exactly as
far as the tree happened to exercise them. That is how a real blind spot shipped
and stayed: the link check ran line by line, so a markdown link whose text wraps
across lines was never seen at all. A wrapped image link pointing at a file that
does not exist passed, and the checker printed "conventions hold".

That is the shape this project keeps getting bitten by, now at least five times
over: a check that cannot ask reports the same thing as a check that found
nothing. So the cases live here, each one as a negative control that fails if
the rule stops working.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src/redstackpro/tools"))

import check_conventions  # noqa: E402

EM_DASH = chr(0x2014)
EN_DASH = chr(0x2013)


def links(text, parent):
    return check_conventions.link_problems("doc.md", text, parent)


def dashes(text):
    return check_conventions.dash_problems("doc.md", text)


# ---------------------------------------------------------------- the bug ---

def test_a_wrapped_link_to_a_missing_file_is_caught(tmp_path):
    """THE REGRESSION. Link text that wraps used to be invisible to the check.

    An image's alt text is a sentence, so this is the ordinary case for a
    screenshot in a README, not an exotic one.
    """
    text = "intro\n\n![The canvas, showing a lab\nas a topology.](img/missing.png)\n"
    problems = links(text, tmp_path)
    assert len(problems) == 1
    assert "img/missing.png" in problems[0]


def test_a_wrapped_link_that_resolves_is_accepted(tmp_path):
    (tmp_path / "img").mkdir()
    (tmp_path / "img" / "canvas.png").write_bytes(b"\x89PNG")
    text = "intro\n\n![The canvas, showing a lab\nas a topology.](img/canvas.png)\n"
    assert links(text, tmp_path) == []


def test_a_wrapped_link_reports_the_line_it_starts_on(tmp_path):
    """The line number has to point at the link, not at the end of its text.

    Computed from the match offset now that the scan is document-wide, which is
    the part of the rewrite most likely to drift.
    """
    text = "one\ntwo\nthree\n[a label that\nwraps](gone.md)\n"
    problems = links(text, tmp_path)
    assert problems[0].startswith("doc.md:4 ")


# ------------------------------------------------- the rule, still working ---

def test_a_single_line_link_to_a_missing_file_is_still_caught(tmp_path):
    problems = links("see [the record](decisions/0004.md) for why\n", tmp_path)
    assert len(problems) == 1
    assert "decisions/0004.md" in problems[0]


def test_a_link_that_resolves_is_accepted(tmp_path):
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")
    assert links("see [the readme](README.md)\n", tmp_path) == []


def test_external_links_are_not_filesystem_paths(tmp_path):
    text = ("[site](https://example.com/a) [plain](http://example.com) "
            "[mail](mailto:x@example.com) [anchor](#heading)\n")
    assert links(text, tmp_path) == []


def test_an_anchor_is_stripped_before_the_file_is_looked_up(tmp_path):
    (tmp_path / "doc.md").write_text("hi", encoding="utf-8")
    assert links("[a heading](doc.md#some-heading)\n", tmp_path) == []
    assert len(links("[a heading](gone.md#some-heading)\n", tmp_path)) == 1


def test_several_links_on_one_line_are_all_checked(tmp_path):
    (tmp_path / "here.md").write_text("hi", encoding="utf-8")
    problems = links("[a](here.md) and [b](gone.md) and [c](also-gone.md)\n",
                     tmp_path)
    assert len(problems) == 2


# ------------------------------------------------------------- the dashes ---

def test_an_em_dash_is_caught_with_its_line():
    problems = dashes("fine\nnot %s fine\n" % EM_DASH)
    assert len(problems) == 1
    assert problems[0].startswith("doc.md:2 ")
    assert "em dash" in problems[0]


def test_an_en_dash_is_caught():
    problems = dashes("a %s b\n" % EN_DASH)
    assert len(problems) == 1
    assert "en dash" in problems[0]


def test_a_hyphen_is_not_a_dash():
    """The bullet glyph and every hyphenated word would trip a loose check."""
    assert dashes("a plain-hyphen, a range 1-5, a bullet -  item\n") == []


# ------------------------------------------------------- the whole checker ---

def test_the_checker_passes_on_this_repo():
    """The CI invocation, run here too, so a refactor cannot quietly break it."""
    assert check_conventions.main() == 0
