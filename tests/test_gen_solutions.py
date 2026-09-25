"""The per-lab solution sets are generated from the authored GOAD series.

A generated folder that drifts from its source is worse than no folder at all:
it reads as a maintained guide while quietly describing a lab that has moved on.
These tests pin the generator's behaviour and fail when the committed output
stops matching what the tool would write today.
"""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("gen_solutions", ROOT / "src/redstackpro/tools/gen_solutions.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def _template(lab):
    # Most templates live under the goad/ tree; harbor is redStackPRO's own range
    # and sits at frontend/public/harbor.json, so fall back to the public root.
    path = ROOT / f"frontend/public/goad/{lab}.json"
    if not path.exists():
        path = ROOT / f"frontend/public/{lab}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_committed_output_matches_the_generator():
    """Regenerating must be a no-op, or the folders are stale."""
    assert gen.main_check() == 0, (
        "docs/solutions/<lab>/ is out of date. Run python -m redstackpro.tools.gen_solutions"
    )


def test_surface_counts_match_the_published_coverage_matrix():
    """The two-dimension surface count is the number the lab matrix publishes.

    docs/solutions/labs/README.md states goad reaches 36 techniques and
    goad-light 22. Those numbers are the whole basis for calling the smaller
    labs subsets, so the extractor has to reproduce them exactly. Counting host
    vulns alone understates goad by six, which is the mistake the matrix itself
    warns about.
    """
    assert len(gen.lab_surface(_template("goad"))) == 39
    assert len(gen.lab_surface(_template("goad-light"))) == 22


def test_the_lab_coverage_matrix_matches_the_templates():
    """Every number in docs/solutions/labs/README.md, checked against the labs.

    That table is the entry point for picking a lab, and it was maintained by
    hand next to machine readable templates, so it drifted: goad-wazuh's surface
    was published as 13 against a real 11, and dracarys as 3 against a real 6.
    Parsing the table and recomputing each row is the only thing that keeps the
    published numbers honest as the templates change.
    """
    rows = {}
    in_matrix = False
    for line in (ROOT / "docs/solutions/labs/README.md").read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells[:4] == ["lab", "domains", "hosts", "surface"]:
            # Anchor on the header. The page carries a second five column table
            # of build runtimes whose rows also start with a lab name, and a
            # loose shape match reads those as coverage numbers.
            in_matrix = True
            continue
        if not in_matrix:
            continue
        if not line.startswith("|"):
            break
        if len(cells) != 5 or set(cells[1]) <= set("-"):
            continue
        name = cells[0].split("](")[0].lstrip("[")
        # The last column opens with "N unique" where the lab adds techniques
        # goad never reaches. Both rows that drifted were stale in that number
        # too, so it is checked with the rest rather than left to prose.
        unique = int(cells[4].split()[0]) if cells[4].split()[:2][-1:] == ["unique"] else None
        rows[name] = tuple(int(c) for c in cells[1:4]) + (unique,)
    assert len(rows) == 9, f"parsed {len(rows)} lab rows, expected 9"

    goad = gen.lab_surface(_template("goad"))
    wrong = []
    for lab, published in rows.items():
        template = _template(lab)
        kinds = [n.get("kind") for n in template["nodes"]]
        surface = gen.lab_surface(template)
        actual = (
            kinds.count("domain"),
            sum(1 for k in kinds if k in ("dc", "srv", "wks", "jumpbox", "siem")),
            len(surface),
            len(surface - goad) if published[3] is not None else None,
        )
        if actual != published:
            wrong.append(f"{lab}: table says {published}, template says {actual}")
    assert not wrong, (
        "coverage matrix is stale (domains, hosts, surface, unique):\n" + "\n".join(wrong)
    )


def test_anonymous_grants_alone_do_not_count_as_an_acl_chain():
    """minilab plants two ACL edges and neither is an escalation.

    Both grant `NT AUTHORITY\\ANONYMOUS LOGON` read over the domain root, which
    configures anonymous LDAP enumeration - part 2 material, not part 11. A
    truthiness test on the acls list called that an ACL abuse chain and would
    hand minilab a page with nothing in it to walk. Labs with a real chain must
    still earn the token.
    """
    assert "acls" not in gen.lab_targets(_template("minilab"))
    for lab in ("goad", "goad-light", "goad-mini", "nha"):
        assert "acls" in gen.lab_targets(_template(lab)), lab


def test_hand_written_part_tables_agree_with_the_templates():
    """The three ungenerated labs keep hand-written part tables. Audit them.

    Five of the fourteen rows on nha and minilab were wrong when this was first
    run, the same defect already found on goad-light, goad-mini and the coverage
    matrix. These labs cannot be generated (each carries techniques the goad
    series never exercises), so the table stays hand-written and this test is
    what keeps it honest.

    Two rows are deliberately allowed to disagree, because the extractor is
    permissive where a source section carries no marker and the hand-written
    answer is the more useful one. They are named here so a NEW disagreement
    still fails.
    """
    import re

    sources = sorted(p for p in gen.SOURCE_DIR.iterdir() if gen.PART_FILE.match(p.name))
    allowed = {("minilab", 5)}  # unmarked sections; "partial" is the better answer

    wrong = []
    for lab in ("nha", "minilab"):
        template = _template(lab)
        surface = gen.lab_surface(template) | gen.lab_targets(template)
        computed = {}
        for source in sources:
            number = int(re.match(r"part-(\d+)", source.name).group(1))
            rendered = gen.render_part(source, lab, surface)
            computed[number] = (
                "no" if rendered is None else ("partial" if rendered[1] else "yes")
            )

        page = (ROOT / f"docs/solutions/labs/{lab}.md").read_text(encoding="utf-8")
        published = {}
        for line in page.splitlines():
            row = re.match(r"\|\s*(\d+)\s+[^|]*\|\s*\**(yes|no|partial)\**\s*\|", line.strip())
            if row:
                published[int(row.group(1))] = row.group(2)
        assert len(published) == 14, f"{lab}: parsed {len(published)} rows, expected 14"

        for number, expected in sorted(computed.items()):
            if (lab, number) in allowed:
                continue
            if published[number] != expected:
                wrong.append(
                    f"{lab} part {number}: page says {published[number]}, template says {expected}"
                )
    assert not wrong, "hand-written part tables are stale:\n" + "\n".join(wrong)


def test_goad_light_is_a_strict_subset_of_goad():
    assert gen.lab_surface(_template("goad-light")) <= gen.lab_surface(_template("goad"))


def test_an_unmarked_section_is_always_kept():
    """Annotation is opt-in, so a forgotten marker shows too much, never too
    little. Silently dropping a step from someone's only guide is the failure
    that must not be possible."""
    kept, dropped = gen.render_sections(
        [("Step 1 - something", "## Step 1 - something\n\nbody\n")],
        lab="goad-light",
        surface=set(),
    )
    assert len(kept) == 1 and not dropped


def test_a_section_is_dropped_only_when_the_lab_cannot_meet_it():
    sections = [
        ("Step 5 - linked", "## Step 5 - linked\n<!-- lab-requires: mssql_linked -->\n\nbody\n"),
        ("Step 2 - impersonate", "## Step 2 - impersonate\n<!-- lab-requires: mssql_impersonation -->\n\nbody\n"),
    ]
    kept, dropped = gen.render_sections(sections, lab="goad-light", surface={"mssql_impersonation"})
    assert len(kept) == 1
    assert len(dropped) == 1 and "mssql_linked" in dropped[0]


def test_any_one_named_technique_satisfies_a_marker():
    sections = [("Step", "## Step\n<!-- lab-requires: esc1, esc4 -->\n\nbody\n")]
    kept, _ = gen.render_sections(sections, lab="goad-light", surface={"esc1"})
    assert len(kept) == 1


def test_lab_only_material_reaches_only_that_lab():
    sections = [("ESC1", "## ESC1\n<!-- lab-only: goad-light -->\n\nbody\n")]
    kept, dropped = gen.render_sections(sections, lab="goad-light", surface=set())
    assert len(kept) == 1
    kept, dropped = gen.render_sections(sections, lab="goad-mini", surface=set())
    # Another lab's material is absent, not "removed": it was never owed here.
    assert not kept and not dropped


def test_markers_never_reach_the_reader():
    sections = [("Step", "## Step\n<!-- lab-requires: esc1 -->\n<!-- lab-only: goad-light -->\n\nbody\n")]
    kept, _ = gen.render_sections(sections, lab="goad-light", surface={"esc1"})
    assert "lab-requires" not in kept[0] and "lab-only" not in kept[0]


def test_links_to_a_part_this_lab_lacks_go_to_the_source_series():
    """A sibling link to a part the lab never generated would 404."""
    out = gen.retarget_links(
        "see [part 6](part-06-adcs.md#step-2) and [part 1](part-01-recon.md)",
        present={"part-01-recon.md"},
    )
    assert "](../goad/part-06-adcs.md#step-2)" in out
    assert "](part-01-recon.md)" in out


def test_host_and_domain_names_are_usable_as_requirements():
    """ESC4 is modelled as an ACL, not a vuln id, so the only honest way to gate
    it is by the host that carries it."""
    targets = gen.lab_targets(_template("goad"))
    assert {"meereen", "braavos", "essos"} <= targets
    assert "meereen" not in gen.lab_targets(_template("goad-light"))


# ------------------------------------------------ the generator deletes files ---
#
# `--check` is solid: an edited part, a deleted part, a stale extra, a vanished
# source series and a missing output folder were each tried and each failed
# loudly. The write path was the gap. It reported only what it WROTE, so a run
# that removed five committed parts because the surface had quietly shrunk looked
# exactly like an ordinary run, and exited 0.

import io
import shutil


def _sandbox(tmp_path, monkeypatch, lab="goad-light"):
    """Copies of the source series, the templates and one lab's output."""
    shutil.copytree(ROOT / "docs/solutions/goad", tmp_path / "goad")
    shutil.copytree(ROOT / "frontend/public/goad", tmp_path / "tpl")
    shutil.copytree(ROOT / f"docs/solutions/{lab}", tmp_path / lab)
    monkeypatch.setattr(gen, "SOURCE_DIR", tmp_path / "goad")
    monkeypatch.setattr(gen, "SOLUTIONS_DIR", tmp_path)
    monkeypatch.setattr(gen, "TEMPLATE_DIR", tmp_path / "tpl")
    return tmp_path / lab


def test_an_empty_surface_is_refused_before_anything_is_deleted(tmp_path, monkeypatch, capsys):
    """A renamed overlay key looks exactly like this from inside the generator.

    Every shipped lab reaches at least two techniques, so an empty surface is an
    input problem and never a shape. It has to be caught BEFORE the delete, not
    reported after it.
    """
    out = _sandbox(tmp_path, monkeypatch)
    before = sorted(p.name for p in out.glob("part-*.md"))
    monkeypatch.setattr(gen, "lab_surface", lambda t: set())
    monkeypatch.setattr(gen, "lab_targets", lambda t: set())

    assert gen.generate("goad-light", check=False) == 2
    assert sorted(p.name for p in out.glob("part-*.md")) == before, (
        "the refusal must not have deleted anything")
    assert "empty" in capsys.readouterr().err


def test_the_floor_is_the_surface_and_not_the_part_count(tmp_path, monkeypatch):
    """Why the guard is written against the surface.

    A part carrying no marker is kept for every lab on purpose, so with the
    surface emptied entirely four parts still render and a part-count floor
    never trips. Tried that way first, and it let nine files go.
    """
    _sandbox(tmp_path, monkeypatch)
    monkeypatch.setattr(gen, "lab_surface", lambda t: set())
    monkeypatch.setattr(gen, "lab_targets", lambda t: set())
    sources = sorted(p for p in gen.SOURCE_DIR.iterdir() if gen.PART_FILE.match(p.name))
    kept = [s for s in sources if gen.render_part(s, "goad-light", set()) is not None]
    assert kept, "a part-count floor would never trip, which is the point"


def test_removing_a_part_is_reported_by_name(tmp_path, monkeypatch, capsys):
    """Removal is a legitimate outcome: filtering goad-mini on lab shape
    correctly took it from 14 parts to 5. So this is not refused, it is said.
    A run that only reports what it wrote hides the half that matters."""
    out = _sandbox(tmp_path, monkeypatch)
    doomed = out / "part-99-not-generated-any-more.md"
    doomed.write_text("stale", encoding="utf-8")

    assert gen.generate("goad-light", check=False) == 0
    assert not doomed.exists()
    err = capsys.readouterr().err
    assert "removed 1 file(s)" in err and doomed.name in err, err


def test_an_ordinary_run_says_nothing_about_removals(tmp_path, monkeypatch, capsys):
    """The notice has to be silent when nothing went, or it is noise that gets
    ignored on the run that matters."""
    _sandbox(tmp_path, monkeypatch)
    assert gen.generate("goad-light", check=False) == 0
    assert "removed" not in capsys.readouterr().err
