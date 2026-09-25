"""The range briefing joins the document (users, domains, trusts, attack paths)
with the terraform address tokens into one operator hand-off. See briefing.py."""

import json
from pathlib import Path

from redstackpro.briefing import range_briefing
from redstackpro.export import compile_topology
from redstackpro.registry import Registry
from shipped import load

ROOT = Path(__file__).resolve().parent.parent


def _goad():
    return json.loads(
        (ROOT / "frontend/public/goad/goad.json").read_text(encoding="utf-8"))


def test_briefing_covers_boxes_accounts_users_trusts_and_siem():
    md = range_briefing(_goad())
    # The sections a hand-off needs.
    for heading in ("Range Briefing", "## The access model", "## Access",
                    "## Credentials", "## Hosts", "## Domains & trusts",
                    "## Domain users", "## Planted attack surface"):
        assert heading in md
    # The external red-team POV is stated up front (P0.2), and patient zero (the
    # assumed_breach foothold, hodor in GOAD) is named as the entry identity.
    assert "external red-team POV" in md
    assert "Patient zero" in md
    assert "Assumed-breach foothold" in md and "hodor" in md
    # Access + credentials.
    assert "/guacamole" in md
    assert "terraform output -raw lab_password" in md
    # Addresses are tokens tf_inventory fills after apply.
    assert "<<tf:cyb-jumpbox:public_address>>" in md
    assert "<<tf:cyb-kingslanding:private_address>>" in md
    # The lab's substance: a controller, a domain, a user from the cast, a trust,
    # and the ACL attack chain.
    assert "Domain Controller" in md
    assert "sevenkingdoms.local" in md
    assert "tywin.lannister" in md
    assert "parent_child" in md or "forest" in md
    assert "ACL chains" in md


def test_briefing_states_the_password_the_dc_role_actually_seeds():
    """The briefing is the hand-off a user follows, so its password column has to
    match what the dc role seeds (main.yml: item.password | default(lab)), not a
    guess from the flaw list. A prior version printed a hardcoded 'Summer2024!'
    for any kerberoastable/asrep account and 'lab password' for everyone else,
    so it misstated every declared credential -- including hodor, the patient
    zero a reader logs in as."""
    md = range_briefing(_goad())

    # A declared password is shown verbatim: hodor is the entry identity, and
    # brandon.stark's asrep hash cracks to exactly this in the solution.
    assert "| hodor |" in md
    hodor_row = next(line for line in md.splitlines() if "| hodor |" in line)
    assert "`hodor`" in hodor_row
    assert "lab password" not in hodor_row

    brandon_row = next(line for line in md.splitlines()
                       if "| brandon.stark |" in line)
    assert "`iseedeadpeople`" in brandon_row

    # The stale hardcoded fallback must not appear for an account that declares a
    # real password. GOAD declares one for every flagged user, so it should be
    # absent entirely here.
    assert "Summer2024!" not in md


def test_briefing_is_emitted_for_a_range_not_for_ops():
    files = compile_topology(_goad(), Registry(), provider="aws")
    assert "RANGE-BRIEFING.md" in files
    assert "Range Briefing" in files["RANGE-BRIEFING.md"]

    redstack = load(ROOT / "frontend/public/redstack.json")
    ops_files = compile_topology(redstack, Registry(), provider="aws")
    assert "RANGE-BRIEFING.md" not in ops_files
