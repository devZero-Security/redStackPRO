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
    for heading in ("Defense Briefing", "## The access model", "## Access",
                    "## Credentials", "## Hosts", "## Domains & trusts",
                    "## Domain users", "## Planted attack surface"):
        assert heading in md
    # The external red team POV is stated up front, and patient zero (the
    # assumed_breach foothold, hodor in GOAD) is named as the entry identity.
    assert "external red team POV" in md
    assert "Patient zero" in md
    assert "Assumed-breach foothold" in md and "hodor" in md
    # Access + credentials.
    assert "/guacamole" in md
    assert "terraform output -raw lab_password" in md
    # Addresses are tokens tf_inventory fills after apply.
    assert "<<tf:def-jumpbox:public_address>>" in md
    assert "<<tf:def-kingslanding:private_address>>" in md
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


def test_briefing_filename_is_mode_specific():
    # A defense range emits DEFENSE-BRIEFING.md; an offense stack emits OFFENSE-BRIEFING.md.
    # The old fixed RANGE-BRIEFING.md name is gone from both.
    files = compile_topology(_goad(), Registry(), provider="aws")
    assert "DEFENSE-BRIEFING.md" in files
    assert "Defense Briefing" in files["DEFENSE-BRIEFING.md"]
    assert "RANGE-BRIEFING.md" not in files

    redstack = load(ROOT / "frontend/public/redstack.json")
    ops_files = compile_topology(redstack, Registry(), provider="aws")
    assert "OFFENSE-BRIEFING.md" in ops_files
    assert "Offense Briefing" in ops_files["OFFENSE-BRIEFING.md"]
    assert "Range Briefing" not in ops_files["OFFENSE-BRIEFING.md"]
    assert "DEFENSE-BRIEFING.md" not in ops_files


# -- the offense operators / VPN access section

def _offense_with_operators(access_mode=None, operators=None, **vpn):
    doc = json.loads(
        (ROOT / "frontend/public/redstack.json").read_text(encoding="utf-8"))
    for n in doc["nodes"]:
        if n["kind"] == "jumpbox":
            ov = n.setdefault("overlay", {})
            if access_mode:
                ov["access_mode"] = access_mode
            ov.update(vpn)
            if operators is not None:
                ov["operators"] = operators
    return doc


def test_briefing_lists_each_operator_and_their_wireguard_credential():
    md = range_briefing(_offense_with_operators(
        access_mode="wireguard",
        operators=[{"handle": "alice"}, {"handle": "bob", "role": "lead"}]))
    assert "## Operators & VPN access" in md
    assert "wireguard" in md
    # The endpoint is the jumpbox public address token, filled at apply.
    assert "public_address>>:51820/udp" in md
    # Each operator: a portal account and a personal WireGuard config to fetch.
    assert "| alice |" in md and "`/opt/redstackpro/vpn/alice.conf`" in md
    assert "| bob |" in md and "lead" in md
    assert "scp" in md and "<handle>.conf" in md


def test_briefing_openvpn_uses_the_custom_port_protocol_and_ovpn_extension():
    md = range_briefing(_offense_with_operators(
        access_mode="openvpn", vpn_protocol="tcp", vpn_port=5124,
        operators=[{"handle": "carol"}]))
    assert "public_address>>:5124/tcp" in md
    assert "`/opt/redstackpro/vpn/carol.ovpn`" in md


def test_briefing_omits_the_operator_section_without_vpn_or_roster():
    """A plain offense stack (no access_mode, no operators) gets no section, the
    same as before the feature."""
    md = range_briefing(_offense_with_operators(operators=[]))
    assert "## Operators & VPN access" not in md
