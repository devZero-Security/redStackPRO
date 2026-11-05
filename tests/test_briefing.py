"""The range briefing joins the document (users, domains, trusts, attack paths)
with the terraform address tokens into one operator hand-off. See briefing.py."""

import json
import re
from pathlib import Path

from redstackpro.authoring import set_redirector_hostname
from redstackpro.briefing import range_briefing
from redstackpro.export import compile_topology
from redstackpro.registry import Registry
from shipped import load

ROOT = Path(__file__).resolve().parent.parent


def _goad():
    return json.loads(
        (ROOT / "frontend/public/goad/goad.json").read_text(encoding="utf-8"))


def test_offense_briefing_gives_the_c2_payload_recipe():
    """A beacon needs the callback domain, the gating header, and each teamserver's
    URI prefix to reach a front door. The briefing must carry all three, and the
    gating value it prints has to be the SAME one the Ansible host_vars gate on, or
    a payload built from the briefing would be turned away as an intruder."""
    doc = json.loads(
        (ROOT / "frontend/public/redstack.json").read_text(encoding="utf-8"))
    set_redirector_hostname(doc, "c2.acmecorp.net")
    files = compile_topology(doc, Registry(), provider="gcp")
    md = [v for k, v in files.items() if k.endswith("OFFENSE-BRIEFING.md")][0]

    assert "## C2 redirectors & payloads" in md
    assert re.search(r"Callback domain:\*\* `c2\.acmecorp\.net`", md), md
    m = re.search(r"Gating header:\*\* `([^:]+): ([^`]+)`", md)
    assert m, "the briefing states no gating header"
    header_name, token = m.group(1), m.group(2)
    assert header_name == "X-Request-Id"
    # A route line, with the ready-to-call URL for a teamserver prefix.
    assert re.search(r"call `https://c2\.acmecorp\.net/[^`]+/\.\.\.`", md)

    # The value in the briefing is the value the redirector and its teamservers gate
    # on: same token everywhere, or the recipe is wrong.
    gated = [v for k, v in files.items()
             if "host_vars" in k and "header_value" in v]
    assert gated, "no host_vars carried a gating value"
    for contents in gated:
        assert token in contents


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


def _goad_light_briefing(provider, doc=None):
    doc = doc or load(ROOT / "frontend/public/goad/goad-light.json")
    files = compile_topology(doc, Registry(), provider=provider)
    return files["DEFENSE-BRIEFING.md"]


def _host_row(md, host):
    return next(line for line in md.splitlines() if line.startswith("| %s |" % host))


def test_the_edr_column_does_not_claim_defender_is_on_when_it_is_off():
    """edr: defender is a label. Defender real-time protection runs only when
    defender_enabled is set, so a row that says plain "defender" overstated it."""
    doc = load(ROOT / "frontend/public/goad/goad-light.json")
    md = _goad_light_briefing("gcp", doc)
    assert _host_row(md, "winterfell").rstrip().endswith("| defender (off) |")
    assert _host_row(md, "castelblack").rstrip().endswith("| none |")

    for n in doc["nodes"]:
        if n["id"] == "winterfell":
            n["overlay"]["defender_enabled"] = True
    md = _goad_light_briefing("gcp", doc)
    assert _host_row(md, "winterfell").rstrip().endswith("| defender |")


def test_vulns_the_provider_drops_are_marked_not_listed_as_planted():
    """The poisoning family needs a real L2 domain, so a cloud compile drops it
    (VULN_PROVIDERS). The briefing used to list it as planted anyway."""
    md = _goad_light_briefing("gcp")
    line = next(l for l in md.splitlines() if l.startswith("- **winterfell** host vulns"))
    for vuln in ("llmnr_poisoning", "nbtns_poisoning", "responder", "ntlm_relay"):
        assert "%s (not on gcp)" % vuln in line, line
    assert "autologon," in line and "autologon (not" not in line

    md = _goad_light_briefing("proxmox")
    line = next(l for l in md.splitlines() if l.startswith("- **winterfell** host vulns"))
    assert "(not on" not in line
    assert "llmnr_poisoning" in line


def test_the_briefing_lists_who_each_bot_runs_as():
    import json
    from pathlib import Path
    from redstackpro.briefing import range_briefing
    root = Path(__file__).resolve().parent.parent
    doc = json.loads((root / "frontend/public/goad/goad-light.json").read_text(encoding="utf-8"))
    text = range_briefing(doc, provider="azure")
    section = text[text.index("## User activity"):]
    assert r"| winterfell | logon bot (connect_bot) | north\robb.stark |" in section
    logon = next(l for l in section.splitlines() if "logon bot (connect_bot)" in l)
    assert logon.endswith("| 3 min |"), logon
    # Broadcast poisoning bots cannot plant on a cloud provider, and say so.
    assert r"| winterfell | share-browsing bot (responder_bot) | north\robb.stark | not planted on azure |" in section
    assert "saved credential" in section


def test_the_briefing_shows_the_logon_bot_interval_set():
    import json
    from pathlib import Path
    from redstackpro.briefing import range_briefing
    root = Path(__file__).resolve().parent.parent
    doc = json.loads((root / "frontend/public/goad/goad-light.json").read_text(encoding="utf-8"))
    winterfell = next(n for n in doc["nodes"] if n["id"] == "winterfell")
    winterfell["overlay"]["vulns_vars"]["bot_interval_minutes"] = 10
    text = range_briefing(doc, provider="gcp")
    logon = next(l for l in text.splitlines() if "logon bot (connect_bot)" in l)
    assert logon.endswith("| 10 min |"), logon


_SIGNIN_ROW = ("| fr-wks01 | console sign-in | FREIGHT\\dana.brooks | signed in at the "
               "console at boot, so its scheduled tasks run | at boot |")


def _harbor(edit=None):
    doc = json.loads((ROOT / "frontend/public/harbor.json").read_text(encoding="utf-8"))
    wks = next(n for n in doc["nodes"] if n["id"] == "fr-wks01")
    if edit:
        edit(wks["overlay"])
    return doc


def test_a_windows_10_workstation_lists_its_console_signin_where_it_boots_a_client():
    """Windows 10 and 11 run a user's scheduled tasks only after a console
    sign-in, so the role signs the stored credential's owner in at boot."""
    for provider in ("azure", "proxmox", "esxi"):
        md = range_briefing(_harbor(), provider=provider)
        assert _SIGNIN_ROW in md[md.index("## User activity"):], provider
    md = range_briefing(_harbor(lambda ov: ov.update(os="windows_11")), provider="azure")
    assert _SIGNIN_ROW in md


def test_no_console_signin_where_the_workstation_boots_a_server():
    # GCP and AWS boot Server 2022 for windows_10 (CAP005).
    for provider in ("gcp", "aws"):
        md = range_briefing(_harbor(), provider=provider)
        assert "saved credential" in md and "console sign-in" not in md, provider
    md = range_briefing(_harbor(lambda ov: ov.update(os="windows_server_2022")), provider="azure")
    assert "saved credential" in md and "console sign-in" not in md


def test_no_console_signin_without_a_user_task_or_with_the_autologon_vuln():
    md = range_briefing(_harbor(lambda ov: ov.update(vulns=["smbv1"])), provider="azure")
    assert "console sign-in" not in md
    md = range_briefing(_harbor(lambda ov: ov["vulns"].append("autologon")), provider="azure")
    assert "saved credential" in md and "console sign-in" not in md


def test_a_poisoning_bot_the_provider_drops_needs_no_console_signin():
    from redstackpro.briefing import console_signin_user
    overlay = {"os": "windows_10", "vulns": ["responder"],
               "vulns_vars": {"bot_user": "north\\jon.snow"}}
    assert console_signin_user(overlay, "azure") is None
    assert console_signin_user(overlay, "esxi") == "north\\jon.snow"

