"""Native Ansible generation for a defensive (AD) range.

A defend range compiles through the same native pipeline as an attack range, not
a GOAD package: the controllers, domains, trusts, groups, and users are stood up
by redStackPRO's own roles over psrp. These assert the parts that exist nowhere
else and would fail silently at deploy if they drifted. See
goad-native-recreation.
"""

import json
from pathlib import Path

import pytest
import yaml

from redstackpro.ansible import generate

ROOT = Path(__file__).resolve().parent.parent
GOAD_LIGHT = json.loads(
    (ROOT / "frontend/public/goad/goad-light.json").read_text(encoding="utf-8"))
GOAD_FULL = json.loads(
    (ROOT / "frontend/public/goad/goad.json").read_text(encoding="utf-8"))
DRACARYS = json.loads(
    (ROOT / "frontend/public/goad/dracarys.json").read_text(encoding="utf-8"))
HARBOR = json.loads(
    (ROOT / "frontend/public/harbor.json").read_text(encoding="utf-8"))
HOST_VULNS_IMPLEMENTED = yaml.safe_load(
    (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.host_vulns"
            "/defaults/main.yml").read_text(encoding="utf-8")
)["redstackpro_host_vulns_implemented"]


def _files():
    return generate(GOAD_LIGHT)


def test_assumed_breach_user_becomes_a_jumpbox_foothold():
    """A domain user flagged assumed_breach (GOAD's hodor) is threaded to the
    jumpbox as a foothold account, so the jumpbox role creates it as a local
    admin patient-zero can SSH in as. It stays a low-priv domain member on the
    dc side. See range-access-model and P2.5."""
    files = generate(GOAD_FULL)
    jb = yaml.safe_load(files["ansible/host_vars/hvn-jumpbox.yml"])
    assert "hodor" in (jb.get("redstackpro_jumpbox_foothold_users") or [])


def test_local_admin_users_are_added_to_member_administrators():
    """A domain user flagged privilege: local_admin (dracarys's rhaegal) is
    threaded to the Windows member servers of its own domain as DOMAIN\\user, so
    the srv role adds it to local Administrators -- rhaegal must be able to log on
    to vhagar for the keepass_bot CredSSP hop to run there. The DC itself gets no
    such list. See dracarys-fidelity-gap."""
    files = generate(DRACARYS)
    vhagar = yaml.safe_load(files["ansible/host_vars/hvn-vhagar.yml"])
    assert "DRACARYS\\rhaegal" in (vhagar.get("redstackpro_srv_local_admins") or [])
    # The DC is not a member server and carries no local-admin injection.
    balerion = yaml.safe_load(files["ansible/host_vars/hvn-balerion.yml"])
    assert "redstackpro_srv_local_admins" not in balerion


def test_privilege_maps_to_the_built_in_admin_group():
    """A user's privilege names the built-in group the directory must actually
    grant: domain_admin -> Domain Admins, enterprise_admin -> Enterprise Admins.
    The dc role honours a user's `groups`, not the `privilege` field, so the
    compiler folds the mapped group in. harbor relies on this: eric.vance (child
    DA) and roland.hale (forest EA) carry only the privilege and no explicit group,
    so without the mapping they would deploy unprivileged and the chain would
    dead-end. A plain user gets no privileged group."""
    files = generate(HARBOR)
    freight = yaml.safe_load(files["ansible/vars/domains/freight.harbor.corp.yml"])
    eric = next(u for u in freight["users"] if u["username"] == "eric.vance")
    assert "Domain Admins" in eric["groups"]
    dana = next(u for u in freight["users"] if u["username"] == "dana.brooks")
    assert "Domain Admins" not in (dana.get("groups") or [])
    harbor = yaml.safe_load(files["ansible/vars/domains/harbor.corp.yml"])
    roland = next(u for u in harbor["users"] if u["username"] == "roland.hale")
    assert "Enterprise Admins" in roland["groups"]


def test_a_workstation_grants_patient_zero_rdp():
    """A workstation is the usual patient-zero landing host, and its portal tile
    signs in as the assumed-breach user. The compiler emits redstackpro_srv_rdp_users
    for the landing host of either kind, but only the srv role consumed it, so a
    patient zero on a workstation was refused RDP (dana.brooks on harbor's fr-wks01
    hit exactly this live). The wks role must apply it too. See range-access-model."""
    wks = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.wks"
           "/tasks/main.yml").read_text(encoding="utf-8")
    assert "redstackpro_srv_rdp_users" in wks
    assert "Remote Desktop Users" in wks


def test_endpoint_telemetry_toggle_reaches_the_host():
    """A host with endpoint_telemetry set gets redstackpro_endpoint_telemetry so
    the host_vulns role installs Sysmon + command-line auditing; a host without it
    does not. goad-wazuh opts its Wazuh-monitored hosts in. See F-wazuh-telemetry."""
    files = generate(json.loads(
        (ROOT / "frontend/public/goad/goad-wazuh.json").read_text(encoding="utf-8")))
    wint = yaml.safe_load(files["ansible/host_vars/hvn-winterfell.yml"])
    assert wint.get("redstackpro_endpoint_telemetry") is True
    ws01 = yaml.safe_load(files["ansible/host_vars/hvn-ws01.yml"])
    assert "redstackpro_endpoint_telemetry" not in ws01


def test_dracarys_vault_and_bots_are_faithful():
    """The dracarys chain: vhagar generates a KeePass vault (keepass_vault) and
    runs a real SSH bot to syrax; balerion runs a CredSSP keepass_bot and serves
    LDAPS. These make the challenge's credential-exposure path real rather than a
    hollow stand-in. See dracarys-fidelity-gap."""
    files = generate(DRACARYS)
    vhagar = yaml.safe_load(files["ansible/host_vars/hvn-vhagar.yml"])
    assert "keepass_vault" in (vhagar.get("redstackpro_srv_vulns") or [])
    bot = vhagar["redstackpro_srv_vulns_vars"]["schedule"]["script_content"]
    assert "plink" in bot and "syrax" in bot
    balerion = yaml.safe_load(files["ansible/host_vars/hvn-balerion.yml"])
    assert "ldaps" in (balerion.get("redstackpro_dc_vulns") or [])
    kb = balerion["redstackpro_dc_vulns_vars"]["schedule"]["script_content"]
    assert "Credssp" in kb and "vhagar" in kb


def test_the_jumpbox_accepts_keys_only_even_for_patient_zero():
    """Key-only sshd with NO exception for the foothold accounts. This inverts an
    earlier rule: patient zero used to hold a password and a trailing Match block
    re-enabled password auth for it, because the briefing said to SSH in as
    patient zero. Since 2026-09-10 the portal is the way in and the foothold is
    reached through an RDP tile, so that exception was a password-authenticating
    account on the internet with nothing depending on it. Guarding the inversion
    matters because restoring it looks like a fix. See range-access-model."""
    tpl = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.jumpbox"
                  "/templates/sshd-redstackpro.conf.j2").read_text(
        encoding="utf-8")
    assert "PasswordAuthentication no" in tpl
    assert "PasswordAuthentication yes" not in tpl
    # A Match block is how the exception would come back: everything after one
    # belongs to it, so a stray Match would also silently scope AllowUsers.
    assert "Match User" not in tpl
    assert "AllowUsers" in tpl


JUMPBOX_ROLE = (ROOT / "src/redstackpro/assets/ansible/roles"
                       "/redstackpro.jumpbox")


def test_the_portal_seeds_a_database_not_a_file():
    """ADR 0056: the portal moved off the read-only file provider onto a JDBC
    database, because named accounts and per-user TOTP both need writable user
    records. The file template is gone and its logic is SQL now. These guard the
    pieces that would fail silently: the seed still exists, the service stands up
    postgres, and the retired template did not linger to be mounted alongside the
    new backend and confuse which login is real."""
    assert not (JUMPBOX_ROLE / "templates/user-mapping.xml.j2").exists()
    service = (JUMPBOX_ROLE / "tasks/service-guacamole.yml").read_text(
        encoding="utf-8")
    assert "POSTGRESQL_HOSTNAME" in service
    assert "guacamole-seed.sql.j2" in service
    # The schema load is guarded on an empty database, or a re-run wipes the
    # account and TOTP state the volume exists to keep.
    assert "to_regclass" in service


def test_the_seed_sql_is_safe_and_idempotent():
    """The seed's two halves have to behave differently and both matter for
    security. Accounts are created-if-absent so a re-run cannot reset a password
    or wipe a TOTP enrollment; connections are rebuilt so the topology stays the
    truth. A break-glass admin always exists, and the stock guacadmin/guacadmin
    default -- a well-known credential on the one public host -- is removed."""
    seed = (JUMPBOX_ROLE / "templates/guacamole-seed.sql.j2").read_text(
        encoding="utf-8")
    # The stock default admin is deleted unless it is deliberately ours.
    assert "DELETE FROM guacamole_entity WHERE name = 'guacadmin'" in seed
    # Break-glass admin is the operator, unconditionally.
    assert "redstackpro_guac_operator" in seed
    # Accounts are created-if-absent (a real password/TOTP survives a re-run);
    # connections are rebuilt (the topology reconciles).
    assert "NOT EXISTS (SELECT 1 FROM guacamole_user" in seed
    assert "DELETE FROM guacamole_connection;" in seed
    # The password is hashed the way guacamole hashes: sha256 over the password
    # plus the uppercase hex salt. A plaintext insert would lock everyone out.
    assert "digest(" in seed and "upper(encode(" in seed
    # pgcrypto is not on by default in the stock image.
    assert "CREATE EXTENSION IF NOT EXISTS pgcrypto" in seed


def _render_guac_seed(hostvars):
    """Render the real template with a fabricated inventory, StrictUndefined so a
    missing var fails loud rather than falling through to the wrong branch.
    Jinja is a test convenience here; Ansible renders this in production."""
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(JUMPBOX_ROLE / "templates")),
        autoescape=False,
        undefined=jinja2.StrictUndefined,
    )
    return env.get_template("guacamole-seed.sql.j2").render(
        ansible_managed="test",
        redstackpro_guac_operator="redop",
        redstackpro_guac_password="labpw",
        redstackpro_jumpbox_user="redop",
        redstackpro_guac_ssh_key="fake-key",
        inventory_hostname="art-jump-bx01",
        groups={"all": ["art-jump-bx01"] + list(hostvars)},
        hostvars=hostvars,
    )


def test_a_desktop_kali_operator_gets_an_rdp_tile_not_ssh():
    """The rdp-vs-ssh branch used to gate on psrp or operator_os == windows, which
    left a desktop:true Kali operator on the ssh branch with no way to reach its
    xrdp session. See CAR008 and overlay_operator.desktop."""
    seed = _render_guac_seed({
        "art-kali-op01": {
            "ansible_host": "10.20.0.5",
            "redstackpro_operator_os": "kali",
            "redstackpro_operator_desktop": True,
        },
        "art-ssh-op01": {
            "ansible_host": "10.20.0.6",
            "redstackpro_operator_os": "kali",
        },
    })
    assert "-- art-kali-op01 (rdp)" in seed
    assert "-- art-ssh-op01 (ssh)" in seed
    # The rdp tile for the GUI operator, not just any rdp tile in the file.
    gui_tile = seed.split("-- art-kali-op01 (rdp)")[1].split("-- art-ssh-op01")[0]
    assert "'rdp'" in gui_tile
    assert "'3389'" in gui_tile


def test_patient_zero_gets_a_portal_tile_on_one_landing_host():
    """The portal is how an operator enters a range, so patient zero needs a tile
    that signs in AS patient zero -- every other tile is the operator, and a
    beacon launched from one of those starts the engagement holding the wrong
    token. Three things have to agree: the compiler picks one landing host per
    breach domain, that host lets p0 log on over RDP, and the tile carries the
    credential the dc role actually seeded. See range-access-model."""
    out = generate(GOAD_FULL)
    jumpbox = yaml.safe_load(out["ansible/host_vars/hvn-jumpbox.yml"])
    tiles = jumpbox["redstackpro_jumpbox_foothold_tiles"]
    # GOAD's patient zero is hodor, a NORTH domain member with a declared
    # password. The declared password must win: falling back to the shared lab
    # password here would produce a tile that cannot log in.
    assert [t["username"] for t in tiles] == ["hodor"]
    assert tiles[0]["domain"] == "NORTH"
    assert tiles[0]["password"] == "hodor"

    # Exactly one landing host, and it is a member rather than the domain
    # controller -- signing a Domain Users member in interactively on a DC is not
    # the shape being modelled.
    landing = tiles[0]["host"]
    assert landing != "hvn-winterfell"
    host = yaml.safe_load(out["ansible/host_vars/%s.yml" % landing])
    assert host["redstackpro_srv_rdp_users"] == ["NORTH\\hodor"]

    # Remote Desktop Users, not Administrators. Making p0 a local admin on the
    # landing host would hand away the first half of the solution.
    others = [n for n in out
              if n.startswith("ansible/host_vars/")
              and n != "ansible/host_vars/%s.yml" % landing
              and "redstackpro_srv_rdp_users" in (yaml.safe_load(out[n]) or {})]
    assert not others, "p0 should land on one host, not %s" % others
    assert "NORTH\\hodor" not in (host.get("redstackpro_srv_local_admins") or [])


def test_every_host_is_named_for_a_hosts_file():
    """Every host carries a canvas-name alias (redstackpro_host_shortname) so the
    hosts-file play can name it, and an AD host also carries its FQDN -- what lets
    Kerberos resolve a KDC over a SOCKS pivot and mirrors mayfly's hardcoded
    /etc/hosts. The address itself stays a placeholder in ansible_host; only the
    names come from the topology.

    The recipient of the block is any host that does NOT join a domain: the
    jumpbox gets it (and so carries no FQDN of its own, only the alias); the AD
    members are excluded from the play because they resolve through the DCs'
    DNS. See range-access-model and the /etc/hosts PAI item."""
    out = generate(GOAD_FULL)
    wint = yaml.safe_load(out["ansible/host_vars/hvn-winterfell.yml"])
    assert wint["redstackpro_host_fqdn"] == "winterfell.north.sevenkingdoms.local"
    assert wint["redstackpro_host_shortname"] == "winterfell"
    # A member resolves to the domain it joins, not a forest-root guess.
    cb = yaml.safe_load(out["ansible/host_vars/hvn-castelblack.yml"])
    assert cb["redstackpro_host_fqdn"] == "castelblack.north.sevenkingdoms.local"
    # The jumpbox is not an AD host: it carries the alias but no FQDN, and it
    # is a recipient of the block (it does not join a domain).
    jb = yaml.safe_load(out["ansible/host_vars/hvn-jumpbox.yml"])
    assert jb["redstackpro_host_shortname"] == "jumpbox"
    assert "redstackpro_host_fqdn" not in jb
    site = out["ansible/site.yml"]
    assert "Map hosts by name (Linux, non-domain-joined)" in site
    # A pure GOAD has no standalone Windows host, so no Windows hosts play: its
    # Windows hosts are all AD members that resolve through DNS. The Windows play
    # only appears when a range carries a non-joined Windows box.
    assert "Map hosts by name (Windows, non-domain-joined)" not in site
    # Linux edits /etc/hosts as root; the recipient pattern drops the Windows
    # hosts AND every AD group present (dc/srv/wks), so what remains is the
    # standalone Linux hosts -- the jumpbox above all, which the operator enters
    # by. GOAD-full has controllers and servers but no separate workstations.
    assert "hosts: all:!windows:!domain_controllers:!servers\n" in site
    # win_lineinfile is in community.windows, NOT ansible.windows -- the wrong
    # collection is a parse-time module-resolution error that fails the whole
    # site.yml, which a live deploy caught. Guard the collection name.
    hosts_role = (JUMPBOX_ROLE.parent / "redstackpro.hosts/tasks/main.yml").read_text(
        encoding="utf-8")
    assert "community.windows.win_lineinfile" in hosts_role
    assert "ansible.windows.win_lineinfile" not in hosts_role


def test_host_vuln_building_blocks_are_wired():
    """disable_firewall / directory / files (GOAD's host building blocks, P9)
    are real host_vulns roles now, not notes: each has a task file and is in the
    implemented list (so main.yml dispatches it). Catalog membership is guarded
    on the frontend by vulns.test.mjs. See goad-fidelity-build."""
    role = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.host_vulns"
    for v in ("disable_firewall", "directory", "files"):
        assert v in HOST_VULNS_IMPLEMENTED, v
        assert (role / f"tasks/{v}.yml").exists(), v


def test_defender_off_by_default_and_opts_in_per_host():
    """Windows Defender RTP is off by default (no redstackpro_defender_enabled
    in a host's vars) -- even on GOAD's DCs, which carry edr=defender, so the
    two are independent. A host with the defender_enabled overlay toggle set
    (a defended range) gets redstackpro_defender_enabled true. See PZ-5 / P0.2."""
    import copy
    files = generate(GOAD_FULL)
    kl = yaml.safe_load(files["ansible/host_vars/hvn-kingslanding.yml"])
    assert kl.get("redstackpro_defender_enabled") in (None, False)
    g = copy.deepcopy(GOAD_FULL)
    for n in g["nodes"]:
        if n["id"] == "kingslanding":
            n.setdefault("overlay", {})["defender_enabled"] = True
    kl2 = yaml.safe_load(
        generate(g)["ansible/host_vars/hvn-kingslanding.yml"])
    assert kl2.get("redstackpro_defender_enabled") is True


def test_range_connects_as_the_blueop_account():
    """A defensive range's single platform account is blueop (P1.7): the SSH /
    admin identity every host authorizes, emitted as the group-wide ansible_user."""
    files = generate(GOAD_FULL)
    all_vars = yaml.safe_load(files["ansible/group_vars/all.yml"])
    assert all_vars["ansible_user"] == "blueop"


def test_printnightmare_kept_optin_not_declaart_on_default_dcs():
    """PrintNightmare is RETAINED as an opt-in host_vulns role (task file +
    implemented id) but is not declared on any default GOAD DC. Its live
    exploitation is patch-blocked on any fully-patched build regardless of
    provider (KB5005652 hardens the server-side RpcAddPrinterDriverEx, so
    cube0x0 fails at driver enumeration) -- a provider cannot fix that, only a
    patch-baseline image can, and that is not built yet. So unlike
    ldap_signing_off, printnightmare gets no `providers` gate and simply is not
    declared by the default templates. See goad-fidelity-build and
    current-activity-list (session 4 Part 4/5 conclusions)."""
    files = generate(GOAD_FULL)
    for dc in ("hvn-kingslanding", "hvn-winterfell", "hvn-meereen"):
        vulns = yaml.safe_load(files[f"ansible/host_vars/{dc}.yml"])[
            "redstackpro_dc_vulns"]
        assert "printnightmare" not in vulns, dc
    assert "printnightmare" in HOST_VULNS_IMPLEMENTED
    role = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.host_vulns"
    assert (role / "tasks/printnightmare.yml").exists()


def test_ldap_signing_off_is_provider_gated_to_proxmox_and_esxi():
    """ldap_signing_off IS declared on the default GOAD DCs (its relay payoff is
    a real technique, just not a cloud-viable one), but the compiler only plants
    it when compiling for a provider whose network model gives the range a real
    L2 broadcast domain. A cloud compile (no provider named, or any of
    aws/gcp/azure) silently drops it; Proxmox/ESXi keep it. See
    redstackpro.ansible.VULN_PROVIDERS and current-activity-list (provider-aware
    toggles)."""
    dcs = ("hvn-kingslanding", "hvn-winterfell", "hvn-meereen")

    def _dc_vulns(provider):
        files = generate(GOAD_FULL, provider=provider)
        return {
            dc: yaml.safe_load(files[f"ansible/host_vars/{dc}.yml"])[
                "redstackpro_dc_vulns"]
            for dc in dcs
        }

    for provider in (None, "gcp", "aws", "azure"):
        vulns = _dc_vulns(provider)
        for dc in dcs:
            assert "ldap_signing_off" not in vulns[dc], (provider, dc)

    for provider in ("proxmox", "esxi"):
        vulns = _dc_vulns(provider)
        for dc in dcs:
            assert "ldap_signing_off" in vulns[dc], (provider, dc)

    # Role file + implemented id present regardless -- the same role plants it,
    # only the compiler's provider filter decides whether it reaches the host.
    assert "ldap_signing_off" in HOST_VULNS_IMPLEMENTED
    role = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.host_vulns"
    assert (role / "tasks/ldap_signing_off.yml").exists()


def test_defender_is_off_by_default_with_an_enable_toggle():
    """Windows Defender is disabled by default (GOAD parity) via the shared
    host_vulns path, with an opt-in redstackpro_defender_enabled toggle to leave it
    on. See productize-temp-fixes (PZ-5)."""
    role = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.host_vulns"
    defaults = yaml.safe_load((role / "defaults/main.yml").read_text(encoding="utf-8"))
    assert defaults["redstackpro_defender_enabled"] is False
    assert (role / "tasks/disable_defender.yml").exists()
    main = (role / "tasks/main.yml").read_text(encoding="utf-8")
    assert "disable_defender.yml" in main
    assert "redstackpro_defender_enabled" in main


def test_essos_ca_plants_the_full_esc_template_set():
    """The essos forest CA (braavos) aggregates mayfly's ESC1/ESC2/ESC3 templates
    (declared on the essos DC) alongside the ESC6/7/11/13/15 it already carried, and
    each ESC template has a clean-room planter script. Closes the Part 6 fidelity
    delta where ESSOS-CA shipped only ESC4+ESC13. See goad-fidelity-build."""
    files = generate(GOAD_FULL)
    escs = yaml.safe_load(files["ansible/host_vars/hvn-braavos.yml"])[
        "redstackpro_adcs_forest_escs"]
    for e in ("esc1", "esc2", "esc3"):
        assert e in escs, e
    adcs_files = (ROOT / "src/redstackpro/assets/ansible/roles"
                  "/redstackpro.adcs/files")
    for e in ("esc1", "esc2", "esc3"):
        assert (adcs_files / f"plant_{e}.ps1").exists(), e


def test_linked_sql_hosts_map_a_remote_login_not_self():
    """Each GOAD SQL host with a linked server also carries a linked-login mapping
    to a fixed remote login (sa), so a domain caller crossing the trusted link does
    not double-hop to ANONYMOUS (the Part 7 finding) and the link RCE chain lands.
    See goad-fidelity-build."""
    files = generate(GOAD_FULL)
    for h in ("hvn-castelblack", "hvn-braavos"):
        vv = yaml.safe_load(files[f"ansible/host_vars/{h}.yml"])[
            "redstackpro_srv_vulns_vars"]
        targets = vv.get("mssql_linked_targets") or []
        logins = {m["target"]: m for m in (vv.get("mssql_linked_logins") or [])}
        assert targets, h
        for t in targets:
            assert t in logins, f"{h} link {t} has no login mapping"
            assert logins[t].get("remote_user") == "sa", h


def test_domains_are_not_hosts():
    """A domain is a logical container, so it never becomes an inventory host or
    a host_vars file."""
    files = _files()
    inventory = yaml.safe_load(files["ansible/inventory.yml"])
    groups = inventory["all"]["children"]
    hosts = {h for g in groups.values() for h in (g.get("hosts") or {})}
    assert not any("sevenkingdoms" in h or "north" in h for h in hosts)
    assert not any("domains/" not in p and ("sevenkingdoms" in p or "north" in p)
                   for p in files if p.startswith("ansible/host_vars/"))


def test_play_order_builds_the_forest_before_it_is_joined():
    """The jumpbox first, then controllers, then the members that join them."""
    site = yaml.safe_load(_files()["ansible/site.yml"])
    order = [p["hosts"] for p in site]
    assert order.index("jumpboxes") < order.index("domain_controllers")
    assert order.index("domain_controllers") < order.index("servers")


def test_ad_hosts_stay_in_their_play():
    """Unlike the attack side, a range's Windows hosts are the provisioning
    target, so they are not excluded from their play."""
    site = yaml.safe_load(_files()["ansible/site.yml"])
    dc_play = next(p for p in site if p["hosts"] == "domain_controllers")
    assert ":!windows" not in dc_play["hosts"]
    assert dc_play["become"] is False
    assert "redstackpro.dc" in dc_play["roles"]


def test_controller_is_reached_over_psrp_with_its_domain_file():
    files = _files()
    dc = yaml.safe_load(files["ansible/host_vars/hvn-kingslanding.yml"])
    assert dc["ansible_connection"] == "psrp"
    assert dc["redstackpro_domain_vars"] == "vars/domains/sevenkingdoms.local.yml"
    assert dc["redstackpro_join_fqdn"] == "sevenkingdoms.local"


def test_member_points_dns_at_its_controller():
    files = _files()
    member = yaml.safe_load(files["ansible/host_vars/hvn-castelblack.yml"])
    # castelblack joins north, whose controller is winterfell.
    assert member["redstackpro_join_dc_address"] == \
        "<<tf:hvn-winterfell:private_address>>"
    assert member["redstackpro_join_fqdn"] == "north.sevenkingdoms.local"


def test_child_domain_knows_its_parent_and_parent_dc():
    files = _files()
    north = yaml.safe_load(files["ansible/vars/domains/north.sevenkingdoms.local.yml"])
    assert north["forest_root"] is False
    assert north["parent_fqdn"] == "sevenkingdoms.local"
    assert north["parent_dc_address"] == "<<tf:hvn-kingslanding:private_address>>"
    root = yaml.safe_load(files["ansible/vars/domains/sevenkingdoms.local.yml"])
    assert root["forest_root"] is True
    # A parent_child trust to north is carried on the source domain.
    assert any(t["target_fqdn"] == "north.sevenkingdoms.local"
               for t in root["trusts"])


def test_lab_password_is_never_written_into_the_export():
    files = _files()
    allvars = yaml.safe_load(files["ansible/group_vars/all.yml"])
    assert allvars["redstackpro_range_admin_user"] == "Administrator"
    # A run-time lookup, not a value.
    assert "lookup('env'" in allvars["redstackpro_lab_password"]
    blob = "\n".join(files.values())
    assert "REDSTACKPRO_LAB_PASSWORD" in blob  # the env var name, never a secret


# -- the weak-password policy relax (found live on AWS)

DC_TASKS = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.dc/tasks")


def test_the_password_policy_relax_is_written_into_the_gpo():
    """GOAD's weak per-user passwords ("hodor", "Needle") are refused unless the
    domain policy is relaxed, and relaxing only the domain object is not durable:
    the Default Domain Policy GPO defines the same settings and re-asserts them on
    the next Group Policy refresh. Live on AWS that reverted, and seven users per
    domain were left as DISABLED, password-less accounts -- including hodor, the
    assumed-breach foothold. So the GPO itself must be written."""
    policy = (DC_TASKS / "password_policy.yml").read_text(encoding="utf-8")
    # The Default Domain Policy's well-known GUID, and the settings that matter.
    assert "31B2F340-016D-11D2-945F-00C04FB984F9" in policy
    assert "GptTmpl.inf" in policy
    assert "PasswordComplexity" in policy
    # Group Policy ignores a GPO whose version did not change, and the computer
    # half of versionNumber lives in the high word.
    assert "versionNumber" in policy
    assert "65536" in policy


def test_the_password_policy_relax_is_verified_not_assumed():
    """The original task hardcoded changed_when: true, so it reported success while
    the policy had reverted and the failure was invisible until a range came up with
    no foothold account. The relax must now prove itself and fail the deploy."""
    policy = (DC_TASKS / "password_policy.yml").read_text(encoding="utf-8")
    tasks = yaml.safe_load(policy)
    verify = [t for t in tasks if "Verify" in t["name"]]
    assert verify, [t["name"] for t in tasks]
    script = verify[0]["ansible.windows.win_powershell"]["script"]
    assert "throw" in script                      # fails the play, loudly
    assert "ComplexityEnabled" in script
    assert verify[0]["changed_when"] is False

    # And the relax must actually be reached: main.yml includes it, and no longer
    # carries the old fire-and-forget inline task.
    main = (DC_TASKS / "main.yml").read_text(encoding="utf-8")
    assert "include_tasks: password_policy.yml" in main
    assert "Set-ADDefaultDomainPasswordPolicy" not in main


def test_a_weak_password_flaw_never_overwrites_a_declaart_password():
    """A user's declared password IS the lab's documented credential. The
    weak_password flaw exists to make an account sprayable, which an already-weak
    declared password satisfies, so it must only fill in for an account that has
    none. Found live on minilab: this ran after user creation and replaced alice's
    "spongebob" with "superman", so the documented credential stopped working AND
    the deploy deadlocked, because stoart_credential registers a scheduled task as
    alice using the declared password."""
    paths = (DC_TASKS / "attack_paths.yml").read_text(encoding="utf-8")
    tasks = yaml.safe_load(paths)
    weak = [t for t in tasks if "weak" in t["name"].lower()]
    assert weak, [t["name"] for t in tasks]
    conditions = weak[0]["when"]
    assert isinstance(conditions, list), conditions
    # The flaw still applies, but only to an account with no password of its own.
    assert any("weak_password" in str(c) for c in conditions)
    assert any("item.password" in str(c) for c in conditions), conditions



def test_an_empty_list_or_dict_renders_explicitly_not_as_null():
    """The hand-rolled YAML renderer used to emit a bare "key:" for an empty list,
    which YAML reads as None -- and None is not an empty list. `| default([])` does
    not rescue it either, because the variable IS defined.

    Found live on goad-wazuh: ws01 declares "vulns": [], got
    redstackpro_wks_vulns: None, and the host_vulns role died with "the filter
    plugin 'ansible.builtin.intersect' failed: 'NoneType' object is not iterable",
    failing the whole play."""
    from redstackpro.ansible import _render_yaml
    rendered = _render_yaml({"empty_list": [], "empty_dict": {},
                             "full": ["a"], "scalar": "x"})
    assert "empty_list: []" in rendered
    assert "empty_dict: {}" in rendered
    parsed = yaml.safe_load(rendered)
    assert parsed["empty_list"] == []
    assert parsed["empty_dict"] == {}
    assert parsed["full"] == ["a"]


def test_a_host_declaring_no_vulns_compiles_to_an_empty_list():
    """End to end through the real compiler: goad-wazuh's ws01 declares an empty
    vulns list, and its host_vars must carry [] so the host_vulns role can
    intersect it."""
    topology = json.loads(
        (ROOT / "frontend/public/goad/goad-wazuh.json").read_text(encoding="utf-8"))
    files = generate(topology)
    ws01 = yaml.safe_load(files["ansible/host_vars/hvn-ws01.yml"])
    assert ws01["redstackpro_wks_vulns"] == []


# -- the foothold's offensive toolchain (PZ-2)

def test_a_range_jumpbox_carries_the_toolchain_by_default():
    """In a range the jumpbox IS the assumed-breach foothold the solution runs
    from, so leaving it bare would mean every operator hand-installs the same tools
    before step one."""
    files = _files()
    jb = yaml.safe_load(files["ansible/host_vars/hvn-jumpbox.yml"])
    assert jb["redstackpro_jumpbox_offensive_toolkit"] is True


def test_the_overlay_can_decline_the_toolchain():
    """It is a canvas toggle, not a mandate: a range that wants a bare foothold
    says so and the compiler does not override it."""
    topology = json.loads(json.dumps(GOAD_LIGHT))
    for node in topology["nodes"]:
        if node["kind"] == "jumpbox":
            node["overlay"]["offensive_toolkit"] = False
    jb = yaml.safe_load(
        generate(topology)["ansible/host_vars/hvn-jumpbox.yml"])
    assert jb["redstackpro_jumpbox_offensive_toolkit"] is False


def test_an_ops_jumpbox_gets_no_toolchain(redstack):
    """An ops bastion is a way through to the operator boxes, not a place to work
    from, so the tooling belongs on the kali/operator host instead."""
    files = generate(redstack)
    seen = 0
    for path, body in files.items():
        if not path.startswith("ansible/host_vars/"):
            continue
        vars_ = yaml.safe_load(body) or {}
        if vars_.get("redstackpro_kind") != "jumpbox":
            continue
        seen += 1
        assert "redstackpro_jumpbox_offensive_toolkit" not in vars_, path
    assert seen, "the ops example should have a jumpbox to check"


def test_offense_stack_names_every_host(redstack):
    """An offense stack has no domains, so every host is standalone and names
    every other by its canvas alias -- what the operator's MobaXterm sessions and
    the redirector fronting rely on. Every host carries a shortname and none
    carries an FQDN (no AD), and the Linux hosts play is emitted (the Windows
    operator is not an ansible recipient -- it has no WinRM and takes its block
    from the boot script instead). See the /etc/hosts PAI item."""
    out = generate(redstack)
    for path, body in out.items():
        if not path.startswith("ansible/host_vars/"):
            continue
        vars_ = yaml.safe_load(body) or {}
        assert vars_.get("redstackpro_host_shortname"), path
        assert "redstackpro_host_fqdn" not in vars_, path
    site = out["ansible/site.yml"]
    assert "Map hosts by name (Linux, non-domain-joined)" in site
    # No AD groups exist, so the recipient pattern is a plain all:!windows -- no
    # spurious :!domain_controllers excludes on an offense compile.
    assert "hosts: all:!windows\n" in site
    # The offense Windows operator self-provisions at boot (no WinRM), so there
    # is no ansible Windows hosts play; its /etc/hosts rides operator_setup.ps1.
    assert "Map hosts by name (Windows, non-domain-joined)" not in site


def test_each_tool_gets_its_own_python_environment():
    """coercer pins impacket<0.11 and certipy needs 0.13.x, so a shared
    site-packages forces a loser that then fails mid-solution. pipx gives each
    application its own venv. dsinternals must be INJECTED into impacket's venv,
    since ntlmrelayx imports it for the shadow-credentials path."""
    toolkit = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.jumpbox"
                      "/tasks/toolkit.yml").read_text(encoding="utf-8")
    assert "pipx install" in toolkit
    # dsinternals is injected into impacket's venv. The invocation moved from a
    # bare command to a loop when pyOpenSSL<24 joined it (the ESC8 relay pin), so
    # match on what it does -- inject impacket, with dsinternals in the set --
    # rather than on one exact command string.
    assert "pipx inject impacket" in toolkit
    assert "dsinternals" in toolkit
    for tool in ("impacket", "certipy-ad", "coercer", "bloodhound"):
        assert tool in toolkit, tool
    # nxc is deliberately absent: NetExec is not on PyPI and ships no release
    # binary, so it means rustup plus minutes of Rust compilation on every
    # deploy, on the host facing the internet, for ergonomics that
    # impacket/smbclient/ldapsearch already cover. (The rustc-version objection
    # was decisive on Debian 12 and is weaker on the Debian 13 default; the
    # build-time one is not.) The toolkit records the manual path instead.
    assert "pipx install --force git+https://github.com/Pennyw0rth" not in toolkit
    assert "rustc" not in toolkit.split("## Why nxc")[0],         "the rust toolchain existed only for nxc and should be gone with it"
    # ntlmrelayx and responder need a pty, and hashcat has no GPU here.
    assert "screen" in toolkit and "pocl-opencl-icd" in toolkit


def test_sql_install_is_judged_by_the_service_not_by_chocos_exit_code():
    """The sql-server-express package installs the engine and then deletes its
    extracted files, and that cleanup races a handle Setup still holds on
    SCENARIOENGINE.EXE: 'Access to the path is denied', choco exits -1, package
    reported failed -- with SQL Server fully installed and the service running.

    Found on a live range 2026-09-18, where it failed a deploy over a database
    that was actually there. The install task must decide on the OUTCOME: a
    missing service is a failure, a bad exit code with the service present is
    not. Same shape as everything else this pipeline learned the hard way --
    trust what happened, not what a return code claims about it.
    """
    tasks = yaml.safe_load(
        (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.mssql"
         / "tasks/main.yml").read_text(encoding="utf-8"))

    def find(name, items):
        for t in items:
            if name in (t.get("name") or ""):
                return t
            block = t.get("block")
            if block:
                hit = find(name, block)
                if hit:
                    return hit
        return None

    install = find("Install SQL Server under a scheduled task", tasks)
    assert install, "the scheduled-task install is gone"
    script = install["ansible.windows.win_powershell"]["script"]

    # The failure condition must require BOTH a bad exit code AND no service,
    # so the SCENARIOENGINE cleanup flake (service present) does not fail it.
    assert "Get-Service" in script, (
        "the install trusts choco's exit code alone; a cleanup-step failure "
        "after a successful install will fail the deploy")
    assert "-not $svc -and" in script, (
        "the throw is not gated on the service being ABSENT, so a good install "
        "with a bad cleanup exit code still fails")
