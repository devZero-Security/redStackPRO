"""Fields a canvas document may leave empty compile to a working build.

Each case strips a field off a shipped blueprint and checks what the export does
with the gap: the default lands in Terraform and Ansible alike, and nothing in
the export names a role or an address that will never exist.
"""

import json
import re
from pathlib import Path

import pytest
import yaml

from redstackpro import Registry
from redstackpro.ansible import (ACL_RIGHT_ALIASES, acl_right,
                                 apply_compile_defaults)
from redstackpro.export import compile_topology

from shipped import load

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "frontend/public"
ROLES = ROOT / "src/redstackpro/assets/ansible/roles"
PROVIDERS = ("gcp", "aws", "azure")


def goad_light():
    return load(PUBLIC / "goad/goad-light.json")


def _node(doc, node_id):
    return next(n for n in doc["nodes"] if n["id"] == node_id)


def _yaml(files, path):
    return yaml.safe_load(files[path])


def _site_roles(site):
    return sorted({m.group(1) for m in re.finditer(
        r"(?m)^\s*-\s*(?:role:\s*)?(redstackpro\.[a-z_]+)\s*$", site)})


@pytest.mark.parametrize("provider", PROVIDERS)
def test_an_ad_host_with_no_os_is_windows_in_both_halves(provider):
    """Terraform already built an os-less dc as Server 2022; Ansible called it
    Linux, left it out of the windows group and reached for ssh. Now both say
    Windows."""
    doc = goad_light()
    for nid in ("winterfell", "castelblack"):
        _node(doc, nid)["overlay"].pop("os")
    files = compile_topology(doc, Registry(), provider=provider)
    inv = _yaml(files, "ansible/inventory.yml")
    windows = inv["all"]["children"]["windows"]["hosts"]
    assert "def-winterfell" in windows and "def-castelblack" in windows
    for name, kind in (("def-winterfell", "dc"), ("def-castelblack", "srv")):
        hv = _yaml(files, "ansible/host_vars/%s.yml" % name)
        assert hv["ansible_connection"] == "psrp"
        assert "ansible_ssh_common_args" not in hv
        assert hv["redstackpro_%s_os" % kind] == "windows_server_2022"
    main = files["terraform/main.tf"]
    image = {"gcp": "windows-cloud/windows-2022",
             "aws": "Windows_Server-2022-English-Full-Base",
             "azure": "2022-datacenter-azure-edition"}[provider]
    assert image in main


def test_a_dc_with_no_hostname_takes_its_node_id():
    doc = goad_light()
    _node(doc, "winterfell")["overlay"].pop("hostname")
    files = compile_topology(doc, Registry(), provider="gcp")
    hv = _yaml(files, "ansible/host_vars/def-winterfell.yml")
    assert hv["redstackpro_dc_hostname"] == "winterfell"
    assert hv["redstackpro_host_fqdn"] == "winterfell.north.sevenkingdoms.local"


def test_shipped_hostnames_are_kept_as_authored():
    """sccm names its hosts in capitals; the default never overrides a value."""
    doc = load(PUBLIC / "goad/sccm.json")
    files = compile_topology(doc, Registry(), provider="gcp")
    assert _yaml(files, "ansible/host_vars/def-dc.yml")["redstackpro_dc_hostname"] == "DC"


def test_a_domain_with_no_netbios_takes_its_first_label():
    doc = goad_light()
    _node(doc, "north")["overlay"].pop("netbios")
    files = compile_topology(doc, Registry(), provider="gcp")
    north = _yaml(files, "ansible/vars/domains/north.sevenkingdoms.local.yml")
    assert north["domain_netbios"] == "NORTH"

    long = {"nodes": [{"id": "d", "kind": "domain",
                       "overlay": {"fqdn": "averyveryverylongname.corp.local"}}],
            "edges": []}
    apply_compile_defaults(long)
    assert long["nodes"][0]["overlay"]["netbios"] == "AVERYVERYVERYLO"


@pytest.mark.parametrize("reverse", [False, True])
def test_an_untyped_trust_under_its_parent_builds_a_child(reverse):
    """Drawn either way round, a trust between north.sevenkingdoms.local and
    sevenkingdoms.local is the parent and child it reads as: north promotes into
    the parent forest instead of as a forest of its own."""
    doc = goad_light()
    edge = next(e for e in doc["edges"] if e["role"] == "trusts")
    for key in ("trust_type", "direction", "transitive"):
        edge.pop(key)
    if reverse:
        edge["source"], edge["target"] = edge["target"], edge["source"]
    files = compile_topology(doc, Registry(), provider="aws")
    north = _yaml(files, "ansible/vars/domains/north.sevenkingdoms.local.yml")
    root = _yaml(files, "ansible/vars/domains/sevenkingdoms.local.yml")
    assert north["forest_root"] is False
    assert north["parent_fqdn"] == "sevenkingdoms.local"
    assert north["parent_dc_address"] == "<<tf:def-kingslanding:private_address>>"
    assert root["forest_root"] is True
    (trust,) = root["trusts"]
    assert trust["type"] == "parent_child"
    assert trust["direction"] == "bidirectional"
    assert trust["transitive"] is True
    assert "parent_child" in files["DEFENSE-BRIEFING.md"]


def test_an_untyped_trust_between_unrelated_domains_is_a_forest_trust():
    doc = load(PUBLIC / "goad/goad.json")
    edge = next(e for e in doc["edges"]
                if e["role"] == "trusts" and e["target"] == "essos")
    edge.pop("trust_type")
    edge.pop("direction")
    files = compile_topology(doc, Registry(), provider="gcp")
    essos = _yaml(files, "ansible/vars/domains/essos.local.yml")
    root = _yaml(files, "ansible/vars/domains/sevenkingdoms.local.yml")
    assert essos["forest_root"] is True
    forest = [t for t in root["trusts"] if t["target_fqdn"] == "essos.local"]
    assert forest and forest[0]["type"] == "forest"
    assert forest[0]["direction"] == "bidirectional"


def test_the_forest_trust_task_honours_an_inbound_direction():
    """inbound used to fall through to Outbound."""
    text = (ROLES / "redstackpro.dc/tasks/trusts.yml").read_text(encoding="utf-8")
    assert '"inbound" { "Inbound" }' in text
    assert "default { \"Bidirectional\" }" in text


def _jumpbox_services(doc, provider="gcp"):
    files = compile_topology(doc, Registry(), provider=provider)
    (path,) = [p for p in files
               if p.startswith("ansible/host_vars/") and "jump" in p]
    return _yaml(files, path)["redstackpro_jumpbox_services"]


def test_a_vpn_listed_in_services_is_ignored_without_access_mode():
    """redstack ticked wireguard in services on a public jumpbox: the server was
    installed on a port Terraform never opened."""
    doc = load(PUBLIC / "redstack.json")
    jb = next(n for n in doc["nodes"] if n["kind"] == "jumpbox")
    jb["overlay"]["services"] = ["ssh", "guacamole", "wireguard", "openvpn"]
    jb["overlay"].pop("access_mode", None)
    assert _jumpbox_services(doc) == ["ssh", "guacamole"]


def test_access_mode_alone_installs_the_vpn():
    doc = load(PUBLIC / "redstack.json")
    jb = next(n for n in doc["nodes"] if n["kind"] == "jumpbox")
    jb["overlay"]["services"] = ["ssh", "guacamole"]
    jb["overlay"]["access_mode"] = "openvpn"
    assert _jumpbox_services(doc) == ["ssh", "guacamole", "openvpn"]


def test_a_defense_jumpbox_gets_no_vpn_server():
    """A range keeps the public portal (VPN002) and Terraform opens no VPN port
    there, so no listener is installed either."""
    doc = goad_light()
    jb = next(n for n in doc["nodes"] if n["kind"] == "jumpbox")
    jb["overlay"]["services"] = ["ssh", "guacamole", "wireguard"]
    jb["overlay"]["access_mode"] = "wireguard"
    assert _jumpbox_services(doc) == ["ssh", "guacamole"]


def test_a_jumpbox_with_only_a_vpn_service_keeps_ssh():
    doc = load(PUBLIC / "redstack.json")
    jb = next(n for n in doc["nodes"] if n["kind"] == "jumpbox")
    jb["overlay"]["services"] = ["wireguard"]
    assert _jumpbox_services(doc) == ["ssh"]


def _with_fw_and_appliance(doc):
    seg = next(n for n in doc["nodes"] if n["kind"] == "segment")["id"]
    dom = next(n for n in doc["nodes"] if n["kind"] == "domain")["id"]
    doc["nodes"] += [{"id": "fw01", "kind": "fw", "overlay": {"os": "linux"}},
                     {"id": "appl01", "kind": "appliance", "overlay": {}}]
    doc["edges"] += [
        {"id": "e-fw01-att", "role": "attached", "source": "fw01", "target": seg},
        {"id": "e-appl01-att", "role": "attached", "source": "appl01", "target": seg},
        {"id": "e-fw01-join", "role": "joins", "source": "fw01", "target": dom},
    ]
    return doc


@pytest.mark.parametrize("provider", PROVIDERS)
def test_fw_and_appliance_hosts_get_no_role_and_no_dangling_address(provider):
    """site.yml named redstackpro.fw and redstackpro.appliance, which do not
    exist, so ansible-playbook failed at load and the range provisioned nothing.
    Terraform builds neither kind, so their address tokens never filled either."""
    files = compile_topology(_with_fw_and_appliance(goad_light()), Registry(),
                             provider=provider)
    roles = _site_roles(files["ansible/site.yml"])
    assert roles, "no roles parsed from site.yml"
    for role in roles:
        assert (ROLES / role / "tasks/main.yml").is_file(), role
    for path, body in files.items():
        if path.startswith(("ansible/", "terraform/")) or path.endswith("BRIEFING.md"):
            assert "def-fw01" not in body, path
            assert "def-appl01" not in body, path
    assert "Not built by this release" in files["DEFENSE-BRIEFING.md"]


@pytest.mark.parametrize("name", sorted(
    [p.name for p in PUBLIC.glob("*.json")]
    + ["goad/" + p.name for p in (PUBLIC / "goad").glob("*.json")]))
def test_every_role_a_shipped_blueprint_names_exists(name):
    files = compile_topology(load(PUBLIC / name), Registry(), provider="gcp")
    for role in _site_roles(files["ansible/site.yml"]):
        assert (ROLES / role / "tasks/main.yml").is_file(), role


def test_acl_right_labels_map_to_the_names_the_script_applies():
    assert acl_right("ForceChangePassword") == "Ext-User-Force-Change-Password"
    assert acl_right("AddMember") == "Ext-Write-Member"
    assert acl_right("addmember") == "Ext-Write-Member"
    assert acl_right("GenericAll") == "GenericAll"
    assert acl_right("Ext-User-Force-Change-Password") == "Ext-User-Force-Change-Password"
    script = (ROLES / "redstackpro.dc/files/apply_acls.ps1").read_text(encoding="utf-8")
    for target in ACL_RIGHT_ALIASES.values():
        assert '"%s"' % target in script, target
    # AddMember is a WriteProperty on member (schemaIDGUID bf9679c0-...).
    assert re.search(r'"Ext-Write-Member"\s*=\s*\[GUID\]"bf9679c0-0de6-11d0-a285-00aa003049e2"',
                     script)


def test_old_documents_with_acl_labels_compile_to_script_names():
    doc = goad_light()
    dom = _node(doc, "north")
    dom["overlay"]["acls"] = [
        {"principal": "jon.snow", "target": "sansa.stark", "right": "ForceChangePassword"},
        {"principal": "jon.snow", "target": "Night Watch", "right": "AddMember"},
        {"principal": "jon.snow", "target": "arya.stark", "right": "GenericAll"},
    ]
    files = compile_topology(doc, Registry(), provider="gcp")
    north = _yaml(files, "ansible/vars/domains/north.sevenkingdoms.local.yml")
    assert [a["right"] for a in north["acls"]] == [
        "Ext-User-Force-Change-Password", "Ext-Write-Member", "GenericAll"]


def test_defaults_do_not_touch_the_callers_document():
    doc = goad_light()
    _node(doc, "winterfell")["overlay"].pop("os")
    before = json.dumps(doc, sort_keys=True)
    compile_topology(doc, Registry(), provider="gcp")
    assert json.dumps(doc, sort_keys=True) == before


# -- domain user flaws

ATTACK_PATHS = ROLES / "redstackpro.dc/tasks/attack_paths.yml"


def _north_users(doc):
    return _node(doc, "north")["overlay"]["users"]


def test_password_in_description_plants_the_password():
    doc = goad_light()
    users = _north_users(doc)
    users += [
        {"username": "desc.declared", "password": "Winter1!",
         "description": "Helpdesk", "flaws": ["password_in_description"]},
        {"username": "desc.weak", "weak_password": "Spring2025",
         "flaws": ["password_in_description", "weak_password"]},
        {"username": "desc.none", "display_name": "No Password",
         "flaws": ["password_in_description"]},
    ]
    files = compile_topology(doc, Registry(), provider="gcp")
    north = _yaml(files, "ansible/vars/domains/north.sevenkingdoms.local.yml")
    by = {u["username"]: u for u in north["users"]}
    assert by["desc.declared"]["description"] == "Helpdesk (Password : Winter1!)"
    assert by["desc.weak"]["password"] == "Spring2025"
    assert by["desc.weak"]["description"] == "desc.weak (Password : Spring2025)"
    # No password of its own: it gets one, never the shared lab password.
    pw = by["desc.none"]["password"]
    assert pw and by["desc.none"]["description"] == "No Password (Password : %s)" % pw
    group = _yaml(files, "ansible/group_vars/all.yml")
    assert group["redstackpro_user_passwords"]["desc.none"] == pw
    assert pw in files["DEFENSE-BRIEFING.md"]


def test_a_description_that_already_holds_the_password_is_kept():
    doc = load(PUBLIC / "goad/goad-wazuh.json")
    files = compile_topology(doc, Registry(), provider="gcp")
    north = _yaml(files, "ansible/vars/domains/north.sevenkingdoms.local.yml")
    sam = next(u for u in north["users"] if u["username"] == "samwell.tarly")
    assert sam["description"] == "Samwell Tarly (Password : Heartsbane)"


def test_the_user_role_honours_spns_delegate_to_enabled_and_reversible():
    tasks = {t["name"]: t for t in yaml.safe_load(
        ATTACK_PATHS.read_text(encoding="utf-8"))}
    spn = tasks["Set SPNs on kerberoastable accounts"]["microsoft.ad.user"]["spn"]["add"]
    assert "item.spns if" in spn and "MSSQLSvc/" in spn
    deleg = tasks["Configure constrained delegation (protocol transition) on flagged users"]
    assert "item.delegate_to" in deleg["ansible.windows.win_powershell"]["parameters"]["DelegateTo"]
    assert "-Replace @{'msDS-AllowedToDelegateTo'" in deleg["ansible.windows.win_powershell"]["script"]
    rev = tasks["Store passwords with reversible encryption on flagged accounts"]
    script = rev["ansible.windows.win_powershell"]["script"]
    assert "-AllowReversiblePasswordEncryption $true" in script
    assert "Set-ADAccountPassword" in script
    assert "reversible_encryption" in rev["when"]
    main = yaml.safe_load((ROLES / "redstackpro.dc/tasks/main.yml").read_text(encoding="utf-8"))
    create = next(t for t in main if t.get("name") == "Create the domain users")
    assert create["microsoft.ad.user"]["enabled"] == "{{ item.enabled | default(true) | bool }}"
    assert create["microsoft.ad.user"]["description"] == "{{ item.description | default(omit) }}"
    assert create["microsoft.ad.user"]["password_never_expires"] is True
