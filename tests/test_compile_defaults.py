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


@pytest.mark.parametrize("provider", PROVIDERS)
def test_a_wks_with_no_os_is_windows_11_in_both_halves(provider):
    """A workstation defaults to Windows 11; GCP and AWS boot Server 2022 for it."""
    doc = load(PUBLIC / "goad/minilab.json")
    _node(doc, "ws")["overlay"].pop("os")
    files = compile_topology(doc, Registry(), provider=provider)
    hv = _yaml(files, "ansible/host_vars/def-ws.yml")
    assert hv["redstackpro_wks_os"] == "windows_11"
    assert hv["ansible_connection"] == "psrp"
    image = {"gcp": "windows-cloud/windows-2022",
             "aws": "Windows_Server-2022-English-Full-Base",
             "azure": '"win11-23h2-pro"'}[provider]
    assert image in files["terraform/main.tf"]


@pytest.mark.parametrize("name, host", [
    ("goad/goad-wazuh.json", "ws01"), ("goad/minilab.json", "ws"),
    ("goad/sccm.json", "client"), ("harbor.json", "fr-wks01")])
def test_shipped_workstations_are_windows_11(name, host):
    """Windows 10 left support on 2025-10-14; the shipped labs moved off it."""
    assert _node(load(PUBLIC / name), host)["overlay"]["os"] == "windows_11"


def test_azure_terraform_falls_back_to_the_build_ansible_defaults_to():
    """image_for without apply_compile_defaults agrees with it per kind."""
    from redstackpro.terraform import azure
    from redstackpro.terraform.plan import DEFAULT_WINDOWS_OS, TerraformPlan
    plan = TerraformPlan(goad_light(), Registry())
    assert DEFAULT_WINDOWS_OS == {"dc": "windows_server_2022",
                                  "srv": "windows_server_2022", "wks": "windows_11"}
    for kind, build in DEFAULT_WINDOWS_OS.items():
        node = {"id": "%s01" % kind, "kind": kind, "overlay": {}}
        assert azure.image_for(plan, node) == azure.WINDOWS_IMAGES[build], kind
    assert azure.WINDOWS_IMAGES["windows_11"][:3] == (
        "MicrosoftWindowsDesktop", "windows-11", "win11-23h2-pro")


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


# -- shipped labs carry the parameters their ticked vulns read

@pytest.mark.parametrize("name,host,vuln", [
    ("goad/nha.json", "sql", "mssql_linked"),
    ("harbor.json", "fr-wks01", "stored_credential"),
])
def test_lab_vulns_have_their_parameters(name, host, vuln):
    from redstackpro.validate import validate
    doc = load(PUBLIC / name)
    assert vuln in _node(doc, host)["overlay"]["vulns"]
    codes = [f.code for f in validate(doc) if host in f.target_ids]
    assert "RNG011" not in codes, codes


def test_the_stored_credential_owner_gets_batch_logon():
    """cmdkey runs in a scheduled task as the vault owner; without batch logon
    a Domain Users owner's task never runs and the vault stays empty."""
    tasks = yaml.safe_load((ROLES / "redstackpro.host_vulns/tasks/stored_credential.yml")
                           .read_text(encoding="utf-8"))
    names = [t["name"] for t in tasks]
    grant = tasks[names.index("Let the vault owner log on as a batch job")]
    assert grant["ansible.windows.win_user_right"]["name"] == "SeBatchLogonRight"
    assert names.index("Let the vault owner log on as a batch job") < names.index(
        "Plant a Credential Manager credential in a user's vault")


def test_the_stored_credential_owner_can_read_its_script_and_a_miss_fails():
    """The plant script is written as admin into C:\\Windows\\Temp, where Users may
    create files but not read anyone else's, so the owner's task could not open
    it. The role reported changed anyway; found live on Azure 2026-11-05."""
    tasks = yaml.safe_load((ROLES / "redstackpro.host_vulns/tasks/stored_credential.yml")
                           .read_text(encoding="utf-8"))
    names = [t["name"] for t in tasks]
    script = tasks[names.index("Plant a Credential Manager credential in a user's vault")][
        "ansible.windows.win_powershell"]["script"]
    assert '/grant "${Owner}:(RX)"' in script
    assert script.index("/grant") < script.index("Register-ScheduledTask")
    assert "throw" in script, "a credential that was not saved must fail the task"
    assert "Remove-Item $script" in script, "the script holds the password in clear"


def test_smbv1_reboots_until_the_server_dialect_is_on():
    """Enabling the SMB1 feature does nothing until the drivers load at boot; the
    role used -NoRestart and never rebooted, so the dialect stayed off."""
    tasks = yaml.safe_load((ROLES / "redstackpro.host_vulns/tasks/smbv1.yml")
                           .read_text(encoding="utf-8"))
    feature = next(t for t in tasks if t.get("register") == "rsp_smb1_feature")
    assert "Get-SmbServerConfiguration).EnableSMB1Protocol" in feature[
        "ansible.windows.win_powershell"]["script"]
    reboot = next(t for t in tasks if "ansible.windows.win_reboot" in t)
    assert "rsp_smb1_feature" in reboot["when"]
    assert tasks.index(feature) < tasks.index(reboot)


@pytest.mark.parametrize("task_file", [
    "rdp_scheduler.yml", "responder.yml", "ntlm_relay.yml", "schedule.yml",
])
def test_every_bot_user_gets_batch_logon_before_its_task(task_file):
    """Each bot is a scheduled task that runs as a domain user. Without Log on
    as a batch job a Domain Users bot never runs, and nothing reports it."""
    tasks = yaml.safe_load((ROLES / "redstackpro.host_vulns/tasks" / task_file)
                           .read_text(encoding="utf-8"))
    grants = [i for i, t in enumerate(tasks)
              if t.get("ansible.windows.win_user_right", {}).get("name") == "SeBatchLogonRight"]
    registers = [i for i, t in enumerate(tasks)
                 if "Register-ScheduledTask" in str(t.get("ansible.windows.win_powershell", {}))]
    assert grants and registers, task_file
    assert grants[0] < registers[0], task_file


def _logon_bot_interval(vulns_vars):
    """The Mins the logon bot task hands its trigger, rendered as Ansible does:
    the task var first, then the parameter that reads it."""
    jinja2 = pytest.importorskip("jinja2")
    tasks = yaml.safe_load((ROLES / "redstackpro.host_vulns/tasks/rdp_scheduler.yml")
                           .read_text(encoding="utf-8"))
    task = next(t for t in tasks if t["name"] == "Create the RDP logon bot")
    env = jinja2.Environment()
    # Ansible's match test.
    env.tests["match"] = lambda value, pattern: re.match(pattern, str(value)) is not None
    ctx = {"redstackpro_host_vulns_vars": vulns_vars}
    ctx["rsp_bot_interval"] = env.from_string(task["vars"]["rsp_bot_interval"]).render(ctx)
    ps = task["ansible.windows.win_powershell"]
    assert "-RepetitionInterval (New-TimeSpan -Minutes $Mins)" in ps["script"]
    return env.from_string(ps["parameters"]["Mins"]).render(ctx)


def test_the_logon_bot_runs_every_3_minutes_by_default():
    # It was a hard-coded 1 minute.
    assert _logon_bot_interval({"bot_user": "north\\robb.stark"}) == "3"
    assert _logon_bot_interval({}) == "3"


def test_the_logon_bot_interval_is_set_from_vulns_vars():
    doc = goad_light()
    _node(doc, "winterfell")["overlay"]["vulns_vars"]["bot_interval_minutes"] = 10
    files = compile_topology(doc, Registry(), provider="gcp")
    vv = _yaml(files, "ansible/host_vars/def-winterfell.yml")["redstackpro_dc_vulns_vars"]
    assert vv["bot_interval_minutes"] == 10
    assert _logon_bot_interval(vv) == "10"
    assert _logon_bot_interval({"bot_interval_minutes": 1}) == "1"
    assert _logon_bot_interval({"bot_interval_minutes": " 15 "}) == "15"


@pytest.mark.parametrize("value", [0, -5, 2.5, "abc", "", None, True, [5], {"m": 5}])
def test_a_logon_bot_interval_that_is_not_a_whole_number_from_1_is_3(value):
    assert _logon_bot_interval({"bot_interval_minutes": value}) == "3"


def test_a_logon_bot_interval_over_31_days_is_capped():
    # Task Scheduler refuses a repetition interval over 31 days.
    assert _logon_bot_interval({"bot_interval_minutes": 50000}) == "44640"


def test_the_briefing_reads_the_logon_bot_interval_as_the_role_does():
    from redstackpro.briefing import logon_bot_minutes
    for value in (1, 3, 10, "7", " 15 ", 0, -5, 2.5, "abc", "", None, True, [5], 50000):
        vv = {"bot_interval_minutes": value}
        assert str(logon_bot_minutes(vv)) == _logon_bot_interval(vv), value
    assert str(logon_bot_minutes({})) == _logon_bot_interval({})


def test_the_schedule_bot_does_not_reuse_the_logon_bot_task_name():
    # Both defaulted to connect_bot, so a host with both kept only one.
    text = (ROLES / "redstackpro.host_vulns/tasks/schedule.yml").read_text(encoding="utf-8")
    assert "default('schedule_bot')" in text and "default('connect_bot')" not in text
