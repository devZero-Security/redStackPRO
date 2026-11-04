"""The 0.10.0 UX pass on the validator: the schema check, the field path a
finding carries for the canvas, the info severity, and the rules that catch a
value which compiles but does nothing or breaks the deploy. Each rule has a case
that fires and one that does not.
"""

import json
from pathlib import Path

import pytest

from redstackpro.findings import finding

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "src/redstackpro/schema/topology/0.7.0.json")
                    .read_text(encoding="utf-8"))
DEFS = SCHEMA["$defs"]


# -- the finding shape

def test_a_field_finding_serializes_its_path():
    d = finding("SCH001", "error", ["rd01"], "{path} bad", path="tls.cert_source",
                field="tls.cert_source").to_dict()
    assert d["field"] == "tls.cert_source"
    assert d["message"] == "tls.cert_source bad"


def test_a_finding_without_a_field_keeps_its_old_shape():
    d = finding("X001", "error", ["a"], "bad").to_dict()
    assert "field" not in d


def test_info_is_a_severity():
    assert finding("X001", "info", ["a"], "note").severity == "info"
    with pytest.raises(ValueError):
        finding("X001", "notice", ["a"], "note")


# -- the schema as the canvas reads it

def _untitled(node, path):
    out = []
    if isinstance(node, dict):
        for key, spec in (node.get("properties") or {}).items():
            if "title" not in spec:
                out.append("/".join(path + [key]))
            out += _untitled(spec, path + [key])
        if isinstance(node.get("items"), dict):
            out += _untitled(node["items"], path + ["[]"])
    return out


def test_every_property_has_a_title():
    gaps = _untitled(SCHEMA, ["root"])
    for name, spec in DEFS.items():
        gaps += _untitled(spec, [name])
    assert not gaps, gaps


def test_the_shared_defs_carry_a_title_and_help():
    # The Inspector resolves $ref, so a field that is only a $ref shows these.
    for name in ("identifier", "cidr", "ipv4", "port", "public_address"):
        assert DEFS[name].get("title"), name
        assert DEFS[name].get("description"), name


def test_values_that_broke_the_deploy_are_gone_from_the_enums():
    rd = DEFS["overlay_redirector"]["properties"]["tls"]["properties"]
    assert "provided" not in rd["cert_source"]["enum"]
    assert "splunk" not in DEFS["overlay_collector"]["properties"]["sink"]["enum"]
    assert "splunk" not in DEFS["overlay_siem"]["properties"]["product"]["enum"]


LINUX = ("debian_13", "debian_12", "ubuntu_2204", "ubuntu_2004")


def test_every_named_linux_os_maps_to_an_image_on_each_cloud():
    from redstackpro.terraform import aws, azure, gcp
    range_os = DEFS["overlay_range_host"]["properties"]["os"]["enum"]
    siem_os = DEFS["overlay_siem"]["properties"]["os"]["enum"]
    for os in LINUX:
        assert os in range_os and os in siem_os, os
        assert os in gcp.LINUX_IMAGES, os
        assert os in aws.LINUX_IMAGES, os
        assert os in azure.LINUX_IMAGES, os
    assert set(siem_os) == set(LINUX)


# -- SCH001, the schema applied inside validate()

from redstackpro import validate  # noqa: E402
from shipped import example  # noqa: E402


def _sch(doc):
    return [f for f in validate(doc) if f.code == "SCH001"]


def _node(doc, kind):
    return next(n for n in doc["nodes"] if n["kind"] == kind)


def test_a_clean_document_has_no_schema_finding():
    assert not _sch(example("redstack.json"))


@pytest.mark.parametrize("mutate, target, field, words", [
    (lambda d: d.update(prefix="R_T"), "topology", "prefix",
     "1 to 8 lowercase letters"),
    (lambda d: _node(d, "segment")["overlay"].update(cidr="10.30.0.0"),
     "mgmt-sub01", "cidr", "CIDR form"),
    (lambda d: _node(d, "segment")["overlay"].update(cidr="10.30.10.5/24"),
     "mgmt-sub01", "cidr", "10.30.10.0/24"),
    (lambda d: _node(d, "redirector")["overlay"].update(
        hostname="https://cdn.x.net/"), "apache-rd01", "hostname", "no scheme"),
    (lambda d: _node(d, "redirector")["overlay"]["gating"].update(
        header_name="X Request Id"), "apache-rd01", "gating.header_name",
     "X-Request-Id"),
    (lambda d: _node(d, "redirector")["overlay"]["tls"].update(
        cert_source="provided"), "apache-rd01", "tls.cert_source",
     "must be one of letsencrypt, self_signed"),
    (lambda d: _node(d, "collector")["overlay"].pop("sink"), "open-log01", "sink",
     "is required"),
    (lambda d: _node(d, "collector")["overlay"].update(sink="splunk"),
     "open-log01", "sink", "must be one of"),
    (lambda d: d.update(auto_stop={"enabled": True, "at": "25:00"}), "topology",
     "auto_stop.at", "HH:MM"),
])
def test_a_bad_value_is_one_finding_naming_its_field(mutate, target, field, words):
    doc = example("redstack.json")
    mutate(doc)
    found = _sch(doc)
    assert len(found) == 1, [f.message for f in found]
    f = found[0]
    assert f.severity == "error"
    assert f.target_ids == (target,)
    assert f.field == field
    assert words in f.message
    assert f.message.startswith(field + " on ")


def test_a_fronts_edge_field_is_reported_on_the_edge():
    doc = example("redstack.json")
    edge = next(e for e in doc["edges"] if e["role"] == "fronts")
    edge["uri_prefix"] = "api/v1"
    edge["listen_port"] = "443"
    found = {f.field: f for f in _sch(doc)}
    assert set(found) == {"uri_prefix", "listen_port"}
    assert found["uri_prefix"].target_ids == (edge["id"],)
    assert "Example: /cdn/assets" in found["uri_prefix"].message
    assert "must be a whole number" in found["listen_port"].message


def test_a_field_no_kind_has_is_reported_once_per_key():
    doc = example("redstack.json")
    node = _node(doc, "collector")
    node["name"] = "RT-LOG"
    node["overlay"]["colour"] = "red"
    found = sorted(f.field for f in _sch(doc))
    assert found == ["colour", "name"]


def test_a_range_internal_ip_and_hostname_are_checked():
    doc = json.loads((ROOT / "frontend/public/goad/goad-light.json").read_text())
    dc = _node(doc, "dc")
    dc["overlay"]["internal_ip"] = "10.30.10.300"
    dc["overlay"]["hostname"] = "kingslanding-keep"
    found = {f.field: f for f in _sch(doc)}
    assert set(found) == {"internal_ip", "hostname"}
    # A range names hosts by bare id.
    assert found["hostname"].message.startswith("hostname on %s:" % dc["id"])


def test_problems_another_rule_reports_are_not_repeated():
    doc = example("redstack.json")
    jb = _node(doc, "jumpbox")
    jb["overlay"]["access_mode"] = "wireguard"
    jb["overlay"]["operators"] = [{"handle": "Bad Name"}]
    _node(doc, "redirector")["overlay"]["hostname"] = ""
    codes = [f.code for f in validate(doc)]
    assert "VPN005" in codes and "RDR001" in codes
    assert not _sch(doc)


def test_a_document_missing_ids_reports_instead_of_raising():
    doc = example("minimal.json")
    doc["nodes"][0].pop("id")
    found = validate(doc)
    assert [f.code for f in found] == ["SCH001"]
    assert found[0].target_ids == ("topology",)
    assert found[0].field == "nodes.0.id"


def test_an_unknown_schema_version_is_one_finding():
    doc = example("minimal.json")
    doc["schema_version"] = "9.9.9"
    found = _sch(doc)
    assert len(found) == 1 and found[0].field == "schema_version"


def test_an_older_document_is_checked_against_its_own_version():
    doc = json.loads((ROOT / "src/redstackpro/schema/topology/examples/0.6.0/"
                      "redstack.json").read_text())
    assert doc["schema_version"] == "0.6.0"
    assert not _sch(doc)


def test_the_api_serializes_the_field_path(tmp_path):
    from fastapi.testclient import TestClient
    from redstackpro.api import create_app
    app = create_app("sqlite+pysqlite:///" + str(tmp_path / "t.db"))
    try:
        doc = example("redstack.json")
        _node(doc, "redirector")["overlay"]["tls"]["cert_source"] = "provided"
        body = TestClient(app).post("/api/v1/validate",
                                    json={"document": doc}).json()
        sch = [f for f in body["findings"] if f["code"] == "SCH001"]
        assert sch == [{
            "code": "SCH001", "severity": "error",
            "target_ids": ["apache-rd01"],
            "template": "{path} on {node}: {reason}.",
            "values": {"path": "tls.cert_source", "node": "off-apache-rd01",
                       "reason": "must be one of letsencrypt, self_signed"},
            "message": "tls.cert_source on off-apache-rd01: must be one of "
                       "letsencrypt, self_signed.",
            "remedy": "Pick one of the listed values.",
            "field": "tls.cert_source",
        }]
        assert body["valid"] is False and body["infos"] == 0
    finally:
        app.state.engine.dispose()


# -- the rules

def _range(*hosts, domain=None):
    """A one-domain range. Each host is (id, kind, overlay) and joins it."""
    nodes = [
        {"id": "net01", "kind": "network", "overlay": {"cidr": "192.168.0.0/16"}},
        {"id": "sub01", "kind": "segment",
         "overlay": {"cidr": "192.168.56.0/24", "egress": "allowed",
                     "exposure": "local"}},
        {"id": "jump", "kind": "jumpbox",
         "overlay": {"services": ["ssh", "guacamole"]}},
        {"id": "d", "kind": "domain", "overlay": domain or {
            "fqdn": "corp.local", "netbios": "CORP",
            "users": [{"username": "alice", "privilege": "domain_admin"}]}},
        {"id": "dc01", "kind": "dc", "overlay": {"hostname": "dc01"}},
    ]
    edges = [{"id": "e-sub", "role": "attached", "source": "sub01",
              "target": "net01"},
             {"id": "e-jump", "role": "attached", "source": "jump",
              "target": "sub01"},
             {"id": "e-dc-att", "role": "attached", "source": "dc01",
              "target": "sub01"},
             {"id": "e-dc-joins", "role": "joins", "source": "dc01",
              "target": "d"}]
    for hid, kind, overlay in hosts:
        nodes.append({"id": hid, "kind": kind, "overlay": overlay})
        edges += [
            {"id": "e-%s-att" % hid, "role": "attached", "source": hid,
             "target": "sub01"},
            {"id": "e-%s-joins" % hid, "role": "joins", "source": hid,
             "target": "d"},
        ]
    return {"schema_version": "0.7.0", "mode": "defense", "name": "r",
            "prefix": "def", "nodes": nodes, "edges": edges}


def _of(doc, code, **kw):
    return [f for f in validate(doc, **kw) if f.code == code]


def test_the_base_range_is_clean():
    assert [f.code for f in validate(_range())] == []


def test_net007_a_subnet_outside_its_network_is_an_error():
    doc = example("redstack.json")
    seg = _node(doc, "segment")
    assert not _of(doc, "NET007")
    seg["overlay"]["cidr"] = "172.16.5.0/24"
    (f,) = _of(doc, "NET007")
    assert f.severity == "error" and f.field == "cidr"
    assert "172.16.5.0/24" in f.message and "outside its network" in f.message
    assert f.remedy.startswith("Pick a range inside 10.30.0.0/16, e.g. 10.30.0.0/24")


@pytest.mark.parametrize("fqdn", ["corp", "Seven Kingdoms.local", "", "-a.local",
                                  "corp..local"])
def test_dom001_a_bad_fqdn_is_an_error(fqdn):
    doc = _range(domain={"fqdn": fqdn, "users": [
        {"username": "alice", "privilege": "domain_admin"}]})
    found = _of(doc, "DOM001")
    assert [f.field for f in found] == ["fqdn"], fqdn
    assert found[0].severity == "error"
    assert "corp.local" in found[0].remedy


@pytest.mark.parametrize("netbios", ["SEVENKINGDOMSLAND", "SEVEN KINGS", "", "A-B"])
def test_dom001_a_bad_netbios_is_an_error(netbios):
    doc = _range(domain={"fqdn": "corp.local", "netbios": netbios, "users": [
        {"username": "alice", "privilege": "domain_admin"}]})
    assert [f.field for f in _of(doc, "DOM001")] == ["netbios"], netbios


def test_dom001_good_names_and_an_unset_netbios_pass():
    for fqdn in ("corp.local", "north.sevenkingdoms.local", "academy.ninja.lan"):
        doc = _range(domain={"fqdn": fqdn, "users": [
            {"username": "alice", "privilege": "domain_admin"}]})
        assert not _of(doc, "DOM001"), fqdn


def test_nam003_on_a_linux_host_does_not_talk_about_netbios():
    doc = example("redstack.json")
    doc["prefix"] = "redteam"
    linux = [f for f in _of(doc, "NAM003") if "NetBIOS" not in f.message]
    windows = [f for f in _of(doc, "NAM003") if "NetBIOS" in f.message]
    assert linux and all("capped at 15" in f.message for f in linux)
    # The Windows operator keeps the NetBIOS wording.
    win = next(n["id"] for n in doc["nodes"]
               if n["kind"] == "operator" and n["overlay"]["os"] == "windows")
    assert [f.target_ids for f in windows] == [(win,)]


def test_jmp001_a_jumpbox_without_guacamole_warns():
    doc = _range()
    _node(doc, "jumpbox")["overlay"]["services"] = ["ssh"]
    (f,) = _of(doc, "JMP001")
    assert f.severity == "warning" and f.field == "services"
    assert f.message == ("jump has no guacamole, so there is no portal; hosts "
                         "are reachable over ssh only.")
    _node(doc, "jumpbox")["overlay"]["services"] = ["ssh", "guacamole"]
    assert not _of(doc, "JMP001")


def test_jmp002_the_ca_off_while_something_needs_it_is_an_error():
    doc = example("redstack.json")  # a TLS collector and a Windows operator
    jb = _node(doc, "jumpbox")
    assert not _of(doc, "JMP002")
    jb["overlay"]["certificate_authority"] = False
    (f,) = _of(doc, "JMP002")
    assert f.severity == "error" and f.field == "certificate_authority"
    assert "collector" in f.message and "Windows operator" in f.message


def test_jmp002_openvpn_alone_needs_the_ca():
    doc = _range()
    jb = _node(doc, "jumpbox")
    jb["overlay"]["certificate_authority"] = False
    assert not _of(doc, "JMP002"), "nothing here needs the CA"
    jb["overlay"]["access_mode"] = "openvpn"
    (f,) = _of(doc, "JMP002")
    assert "openvpn" in f.message


def test_rng011_keepass_without_a_master_password_is_an_error():
    doc = _range(("srv01", "srv", {"vulns": ["keepass_vault"]}))
    (f,) = _of(doc, "RNG011")
    assert f.severity == "error"
    doc = _range(("srv01", "srv", {"vulns": ["files"]}))
    (f,) = _of(doc, "RNG011")
    assert f.severity == "warning", "other missing keys stay warnings"


def test_frt003_a_port_or_protocol_the_redirector_does_not_serve_warns():
    doc = example("redstack.json")
    edge = next(e for e in doc["edges"] if e["role"] == "fronts")
    assert not _of(doc, "FRT003")
    edge["listen_port"] = 8443
    (f,) = _of(doc, "FRT003")
    assert f.severity == "warning" and f.field == "listen_port"
    assert f.message == (
        "off-apache-rd01 serves HTTPS on 443 only; listen_port 8443 opens a port "
        "nothing answers on, and the beacon will call it.")
    edge["listen_port"] = 443
    edge["protocol"] = "dns"
    edge["upstream_port"] = 8080
    (f,) = _of(doc, "FRT003")
    assert "dns opens UDP" in f.message and "upstream_port 8080" in f.message


def test_hrd001_listed_hardening_warns():
    doc = _range(("ws01", "wks", {"hardening": ["asr", "runasppl"]}))
    (f,) = _of(doc, "HRD001")
    assert f.severity == "warning" and f.field == "hardening"
    assert f.message == ("ws01 lists hardening asr, runasppl, which this release "
                         "does not apply.")
    assert not _of(_range(("ws01", "wks", {"hardening": []})), "HRD001")


@pytest.mark.parametrize("kind", ["external", "tree_root"])
def test_tru001_a_trust_type_not_built_warns(kind):
    doc = _range()
    doc["nodes"].append({"id": "d2", "kind": "domain",
                         "overlay": {"fqdn": "other.local"}})
    doc["edges"].append({"id": "t1", "role": "trusts", "source": "d",
                         "target": "d2", "trust_type": kind})
    (f,) = _of(doc, "TRU001")
    assert f.severity == "warning" and f.field == "trust_type"
    assert f.target_ids[0] == "t1"
    for ok in ("forest", "parent_child", None):
        if ok is None:
            doc["edges"][-1].pop("trust_type")
        else:
            doc["edges"][-1]["trust_type"] = ok
        assert not _of(doc, "TRU001"), ok


def _acl_range(acls, **extra):
    domain = {"fqdn": "corp.local", "netbios": "CORP",
              "users": [{"username": "alice", "privilege": "domain_admin",
                         "groups": ["IT"]},
                        {"username": "bob"}],
              "group_members": {"Domain Admins": ["Tier0"]},
              "ous": ["Servers"], "acls": acls}
    domain.update(extra)
    return _range(("srv01", "srv", {}), domain=domain)


BACKSLASH = chr(92)


def test_acl001_known_names_and_rights_pass():
    acls = [
        {"principal": "alice", "target": "bob", "right": "GenericAll"},
        {"principal": "IT", "target": "Tier0", "right": "WriteDacl"},
        {"principal": "Domain Users", "target": "srv01$", "right": "GenericWrite"},
        {"principal": "bob", "target": "Servers", "right": "WriteOwner"},
        {"principal": "bob", "target": "OU=Servers,DC=corp,DC=local",
         "right": "ForceChangePassword"},
        {"principal": "CORP" + BACKSLASH + "bob", "target": "dc01",
         "right": "AddMember"},
        {"principal": "NT AUTHORITY" + BACKSLASH + "ANONYMOUS LOGON",
         "target": "DC=corp,DC=local", "right": "ReadProperty"},
        {"principal": "Helpdesk", "target": "bob", "right": "Ext-Write-SPN"},
    ]
    doc = _acl_range(acls, groups=["Helpdesk"])
    assert not _of(doc, "ACL001"), [f.message for f in _of(doc, "ACL001")]


def test_acl001_a_mistyped_principal_target_or_right_warns():
    doc = _acl_range([
        {"principal": "alcie", "target": "bob", "right": "GenericAll"},
        {"principal": "alice", "target": "bobb", "right": "GenericAll"},
        {"principal": "alice", "target": "srv02$", "right": "GenericAll"},
        {"principal": "alice", "target": "bob", "right": "FullControl"},
        {"principal": "NOPE" + BACKSLASH + "bob", "target": "bob",
         "right": "GenericAll"},
    ])
    found = {f.field: f for f in _of(doc, "ACL001")}
    assert set(found) == {"acls.0.principal", "acls.1.target", "acls.2.target",
                          "acls.3.right", "acls.4.principal"}
    assert all(f.severity == "warning" for f in found.values())
    assert found["acls.0.principal"].message == (
        "ACL alcie to bob: alcie is not a user, group or computer on d; it would "
        "be created as an empty group.")
    assert "empty group" in found["acls.1.target"].message
    assert "skipped" in found["acls.2.target"].message
    assert "FullControl" in found["acls.3.right"].message


def test_acl_rights_match_the_apply_script():
    import re
    from redstackpro.validate import ACL_RIGHTS
    script = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.dc/files/"
              "apply_acls.ps1").read_text(encoding="utf-8")
    known = set(re.findall(r'^\s*"([A-Za-z-]+)"\s*=', script, re.MULTILINE))
    assert known == ACL_RIGHTS


def test_svc001_a_service_nothing_installs_warns():
    doc = _range(("srv01", "srv", {"services": ["smb", "mssql"]}),
                 ("ws01", "wks", {"services": ["iis"]}),
                 ("ca01", "srv", {"services": ["adcs"]}),
                 ("lx01", "srv", {"os": "linux", "services": ["mssql"]}))
    found = sorted((f.target_ids[0], f.values["svc"]) for f in _of(doc, "SVC001"))
    assert found == [("ca01", "adcs"), ("lx01", "mssql"), ("srv01", "smb"),
                     ("ws01", "iis")]
    assert all(f.severity == "warning" and f.field == "services"
               for f in _of(doc, "SVC001"))


def test_svc001_services_a_role_installs_pass():
    doc = _range(("sql01", "srv", {"services": ["mssql", "iis", "exchange"]}),
                 ("ca01", "srv", {"role": "adcs", "services": ["adcs"]}),
                 ("mecm01", "srv", {"role": "mecm", "services": ["mecm"]}))
    _node(doc, "dc")["overlay"].update(role="adcs", services=["adcs"])
    assert not _of(doc, "SVC001")


def test_the_services_a_role_acts_on_match_the_srv_role():
    import re
    tasks = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.srv/tasks"
    text = "".join(p.read_text(encoding="utf-8") for p in tasks.glob("*.yml"))
    read = set(re.findall(r"'(\w+)' in \(redstackpro_srv_services", text))
    assert read == {"mssql", "iis", "exchange"}


def test_svc002_a_firewall_or_appliance_is_an_info_note():
    doc = _range()
    doc["nodes"].append({"id": "fw01", "kind": "fw", "overlay": {}})
    doc["edges"].append({"id": "e-fw", "role": "attached", "source": "fw01",
                         "target": "sub01"})
    (f,) = _of(doc, "SVC002")
    assert f.severity == "info"
    assert "installs nothing" in f.message
    assert not _of(_range(), "SVC002")


@pytest.mark.parametrize("provider, fires", [("gcp", True), ("aws", True),
                                             ("azure", False)])
def test_cap005_a_windows_client_build_on_gcp_or_aws_is_an_info_note(
        provider, fires):
    doc = _range(("ws01", "wks", {"os": "windows_10"}))
    found = _of(doc, "CAP005", provider=provider)
    assert bool(found) == fires
    if fires:
        assert found[0].severity == "info" and found[0].field == "os"
        assert found[0].message == ("ws01 asks for Windows 10; %s has no client "
                                    "image, so it boots Windows Server 2022."
                                    % provider)
    assert not _of(_range(("ws01", "wks", {"os": "windows_server_2022"})),
                   "CAP005", provider="gcp")


def test_an_info_finding_does_not_block_the_compile():
    from redstackpro import is_valid
    doc = _range(("ws01", "wks", {"os": "windows_11"}))
    assert _of(doc, "CAP005", provider="aws")
    assert is_valid(doc, provider="aws")


# -- remedies a person can act on in the canvas

def test_the_rewritten_remedies():
    doc = example("redstack.json")
    op = _node(doc, "operator")
    doc["edges"] = [e for e in doc["edges"]
                    if not (e["role"] == "attached" and e["source"] == op["id"])]
    assert {f.remedy for f in _of(doc, "CAR001")} == {
        "Drag it into a subnet box on the canvas."}

    doc = example("redstack.json")
    _node(doc, "segment")["overlay"]["egress"] = "none"
    assert {f.remedy for f in _of(doc, "EXP003")} == {
        "Set the subnet's egress to allowed."}


def test_a_capability_finding_names_the_field_that_raised_it(registry):
    # CAP001 and CAP002 share the remedy; proxmox has no public address, which
    # a segment's exposure internet asks for.
    doc = example("redstack.json")
    found = [f for f in validate(doc, provider="proxmox", registry=registry)
             if f.code == "CAP002"]
    assert found
    assert {f.field for f in found} == {"exposure"}
    assert "change exposure (now internet)" in found[0].remedy


# -- shipped content stays clean

# The codes this pass added. A shipped blueprint raises none of them, and no
# error but the intentional RDR001. CAP005 and SVC002 are info notes and allowed.
NEW_CODES = {"SCH001", "NET007", "DOM001", "JMP001", "JMP002", "FRT003", "HRD001",
             "TRU001", "ACL001", "SVC001"}

# Blueprints waiting on a content fix, with the fix. Remove an entry once the
# blueprint is fixed.
PENDING = {}


def _shipped():
    out = []
    paths = (sorted((ROOT / "frontend/public").rglob("*.json"))
             + sorted((ROOT / "src/redstackpro/schema/topology/examples/0.7.0")
                      .glob("*.json")))
    for path in paths:
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or "nodes" not in doc:
            continue
        marks = ([pytest.mark.xfail(reason=PENDING[path.name], strict=False)]
                 if path.name in PENDING else [])
        out.append(pytest.param(path, id=path.name, marks=marks))
    return out


@pytest.mark.parametrize("path", _shipped())
@pytest.mark.parametrize("provider", [None, "gcp", "aws", "azure"])
def test_a_shipped_blueprint_raises_no_new_finding(path, provider, registry):
    doc = json.loads(path.read_text(encoding="utf-8"))
    found = validate(doc, provider=provider,
                     registry=registry if provider else None)
    new = ["%s %s" % (f.code, f.message) for f in found if f.code in NEW_CODES]
    errors = ["%s %s" % (f.code, f.message) for f in found
              if f.severity == "error" and f.code != "RDR001"]
    assert not new, new
    assert not errors, errors


def test_a_document_field_remedy_says_where_to_edit_it():
    doc = example("minimal.json")
    doc["auto_stop"] = {"enabled": True, "at": "8pm"}
    (f,) = _sch(doc)
    assert "Topology settings" in f.remedy


def test_a_schema_version_is_never_read_as_a_path():
    from redstackpro import schemacheck
    assert schemacheck.schema_for("../topology/0.7.0") is None
    assert schemacheck.schema_for("0.7.0")["$id"].endswith("0.7.0.json")


def test_dom001_says_what_is_wrong_in_plain_words():
    doc = _range(domain={"fqdn": "corp", "netbios": "", "users": [
        {"username": "alice", "privilege": "domain_admin"}]})
    messages = sorted(f.message for f in _of(doc, "DOM001"))
    assert messages == [
        "The NetBIOS name (empty) on d is not 1 to 15 letters or digits.",
        "The fqdn corp on d is not a domain name. It needs at least two labels "
        "of letters, digits and hyphens.",
    ]
