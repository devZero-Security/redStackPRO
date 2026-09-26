"""Nodes become module blocks; edges become firewall rules. The firewall half is
the part that exists nowhere else, so it carries most of the tests.
"""

import json
import re
import io
from pathlib import Path

import hcl2
import pytest

from redstackpro.authoring import set_redirector_hostname
from redstackpro.terraform import GenerationError, generate
from redstackpro.terraform import aws as aws_images

ROOT = Path(__file__).resolve().parent.parent


def files(topology, **kw):
    return generate(topology, **kw)


def _clean(value):
    """This hcl2 build keeps surrounding quotes on keys and string values."""
    if isinstance(value, str):
        v = value.strip()
        return v[1:-1] if len(v) > 1 and v[0] == v[-1] == '"' else v
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {_clean(k): _clean(v) for k, v in value.items()
                if k != "__is_block__"}
    return value


def parse(text):
    return _clean(hcl2.load(io.StringIO(text)))


def firewall_rules(topology):
    parsed = parse(files(topology)["terraform/firewall.tf"])
    out = {}
    for block in parsed.get("resource", []):
        for name, body in block.get("google_compute_firewall", {}).items():
            out[name] = body
    return out


def modules(topology):
    return _modules_for(topology)


def _modules_for(topology, **kw):
    parsed = parse(files(topology, **kw)["terraform/main.tf"])
    out = {}
    for block in parsed.get("module", []):
        out.update(block)
    return out


# -- shape

def test_generates_expected_paths(redstack):
    out = files(redstack)
    assert set(out) == {
        "terraform/versions.tf", "terraform/variables.tf",
        "terraform/terraform.tfvars", "terraform/main.tf",
        "terraform/firewall.tf", "terraform/outputs.tf"}


def test_all_output_is_parseable_hcl(redstack):
    for text in files(redstack).values():
        parse(text)


def test_a_check_warns_when_operator_source_ranges_is_wide_open(redstack):
    """operator_source_ranges is a tfvars value the topology validator never sees,
    so a wide-open default (ssh and the portal open to the internet) is caught at
    apply by a Terraform check block. A failed check warns, it does not fail the
    apply. Emitted once per main.tf, for both providers. See operator_source_ranges_check."""
    for provider in ("gcp", "aws"):
        main = files(redstack, provider=provider)["terraform/main.tf"]
        assert main.count('check "operator_source_ranges_is_narrowed"') == 1
        assert '!contains(var.operator_source_ranges, "0.0.0.0/0")' in main


def test_region_resolves_from_the_argument_then_the_document_then_a_default(redstack):
    """The compile argument wins, then a region on the document, then the
    per-provider default. Region is a location, not provider vocabulary."""
    tf = files(redstack, provider="aws", region="us-west-2")["terraform/variables.tf"]
    assert _region_of(tf) == "us-west-2"                  # the argument
    redstack["region"] = "eu-central-1"
    tf = files(redstack, provider="aws")["terraform/variables.tf"]
    assert _region_of(tf) == "eu-central-1"               # the document
    del redstack["region"]
    tf = files(redstack, provider="aws")["terraform/variables.tf"]
    assert _region_of(tf) == "us-east-1"                  # the default


def _region_of(variables_tf):
    import re
    return re.search(r'variable "region"[^}]*default\s*=\s*"([^"]+)"',
                     variables_tf, re.S).group(1)


def test_refuses_invalid_topology(minimal):
    minimal["edges"] = [e for e in minimal["edges"] if e["role"] != "manages"]
    with pytest.raises(GenerationError):
        generate(minimal)


def test_an_unwritten_backend_says_so(redstack):
    with pytest.raises(GenerationError) as exc:
        generate(redstack, provider="digitalocean")
    assert "aws" in str(exc.value) and "gcp" in str(exc.value)


def test_gcp_renders_a_peering_for_a_peers_edge(peered):
    """A peers edge becomes a peering module wiring the two networks by their
    self links, and the module stands up the resource on each side. See 0030."""
    mods = modules(peered)
    peering = next(b for name, b in mods.items()
                   if b.get("source") == "./modules/gcp/peering")
    assert peering["network_a"] == "${module.red_main_net01.self_link}"
    assert peering["network_b"] == "${module.red_c2_net01.self_link}"


def test_cross_network_management_uses_a_cidr_rule_not_a_tag(peered):
    """A network tag does not cross a peering, so the rule reaching managed hosts
    in the other network names the jumpbox subnet by CIDR instead. See 0030."""
    rules = firewall_rules(peered)
    rule = rules["mgmt_out_red_jump_bx01_red_c2_net01_22"]
    assert rule["source_ranges"] == ["10.60.0.0/24"]      # the jumpbox subnet
    assert "source_tags" not in rule
    assert set(rule["target_tags"]) == {"red-nginx-rd01", "red-myth-ts01"}


def test_aws_renders_a_peering_with_routes(peered):
    """AWS does not exchange routes across a peering on its own, so the module
    also routes each segment to the peer CIDR. See 0031."""
    mods = aws_modules(peered)
    peering = next(b for b in mods.values()
                   if b.get("source") == "./modules/aws/peering")
    assert peering["vpc_a"] == "${module.red_main_net01.id}"
    assert peering["cidr_b"] == "10.61.0.0/16"
    # Every segment on each side hands its route table to the module: one in the
    # management VPC, two in the operations VPC.
    # A real HCL list now (not a compact() string), so membership is exact.
    tables_a = " ".join(peering["route_tables_a"])
    tables_b = " ".join(peering["route_tables_b"])
    assert "module.red_mgmt_sub01.route_table_id" in tables_a
    for seg in ("red_c2_sub01", "red_rdir_sub01"):
        assert "module.%s.route_table_id" % seg in tables_b, seg

    # And the PUBLIC route table on each side, which is the one that matters for
    # a public-addressed host. Such a host is relocated out of its segment into
    # the public subnet (0054), so routing only the segment tables leaves it
    # able to reach the internet and its own VPC but nothing across the peering
    # -- with the peering active and looking perfectly healthy. A live ops
    # deploy stalled on exactly that, its jumpbox unable to SSH the redirector.
    assert "module.red_main_net01.public_route_table_id" in tables_a
    assert "module.red_c2_net01.public_route_table_id" in tables_b
    # The public route table is included at COMPILE time, only for a network that
    # actually builds one, so the list is a statically known length. It must NOT
    # be a compact(try(...,null)) computed at apply: the peering module's
    # count = length(route_tables) then cannot be resolved at plan and terraform
    # fails with "Invalid count argument". A fresh deploy caught that.
    assert "compact(" not in tables_a


def test_aws_cross_network_management_uses_a_cidr_not_a_group(peered):
    """A security group reference across peered VPCs needs the connection active
    first, so the cross-network rule names the jumpbox subnet by CIDR. See 0031.

    The CIDR is the PUBLIC subnet, not the declared segment. A host that takes a
    public address is relocated out of its segment on AWS, because one route
    table serves a whole subnet and an addressed host cannot sit in the
    NAT-routed one (0054). Naming the declared segment allows a range the
    jumpbox is not in, and the rule denies the traffic it exists to permit --
    which is exactly what stranded a live ops deploy, where the rule allowed
    10.30.0.0/24 while the jumpbox sat at 10.30.255.249.
    """
    rules = aws_rules(peered)
    rule = rules["mgmt_out_red_jump_bx01_red_nginx_rd01"]
    assert rule["cidr_ipv4"] == "10.60.255.240/28"   # the jumpbox's real subnet
    assert "referenced_security_group_id" not in rule


def test_gcp_declares_only_capabilities_it_renders(peered, registry):
    """The mirror of the aws check: network_peering is declared, so a rendered
    peering has to exist to back it."""
    assert "network_peering" in registry.capabilities("gcp")
    assert "google_compute_network_peering" in "\n".join(
        (ROOT / "src/redstackpro/assets/terraform/modules/gcp/peering/main.tf")
        .read_text().splitlines())


# -- module blocks

def test_one_module_per_node(redstack):
    mods = modules(redstack)
    node_count = len(redstack["nodes"])
    peerings = sum(1 for e in redstack["edges"] if e["role"] == "peers")
    # One module per node, plus a peering module for each peers edge.
    assert len(mods) == node_count + peerings


def test_segment_references_its_network(redstack):
    mods = modules(redstack)
    assert mods["red_c2_sub01"]["network"] == "${module.red_main_net01.self_link}"


def test_host_references_its_segment(redstack):
    mods = modules(redstack)
    assert mods["red_myth_ts01"]["subnetwork"] == "${module.red_c2_sub01.self_link}"


def test_exposure_drives_public_address(redstack):
    mods = modules(redstack)
    assert mods["red_apache_rd01"]["public_address"] in (True, "true")
    assert mods["red_myth_ts01"]["public_address"] in (False, "false")
    assert mods["red_win_op01"]["public_address"] in (False, "false")


def test_redirector_and_jumpbox_reserve_a_static_ip(redstack):
    """The redirector and jumpbox reserve a static external IP so a stop/start
    keeps the same public address: the redirector's C2 callback domain must keep
    resolving and the jumpbox is the Guacamole/SSH entry point. Private hosts do
    not reserve one. See the ephemeral-IP finding."""
    mods = modules(redstack)
    assert mods["red_apache_rd01"]["reserve_ip"] in (True, "true")   # redirector
    assert mods["red_jump_bx01"]["reserve_ip"] in (True, "true")     # jumpbox
    assert mods["red_myth_ts01"]["reserve_ip"] in (False, "false")   # private


def test_operator_os_selects_the_image(redstack):
    mods = modules(redstack)
    assert "windows" in mods["red_win_op01"]["image"]
    # A GCP Kali operator boots the red-kali custom image (Kali's official cloud
    # disk imported into the project), unqualified so terraform resolves it in
    # the deploy's own project. Runtime debian->kali conversion was unreliable.
    assert mods["red_kali_op01"]["image"] == "red-kali"


def test_offense_windows_operator_takes_the_setup_at_boot(redstack):
    """The offense Windows operator has no WinRM, so its kit and its hosts file
    ride the boot script: it takes the operator setup script verbatim as a
    metadata key and a hosts block naming the range. No other host does, and the
    hosts block names each host by its canvas id plus the conventional alias the
    MobaXterm sessions use (mythic/sliver/adaptix/redirector/kali/guac). See
    operator_setup.ps1 and the /etc/hosts PAI item."""
    mods = modules(redstack)
    winop = mods["red_win_op01"]
    assert winop["operator_setup"] is True
    assert "scripts/operator_setup.ps1" in winop["operator_setup_script"]
    # It also takes the stack's SSH key, so MobaXterm key-auths instead of
    # prompting for the password. The Guacamole key, already authorized for the
    # platform account on every host, so nothing new has to be trusted.
    assert winop["operator_ssh_key"] == \
        "${tls_private_key.guacamole.private_key_openssh}"
    hosts = winop["operator_hosts"]
    # Canvas id first (the alias of record), conventional alias appended.
    assert "myth-ts01 mythic" in hosts
    assert "sliv-ts01 sliver" in hosts
    assert "apache-rd01 redirector" in hosts
    assert "kali-op01 kali" in hosts
    assert "jump-bx01 guac" in hosts
    assert "module.red_myth_ts01.private_address" in hosts
    # The win-op must NOT reference its own private_address, or Terraform sees a
    # dependency cycle (operator_hosts -> its own instance -> operator_hosts).
    assert "win-op01" not in hosts
    assert "module.red_win_op01.private_address" not in hosts
    # No other host runs the setup.
    assert "operator_setup" not in mods["red_kali_op01"]
    assert "operator_setup" not in mods["red_apache_rd01"]


def test_offense_windows_operator_takes_the_setup_on_aws_and_azure(redstack):
    """The same boot delivery exists on every cloud backend, differing only in
    mechanism: AWS and Azure embed the script base64-encoded (it has here-strings
    of its own), GCP fetches it from the metadata server. All three name the
    range in operator_hosts and gate on the offense Windows operator."""
    for provider in ("aws", "azure"):
        # Azure's peering capability trips on this ops fixture (CAP004), which is
        # unrelated to the boot wiring under test; skip validation to exercise the
        # codegen. AWS validates cleanly and is checked the same way.
        winop = _modules_for(redstack, provider=provider,
                             skip_validation=True)["red_win_op01"]
        assert winop["operator_setup"] is True, provider
        encoder = "base64gzip" if provider == "aws" else "base64encode"
        assert encoder in winop["operator_setup_script_b64"], provider
        assert "myth-ts01 mythic" in winop["operator_hosts"], provider
        assert "kali-op01 kali" in winop["operator_hosts"], provider


def test_the_aws_operator_boot_script_fits_in_user_data():
    """AWS caps user_data at 16384 bytes and fails apply outright when it does
    not fit -- "expected length of user_data to be in the range (0 - 16384)".
    Plain base64 of operator_setup.ps1 is 13808 bytes, which plus the boot
    wrapper is ~18.6KB, so the first AWS offense deploy could never have worked.
    Hence base64gzip. Growing the setup script is fine; growing it past the
    budget is not, and this is the only place that would say so before apply.

    GCP carries the same script in a metadata key (256KB), so it is unaffected.
    """
    import base64
    import gzip

    assets = ROOT / "src/redstackpro/assets/terraform"
    script = (assets / "scripts/operator_setup.ps1").read_bytes()
    wrapper = (assets / "modules/aws/host/windows-setup.ps1.tftpl").read_bytes()

    payload = len(base64.b64encode(gzip.compress(script, 9)))
    total = payload + len(wrapper)
    assert total < 16384, (
        "AWS user_data would be %d bytes, over the 16384 limit "
        "(payload %d + wrapper %d)" % (total, payload, len(wrapper)))


def test_setup_script_is_shipped_for_every_provider(redstack):
    """The generated terraform reads operator_setup.ps1 with file(), so it must be
    in the export tree or terraform init fails. static_files ships it for each."""
    from redstackpro.export import static_files
    for provider in ("gcp", "aws", "azure"):
        assert "terraform/scripts/operator_setup.ps1" in static_files(provider), \
            provider


# -- firewall, derived from edges

def test_redirector_accepts_public_traffic(redstack):
    rule = firewall_rules(redstack)["in_red_apache_rd01_443"]
    assert rule["source_ranges"] == ["0.0.0.0/0"]
    assert rule["target_tags"] == ["red-apache-rd01"]


def test_redirector_opens_port_80_for_certbot(redstack):
    # Let's Encrypt validates the ACME http-01 challenge over HTTP on 80, whatever
    # port the redirector fronts on, so every redirector keeps 80 open to the
    # internet or an otherwise correct letsencrypt cert never issues.
    rule = firewall_rules(redstack)["acme_in_red_apache_rd01"]
    ports = [p for a in rule.get("allow", []) for p in a.get("ports", [])]
    assert "80" in ports
    assert rule["source_ranges"] == ["0.0.0.0/0"]
    assert rule["target_tags"] == ["red-apache-rd01"]


def test_teamserver_accepts_only_its_redirectors(rollover):
    rules = firewall_rules(rollover)
    forwarding = {name: r for name, r in rules.items()
                  if r.get("target_tags") == ["red-myth-ts01"]}
    # The rollover pool lives in a peered network, so the teamserver names the
    # redirector subnet by CIDR rather than by tag. Both redirectors share it,
    # and the subnet holds nothing but redirectors, so it is still the pool and
    # only the pool. See 0030.
    sources = {c for r in forwarding.values() for c in r.get("source_ranges", [])}
    assert sources == {"10.31.10.0/24"}, "the redirector subnet, and only it"


def test_no_teamserver_is_publicly_reachable(redstack):
    """A rule with NO target_tags applies to every instance in the network, so
    it counts as reaching the teamservers too. The ops-mode intra-stack rule is
    exactly that shape, and the whole point of checking it here is that opening
    the stack internally must not open it to the internet."""
    for name, rule in firewall_rules(redstack).items():
        targets = rule.get("target_tags")
        hits_teamserver = (targets is None
                           or "red-myth-ts01" in targets
                           or "red-sliv-ts01" in targets)
        if hits_teamserver:
            assert "0.0.0.0/0" not in rule.get("source_ranges", []), \
                "%s exposes a teamserver to the internet" % name


def test_collector_ingress_names_only_its_senders(redstack):
    rules = firewall_rules(redstack)
    same = rules["log_red_open_log01"]
    assert same["target_tags"] == ["red-open-log01"]
    # The teamservers share the collector's network and are named by tag; the
    # redirector ships across the peering, so it is a separate CIDR rule. See 0030.
    assert set(same["source_tags"]) == {"red-myth-ts01", "red-sliv-ts01", "red-adpx-ts01"}
    assert same["allow"][0]["ports"] == ["5044"]
    peered = rules["log_red_open_log01_peered"]
    assert peered["target_tags"] == ["red-open-log01"]
    assert peered["source_ranges"] == ["10.31.10.0/24"]


def test_collector_source_is_tags_not_a_cidr(redstack):
    """Source restriction derives from logs_to edges, not from the segment
    range, so a host in the same segment without an edge is not permitted."""
    rule = firewall_rules(redstack)["log_red_open_log01"]
    assert "source_ranges" not in rule


def test_management_ssh_only_from_the_jumpbox(redstack):
    rule = firewall_rules(redstack)["mgmt_out_red_jump_bx01_22"]
    assert rule["source_tags"] == ["red-jump-bx01"]
    assert rule["allow"][0]["ports"] == ["22"]
    assert "red-jump-bx01" not in rule["target_tags"], \
        "the jumpbox does not proxy to itself"


def test_a_windows_host_gets_winrm_not_ssh(redstack):
    """Opening 22 to a Windows box opens nothing. The management rule follows
    the same branch the Ansible connection plugin does. See 0019."""
    rules = firewall_rules(redstack)
    assert "red-win-op01" not in rules["mgmt_out_red_jump_bx01_22"]["target_tags"]
    winrm = rules["mgmt_out_red_jump_bx01_5986"]
    assert winrm["target_tags"] == ["red-win-op01"]
    assert winrm["source_tags"] == ["red-jump-bx01"]
    # guacd on the jumpbox also needs 3389 to render the Windows RDP tile.
    rdp = rules["mgmt_out_red_jump_bx01_3389"]
    assert rdp["target_tags"] == ["red-win-op01"]
    assert rdp["source_tags"] == ["red-jump-bx01"]


def _minimalc2_gui():
    """The GUI template: a desktop:true Kali operator, no Windows operator at
    all. Ships one field short like every redirector-bearing example (RDR001),
    so the hostname is filled the same way the CLI and CI do."""
    doc = json.loads(
        (ROOT / "frontend/public/minimalc2-gui.json").read_text(encoding="utf-8"))
    return set_redirector_hostname(doc, "cdn.redteam.test")


def test_gcp_gui_operator_opens_3389_and_gets_a_bigger_disk():
    """A desktop:true Kali operator is still reached over ssh/ansible (22), but
    guacd also needs 3389 for its RDP tile, and xfce+xrdp on top of the Kali
    metapackage needs more than the module's 30 GB default. See is_gui_operator
    and CAR008."""
    doc = _minimalc2_gui()
    mods = modules(doc)
    op = mods["red_kali_op01"]
    assert op["disk_size_gb"] == 50
    rules = firewall_rules(doc)
    assert "red-kali-op01" in rules["mgmt_out_red_jump_bx01_22"]["target_tags"]
    assert "red-kali-op01" in rules["mgmt_out_red_jump_bx01_3389"]["target_tags"]


def test_aws_gui_operator_opens_3389_and_gets_a_bigger_disk():
    doc = _minimalc2_gui()
    mods = aws_modules(doc)
    op = mods["red_kali_op01"]
    assert op["disk_size_gb"] == 50
    rules = aws_rules(doc)
    assert rules["mgmt_out_red_jump_bx01_red_kali_op01"]["from_port"] == 22
    assert rules["mgmt_out_red_jump_bx01_red_kali_op01_rdp"]["from_port"] == 3389


def test_offense_jumpbox_opens_the_guacamole_portal(redstack):
    """Guacamole runs on the jumpbox in every mode, so the offense topology's
    jumpbox must open 443 to the operator, not only a defensive range."""
    rule = firewall_rules(redstack)["guac_in_red_jump_bx01"]
    assert rule["allow"][0]["ports"] == ["443"]
    assert rule["target_tags"] == ["red-jump-bx01"]


def test_operator_access_is_a_variable_not_a_wildcard(redstack):
    rule = firewall_rules(redstack)["mgmt_in_red_jump_bx01"]
    assert rule["source_ranges"] == "${var.operator_source_ranges}"


def test_jumpbox_foothold_accepts_its_own_segment(redstack):
    """The jumpbox is the range's initial-access foothold: a coerced or relayed
    NTLM auth (or any pivoted callback) that a range host initiates back to an
    operator listener on it must be allowed. This is internal (range-segment)
    surface, so the source is the segment CIDR, never the operator wildcard, and
    it is all-protocol like the AD hosts' intra-segment rule."""
    rule = firewall_rules(redstack)["foothold_in_red_jump_bx01"]
    assert rule["allow"][0]["protocol"] == "all"
    assert rule["target_tags"] == ["red-jump-bx01"]
    assert isinstance(rule["source_ranges"], list)
    assert "/" in "".join(rule["source_ranges"])           # a CIDR, not a var
    assert "operator_source_ranges" not in "".join(rule["source_ranges"])


def test_operator_reaches_each_teamserver_control_plane(redstack):
    """P7: an operator box drives each teamserver over its C2 control port
    (Mythic 7443, Sliver 31337, Adaptix 4321). The beacon channel rides the
    fronts edge; this is the separate operator->teamserver management path.
    Operators and teamservers share the main network here, so the source is the
    operator tags, not a wildcard."""
    rules = firewall_rules(redstack)
    expected = {"red-myth-ts01": "7443", "red-sliv-ts01": "31337",
                "red-adpx-ts01": "4321"}
    for ts, port in expected.items():
        rule = rules["ctl_%s" % ts.replace("-", "_")]
        assert rule["allow"][0]["ports"] == [port]
        assert rule["target_tags"] == [ts]
        assert set(rule["source_tags"]) == {"red-kali-op01", "red-win-op01"}
        assert "source_ranges" not in rule           # not an internet wildcard


def test_generic_teamserver_opens_no_operator_control_path(redstack):
    """A teamserver with an unset/unknown C2 gets no control rule: the secure
    default. Flip Mythic to a generic teamserver and its ctl rule disappears."""
    import copy
    g = copy.deepcopy(redstack)
    for node in g["nodes"]:
        if node["id"] == "myth-ts01":
            node["overlay"].pop("c2", None)
    assert "ctl_red_myth_ts01" not in firewall_rules(g)
    # the others, still C2-typed, keep theirs
    assert "ctl_red_sliv_ts01" in firewall_rules(g)


def test_aws_operator_reaches_each_teamserver_control_plane(redstack):
    """The AWS mirror of P7: one ingress rule per operator/port, sourced by the
    operator's security group (same VPC), opening each teamserver's C2 control
    port. Never an internet wildcard."""
    rules = aws_rules(redstack)
    rule = rules["ctl_red_myth_ts01_red_kali_op01_7443"]
    assert rule["from_port"] == 7443 and rule["to_port"] == 7443
    assert "security_group_id" in rule["referenced_security_group_id"]
    assert "cidr_ipv4" not in rule
    assert "ctl_red_sliv_ts01_red_win_op01_31337" in rules
    assert "ctl_red_adpx_ts01_red_kali_op01_4321" in rules


def test_parallel_chains_rules_land_in_the_right_networks(parallel_chains):
    text = files(parallel_chains)["terraform/firewall.tf"]
    assert "module.red_main_net02.self_link" in text
    assert "module.red_main_net03.self_link" in text


# -- outputs

def test_addresses_output_covers_every_host(redstack):
    text = files(redstack)["terraform/outputs.tf"]
    assert "redstackpro_addresses" in text
    for node in redstack["nodes"]:
        if node["kind"] in ("network", "segment"):
            continue
        assert '"red-%s"' % node["id"] in text


def test_rollover_pool_is_an_output(rollover):
    text = files(rollover)["terraform/outputs.tf"]
    assert "redirector_pools" in text
    assert "module.red_apache_rd01.public_address" in text
    assert "module.red_apache_rd02.public_address" in text


# -- secrets

def test_no_credentials_or_key_material(redstack):
    joined = "\n".join(files(redstack).values())
    assert "BEGIN" not in joined, "no key material"
    assert "credentials =" not in joined, "no provider credentials block"
    assert "ssh-rsa" not in joined and "ssh-ed25519" not in joined
    assert "var.ssh_public_key" in joined, "the key is a variable, not a value"


def test_tfvars_ships_empty(redstack):
    tfvars = files(redstack)["terraform/terraform.tfvars"]
    assert 'project        = ""' in tfvars
    assert 'ssh_public_key = ""' in tfvars


def test_source_ranges_literal_and_expression_render_differently(redstack):
    """A list valued variable is emitted unwrapped. Wrapping it produces a list
    of lists, which terraform validate rejects."""
    text = files(redstack)["terraform/firewall.tf"]
    assert "source_ranges = var.operator_source_ranges" in text
    assert "source_ranges = [var.operator_source_ranges]" not in text
    assert 'source_ranges = ["0.0.0.0/0"]' in text


# ---------------------------------------------------------------- aws
#
# The module blocks are mechanical. The firewall is not: GCP restricts a source
# by network tag, which is a string, and AWS by security group reference, which
# is a resource. 0015 named this as the place the abstraction leaks, so it is
# where the tests go.

def aws(topology):
    return files(topology, provider="aws")


def aws_modules(topology):
    parsed = parse(aws(topology)["terraform/main.tf"])
    out = {}
    for block in parsed.get("module", []):
        out.update(block)
    return out


def aws_rules(topology):
    parsed = parse(aws(topology)["terraform/firewall.tf"])
    out = {}
    for block in parsed.get("resource", []):
        for name, body in block.get(
                "aws_vpc_security_group_ingress_rule", {}).items():
            out[name] = body
    return out


def test_aws_output_is_parseable_hcl(redstack):
    for text in aws(redstack).values():
        parse(text)


def test_aws_makes_one_module_per_node(redstack):
    peerings = sum(1 for e in redstack["edges"] if e["role"] == "peers")
    assert len(aws_modules(redstack)) == len(redstack["nodes"]) + peerings


def test_aws_host_references_its_segment_and_network(redstack):
    mods = aws_modules(redstack)
    assert mods["red_myth_ts01"]["subnet_id"] == "${module.red_c2_sub01.subnet_id}"
    assert mods["red_myth_ts01"]["vpc_id"] == "${module.red_main_net01.id}"


def test_aws_restricts_by_security_group_not_by_range(redstack):
    """The leak. A GCP rule names a tag; an AWS rule names a group that has to
    exist as a resource, which is why the host module owns one. Shown on a
    same-VPC rule; across a peering the source is a CIDR instead."""
    rule = aws_rules(redstack)["log_red_open_log01_red_myth_ts01"]
    assert rule["referenced_security_group_id"] == \
        "${module.red_myth_ts01.security_group_id}"
    assert "cidr_ipv4" not in rule


def test_aws_fans_a_shared_sink_into_one_rule_per_sender(redstack):
    """A security group rule carries exactly one source, so the fan in that is
    one rule on GCP is several here. This is the shape 0015 predicted. A sender
    in the collector's VPC names a group; one across a peering names a CIDR."""
    rules = aws_rules(redstack)
    senders = [e["source"] for e in redstack["edges"]
               if e["role"] == "logs_to" and e["target"] == "open-log01"]
    assert len(senders) > 1, "the example is meant to have several shippers"
    for sender in senders:
        name = "log_red_open_log01_red_%s" % sender.replace("-", "_")
        assert name in rules, name
        rule = rules[name]
        # Exactly one source per rule, a group in the same VPC or a CIDR across
        # the peering, never both.
        assert ("referenced_security_group_id" in rule) ^ ("cidr_ipv4" in rule)
    # The teamservers share the collector VPC, so they are named by group.
    assert rules["log_red_open_log01_red_myth_ts01"]["referenced_security_group_id"] == \
        "${module.red_myth_ts01.security_group_id}"
    # The redirector ships across the peering, so it is named by CIDR -- and the
    # CIDR is the PUBLIC subnet it was relocated into, not its declared segment.
    # A public-addressed host leaves its segment on AWS (0054), so the declared
    # range would not contain it. GCP keeps the host in its subnet and only
    # attaches an address, which is why the GCP tests above still name the
    # segment.
    assert rules["log_red_open_log01_red_apache_rd01"]["cidr_ipv4"] == \
        "10.31.255.240/28"


def test_aws_jumpbox_foothold_accepts_its_own_segment(redstack):
    """The AWS mirror of the GCP foothold rule: a coerced/relayed NTLM auth (or
    any pivoted callback) a range host initiates back to an operator listener on
    the jumpbox must be allowed. Internal (segment) surface, so the source is the
    segment CIDR, never the operator wildcard, and it is every protocol."""
    rule = aws_rules(redstack)["foothold_in_red_jump_bx01"]
    assert rule["ip_protocol"] == "-1"                     # every protocol/port
    assert "/" in rule["cidr_ipv4"]                        # a CIDR, not a var
    assert "operator_source_ranges" not in rule["cidr_ipv4"]


def test_aws_operator_access_stays_a_variable(redstack):
    rule = aws_rules(redstack)["mgmt_in_red_jump_bx01"]
    assert rule["for_each"] == "${toset(var.operator_source_ranges)}"
    assert rule["cidr_ipv4"] == "${each.value}"


def test_aws_windows_host_gets_winrm_and_a_listener(redstack):
    """A fresh Windows image has no listener on 5986, and opening 22 to it opens
    nothing. Both halves have to be true or the operators play cannot run."""
    assert aws_modules(redstack)["red_win_op01"]["windows"] is True
    assert aws_modules(redstack)["red_kali_op01"]["windows"] is False
    assert aws_rules(redstack)["mgmt_out_red_jump_bx01_red_win_op01"]["from_port"] == 5986
    assert aws_rules(redstack)["mgmt_out_red_jump_bx01_red_kali_op01"]["from_port"] == 22
    # guacd on the jumpbox also needs 3389 to render the Windows RDP tile.
    assert aws_rules(redstack)["mgmt_out_red_jump_bx01_red_win_op01_rdp"]["from_port"] == 3389


def test_aws_internal_hosts_are_private_behind_a_nat(redstack):
    """The exposure model: only the jumpbox and the redirector take a public
    address; every internal host (teamservers, operators, collector) is private,
    so it cannot be scanned or reached from the internet, and egresses through a
    NAT gateway. See 0021."""
    mods = aws_modules(redstack)
    ref = lambda nid: "red_" + nid.replace("-", "_")
    public = {"red_jump_bx01", "red_apache_rd01"}
    hosts = [n for n in redstack["nodes"]
             if n["kind"] not in ("network", "segment")]
    for node in hosts:
        want = ref(node["id"]) in public
        assert mods[ref(node["id"])]["public_address"] is want, node["id"]
    # The main network builds a NAT gateway for its private members; the
    # redirector network holds only the public redirector, so it needs none.
    assert mods["red_main_net01"]["create_nat"] is True
    assert mods["red_rdir_net01"]["create_nat"] is False


def test_aws_gives_a_stable_ip_only_to_the_hosts_reached_from_outside(redstack):
    """The jumpbox and the redirector are addressed from outside, so they get an
    Elastic IP that survives a stop and start; every other host keeps the
    auto-assigned address it uses only for outbound, which may change."""
    mods = aws_modules(redstack)
    ref = lambda nid: "red_" + nid.replace("-", "_")
    for node in redstack["nodes"]:
        if node["kind"] in ("network", "segment"):
            continue
        expected = node["kind"] in ("jumpbox", "redirector")
        assert mods[ref(node["id"])]["elastic_ip"] is expected, node["id"]


def test_aws_gives_an_egress_ip_to_an_addressless_host_on_an_internet_segment():
    """redStack pattern: an address-less host on an internet-exposure (IGW-routed)
    segment has no NAT to reach, so it takes an auto-assigned public IP for egress,
    with the security group still locking inbound. Without it the operator has no
    route out and cannot even apt update, which stranded the Kali operator on AWS.
    See 0021."""
    import json
    topo = json.loads((ROOT / "frontend/public/minimalc2-cli.json").read_text())
    for n in topo["nodes"]:
        if n["kind"] == "redirector":
            n.setdefault("overlay", {})["hostname"] = "cdn.redteam.test"
    mods = _modules_for(topo, provider="aws")
    # Select hosts by kind, not by a hardcoded id: a teamserver's default id slug
    # encodes its C2 (myth/sliv/adpx), so keying on the id breaks the moment the
    # C2 is swapped. What is under test is the kind's routing, not the C2.
    prefix = topo.get("prefix", "red")

    def ref(kind):
        nid = next(n["id"] for n in topo["nodes"] if n["kind"] == kind)
        return "%s_%s" % (prefix, nid.replace("-", "_"))

    op, ts = ref("operator"), ref("teamserver")
    # The operator sits on the internet-exposure mgmt segment with no Elastic IP,
    # so it needs an auto-assigned public IP purely for egress.
    assert mods[op]["public_address"] is False
    assert mods[op]["auto_public_ip"] is True
    # The teamserver sits on a local, NAT-routed segment: private, egress via NAT.
    assert mods[ts]["public_address"] is False
    assert mods[ts]["auto_public_ip"] is False


def test_aws_skips_the_gateway_when_nothing_needs_it(redstack):
    """A NAT gateway bills by the hour, so it is not created speculatively.

    Validation is skipped because cutting every segment's egress is a topology the
    validator objects to on its own grounds, and what is under test here is what
    the backend renders rather than whether the topology is a good one."""
    for node in redstack["nodes"]:
        if node["kind"] == "segment":
            node["overlay"]["egress"] = "none"
    parsed = parse(files(redstack, provider="aws", skip_validation=True)
                   ["terraform/main.tf"])
    mods = {}
    for block in parsed.get("module", []):
        mods.update(block)
    assert mods["red_main_net01"]["create_nat"] is False
    assert "nat_subnet_cidr" not in mods["red_main_net01"]


def test_aws_gateway_says_so_when_the_network_is_full(redstack):
    """Filling the network is a topology problem, and the message says which."""
    from redstackpro.terraform import TerraformPlan
    for node in redstack["nodes"]:
        if node["id"] == "main-net01":
            node["overlay"]["cidr"] = "10.30.0.0/24"
        if node["kind"] == "segment":
            node["overlay"]["cidr"] = "10.30.0.0/24"
    plan = TerraformPlan(redstack, provider="aws")
    with pytest.raises(GenerationError) as exc:
        plan.spare_subnet("main-net01")
    assert "red-main-net01" in str(exc.value)


def test_aws_emits_no_credentials(redstack):
    joined = "\n".join(aws(redstack).values())
    assert "BEGIN" not in joined
    assert "access_key" not in joined and "secret_key" not in joined
    assert 'ssh_public_key = ""' in joined, "the key is a variable, not a value"


def test_aws_declares_only_capabilities_it_renders(redstack, registry):
    """The registry says what aws can do. Editing that list to match what got
    built is the wrong direction, so this checks the other one."""
    rendered = "\n".join(aws(redstack).values()) + "\n".join(
        (ROOT / p).read_text()
        for p in [
            "src/redstackpro/assets/terraform/modules/aws/network/main.tf",
            "src/redstackpro/assets/terraform/modules/aws/segment/main.tf",
            "src/redstackpro/assets/terraform/modules/aws/host/main.tf",
            "src/redstackpro/assets/terraform/modules/aws/peering/main.tf",
        ])
    evidence = {
        "routing_domain": "aws_vpc",
        "subnet": "aws_subnet",
        "compute": "aws_instance",
        # Taken from the generator's own map rather than written out here. A
        # literal made this test fail on a deliberate Debian bump, in a file that
        # has nothing to do with which Debian we ship -- friction with no signal.
        # Reading the map also makes the assertion stronger: it checks that what
        # the generator SAYS it uses is what it actually renders, which a
        # hardcoded string cannot.
        "linux_image": aws_images.DEFAULT_IMAGES["debian"][1].rstrip("*"),
        "windows_image": "Windows_Server-2022",
        "public_address": "associate_public_ip_address",
        "outbound_routing": "aws_nat_gateway",
        "private_dns": "enable_dns_hostnames",
        "network_peering": "aws_vpc_peering_connection",
        # The mixed shape works because an addressed host is moved out of the
        # segment's NAT-routed subnet and into the network's IGW-routed public one,
        # which is the resource that proves it. See 0054 and the CAP003 retirement.
        "mixed_exposure_segment": 'aws_subnet" "public',
    }
    for capability in registry.capabilities("aws"):
        assert capability in evidence, \
            "aws declares %s and nothing here shows it is real" % capability
        assert evidence[capability] in rendered, capability


def test_aws_honors_the_named_linux_os(redstack):
    """AWS used to ignore os: every non-Windows host resolved to the Debian
    default, so a lab pinned to ubuntu_2204 or debian_12 silently booted Debian
    13. Each named distribution must now resolve to its own owner/pattern, and
    the two must be distinct from each other and from the default."""
    from redstackpro.terraform import TerraformPlan
    plan = TerraformPlan(redstack, provider="aws")
    default = aws_images.DEFAULT_IMAGES["debian"]

    def linux(os):
        # A collector, not an AD host kind: with os unset an AD kind defaults to
        # Windows, so this exercises the Linux branch for the unset case too.
        return aws_images.image_for(
            plan, {"id": "c2-col01", "kind": "collector", "overlay": {"os": os}})

    ubuntu = linux("ubuntu_2204")
    debian12 = linux("debian_12")
    assert ubuntu != default and "jammy" in ubuntu[1]
    assert debian12 == ("136693071363", "debian-12-amd64-*")
    assert ubuntu != debian12
    # Unset still falls back to the Debian default, the unchanged behavior. The
    # generic "linux" (GOAD's syrax uses it) does too rather than erroring.
    assert linux(None) == default
    assert linux("linux") == default


def test_aws_rejects_an_unknown_os(redstack):
    """An unrecognized os is a topology error with a clean message naming the node
    and the bad value, not a bare KeyError. Covers the operator branch (where the
    old code indexed DEFAULT_IMAGES directly) and the Linux host branch."""
    from redstackpro.terraform import TerraformPlan
    plan = TerraformPlan(redstack, provider="aws")
    for node in (
            {"id": "cyb-srv09", "kind": "srv", "overlay": {"os": "plan9"}},
            {"id": "op-op01", "kind": "operator", "overlay": {"os": "plan9"}}):
        with pytest.raises(GenerationError) as exc:
            aws_images.image_for(plan, node)
        assert "plan9" in str(exc.value) and node["id"] in str(exc.value)


def test_the_linux_default_is_new_enough_for_the_toolchain():
    """The default Linux image is a TOOLCHAIN decision, not a taste one.

    certipy-ad 5.x declares Requires-Python >=3.12. Debian 12 ships 3.11, so pip
    silently skipped every 5.x release and installed 4.8.2 instead -- which then
    failed to start at all, because it imports pkg_resources and setuptools
    removed that in v81. The result was a jumpbox where certipy was installed, on
    PATH, and had never once run, and where ESC13 through ESC16 had no tooling
    whatever the range planted.

    So dropping back to a Debian whose Python is below 3.12 silently breaks the
    AD CS half of every walkthrough. If that is ever deliberate, this test is the
    place to argue with.
    """
    from redstackpro.terraform import gcp as gcp_images
    from redstackpro.terraform import azure as azure_images
    from redstackpro.terraform import proxmox as proxmox_images

    def release(text):
        m = re.search(r"debian[-_](\d+)", text)
        return int(m.group(1)) if m else None

    defaults = {
        "gcp": gcp_images.DEFAULT_IMAGES["debian"],
        "aws": aws_images.DEFAULT_IMAGES["debian"][1],
        "azure": azure_images.LINUX_IMAGES["debian"][1],
        "proxmox": proxmox_images.LINUX_IMAGES["debian"],
    }
    for provider, image in defaults.items():
        got = release(image)
        assert got is not None, "%s: cannot tell which Debian %r is" % (provider, image)
        assert got >= 13, (
            "%s defaults to Debian %d, whose Python is older than certipy 5 "
            "requires; the AD CS toolchain silently degrades to a build that "
            "does not run" % (provider, got))

    # Kali's stand-in base on the providers with no real Kali image is a BASE,
    # not something a topology asked for, so it moves with the default. Kali tracks
    # Debian testing, which makes the newer base the closer stand-in as well as
    # the consistent one.
    for provider, image in (("azure", azure_images.LINUX_IMAGES["kali"][1]),
                            ("proxmox", proxmox_images.LINUX_IMAGES["kali"])):
        assert release(image) >= 13, (
            "%s stands Kali up on Debian %d while everything else is newer"
            % (provider, release(image)))

    # And a topology that NAMES the old one still gets it: pinning a lab to an older
    # distribution is a legitimate thing to want -- an old interpreter or an old
    # OpenSSL is a lab in itself -- and quietly upgrading it would change what
    # that lab teaches. Nothing we ship names it, so this is a lever, not a
    # leftover.
    assert release(gcp_images.LINUX_IMAGES["debian_12"]) == 12
    assert release(azure_images.LINUX_IMAGES["debian_12"][1]) == 12
    assert release(proxmox_images.LINUX_IMAGES["debian_12"]) == 12


def test_a_tool_is_verified_by_running_it_not_by_statting_it():
    """Installed, on PATH, and usable are three different facts.

    The jumpbox task named "verify the toolchain is actually runnable" used to
    call stat, and stayed green for months over a certipy that raised on import
    before doing anything. The operator role checked nothing at all.
    """
    import yaml as _yaml
    checks = {
        "jumpbox": ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.jumpbox/tasks/toolkit.yml",
        "operator": ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.operator/tasks/toolchain.yml",
    }
    for role, path in checks.items():
        tasks = _yaml.safe_load(path.read_text(encoding="utf-8"))
        verify = [t for t in tasks
                  if "verif" in (t.get("name") or "").lower()
                  and "run" in (t.get("name") or "").lower()]
        assert verify, "%s has no task that verifies its tools run" % role
        for task in verify:
            assert "ansible.builtin.command" in task, (
                "%s verifies by %s rather than by running the tool"
                % (role, [k for k in task if not k.startswith(("name", "loop", "when"))]))
            assert "--help" in str(task["ansible.builtin.command"].get("cmd", "")), role
        # And the failure must name an import error, which is the breakage a
        # file-existence check cannot see.
        assert "ModuleNotFoundError" in path.read_text(encoding="utf-8"), (
            "%s does not treat an import error as a broken tool" % role)


def test_aws_pins_one_zone_for_every_subnet(redstack):
    """Left to AWS each subnet gets whichever zone it is given, so two applies
    differ and traffic that should be local crosses zones and bills for it."""
    mods = aws_modules(redstack)
    for name, body in mods.items():
        if "cidr" in body and "kind" not in body:
            assert body["availability_zone"] == "${local.availability_zone}", name

    text = aws(redstack)["terraform/main.tf"]
    assert "aws_availability_zones" in text, "the default has to come from somewhere"
    assert "coalesce(" in text, "and tfvars has to be able to override it"
    assert "availability_zone" in aws(redstack)["terraform/variables.tf"]


def test_aws_uses_the_official_kali_image(redstack):
    """os kali gets a real Kali box on AWS, the same as it does on GCP, rather
    than Debian with the archive repointed at run time. See the 0020 amendment."""
    mods = aws_modules(redstack)
    assert "kali" in mods["red_kali_op01"]["image_name"]
    assert mods["red_kali_op01"]["image_owner"] != mods["red_myth_ts01"]["image_owner"], \
        "a Kali box and a Debian box do not come from the same publisher"
    assert "debian" in mods["red_myth_ts01"]["image_name"]


def test_the_export_says_what_the_account_has_to_do_first(redstack, registry):
    """The Kali listing needs a subscription and an export cannot take it. An
    apply that stops with OptInRequired names the problem, not the remedy."""
    from redstackpro.export import compile_topology
    readme = compile_topology(redstack, registry, provider="aws")["README.md"]
    assert "subscription" in readme
    assert "availability_zone" in readme
    assert "subscription" not in compile_topology(
        redstack, registry, provider="gcp")["README.md"]


# -- native defense range backends (aws and gcp)

import json


def _range_doc():
    return json.loads(
        (ROOT / "frontend/public/goad/goad-light.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("provider", ["aws", "gcp"])
def test_range_backend_emits_range_apparatus(provider):
    """A defense range compiles for both native backends with the same shape:
    Windows controllers on a real 2019 image, the low-touch lab password and
    Guacamole outputs, WinRM boot, and the range firewall rules."""
    out = files(_range_doc(), provider=provider)
    main = out["terraform/main.tf"]
    fw = out["terraform/firewall.tf"]

    assert "2019" in main                      # controllers resolve to a real image
    assert "enable_winrm" in main              # Windows hosts stand up a listener
    assert "lab_password" in main
    assert 'output "guacamole"' in main
    assert "ad_intra" in fw or "ad-intra" in fw   # AD intra-segment, from joins
    assert "443" in fw                            # Guacamole portal to the jumpbox


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure", "proxmox", "esxi"])
def test_the_portal_login_is_the_platform_account_not_operator(provider):
    """P1.7: the Windows local account and the Guacamole login collapsed into the
    single platform account -- blueop for a range, redop for ops -- so there is no
    separate "operator" identity left. This is a range doc, so the account is
    blueop. Guarding it because the old default was the literal "operator" and a
    regression would silently reintroduce a second account the portal and the
    Windows box would then disagree about. See naming.platform_account."""
    out = files(_range_doc(), provider=provider)
    main = out["terraform/main.tf"]
    # Whitespace-insensitive for the same reason as the windows flag below:
    # align() repads a module block whenever a longer key joins it, so a pinned
    # spacing fails on a purely cosmetic change. auto_stop_timezone did exactly
    # that to the Azure host module.
    flat = re.sub(r"[ 	]+", " ", main)
    assert 'username = "blueop"' in flat          # the portal output
    assert 'operator_username = "blueop"' in flat  # the module input
    # The overridable variable is gone; the value is compiled in by mode.
    assert 'variable "operator_username"' not in out["terraform/variables.tf"]
    assert 'var.operator_username' not in main


def test_range_rejects_a_provider_without_a_native_backend():
    from redstackpro.export import compile_topology
    with pytest.raises(GenerationError):
        compile_topology(_range_doc(), provider="digitalocean")


def test_range_proxmox_emits_vms_static_ips_and_vm_firewall():
    """The Proxmox range shape differs from the clouds: VMs (not cloud images
    per build), static addresses allocated from each segment, and a per-VM
    firewall. Windows still boots with WinRM and the low-touch credentials."""
    out = files(_range_doc(), provider="proxmox")
    main = out["terraform/main.tf"]
    fw = out["terraform/firewall.tf"]

    # Whitespace-insensitive: align() pads every key in a module block to the
    # longest one, so adding any longer field (auto_stop_timezone did) shifts
    # this line and a pinned spacing fails on a change that is purely cosmetic.
    assert "windows = true" in re.sub(r"[ 	]+", " ", main)
    assert "enable_winrm" in main
    assert "lab_password" in main
    assert 'output "guacamole"' in main
    assert "vlan_id" in main and "ip_address" in main   # static addressing
    assert "proxmox_virtual_environment_firewall_rules" in fw
    assert "intra-domain" in fw                          # AD intra, per VM
    assert "443" in fw                                   # Guacamole portal
    assert "foothold" in fw                              # jumpbox foothold ingress


def test_range_azure_emits_vms_nsg_rules_and_winrm():
    """The Azure range: a resource group, VMs with static private addresses, NSG
    rules matched by address, and the Windows WinRM self-provision extension.
    Windows carries the low-touch credentials the same as the other backends."""
    out = files(_range_doc(), provider="azure")
    main = out["terraform/main.tf"]
    fw = out["terraform/firewall.tf"]

    assert "azurerm_resource_group" in main
    # Whitespace-insensitive: align() pads every key in a module block to the
    # longest one, so adding any longer field (auto_stop_timezone did) shifts
    # this line and a pinned spacing fails on a change that is purely cosmetic.
    assert "windows = true" in re.sub(r"[ 	]+", " ", main)
    assert "enable_winrm" in main
    assert "lab_password" in main
    assert 'output "guacamole"' in main
    assert "private_ip" in main                         # static addressing
    assert "azurerm_network_security_rule" in fw
    assert "ad_intra" in fw                              # AD intra, by address
    assert "443" in fw                                   # Guacamole portal
    assert "foothold" in fw                              # jumpbox foothold ingress


def test_range_esxi_uses_vsphere_datasources_static_ips_and_no_firewall():
    """The ESXi range: vSphere data sources resolved once, VMs with static
    addresses (Linux from an OVA, Windows cloned from a template), and no
    firewall (vSphere has no managed per-VM firewall; VLANs isolate)."""
    out = files(_range_doc(), provider="esxi")
    main = out["terraform/main.tf"]
    fw = out["terraform/firewall.tf"]

    assert 'data "vsphere_datacenter"' in main
    # Whitespace-insensitive: align() pads every key in a module block to the
    # longest one, so adding any longer field (auto_stop_timezone did) shifts
    # this line and a pinned spacing fails on a change that is purely cosmetic.
    assert "windows = true" in re.sub(r"[ 	]+", " ", main)
    assert "lab_password" in main
    assert 'output "guacamole"' in main
    assert "ip_address" in main and "vlan_id" in main   # static addressing
    assert "resource" not in fw                          # no managed firewall
    assert "no rules are rendered" in fw


# -- internal_ip (0055): a range locking a host to a specific address

@pytest.mark.parametrize("provider,var", [
    ("gcp", "network_ip"), ("aws", "private_ip"), ("azure", "private_ip"),
])
def test_internal_ip_pins_the_exact_address(provider, var):
    """goad-light.json declares kingslanding's internal_ip as 192.168.56.10
    (GOAD's own canonical octet, see 0055); every provider that takes it must
    render that literal address on kingslanding's module, not an auto-assigned
    one."""
    kingslanding = _modules_for(_range_doc(), provider=provider)["cyb_kingslanding"]
    assert kingslanding[var] == "192.168.56.10"


def test_aws_puts_an_addressed_host_in_the_public_subnet():
    """AWS routes per subnet, not per instance. The segment's subnet routes to the
    NAT gateway for the internal AD hosts, so a host with a public address sharing
    it cannot answer inbound at all: replies leave through the NAT and die. That is
    what made every AWS range unreachable at its jumpbox, silently. The jumpbox
    must land in the network's public subnet instead, while the AD hosts stay in
    the segment."""
    mods = _modules_for(_range_doc(), provider="aws")
    assert mods["cyb_jumpbox"]["subnet_id"] == \
        "${module.cyb_net01.public_subnet_id}"
    assert mods["cyb_kingslanding"]["subnet_id"] == \
        "${module.cyb_sub01.subnet_id}"
    # The network has to be told to build it, and be given a range for it.
    assert mods["cyb_net01"]["create_public_subnet"] is True
    assert mods["cyb_net01"]["public_subnet_cidr"]


def test_aws_drops_a_pin_on_a_host_it_moves_to_the_public_subnet():
    """The public subnet is carved from spare network space, so a pin written
    against the segment's range cannot be honoured there -- AWS would refuse an
    address outside the subnet. The jumpbox's pin is dropped; the AD pins, which
    are the ones fidelity depends on, are untouched."""
    mods = _modules_for(_range_doc(), provider="aws")
    assert "private_ip" not in mods["cyb_jumpbox"]
    assert mods["cyb_kingslanding"]["private_ip"] == "192.168.56.10"


def test_aws_keeps_the_foothold_reaching_the_ad_hosts():
    """The all-from-segment rule is written against the segment range, which the
    relocated jumpbox is no longer in, so without an extra rule every tool run
    from the foothold against AD (SMB, LDAP, Kerberos, RPC) would be dropped. The
    rule references the jumpbox's security group, so it does not depend on which
    subnet the jumpbox ended up in."""
    parsed = parse(files(_range_doc(), provider="aws")["terraform/firewall.tf"])
    rules = {}
    for block in parsed.get("resource", []):
        rules.update(block.get("aws_vpc_security_group_ingress_rule", {}))
    name = "ad_intra_cyb_kingslanding_from_cyb_jumpbox"
    assert name in rules, sorted(rules)
    assert rules[name]["ip_protocol"] == "-1"
    assert rules[name]["referenced_security_group_id"] == \
        "${module.cyb_jumpbox.security_group_id}"


def test_gcp_leaves_the_jumpbox_in_the_range_segment():
    """The AWS relocation must not leak into GCP, where Cloud NAT serves only
    instances without an external address, so an addressed host sits happily in
    the range subnet and keeps its pinned octet."""
    mods = _modules_for(_range_doc(), provider="gcp")
    assert mods["cyb_jumpbox"]["subnetwork"] == "${module.cyb_sub01.self_link}"
    assert mods["cyb_jumpbox"]["network_ip"] == "192.168.56.4"


def test_internal_ip_pins_the_exact_address_proxmox():
    # Proxmox's ip_address carries the prefix length too (static config, not a
    # bare address), so it is checked separately from the other providers.
    kingslanding = _modules_for(_range_doc(), provider="proxmox")["cyb_kingslanding"]
    assert kingslanding["ip_address"] == "192.168.56.10/24"


def test_internal_ip_pins_the_exact_address_esxi():
    kingslanding = _modules_for(_range_doc(), provider="esxi")["cyb_kingslanding"]
    assert kingslanding["ip_address"] == "192.168.56.10"


@pytest.mark.parametrize("provider", ["gcp", "aws"])
def test_unset_internal_ip_leaves_the_default_dhcp_assignment(provider):
    """A host with no internal_ip on its overlay renders no pinned-address
    argument on GCP/AWS at all, so the provider keeps assigning one from the
    subnet's DHCP range exactly as before this feature existed."""
    doc = _range_doc()
    kingslanding = next(n for n in doc["nodes"] if n["id"] == "kingslanding")
    del kingslanding["overlay"]["internal_ip"]
    key = "network_ip" if provider == "gcp" else "private_ip"
    assert key not in _modules_for(doc, provider=provider)["cyb_kingslanding"]


# -- auto stop (0057)

def test_a_range_does_not_stop_itself_unless_asked(redstack):
    """Off by default, deliberately: a range that disappears underneath someone
    is worse than one that bills. Nothing should be emitted when unset."""
    main = generate(redstack, provider="gcp")["terraform/main.tf"]
    assert "google_compute_resource_policy" not in main
    assert "resource_policies" not in main


def test_auto_stop_becomes_a_gcp_schedule_on_every_instance(redstack):
    """GCP applies the policy itself, so the range turns off with nothing of
    ours running and no credential anywhere. Every host must reference it, or
    the ones that do not keep billing after the rest stop."""
    redstack["auto_stop"] = {"enabled": True, "at": "02:00",
                             "timezone": "Europe/London"}
    main = generate(redstack, provider="gcp")["terraform/main.tf"]

    assert 'resource "google_compute_resource_policy" "auto_stop"' in main
    assert 'schedule = "0 2 * * *"' in main
    assert 'time_zone = "Europe/London"' in main
    # vm_stop_schedule, never a delete: the provisioned forest comes back on
    # boot and destroying it would be a different, unasked-for thing.
    assert "vm_stop_schedule" in main
    assert "vm_start_schedule" not in main

    hosts = len([n for n in redstack["nodes"]
                 if n.get("kind") not in ("network", "segment")])
    assert main.count(
        "resource_policies = "
        "[google_compute_resource_policy.auto_stop.self_link]") == hosts


def test_after_hours_and_at_resolve_to_the_earlier_stop(redstack):
    """Both fields may be set and they answer different questions. The earlier
    one has to win: taking the later would let the range outlive the cap the
    operator asked for, and a cap that the other field can override is not a
    cap."""
    from redstackpro.terraform.plan import TerraformPlan

    early = dict(redstack, auto_stop={"enabled": True, "at": "00:30"})
    late = dict(redstack, auto_stop={"enabled": True, "at": "23:30"})

    # 00:30 is the earliest minute-of-day there is short of midnight, so it
    # wins against any after_hours the clock could produce today.
    plan = TerraformPlan(early)
    assert (plan.auto_stop["hour"], plan.auto_stop["minute"]) == (0, 30)

    # With a late `at` and a cap, the cap is what should bind.
    both = dict(late)
    both["auto_stop"] = {"enabled": True, "at": "23:30", "after_hours": 1}
    got = TerraformPlan(both).auto_stop
    assert (got["hour"] * 60 + got["minute"]) <= 23 * 60 + 30

    assert TerraformPlan(dict(redstack, auto_stop={"enabled": False,
                                                  "at": "02:00"})).auto_stop is None
    assert TerraformPlan(redstack).auto_stop is None


def test_auto_stop_becomes_an_azure_shutdown_schedule(redstack):
    """Azure has a purpose built per VM shutdown schedule, so like GCP it needs
    no credential and nothing of ours running. The format is NOT GCP's: HHmm
    rather than cron, and a Windows timezone id rather than an IANA name."""
    redstack["auto_stop"] = {"enabled": True, "at": "02:30", "timezone": "UTC"}
    main = generate(redstack, provider="azure",
                    skip_validation=True)["terraform/main.tf"]
    assert 'auto_stop_at       = "0230"' in main
    assert 'auto_stop_timezone = "UTC"' in main

    hosts = len([n for n in redstack["nodes"]
                 if n.get("kind") not in ("network", "segment")])
    assert main.count("auto_stop_at ") == hosts

    # And nothing at all when the canvas did not ask.
    del redstack["auto_stop"]
    assert "auto_stop_at" not in generate(
        redstack, provider="azure", skip_validation=True)["terraform/main.tf"]


def test_the_azure_timezone_is_not_silently_translated(redstack):
    """The two clouds disagree: GCP wants IANA, Azure wants a Windows timezone
    id, and they overlap only on UTC. Passing the value through unchanged means
    a wrong one fails loudly at apply rather than shifting a shutdown by hours.
    """
    redstack["auto_stop"] = {"enabled": True, "at": "02:30",
                             "timezone": "GMT Standard Time"}
    main = generate(redstack, provider="azure",
                    skip_validation=True)["terraform/main.tf"]
    assert 'auto_stop_timezone = "GMT Standard Time"' in main


# -- ops mode opens the operator's own stack internally

def test_ops_stack_is_open_internally_but_a_range_is_not(redstack):
    """An offense platform is the operator's own infrastructure, not a target,
    and segmenting it only creates friction -- the Windows operator box could
    not SSH the teamservers its own saved sessions point at, and the jumpbox
    could not reach its redirector. redStack gives every host an all-from-VPC
    rule for the same reason.

    A range must NOT get this: there the segmentation is the exercise, and what
    a lateral movement step proves depends on it.
    """
    ops = firewall_rules(redstack)
    intra = {n: r for n, r in ops.items() if n.startswith("intra_")}
    assert intra, "ops mode should open the stack internally"
    for rule in intra.values():
        # Every network in the plan, so a peered redirector is reachable too.
        assert rule["source_ranges"] == ["10.30.0.0/16", "10.31.0.0/16"]
        # No target_tags: every instance in the operator's own network.
        assert rule.get("target_tags") is None
        assert rule["allow"][0]["protocol"] == "all"


def test_a_range_keeps_strictly_edge_derived_rules():
    """The mirror of the above, against a real shipped range template rather
    than a fixture, since this is the half that must not regress."""
    import json
    import re
    goad = json.loads(
        (ROOT / "frontend/public/goad/goad.json").read_text(encoding="utf-8"))
    assert goad["mode"] == "haven"
    for provider in ("gcp", "aws"):
        fw = generate(goad, provider=provider)["terraform/firewall.tf"]
        # ad_intra_* rules are a different, edge-derived thing and stay.
        found = re.findall(r'" "(intra_[^"]+)"', fw)
        assert not found, (provider, found)


def test_aws_security_group_rule_descriptions_are_valid(redstack):
    """AWS rejects a security group rule description with a character outside
    its allowed set -- an apostrophe among them, which failed every intra rule
    on the first fresh ops deploy with "Invalid rule description". Guard every
    generated description against the documented set so codegen cannot ship one
    AWS will refuse at apply."""
    import re
    fw = generate(redstack, provider="aws")["terraform/firewall.tf"]
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "0123456789. _-:/()#,@[]+=&;{}!$*")
    descs = re.findall(r'description\s*=\s*"([^"]*)"', fw)
    assert descs, "expected rule descriptions to check"
    for d in descs:
        bad = sorted(set(d) - allowed)
        assert not bad, "description %r has invalid chars %r" % (d, bad)


def test_the_operator_setup_script_carries_no_stray_carriage_return():
    """A backslash-r inside a Windows path in this script had become a real
    carriage return byte, so every MobaXterm session named C:<CR>edstackpro
    instead of C:\redstackpro. MobaXterm read up to the CR and refused the key
    with: Unable to use key file "C:". All five sessions silently fell back to a
    password prompt, and the corruption is invisible in any printed diff because
    a CR just returns the cursor to the start of the line. Found on a live
    operator box, which is the only place it could show.

    The script is delivered verbatim to every cloud, so a stray CR anywhere in
    it is the same class of bug waiting to happen. This is a byte check.
    """
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    script = root / "src/redstackpro/assets/terraform/scripts/operator_setup.ps1"
    raw = script.read_bytes()
    assert b"\r" not in raw, "stray carriage return in operator_setup.ps1"

    text = raw.decode("utf-8")
    # And the sessions must take the path from the variable that writes the key,
    # never an inline copy, which is how the two drifted apart in the first place.
    assert "__RSP_KEY__" in text
    assert "$mobaIni.Replace('__RSP_KEY__', $RspKeyPath)" in text
    assert text.count("__RSP_KEY__%%") == 5, "one key path per saved session"


def _stopping_range_doc():
    doc = _range_doc()
    doc["auto_stop"] = {"enabled": True, "at": "23:40", "timezone": "UTC"}
    return doc


def test_aws_stops_the_range_with_a_schedule_and_no_lambda():
    """AWS has no per-instance schedule -- no answer to GCP's resource policy or
    Azure's shutdown setting -- so the stop is one EventBridge schedule calling
    the SDK directly through the universal target. No Lambda to write or pay for.
    """
    main = files(_stopping_range_doc(), provider="aws")["terraform/main.tf"]
    assert 'resource "aws_scheduler_schedule" "auto_stop"' in main
    assert "arn:aws:scheduler:::aws-sdk:ec2:stopInstances" in main
    assert 'cron(40 23 * * ? *)' in main
    # AWS takes an IANA name, the same vocabulary GCP uses, so the canvas value
    # passes straight through. Azure is the one that needs a Windows id.
    assert 'schedule_expression_timezone = "UTC"' in main
    assert "aws_lambda" not in main


def test_the_stop_permission_is_a_role_not_a_credential_on_a_host():
    """The jumpbox is the range's only public box and stays credential free
    (minimize-jumpbox-web-surface). EventBridge assumes the role itself, so no
    key material lands anywhere, and the policy names one action.
    """
    main = files(_stopping_range_doc(), provider="aws")["terraform/main.tf"]
    assert 'resource "aws_iam_role" "auto_stop"' in main
    assert '"scheduler.amazonaws.com"' in main
    flat = re.sub(r"[ \t]+", " ", main)
    assert 'Action = "ec2:StopInstances"' in flat
    # Stop, never terminate: a forest takes forty minutes to provision and comes
    # back on boot.
    assert "TerminateInstances" not in main
    # Scoped to this range's instances rather than every instance in the account.
    assert "arn:aws:ec2:${var.region}:*:instance/${module." in main


def test_no_auto_stop_means_no_iam_resource_at_all():
    """This is the stack's first IAM resource, and an operator whose credentials
    cannot create roles would fail the apply on it. A range that never asked for
    a TTL should not meet that failure.
    """
    doc = _range_doc()
    # The shared range fixture already asks for a TTL, so take it away rather
    # than assuming its absence.
    doc.pop("auto_stop", None)
    main = files(doc, provider="aws")["terraform/main.tf"]
    assert "aws_iam_role" not in main
    assert "aws_scheduler_schedule" not in main


def test_every_host_is_named_in_the_stop_list():
    """A schedule that stops some of the range still bills for the rest."""
    doc = _stopping_range_doc()
    main = files(doc, provider="aws")["terraform/main.tf"]
    body = main[main.index("aws_scheduler_schedule"):]
    hosts = [n["id"] for n in doc["nodes"]
             if n["kind"] in ("dc", "srv", "wks", "jumpbox", "siem",
                              "teamserver", "redirector", "operator",
                              "collector")]
    assert hosts, "the range fixture grew no hosts?"
    for host in hosts:
        assert host.replace("-", "_") in body.replace("-", "_"), host


# ---------------------------------------- the stop clock is counted from apply ---
#
# `after_hours` used to resolve HERE, at compile, which was the closest the
# generator could stand to the apply. The gap between the two was then eaten out
# of the TTL: a build compiled in the morning and applied that afternoon stopped
# itself part-provisioned behind a run reporting no error. deploy.sh refuses that
# at the apply boundary, which makes it loud, but the trap stayed. It is resolved
# by hashicorp/time's time_offset, which computes the instant once at apply and
# keeps it in state, so a second plan is a no-op rather than a perpetual diff.

def test_after_hours_no_longer_depends_on_when_you_compiled(redstack):
    """THE FIX, pinned where it can be seen.

    Two compiles hours apart used to differ, and the difference was the TTL
    silently shrinking. The emitted file must now be identical, because the
    clock is resolved by terraform and not by this process.
    """
    import datetime as real_dt
    from redstackpro.terraform import plan as plan_module

    redstack["auto_stop"] = {"enabled": True, "after_hours": 8, "timezone": "UTC"}

    class FrozenAt(real_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 9, 17, cls.pretend_hour, 0, tzinfo=tz)

    seen = []
    for hour in (9, 14):
        FrozenAt.pretend_hour = hour
        original = plan_module._dt.datetime
        plan_module._dt.datetime = FrozenAt
        try:
            seen.append(generate(redstack, provider="gcp")["terraform/main.tf"])
        finally:
            plan_module._dt.datetime = original

    assert seen[0] == seen[1], (
        "the export still moves with the wall clock, so staging a build ahead "
        "of deploying it still eats the TTL")
    assert "time_offset" in seen[0]


def test_after_hours_emits_the_offset_and_reads_it_on_every_provider(redstack):
    """One resource at the root, three schedules reading the same two locals."""
    redstack["auto_stop"] = {"enabled": True, "after_hours": 8, "timezone": "UTC"}

    gcp = generate(redstack, provider="gcp")
    aws = generate(redstack, provider="aws")
    # Azure refuses an ops topology on CAP004 (no peering module), which is
    # correct and not what this test is about.
    azure = generate(redstack, provider="azure", skip_validation=True)

    for files in (gcp, aws, azure):
        main = files["terraform/main.tf"]
        assert 'resource "time_offset" "auto_stop"' in main
        assert "offset_hours = 8" in main
        # Declared once, not once per host or per schedule.
        assert main.count('resource "time_offset"') == 1
        assert "hashicorp/time" in files["terraform/versions.tf"]

    assert ('schedule = "${local.rsp_stop_minute} ${local.rsp_stop_hour} * * *"'
            in gcp["terraform/main.tf"])
    assert ("cron(${local.rsp_stop_minute} ${local.rsp_stop_hour} * * ? *)"
            in aws["terraform/main.tf"])
    # Azure needs HHMM zero padded, which the bare locals cannot give it.
    assert "auto_stop_at       = local.rsp_stop_hhmm" in azure["terraform/main.tf"]


def test_a_fixed_at_is_still_a_literal_and_pulls_in_no_provider(redstack):
    """A wall-clock `at` really is known at compile, so nothing about it moves.

    Byte-for-byte what it produced before, because an input that has not changed
    must not produce a different file, and because a topology that needs no
    apply-time clock should not download a provider to resolve one. See 0010.
    """
    redstack["auto_stop"] = {"enabled": True, "at": "22:00", "timezone": "UTC"}

    gcp = generate(redstack, provider="gcp")
    aws = generate(redstack, provider="aws")
    # Azure refuses an ops topology on CAP004 (no peering module), which is
    # correct and not what this test is about.
    azure = generate(redstack, provider="azure", skip_validation=True)

    for files in (gcp, aws, azure):
        assert "time_offset" not in files["terraform/main.tf"]
        assert "hashicorp/time" not in files["terraform/versions.tf"]

    assert 'schedule = "0 22 * * *"' in gcp["terraform/main.tf"]
    assert 'cron(0 22 * * ? *)' in aws["terraform/main.tf"]
    assert 'auto_stop_at       = "2200"' in azure["terraform/main.tf"]


def test_with_both_fields_the_earlier_still_wins_but_in_hcl(redstack):
    """The comparison cannot happen at compile any more, because one side is not
    known until apply. It moves into HCL unchanged rather than quietly becoming
    whichever value the generator happened to see."""
    redstack["auto_stop"] = {"enabled": True, "at": "22:00",
                             "after_hours": 8, "timezone": "UTC"}
    main = generate(redstack, provider="gcp")["terraform/main.tf"]

    # 22:00 as a minute of day, against the offset the apply will compute.
    assert ("rsp_stop_at     = min(1320, time_offset.auto_stop.hour * 60 "
            "+ time_offset.auto_stop.minute)") in main


def test_no_auto_stop_pulls_in_no_time_provider(redstack):
    for provider in ("gcp", "aws", "azure"):
        files = generate(redstack, provider=provider, skip_validation=True)
        assert "hashicorp/time" not in files["terraform/versions.tf"]
        assert "time_offset" not in files["terraform/main.tf"]
