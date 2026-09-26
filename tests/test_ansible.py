"""The generator turns edges into variables and play order. Both are the parts
that exist nowhere else, so both need tests that fail loudly when they drift.
"""

import json
import re
from pathlib import Path

import pytest
import yaml

from redstackpro.ansible import AnsiblePlan, GenerationError, generate

ROOT = Path(__file__).resolve().parent.parent
REDIRECTOR_ROLE = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.redirector"


def test_every_decoy_enum_value_has_a_site():
    """The redirector renders a small multi-page decoy site from the catalog in
    the role's vars, keyed by the decoy enum value. A value with no catalog entry
    would deploy a redirector that fails to place its cover, and an entry missing
    its home page or 404 would deploy a broken one. The base template renders
    every page, so it must exist too.
    """
    schema = json.loads((ROOT / "src/redstackpro/schema/topology/0.5.0.json").read_text())
    decoy = schema["$defs"]["overlay_redirector"]["properties"]["gating"][
        "properties"
    ]["decoy"]["enum"]
    assert (REDIRECTOR_ROLE / "templates/decoy-site.html.j2").exists()
    sites = yaml.safe_load((REDIRECTOR_ROLE / "vars/main.yml").read_text())[
        "redstackpro_decoy_sites"
    ]
    for value in decoy:
        if value == "none":
            continue
        site = sites.get(value)
        assert site, f"no decoy site catalog entry for {value}"
        slugs = [p["slug"] for p in site["pages"]]
        assert "index" in slugs, f"{value} site has no home page"
        assert len(site["pages"]) >= 2, f"{value} site should have 2+ pages"
        assert site.get("notfound"), f"{value} site has no 404 page"


def files(topology, **kw):
    return generate(topology, **kw)


def load(files_, path):
    return yaml.safe_load(files_[path])


# -- shape

def test_generates_expected_paths(redstack):
    out = files(redstack)
    assert "ansible/inventory.yml" in out
    assert "ansible/site.yml" in out
    assert "ansible/group_vars/all.yml" in out
    assert "ansible/host_vars/art-myth-ts01.yml" in out


def test_output_is_valid_yaml(redstack):
    for path, text in files(redstack).items():
        yaml.safe_load(text)


def test_refuses_invalid_topology(minimal):
    minimal["edges"] = [e for e in minimal["edges"] if e["role"] != "manages"]
    with pytest.raises(GenerationError):
        generate(minimal)


# -- groups

def test_groups_come_from_the_registry(redstack):
    inv = load(files(redstack), "ansible/inventory.yml")
    children = inv["all"]["children"]
    # windows is auxiliary, not a kind group: it exists only to give the
    # bootstrap play a target. See 0022.
    assert set(children) == {"collectors", "jumpboxes", "operators",
                             "redirectors", "teamservers", "windows"}
    assert set(children["redirectors"]["hosts"]) == {"art-apache-rd01"}
    assert set(children["teamservers"]["hosts"]) == {
        "art-myth-ts01", "art-sliv-ts01", "art-adpx-ts01"}


def test_containers_are_not_hosts(redstack):
    inv = load(files(redstack), "ansible/inventory.yml")
    names = {h for g in inv["all"]["children"].values() for h in g["hosts"]}
    assert not any(re.search(r"-(net|sub)\d\d$", n) for n in names)


# -- injected variables

def test_fronts_collects_one_upstream_per_edge(redstack):
    """A redirector fronts as many teamservers as it has edges, each on its own
    prefix. Overwriting instead of collecting would silently drop two of the
    three."""
    rdir = load(files(redstack), "ansible/host_vars/art-apache-rd01.yml")
    assert len(rdir["upstreams"]) == 3
    by_prefix = {u["uri_prefix"]: u for u in rdir["upstreams"]}
    assert set(by_prefix) == {"/api/v1", "/cdn/assets", "/updates"}
    assert by_prefix["/api/v1"]["address"] == "<<tf:art-myth-ts01:private_address>>"
    assert by_prefix["/api/v1"]["name"] == "art-myth-ts01"


def test_a_rollover_pool_carries_the_same_prefixes(rollover):
    out = files(rollover)
    first = load(out, "ansible/host_vars/art-apache-rd01.yml")["upstreams"]
    second = load(out, "ansible/host_vars/art-apache-rd02.yml")["upstreams"]
    assert ([u["uri_prefix"] for u in first]
            == [u["uri_prefix"] for u in second])


def test_logs_to_injects_sink_address(redstack):
    ts = load(files(redstack), "ansible/host_vars/art-myth-ts01.yml")
    assert ts["log_sink_address"] == "<<tf:art-open-log01:private_address>>"


def test_collector_does_not_ship_to_itself(redstack):
    log = load(files(redstack), "ansible/host_vars/art-open-log01.yml")
    assert "log_sink_address" not in log


def test_manages_injects_proxy_jump(redstack):
    # The proxy user is the single platform account, redop in ops mode (P1.7).
    ts = load(files(redstack), "ansible/host_vars/art-myth-ts01.yml")
    assert "ProxyJump=redop@<<tf:art-jump-bx01:public_address>>" in \
        ts["ansible_ssh_common_args"]


def test_jumpbox_does_not_proxy_through_itself(redstack):
    jump = load(files(redstack), "ansible/host_vars/art-jump-bx01.yml")
    assert "ansible_ssh_common_args" not in jump


def test_host_key_policy_is_accept_new(redstack):
    ts = load(files(redstack), "ansible/host_vars/art-myth-ts01.yml")
    assert "StrictHostKeyChecking=accept-new" in ts["ansible_ssh_common_args"]
    assert "StrictHostKeyChecking=no" not in ts["ansible_ssh_common_args"]


# -- addresses

def test_the_jumpbox_is_addressed_at_its_public_address(redstack):
    # The jumpbox is the one host reached directly, so it is addressed at its
    # public address. Every other host is managed through it.
    jump = load(files(redstack), "ansible/host_vars/art-jump-bx01.yml")
    assert jump["ansible_host"] == "<<tf:art-jump-bx01:public_address>>"


def test_a_proxied_exposed_host_is_managed_at_its_private_address(redstack):
    # The redirector holds a public address for its own inbound traffic, but it
    # is managed through the jumpbox, so ssh goes to its private address. The
    # jumpbox reaching the public address would hairpin out through the internet
    # gateway and miss the management security group. See ansible.py.
    rdir = load(files(redstack), "ansible/host_vars/art-apache-rd01.yml")
    assert rdir["ansible_host"] == "<<tf:art-apache-rd01:private_address>>"
    assert "ProxyJump" in rdir["ansible_ssh_common_args"]


def test_unexposed_host_uses_private_address(redstack):
    ts = load(files(redstack), "ansible/host_vars/art-myth-ts01.yml")
    assert ts["ansible_host"] == "<<tf:art-myth-ts01:private_address>>"


def test_no_key_material_in_output(redstack):
    joined = "\n".join(files(redstack).values())
    assert "BEGIN" not in joined
    assert "redstackpro_ssh_key_path" in joined, "key is a variable, not a value"


def test_placeholders_are_not_jinja(redstack):
    """Ansible templates ansible_host, and a hyphenated id is subtraction in
    Jinja. Placeholders must not be mistakable for templates."""
    joined = "\n".join(files(redstack).values())
    assert "{{ tf." not in joined


# -- overlays

def test_overlay_values_are_namespaced(redstack):
    ts = load(files(redstack), "ansible/host_vars/art-myth-ts01.yml")
    assert ts["redstackpro_teamserver_c2"] == "mythic"


def test_operator_os_reaches_the_role(redstack):
    ops = load(files(redstack), "ansible/host_vars/art-win-op01.yml")
    assert ops["redstackpro_operator_os"] == "windows"


# -- ordering

def test_supplier_configuart_before_consumer(redstack):
    site = load(files(redstack), "ansible/site.yml")
    order = [play["hosts"] for play in site]
    assert order.index("teamservers") < order.index("redirectors")
    assert order.index("collectors") < order.index("teamservers")
    assert order[0] == "jumpboxes"


def test_every_group_gets_a_play(redstack):
    plan = AnsiblePlan(redstack)
    site = load(files(redstack), "ansible/site.yml")
    # A group holding a Windows host targets "<group>:!windows", since Windows
    # self-provisions and is not reached by a play. Normalize before comparing.
    # The hosts-mapping play is not a kind play (it names no group, it targets
    # all:!windows to write /etc/hosts), so it is excluded here.
    kind_plays = {p["hosts"].split(":")[0] for p in site
                  if not p["name"].startswith("Map hosts by name")}
    assert kind_plays == set(plan.groups)


def test_role_name_comes_from_the_kind(redstack):
    site = load(files(redstack), "ansible/site.yml")
    roles = {p["hosts"]: p["roles"][0] for p in site}
    assert roles["jumpboxes"] == "redstackpro.jumpbox"
    assert roles["teamservers"] == "redstackpro.teamserver"


# -- multi network

def test_parallel_chains_each_use_their_own_jumpbox(parallel_chains):
    out = files(parallel_chains)
    a = load(out, "ansible/host_vars/art-myth-ts01.yml")
    b = load(out, "ansible/host_vars/art-sliv-ts01.yml")
    assert "art-jump-bx02" in a["ansible_ssh_common_args"]
    assert "art-jump-bx03" in b["ansible_ssh_common_args"]


# -- gating, injected across the fronts edge

def test_gating_reaches_the_teamserver(redstack):
    """The redirector holds the gating rules; the teamserver has to know them or
    its C2 profile and the redirector disagree and every beacon gets the decoy."""
    out = files(redstack)
    ts = load(out, "ansible/host_vars/art-myth-ts01.yml")
    assert ts["gating_header_name"] == "X-Request-Id"
    assert ts["uri_prefix"] == "/api/v1"
    # An untouched redirector ships a random secret, not the placeholder, and the
    # teamserver's copy is the same value the redirector will demand.
    rd = load(out, "ansible/host_vars/art-apache-rd01.yml")
    assert ts["gating_header_value"] != "CHANGE-ME"
    assert re.fullmatch(r"[a-z0-9]{24}", ts["gating_header_value"])
    assert ts["gating_header_value"] == rd["redstackpro_redirector_gating"][
        "header_value"]


def test_explicit_gating_value_is_kept(redstack):
    """A value the user set on the canvas is authored intent; the compiler leaves
    it alone rather than rolling a random one over it."""
    for node in redstack["nodes"]:
        if node["id"] == "apache-rd01":
            node["overlay"]["gating"]["header_value"] = "operator-chosen"
    ts = load(files(redstack), "ansible/host_vars/art-myth-ts01.yml")
    assert ts["gating_header_value"] == "operator-chosen"


def test_rollover_front_doors_share_one_gating_value(rollover):
    """Several redirectors fronting one teamserver must demand the same header or
    a beacon works through one door and gets the decoy through the next."""
    out = files(rollover)
    values = {
        load(out, "ansible/host_vars/art-%s.yml" % rd)[
            "redstackpro_redirector_gating"]["header_value"]
        for rd in ("apache-rd01", "apache-rd02")
    }
    assert len(values) == 1
    assert values.pop() != "CHANGE-ME"


def test_teamserver_play_runs_before_the_redirector_that_needs_it(redstack):
    """The dependency now travels inside a collected entry, so the ordering has
    to look there rather than at the top level of the inject."""
    site = load(files(redstack), "ansible/site.yml")
    order = [play["hosts"] for play in site]
    assert order.index("teamservers") < order.index("redirectors")


def test_conflicting_gating_is_a_generation_error(rollover):
    """Two redirectors fronting one teamserver must agree on what they demand
    of a beacon, or it works through one and gets the decoy through the other.
    Two different values the user set explicitly cannot be reconciled, so the
    compiler refuses rather than picking one."""
    for node in rollover["nodes"]:
        if node["id"] == "apache-rd01":
            node["overlay"]["gating"]["header_value"] = "value-a"
        if node["id"] == "apache-rd02":
            node["overlay"]["gating"]["header_value"] = "value-b"
    with pytest.raises(GenerationError):
        generate(rollover, skip_validation=True)


def test_ssh_key_path_is_defined_not_left_dangling(redstack):
    """An undefined key path fails at fact gathering with an error that says
    nothing about what to do."""
    group = load(files(redstack), "ansible/group_vars/all.yml")
    assert group["redstackpro_ssh_key_path"]
    assert "BEGIN" not in str(group)


# -- windows

def test_windows_operator_is_not_reached_over_ssh(redstack):
    """A role cannot choose its own connection: Ansible picks the plugin before
    the first task runs. So the connection is part of what the topology derives,
    the same as the group and the play position. See 0019."""
    ops = load(files(redstack), "ansible/host_vars/art-win-op01.yml")
    assert ops["redstackpro_operator_os"] == "windows"
    assert ops["ansible_connection"] == "psrp"
    assert ops["ansible_port"] == 5986
    assert ops["ansible_shell_type"] == "powershell"


def test_windows_operator_gets_no_proxy_jump(redstack):
    """ProxyJump is an OpenSSH feature. Emitting it on a psrp host would look
    like a management path that works."""
    ops = load(files(redstack), "ansible/host_vars/art-win-op01.yml")
    assert "ansible_ssh_common_args" not in ops


def test_windows_is_excluded_from_the_operators_play(redstack):
    """Windows self-provisions from its boot script, so the operators play, which
    also holds the Kali box, targets the group minus the Windows host."""
    site = load(files(redstack), "ansible/site.yml")
    operators = [p for p in site if p["hosts"].startswith("operators")][0]
    assert operators["hosts"] == "operators:!windows"
    assert operators["become"] is True


def test_linux_operator_keeps_its_proxy_jump(redstack):
    """The Windows branch must not cost the other operator box its path."""
    ops = load(files(redstack), "ansible/host_vars/art-kali-op01.yml")
    assert ops["redstackpro_operator_os"] == "kali"
    assert "ProxyJump" in ops["ansible_ssh_common_args"]
    assert "ansible_connection" not in ops


# -- windows listener signing (0022)

def test_windows_host_vars_validate_against_the_authority(redstack):
    """The steady state validates. The listener is signed by the bootstrap play,
    so host_vars point at the authority rather than ignoring the certificate."""
    ops = load(files(redstack), "ansible/host_vars/art-win-op01.yml")
    assert ops["ansible_psrp_cert_validation"] == "{{ redstackpro_ca_local_path }}"
    assert ops["ansible_psrp_cert_validation"] != "ignore"


def test_windows_group_holds_only_windows_hosts(redstack):
    """An auxiliary group for the bootstrap play. The Windows host is in it and
    still in operators; the Kali operator is not."""
    inv = load(files(redstack), "ansible/inventory.yml")
    assert set(inv["all"]["children"]["windows"]["hosts"]) == {"art-win-op01"}
    assert "art-win-op01" in inv["all"]["children"]["operators"]["hosts"]


def test_no_windows_host_means_no_bootstrap_play_or_group(minimal):
    """A topology with no Windows host keeps the play list and inventory it had.
    The auxiliary group and the bootstrap play appear only when needed."""
    out = files(minimal)
    inv = load(out, "ansible/inventory.yml")
    assert "windows" not in inv["all"]["children"]
    site = load(out, "ansible/site.yml")
    assert all(p["hosts"] != "windows" for p in site)
    assert not any("redstackpro.winrm_ca" in (p.get("roles") or []) for p in site)


# -- platform (range only)

def _range_doc():
    return json.loads(
        (ROOT / "frontend/public/goad/goad-light.json").read_text())


def test_range_emits_the_compile_provider_as_platform():
    """A range surfaces the provider it compiled for as redstackpro_platform so
    the roles can branch on it. AWS and GCP must stay independent: a promotion
    fix proven on one provider cannot regress another, and the branch key is
    this variable. See goad-native-recreation."""
    for provider in ("aws", "gcp"):
        out = files(_range_doc(), provider=provider)
        all_ = load(out, "ansible/group_vars/all.yml")
        assert all_["redstackpro_platform"] == provider


def test_offense_range_does_not_emit_a_platform(redstack):
    """The platform var is a range concept; an offense export never carries it,
    so nothing keys off a provider where the notion does not apply."""
    all_ = load(files(redstack, provider="aws"), "ansible/group_vars/all.yml")
    assert "redstackpro_platform" not in all_


def test_range_platform_defaults_to_generic_without_a_provider():
    all_ = load(files(_range_doc()), "ansible/group_vars/all.yml")
    assert all_["redstackpro_platform"] == "generic"


# -- shipping

def test_collector_wire_reaches_the_shippers(redstack):
    """The port and the TLS choice are declared on the collector, so they travel
    to every shipper. Two defaults that agree today drift the moment someone
    edits the overlay, and the failure is a shipper talking to a closed port."""
    for host in ("art-myth-ts01", "art-apache-rd01"):
        vars_ = load(files(redstack), "ansible/host_vars/%s.yml" % host)
        assert vars_["redstackpro_shipper_port"] == 5044
        assert vars_["redstackpro_shipper_tls"] is True


def test_a_changed_ingest_port_moves_every_shipper(redstack):
    for node in redstack["nodes"]:
        if node["id"] == "open-log01":
            node["overlay"]["ingest_port"] = 5999
    out = files(redstack)
    assert load(out, "ansible/host_vars/art-open-log01.yml")[
        "redstackpro_collector_ingest_port"] == 5999
    assert load(out, "ansible/host_vars/art-myth-ts01.yml")[
        "redstackpro_shipper_port"] == 5999


def test_every_play_ships_when_the_topology_says_to(redstack):
    """The shipper role follows the logs_to edge rather than the kind, so it is
    a conditional role on every play rather than a group of its own."""
    site = load(files(redstack), "ansible/site.yml")
    # The bootstrap play does not ship logs; it only signs the listener (0022).
    # The hosts-mapping play only writes /etc/hosts and ships nothing either.
    for play in [p for p in site if p["hosts"] != "windows"
                 and not p["name"].startswith("Map hosts by name")]:
        conditional = [r for r in play["roles"] if isinstance(r, dict)]
        assert any(r["role"] == "redstackpro.shipper" for r in conditional), \
            play["hosts"]
        assert "log_sink_address" in conditional[0]["when"]


def test_the_shipper_runs_after_the_role_that_makes_the_logs(redstack):
    site = load(files(redstack), "ansible/site.yml")
    rdir = [p for p in site if p["hosts"] == "redirectors"][0]
    names = [r["role"] if isinstance(r, dict) else r for r in rdir["roles"]]
    assert names == ["redstackpro.redirector", "redstackpro.shipper"]


def test_the_certificate_authority_path_is_shaart_not_per_role(redstack):
    """Three roles on three hosts need the same two paths, and a role default is
    scoped to the role that declares it."""
    group = load(files(redstack), "ansible/group_vars/all.yml")
    assert group["redstackpro_ca_dir"]
    assert group["redstackpro_ca_local_path"]


JUMPBOX_ROLE = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.jumpbox"


def test_the_operator_source_ranges_reach_the_jumpbox(redstack):
    """fail2ban guards the range's only entry point, and the operator's own
    tooling is what trips it. The ranges are an apply-time answer, so they
    arrive as a placeholder rather than a canvas value."""
    group = load(files(redstack), "ansible/group_vars/all.yml")
    assert group["redstackpro_operator_source_ranges"] == \
        "<<tf:@settings:operator_source_ranges>>"


def test_a_world_open_range_is_never_exempted_from_the_jail():
    """The load bearing half of the ignoreip change. operator_source_ranges
    DEFAULTS to 0.0.0.0/0, so exempting it verbatim would set ignoreip to the
    whole internet and leave the jail enabled, healthy looking, and a no-op.
    Dropping this filter is a silent downgrade, so it is guarded here."""
    defaults = yaml.safe_load(
        (JUMPBOX_ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
    world = defaults["redstackpro_jumpbox_fail2ban_world_ranges"]
    assert "0.0.0.0/0" in world and "::/0" in world

    template = (JUMPBOX_ROLE / "templates/fail2ban-sshd.local.j2").read_text(
        encoding="utf-8")
    assert "redstackpro_jumpbox_fail2ban_world_ranges" in template, \
        "the template must filter world open ranges out of ignoreip"
    # ignoreip may only be emitted from the filtered list, never from the raw
    # variable, which would reintroduce the 0.0.0.0/0 exemption.
    # An actual directive, not prose: fail2ban keys are unindented assignments,
    # and the surrounding comment legitimately says the word "ignoreip".
    ignoreip = [ln for ln in template.splitlines()
                if re.match(r"^ignoreip\s*=", ln)]
    assert ignoreip and all("_scoped" in ln for ln in ignoreip), ignoreip
    assert "redstackpro_operator_source_ranges" not in "".join(ignoreip)


ASSET_ROLES = ROOT / "src/redstackpro/assets/ansible/roles"


def test_no_shipped_role_file_spells_the_placeholder_prefix():
    """deploy.sh decides substitution is finished by grepping the WHOLE ansible
    tree for the token prefix, roles included. So a role file that merely
    MENTIONS it -- a comment explaining the token, say -- aborts every deploy
    with "unfilled address placeholders remain". Cost one live AWS deploy.

    The compiler still emits real tokens into group_vars and host_vars, which is
    the point; this guards only the static role assets that ship unchanged.
    """
    prefix = "<<" + "tf:"
    offenders = [
        p.relative_to(ROOT).as_posix()
        for p in ASSET_ROLES.rglob("*")
        if p.is_file()
        and prefix in p.read_text(encoding="utf-8", errors="ignore")
    ]
    assert not offenders, (
        "these shipped role files spell the placeholder prefix and will abort "
        "deploy.sh: %s" % offenders)


# -- rendering
#
# The generator hand rolls YAML so the output is ordered and commented, which
# means it also owns quoting. Deciding that from a list of punctuation misses
# everything YAML coerces by shape, and those values reach the generator through
# the overlay.

NASTY = [
    "no", "yes", "on", "off", "No", "OFF", "y", "n",          # YAML 1.1 booleans
    "1.5", "007", "0x1F", "1e5", "-3",                        # numbers
    "null", "~", "NULL",                                      # nulls
    "2024-01-01", "12:30:00",                                 # dates and times
    "a: b", "* star", "- dash", "# hash", "@at", "%pct",      # punctuation
    r"C:\redstackpro", r"back\slash", 'say "hi"', "tab\there",    # escapes
    "line1\nline2", "  pad  ", "",                            # whitespace
    "X-Request-Id", "/api/v1", "debian-12", "10.30.0.0/16",   # ordinary values
]


def test_every_scalar_survives_a_round_trip():
    """Render, parse, compare. The list of characters that need quoting is
    longer than it looks, so the parser decides rather than a heuristic."""
    from redstackpro.ansible import _render_yaml
    for value in NASTY:
        text = _render_yaml({"v": value})
        assert yaml.safe_load(text) == {"v": value}, repr(value)


def test_nesting_and_lists_use_the_same_quoting():
    from redstackpro.ansible import _render_yaml
    document = {"list": NASTY, "map": {"inner": "no", "deep": {"x": "007"}}}
    assert yaml.safe_load(_render_yaml(document)) == document


def test_an_overlay_value_reaches_host_vars_unchanged(redstack):
    """The end to end version. A gating header value is an arbitrary string and
    lands in host_vars, so 'off' has to still be a string when it gets there."""
    for node in redstack["nodes"]:
        if node["id"] in ("apache-rd01", "apache-rd02"):
            node["overlay"]["gating"]["header_value"] = "off"
            node["overlay"]["hostname"] = "007"
    out = files(redstack)
    ts = load(out, "ansible/host_vars/art-myth-ts01.yml")
    assert ts["gating_header_value"] == "off", "became a boolean"
    rdir = load(out, "ansible/host_vars/art-apache-rd01.yml")
    assert rdir["redstackpro_redirector_hostname"] == "007", "became a number"


def test_a_windows_path_is_not_mangled_by_escapes():
    r"""A backslash inside a double quoted scalar is an escape, so C:\redstackpro
    arrives carrying a carriage return unless the backslash is escaped first.
    The operator role puts a Windows path in a variable, so this is reachable."""
    from redstackpro.ansible import _render_yaml
    path = "C:" + chr(92) + "redstackpro" + chr(92) + "new"
    assert chr(13) not in yaml.safe_load(_render_yaml({"v": path}))["v"]
    assert yaml.safe_load(_render_yaml({"v": path}))["v"] == path


def _redirector_tasks():
    return yaml.safe_load((REDIRECTOR_ROLE / "tasks/main.yml").read_text())


def _task_named(tasks, fragment):
    for task in tasks:
        if fragment.lower() in (task.get("name") or "").lower():
            return task
    raise AssertionError("no redirector task named like %r" % fragment)


def test_a_redirector_asks_for_a_real_certificate_by_default():
    """A default nobody changes should be the one that is right, and a real
    engagement uses a real certificate. self_signed was the default only because
    issuance needed an A record that could not exist before terraform reserved
    the address; the deploy now prints that record and waits for it, so the
    reason is gone.
    """
    defaults = yaml.safe_load((REDIRECTOR_ROLE / "defaults/main.yml").read_text())
    assert defaults["redstackpro_redirector_tls"]["cert_source"] == "letsencrypt"


def test_a_missing_dns_record_does_not_fail_the_deploy():
    """THE point of the fallback. An operator who has not created the A record
    yet still gets their range: the redirector keeps the bootstrap self signed
    certificate and the run carries on. Before this, the wait was non-fatal but
    certbot then ran anyway and ended the deploy five minutes later, so the
    gating condition is the whole fix.
    """
    tasks = _redirector_tasks()

    wait = _task_named(tasks, "Wait for the domain to resolve")
    assert wait["failed_when"] is False

    for name in ("Obtain a Let's Encrypt certificate",
                 "Point the redirector at the issued certificate"):
        assert "redstackpro_redirector_dns_ok" in _task_named(tasks, name)["when"], (
            "%r must be gated on the record having landed, or a missing record "
            "still fails the run" % name)


def test_the_operator_is_left_a_way_to_finish_issuance():
    """A reminder that only scrolls past in a deploy recap is not a reminder.
    The redirector writes the warning into /etc/motd and ships the one command
    that completes issuance once the record exists.
    """
    tasks = _redirector_tasks()
    assert (REDIRECTOR_ROLE / "templates/rsp-issue-cert.j2").exists()

    motd = _task_named(tasks, "Leave the reminder")
    # Removed once the certificate is issued, so the warning cannot outlive the
    # problem it describes.
    assert "redstackpro_redirector_dns_ok" in motd["ansible.builtin.blockinfile"]["state"]

    script = (REDIRECTOR_ROLE / "templates/rsp-issue-cert.j2").read_text()
    assert "certbot certonly" in script
    # Installed whatever the redirector was built with, because switching a
    # self signed redirector onto a real certificate is one of its three jobs.
    install = _task_named(tasks, "Install the certificate command")
    assert not any("cert_source" in str(c) for c in install["when"])
    # It must clear the same marker blockinfile wrote, or a fixed redirector
    # keeps greeting its operator with a stale warning.
    assert "REDSTACKPRO TLS" in script
    assert "REDSTACKPRO TLS" in motd["ansible.builtin.blockinfile"]["marker"]


def test_the_dns_wait_is_not_longer_than_the_patience_it_asks_for():
    """Fifty minutes of a deploy that looks hung was defensible when missing the
    window cost the certificate. Now that it costs nothing, it buys nothing.
    """
    defaults = yaml.safe_load((REDIRECTOR_ROLE / "defaults/main.yml").read_text())
    minutes = (defaults["redstackpro_redirector_dns_retries"]
               * defaults["redstackpro_redirector_dns_delay"]) / 60
    assert 5 <= minutes <= 20


def test_a_self_signed_redirector_can_still_move_to_a_real_certificate():
    """Nothing about choosing self_signed at compile time should foreclose a real
    certificate later. The pieces issuance needs are unconditional: the ACME
    webroot exists, both web server templates serve the challenge path, and
    certbot is installed on every redirector. So the switch is one command on the
    box, not a redeploy of the range.
    """
    source = (REDIRECTOR_ROLE / "tasks/main.yml").read_text()

    # certbot used to be appended only for a letsencrypt redirector. Installed
    # unconditionally it costs one small package; gated, it costs a redeploy.
    install = source[:source.index("scanner and AV blocklist")]
    assert "'certbot'" in install
    assert "if redstackpro_redirector_tls.cert_source == 'letsencrypt'" not in install, (
        "certbot is gated on cert_source again; a self signed redirector then "
        "cannot switch without a redeploy")

    for server in ("apache-redirector.conf.j2", "nginx-redirector.conf.j2"):
        conf = (REDIRECTOR_ROLE / "templates" / server).read_text()
        assert "acme-challenge" in conf
        # Gating the challenge path on cert_source would break the switch just
        # as thoroughly as gating the package.
        challenge = conf[conf.index("acme-challenge") - 400:conf.index("acme-challenge")]
        assert "cert_source" not in challenge

    script = (REDIRECTOR_ROLE / "templates/rsp-issue-cert.j2").read_text()
    # Repointing these two paths is what actually moves the server onto the new
    # certificate; issuing without relinking would change nothing a client sees.
    assert "/etc/redstackpro/tls/redirector.crt" in script
    assert "/etc/redstackpro/tls/redirector.key" in script
    # Renewal is the third job, and it has to be reachable without arguments.
    assert "--keep-until-expiring" in script
    assert "--force" in script


def test_impacket_pins_pyopenssl_below_the_release_that_breaks_the_adcs_relay():
    """The AD CS relay (ESC8) builds its CSR with crypto.X509Req, which pyOpenSSL
    removed in 24.0. A fresh impacket install pulls 26.x, so `ntlmrelayx --adcs`
    crashed with "module 'OpenSSL.crypto' has no attribute 'X509Req'" -- AFTER
    the coercion and the relayed authentication had both succeeded. The whole
    attack, failing at the final step.

    Proven on a live range 2026-09-18 running the full chain to a DomainController
    certificate and a machine-account TGT. `ntlmrelayx.py --help` runs clean, so
    the toolchain's run-check cannot catch this; a version floor is the only
    thing that does. Pinned in BOTH the places impacket is installed.
    """
    jumpbox = yaml.safe_load(
        (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.jumpbox"
         / "tasks/toolkit.yml").read_text())
    injected = []
    for t in jumpbox:
        cmd = str(t.get("ansible.builtin.command", {}).get("cmd", ""))
        if "pipx inject impacket" in cmd:
            injected += t.get("loop", [cmd])
    assert any("pyOpenSSL<24" in str(x) for x in injected), (
        "the jumpbox no longer pins pyOpenSSL, so the ESC8 relay will crash at "
        "CSR generation on a fresh deploy")
    # Any AUTHENTICATED impacket tool computes an NT hash with MD4, which
    # OpenSSL 3 dropped; impacket falls back to pycryptodome's MD4 only if it is
    # installed. And the git tools import `future`. Both found live when the
    # part-14 relay could not authenticate or even import.
    assert any("pycryptodome" in str(x) for x in injected), (
        "no pycryptodome in impacket's venv; authenticated tools hit "
        "'unsupported hash type MD4' on OpenSSL 3")
    assert any(str(x) == "future" for x in injected), (
        "krbrelayx/dnstool import future; a fresh venv lacks it")

    toolkit = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.jumpbox"
               / "tasks/toolkit.yml").read_text(encoding="utf-8")
    # The git-cloned tools must be wrapped to run with the impacket interpreter.
    # Running them with a bare python3 fails at "No module named 'impacket'",
    # which is how the part-14 relay could not start at all.
    assert "/opt/pipx/venvs/impacket/bin/python" in toolkit, (
        "the krbrelayx/PKINITtools wrappers do not use the impacket interpreter, "
        "so they cannot import impacket")
    assert "python3 /opt/krbrelayx" not in toolkit, (
        "a git tool is still invoked with bare python3, which has no impacket")

    operator = yaml.safe_load(
        (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.operator"
         / "defaults/main.yml").read_text())
    impacket = next(x for x in operator["redstackpro_operator_pipx_tools"]
                    if x["name"] == "impacket")
    assert any("pyOpenSSL<24" in i for i in impacket.get("inject", [])), (
        "the operator no longer pins pyOpenSSL for impacket")


def test_the_mythic_install_can_never_wait_on_a_prompt():
    """Found live 2026-09-13. The image already carries http and apollo under
    InstalledServices, so `mythic-cli install github` finds an older copy and
    PROMPTS to overwrite. A command task has no stdin to answer with, so it
    blocked the full 1500s timeout, was killed, and retried twice more: about
    seventy-five minutes of a deploy that looked like a slow build and then
    failed. The same command with -f finished in seconds.

    Two guards, because the flag only covers the prompt upstream documents:
    --force for that one, and an empty stdin so any other prompt reads EOF and
    fails in seconds instead of hanging to the timeout.
    """
    role = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.teamserver"
            / "tasks/c2-mythic.yml")
    tasks = yaml.safe_load(role.read_text())
    task = next(t for t in tasks
                if "Install the HTTP profile" in (t.get("name") or ""))
    cmd = task["ansible.builtin.command"]
    assert " -f" in cmd["cmd"], "mythic-cli install lost --force; it will prompt"
    assert cmd.get("stdin") == "", "install must have no stdin to block on"
    # The bound stays: a genuinely wedged build should still end the task.
    assert "timeout " in cmd["cmd"]


def test_the_adaptix_listener_uses_the_wire_field_names():
    """name/type/config, lowercase, because that is what the teamserver binds.

    AdaptixServer/core/connector/tc_listeners.go:

        type ListenerConfig struct {
            ListenerName string `json:"name"`
            ConfigType   string `json:"type"`
            Config       string `json:"config"`
        }

    gin's ShouldBindJSON binds on the json tag. Send the Go field names --
    ListenerName/ConfigType/Config -- and it binds nothing at all: every field
    stays empty, the handler's next line runs ValidListenerName("") against
    ^[a-zA-Z0-9-_]+$, the + fails on an empty string, and the API answers
    "Invalid listener name".

    That error is true and reads like a category error, which is what made it
    expensive: on a live range every name spelling failed, every ConfigType
    failed, the config shape made no difference, and rebuilding the extenders and
    restarting the teamserver changed nothing, because none of it was arriving.
    Guarded here because the capitalised names look more correct than the right
    ones and would be an easy "tidy-up".
    """
    role = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.teamserver"
            / "tasks/c2-adaptix.yml")
    tasks = yaml.safe_load(role.read_text())

    def find(nodes):
        for t in nodes:
            if "Start the HTTP beacon listener" in (t.get("name") or ""):
                return t
            for key in ("block", "rescue", "always"):
                if key in t:
                    found = find(t[key])
                    if found:
                        return found
        return None

    task = find(tasks)
    assert task, "the listener create task is gone"
    body = task["ansible.builtin.uri"]["body"]

    assert set(body) == {"name", "type", "config"}, (
        "the listener body must use the wire names name/type/config; %s binds to "
        "nothing and the teamserver reports an empty name" % sorted(body))
    assert body["type"] == "BeaconHTTP"
    # Config is a Go string, so the transport config travels as JSON text rather
    # than as a nested object.
    assert "to_json" in body["config"]


# --------------------------------------------- a declared vuln nobody plants ---

HOST_VULNS_ROLE = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.host_vulns"
ADCS_ROLE = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.adcs"


def _host_vuln_defaults():
    import yaml
    return yaml.safe_load((HOST_VULNS_ROLE / "defaults/main.yml").read_text(encoding="utf-8"))


def test_the_unplanted_notice_does_not_blanket_reject_every_esc():
    """It used to reject anything matching ^esc, on the grounds that the adcs
    role planted all of them. It does not plant esc8, so a range declaring esc8
    got no planter AND no notice: the assumption in the filter suppressed the
    warning for the one case the assumption did not cover."""
    main = (HOST_VULNS_ROLE / "tasks/main.yml").read_text(encoding="utf-8")
    assert "reject('match', '^esc')" not in main, (
        "the blanket reject is back, and esc8 is invisible again")
    assert "difference(redstackpro_adcs_planted)" in main


def test_esc8_is_planted_and_so_is_not_reported():
    """esc8 was the id the canvas offered and nothing planted. The adcs role now
    serves /certsrv for it, so it belongs in the planted list and must not turn
    up in the notice; an id that IS planted being called unplanted would train
    people to ignore that line."""
    d = _host_vuln_defaults()
    assert "esc8" in d["redstackpro_adcs_planted"]
    unplanted = (set(["esc1", "esc4", "esc8"])
                 - set(d["redstackpro_host_vulns_implemented"])
                 - set(d["redstackpro_adcs_planted"]))
    assert unplanted == set()

    # And something genuinely unknown still is reported, or the notice is dead.
    unknown = ({"esc1", "made_up_technique"}
               - set(d["redstackpro_host_vulns_implemented"])
               - set(d["redstackpro_adcs_planted"]))
    assert unknown == {"made_up_technique"}


def test_the_adcs_planted_list_matches_what_the_role_gates_on():
    """Anti-drift. The list is a copy of the adcs role's own coverage, and a copy
    is a thing that goes stale: if esc8 is ever implemented there, or a template
    is dropped, this list has to move with it or the notice starts lying again.

    esc4 is the documented exception: it is planted through
    redstackpro_adcs_acl_templates (an ACL on a template object, not a template
    id), so it never appears in an `'escN' in` gate.
    """
    import re
    source = ""
    for path in ADCS_ROLE.rglob("*"):
        if path.is_file() and path.suffix in (".yml", ".ps1"):
            source += path.read_text(encoding="utf-8", errors="ignore")
    gated = set(re.findall(r"'(esc\d+)' in", source))
    listed = set(_host_vuln_defaults()["redstackpro_adcs_planted"])

    assert gated - listed == set(), (
        "the adcs role plants %s and the notice does not know it" % (gated - listed))
    assert listed - gated == {"esc4"}, (
        "unexpected entries with no gate in the adcs role: %s"
        % (listed - gated - {"esc4"}))


def test_every_esc_the_canvas_offers_is_planted_or_reported():
    """The catalog is what a person can tick. An id it offers must either be
    planted by something or come back in the unplanted notice, never neither."""
    import re
    catalog = re.findall(
        r'\{\s*id:\s*"(esc\d+)"',
        (ROOT / "frontend/src/vulns.js").read_text(encoding="utf-8"))
    assert catalog, "parsed no esc ids out of the catalog"
    d = _host_vuln_defaults()
    known = set(d["redstackpro_host_vulns_implemented"]) | set(d["redstackpro_adcs_planted"])
    # Every esc the canvas offers is now planted by something. This asserted
    # `== {"esc8"}` until esc8 was built, which is what made implementing it come
    # back here rather than pass quietly. Keep it exact: a new catalog entry with
    # no planter should fail this, not widen it.
    assert set(catalog) - known == set(), (
        "the canvas offers esc ids nothing plants: %s" % (set(catalog) - known))


def test_no_lab_plants_esc16_alongside_esc9():
    """ESC16 takes the SID security extension out of EVERY certificate the CA
    issues, which is what ESC9 asks for on ONE template. A lab with both has an
    ESC9 template that teaches nothing: it would behave identically with the flag
    removed, so a learner cannot tell which misconfiguration they exploited.

    ESC16 is deliberately not declared on goad for this reason. It is in the
    catalog for a lab built around it.
    """
    import json
    for path in sorted((ROOT / "frontend/public/goad").glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        per_domain = {}
        for node in doc.get("nodes", []):
            vulns = set((node.get("overlay") or {}).get("vulns") or [])
            if {"esc9", "esc16"} & vulns:
                per_domain.setdefault(path.stem, set()).update(vulns)
        got = per_domain.get(path.stem, set())
        assert not {"esc9", "esc16"} <= got, (
            "%s declares both esc9 and esc16, so the esc9 template is "
            "indistinguishable from the CA-wide setting" % path.stem)


def test_no_planter_builds_a_certificate_nobody_can_authenticate_with():
    """0x8000000 is CT_FLAG_SUBJECT_ALT_REQUIRE_DNS. The flag that builds a
    subject from the directory is CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH,
    0x80000000, one zero longer.

    The ESC13 and ESC4 planters both wrote the short one under a comment saying
    the directory built the subject. Nothing failed: the template planted,
    published and enrolled, and the certificate came back with a DNS SAN, no UPN
    and no SID extension, so a DC had nothing to map to an account and PKINIT
    authenticated no one. A dropped digit that lands on another real flag is
    invisible until someone tries the technique on a live range.

    The fix is to INHERIT the flag from the built-in User template, so this
    forbids writing the wrong constant rather than requiring the right one --
    0x80000000 does not fit a signed 32-bit int and hand-writing it is the second
    way to get this wrong.
    """
    import re
    bad = []
    for path in sorted(ADCS_ROLE.rglob("plant_*.ps1")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue
            if re.search(r'Certificate-Name-Flag"\s*,\s*0x8000000\b', line):
                bad.append(path.name)
    assert not bad, (
        "%s writes msPKI-Certificate-Name-Flag = 0x8000000 (SUBJECT_ALT_REQUIRE_DNS); "
        "inherit it from the User template instead" % ", ".join(bad))


def test_a_user_auth_planter_inherits_the_name_flag_rather_than_guessing():
    """The other half of the above: the templates whose certificates have to map
    to an account must take the subject rules from the template Windows ships,
    not invent them. ESC1 and ESC2 are excluded because the enrollee supplying
    the subject IS their technique.
    """
    for name in ("plant_esc4.ps1", "plant_esc9.ps1", "plant_esc13.ps1"):
        text = (ADCS_ROLE / "files" / name).read_text(encoding="utf-8")
        assert '"msPKI-Certificate-Name-Flag"' in text.split("$t.Put")[0] or \
            "msPKI-Certificate-Name-Flag" in text, name
        # It must be in the attribute-copy loop, not in a Put.
        loop = text[text.index("foreach ($a in @("):text.index("$t.Put(\"displayName\"")]
        assert "msPKI-Certificate-Name-Flag" in loop, (
            "%s does not inherit the name flag from the User template" % name)


def test_every_planter_the_role_runs_is_actually_staged_to_the_host():
    """A planter missing from the staging loop is never copied, so the task that
    runs it fails on a missing file rather than on anything to do with the
    technique. The two lists are written in different places and drift silently.
    """
    import re
    tasks = (ADCS_ROLE / "tasks/plant_templates.yml").read_text(encoding="utf-8")
    staged = set(re.findall(r"- (plant_esc\d+\.ps1)", tasks))
    invoked = set(re.findall(r"\\(plant_esc\d+\.ps1)", tasks))
    on_disk = {p.name for p in (ADCS_ROLE / "files").glob("plant_esc*.ps1")}

    assert invoked - staged == set(), (
        "run but never staged: %s" % (invoked - staged))
    assert staged - on_disk == set(), (
        "staged but not in files/: %s" % (staged - on_disk))


def test_every_esc_knob_the_roles_read_survives_the_compiler():
    """The compiler copies vulns_vars through a hardcoded key tuple. A key the
    roles consume but the tuple omits is dropped in transit, so the technique
    plants with its default and the value set on the topology is silently ignored --
    which looks exactly like the technique not working.
    """
    import re
    compiler = (ROOT / "src/redstackpro/ansible.py").read_text(encoding="utf-8")
    block = compiler[compiler.index("for k in (\"esc7_manager\""):]
    carried = set(re.findall(r'"(esc\w+)"', block[:block.index(")")]))

    consumed = set()
    for role in ("redstackpro.dc", "redstackpro.srv"):
        text = (ROOT / "src/redstackpro/assets/ansible/roles" / role
                / "tasks/main.yml").read_text(encoding="utf-8")
        consumed |= set(re.findall(r"\)\.(esc\w+)", text))

    assert consumed - carried == set(), (
        "the roles read %s but the compiler never carries it" % (consumed - carried))


def test_esc14_refuses_to_plant_a_bypass_on_a_guessed_account():
    """A weak explicit mapping is a standing authentication bypass on whatever
    account it names. With no target configured the right behaviour is to plant
    nothing, not to pick somebody."""
    tasks = (ADCS_ROLE / "tasks/plant_templates.yml").read_text(encoding="utf-8")
    block = tasks[tasks.index("- name: Plant ESC14"):]
    block = block[:block.index("- name:", 10)]
    assert "redstackpro_adcs_esc14_target | default('') | length > 0" in block, (
        "esc14 plants without requiring a target account")
    defaults = yaml.safe_load(
        (ADCS_ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
    assert defaults["redstackpro_adcs_esc14_target"] == "", (
        "esc14 ships with a default target, so enabling it silently weakens "
        "whichever account that names")


def test_no_inline_content_depends_on_ansible_managed():
    """`ansible_managed` exists for templates, not for inline content.

    The template module injects it; ordinary task templating does not. So a
    .j2 file may use it and a `copy: content:` may not, and the two look
    identical in review. On ansible-core 2.21 the inline form raises "Error
    while resolving value for 'content': 'ansible_managed' is undefined",
    which fails the task WITHOUT failing the play -- so the deploy reports
    success and the files simply are not there.

    That is how the jumpbox shipped with no krbrelayx or dnstool wrapper,
    leaving those tools to run under a python with no impacket. Found on a
    live range; both halves were then proven on that host, the template
    module rendering the value and copy raising on it.
    """
    import re
    roles = ROOT / "src/redstackpro/assets/ansible/roles"
    offenders = []
    for path in roles.rglob("*.yml"):
        text = path.read_text(encoding="utf-8")
        if "ansible_managed" not in text:
            continue
        # Only task files matter here; a .j2 under templates/ is fine by
        # construction, and this walk does not visit them anyway.
        for block in re.findall(r"content:\s*\|(.*?)(?=\n\s*\w+:|\Z)", text, re.S):
            if "ansible_managed" in block:
                offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, (
        "inline content cannot resolve ansible_managed: %s" % offenders)


def test_mythic_log_pin_is_stripped_without_damaging_the_compose():
    """Mythic never reached the C2 index, and this is why.

    mythic-cli generates docker-compose.yml with `logging: driver: json-file`
    on every service. A per-service driver beats the daemon default, so a host
    configured to send container output to the journal never gets Mythic's, and
    the shipper's journald inputs for mythic_server and basic_logger match
    nothing. Nothing looks broken: Mythic runs, the deploy is green, the other
    teamservers report, and the dashboard's teamserver panel has no mythic row.
    Measured on a live range before the fix -- 661 C2 documents, 580 sliver,
    81 adaptix, 0 mythic.

    The edit has to be YAML-aware. The pin is a nested mapping, so deleting its
    line leaves the `options:` children behind as orphans and the compose file
    becomes invalid rather than unpinned -- a worse failure than the one being
    fixed, because it stops Mythic entirely.

    Idempotence matters too: the role recreates containers only when this
    reports a change, and a script that always claims to have stripped
    something would recreate the teamserver on every converge.
    """
    import subprocess
    import sys
    import tempfile

    script = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.teamserver"
              / "files/mythic-unpin-logging.py")
    assert script.exists(), script

    document = {"services": {
        "mythic_server": {"image": "mythic_server", "ports": ["17443:17443"],
                          "logging": {"driver": "json-file",
                                      "options": {"max-file": "1"}}},
        "basic_logger": {"image": "basic_logger",
                         "logging": {"driver": "json-file"}},
        "mythic_redis": {"image": "redis", "restart": "always"},
    }}

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "docker-compose.yml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")

        first = subprocess.run([sys.executable, str(script), str(path)],
                               capture_output=True, text=True)
        assert "stripped 2 services" in first.stdout, first.stdout

        after = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "logging" not in after["services"]["mythic_server"]
        assert "logging" not in after["services"]["basic_logger"]
        # Everything that is not the pin has to survive intact.
        assert after["services"]["mythic_server"]["ports"] == ["17443:17443"]
        assert after["services"]["mythic_redis"]["restart"] == "always"

        second = subprocess.run([sys.executable, str(script), str(path)],
                                capture_output=True, text=True)
        assert "already unpinned" in second.stdout, second.stdout


def test_the_mythic_unpin_runs_after_every_install_that_regenerates_the_compose():
    """Ordering is the fix, not just the edit.

    Each `mythic-cli install` regenerates docker-compose.yml and puts the pin
    back, so an unpin placed before the last install is undone by it. This
    pins the task after both the agent and the logging-container installs.
    """
    tasks = yaml.safe_load(
        (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.teamserver"
         / "tasks/c2-mythic.yml").read_text(encoding="utf-8"))
    names = [t.get("name", "") for t in tasks]

    unpin = next(i for i, n in enumerate(names) if "pinning its containers" in n)
    for installer in ("Install the HTTP profile and the Apollo agent",
                      "Install the Mythic logging container",
                      "Start the Mythic logging container"):
        assert names.index(installer) < unpin, (installer, names[unpin])


# -- multi-user VPN access wiring (vpn-multiuser-spec)
# access_mode is the single field an operator sets; the compiler turns it into the
# concrete VPN service task and pins the listen port so Ansible and Terraform agree.

def _jumpbox_overlay(doc, drop_services=False, **overlay):
    """A copy of the fixture with overlay fields on its jumpbox, and optionally
    the services list stripped back so the add-the-service path is exercised."""
    doc = json.loads(json.dumps(doc))
    for n in doc["nodes"]:
        if n["kind"] == "jumpbox":
            ov = n.setdefault("overlay", {})
            if drop_services:
                ov["services"] = ["ssh", "guacamole"]
            ov.update(overlay)
    return doc


def _jumpbox_vars(doc):
    out = files(doc)
    (path,) = [p for p in out
               if p.startswith("ansible/host_vars/") and "jump" in p]
    return load(out, path)


def test_wireguard_access_mode_adds_the_service_and_carries_the_operators(redstack):
    """Setting access_mode wireguard adds the wireguard service to the jumpbox
    task list even when the overlay omitted it, and the operator roster reaches
    Ansible for per-user peer generation. No vpn_port means the role default, so
    the port var is not pinned."""
    doc = _jumpbox_overlay(
        redstack, drop_services=True, access_mode="wireguard",
        operators=[{"handle": "alice"}, {"handle": "bob", "role": "lead"}])
    v = _jumpbox_vars(doc)
    assert "wireguard" in v["redstackpro_jumpbox_services"]
    assert [o["handle"] for o in v["redstackpro_jumpbox_operators"]] == ["alice", "bob"]
    assert "redstackpro_wireguard_port" not in v


def test_openvpn_access_mode_pins_the_custom_port_and_protocol(redstack):
    """OpenVPN on a custom tcp port pins both, so the listener Ansible writes
    matches the port Terraform opened."""
    doc = _jumpbox_overlay(redstack, drop_services=True, access_mode="openvpn",
                           vpn_protocol="tcp", vpn_port=5124)
    v = _jumpbox_vars(doc)
    assert "openvpn" in v["redstackpro_jumpbox_services"]
    assert v["redstackpro_openvpn_port"] == 5124
    assert v["redstackpro_openvpn_protocol"] == "tcp"


def test_public_jumpbox_gets_no_vpn_wiring(redstack):
    """With access_mode absent (public), the compiler pins nothing: the role
    keeps its default ports and no openvpn protocol override appears."""
    v = _jumpbox_vars(redstack)
    assert "redstackpro_wireguard_port" not in v
    assert "redstackpro_openvpn_port" not in v
    assert "redstackpro_openvpn_protocol" not in v
