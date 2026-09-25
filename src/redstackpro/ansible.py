"""Ansible generation.

Nodes become groups and hosts. Edges become injected variables and play order.
Role bodies are static and live outside the compiler; everything here is the
per-topology half. See 0011 and 0015.

Addresses do not exist until apply, so every derived value is emitted as a
placeholder token that tools/tf_inventory.py substitutes from `terraform output`.
"""

import copy
import re
import secrets
import string

import yaml

from . import decoyart, decoyassets
from .naming import platform_account
from .registry import Registry
from .validate import Context, is_valid

PLACEHOLDER = "<<tf:%s:%s>>"

# The shipped blueprints seed the gating header with this so a redirector reads
# as configured on the canvas. Treated as "unset" at compile: an untouched
# redirector is randomized rather than shipping a value anyone could guess.
GATING_PLACEHOLDER = "CHANGE-ME"

# A Windows host is not reached over SSH, and a role cannot fix that: the
# connection is chosen before any task runs. So the connection plugin is part of
# what the topology derives, the same as the group and the play position.
#
# `ansible_become` is false rather than absent because the generated play sets
# `become: true` for the whole group, and an operators group holds Kali and
# Windows boxes together. Overriding per host keeps one group and one play.
#
# Certificate validation points at the jumpbox authority rather than being off.
# The listener is self signed only until the winrm_ca bootstrap play signs it
# from that authority, and that play runs before this host's operators play. The
# bootstrap play overrides this value with `ignore` for its own connection,
# because it is the one connection that has to happen before the listener is
# signed. See 0022, which supersedes the gap 0019 recorded.
WINDOWS_CONNECTION = {
    "ansible_connection": "psrp",
    "ansible_port": 5986,
    "ansible_shell_type": "powershell",
    "ansible_become": False,
    "ansible_psrp_cert_validation": "{{ redstackpro_ca_local_path }}",
}

# A range's Windows hosts are the inverse of the attack side's. There a Windows
# box self-provisions at boot and nothing reaches into it; here a domain
# controller or a member is the whole point of the play and is driven over psrp.
# The lab is an isolated local subnet, so the listener is self signed and
# validation is off, and the control node authenticates as the built-in
# Administrator the boot script gave the shared lab password. Administrator is
# used rather than a custom account because promoting the forest root turns the
# local Administrator into the domain Administrator with the same password, so
# the connection survives the promotion. The password is never written into the
# export: it is supplied at run time from the terraform output, read from the
# environment. See goad-native-recreation.
RANGE_WINDOWS_CONNECTION = {
    "ansible_connection": "psrp",
    "ansible_port": 5986,
    "ansible_shell_type": "powershell",
    "ansible_become": False,
    "ansible_user": "{{ redstackpro_range_admin_user }}",
    "ansible_password": "{{ redstackpro_lab_password }}",
    "ansible_psrp_auth": "negotiate",
    "ansible_psrp_cert_validation": "ignore",
    # Retry connection errors at the connection layer. A freshly booted cloud
    # Windows box (notably on GCP) has an unstable WinRM listener for the first
    # several minutes: individual operations drop with RemoteDisconnected, which
    # is terminal at the task layer (ansible's until/ignore_unreachable/failed_when
    # cannot catch a connection aborted mid-operation). These make pypsrp retry the
    # operation instead, riding over the transient drops. Purely additive: a stable
    # listener (as on AWS) never triggers them, so the proven path is unaffected.
    "ansible_psrp_reconnection_retries": 15,
    "ansible_psrp_reconnection_backoff": 4,
}


class GenerationError(Exception):
    pass


# The range providers a vuln id is exploitable on, keyed by the canvas catalog
# id (frontend/src/vulns.js). An id absent here lands on every provider, the
# common case; an id present is restricted because its payoff depends on
# something the provider's network model does or doesn't give the range, not on
# a per-host setting. AnsiblePlan filters a host's declared vulns through this
# before planting them, so a template can declare an id on every host and have
# it silently no-op on a provider it cannot land on -- the same id the canvas
# greys out there. Kept in sync with the `providers` field in
# frontend/src/vulns.js by tests/test_vuln_providers_sync.py. See
# current-activity-list (provider-aware toggles) and goad-fidelity-build.
VULN_PROVIDERS = {
    # The relay payoff (mitm6/WPAD, or coercion into a CVE-2019-1040-vulnerable
    # relay) needs a real L2 broadcast/multicast domain. Proxmox/ESXi put the
    # range on a real bridge/vSwitch; every cloud VPC's SDN drops broadcast and
    # multicast, so the DC-side toggle would have nothing to demonstrate there.
    "ldap_signing_off": ("proxmox", "esxi"),

    # The name-resolution poisoning family, same reason and same answer. Each of
    # these was being planted on cloud ranges where it can never pay off, which
    # is a toggle the canvas offered and the provider could not deliver:
    #   llmnr_poisoning  sets EnableMulticast=1        -- multicast
    #   nbtns_poisoning  forces NetBIOS over TCP/IP    -- broadcast
    #   responder        a bot whose lookup falls through to the two above
    #   ntlm_relay       a privileged bot's auth, which an attacker only
    #                    receives by poisoning the name it resolves
    #
    # ESC8 is deliberately NOT in this list. Its coercion is attacker-driven RPC
    # to a named host (PetitPotam/printerbug) and the relay is unicast, so no
    # part of it depends on broadcast. Filing it here would have been a
    # plausible reason that does not survive reading what the attack does.
    "llmnr_poisoning": ("proxmox", "esxi"),
    "nbtns_poisoning": ("proxmox", "esxi"),
    "responder": ("proxmox", "esxi"),
    "ntlm_relay": ("proxmox", "esxi"),
}


# The reserved pseudo-node deploy-time settings resolve under. Mirrors
# tf_inventory.SETTINGS; not a legal node id, so no host can shadow it.
SETTINGS_NODE = "@settings"


def _token(node_id, field):
    """Keyed by the composed name, matching the terraform redstackpro_addresses
    output. One identifier on both sides, no translation table."""
    return PLACEHOLDER % (node_id, field)


def _random_gating_value():
    """A 24 char lowercase alphanumeric token, matching the frontend cover
    profiles so a value set either way looks the same."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(24))


def _randomize_gating(topology):
    """Give every redirector a random beacon-gating header value unless the user
    set an explicit one on the canvas. The header is a shared secret the beacon
    must present, so an export that shipped the placeholder would gate on a value
    anyone reading the templates already knows.

    A redirector and the teamservers it fronts both read this one overlay field,
    and several redirectors can front one teamserver (the rollover shape), so the
    value cannot be rolled per redirector or the front doors to one teamserver
    would demand different headers. Redirectors that share a teamserver, directly
    or through a chain of shared teamservers, form one component and get one
    value: the explicit one if the user set exactly one, otherwise a fresh token.
    Two different explicit values in a component are left as authored so the
    conflict surfaces downstream. Mutates in place; callers that must not see the
    change pass a copy."""
    nodes = {n["id"]: n for n in topology.get("nodes", [])}
    redirectors = [nid for nid, n in nodes.items()
                   if n.get("kind") == "redirector"]
    if not redirectors:
        return

    parent = {r: r for r in redirectors}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    by_teamserver = {}
    for edge in topology.get("edges", []):
        if edge.get("role") == "fronts" and edge.get("source") in parent:
            by_teamserver.setdefault(edge.get("target"), []).append(edge["source"])
    for sharing in by_teamserver.values():
        for other in sharing[1:]:
            union(sharing[0], other)

    def header_value(node_id):
        return (nodes[node_id].get("overlay", {}).get("gating") or {}).get(
            "header_value")

    components = {}
    for redirector in redirectors:
        components.setdefault(find(redirector), []).append(redirector)

    for members in components.values():
        explicit = {header_value(r) for r in members
                    if header_value(r) and header_value(r) != GATING_PLACEHOLDER}
        if len(explicit) == 1:
            value = next(iter(explicit))
        elif not explicit:
            value = _random_gating_value()
        else:
            continue  # conflicting authored values; let FRT001 report it
        for redirector in members:
            current = header_value(redirector)
            if not current or current == GATING_PLACEHOLDER:
                gating = nodes[redirector].setdefault(
                    "overlay", {}).setdefault("gating", {})
                gating["header_value"] = value


class AnsiblePlan:
    """Everything the Ansible half of an export needs, before serialization."""

    def __init__(self, topology, registry=None, provider=None):
        self.topology = topology
        self.registry = registry or Registry()
        self.provider = provider
        self.ctx = Context(topology, self.registry)
        # One nonce per build, mixed with the node id to seed each redirector's
        # decoy artwork. Per build so two ranges never draw the same shapes, and
        # per node so two redirectors in ONE range do not either -- the same
        # reason their subdomains and gating tokens are rolled separately.
        self.art_seed = secrets.token_hex(8)
        self.groups = self._groups()
        self.windows_hosts = self._windows_hosts()
        self.host_vars = self._host_vars()
        self.group_vars = self._group_vars()
        self.play_order = self._play_order()

    # -- groups

    def _groups(self):
        groups = {}
        for node in self.ctx.hosts():
            group = self.registry.kinds[node["kind"]].get("ansible_group")
            if not group:
                raise GenerationError(
                    "kind %s has no ansible_group but is a host" % node["kind"])
            groups.setdefault(group, []).append(self.ctx.name(node["id"]))
        return {g: sorted(names) for g, names in sorted(groups.items())}

    def _windows_hosts(self):
        """An auxiliary group, not a kind group. A Windows host stays in its
        kind group (operators), so the main plays and the one operators group
        are untouched. This group exists only to give the winrm_ca bootstrap
        play a target, and it is emitted only when there is a Windows host, so a
        topology with none keeps the play list it had. See 0022."""
        return sorted(self.ctx.name(node["id"])
                      for node in self.ctx.hosts()
                      if self._is_windows(node))

    # -- variables

    def _injected(self):
        """Variables an edge role puts on a node. Returns {node_id: {name: value}}.

        Three sources, declared in roles.yaml. A derived field becomes a
        placeholder filled after apply. An overlay field and an edge field are
        known at compile time and are emitted literally.
        """
        out = {}
        for edge in self.ctx.edges:
            role = self.registry.roles.get(edge["role"])
            if not role:
                continue
            for inject in role.get("injects", []):
                targets = self._inject_targets(edge, inject["into"])

                # A collecting inject appends one entry per edge rather than
                # setting a value, because a redirector fronts as many
                # teamservers as it has edges. See 0007.
                if inject.get("collect"):
                    entry = {
                        field: self._resolve(edge, spec)
                        for field, spec in inject["entry"].items()
                    }
                    entry = {k: v for k, v in entry.items() if v is not None}
                    for node_id in targets:
                        bucket = out.setdefault(node_id, {}).setdefault(
                            inject["name"], [])
                        if entry not in bucket:
                            bucket.append(entry)
                    continue

                source = edge.get(inject["from"]) if "from" in inject else None

                if "derived_field" in inject:
                    value = _token(self.ctx.name(source),
                                   inject["derived_field"])
                elif "overlay_field" in inject:
                    value = self._overlay_path(source, inject["overlay_field"])
                elif "edge_field" in inject:
                    value = edge.get(inject["edge_field"])
                else:
                    raise GenerationError(
                        "%s inject %s names no source field"
                        % (edge["role"], inject["name"]))

                if value is None:
                    continue
                for node_id in targets:
                    if node_id == source:
                        continue
                    existing = out.setdefault(node_id, {}).get(inject["name"])
                    if existing is not None and existing != value:
                        raise GenerationError(
                            "%s receives conflicting %s: %r and %r. Redirectors "
                            "fronting one teamserver must agree; the validator "
                            "catches this as FRT001."
                            % (self.ctx.name(node_id), inject["name"],
                               existing, value))
                    out[node_id][inject["name"]] = value
        return out

    def _resolve(self, edge, spec):
        """One field of a collected entry. Same three sources as a scalar
        inject, plus the rendered name."""
        source = edge.get(spec["from"]) if "from" in spec else None
        if spec.get("rendered_name"):
            return self.ctx.name(source)
        if "derived_field" in spec:
            return _token(self.ctx.name(source), spec["derived_field"])
        if "overlay_field" in spec:
            return self._overlay_path(source, spec["overlay_field"])
        if "edge_field" in spec:
            return edge.get(spec["edge_field"])
        raise GenerationError("entry field names no source: %r" % spec)

    def _overlay_path(self, node_id, path):
        """Dotted lookup into an overlay: gating.header_name."""
        value = (self.ctx.nodes.get(node_id) or {}).get("overlay", {})
        for part in path.split("."):
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value

    def _inject_targets(self, edge, into):
        if into == "source":
            return [edge["source"]]
        if into == "target":
            return [edge["target"]]
        if into == "target_members":
            scope = edge["target"]
            if self.ctx.kind(scope) == "segment":
                segments = {scope}
            else:
                segments = {s for s in self.ctx.nodes
                            if self.ctx.kind(s) == "segment"
                            and self.ctx.network_of_segment(s) == scope}
            return [h["id"] for h in self.ctx.hosts()
                    if set(self.ctx.segments_of(h["id"])) & segments]
        raise GenerationError("unknown inject target %r" % into)

    def _host_vars(self):
        injected = self._injected()
        # Computed once: it walks every domain and host, and both the landing
        # host and the jumpbox need to agree on the answer.
        landing = self._breach_landing() if self._is_range() else {}
        out = {}
        for node in self.ctx.hosts():
            nid = node["id"]
            vars_ = {
                "redstackpro_node_id": nid,
                "redstackpro_kind": node["kind"],
                "ansible_host": _token(self.ctx.name(nid),
                                   self._primary_address(nid)),
                # The host's canvas name, carried on EVERY host so the
                # hosts-file play can give each host a friendly alias -- the id
                # the user set (and can rename) on the canvas, not a hardcoded
                # mythic/sliver. AD hosts also get an FQDN below. See the
                # redstackpro.hosts role and range-access-model.
                "redstackpro_host_shortname": nid,
                # The host's PRIVATE address, for the /etc/hosts block -- NOT
                # ansible_host, which is the public address for a jumpbox or
                # redirector (reached from outside). Naming a host by its public
                # IP makes an internal caller hairpin out through the gateway;
                # internal name resolution always wants the private address,
                # which every host has. Filled at apply like any token.
                "redstackpro_host_address": _token(self.ctx.name(nid),
                                                   "private_address"),
            }
            for name, value in sorted(injected.get(nid, {}).items()):
                vars_[name] = (
                    sorted(value, key=lambda e: e.get("uri_prefix") or "")
                    if isinstance(value, list) else value)
            vars_.update(self._overlay_vars(node))

            # The jumpbox also creates each assumed-breach domain user as a local
            # admin: the foothold is a jumpbox local admin AND a low-priv domain
            # member (the dc role seeds the domain side). Note the local account
            # no longer opens an SSH session -- sshd here is key-only as of
            # 2026-09-10 -- but the account is still what makes the breach real on
            # this host. See range-access-model and P2.5.
            if self._is_range() and node["kind"] == "jumpbox":
                breach = [u["username"] for u in self._assumed_breach_users()]
                if breach:
                    vars_["redstackpro_jumpbox_foothold_users"] = breach
                # The portal's patient-zero tiles. Every other tile signs in as
                # the operator, which is the wrong identity to launch a beacon
                # from; these sign in as patient zero on the host that domain
                # chose as its landing spot. The portal needs the landing host's
                # INVENTORY name, since that is what the connection list is keyed
                # by. See _breach_landing.
                tiles = []
                for hid, ids in sorted(landing.items()):
                    for i in ids:
                        tile = {"host": self.ctx.name(hid),
                                "username": i["username"],
                                "domain": i["netbios"] or (i["fqdn"] or "")}
                        if i.get("password"):
                            tile["password"] = i["password"]
                        tiles.append(tile)
                if tiles:
                    vars_["redstackpro_jumpbox_foothold_tiles"] = tiles
                # And it carries the offensive toolchain by default, because in a
                # range this host IS the assumed-breach foothold the solution is
                # run from: leaving it bare would mean every operator hand-installs
                # the same tools before step one. An ops-mode bastion gets nothing,
                # since there the tooling belongs on the operator box. The overlay
                # wins if it says either way. Opens no ports. See PZ-2.
                vars_.setdefault("redstackpro_jumpbox_offensive_toolkit", True)

            # A redirector carries two things for its cover site, and the split
            # is deliberate. The artwork is DRAWN here at compile time and
            # inlined, so a redirector with no egress still serves a complete
            # page. The photographs are only PLANNED here -- which slots exist,
            # how big, what to search for -- and fetched by the host itself at
            # deploy time, so the bytes never cross Ansible and every redirector
            # ends up with different images. Neither reaches a third party once
            # the page is being served. See decoyart.py and decoyassets.py.
            if node["kind"] == "redirector":
                gating = node.get("overlay", {}).get("gating") or {}
                decoy = gating.get("decoy")
                seed = "%s/%s" % (self.art_seed, nid)
                art = decoyart.for_decoy(seed, decoy)
                if art:
                    vars_["redstackpro_decoy_art"] = art
                plan = decoyassets.for_decoy(
                    seed, decoy, video=bool(gating.get("decoy_video")))
                if plan:
                    vars_["redstackpro_decoy_assets"] = plan
                pack = gating.get("decoy_asset_pack")
                if pack:
                    vars_["redstackpro_decoy_asset_pack"] = pack

            # A CA host also receives the whole forest's ESC declarations, so the
            # adcs role plants them all even when the canvas lists them on other
            # nodes (upstream places esc7/13/15 on the DC, esc6/11 on the CA host).
            if self._is_range() and node["kind"] in ("dc", "srv"):
                agg = self._adcs_forest_escs(node)
                # Inject only the non-empty aggregates. An empty collection would
                # serialize to a YAML null, and `| default(...)` does not replace a
                # defined null, so a CA host with no ESCs (only an ACL-target
                # template) would get a None templates list. Omitting the key lets
                # the caller's default fall through cleanly.
                if agg is not None:
                    if agg["escs"]:
                        vars_["redstackpro_adcs_forest_escs"] = agg["escs"]
                    if agg["esc_vars"]:
                        vars_["redstackpro_adcs_esc_vars"] = agg["esc_vars"]
                    if agg["acl_templates"]:
                        vars_["redstackpro_adcs_acl_templates"] = agg["acl_templates"]

            # Domain users flagged privilege: local_admin become members of the
            # local Administrators group on the Windows member servers of their own
            # domain (not the DC, which they already control or do not). GOAD models
            # this per host (dracarys puts rhaegal in vhagar's Administrators); our
            # single privilege value scopes it to the domain's members, which is the
            # same outcome for a one-member domain and a sensible generalization for
            # more. The list is DOMAIN\user so the member adds the domain principal.
            if self._is_range() and node["kind"] in ("srv", "wks"):
                admins = self._local_admins_for(nid)
                if admins:
                    vars_["redstackpro_srv_local_admins"] = admins
                # A Domain Users member cannot RDP anywhere by default, so the
                # host chosen as patient zero's landing spot has to let it in.
                # Remote Desktop Users, not Administrators: the point is a
                # low-priv desktop, and making p0 a local admin here would skip
                # the first half of the solution.
                if nid in landing:
                    vars_["redstackpro_srv_rdp_users"] = [
                        "%s\\%s" % (i["netbios"], i["username"]) if i["netbios"]
                        else i["username"]
                        for i in landing[nid]]

            proxy = vars_.pop("proxy_jump", None)
            if self._is_windows(node):
                # ProxyJump is an OpenSSH feature. A Windows host reached over
                # psrp needs the control node on the jumpbox VPN, or a SOCKS
                # proxy through it in ansible_psrp_proxy. Emitting the SSH args
                # anyway would look like a management path that works. See 0019.
                # A range's Windows host is provisioned over psrp as the local
                # Administrator; an ops range's Windows box self-provisions and
                # is only ever reached by the winrm_ca bootstrap. See
                # goad-native-recreation.
                vars_.update(RANGE_WINDOWS_CONNECTION if self._is_range()
                             else WINDOWS_CONNECTION)
                # A Windows operator is internal and reached at its private
                # address over that VPN or proxy, never at a public one it does
                # not hold, so address it privately like every other managed host.
                vars_["ansible_host"] = _token(self.ctx.name(nid), "private_address")
            elif proxy:
                vars_["ansible_ssh_common_args"] = (
                    '-o ProxyJump=%s@%s '
                    '-o StrictHostKeyChecking=accept-new'
                    % (platform_account(self.topology.get("mode")), proxy))
                # Management goes through the jumpbox over the private network. A
                # host that also holds a public address holds it for its own
                # inbound service, not for ssh: the jumpbox reaching that public
                # address hairpins out through the internet gateway, so the source
                # is no longer the jumpbox security group the management rule
                # allows and the connection is dropped. So a proxied host is always
                # managed at its private address.
                vars_["ansible_host"] = _token(self.ctx.name(nid), "private_address")
            # AD host_vars (the domain pointer for a controller, the controller
            # address for a member) apply whether the member is Windows or Linux,
            # so they are set here rather than in the Windows branch.
            if self._is_range() and node["kind"] in ("dc", "srv", "wks"):
                vars_.update(self._ad_vars(node))
                # An AD host also gets its FQDN, so the hosts-file play can map
                # it by fully-qualified name as well as by its canvas alias
                # (redstackpro_host_shortname, set for every host above). The
                # address is a placeholder resolved at apply, carried in
                # ansible_host; here we only need the name. See range-access-model.
                fqdn = self._host_fqdn(node)
                if fqdn:
                    vars_["redstackpro_host_fqdn"] = fqdn
                # A normalized edr the SIEM-agent step reads without knowing the
                # host kind. wazuh and elastic name an agent to install; defender
                # and none install nothing.
                edr = node.get("overlay", {}).get("edr")
                if edr:
                    vars_["redstackpro_edr"] = edr
                # Windows Defender RTP is OFF by default (GOAD parity, so lab
                # tooling runs). A defended range opts a host back in with the
                # defender_enabled overlay toggle; the host_vulns role reads
                # redstackpro_defender_enabled. Independent of edr on purpose, so
                # a host can run Defender AND ship telemetry to a wazuh/elk SIEM.
                if node.get("overlay", {}).get("defender_enabled"):
                    vars_["redstackpro_defender_enabled"] = True
                # Endpoint telemetry (Sysmon + command-line/DS-access auditing) is
                # off by default so a plain lab stays quiet; a defended host whose
                # SIEM should see process/network/object-change events opts in with
                # the endpoint_telemetry toggle. The host_vulns role reads
                # redstackpro_endpoint_telemetry.
                if node.get("overlay", {}).get("endpoint_telemetry"):
                    vars_["redstackpro_endpoint_telemetry"] = True
            out[self.ctx.name(node["id"])] = vars_
        return dict(sorted(out.items()))

    def _is_range(self):
        return self.ctx.topology.get("mode") == "range"

    def _provider_vulns(self, vulns):
        """A declared vulns list, dropping any id VULN_PROVIDERS restricts to
        providers this compile is not targeting. A compile with no provider
        (self.provider is None, as a caller that never names one) keeps only
        the unrestricted ids -- the same conservative default as an unnamed
        cloud provider, since an unnamed compile is never Proxmox/ESXi."""
        return [v for v in (vulns or [])
                if self.provider in VULN_PROVIDERS.get(v, (self.provider,))]

    @staticmethod
    def _is_windows(node):
        """Read off the overlay rather than the kind, because os is a per node
        choice and an operators group holds both. Any Windows build counts: the
        attack side names it "windows" and a range names "windows_server_2019",
        while a Linux server or a SIEM names a non-Windows os."""
        return node.get("overlay", {}).get("os", "").startswith("windows")

    # -- AD / range

    def _assumed_breach_users(self):
        """Every domain user flagged assumed_breach: the range's patient-zero
        foothold identities. Each is a low-priv domain user (seeded by the dc
        role) the jumpbox also creates as a local admin so an operator can SSH in
        as it. See range-access-model and P2.5."""
        out = []
        for node in self.ctx.nodes.values():
            if node.get("kind") != "domain":
                continue
            ov = node.get("overlay") or {}
            for u in ov.get("users") or []:
                if u.get("assumed_breach"):
                    out.append({"username": u["username"], "domain": ov.get("fqdn")})
        return out

    def _local_admins_for(self, host_id):
        """DOMAIN\\user for every domain user flagged privilege: local_admin in the
        domain this host joins. The member server adds them to local Administrators
        so, e.g., a bot that logs on as that user can run there (dracarys's rhaegal
        on vhagar). Scoped to the host's own domain."""
        dom = self._domain_of(host_id)
        if dom is None:
            return []
        ov = self.ctx.nodes[dom].get("overlay") or {}
        netbios = ov.get("netbios") or ""
        out = []
        for u in ov.get("users") or []:
            if u.get("privilege") == "local_admin":
                out.append("%s\\%s" % (netbios, u["username"]) if netbios
                           else u["username"])
        return out

    def _breach_landing(self):
        """Where patient zero actually gets a desktop: {host_id: [identity, ...]}.

        The portal is how an operator enters a range, and the assumed-breach story
        needs a tile that logs in AS patient zero rather than as the operator --
        otherwise a beacon launched from the portal runs in the wrong context and
        the engagement starts from the wrong token. So each breach domain gets one
        landing host, the Windows member its patient zero can sign in to.

        One host per domain, not all of them: signing p0 in everywhere would hand
        the range away before the solution starts. Lateral movement is the
        exercise; the landing host is only the doorway.

        A workstation is preferred over a server because that is where a real
        low-priv user sits, and because a server in admin mode allows only two
        concurrent sessions -- an operator tile competing with a provisioning
        session is a confusing failure. A DC is never chosen: a Domain Users
        member signing in there interactively is not the shape we are modelling.
        A node may claim the job outright with a breach_landing overlay flag.
        """
        out = {}
        for node in self.ctx.nodes.values():
            if node.get("kind") != "domain":
                continue
            ov = node.get("overlay") or {}
            users = [u for u in (ov.get("users") or []) if u.get("assumed_breach")]
            if not users:
                continue
            candidates = [
                h for h in self.ctx.hosts()
                if h["kind"] in ("srv", "wks")
                and self._is_windows(h)
                and self._domain_of(h["id"]) == node["id"]
            ]
            if not candidates:
                continue
            # Explicit claim wins; then a workstation; then a server. Sorted by
            # inventory name inside each tier so the choice is stable across
            # compiles rather than following dict order.
            def rank(h):
                claimed = (h.get("overlay") or {}).get("breach_landing")
                return (0 if claimed else 1,
                        0 if h["kind"] == "wks" else 1,
                        self.ctx.name(h["id"]))
            landing = sorted(candidates, key=rank)[0]
            netbios = ov.get("netbios") or ""
            for u in users:
                # The dc role seeds a declared password and falls back to the
                # shared lab password, so the tile has to make the same choice or
                # it signs in with the wrong credential. GOAD declares one for
                # hodor, so this is the common case, not the edge. A declared
                # password is already public in the template; the lab password is
                # never emitted -- the tile reads it on the jumpbox at run time.
                identity = {"username": u["username"], "netbios": netbios,
                            "fqdn": ov.get("fqdn")}
                if u.get("password"):
                    identity["password"] = u["password"]
                out.setdefault(landing["id"], []).append(identity)
        return out

    def _domain_of(self, host_id):
        """The domain a host joins, or None. A member joins one."""
        for e in self.ctx.by_role.get("joins", []):
            if e["source"] == host_id and self.ctx.kind(e["target"]) == "domain":
                return e["target"]
        return None

    def _adcs_forest_escs(self, node):
        """For a certificate-authority host (role adcs, or an adcs service), the
        union of ESC ids declared across every host in its domain, plus any
        certificate template named in the domain's ACLs (ESC4). The adcs role
        plants all of these on the CA host, so the canvas can declare each ESC on
        the node upstream GOAD lists it on (esc7/13/15 on the essos DC, esc6/11 on
        the CA member) while a single CA host still plants the whole set. Also
        collects the ESC7 CA-manager and ESC13 group parameters from wherever they
        are declared. Returns None for a non-CA host."""
        overlay = node.get("overlay", {}) or {}
        is_ca = (overlay.get("role") == "adcs"
                 or "adcs" in (overlay.get("services") or []))
        if not is_ca:
            return None
        domain = self._domain_of(node["id"])
        if domain is None:
            return None
        escs, esc_vars, acl_templates = set(), {}, set()
        for e in self.ctx.by_role.get("joins", []):
            if e["target"] != domain:
                continue
            ho = self.ctx.nodes.get(e["source"], {}).get("overlay", {}) or {}
            escs.update(v for v in (ho.get("vulns") or []) if v.startswith("esc"))
            vv = ho.get("vulns_vars") or {}
            # Every per-technique knob a host can set. A key missing from this
            # tuple is silently dropped on the way to the CA, so the technique
            # plants with its default and the topology's value is never applied.
            for k in ("esc7_manager", "esc13_group", "esc5_principal",
                      "esc14_target", "esc14_subject"):
                if k in vv:
                    esc_vars[k] = vv[k]
        # Certificate templates named as an ACL target (ESC4, or a lab's own name
        # like SignatureValidation): the CA host plants a generic enrollable
        # template of that exact name so the over-permissive ACL resolves onto it.
        dov = self.ctx.nodes.get(domain, {}).get("overlay", {}) or {}
        for a in (dov.get("acls") or []):
            m = re.match(r"CN=([^,]+),CN=Certificate Templates",
                         a.get("target", ""))
            if m:
                acl_templates.add(m.group(1))
        return {"escs": sorted(escs), "esc_vars": esc_vars,
                "acl_templates": sorted(acl_templates)}

    def _dc_of(self, domain_id):
        """The controller that anchors a domain, or None."""
        for e in self.ctx.by_role.get("joins", []):
            if e["target"] == domain_id and self.ctx.kind(e["source"]) == "dc":
                return e["source"]
        return None

    def _parent_domain(self, domain_id):
        """The parent of a child domain, or None for a forest or tree root. A
        child domain is the target of a parent_child trust; its parent is the
        source."""
        for e in self.ctx.by_role.get("trusts", []):
            if e.get("trust_type") == "parent_child" and e["target"] == domain_id:
                return e["source"]
        return None

    def _host_fqdn(self, node):
        """An AD host's fully-qualified name, <id>.<domain fqdn>, or None. The id
        is the bare node id (winterfell), which is also the Windows computer name,
        so the FQDN is winterfell.north.sevenkingdoms.local. A DC uses its own
        domain; a member the domain it joins."""
        dom = self._domain_of(node["id"])
        if dom is None:
            return None
        fqdn = (self.ctx.nodes[dom].get("overlay") or {}).get("fqdn")
        return "%s.%s" % (node["id"], fqdn) if fqdn else None

    def _ad_vars(self, node):
        """AD host_vars a joins edge alone cannot carry.

        A domain controller gets a pointer to its domain's vars file. The domain
        itself (users, groups, ACLs, trusts) is emitted there rather than inline,
        because a user nests a group list the flat host_vars renderer cannot
        express and yaml.safe_dump can. A member instead gets the address of the
        controller it must point DNS at before it can join, which is not known
        until apply, so it travels as a placeholder like every other address."""
        domain_id = self._domain_of(node["id"])
        if not domain_id:
            return {}
        if node["kind"] == "dc":
            fqdn = (self.ctx.nodes[domain_id].get("overlay", {}) or {}).get("fqdn")
            return ({"redstackpro_domain_vars": "vars/domains/%s.yml" % fqdn}
                    if fqdn else {})
        dc = self._dc_of(domain_id)
        if dc is None:
            return {}
        return {"redstackpro_join_dc_address":
                _token(self.ctx.name(dc), "private_address")}

    def domain_files(self):
        """One vars file per domain, consumed by the dc role. Range only. The
        controller reads its file to promote (forest root or child) and to
        populate the directory. A child domain also learns its parent's DC
        address as a placeholder, so it can point DNS there before it joins the
        forest."""
        files = {}
        for domain in self.ctx.of_kind("domain"):
            overlay = domain.get("overlay", {}) or {}
            fqdn = overlay.get("fqdn")
            if not fqdn:
                continue
            users = overlay.get("users", []) or []
            groups = {g for u in users for g in (u.get("groups") or [])}
            # Group-in-group nesting (e.g. Dragons -> QueenProtector -> Domain
            # Admins). Every group named as a nesting parent or child must exist,
            # so fold them into the set the controller creates.
            group_members = overlay.get("group_members", {}) or {}
            groups |= set(group_members.keys())
            groups |= {m for members in group_members.values() for m in members}
            groups = sorted(groups)
            parent = self._parent_domain(domain["id"])
            parent_fqdn = None
            parent_dc_address = None
            if parent is not None:
                parent_fqdn = (self.ctx.nodes[parent].get("overlay", {}) or {}).get("fqdn")
                parent_dc = self._dc_of(parent)
                if parent_dc is not None:
                    parent_dc_address = _token(self.ctx.name(parent_dc),
                                               "private_address")
            trusts = []
            for e in self.ctx.by_role.get("trusts", []):
                if e["source"] != domain["id"]:
                    continue
                target = self.ctx.nodes.get(e["target"], {}).get("overlay", {}) or {}
                target_dc = self._dc_of(e["target"])
                trusts.append({
                    "target_fqdn": target.get("fqdn"),
                    "target_netbios": target.get("netbios"),
                    # The controller across the trust, so the source can add a DNS
                    # conditional forwarder to it and reach it to build the trust.
                    "target_dc_address": (_token(self.ctx.name(target_dc),
                                                 "private_address")
                                          if target_dc else None),
                    "type": e.get("trust_type"),
                    "direction": e.get("direction"),
                    "transitive": e.get("transitive", False),
                })
            # The domain's member hosts and the vulns planted on each, so the dc
            # role can apply the domain-level attack paths (a computer's
            # unconstrained delegation, a GPP password in SYSVOL, shadow
            # credentials on a computer). Host-local vulns (a member's MSSQL or
            # IIS) are applied by that host's own role from its host_vars.
            members = []
            for e in self.ctx.by_role.get("joins", []):
                if e["target"] != domain["id"]:
                    continue
                host = self.ctx.nodes.get(e["source"], {})
                host_overlay = host.get("overlay", {}) or {}
                members.append({
                    "hostname": host_overlay.get("hostname", e["source"]),
                    "kind": host.get("kind"),
                    "vulns": self._provider_vulns(host_overlay.get("vulns")),
                    "vulns_vars": host_overlay.get("vulns_vars", {}) or {},
                })
            data = {
                "domain_fqdn": fqdn,
                "domain_netbios": overlay.get("netbios"),
                "forest_root": parent is None,
                "parent_fqdn": parent_fqdn,
                "parent_dc_address": parent_dc_address,
                "users": users,
                "groups": groups,
                "group_members": group_members,
                "ous": overlay.get("ous", []) or [],
                "acls": overlay.get("acls", []) or [],
                "trusts": trusts,
                "members": members,
                # Group-managed service accounts and LAPS reader delegations are
                # domain-level attack surface applied after the members join.
                "gmsa": overlay.get("gmsa", []) or [],
                "laps_readers": overlay.get("laps_readers", []) or [],
            }
            body = ("# Generated by redStackPRO. The domain %s, read by the dc "
                    "role.\n" % fqdn) + yaml.safe_dump(
                        data, sort_keys=False, default_flow_style=False)
            files["ansible/vars/domains/%s.yml" % fqdn] = body
        return files

    def _primary_address(self, node_id):
        return ("public_address"
                if self.ctx.exposure(node_id) == "internet"
                else "private_address")

    def _overlay_vars(self, node):
        """Overlay values the roles need, namespaced so they cannot collide.

        vulns passes through _provider_vulns first, so a template can declare
        an id everywhere and have this compile quietly drop the ones its
        provider cannot land (see VULN_PROVIDERS)."""
        prefix = "redstackpro_%s_" % node["kind"]
        return {prefix + k: (self._provider_vulns(v) if k == "vulns" else v)
                for k, v in sorted(node.get("overlay", {}).items())}

    def _group_vars(self):
        """No key material, only a path. The compiler emits a variable and never
        a key. See 0011. A default is emitted rather than leaving the variable
        undefined, because an undefined one fails at fact gathering with an
        error that says nothing about what to do."""
        all_ = {
            "ansible_user": platform_account(self.topology.get("mode")),
            "redstackpro_ssh_key_path": "~/.ssh/id_ed25519",
            "ansible_ssh_private_key_file": "{{ redstackpro_ssh_key_path }}",
            "ansible_python_interpreter": "auto_silent",
            # The certificate authority the jumpbox builds and the
            # redirector and collector trust. Three roles on three hosts
            # need the same two paths, and a role default is scoped to the
            # role that declares it.
            "redstackpro_ca_dir": "/etc/redstackpro/ca",
            "redstackpro_ca_local_path":
                "{{ playbook_dir }}/generated/redstackpro-ca.crt",
            # Where the operator connects from, exactly as terraform received
            # it, comma separated. The jumpbox's fail2ban uses it to keep the
            # legitimate operator out of the jail guarding the range's only
            # entry point. An apply-time answer, not a canvas one, so it arrives
            # as a placeholder that tf_inventory fills from the settings output.
            "redstackpro_operator_source_ranges":
                _token(SETTINGS_NODE, "operator_source_ranges"),
        }
        # The one credential the operator is handed, in both modes. Terraform
        # calls it the shared password for the admin account, the Windows
        # operator, and the portal, so a service on an ops box that needs a
        # password should use that one rather than invent or inherit another.
        # AdaptixC2 shipped upstream's profile with the password "pass" because
        # nothing it could reach knew the real one. Never written into the
        # export: the operator supplies it at run time from the terraform output
        # through the environment, the same secret terraform printed. See 0001.
        all_["redstackpro_lab_password"] = \
            "{{ lookup('env', 'REDSTACKPRO_LAB_PASSWORD') }}"
        if self._is_range():
            # The account the range's Windows hosts are provisioned as.
            # See goad-native-recreation.
            all_["redstackpro_range_admin_user"] = "Administrator"
            # Per-user passwords, for a lab that seeds real per-account
            # credentials (GOAD's documented passwords). A task that logs on as,
            # or plants the credential of, a specific user looks its password up
            # here and falls back to the shared lab password for an account that
            # has none, so a login/coercion bot or a planted credential matches
            # the account's actual password rather than assuming the lab one.
            # Only accounts with an explicit password appear.
            # Key by the bare sAMAccountName and by every casing of the
            # NETBIOS\user form, because a bot or plant references its user as
            # "north\robb.stark" while the account is created bare -- keying both
            # lets a task look the password up with the exact string it holds,
            # without brittle backslash handling in Jinja.
            user_pw = {}
            for _dom in self.ctx.of_kind("domain"):
                _ov = _dom.get("overlay", {}) or {}
                _nb = _ov.get("netbios") or ""
                for _u in _ov.get("users", []) or []:
                    if not _u.get("password"):
                        continue
                    _un, _pw = _u["username"], _u["password"]
                    user_pw[_un] = _pw
                    for _p in {_nb, _nb.lower(), _nb.upper()} - {""}:
                        user_pw["%s\\%s" % (_p, _un)] = _pw
            all_["redstackpro_user_passwords"] = user_pw
            # The cloud/hypervisor this range was compiled for. Roles that must
            # differ by platform branch on this rather than sharing one path, so
            # a fix proven on one provider cannot regress another. Defaults to
            # "generic" when the compile did not name a provider. See
            # goad-native-recreation and the dc role's promotion branch.
            all_["redstackpro_platform"] = self.provider or "generic"
            # The SIEM addresses a Windows host's agents report to. A host reports
            # to every SIEM box the range has, so this maps each SIEM box's
            # product to the edr it serves (elk -> elastic, wazuh -> wazuh): the
            # siem_agent role installs Winlogbeat when there is an elastic address
            # and the Wazuh agent when there is a wazuh address, each pointed at
            # its own box, so both run when both boxes exist. The flat address is
            # a single-SIEM fallback.
            siems = self.ctx.of_kind("siem")
            if siems:
                product_edr = {"elk": "elastic", "elasticsearch": "elastic",
                               "wazuh": "wazuh", "splunk": "splunk"}
                addresses = {}
                for s in siems:
                    edr = product_edr.get(s.get("overlay", {}).get("product", ""))
                    if edr and edr not in addresses:
                        addresses[edr] = _token(
                            self.ctx.name(s["id"]), "private_address")
                all_["redstackpro_siem_addresses"] = addresses
                all_["redstackpro_siem_address"] = _token(
                    self.ctx.name(siems[0]["id"]), "private_address")

        # Where the collector's dashboard lives, for the portal to proxy to.
        #
        # A group var rather than a logs_to edge, and that is forced rather than
        # chosen: the collector's receiver certificate is issued by the JUMPBOX's
        # authority, so the collector already depends on the jumpbox. An edge
        # pointing back would be a real dependency cycle and the generator says
        # so -- "open-log01 -> jump-bx01 -> open-log01". The jumpbox needs to
        # KNOW the address, not to be ordered after it, which is what a var is
        # for. Same shape as redstackpro_siem_addresses above, for the same
        # reason: a host that must reach a box it shares no edge with.
        collectors = self.ctx.of_kind("collector")
        if collectors:
            overlay = collectors[0].get("overlay", {})
            all_["redstackpro_collector_address"] = _token(
                self.ctx.name(collectors[0]["id"]), "private_address")
            # The wire, not just the address. A logs_to edge carries the port and
            # the TLS choice off the collector's overlay precisely so the two
            # sides cannot drift; a jumpbox shipping on the fallback would
            # otherwise use role defaults that agree today and stop agreeing the
            # moment someone edits the overlay, and the failure is a shipper
            # talking to a closed port.
            if overlay.get("ingest_port"):
                all_["redstackpro_collector_ingest_port"] = overlay["ingest_port"]
            if "tls" in overlay:
                all_["redstackpro_collector_tls"] = overlay["tls"]
        return {"all": all_}

    # -- ordering

    def _role_for_group(self, group):
        for kind, spec in self.registry.kinds.items():
            if spec.get("ansible_group") == group:
                return "redstackpro.%s" % kind
        raise GenerationError("no kind maps to ansible_group %r" % group)

    def _play_order(self):
        """Derived from address dependency, never declared. See 0007.

        A range has no address-carrying edges (a joins edge injects the domain
        by name, not by address), so there is nothing to derive from. The order
        is instead the AD build sequence: the jumpbox first for the CA and the
        management path, then controllers before the members that join them,
        then the SIEM that collects from all of them."""
        if self._is_range():
            order = ["jumpboxes", "domain_controllers", "servers",
                     "workstations", "siem"]
            present = [g for g in order if g in self.groups]
            return present + [g for g in self.groups if g not in present]

        deps = {}
        for node in self.ctx.hosts():
            deps.setdefault(node["id"], set())
        for edge in self.ctx.edges:
            role = self.registry.roles.get(edge["role"])
            if not role:
                continue
            for inject in role.get("injects", []):
                # Only a derived field creates an ordering constraint. An
                # overlay or edge field is known at compile time, so it says
                # nothing about which host has to exist first. A collecting
                # inject hides its derived fields inside each entry.
                specs = (list(inject["entry"].values())
                         if inject.get("collect") else [inject])
                for spec in specs:
                    if "derived_field" not in spec or "from" not in spec:
                        continue
                    source = edge[spec["from"]]
                    for node_id in self._inject_targets(edge, inject["into"]):
                        if node_id != source and node_id in deps:
                            deps[node_id].add(source)

        ordered, seen = [], set()

        def visit(node_id, stack):
            if node_id in seen:
                return
            if node_id in stack:
                raise GenerationError(
                    "dependency cycle: %s" % " -> ".join(stack + [node_id]))
            stack.append(node_id)
            for dep in sorted(deps.get(node_id, ())):
                if dep in deps:
                    visit(dep, stack)
            stack.pop()
            seen.add(node_id)
            ordered.append(node_id)

        for node_id in sorted(deps):
            visit(node_id, [])

        stages, placed = [], set()
        for node_id in ordered:
            group = self.registry.kinds[self.ctx.kind(node_id)]["ansible_group"]
            if group in placed:
                continue
            if all(self.registry.kinds[self.ctx.kind(d)]["ansible_group"] in placed
                   or self.registry.kinds[self.ctx.kind(d)]["ansible_group"] == group
                   for d in deps[node_id]):
                stages.append(group)
                placed.add(group)

        for group in self.groups:
            if group not in placed:
                stages.append(group)
                placed.add(group)
        return stages


def generate(topology, registry=None, skip_validation=False, provider=None):
    """Returns {path: contents}, the Ansible half of a compile file map.

    ``provider`` names the cloud/hypervisor the range compiles for and is
    surfaced to the roles as ``redstackpro_platform`` so platform-specific
    steps branch on it. It is only meaningful for a range."""
    if not skip_validation and not is_valid(topology, registry=registry):
        raise GenerationError(
            "topology has validation errors; the compiler refuses to run")

    # The caller's document keeps its authored value, placeholder and all; the
    # randomized secret lives only in this export.
    topology = copy.deepcopy(topology)
    _randomize_gating(topology)
    plan = AnsiblePlan(topology, registry, provider=provider)
    files = {}

    files["ansible/inventory.yml"] = _render_inventory(plan)
    files["ansible/group_vars/all.yml"] = (
        "# Generated by redStackPRO. Override redstackpro_ssh_key_path if your key is\n"
        "# somewhere else. redStackPRO never emits key material, only a path.\n"
        + _render_yaml(plan.group_vars["all"]))
    for name, vars_ in plan.host_vars.items():
        files["ansible/host_vars/%s.yml" % name] = _render_yaml(vars_)
    # One vars file per domain for the dc role. Empty for an attack range, which
    # has no domains, so this is a no-op there.
    files.update(plan.domain_files())
    files["ansible/site.yml"] = _render_site(plan)
    return files


# ---------------------------------------------------------------- rendering
# Rendered by hand rather than with yaml.dump, so the output is stable, ordered,
# and commented. Generated files are read by people.

# A bare scalar YAML will hand back unchanged. Deliberately narrow: it starts
# with a letter or underscore, so nothing that looks like a number, a date, or a
# sequence entry gets in, and the reserved words are excluded separately.
_PLAIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_./-]*$")

# YAML 1.1 reads all of these as something other than a string.
_RESERVED = {"y", "yes", "n", "no", "true", "false", "on", "off",
             "null", "none", "nan", "inf"}


def _quote(text):
    """Double quoted, with the escapes YAML defines. Backslash goes first, or
    escaping a quote would then have its own backslash escaped."""
    for old, new in (("\\", "\\\\"), ('"', '\\"'), ("\n", "\\n"),
                     ("\r", "\\r"), ("\t", "\\t")):
        text = text.replace(old, new)
    return '"%s"' % text


def _needs_quotes(text):
    """Asked of the parser rather than decided from a list of punctuation.

    The punctuation list misses everything YAML coerces by shape rather than by
    character: no, yes, on, and off become booleans, 007 and 1.5 become numbers,
    2024-01-01 becomes a date, and a leading dash does not parse at all. A
    gating header value or a version string can be any of those. So the test is
    whether the parser gives the string back, in the mapping context it will
    actually sit in.
    """
    if not text or text != text.strip():
        return True
    if _PLAIN.match(text) and text.lower() not in _RESERVED:
        return False
    try:
        return yaml.safe_load("v: %s" % text) != {"v": text}
    except yaml.YAMLError:
        return True


def _scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    return _quote(text) if _needs_quotes(text) else text


def _render_yaml(mapping, indent=0):
    pad = " " * indent
    lines = ["---"] if indent == 0 else []
    for key, value in mapping.items():
        if isinstance(value, list):
            # An EMPTY list has to render as an explicit [], not a bare "key:".
            # A bare key with nothing under it parses as None, and None is not an
            # empty list: `| default([])` does not rescue it, because the variable
            # IS defined. Found live on goad-wazuh, whose ws01 declares "vulns": []
            # and so got redstackpro_wks_vulns: None, which crashed the host_vulns
            # role with "the filter plugin 'ansible.builtin.intersect' failed:
            # 'NoneType' object is not iterable" and failed the whole play.
            if not value:
                lines.append("%s%s: []" % (pad, key))
                continue
            lines.append("%s%s:" % (pad, key))
            for item in value:
                if isinstance(item, dict):
                    # A list of mappings: the first key carries the dash, the
                    # rest align under it.
                    first = True
                    for name, inner in item.items():
                        prefix = "%s  - " % pad if first else "%s    " % pad
                        lines.append("%s%s: %s" % (prefix, name, _scalar(inner)))
                        first = False
                else:
                    lines.append("%s  - %s" % (pad, _scalar(item)))
        elif isinstance(value, dict):
            # Same trap as the empty list above: a bare key renders as None.
            if not value:
                lines.append("%s%s: {}" % (pad, key))
                continue
            lines.append("%s%s:" % (pad, key))
            lines.append(_render_yaml(value, indent + 2))
        else:
            lines.append("%s%s: %s" % (pad, key, _scalar(value)))
    return "\n".join(lines) + ("\n" if indent == 0 else "")


def _render_inventory(plan):
    lines = [
        "---",
        "# Generated by redStackPRO. Do not edit.",
        "# Addresses are placeholders until tools/tf_inventory.py fills them",
        "# from terraform output.",
        "all:",
        "  children:",
    ]
    for group, hosts in plan.groups.items():
        lines.append("    %s:" % group)
        lines.append("      hosts:")
        for host in hosts:
            lines.append("        %s:" % host)
    if plan.windows_hosts:
        # An auxiliary group. Every host here is already in operators; this
        # group only gives the winrm_ca bootstrap play something to target. See
        # 0022.
        lines.append("    windows:")
        lines.append("      hosts:")
        for host in plan.windows_hosts:
            lines.append("        %s:" % host)
    return "\n".join(lines) + "\n"


def _render_site(plan):
    lines = [
        "---",
        "# Generated by redStackPRO. Play order is derived from address dependency,",
        "# never declared. A node that supplies an address is configured before",
        "# the nodes that consume it.",
    ]
    range_mode = plan._is_range()
    windows = set(plan.windows_hosts)
    for group in plan.play_order:
        group_windows = bool(windows & set(plan.groups.get(group, [])))
        # On the attack side a Windows host self-provisions from its boot script
        # (the account, the password, and RDP are set at first boot), so a group
        # that holds one excludes it from the play. A range inverts this: its
        # Windows hosts are the domain controllers and members the play exists to
        # provision, so they stay in and are driven over psrp. See 0019, 0022 and
        # goad-native-recreation.
        host_pattern = group
        if group_windows and not range_mode:
            host_pattern = "%s:!windows" % group
        roles = ["    - %s" % plan._role_for_group(group)]
        if not range_mode:
            # Shipping follows the logs_to edge, not the kind, so any host can
            # ship and the condition is the injected sink address rather than
            # group membership. It runs after the kind role because that is what
            # creates the logs it reads. A range collects through its SIEM's own
            # agents, not the shipper, so this is attack-side only.
            # The jumpbox is the exception, and it has to be. It is the one host
            # operators actually log into, so its auth.log IS the login source --
            # and it is the one host that cannot carry a logs_to edge, because
            # the collector's receiver certificate is issued by the jumpbox's own
            # authority. An edge back would be a dependency cycle and the
            # generator refuses it by name: open-log01 -> jump-bx01 ->
            # open-log01. So the jumpbox ships on the collector address instead,
            # which it knows as a group var.
            #
            # It ships before the collector is up, which is fine: filebeat
            # retries its output forever, and the CA it needs to trust the
            # receiver is the one this very host issued.
            sink = "log_sink_address | default('') | length > 0"
            if group == "jumpboxes":
                sink = ("(log_sink_address | default('') | length > 0) or "
                        "(redstackpro_collector_address | default('') | length > 0)")
            roles += [
                "    - role: redstackpro.shipper",
                "      when: %s" % sink,
            ]
        # A Windows play reached over psrp runs as the connected admin and cannot
        # use SSH-style privilege escalation, so become is off there; every Linux
        # play keeps it on for package installation.
        become = "false" if (range_mode and group_windows) else "true"
        lines += [
            "",
            "- name: Configure %s" % group,
            "  hosts: %s" % host_pattern,
            # Free strategy so each host in the group provisions on its own pace
            # rather than in lockstep, the way the real redStack's per-host setup
            # scripts run in parallel. A slow build on one teamserver no longer
            # holds up the others. Cross-group order still comes from play order.
            "  strategy: free",
            "  become: %s" % become,
            "  roles:",
        ] + roles

    # A final play that plants the domain-level attack paths targeting member
    # computers (unconstrained delegation, shadow credentials), after the members
    # have joined. It runs on the controllers, each connecting as the domain
    # admin its own play set. Range only, when there are controllers.
    if range_mode and "domain_controllers" in plan.groups:
        lines += [
            "",
            "- name: Plant domain attack paths",
            "  hosts: domain_controllers",
            "  strategy: free",
            "  become: false",
            "  roles:",
            "    - redstackpro.domain_vulns",
        ]

    # A final play that installs the SIEM agent on every Windows host, after the
    # SIEM box itself is up (it is the last kind play). Each host connects with
    # the user its own play left set, so a controller uses the domain admin and a
    # member the local one. The role is a no-op on a host whose edr names no
    # agent. Only emitted when the range has a SIEM.
    if range_mode and plan.ctx.of_kind("siem") and plan.windows_hosts:
        lines += [
            "",
            "- name: Install SIEM agents",
            "  hosts: windows",
            "  strategy: free",
            "  become: false",
            "  roles:",
            "    - redstackpro.siem_agent",
        ]

    # Give every host a hosts file naming the others, so the compile resolves
    # itself by name and not just by IP. The recipient is any host that does NOT
    # join a domain: an AD member (dc/srv/wks) already resolves the whole domain
    # through the DCs' DNS and gets nothing, while a standalone host has no such
    # resolver. That single rule produces both wanted shapes -- an offense stack
    # (no domains) is all-standalone so every host names every other, and a
    # defense range's non-joined hosts (the jumpbox, a SIEM, an operator box)
    # name the AD hosts they cannot otherwise resolve. The block itself always
    # lists every host in the compile; only the recipient set is filtered here.
    #
    # Two plays because connection and privilege differ: Linux hosts edit
    # /etc/hosts as root over ssh; Windows hosts edit their own hosts file over
    # psrp with no become. The offense Windows operator has no WinRM (it
    # self-provisions at boot), so it is NOT an ansible recipient -- its hosts
    # block rides the boot script instead (operator_setup.ps1 / RSP_HOSTS). That
    # is why the Windows play is range-only: only a range's Windows hosts are
    # reachable over psrp. See range-access-model and the /etc/hosts PAI item.
    ad_groups = [g for g in ("domain_controllers", "servers", "workstations")
                 if g in plan.groups]
    ad_hosts = set().union(*(set(plan.groups[g]) for g in ad_groups)) \
        if ad_groups else set()
    ad_exclude = "".join(":!%s" % g for g in ad_groups)
    all_hosts = [h for hosts in plan.groups.values() for h in hosts]
    non_joined_linux = [h for h in all_hosts
                        if h not in ad_hosts and h not in set(plan.windows_hosts)]
    non_joined_windows = [w for w in plan.windows_hosts if w not in ad_hosts]
    if non_joined_linux and len(all_hosts) > 1:
        # all:!windows already drops the Windows hosts; the AD-group excludes
        # drop any Linux AD member too, so what remains is the standalone Linux
        # hosts (jumpbox, SIEM, operator/teamserver/redirector boxes). In a
        # range the jumpbox writes its file in its own provisioning pass, which
        # is what carries the full set onto the one host the operator enters by.
        lines += [
            "",
            "- name: Map hosts by name (Linux, non-domain-joined)",
            "  hosts: all:!windows%s" % ad_exclude,
            "  strategy: free",
            "  become: true",
            "  roles:",
            "    - redstackpro.hosts",
        ]
    if range_mode and non_joined_windows:
        lines += [
            "",
            "- name: Map hosts by name (Windows, non-domain-joined)",
            "  hosts: windows%s" % ad_exclude,
            "  strategy: free",
            "  become: false",
            "  roles:",
            "    - redstackpro.hosts",
        ]
    return "\n".join(lines) + "\n"
