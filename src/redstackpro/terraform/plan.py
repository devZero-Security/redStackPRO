"""What every Terraform backend needs before it renders anything.

Nodes become module blocks calling static modules. Edges become generated code,
because a firewall rule permitting 443 from one host to another exists only
because someone drew a line. See 0015.

Everything provider agnostic lives here. What a backend adds is the vocabulary:
GCP keys firewall rules on a network tag, AWS on a security group reference, and
0015 already names that as the place the abstraction leaks.
"""

import datetime as _dt
import ipaddress

from ..naming import platform_account, tf_ref
from ..registry import Registry
from ..validate import Context

# Attack-side host kinds and the AD range host kinds. Both become real machines
# the terraform stands up. A domain is a logical container, not a host, so it is
# absent here and never gets a module block; it drives the Ansible layer instead.
# See goad-native-recreation: a defend range compiles through this same native
# pipeline, not a GOAD package.
AD_HOST_KINDS = ("dc", "srv", "wks")
HOST_KINDS = ("redirector", "teamserver", "collector", "jumpbox", "operator",
              "dc", "srv", "wks", "siem")


class GenerationError(Exception):
    pass


# A default region per cloud provider, used when neither the compile nor the
# document names one. Proxmox has no region.
DEFAULT_REGION = {"aws": "us-east-1", "gcp": "us-east4"}

# Operator-facing control-plane ports per C2 product on a teamserver. An
# operator drives the teamserver over these from an operator box; the beacon
# channel itself rides the fronts edge through the redirector and is opened
# there. A teamserver with an unset or unknown C2 gets no operator control rule,
# the same secure default as a generic teamserver. See P7.
C2_CONTROL_PORTS = {
    "mythic": [7443],    # Mythic web UI
    "sliver": [31337],   # Sliver multiplayer operator listener
    "adaptix": [4321],   # AdaptixC2 teamserver operator endpoint
    # `none` is intentionally absent: it stands up no team server. It is the plain
    # Debian catchall for a custom, operator-supplied C2 (OC2 and the like, plus any
    # C2 kept for the roadmap such as Cobalt Strike), which the operator installs and
    # drives themselves rather than through an in-range operator box, so there is no
    # redStackPRO service to open a control port for. See P2.
}

# The VPN listen port per access mode, used when the jumpbox overlay leaves
# vpn_port unset. WireGuard is udp only; OpenVPN takes udp or tcp. See
# vpn-multiuser-spec.
VPN_DEFAULT_PORT = {"wireguard": 51820, "openvpn": 1194}


class TerraformPlan:
    def __init__(self, topology, registry=None, provider="gcp", region=None):
        self.provider = provider
        self.topology = topology
        self.registry = registry or Registry()
        self.ctx = Context(topology, self.registry)
        # Region: the compile argument wins, then a region on the document, then
        # the per-provider default. A location rather than provider vocabulary,
        # so the document may carry it without naming a provider. See 0053.
        self.region = region or topology.get("region") or DEFAULT_REGION.get(provider)

    # -- naming

    def ref(self, node_id):
        """Terraform module label. Underscores, derived from the composed name
        so a module label and a firewall reference describe the same host."""
        return tf_ref(self.ctx.prefix, node_id)

    def tag(self, node_id):
        """The string a person sees. GCP uses it as a network tag; AWS uses it
        as a resource name."""
        return self.ctx.name(node_id)

    # -- selection

    def networks(self):
        return [n for n in self.ctx.nodes.values() if n["kind"] == "network"]

    def segments(self):
        return [n for n in self.ctx.nodes.values() if n["kind"] == "segment"]

    def hosts(self):
        return [n for n in self.ctx.nodes.values() if n["kind"] in HOST_KINDS]

    def segments_in(self, network_id):
        return [s for s in self.segments()
                if self.ctx.network_of_segment(s["id"]) == network_id]

    def is_public(self, node):
        """Whether this host takes an address, not whether its segment permits
        one. The validator answers it, so the two cannot disagree. See 0021."""
        return self.ctx.public_address(node["id"])

    def takes_public_address(self, node):
        """Whether this host ends up with a public address in the export.

        is_public answers what the topology asked for; a range's jumpbox also gets
        one unconditionally, because it is the only way into the range. Both
        callers that care (which subnet a host lands in, and whether to allocate
        an address) go through here so they cannot disagree: on AWS a host that
        takes an address must leave the NAT-routed segment subnet, and deciding
        that twice is how the jumpbox ended up unreachable. See 0021.
        """
        return bool(self.is_public(node)
                    or (self.is_range() and node["kind"] == "jumpbox"))

    def public_hosts_in_network(self, network_id):
        """Hosts in this network that take a public address, so the AWS backend
        knows whether to build a public subnet for them."""
        return [h for h in self.hosts()
                if self.ctx.network_of_segment(self.primary_segment(h))
                == network_id and self.takes_public_address(h)]

    def is_windows(self, node):
        # An explicit os wins: the range schema names it "windows_server_2019"
        # and the attack side names it "windows", while a siem or a linux server
        # names a non-windows os. With no os set, the AD host kinds default to
        # Windows because a DC or a member server is one.
        os = node.get("overlay", {}).get("os", "")
        if os:
            return os.startswith("windows")
        return node["kind"] in AD_HOST_KINDS

    def is_gui_operator(self, node):
        """A Kali (or other non-Windows) operator with desktop:true: xrdp over a
        Guacamole RDP tile instead of SSH. Still Ansible-managed over 22, so this
        is intentionally separate from is_windows -- folding it in would route
        this host over WinRM, which a GUI Kali box has no listener for."""
        return (node["kind"] == "operator"
                and bool((node.get("overlay") or {}).get("desktop")))

    # -- range / AD selection

    def is_range(self):
        return self.topology.get("mode") == "haven"

    @property
    def admin_account(self):
        """The single platform account for this canvas (blueop for a range,
        redop for ops). The Linux admin/SSH identity every host authorizes; the
        terraform host modules take it as var.admin_username. See naming.py."""
        return platform_account(self.topology.get("mode"))

    @property
    def auto_stop(self):
        """When this range turns itself off, resolved to one shape every
        provider reads, or None when it does not. See 0057.

        The canvas offers two ways to say it and they answer different
        questions, so both are kept rather than collapsed. `at` is a daily wall
        clock stop, which is what the cloud schedulers express natively and what
        catches the range left running overnight. `after_hours` is a cap for a
        range started at an odd hour, where a fixed nightly time would let it
        run most of a day; it is approximate by construction, because a cron
        schedule cannot count from an apply, so it becomes a daily time too.

        When both are set the EARLIER of the two wins on the day of the apply.
        Taking the later one would let a range outlive the cap the operator
        asked for, and a cap that can be overridden by the other field is not a
        cap.

        `after_hours` is counted from the APPLY, not from this compile. It used
        to be counted here, which was the closest the generator could stand to
        the apply, and the gap between the two was silently eaten out of the
        TTL: a build compiled in the morning and applied that afternoon stopped
        itself part-provisioned, behind a run reporting no error. deploy.sh
        refuses that case at the apply boundary, but the trap was still there.
        It is now resolved by `time_offset` from hashicorp/time, which computes
        the instant once at apply and keeps it in state, so unlike `timestamp()`
        it does not produce a perpetual diff (verified: a second plan minutes
        later reports no changes).

        So the clock is HCL rather than a number whenever `after_hours` is in
        play, and callers interpolate `hour_expr` and `minute_expr` instead of
        formatting `hour` and `minute`. Those two stay, because `at` really is a
        compile-time constant and because they are what the shape is tested on.
        """
        cfg = self.topology.get("auto_stop") or {}
        if not cfg.get("enabled"):
            return None

        candidates = []
        at_minute = None
        at = cfg.get("at")
        if at:
            hh, mm = at.split(":")
            at_minute = int(hh) * 60 + int(mm)
            candidates.append(at_minute)
        hours = cfg.get("after_hours")
        if hours:
            # Kept for `hour`/`minute` below, which is what a caller that cannot
            # take an expression still reads, and what the shape is tested on.
            now = _dt.datetime.now(_dt.timezone.utc)
            candidates.append(
                (now.hour * 60 + now.minute + hours * 60) % (24 * 60))
        if not candidates:
            return None

        minute = min(candidates)
        return {
            "hour": minute // 60,
            "minute": minute % 60,
            "timezone": cfg.get("timezone") or "UTC",
            "after_hours": hours or None,
            "at_minute": at_minute,
            # Every provider reads these and never the numbers, so the three
            # generators stay identical and the apply-time resolution is written
            # once. Literals when there is no offset to wait for, because a
            # fixed `at` really is known now.
            #
            # Two forms because there are two contexts and they differ: `_expr`
            # goes where HCL already expects an expression (Azure's format()
            # call), `_tpl` goes inside a quoted string (the two cron lines).
            # Wrapping a literal as "${22}" renders correctly but is noise in a
            # file people read, and this file is the product.
            "hour_expr": ("local.rsp_stop_hour" if hours else str(minute // 60)),
            "minute_expr": ("local.rsp_stop_minute" if hours else str(minute % 60)),
            "hour_tpl": ("${local.rsp_stop_hour}" if hours else str(minute // 60)),
            "minute_tpl": ("${local.rsp_stop_minute}" if hours else str(minute % 60)),
            # Azure wants HHMM with no separator, which needs zero padding the
            # other two do not. Precomputed as a local so a fixed `at` still
            # renders the same literal it always did: an input that has not
            # changed must not produce a different file. See 0010.
            "hhmm_expr": ("local.rsp_stop_hhmm" if hours
                          else '"%02d%02d"' % (minute // 60, minute % 60)),
        }

    def needs_time_provider(self):
        stop = self.auto_stop
        return bool(stop and stop["after_hours"])

    def auto_stop_block(self):
        """The HCL that resolves the stop clock at apply, or [] when there is
        none to resolve.

        Emitted once per root module, above whatever schedule the provider
        wants. Shared here rather than written three times: `outputs()` taught
        the same lesson, that the per-provider half of one of these is usually
        the smaller half.
        """
        stop = self.auto_stop
        if not stop or not stop["after_hours"]:
            return []
        offset = ("time_offset.auto_stop.hour * 60 "
                  "+ time_offset.auto_stop.minute")
        # Both fields set: the earlier still wins, but the comparison can no
        # longer happen here, because one side is not known until apply. It
        # moves into HCL unchanged rather than quietly becoming "whichever the
        # generator saw first".
        if stop["at_minute"] is not None:
            offset = "min(%d, %s)" % (stop["at_minute"], offset)
        return [
            "",
            "# Auto stop, counted from the APPLY and not from the compile, so",
            "# staging a build ahead of deploying it does not eat the TTL.",
            "# time_offset stores the instant in state, so re-planning is a",
            "# no-op rather than a perpetual diff. See 0057.",
            'resource "time_offset" "auto_stop" {',
            "  offset_hours = %d" % stop["after_hours"],
            "}",
            "",
            "locals {",
            "  rsp_stop_at     = %s" % offset,
            "  rsp_stop_hour   = floor(local.rsp_stop_at / 60)",
            # A single %, not %%: this line is a literal in a list and is never
            # passed through % formatting, so an escape would survive into HCL.
            "  rsp_stop_minute = local.rsp_stop_at % 60",
            '  rsp_stop_hhmm   = format("%02d%02d", floor(local.rsp_stop_at / 60), local.rsp_stop_at % 60)',
            "}",
        ]

    def domains(self):
        return [n for n in self.ctx.nodes.values() if n["kind"] == "domain"]

    def joins_to(self, domain_id):
        """Hosts joined to this domain, DCs first so a play order that walks
        them promotes the controller before it joins a member."""
        joined = [self.ctx.nodes[e["source"]]
                  for e in self.ctx.by_role.get("joins", [])
                  if e["target"] == domain_id and e["source"] in self.ctx.nodes]
        return sorted(joined, key=lambda n: 0 if n["kind"] == "dc" else 1)

    def domain_of(self, host_id):
        for e in self.ctx.by_role.get("joins", []):
            if e["source"] == host_id and self.ctx.kind(e["target"]) == "domain":
                return e["target"]
        return None

    def ad_hosts(self):
        """Every host that joins a domain, DC or member. These are the machines
        the AD firewall opens intra-segment, because AD talks on a wide and
        partly dynamic set of ports a rule per service could not enumerate."""
        joined = {e["source"] for e in self.ctx.by_role.get("joins", [])}
        return [h for h in self.hosts() if h["id"] in joined]

    def intra_segment_hosts(self):
        """Hosts that accept all traffic from their own segment: the AD hosts
        (AD replicates on a wide, partly dynamic port set) plus the SIEM boxes
        (agents ship to them on ingest ports a rule per product would not
        enumerate, and a blocked ingest looks like a dead SIEM). The lab subnet
        is isolated, so an all-from-segment rule is the pragmatic shape. See 0019."""
        hosts = list(self.ad_hosts())
        seen = {h["id"] for h in hosts}
        hosts += [h for h in self.hosts()
                  if h["kind"] == "siem" and h["id"] not in seen]
        return hosts

    def management_port(self, node):
        """A Windows host is reached over WinRM rather than ssh, so the rule
        that opens its management path opens a different port. Same branch the
        Ansible generator makes for the connection plugin. See 0019."""
        return 5986 if self.is_windows(node) else 22

    def control_ports(self, node):
        """The management ports an operator uses to drive this teamserver, keyed
        on its C2 product. Empty for a non-teamserver or an unknown/unset C2, so
        a generic teamserver opens no operator control path by default. See P7."""
        if self.ctx.kind(node["id"]) != "teamserver":
            return []
        c2 = node.get("overlay", {}).get("c2", "")
        return list(C2_CONTROL_PORTS.get(c2, []))

    def operators(self):
        return [h for h in self.hosts() if self.ctx.kind(h["id"]) == "operator"]

    def vpn_access(self, jumpbox):
        """The VPN listener for this jumpbox, or None when access is the public
        portal. Returns (mode, port, protocol).

        Only meaningful on an artie topology: a haven range ignores the fields and
        keeps the public portal, so this returns None there. In a VPN mode the
        jumpbox exposes only its VPN port and management (ssh plus the Guacamole
        portal) rides the tunnel rather than the public 22/443. WireGuard is udp
        only; OpenVPN takes udp or tcp. The port defaults per mode when unset. See
        vpn-multiuser-spec.
        """
        if self.is_range():
            return None
        ov = jumpbox.get("overlay") or {}
        mode = ov.get("access_mode", "public")
        if mode not in VPN_DEFAULT_PORT:
            return None
        protocol = "udp" if mode == "wireguard" else ov.get("vpn_protocol", "udp")
        port = ov.get("vpn_port") or VPN_DEFAULT_PORT[mode]
        return (mode, port, protocol)

    def primary_segment(self, node):
        segments = self.ctx.segments_of(node["id"])
        if not segments:
            raise GenerationError(
                "%s is not attached to a segment" % self.ctx.name(node["id"]))
        if len(segments) == 1:
            return segments[0]
        for edge in self.ctx.by_role.get("attached", []):
            if edge["source"] == node["id"] and edge.get("primary", True):
                return edge["target"]
        return segments[0]

    # -- egress

    def segment_needs_nat(self, segment_id):
        """Whether this segment needs a NAT route of its own.

        Not derivable inside the segment module, which is why it is computed
        here and passed in. Under 0021 a segment can permit public addresses and
        still hold hosts that took none, and a gateway route is no use to a host
        with no address. So the question is about the members, and only the
        compiler can see them.

        An internet segment never asks for one. One route table cannot point at
        both the internet gateway and a NAT, and the gateway is what the
        addressed members need. The members that took no address are internal
        only there, reaching out through the jumpbox rather than a NAT, which is
        the redStack shape: one public subnet, the jumpbox addressed, everyone
        else internal. GCP renders the same topology with Cloud NAT, so its
        internal members do get their own egress; that provider difference is
        surfaced by CAP003 as a note, not refused. See 0021 and 0039.
        """
        segment = self.ctx.nodes[segment_id]
        if segment["overlay"].get("egress") != "allowed":
            return False
        if segment["overlay"].get("exposure") == "internet":
            return False
        members = [h for h in self.hosts()
                   if segment_id in self.ctx.segments_of(h["id"])]
        if not members:
            # An empty local segment with egress allowed gets a path out,
            # because the next host dropped into it will need one.
            return True
        return any(not self.is_public(h) for h in members)

    def needs_nat(self, network_id):
        return any(self.segment_needs_nat(s["id"])
                   for s in self.segments_in(network_id))

    def spare_subnet(self, network_id, prefix=28):
        """A range inside the network that no segment occupies.

        GCP's Cloud NAT attaches to the network and needs no subnet of its own.
        AWS puts a NAT gateway in a subnet, so the export needs one the topology
        never asked for. Carving it from the high end and checking every segment
        beats overlapping one, which fails at apply with an error about CIDRs
        rather than about the topology.
        """
        node = self.ctx.nodes[network_id]
        network = ipaddress.ip_network(node["overlay"]["cidr"])
        taken = [ipaddress.ip_network(s["overlay"]["cidr"])
                 for s in self.segments_in(network_id)
                 if s["overlay"].get("cidr")]

        step = 2 ** (network.max_prefixlen - prefix)
        addr = int(network.broadcast_address) + 1 - step
        while addr >= int(network.network_address):
            candidate = ipaddress.ip_network((addr, prefix))
            if not any(candidate.overlaps(t) for t in taken):
                return str(candidate)
            addr -= step

        raise GenerationError(
            "%s has no free /%d for the outbound gateway: its segments fill "
            "%s. Widen the network range or narrow a segment."
            % (self.ctx.name(network_id), prefix, node["overlay"]["cidr"]))


# ---------------------------------------------------------------- rendering

def time_provider(plan):
    """The `time` entry for required_providers, or "" when nothing needs it.

    Only a topology whose stop clock is counted from the apply pulls hashicorp/time
    in, so a topology with auto_stop off, or one that names a fixed wall-clock `at`,
    installs exactly what it did before. Written here because all three clouds
    declare it identically and the alternative is the same four lines in three
    files, which is how they drift.
    """
    if not plan.needs_time_provider():
        return ""
    return """
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }"""


def operator_source_ranges_check():
    """A Terraform check block that warns when management ingress is left wide open.

    operator_source_ranges is a tfvars value, not a topology field, so the topology
    validator never sees it: left at the default 0.0.0.0/0 it opens the jumpbox ssh
    (22) and the Guacamole portal (443) to the whole internet. A failed check
    assertion warns, it does not fail the apply, so this is a non-blocking nudge at
    deploy time. required_version >= 1.5 on both backends, so check blocks exist.
    Emitted once per generated main.tf; the name is fixed, so callers add it once.
    """
    return [
        "",
        '# Non-blocking: warns (does not fail) when management ingress is wide open.',
        'check "operator_source_ranges_is_narrowed" {',
        "  assert {",
        '    condition     = !contains(var.operator_source_ranges, "0.0.0.0/0")',
        '    error_message = "operator_source_ranges is 0.0.0.0/0, so ssh and the Guacamole portal are open to the whole internet. Narrow it in terraform.tfvars to the addresses operators connect from."',
        "  }",
        "}",
    ]


def align(pairs, indent="  "):
    """Argument lines with the equals signs lined up.

    This is what `terraform fmt` does, and the export panel is the product, so
    the generated file should already look like the file a person would keep.
    It also means `terraform fmt -check` passes, which makes it usable as a
    test rather than a thing everyone reformats by hand.

    Alignment is per contiguous run, matching fmt: a blank line starts a new
    group, so callers pass one group at a time. A multi-line value (one whose
    HCL spans several lines, e.g. a join([...]) block) also breaks the run the
    way fmt does: it is emitted with a single space and starts a fresh alignment
    group after it, so a block that mixes scalar args with a multi-line one
    still passes `terraform fmt -check`.
    """
    pairs = list(pairs)
    lines, group = [], []

    def flush():
        if not group:
            return
        width = max(len(key) for key, _ in group)
        lines.extend("%s%-*s = %s" % (indent, width, key, value)
                     for key, value in group)
        group.clear()

    for key, value in pairs:
        if "\n" in str(value):
            flush()
            lines.append("%s%s = %s" % (indent, key, value))
        else:
            group.append((key, value))
    flush()
    return lines


def operator_hosts_hcl(plan):
    """An HCL expression: the offense stack as an /etc/hosts block, each host by
    its canvas node name and, where it can be told unambiguously, the
    conventional alias the operator's MobaXterm sessions and browser bookmarks
    use (mythic/sliver/adaptix/redirector/kali/guac). The canvas name comes
    first -- it is the alias of record, the id the user sets and can rename on
    the canvas -- with the conventional alias appended so the stock sessions
    resolve out of the box. First host of a kind claims the conventional alias;
    a second redirector or teamserver keeps only its canvas name. Built from
    module private addresses, so it resolves at apply. This is the offense-side
    counterpart to the redstackpro.hosts Ansible role (which names the Linux
    hosts); the Windows operator has no WinRM, so its block rides the boot
    script. Provider-agnostic: every host module outputs private_address. See
    operator_setup.ps1 and the /etc/hosts PAI item.

    The Windows operators are omitted: this list is consumed only by a Windows
    operator (its operator_hosts input), and a host that referenced its own
    module output as an input would be a Terraform dependency cycle. A host needs
    no /etc/hosts entry for itself anyway."""
    used = set()
    entries = []
    for node in plan.hosts():
        ov = node.get("overlay", {}) or {}
        kind = node["kind"]
        if kind == "operator" and ov.get("os", "").startswith("windows"):
            continue
        conventional = None
        if kind == "teamserver":
            conventional = ov.get("c2")
        elif kind == "redirector":
            conventional = "redirector"
        elif kind == "jumpbox":
            conventional = "guac"
        elif kind == "collector":
            conventional = "collector"
        elif kind == "operator" and ov.get("os") == "kali":
            conventional = "kali"
        aliases = [node["id"]]
        if conventional and conventional not in used and conventional != node["id"]:
            aliases.append(conventional)
            used.add(conventional)
        entries.append('    "${module.%s.private_address}  %s"'
                       % (plan.ref(node["id"]), " ".join(aliases)))
    if not entries:
        return '""'
    return "join(\"\\n\", [\n%s,\n  ])" % ",\n".join(entries)


# ---------------------------------------------------------------- outputs
# Shared, because tools/tf_inventory.py reads one shape whatever produced it.

def outputs(plan):
    ctx = plan.ctx
    lines = [
        "# Generated by redStackPRO. Do not edit.",
        "",
        "# Consumed by tools/tf_inventory.py, which fills the Ansible",
        "# placeholders after apply.",
        'output "redstackpro_addresses" {',
        "  value = {",
    ]
    for node in plan.hosts():
        ref = plan.ref(node["id"])
        lines += [
            '    "%s" = {' % plan.tag(node["id"]),
            "      private_address = module.%s.private_address" % ref,
            "      public_address  = module.%s.public_address" % ref,
            "    }",
        ]
    lines += ["  }", "}"]

    # Deploy-time answers the topology cannot carry, because the operator supplies
    # them at apply rather than on the canvas. tf_inventory fills these into the
    # Ansible tree under the reserved "@settings" pseudo-node. This is a separate
    # output rather than another row in redstackpro_addresses so that a host can
    # never collide with it, whatever the canvas names things. Joined to a string
    # because every value tf_inventory substitutes is substituted into text.
    lines += [
        "",
        "# Consumed by tools/tf_inventory.py, alongside redstackpro_addresses.",
        'output "redstackpro_settings" {',
        "  value = {",
        '    operator_source_ranges = join(",", var.operator_source_ranges)',
        "  }",
        "}",
    ]

    # Rollover pools. The topology knows which redirectors serve which teamserver;
    # the operator writes the C2 profile. See 0007.
    pools = {}
    for edge in ctx.by_role.get("fronts", []):
        pools.setdefault(edge["target"], []).append(edge["source"])
    if pools:
        lines += [
            "",
            "# Redirectors fronting each teamserver. Paste into your C2 profile;",
            "# redStackPRO does not generate profiles or rotation policy.",
            'output "redirector_pools" {',
            "  value = {",
        ]
        for teamserver, redirectors in sorted(pools.items()):
            entries = ", ".join(
                "module.%s.public_address" % plan.ref(r)
                for r in sorted(redirectors))
            lines.append('    "%s" = [%s]' % (ctx.name(teamserver), entries))
        lines += ["  }", "}"]

    return "\n".join(lines) + "\n"
