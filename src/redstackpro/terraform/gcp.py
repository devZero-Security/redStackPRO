"""The GCP backend.

Source restriction is by network tag. A tag is a string, so a rule references a
host without depending on the host resource, which is why this backend needs no
per host firewall object. The AWS backend does. See 0015.
"""

from .plan import (  # noqa: F401  GenerationError re-exported
    GenerationError, align, operator_hosts_hcl, time_provider)

# Kali has no GCP public image, and converting a booted Debian at provision
# time is unreliable: apt refuses the kali-linux-headless dependency tree on a
# converted base ("... not going to be installed"), which cannot be forced from
# automation. Instead a Kali operator boots a `red-kali` custom image -- Kali's
# own official cloud disk imported into the project once (see the import steps in
# the deploy docs) -- so it is genuine Kali and the metapackage installs cleanly.
# The name is unqualified so terraform resolves it in the deploy's own project;
# the image must be imported there first. The operator role's os-kali.yml skips
# the conversion on a real Kali image and just layers the tooling on top. AWS
# keeps its real Kali AMI.
# Debian 13 (trixie), not 12, and the reason is a Python floor rather than
# taste. Debian 12 ships Python 3.11, and certipy-ad 5.x declares
# Requires-Python >=3.12, so pip silently skipped every 5.x release and installed
# the newest 4.x instead. That build then died on every invocation, because
# certipy 4.8.2 imports pkg_resources and setuptools removed it in v81.
#
# The result was a jumpbox where `certipy` was on PATH, the install task reported
# success, and the tool had never once run. It also capped the toolkit at ESC11,
# so ESC13 through ESC16 had no tooling at all no matter what the range planted.
# Found on a live range 2026-09-18, after the version claim had been written down
# from PyPI metadata rather than from what the host would actually resolve.
DEFAULT_IMAGES = {
    "debian": "debian-cloud/debian-13",
    "kali": "red-kali",
    "windows": "windows-cloud/windows-2022",
}

# The AD range names a specific Windows build or Linux distribution per host.
# GCP publishes each as an image family, so a host tracks the latest patched
# image for its build. An unrecognized or unset Windows build falls back to
# 2022, the same default the attack side's bare "windows" resolves to.
#
# Windows Server 2016 is pinned to the 2019 family on purpose: it reaches
# Microsoft end-of-support on 2027-01-12, after which the 2016 family is
# retired. A range that still names 2016 keeps deploying, on the closest build.
# GCP publishes no Windows client image, so a workstation build maps to Server
# 2022; the box still joins and behaves as a member, it is just not a client OS.
WINDOWS_IMAGES = {
    "windows_server_2016": "windows-cloud/windows-2019",
    "windows_server_2019": "windows-cloud/windows-2019",
    "windows_server_2022": "windows-cloud/windows-2022",
    "windows_10": "windows-cloud/windows-2022",
    "windows_11": "windows-cloud/windows-2022",
}

# A topology that NAMES a distribution still gets that distribution. debian_12 is
# kept deliberately: a lab pinned to it wants the older Python and the older
# tooling, and silently upgrading it would change what that lab teaches.
LINUX_IMAGES = {
    "debian_13": "debian-cloud/debian-13",
    "debian_12": "debian-cloud/debian-12",
    "ubuntu_2204": "ubuntu-os-cloud/ubuntu-2204-lts",
    "ubuntu_2004": "ubuntu-os-cloud/ubuntu-2004-lts",
}

# Machine sizing per kind. Overridable in tfvars; these are the defaults a
# person would pick, not values the topology carries. A DC promotion and a member
# join are memory hungry; a workstation is lighter; a SIEM ingests and indexes.
DEFAULT_MACHINE = {
    "collector": "e2-standard-2",
    "operator": "e2-standard-2",
    # A teamserver compiles a C2 from source (AdaptixC2's Go build is CPU-bound
    # with no prebuilt release) and runs Mythic's ~8 containers, so the default
    # e2-medium (2 vCPU / 4 GB) is the bottleneck: slow builds and container
    # memory pressure. 4 vCPU / 16 GB roughly halves the build and gives Mythic
    # room.
    "teamserver": "e2-standard-4",
    "dc": "e2-standard-4",
    "srv": "e2-standard-4",
    "wks": "e2-standard-2",
    "siem": "e2-standard-4",
}


def image_for(plan, node):
    kind, overlay = node["kind"], node.get("overlay", {})
    if kind == "operator":
        return DEFAULT_IMAGES[overlay.get("os", "debian")]
    # A DC, member server, or workstation is Windows unless its os says otherwise
    # (a Linux member such as GOAD's lx01/syrax, or a SIEM). is_windows encodes
    # that default: the AD host kinds are Windows when no os is set.
    if plan.is_windows(node):
        return WINDOWS_IMAGES.get(overlay.get("os"), DEFAULT_IMAGES["windows"])
    return LINUX_IMAGES.get(overlay.get("os"), DEFAULT_IMAGES["debian"])


def files(plan):
    return {
        "terraform/versions.tf": _versions(plan),
        "terraform/variables.tf": _variables(plan.region),
        "terraform/terraform.tfvars": _tfvars(plan),
        "terraform/main.tf": _main(plan),
        "terraform/firewall.tf": _firewall(plan),
    }


# ---------------------------------------------------------------- static parts

def _versions(plan):
    return """# Generated by redStackPRO. Do not edit.
# redStackPRO does not run Terraform and does not bundle the binary. See 0001, 0002.

terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }%s
  }
}""" % time_provider(plan) + """

provider "google" {
  project = var.project
  region  = var.region
}
"""


def _variables(region="us-east4"):
    return ("""# Generated by redStackPRO. Do not edit.
# Values live in terraform.tfvars. Credentials and key material never do.

variable "project" {
  description = "GCP project id."
  type        = string
}

variable "region" {
  type    = string
  default = "%s"
}""" % region) + """

variable "zone" {
  type    = string
  default = "us-east4-a"
}

variable "ssh_public_key" {
  description = "Authorized key for the admin account, supplied at run time."
  type        = string
}

variable "operator_source_ranges" {
  description = "Where management access is accepted from. Narrow this."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "lab_password" {
  description = "One shared lab password for the admin account, the Windows operator, and the Guacamole login. Left empty, a strong one is generated at apply and printed in the outputs. Never in the export."
  type        = string
  default     = ""
  sensitive   = true
}
"""


def _tfvars(plan):
    return """# Generated by redStackPRO. Fill these in before running terraform.
# Never commit this file with real values. See the project conventions.

project        = ""
region         = "us-east4"
zone           = "us-east4-a"
ssh_public_key = ""

# Narrow this to the addresses operators connect from.
operator_source_ranges = ["0.0.0.0/0"]
"""


# ---------------------------------------------------------------- root module

def _needs_nat(plan, segment_id):
    """GCP's rule for whether a subnet needs Cloud NAT of its own.

    Cloud NAT serves only the instances without an external IP and coexists with
    the ones that have one, so an internet-exposed subnet still gives its private
    members (a collector, an operator) their own egress. That is unlike AWS,
    where one route table cannot point at both the internet gateway and a NAT, so
    plan.segment_needs_nat excludes internet segments outright and expects their
    internal members to egress through the jumpbox. On GCP there is no such
    exclusion, so this drops it: a segment needs Cloud NAT when egress is allowed
    and it holds any member that took no public address. Without this the offense
    management subnet (internet-exposed, jumpbox addressed, collector/operators
    internal) left the collector with no route out and its apt install hung. See
    0021, 0039, and segment_needs_nat in plan.py.
    """
    seg = plan.ctx.nodes[segment_id]
    if seg["overlay"].get("egress") != "allowed":
        return False
    members = [h for h in plan.hosts()
               if segment_id in plan.ctx.segments_of(h["id"])]
    if not members:
        return True
    return any(not plan.is_public(h) for h in members)


def _main(plan):
    lines = [
        "# Generated by redStackPRO. Do not edit.",
        "# One module block per node. Inter module references resolve at apply",
        "# time on your machine, because redStackPRO never runs Terraform. See 0001.",
    ]

    is_range = plan.is_range()
    # Guacamole runs on the jumpbox in every mode (a defense range and an offense
    # platform alike), so its portal credentials and connection key are
    # provisioned whenever a jumpbox is present, not only for ranges. The shared
    # lab password and the key pair are generated at apply and never written into
    # the export. See 0001, guacamole-on-the-jumpbox, goad-native-recreation.
    has_jumpbox = any(n["kind"] == "jumpbox" for n in plan.hosts())
    if has_jumpbox:
        lines += [
            "",
            "# One shared lab password, generated at apply unless the operator set one.",
            'resource "random_password" "lab" {',
            "  length           = 20",
            "  special          = true",
            '  override_special = "!@#-_=+"',
            "}",
            "",
            "# The jumpbox reaches every box for the Guacamole tiles with this key.",
            "# The public half is authorized on each box at boot; the private half",
            "# goes to the jumpbox, so the portal connects with no password on the wire.",
            'resource "tls_private_key" "guacamole" {',
            '  algorithm = "ED25519"',
            "}",
            "",
            "locals {",
            "  # The operator's password if they set one, otherwise the generated one.",
            "  lab_password = var.lab_password != \"\" ? var.lab_password : random_password.lab.result",
            "}",
        ]

    for node in plan.networks():
        lines += ["", 'module "%s" {' % plan.ref(node["id"])] + align([
            ("source", '"./modules/gcp/network"'),
            ("name", '"%s"' % plan.tag(node["id"])),
            ("project", "var.project"),
        ]) + ["}"]

    for node in plan.segments():
        network = plan.ctx.network_of_segment(node["id"])
        overlay = node["overlay"]
        lines += ["", 'module "%s" {' % plan.ref(node["id"])] + align([
            ("source", '"./modules/gcp/segment"'),
            ("name", '"%s"' % plan.tag(node["id"])),
            ("project", "var.project"),
            ("region", "var.region"),
            ("network", "module.%s.self_link" % plan.ref(network)),
            ("cidr", '"%s"' % overlay["cidr"]),
            ("egress", '"%s"' % overlay["egress"]),
            ("exposure", '"%s"' % overlay["exposure"]),
            # Exposure is a ceiling, so it cannot answer whether any member
            # lacks an address. Only the compiler sees the members. GCP's Cloud
            # NAT coexists with external IPs, so this uses the GCP rule rather
            # than plan.segment_needs_nat's AWS one. See _needs_nat and 0021.
            ("nat", "true" if _needs_nat(plan, node["id"]) else "false"),
        ]) + ["}"]

    # The range turns itself off, so an operator who forgets does not pay for a
    # weekend. GCP expresses this natively as a resource policy every instance
    # references, which means no credential anywhere and nothing to keep running
    # -- the scheduler is the cloud's, not ours. STOP, never delete: the forest
    # took forty minutes to provision and comes back on boot. See 0057.
    stop = plan.auto_stop
    if stop:
        lines += plan.auto_stop_block()
        lines += [
            "",
            "# Auto stop. Attached to every instance below.",
            'resource "google_compute_resource_policy" "auto_stop" {',
            '  name    = "%s-auto-stop"' % plan.topology.get("prefix", "red"),
            "  project = var.project",
            "  region  = var.region",
            "",
            "  instance_schedule_policy {",
            '    time_zone = "%s"' % stop["timezone"],
            "    vm_stop_schedule {",
            '      schedule = "%s %s * * *"'
            % (stop["minute_tpl"], stop["hour_tpl"]),
            "    }",
            "  }",
            "}",
        ]

    for node in plan.hosts():
        segment = plan.primary_segment(node)
        pairs = [
            ("source", '"./modules/gcp/host"'),
            ("name", '"%s"' % plan.tag(node["id"])),
            ("node_id", '"%s"' % plan.tag(node["id"])),
            ("kind", '"%s"' % node["kind"]),
            ("project", "var.project"),
            ("zone", "var.zone"),
            ("subnetwork", "module.%s.self_link" % plan.ref(segment)),
            ("image", '"%s"' % image_for(plan, node)),
            # A range's jumpbox is reached from outside (Guacamole and ssh), so it
            # needs a public address even when exposure would not grant one; every
            # other range host stays private and egresses through Cloud NAT.
            ("public_address",
             "true" if (plan.is_public(node)
                        or (is_range and node["kind"] == "jumpbox"))
             else "false"),
            # Reserve a static external IP for the hosts whose address must not
            # change across a stop/start: the redirector (its C2 callback domain
            # must keep resolving) and the jumpbox (the Guacamole/SSH entry point).
            # Released on teardown, so a fresh deploy still rotates the IP. See the
            # ephemeral-IP finding.
            ("reserve_ip",
             "true" if node["kind"] in ("redirector", "jumpbox") else "false"),
            # The single platform account (redop for ops, blueop for a range);
            # the module creates it and authorizes the keys for it. See P1.7.
            ("admin_username", '"%s"' % plan.admin_account),
            ("ssh_public_key", "var.ssh_public_key"),
        ]
        machine = DEFAULT_MACHINE.get(node["kind"])
        if machine:
            pairs.append(("machine_type", '"%s"' % machine))
        # A range locking this host to a specific address (GOAD's canonical
        # octets, see 0055); omitted lets GCP assign one from the subnet's
        # DHCP range, the unchanged default.
        internal_ip = (node.get("overlay") or {}).get("internal_ip")
        if internal_ip:
            pairs.append(("network_ip", '"%s"' % internal_ip))
        if has_jumpbox:
            # Every box authorizes the Guacamole key for the admin account and (Linux) or
            # sets the operator account (Windows) so the portal tiles connect with
            # no password on the wire; the jumpbox alone gets the private half of
            # the key and writes the portal credential files. See
            # guacamole-on-the-jumpbox and goad-native-recreation.
            pairs += [
                ("windows", "true" if plan.is_windows(node) else "false"),
                # WinRM is the range's Windows provisioning path (the boot script
                # stands up an HTTPS listener for Ansible). An offense Windows
                # operator self-provisions RDP at boot and is never managed over
                # WinRM, so the listener is range-only.
                ("enable_winrm",
                 "true" if (is_range and plan.is_windows(node)) else "false"),
                ("lab_password", "local.lab_password"),
                # The Windows local account and the Guacamole login are the same
                # single platform identity as the Linux admin (redop for ops,
                # blueop for a range), not a separate "operator". The module input
                # keeps its name; the value it now carries is the platform account.
                # See P1.7 and naming.platform_account.
                ("operator_username", '"%s"' % plan.admin_account),
                ("guac_public_key", "tls_private_key.guacamole.public_key_openssh"),
                ("guac_private_key",
                 "tls_private_key.guacamole.private_key_openssh"
                 if node["kind"] == "jumpbox" else '""'),
            ]
        # The offense Windows operator self-provisions its kit at boot (it has no
        # WinRM and Ansible never reaches it), so it takes the operator setup
        # script verbatim as a metadata key plus a hosts block for its MobaXterm
        # sessions. Ops-mode only: a range's Windows hosts are driven by Ansible.
        if (not is_range and node["kind"] == "operator"
                and plan.is_windows(node)):
            pairs += [
                ("operator_setup", "true"),
                ("operator_setup_script",
                 'file("${path.module}/scripts/operator_setup.ps1")'),
                ("operator_hosts", operator_hosts_hcl(plan)),
                # The same key the jumpbox uses: its public half is already an
                # authorized key for the platform account on every host, so the
                # operator box can key-auth into the stack and MobaXterm stops
                # prompting for the password. Password auth stays as fallback.
                ("operator_ssh_key",
                 "tls_private_key.guacamole.private_key_openssh"),
            ]
        # GCP's Windows images are 50 GB, so a Windows boot disk must be at least
        # that large (the module default of 30 is fine for Linux but GCP rejects
        # it for Windows). This applies in ops mode too (the offense Windows
        # operator), not just ranges, so it lives outside the is_range block.
        # Exchange needs far more for the ISO and install.
        services = node.get("overlay", {}).get("services") or []
        if "exchange" in services:
            pairs.append(("disk_size_gb", "120"))
        elif plan.is_windows(node):
            pairs.append(("disk_size_gb", "64"))
        if stop:
            pairs.append(
                ("resource_policies",
                 "[google_compute_resource_policy.auto_stop.self_link]"))
        lines += ["", 'module "%s" {' % plan.ref(node["id"])] + align(pairs) + ["}"]

    # peers: a network peering, both directions. The module names each side; the
    # routes exchange on their own. See 0030.
    for edge in plan.ctx.by_role.get("peers", []):
        a, b = edge["source"], edge["target"]
        lines += ["", 'module "%s" {' % plan.ref(edge["id"])] + align([
            ("source", '"./modules/gcp/peering"'),
            ("name", '"%s"' % plan.tag(edge["id"])),
            ("network_a", "module.%s.self_link" % plan.ref(a)),
            ("network_b", "module.%s.self_link" % plan.ref(b)),
        ]) + ["}"]

    if has_jumpbox:
        # The portal address and the operator credentials, printed at apply. They
        # are generated here rather than in the export, so this is where they surface.
        jumps = [n for n in plan.hosts() if n["kind"] == "jumpbox"]
        if jumps:
            jref = plan.ref(jumps[0]["id"])
            lines += [
                "",
                'output "guacamole" {',
                '  description = "The single pane of glass. Open the url and log in."',
                "  sensitive   = true",
                "  value = {",
                '    url      = "https://${module.%s.public_address}/guacamole"' % jref,
                '    username = "%s"' % plan.admin_account,
                "    password = local.lab_password",
                "  }",
                "}",
            ]
        lines += [
            "",
            'output "lab_password" {',
            '  description = "Shared password for the admin account, the Windows operator, and the portal."',
            "  sensitive   = true",
            "  value       = local.lab_password",
            "}",
        ]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- firewall

def _rule(name, network_ref, direction, protocol, ports, target_tags,
          source_tags=None, source_ranges=None, source_expr=None, comment=None):
    """source_ranges is a list of literal CIDRs. source_expr is raw HCL already
    of list type, so it is emitted unwrapped."""
    lines = []
    if comment:
        lines.append("# %s" % comment)
    lines.append('resource "google_compute_firewall" "%s" {' % name)
    lines += align([
        ("name", '"%s"' % name.replace("_", "-")),
        ("project", "var.project"),
        ("network", "module.%s.self_link" % network_ref),
        ("direction", '"%s"' % direction),
    ])

    allow = [("protocol", '"%s"' % protocol)]
    if ports:
        allow.append(("ports", "[%s]" % ", ".join('"%s"' % p for p in ports)))
    lines += ["", "  allow {"] + align(allow, indent="    ") + ["  }", ""]

    tail = []
    if source_expr:
        tail.append(("source_ranges", source_expr))
    if source_ranges:
        tail.append(("source_ranges",
                     "[%s]" % ", ".join('"%s"' % r for r in source_ranges)))
    if source_tags:
        tail.append(("source_tags",
                     "[%s]" % ", ".join('"%s"' % t for t in source_tags)))
    tail.append(("target_tags",
                 "[%s]" % ", ".join('"%s"' % t for t in target_tags)))
    lines += align(tail)
    lines.append("}")
    return lines


def _firewall(plan):
    """Rules come from edges. A node cannot know them; only a drawn line can."""
    ctx = plan.ctx
    lines = [
        "# Generated by redStackPRO. Do not edit.",
        "# Every rule below exists because of an edge in the topology. Source",
        "# restriction is derived from those edges rather than from segment",
        "# ranges, so a rule names exactly the hosts that need it.",
    ]
    seen = set()

    # OPS MODE ONLY: the stack's own hosts reach each other freely.
    #
    # An offense platform is the operator's own infrastructure, not a target.
    # Segmenting it buys nothing to defend against and costs real friction: the
    # Windows operator box could not SSH the teamservers its own saved sessions
    # point at, and the jumpbox could not reach its redirector. The original
    # redStack gives every host an all-from-VPC rule for exactly this reason.
    #
    # A RANGE keeps strictly edge-derived rules. There the segmentation IS the
    # exercise -- what a lateral movement step proves depends on it -- so this
    # deliberately does not apply. External ingress is untouched in both modes,
    # which is the property that actually matters. See 0057-era notes and
    # range-access-model.
    if not plan.is_range():
        stack_cidrs = [ctx.overlay(n["id"], "cidr") for n in plan.networks()]
        stack_cidrs = [c for c in stack_cidrs if c]
        for net in plan.networks():
            lines += [
                "",
                "# The operator's own stack, internally open. Every network in",
                "# the plan, so a peered redirector is reachable too.",
                'resource "google_compute_firewall" "intra_%s" {'
                % plan.ref(net["id"]),
            ] + align([
                ("name", '"%s-intra"' % plan.tag(net["id"]).replace("_", "-")),
                ("project", "var.project"),
                ("network", "module.%s.self_link" % plan.ref(net["id"])),
                ("direction", '"INGRESS"'),
            ]) + [
                "",
                "  allow {",
                '    protocol = "all"',
                "  }",
                "",
            ] + align([
                ("source_ranges",
                 "[%s]" % ", ".join('"%s"' % c for c in stack_cidrs)),
            ]) + ["}"]
            # No target_tags: every instance in the operator's own network.

    def network_of(node_id):
        nets = ctx.networks_of(node_id)
        return nets[0] if nets else None

    def source_cidr(node_id):
        # The host's own subnet, for a rule that reaches it across a peering
        # where a network tag would not carry. See 0030.
        return ctx.overlay(plan.primary_segment(ctx.nodes[node_id]), "cidr")

    # fronts: public ingress to the redirector, then redirector to teamserver.
    for edge in ctx.by_role.get("fronts", []):
        rdir, ts = edge["source"], edge["target"]
        net = network_of(rdir)
        protocol = "tcp" if edge["protocol"] != "dns" else "udp"
        listen = edge["listen_port"]
        upstream = edge.get("upstream_port", listen)

        name = "in_%s_%s" % (plan.ref(rdir), listen)
        if name not in seen and net:
            seen.add(name)
            lines += [""] + _rule(
                name, plan.ref(net), "INGRESS", protocol, [listen], [plan.tag(rdir)],
                source_ranges=["0.0.0.0/0"],
                comment="%s accepts operational traffic" % ctx.name(rdir))

        name = "fwd_%s_%s" % (plan.ref(rdir), plan.ref(ts))
        tsnet = network_of(ts)
        if name not in seen and tsnet:
            seen.add(name)
            # A redirector in the teamserver's network names itself by tag; one
            # across a peering names its subnet CIDR, since a tag does not carry
            # across the boundary. See 0030.
            if net == tsnet:
                source = {"source_tags": [plan.tag(rdir)]}
                across = ""
            else:
                rcidr = source_cidr(rdir)
                source = {"source_ranges": [rcidr] if rcidr else None}
                across = " across a peering"
            lines += [""] + _rule(
                name, plan.ref(tsnet), "INGRESS", protocol, [upstream],
                [plan.tag(ts)],
                comment="%s forwards to %s%s" % (ctx.name(rdir), ctx.name(ts), across),
                **source)

    # An operator box drives a teamserver from inside the range over the C2's
    # control-plane port (Mythic's web UI, Sliver's multiplayer listener,
    # Adaptix's operator endpoint). The beacon channel itself rides the fronts
    # edge through the redirector above; this is the separate operator ->
    # teamserver management path that nothing else opens. Same network names the
    # operator by tag; across a peering, by its subnet CIDR. Emitted only for a
    # teamserver whose C2 has a known control port and only when an operator
    # exists to reach it. See P7.
    operators = sorted(plan.operators(), key=lambda h: h["id"])
    for ts in sorted(plan.hosts(), key=lambda h: h["id"]):
        ports = plan.control_ports(ts)
        tsnet = network_of(ts["id"])
        if not ports or not tsnet:
            continue
        same = [o for o in operators if network_of(o["id"]) == tsnet]
        cross = [o for o in operators if network_of(o["id"]) != tsnet]
        if same:
            name = "ctl_%s" % plan.ref(ts["id"])
            if name not in seen:
                seen.add(name)
                lines += [""] + _rule(
                    name, plan.ref(tsnet), "INGRESS", "tcp",
                    [str(p) for p in ports], [plan.tag(ts["id"])],
                    source_tags=sorted(plan.tag(o["id"]) for o in same),
                    comment="operators drive %s on its C2 control port(s)"
                            % ctx.name(ts["id"]))
        if cross:
            cidrs = sorted({source_cidr(o["id"]) for o in cross} - {None})
            name = "ctl_%s_peered" % plan.ref(ts["id"])
            if name not in seen and cidrs:
                seen.add(name)
                lines += [""] + _rule(
                    name, plan.ref(tsnet), "INGRESS", "tcp",
                    [str(p) for p in ports], [plan.tag(ts["id"])],
                    source_ranges=cidrs,
                    comment="operators drive %s across a peering on its C2 "
                            "control port(s)" % ctx.name(ts["id"]))

    # A redirector keeps port 80 open to the internet so Certbot's ACME http-01
    # challenge can reach it: Let's Encrypt validates over HTTP on 80 regardless
    # of the port the redirector fronts on, and without this an otherwise correct
    # letsencrypt redirector fails validation (the fronting rule opens only its
    # listen port). Emitted once per redirector, whatever its cert source, so
    # renewals keep working. See the redirector role.
    for node in plan.hosts():
        if ctx.kind(node["id"]) != "redirector":
            continue
        net = network_of(node["id"])
        name = "acme_in_%s" % plan.ref(node["id"])
        if name in seen or not net:
            continue
        seen.add(name)
        lines += [""] + _rule(
            name, plan.ref(net), "INGRESS", "tcp", ["80"], [plan.tag(node["id"])],
            source_ranges=["0.0.0.0/0"],
            comment="%s answers the Certbot ACME http-01 challenge on 80"
            % ctx.name(node["id"]))

    # logs_to: senders reach the collector on its ingest port and nothing else.
    # A sender in the collector's own network is named by tag; one across a
    # peering is named by its subnet CIDR, since tags do not cross. See 0030.
    sinks = {}
    for edge in ctx.by_role.get("logs_to", []):
        sinks.setdefault(edge["target"], []).append(edge["source"])
    for collector, senders in sorted(sinks.items()):
        net = network_of(collector)
        if not net:
            continue
        port = ctx.overlay(collector, "ingest_port", 5044)
        same = [s for s in senders if network_of(s) == net]
        cross = [s for s in senders if network_of(s) != net]
        if same:
            lines += [""] + _rule(
                "log_%s" % plan.ref(collector), plan.ref(net), "INGRESS", "tcp",
                [port], [plan.tag(collector)],
                source_tags=sorted(plan.tag(x) for x in same),
                comment="log shipping into %s, push over TCP with TLS"
                        % ctx.name(collector))
        if cross:
            cidrs = sorted({source_cidr(s) for s in cross} - {None})
            lines += [""] + _rule(
                "log_%s_peered" % plan.ref(collector), plan.ref(net), "INGRESS",
                "tcp", [port], [plan.tag(collector)], source_ranges=cidrs,
                comment="log shipping into %s from senders across a peering"
                        % ctx.name(collector))

    # manages: operator access to the jumpbox, then jumpbox to everything it manages.
    for edge in ctx.by_role.get("manages", []):
        jump, scope = edge["source"], edge["target"]
        net = network_of(jump)
        if not net:
            continue

        name = "mgmt_in_%s" % plan.ref(jump)
        if name not in seen:
            seen.add(name)
            lines += [""] + _rule(
                name, plan.ref(net), "INGRESS", "tcp", [22], [plan.tag(jump)],
                source_expr="var.operator_source_ranges",
                comment="operator access to %s" % ctx.name(jump))

        # The Guacamole portal runs on the jumpbox over HTTPS in every mode (a
        # defense range and an offense topology alike), so the operator reaches it
        # on 443 from the same ranges that get ssh -- not only for ranges.
        name = "guac_in_%s" % plan.ref(jump)
        if name not in seen:
            seen.add(name)
            lines += [""] + _rule(
                name, plan.ref(net), "INGRESS", "tcp", [443], [plan.tag(jump)],
                source_expr="var.operator_source_ranges",
                comment="operator access to the Guacamole portal on %s"
                        % ctx.name(jump))

        # The jumpbox is the range's initial-access foothold: it sits on the
        # range segment and must receive traffic that range hosts initiate back
        # to it -- a coerced or relayed NTLM authentication landing on an
        # operator listener (ntlmrelayx/Responder), a pivoted callback. Without
        # this the jumpbox only accepts the operator's 22/443 and a coerced DC's
        # SMB call back to a relay listener is dropped (ERROR_BAD_NETPATH). This
        # is *internal* (range-segment) surface, which a lab expects; the
        # jumpbox's internet surface stays limited to the operator rules above.
        # Mirrors the all-from-segment rule the AD hosts get below. See part-04.
        name = "foothold_in_%s" % plan.ref(jump)
        scidr = source_cidr(jump)
        if name not in seen and scidr:
            seen.add(name)
            lines += [""] + _rule(
                name, plan.ref(net), "INGRESS", "all", None, [plan.tag(jump)],
                source_ranges=[scidr],
                comment="%s (range foothold) accepts traffic from its own "
                        "segment: coerced/relayed callbacks and pivot returns"
                        % ctx.name(jump))

        managed = sorted(
            (h for h in plan.hosts()
             if h["id"] != jump and ctx.manager_of(h["id"]) == jump),
            key=lambda h: h["id"])

        # A Windows host is reached over WinRM, so opening 22 to it opens
        # nothing. Grouped by port rather than emitted per host, because a tag
        # based rule takes a list of targets and one rule per host would be
        # noise. See 0019.
        same = [h for h in managed if network_of(h["id"]) == net]
        cross = [h for h in managed if network_of(h["id"]) != net]

        by_port = {}
        for host in same:
            by_port.setdefault(plan.management_port(host), []).append(host)
            # guacd runs on the jumpbox and its RDP tile reaches a Windows box on
            # 3389, so the portal needs that path in addition to the ansible port.
            if plan.is_windows(host):
                by_port.setdefault(3389, []).append(host)
        for port, targets in sorted(by_port.items()):
            name = "mgmt_out_%s_%s" % (plan.ref(jump), port)
            if name in seen:
                continue
            seen.add(name)
            lines += [""] + _rule(
                name, plan.ref(net), "INGRESS", "tcp", [port],
                [plan.tag(h["id"]) for h in targets],
                source_tags=[plan.tag(jump)],
                comment="%s reaches the hosts it manages on %d"
                        % (ctx.name(jump), port))

        # Managed hosts across a peering: the rule sits on their network and
        # names the jumpbox subnet by CIDR, because a tag does not carry across
        # the boundary. See 0030.
        xby = {}
        for host in cross:
            xby.setdefault((network_of(host["id"]), plan.management_port(host)),
                           []).append(host)
            # guacd's RDP tile also needs 3389 to a Windows box across the peering.
            if plan.is_windows(host):
                xby.setdefault((network_of(host["id"]), 3389), []).append(host)
        jcidr = source_cidr(jump)
        for (hnet, port), targets in sorted(
                xby.items(), key=lambda kv: (plan.ref(kv[0][0]), kv[0][1])):
            name = "mgmt_out_%s_%s_%s" % (plan.ref(jump), plan.ref(hnet), port)
            if name in seen:
                continue
            seen.add(name)
            lines += [""] + _rule(
                name, plan.ref(hnet), "INGRESS", "tcp", [port],
                [plan.tag(h["id"]) for h in targets],
                source_ranges=[jcidr] if jcidr else None,
                comment="%s reaches hosts it manages in %s across the peering on %d"
                        % (ctx.name(jump), ctx.name(hnet), port))

    # joins: an AD domain. A domain talks to its controller and controllers
    # replicate over a wide, partly dynamic set of ports (Kerberos, LDAP and the
    # global catalog, SMB, DNS, the RPC endpoint mapper and its high dynamic
    # range) too many and too fluid to enumerate as one rule each. The lab subnet
    # is local and isolated, so every AD host accepts all traffic from its own
    # segment: that is how a member reaches its DC to join and how DCs replicate.
    # These rules exist only because a joins edge drew a domain. SIEM boxes get
    # the same all-from-segment rule so agents can reach their ingest ports.
    for host in plan.intra_segment_hosts():
        name = "ad_intra_%s" % plan.ref(host["id"])
        if name in seen:
            continue
        seen.add(name)
        net = network_of(host["id"])
        cidr = source_cidr(host["id"])
        if not net or not cidr:
            continue
        lines += [""] + _rule(
            name, plan.ref(net), "INGRESS", "all", None, [plan.tag(host["id"])],
            source_ranges=[cidr],
            comment="%s accepts intra-domain traffic from its segment"
                    % ctx.name(host["id"]))

    return "\n".join(lines) + "\n"


