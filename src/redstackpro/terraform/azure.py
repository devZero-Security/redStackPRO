"""The Azure backend (hashicorp/azurerm).

Azure is a cloud like AWS and GCP: allocated public addresses, Marketplace images
per build (including Windows client images), and a native admin password on a
Windows VM. So the range maps closely to the other clouds. Segmentation is by
subnet with a Network Security Group; rules are matched by address, and each host
takes a static private address so a rule can name it (the same approach the
on-prem backend uses). A Windows range host sets the operator password natively
and runs a CustomScript extension that enables the built-in Administrator and an
HTTPS WinRM listener, the Azure form of the boot self-provision. See 0015.
"""

import base64
import ipaddress

from .plan import (  # noqa: F401  GenerationError re-exported
    GenerationError, align, operator_hosts_hcl,
    operator_source_ranges_check, time_provider)

# Marketplace image (publisher, offer, sku, version) per build.
WINDOWS_IMAGES = {
    # 2016 is pinned to 2019 ahead of Microsoft EOS on 2027-01-12; see aws.py.
    "windows_server_2016": ("MicrosoftWindowsServer", "WindowsServer", "2019-Datacenter", "latest"),
    "windows_server_2019": ("MicrosoftWindowsServer", "WindowsServer", "2019-Datacenter", "latest"),
    "windows_server_2022": ("MicrosoftWindowsServer", "WindowsServer", "2022-datacenter-azure-edition", "latest"),
    "windows_10": ("MicrosoftWindowsDesktop", "Windows-10", "win10-22h2-pro", "latest"),
    "windows_11": ("MicrosoftWindowsDesktop", "windows-11", "win11-23h2-pro", "latest"),
}
_DEFAULT_WINDOWS = WINDOWS_IMAGES["windows_server_2022"]

# Debian 13 by default; see the note in gcp.py for why the Python floor forced
# it. debian_12 stays reachable for a topology that names it explicitly.
LINUX_IMAGES = {
    "debian": ("Debian", "debian-13", "13-gen2", "latest"),
    "debian_13": ("Debian", "debian-13", "13-gen2", "latest"),
    "debian_12": ("Debian", "debian-12", "12-gen2", "latest"),
    "ubuntu_2204": ("Canonical", "0001-com-ubuntu-server-jammy", "22_04-lts-gen2", "latest"),
    "ubuntu_2004": ("Canonical", "0001-com-ubuntu-server-focal", "20_04-lts-gen2", "latest"),
    # Kali on Azure is a Marketplace image that needs a plan acceptance; a range
    # never uses it, so it maps to Debian here rather than carry that overhead.
    # Trixie rather than bookworm: Kali tracks Debian testing, so the newer base
    # is the closer stand-in, and it is the same interpreter the real toolchain
    # is resolved against everywhere else.
    "kali": ("Debian", "debian-13", "13-gen2", "latest"),
}

DEFAULT_MACHINE = {
    "collector": "Standard_D2s_v3",
    "operator": "Standard_D2s_v3",
    "dc": "Standard_D2s_v3",
    "srv": "Standard_D2s_v3",
    "wks": "Standard_B2s",
    "siem": "Standard_D4s_v3",
}

# IANA -> Windows timezone id for Azure's shutdown schedule, which (unlike gcp/aws)
# does not accept IANA names. The CLDR default per zone. Only the common zones an
# operator is likely to pick; an unmapped IANA zone is refused at compile rather
# than guessed, and UTC or an already-Windows id passes through untouched.
_WINDOWS_TZ = {
    "UTC": "UTC", "Etc/UTC": "UTC",
    "America/New_York": "Eastern Standard Time",
    "America/Toronto": "Eastern Standard Time",
    "America/Chicago": "Central Standard Time",
    "America/Denver": "Mountain Standard Time",
    "America/Phoenix": "US Mountain Standard Time",
    "America/Los_Angeles": "Pacific Standard Time",
    "America/Anchorage": "Alaskan Standard Time",
    "America/Halifax": "Atlantic Standard Time",
    "America/Sao_Paulo": "E. South America Standard Time",
    "Europe/London": "GMT Standard Time",
    "Europe/Dublin": "GMT Standard Time",
    "Europe/Lisbon": "GMT Standard Time",
    "Europe/Berlin": "W. Europe Standard Time",
    "Europe/Amsterdam": "W. Europe Standard Time",
    "Europe/Rome": "W. Europe Standard Time",
    "Europe/Stockholm": "W. Europe Standard Time",
    "Europe/Zurich": "W. Europe Standard Time",
    "Europe/Vienna": "W. Europe Standard Time",
    "Europe/Paris": "Romance Standard Time",
    "Europe/Madrid": "Romance Standard Time",
    "Europe/Brussels": "Romance Standard Time",
    "Europe/Warsaw": "Central European Standard Time",
    "Europe/Prague": "Central European Standard Time",
    "Europe/Budapest": "Central European Standard Time",
    "Europe/Athens": "GTB Standard Time",
    "Europe/Bucharest": "GTB Standard Time",
    "Europe/Helsinki": "FLE Standard Time",
    "Europe/Kyiv": "FLE Standard Time", "Europe/Kiev": "FLE Standard Time",
    "Europe/Moscow": "Russian Standard Time",
    "Asia/Jerusalem": "Israel Standard Time",
    "Asia/Dubai": "Arabian Standard Time",
    "Asia/Kolkata": "India Standard Time",
    "Asia/Singapore": "Singapore Standard Time",
    "Asia/Shanghai": "China Standard Time",
    "Asia/Hong_Kong": "China Standard Time",
    "Asia/Tokyo": "Tokyo Standard Time",
    "Asia/Seoul": "Korea Standard Time",
    "Australia/Sydney": "AUS Eastern Standard Time",
    "Australia/Melbourne": "AUS Eastern Standard Time",
    "Australia/Perth": "W. Australia Standard Time",
    "Pacific/Auckland": "New Zealand Standard Time",
}


def _windows_tz(tz):
    """IANA zone -> Windows timezone id for Azure's shutdown schedule. UTC and an
    already-Windows id (no "/") pass through; a mapped IANA zone is translated; an
    unmapped IANA zone is refused rather than guessed into the wrong zone."""
    if "/" not in tz:  # UTC or an already-Windows id
        return tz
    win = _WINDOWS_TZ.get(tz)
    if win:
        return win
    raise GenerationError(
        "azure auto_stop: no Windows timezone mapping for the IANA zone %r. Use "
        "UTC, one of the common zones redStackPRO maps, or a Windows id directly "
        '(for example "GMT Standard Time"); or use gcp or aws for this range.' % tz)


def image_for(plan, node):
    # One source of truth for OS classification: plan.is_windows, the same call the
    # firewall and gcp/aws use, rather than a second module-level rule that could
    # drift from it. Mirrors aws.image_for(plan, node).
    overlay = node.get("overlay", {})
    if plan.is_windows(node):
        return WINDOWS_IMAGES.get(overlay.get("os"), _DEFAULT_WINDOWS)
    return LINUX_IMAGES.get(overlay.get("os", "debian"), LINUX_IMAGES["debian"])


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
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
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

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}
"""


def _variables(region="eastus"):
    return ("""# Generated by redStackPRO. Do not edit.
# Values live in terraform.tfvars. Credentials and key material never do.

variable "subscription_id" {
  description = "Azure subscription id. Credentials come from the environment (az login or a service principal)."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "%s"
}""" % region) + """

variable "resource_group" {
  description = "Resource group to create and hold the range."
  type        = string
  default     = "redstackpro-range"
}

variable "ssh_public_key" {
  description = "Authorized key for the admin account, supplied at run time."
  type        = string
  validation {
    condition     = can(regex("^(ssh-|ecdsa-|sk-)", var.ssh_public_key))
    error_message = "ssh_public_key must be an SSH public key line (a key type, the base64 key, then a comment). deploy.sh fills it from your private key; or paste keys/<name>.pub into deploy.tfvars."
  }
}

variable "operator_source_ranges" {
  description = "Where management access is accepted from. Narrow this."
  type        = list(string)
  default     = []
}

variable "lab_password" {
  description = "One shared lab password for the operator account, the built-in Administrator, and the Guacamole login. Left empty, a strong one is generated at apply. Never in the export."
  type        = string
  default     = ""
  sensitive   = true
}
"""


def _tfvars(plan):
    return """# Generated by redStackPRO. Fill these in before running terraform.
# Never commit this file with real values. See the project conventions.

subscription_id = ""
location        = "%s"
resource_group  = "redstackpro-range"
ssh_public_key  = ""

# REQUIRED: the addresses operators connect from. deploy.sh aborts until you set
# this, so a range is never exposed by default. One /32 per operator, or a CIDR:
# operator_source_ranges = ["203.0.113.5/32", "198.51.100.7/32"]
""" % plan.region


# ---------------------------------------------------------------- addressing

def _host_ips(plan):
    """Each host takes a static private address from its segment, so an NSG rule
    can name it. A host that declares internal_ip on its overlay (e.g. a range
    locking to GOAD's canonical octets, see 0055) gets that exact address;
    every other host in the segment auto-assigns the next free one, skipping
    whatever the pinned hosts already claimed. Azure reserves the first three
    usable addresses in a subnet, so auto-assignment starts at .10."""
    host_ip = {}
    for seg in plan.segments():
        net = ipaddress.ip_network(seg["overlay"]["cidr"])
        here = sorted((h for h in plan.hosts()
                       if plan.primary_segment(h) == seg["id"]),
                      key=lambda n: n["id"])
        pinned = {h["id"]: h["overlay"]["internal_ip"] for h in here
                  if h.get("overlay", {}).get("internal_ip")}
        taken = set(pinned.values())
        auto = (str(net[i]) for i in range(10, net.num_addresses - 1)
                if str(net[i]) not in taken)
        for h in here:
            host_ip[h["id"]] = pinned.get(h["id"]) or next(auto)
    return host_ip


# ---------------------------------------------------------------- root module

def _needs_nat(plan, segment_id):
    """Whether a subnet needs a NAT gateway of its own. Azure's NAT gateway serves
    the instances without a public IP and coexists with the ones that have one
    (like GCP Cloud NAT, unlike an AWS route table), so an internet-exposed subnet
    still gives its private members (a collector, an operator) their own egress. A
    segment needs it when egress is allowed and it holds any member that took no
    public address. Mirrors gcp._needs_nat; without it a private collector in an
    exposed subnet has no route out and its package install hangs."""
    seg = plan.ctx.nodes[segment_id]
    if seg["overlay"].get("egress") != "allowed":
        return False
    members = [h for h in plan.hosts()
               if segment_id in plan.ctx.segments_of(h["id"])]
    if not members:
        return True
    return any(not plan.is_public(h) for h in members)


def _main(plan):
    is_range = plan.is_range()
    # The jumpbox runs Guacamole and keys into every box for the portal tiles in
    # both modes, so its password and key pair are provisioned whenever a jumpbox
    # exists, not only for ranges (mirrors gcp/aws). Without this an offense export
    # emitted no lab_password output and deploy.sh's `terraform output -raw
    # lab_password` failed.
    has_jumpbox = any(n["kind"] == "jumpbox" for n in plan.hosts())
    host_ip = _host_ips(plan)

    # Azure's shutdown schedule reads a WINDOWS timezone id, not the IANA name
    # gcp/aws want, so translate it (common zones mapped, unmapped ones refused).
    stop = plan.auto_stop
    az_timezone = _windows_tz(stop["timezone"]) if stop else None

    lines = [
        "# Generated by redStackPRO. Do not edit.",
        "# One module block per node. Inter module references resolve at apply",
        "# time on your machine, because redStackPRO never runs Terraform. See 0001.",
        "",
        'resource "azurerm_resource_group" "this" {',
        "  name     = var.resource_group",
        "  location = var.location",
        "}",
    ]
    # Fail closed on wide-open management ingress, same precondition as gcp/aws.
    lines += operator_source_ranges_check()

    # Once at the root, above the module blocks that read the locals it defines.
    lines += plan.auto_stop_block()

    if has_jumpbox:
        lines += [
            "",
            "# One shared lab password, generated at apply unless the operator set one.",
            'resource "random_password" "lab" {',
            "  length           = 20",
            "  special          = true",
            '  override_special = "!@#-_=+"',
            '  min_special      = 1',
            "}",
            "",
            "# The jumpbox reaches every box for the Guacamole tiles with this key.",
            'resource "tls_private_key" "guacamole" {',
            '  algorithm = "ED25519"',
            "}",
            "",
            "locals {",
            "  lab_password = var.lab_password != \"\" ? var.lab_password : random_password.lab.result",
            "}",
        ]

    for node in plan.networks():
        lines += ["", 'module "%s" {' % plan.ref(node["id"])] + align([
            ("source", '"./modules/azure/network"'),
            ("name", '"%s"' % plan.tag(node["id"])),
            ("resource_group", "azurerm_resource_group.this.name"),
            ("location", "azurerm_resource_group.this.location"),
            ("cidr", '"%s"' % node["overlay"]["cidr"]),
        ]) + ["}"]

    for node in plan.segments():
        network = plan.ctx.network_of_segment(node["id"])
        lines += ["", 'module "%s" {' % plan.ref(node["id"])] + align([
            ("source", '"./modules/azure/segment"'),
            ("name", '"%s"' % plan.tag(node["id"])),
            ("resource_group", "azurerm_resource_group.this.name"),
            ("location", "azurerm_resource_group.this.location"),
            ("vnet_name", "module.%s.name" % plan.ref(network)),
            ("cidr", '"%s"' % node["overlay"]["cidr"]),
            ("nat", "true" if _needs_nat(plan, node["id"]) else "false"),
        ]) + ["}"]

    for node in plan.hosts():
        segment = plan.primary_segment(node)
        windows = plan.is_windows(node)
        pub, off, sku, ver = image_for(plan, node)
        pairs = [
            ("source", '"./modules/azure/host"'),
            ("name", '"%s"' % plan.tag(node["id"])),
            ("node_id", '"%s"' % plan.tag(node["id"])),
            ("kind", '"%s"' % node["kind"]),
            ("resource_group", "azurerm_resource_group.this.name"),
            ("location", "azurerm_resource_group.this.location"),
            ("subnet_id", "module.%s.subnet_id" % plan.ref(segment)),
            ("private_ip", '"%s"' % host_ip[node["id"]]),
            # A range's jumpbox is reached from outside (Guacamole and ssh), so it
            # needs a public address even when exposure would not grant one; every
            # other range host stays private.
            ("public_address",
             "true" if (plan.is_public(node)
                        or (is_range and node["kind"] == "jumpbox"))
             else "false"),
            ("size", '"%s"' % DEFAULT_MACHINE.get(node["kind"], "Standard_D2s_v3")),
            ("windows", "true" if windows else "false"),
            ("image_publisher", '"%s"' % pub),
            ("image_offer", '"%s"' % off),
            ("image_sku", '"%s"' % sku),
            ("image_version", '"%s"' % ver),
            ("ssh_public_key", "var.ssh_public_key"),
            # The single platform account (redop for ops, blueop for a range). See P1.7.
            # operator_username is the same identity now, not a separate account:
            # Azure uses it as the VM admin_username and the Guacamole login alike.
            ("admin_username", '"%s"' % plan.admin_account),
            ("operator_username", '"%s"' % plan.admin_account),
        ]
        # An Azure Windows Marketplace image ships a ~127 GB OS disk, so a
        # Windows host's disk must be at least that; Linux is fine at 40, and
        # Exchange needs the room regardless.
        services = node.get("overlay", {}).get("services") or []
        disk = 128 if ("exchange" in services or windows) else 40
        pairs.append(("disk_size", str(disk)))
        # Auto stop, when the canvas asked for one. Azure takes HHmm and a WINDOWS
        # timezone id rather than the IANA name GCP wants; az_timezone (computed
        # above) is the translation, with an unmapped IANA zone already refused. See 0057.
        if stop:
            pairs += [
                # HHMM with no separator, so it needs zero padding the cron
                # schedules do not: "${h}${m}" would render 1 and 5 as "15"
                # rather than "0105". Padded in a local, or a literal when the
                # clock is fixed.
                ("auto_stop_at", stop["hhmm_expr"]),
                ("auto_stop_timezone", '"%s"' % az_timezone),
            ]
        if has_jumpbox:
            pairs += [
                # WinRM is the range's Windows provisioning path (the boot script
                # stands up an HTTPS listener for Ansible). An offense Windows
                # operator self-provisions at boot and is never managed over WinRM,
                # so the listener is range-only.
                ("enable_winrm", "true" if (is_range and windows) else "false"),
                ("lab_password", "local.lab_password"),
                ("guac_public_key", "tls_private_key.guacamole.public_key_openssh"),
                ("guac_private_key",
                 "tls_private_key.guacamole.private_key_openssh"
                 if node["kind"] == "jumpbox" else '""'),
            ]
        else:
            pairs.append(("lab_password", '""'))
        # The offense Windows operator self-provisions its kit at boot (it has no
        # WinRM and Ansible never reaches it), so it takes the operator setup
        # script -- base64-encoded to ride inside the extension command, since the
        # script has here-strings of its own -- plus a hosts block for its
        # MobaXterm sessions. Offense only: a range's Windows hosts use Ansible.
        if not is_range and node["kind"] == "operator" and windows:
            pairs += [
                ("operator_setup", "true"),
                ("operator_setup_script_b64",
                 'base64encode(file("${path.module}/scripts/operator_setup.ps1"))'),
                ("operator_hosts", operator_hosts_hcl(plan)),
                # The same key the jumpbox uses: its public half is already an
                # authorized key for the platform account on every host, so the
                # operator box can key-auth into the stack and MobaXterm stops
                # prompting for the password. Password auth stays as fallback.
                ("operator_ssh_key",
                 "tls_private_key.guacamole.private_key_openssh"),
            ]
        lines += ["", 'module "%s" {' % plan.ref(node["id"])] + align(pairs) + ["}"]

    # peers: a VNet peering, both directions. Azure needs one resource per
    # direction (like gcp), each created in its own VNet naming the other's id;
    # routes exchange on their own once both exist. NSGs do not cross a peering, so
    # cross-peering firewall paths match by subnet CIDR, the same as gcp.
    for edge in plan.ctx.by_role.get("peers", []):
        a, b = edge["source"], edge["target"]
        lines += ["", 'module "%s" {' % plan.ref(edge["id"])] + align([
            ("source", '"./modules/azure/peering"'),
            ("name", '"%s"' % plan.tag(edge["id"])),
            ("resource_group", "azurerm_resource_group.this.name"),
            ("vnet_a_name", "module.%s.name" % plan.ref(a)),
            ("vnet_a_id", "module.%s.id" % plan.ref(a)),
            ("vnet_b_name", "module.%s.name" % plan.ref(b)),
            ("vnet_b_id", "module.%s.id" % plan.ref(b)),
        ]) + ["}"]

    if has_jumpbox:
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
            '  description = "Shared password for the operator account, the built-in Administrator, and the portal."',
            "  sensitive   = true",
            "  value       = local.lab_password",
            "}",
        ]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- firewall

def _firewall(plan):
    """NSG rules, one per subnet's security group, derived from the same edges as
    the cloud backends. Rules are matched by address (each host has a static
    private one) and take an ascending priority per NSG per direction."""
    ctx = plan.ctx
    lines = [
        "# Generated by redStackPRO. Do not edit.",
        "# Every rule below exists because of an edge in the topology. An Azure NSG",
        "# rule matches by address and needs a unique priority, assigned per",
        "# segment in ascending order. See 0015.",
    ]
    host_ip = _host_ips(plan)

    def seg_of(host_id):
        return plan.primary_segment(ctx.nodes[host_id])

    def seg_cidr(host_id):
        return ctx.overlay(seg_of(host_id), "cidr")

    # Accumulate rules per segment NSG so priorities are unique within it. A rule
    # name is also the azurerm resource name, which terraform requires to be unique
    # per module, so the same name is emitted once (first wins): a redirector that
    # fronts three teamservers yields one public-ingress rule, not three, and a
    # host reachable from several manages edges is opened once. Mirrors gcp's seen.
    by_seg = {}
    seen = set()

    def add(seg_id, name, port, source, dest, proto="Tcp"):
        if name in seen:
            return
        seen.add(name)
        by_seg.setdefault(seg_id, []).append(
            {"name": name, "port": port, "source": source, "dest": dest,
             "proto": proto})

    def az_proto(p):
        return {"tcp": "Tcp", "udp": "Udp", "all": "*", "*": "*"}.get(p, "Tcp")

    def ip_list(ids):
        return "[%s]" % ", ".join('"%s"' % host_ip[i] for i in ids)

    for edge in ctx.by_role.get("manages", []):
        jump = edge["source"]
        jseg = seg_of(jump)
        add(jseg, "operator_ssh_%s" % plan.ref(jump), "22",
            "var.operator_source_ranges", '["%s"]' % host_ip[jump])
        # In a VPN access mode (offense) the jumpbox opens its VPN listen port and
        # the Guacamole portal rides the tunnel rather than being exposed on 443;
        # otherwise the portal is open on 443. Mirrors gcp/aws.
        vpn = plan.vpn_access(ctx.nodes[jump])
        if vpn:
            _mode, vport, vproto = vpn
            add(jseg, "operator_vpn_%s" % plan.ref(jump), str(vport),
                "var.operator_source_ranges", '["%s"]' % host_ip[jump],
                proto=az_proto(vproto))
        else:
            add(jseg, "operator_guacamole_%s" % plan.ref(jump), "443",
                "var.operator_source_ranges", '["%s"]' % host_ip[jump])
        # The jumpbox is the range foothold: it must receive traffic range hosts
        # initiate back to it (coerced/relayed NTLM to an operator listener, a
        # pivoted callback). Internal (segment) surface only; its internet
        # surface stays the operator rules above. Mirrors the AD all-from-segment
        # rule below. See part-04 and gcp.py's foothold rule.
        add(jseg, "foothold_%s" % plan.ref(jump), "*",
            '["%s"]' % seg_cidr(jump), '["%s"]' % host_ip[jump], proto="*")
        for host in sorted(plan.hosts(), key=lambda h: h["id"]):
            if host["id"] == jump or ctx.manager_of(host["id"]) != jump:
                continue
            add(seg_of(host["id"]),
                "mgmt_%s" % plan.ref(host["id"]),
                str(plan.management_port(host)),
                '["%s"]' % host_ip[jump], '["%s"]' % host_ip[host["id"]])
            # guacd on the jumpbox reaches a Windows box's RDP tile (or a
            # desktop-mode Kali operator's) on 3389.
            if plan.is_windows(host) or plan.is_gui_operator(host):
                add(seg_of(host["id"]),
                    "mgmt_rdp_%s" % plan.ref(host["id"]), "3389",
                    '["%s"]' % host_ip[jump], '["%s"]' % host_ip[host["id"]])

    # The operator's own stack, internally open (offense only). Every segment
    # accepts all traffic from every stack network's CIDR, so a peered redirector,
    # teamserver, and operator all reach each other. Azure matches by CIDR, which
    # carries across a peering, so there is no same-net-vs-peered split to make. A
    # range keeps strictly edge-derived rules, so this does not apply there.
    if not plan.is_range():
        stack_cidrs = [c for c in (ctx.overlay(n["id"], "cidr")
                                   for n in plan.networks()) if c]
        src = "[%s]" % ", ".join('"%s"' % c for c in stack_cidrs)
        for seg in plan.segments():
            add(seg["id"], "intra_%s" % plan.ref(seg["id"]), "*",
                src, '["%s"]' % ctx.overlay(seg["id"], "cidr"), proto="*")

    # fronts: public ingress to the redirector, then redirector to teamserver.
    for edge in ctx.by_role.get("fronts", []):
        rdir, ts = edge["source"], edge["target"]
        proto = az_proto("tcp" if edge["protocol"] != "dns" else "udp")
        listen = edge["listen_port"]
        upstream = edge.get("upstream_port", listen)
        add(seg_of(rdir), "in_%s_%s" % (plan.ref(rdir), listen), str(listen),
            '["0.0.0.0/0"]', '["%s"]' % host_ip[rdir], proto=proto)
        add(seg_of(ts), "fwd_%s_%s" % (plan.ref(rdir), plan.ref(ts)), str(upstream),
            ip_list([rdir]), '["%s"]' % host_ip[ts], proto=proto)

    # A redirector keeps 80 open to the internet for Certbot's ACME http-01
    # challenge, whatever its cert source, so renewals keep working.
    for node in plan.hosts():
        if ctx.kind(node["id"]) != "redirector":
            continue
        add(seg_of(node["id"]), "acme_in_%s" % plan.ref(node["id"]), "80",
            '["0.0.0.0/0"]', '["%s"]' % host_ip[node["id"]])

    # ctl: an operator drives a teamserver from inside over the C2 control port(s).
    # The beacon channel itself rides the fronts edge through the redirector; this
    # is the separate operator -> teamserver management path. One rule per port.
    operators = sorted(plan.operators(), key=lambda h: h["id"])
    if operators:
        op_src = ip_list([o["id"] for o in operators])
        for ts in sorted(plan.hosts(), key=lambda h: h["id"]):
            for port in plan.control_ports(ts) or []:
                add(seg_of(ts["id"]), "ctl_%s_%s" % (plan.ref(ts["id"]), port),
                    str(port), op_src, '["%s"]' % host_ip[ts["id"]])

    # logs_to: senders reach the collector on its ingest port and nothing else.
    sinks = {}
    for edge in ctx.by_role.get("logs_to", []):
        sinks.setdefault(edge["target"], []).append(edge["source"])
    for collector, senders in sorted(sinks.items()):
        port = ctx.overlay(collector, "ingest_port", 5044)
        add(seg_of(collector), "log_%s" % plan.ref(collector), str(port),
            ip_list(sorted(senders)), '["%s"]' % host_ip[collector])

    for host in plan.intra_segment_hosts():
        add(seg_of(host["id"]), "ad_intra_%s" % plan.ref(host["id"]), "*",
            '["%s"]' % seg_cidr(host["id"]), '["%s"]' % host_ip[host["id"]],
            proto="*")

    for seg_id in sorted(by_seg):
        nsg = "module.%s.nsg_name" % plan.ref(seg_id)
        for i, r in enumerate(by_seg[seg_id]):
            priority = 100 + i
            lines += ["",
                      'resource "azurerm_network_security_rule" "%s" {' % r["name"]]
            body = [
                ("name", '"%s"' % r["name"]),
                ("resource_group_name", "azurerm_resource_group.this.name"),
                ("network_security_group_name", nsg),
                ("priority", str(priority)),
                ("direction", '"Inbound"'),
                ("access", '"Allow"'),
                ("protocol", '"%s"' % r["proto"]),
                ("source_port_range", '"*"'),
                ("destination_port_range", '"%s"' % r["port"]),
            ]
            # source is already valid HCL: either a variable list expression
            # (var.operator_source_ranges) or a literal list of addresses/CIDRs.
            body.append(("source_address_prefixes", r["source"]))
            body.append(("destination_address_prefixes", r["dest"]))
            lines += align(body) + ["}"]

    return "\n".join(lines) + "\n"
