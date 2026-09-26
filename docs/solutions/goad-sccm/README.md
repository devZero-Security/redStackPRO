# SCCM / MECM solution - redStackPRO edition

A redStackPRO adaptation of mayfly277's SCCM LAB series (part 0x0 to 0x3),
which in turn follows the [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager)
taxonomy: RECON, CRED, TAKEOVER, ELEVATE, EXEC. Those attack ids are used here
so a step can be matched back to both sources.

mayfly's part 0x0 is lab installation with Vagrant and VirtualBox. redStackPRO
replaces it entirely: the lab is compiled from the canvas and deployed with one
`deploy.sh`, so this series starts at recon.

> **Status: authored and broader than the mayfly source, the live pass is not yet
> complete.** The steps are reconstructed from the Misconfiguration Manager taxonomy and
> the redStackPRO roles that build the lab; the end-to-end verification against a live
> deploy is still owed. Verify on a deploy before relying on it.

## Methodology

Same external red team framing as the [GOAD series](../goad/README.md), and the same
rules apply. See the [range access model](../README.md#range-access-model):

1. **External POV, C2 only.** The jumpbox is the only public host. Every SCCM
   host is private with no internet exposed port.
2. **Initial access is a beacon in patient zero's context, through the portal.**
   Enter at the Guacamole portal, open the patient-zero RDP tile, drop an Apollo
   payload on the GuacShare drive and run it. The beacon's SOCKS is the pivot.
   The jumpbox ssh SOCKS proxy remains an admin/agent convenience and a fallback,
   not the engagement's initial access.
3. **Linux tooling runs through the pivot** (the beacon's SOCKS) with
   proxychains. Windows side work runs through the beacon.

## Provider differences

redStackPRO compiles this range for cloud backends (`gcp`, `aws`, `azure`) and
on-prem backends (`proxmox`, `esxi`). The attack chain is identical on all of
them; what differs is the operator's path to the range, because the on-prem
backends declare fewer network capabilities (`src/redstackpro/schema/registry/providers/`).

| capability | cloud (gcp/aws/azure) | on-prem (proxmox/esxi) |
|------------|-----------------------|------------------------|
| public address | allocated: the jumpbox gets an external IP | none: reachability depends on the operator's own network and any upstream NAT or firewall |
| private DNS | managed zone, hosts resolve by name | none: use static hosts entries |
| network peering | managed: a jumpbox or collector can serve across the project boundary | none: joining networks is the host network's routing, which redStackPRO does not control |
| host firewall | per-VM firewall | proxmox has one, esxi has none (layer-2 VLAN isolation only) |

- **Range access.** On cloud the jumpbox has an allocated (per-deploy, ephemeral)
  public address, read from `RANGE-BRIEFING.md`. On on-prem there is no allocated
  external IP: reach the jumpbox over the operator's own network or VPN.
- **Name resolution.** On cloud the range can resolve through managed private DNS.
  On on-prem there is no managed zone, so populate static hosts entries from the
  internal IPs. Static entries work on cloud too and keep the commands identical.

Azure is a preview backend: it allocates public addresses, but its private DNS
and peering modules are not built yet (`azure.yaml`), so on azure treat name
resolution as on-prem (static hosts entries) and expect no managed peering.

## Topology under test

Domain `sccm.lab`, subnet `192.168.56.0/24`, prefix `cyb` on the range's GCP
project. Cloud resource names carry the prefix, Windows and AD names do
not.

| host | AD name | address | role |
|------|---------|---------|------|
| cyb-jumpbox | - | 192.168.56.2 | foothold, Guacamole, ssh |
| cyb-mecm | MECM | 192.168.56.3 | site server, MECM primary site |
| cyb-client | CLIENT | 192.168.56.4 | Windows 10 client |
| cyb-dc | DC | 192.168.56.5 | domain controller |
| cyb-mssql | MSSQL | 192.168.56.6 | remote site database |

The separate site database matters: it is what makes TAKEOVER-1 and TAKEOVER-2
reachable, because the site server authenticates to a **different** host.

## Attack coverage

The lab shape decides which attacks exist. This mirrors mayfly's own
present/not-present list, because our topology matches the same five host shape.

Present:

| id | attack | needs |
|----|--------|-------|
| RECON-1 | LDAP enumeration | low user |
| RECON-2 | SMB enumeration | low user |
| RECON-3 | HTTP enumeration | low user |
| RECON-4 | CMPivot | SCCM admin |
| RECON-5 | SMS provider enumeration | SCCM admin |
| CRED-1 | PXE credentials | no creds |
| CRED-2 | policy request, NAA secrets | machine account |
| CRED-3 | DPAPI credentials | admin on client |
| CRED-4 | legacy credentials | admin on client |
| CRED-5 | site database credentials | SCCM admin |
| TAKEOVER-1 | relay to site DB over MSSQL | low user |
| TAKEOVER-2 | relay to site DB over SMB | low user |
| ELEVATE-2 | relay client push installation | low user |
| EXEC-1 | application deployment | SCCM admin |
| EXEC-2 | script deployment | SCCM admin |

Absent, and why. These are lab shape limits, not gaps in the roles:

| id | attack | why not |
|----|--------|---------|
| ELEVATE-1 | relay to site system over SMB | no separate site system |
| TAKEOVER-3 | relay to AD CS | no ADCS in this lab |
| TAKEOVER-4 | relay CAS to child | no central administration site |
| TAKEOVER-5/6 | relay to AdminService / SMS | no separate SMS provider |
| TAKEOVER-7 | relay between HA nodes | no secondary site |
| TAKEOVER-8 | relay HTTP to LDAP | no WebClient on MECM$ |

If any of these should be demonstrable, it is a **topology** change (add the
missing host to the canvas), not a role change.

## Parts

| # | mayfly reference | page | status |
|---|------------------|------|--------|
| 1 | part 0x1, recon and PXE | [part-01-recon-and-pxe.md](part-01-recon-and-pxe.md) | not yet run |
| 2 | part 0x2, low user | [part-02-low-user.md](part-02-low-user.md) | not yet run |
| 3 | part 0x3, admin user | [part-03-admin-user.md](part-03-admin-user.md) | not yet run |

## How we validate

Same rule as the GOAD series: run each part against the live deployment, mark
every step PASS, FAIL or N-A, log gaps in the Pending Action Items list with a
recommendation, fix and commit, then rerun until the part matches the documented
outcome.

Attribution: adapted from mayfly277's SCCM LAB series (mayfly277.github.io) and
the Misconfiguration Manager project. Rewritten in our own words for
redStackPRO.
