# goad-wazuh solution - redStackPRO edition

`goad-wazuh` is a two-domain GOAD cut (GOAD-Light plus the official wazuh and ws01
extensions) with a **Wazuh SIEM** and agents on the Windows hosts. Its offense
overlaps goad, so the [GOAD series](../goad/README.md) is the attack solution. What
makes this lab its own is the **detection axis**: for each technique, does it
actually show up in Wazuh with the shipped config? That is the question goad's
solution never asks, and it is why this page walks the attack and the detection
together. The technique-by-technique detail, including what has been verified
live, is on [the coverage and detection page](../labs/goad-wazuh.md); this page is
the operator walkthrough over it.

> **Status: authored from the lab's own template, with the detection axis
> partially verified live (2026-09-09) and recorded on the coverage page.** The
> attack steps below follow the validated [GOAD series](../goad/README.md) but the
> attack-to-alert pairing for this specific lab is largely a prediction until a
> full offense pass is run against it. Read every "shipped visibility" call as
> predicted unless the coverage page marks it confirmed. Verify on a deploy before
> relying on it.

## Methodology

Same external red team framing as the [GOAD series](../goad/README.md), see the
[range access model](../README.md#range-access-model): the jumpbox is the only
public host, every AD host is private, and the operator works through a
beacon's SOCKS proxy (see [tests run through the
beacon](../README.md#tests-run-through-the-beacon)). Initial access is a beacon in patient zero's
context (`NORTH\hodor`) through the Guacamole portal. The one addition here is the
**Wazuh manager**: after each attack step, check whether the expected event
reached Wazuh and whether a rule fired.

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

## Topology

Two domains in one forest (parent-child, bidirectional, transitive), plus the
SIEM and a hardened workstation, on `192.168.56.0/24`.

| host | AD name | domain | range IP | role |
|------|---------|--------|----------|------|
| kingslanding | KINGSLANDING | sevenkingdoms.local (root) | 192.168.56.10 | DC, `ldap_signing_off`, the full sevenkingdoms ACL chain (12 edges), Wazuh agent |
| winterfell | WINTERFELL | north.sevenkingdoms.local | 192.168.56.11 | DC, `unconstrained_delegation`, `llmnr_poisoning`, `ldap_signing_off`, Wazuh agent |
| castelblack | CASTELBLACK | north.sevenkingdoms.local | 192.168.56.22 | member, MSSQL + IIS, `iis_webshell`, `mssql_impersonation`, `gpp_password`, Wazuh agent |
| ws01 | WS01 | sevenkingdoms.local | 192.168.56.30 | Windows 10 workstation, **hardened** (ASR, RunAsPPL, constrained PowerShell, Defender tamper protection), no planted vulns |
| wazuh | - | - | 192.168.56.5 | the SIEM (Ubuntu) |
| jumpbox | - | - | 192.168.56.4 | foothold, Guacamole, SSH, range CA |

Patient zero is `NORTH\hodor`, a low-privileged domain user (assumed-breach seed).
User flaws worth naming: `sansa.stark` and `sql_svc` are kerberoastable,
`brandon.stark` is AS-REP roastable, `robb.stark` has a weak password,
`samwell.tarly` has his password in his description. Read the briefing for this
deploy's exact values.

## The attack, and what each step should trip

The offense is the GOAD series; the depth is there, not repeated here. This is the
sequence and the detection expectation for each step. Visibility with the shipped
config: **good** (a native Security event Wazuh rules on), **partial** (an event
exists but needs auditing that is off by default, or is subtle), **blind** (no
host telemetry without Sysmon / 4688 / directory-service auditing). The
`endpoint_telemetry` toggle is on for the three Wazuh hosts, which installs Sysmon
and turns on command-line (4688) and directory-service (5136) auditing, so several
otherwise-blind rows come into range here. See the coverage page for the full map.

1. **Recon and find users** ([part 1](../goad/part-01-recon.md),
   [part 2](../goad/part-02-find-users.md)). Six hosts across two domains.
   Detection: logon and enumeration noise, not usually alertable on its own.
2. **LLMNR / NBT-NS poisoning** on the winterfell segment
   ([part 4](../goad/part-04-poison-and-relay.md)). `responder` for NetNTLM.
   Detection: **blind** on the victim host, this is a network technique; a host
   sensor or Sysmon DNS (event 22) helps.
3. **Kerberoast `sql_svc` / `sansa.stark`** and **AS-REP roast `brandon.stark`**
   ([part 3](../goad/part-03-enumeration-with-user.md)). Detection: **good**,
   4769 (TGS, RC4 0x17 for an SPN account) and 4768 (AS-REQ, pre-auth not
   required) are native and Wazuh rules on them.
4. **Weak / sprayable password** (`robb.stark`) and **password in description**
   (`samwell.tarly`). Detection: the spray is **good** (burst of 4625/4771); the
   description read is **blind** (no native per-attribute read event).
5. **castelblack: IIS web shell and MSSQL impersonation**
   ([part 7](../goad/part-07-mssql.md),
   [part 8](../goad/part-08-privilege-escalation.md)). Detection: web-shell child
   process of `w3wp` is **blind** without Sysmon 1 / 4688; MSSQL impersonation is
   **blind** to Windows logs (needs SQL Server audit shipped to Wazuh).
6. **GPP cpassword** on castelblack (`gpp_password`). Detection: **blind**, a
   SYSVOL read of `Groups.xml`; needs object-access auditing or an off-host decrypt
   detection.
7. **Unconstrained delegation** on winterfell
   ([part 10](../goad/part-10-delegations.md)): coerce a DC, capture its TGT.
   Detection: **partial**, subtle 4624/4769 around the capture.
8. **ACL abuse chain** in sevenkingdoms
   ([part 11](../goad/part-11-acl.md)): the twelve-edge path to Domain Admin
   (ForceChangePassword, GenericWrite, WriteDacl, WriteOwner, GenericAll).
   Detection: 4724/4728 are **partial to good**; the object-modify evidence (5136)
   is **blind** without directory-service auditing, which the toggle turns on here.
9. **Child to parent** across the trust
   ([part 12](../goad/part-12-trusts.md)): the child-to-root hop applies (parent
   and child, one forest; there is no second forest).

`ws01` is a deliberate **negative control**, not a target: it is hardened (ASR
rules block LSASS theft and PsExec/WMI child processes, LSASS runs as a Protected
Process Light, PowerShell is constrained) and ships no planted vulnerability. Use
it to confirm that the loud techniques (credential dumping, remote exec) are
blocked and, where they are attempted, generate the ASR and Defender events the
detection story wants.

## How to validate detection

For each step marked **good** or **partial**: run the attack from the GOAD series,
then confirm the expected event reached Wazuh and, if a rule exists, fired. Record
PASS (alert fired), LOGGED (event arrived, no alert), or BLIND (nothing). The
**blind** rows are expected to stay blind with the shipped agent config: they are
the evidence for shipping Sysmon and auditing, not failures of the lab. Gate all
of this on the stand-up check that every Windows agent shows **Active** in the
Wazuh agent list; a disconnected agent means no detection is possible. The
[coverage page](../labs/goad-wazuh.md) records what a live deploy has already
proven (the telemetry pipeline end to end, and the weak-password 4625 row
confirmed PASS).

## Step results

| step | offense | detection | notes |
|------|---------|-----------|-------|
| 1 recon + find users | | n/a | |
| 2 LLMNR/NBT-NS poison | | blind (network) | |
| 3 kerberoast + AS-REP | | good (4769/4768) | roast tooling from part 3 |
| 4 weak pw + password in description | | good spray / blind description | 4625 spray confirmed live |
| 5 IIS webshell + MSSQL impersonation | | blind (needs Sysmon / SQL audit) | |
| 6 GPP cpassword | | blind (SYSVOL read) | |
| 7 unconstrained delegation | | partial | coerce a DC |
| 8 ACL chain to DA | | partial/blind (5136) | 12 edges, sevenkingdoms |
| 9 child to parent trust | | partial | one forest |
| ws01 hardening control | | ASR/Defender events | negative control, not a target |

Attribution: GOAD and its wazuh/ws01 extensions are the GOAD project's. Recreated
natively on the redStackPRO canvas and documented in our own words.
