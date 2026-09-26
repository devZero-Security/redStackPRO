# DRACARYS solution - redStackPRO edition

DRACARYS is a GOAD challenge lab (by Cyril Servieres / Orange Cyberdefense):
start with no credentials and reach Domain Admin on `dracarys.lab`. Unlike the
GOAD pwning series, mayfly deliberately publishes no solution. This page
documents the intended chain against redStackPRO's faithful recreation of the
lab, reconstructed from the upstream `ad/DRACARYS` definition and the redStackPRO
roles that reproduce it. See [[dracarys-fidelity-gap]].

> **Status: authored from the upstream lab definition, not fully live-verified.** The
> chain below follows the intended DRACARYS path; parts of the edge set (the KeePass
> vault, the WriteSPN step, the bots) are recreated in the roles but not all confirmed
> on a live deploy. Verify on a deploy before relying on it.

## Methodology

Same external red-team framing as the [GOAD series](../goad/README.md), see
[[range-access-model]]: the jumpbox is the only public host, everything else is
private, and the operator pivots through the jumpbox (SSH SOCKS or a beacon).
Within the lab, the challenge's own start point is the Linux member.

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

Domain `dracarys.lab`, subnet `192.168.56.0/24`, prefix `cyb` (GCP resource names
only; the Windows/AD names are the bare hostnames). Three members plus the
jumpbox:

| host | AD name | OS | role in the chain |
|------|---------|----|--------------------|
| balerion | BALERION | Server 2019 | DC, serves LDAPS, runs the CredSSP `keepass_bot` |
| vhagar | VHAGAR | Server 2019 | member, holds the KeePass vault, runs `bot_ssh`, CredSSP server |
| syrax | SYRAX | Ubuntu | Linux member, the challenge start point |
| jumpbox | - | Debian | foothold, Guacamole, SSH |

Cast: `drogon` (Domain Admin, also LinuxAdmins), `rhaegal` (local admin on
vhagar, LinuxAdmins), `viserion` (LinuxUsers, has WriteSPN over `vhagar$`),
`sunfyre` (LinuxUsers).

## The chain

### 0. Foothold on syrax

The challenge starts on the Linux member. Reach it through the jumpbox pivot.
`LinuxUsers` and `LinuxAdmins` may SSH to syrax, so any low-user credential (or
the capture in step 1) gets you a shell there.

### 1. Capture viserion (the bot_ssh login bot)

vhagar runs a scheduled bot every minute that authenticates **to syrax as
viserion** (redStackPRO's `bot_ssh`, GOAD's klink/plink login bot). An operator
already on syrax watches for that recurring inbound authentication and recovers
viserion's credential:

```
# on syrax, from the pivot
sudo tcpdump -i any port 22 &          # observe the recurring bot connection
last | grep viserion ; journalctl -u ssh | grep viserion
```

The bot proves viserion is a live domain account and hands you its context.

### 2. viserion -> targeted Kerberoast of vhagar$

viserion holds `Ext-Write-SPN` over the computer account `vhagar$` (a domain
ACL). Write an SPN onto `vhagar$`, then Kerberoast it:

```
proxychains -q certipy account ...        # or:
proxychains -q python3 targetedKerberoast.py -d dracarys.lab -u viserion -p '<pass>'
```

Writing an SPN to a machine account and roasting it yields `vhagar$`'s ticket
material; crack or use it to operate against vhagar.

### 3. rhaegal via the CredSSP double-hop (keepass_bot)

balerion (the DC) runs `keepass_bot` every minute: it uses **CredSSP** to
`Invoke-Command` onto vhagar **as rhaegal**, to open a password vault. CredSSP
delegates rhaegal's *plaintext* credential to vhagar. Because rhaegal is a **local
admin on vhagar** (so the bot can run there), an operator holding vhagar recovers
rhaegal's delegated credential from the CredSSP logon session:

```
# on vhagar, with a beacon or admin session
mimikatz # sekurlsa::credman
mimikatz # sekurlsa::logonpasswords     # the delegated CredSSP credential
```

### 4. Loot the vault -> drogon (Domain Admin)

The `keepass_bot` opens `C:\vault.kdbx` on vhagar. Its master password is visible
in the bot script (`C:\keepass_bot.ps1`, readable once you are on the host).
Open the vault and read the entry: it holds **drogon**'s credential, and drogon
is a Domain Admin.

```
# exfil C:\vault.kdbx, then, with the master seen in keepass_bot.ps1:
keepass2john vault.kdbx        # or open directly with the known master
# entry "domain-admin" -> drogon : <domain admin password>
```

### 5. Domain Admin

Authenticate as drogon and confirm Domain Admin on `dracarys.lab` (DCSync, or a
beacon on balerion as SEVENKINGDOMS-equivalent DA).

```
proxychains -q secretsdump.py 'dracarys.lab/drogon:<pass>@balerion.dracarys.lab'
```

## How redStackPRO reproduces it

Every element above is built by the canvas template, not hand-placed:

| element | how |
|---------|-----|
| WriteSPN edge | domain `acls`: `viserion -> vhagar$ Ext-Write-SPN` |
| CredSSP double-hop | `enable_credssp_client` (balerion) + `enable_credssp_server` (vhagar) |
| the two bots | `schedule` vulns: `keepass_bot` (CredSSP) and `bot_ssh` (SSH to syrax) |
| rhaegal local admin | `privilege: local_admin` -> `redstackpro_srv_local_admins` on vhagar |
| the vault | `keepass_vault`: KeePass DB generated on vhagar, entry filled from drogon's deployed password (no secret in the template) |
| LDAPS realism | `ldaps`: a server-auth cert on balerion |

## Notes

- **No secret is committed for the vault.** The vault entry password is taken
  from drogon's actual deployed password at provision time, so the template ships
  no domain-admin secret. The per-user lab passwords in the topology are lab
  fixtures, as in upstream GOAD.
- **Constrained delegation.** vhagar carries `constrained_delegation_kerberos`
  (WSMAN/vhagar) as an additional path, matching the upstream `wsman_kerb`
  breadcrumb. The upstream `set_spn` breadcrumb points at a host (`arrax`) that
  does not exist in the three-host lab and is left out.

## Step results

| step | result | notes |
|------|--------|-------|
| 0 foothold on syrax | | pivot + LinuxUsers SSH |
| 1 capture viserion (bot_ssh) | | needs the bot running |
| 2 WriteSPN kerberoast vhagar$ | | ACL wired |
| 3 CredSSP capture rhaegal (keepass_bot) | | needs rhaegal local admin on vhagar |
| 4 loot vault -> drogon | | keepass_vault |
| 5 Domain Admin | | |

Attribution: DRACARYS by Cyril Servieres / Orange-Cyberdefense GOAD. Recreated
and documented in our own words for redStackPRO.
