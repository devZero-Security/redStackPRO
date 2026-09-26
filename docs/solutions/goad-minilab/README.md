# minilab solution - redStackPRO edition

`minilab` is the smallest GOAD-family lab that is **not** a subset of goad: a
single domain, one DC and one Windows 10 workstation, built around two techniques
the GOAD series never exercises, CredSSP credential delegation and scheduled-task
abuse. It is covered technique-by-technique in
[the coverage page](../labs/minilab.md); this page walks the intended chain end to
end. The short version: a weak, sprayable password gets you onto the workstation,
a Domain Admin's scheduled bot reaches that workstation over CredSSP every minute,
and CredSSP hands you the admin's plaintext credential.

> **Status: authored from the lab's own template, not yet run against a live
> range.** Every host, user, credential and scheduled task below was read out of
> `frontend/public/goad/minilab.json`. The commands follow the usual redStackPRO
> shape but carry no "Live verification" block and should not be trusted the way
> the validated parts of the [GOAD series](../goad/README.md) can be. Verify on a
> deploy before relying on it.

## Methodology

Same external red team framing as the [GOAD series](../goad/README.md), see the
[range access model](../README.md#range-access-model): the jumpbox is the only
public host, the DC and the workstation are private, and the operator works
through a beacon's SOCKS proxy (see [tests run through the
beacon](../README.md#tests-run-through-the-beacon)). Initial access is a beacon delivered through the
Guacamole portal. Commands below assume `proxychains` over that SOCKS and the
domain name in static hosts entries.

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

One domain, `mini.lab` (MINILAB), on `192.168.56.0/24`.

| host | AD name | role in the chain |
|------|---------|-------------------|
| dc | DC | domain controller, `stored_credential`, `enable_credssp_client`, runs the `connect_bot` scheduled task |
| ws | WS | Windows 10 workstation, `enable_credssp_server` (the CredSSP receiver) |
| jumpbox | - | foothold, Guacamole, SSH, WireGuard, range CA |

Cast (lab passwords are fixtures; read the briefing for this deploy's real ones):

- `alice` and `carol` are **Domain Admins**, both in `wsadmin`.
- `bob` is a plain user in `wsadmin`; `dave` is a plain user in `wsrdp`.
- `wsadmin` is the local-admin group on `ws`; every listed user carries a weak,
  guessable password, which is the point of the lab.

The two ACL edges the template plants both grant
`NT AUTHORITY\ANONYMOUS LOGON` read over the domain root. That configures
anonymous LDAP enumeration (part 2 material), not an escalation chain, so there is
no part 11 ACL walk here; see the coverage page.

## The chain

### 1. Enumerate, then spray the weak passwords

The anonymous-read grants let you list users over LDAP without a credential.
Every account carries a weak password, so a small spray lands a foothold; aim for
a `wsadmin` member, because that group is local admin on `ws`.

```
proxychains GetADUsers.py -all -dc-ip <dc-ip> 'mini.lab/' -no-pass   # anon list
proxychains kerbrute passwordspray -d mini.lab users.txt <candidate>
```

### 2. Land on the workstation

A `wsadmin` credential is a local administrator on `ws`. Get a beacon there.

```
proxychains wmiexec.py 'mini.lab/<wsadmin-user>:<pw>@<ws-ip>'
```

### 3. Catch the CredSSP-delegated Domain Admin credential

The DC runs the `connect_bot` scheduled task **every minute as MINILAB\alice**, a
Domain Admin, reaching `ws`. The lab pairs `enable_credssp_client` on the DC with
`enable_credssp_server` on `ws`, so that recurring authentication delegates
alice's **plaintext** credential to `ws`, where it lands in memory. An operator
who already owns `ws` reads it out:

```
# on ws, high integrity
mimikatz # sekurlsa::logonpasswords     # alice's delegated CredSSP credential
mimikatz # sekurlsa::credman
```

Wait for the task to fire (one-minute interval) so the credential is fresh in a
logon session.

### 4. Domain Admin

Authenticate as `alice` and confirm Domain Admin on `mini.lab`.

```
proxychains secretsdump.py 'mini.lab/alice:<pw>@<dc-ip>'
```

### Also present

- **`stored_credential` on the DC.** A Credential Manager entry
  (`TERMSRV/alicesecret`, owned by `MINILAB\alice`) is recoverable once you are on
  the DC, without touching LSASS. Shares its shape with GOAD part 5.
- **`schedule` on the DC.** The `connect_bot` task itself: confirm it exists, note
  the principal it runs as, and only take a task-rewrite escalation if its ACL
  actually lets a lower-privileged identity change its action.

## Step results

| step | result | notes |
|------|--------|-------|
| 1 enumerate + spray weak passwords | | anon LDAP read, then spray |
| 2 land on ws (wsadmin = local admin) | | |
| 3 capture CredSSP-delegated alice | | needs the bot running, validate both CredSSP sides |
| 4 Domain Admin | | |
| stored_credential on dc | | Credential Manager |

Attribution: minilab follows the GOAD project's MINILAB. Recreated and documented
in our own words for redStackPRO.
