# GOAD solution - redStackPRO edition

A redStackPRO adaptation of [mayfly277's GOAD pwning series](https://mayfly277.github.io/categories/goad/).
mayfly's write-up is the reference template; these pages capture the **same
attack path executed the redStackPRO way**.

## Methodology

We reframe GOAD from an **external red team point of view**. GOAD is normally an
internal-pentest lab; here the redStack attack range (`frontend/public/redstack.json`)
enforces the realistic external kill-chain.
See the [range access model](../README.md#range-access-model). Conventions we follow:

1. **External POV, C2-only.** No VPC peering, no network shortcut. The only
   public surface is the **jumpbox** and the redStack **redirector**; every
   range backend host is private with no internet-exposed port.
2. **Initial access is a beacon in patient zero's context, delivered through the
   portal.** The engagement begins at the **Guacamole portal** on the jumpbox,
   opening the **patient-zero RDP tile** (it signs in as the phished user, e.g.
   `NORTH\hodor`, on a range host). The operator drops an **Apollo** payload onto
   the session's **GuacShare** drive and runs it; it calls home to Mythic through
   the redirector, on your redirector domain (set per deploy with `--hostname`).
   If the browser upload into GuacShare stalls, smuggle the payload in over the
   range's own management plane instead:
   `scp` it to the jumpbox's shared drop, or copy it straight onto the host over
   WinRM from the jumpbox (`win_copy` / `Copy-Item` over a PSSession); a WinRM copy
   also carries no mark-of-the-web, so it runs without a SmartScreen prompt. This
   is the default starting point for the series and it runs live: it models
   initial access more realistically than dropping a beacon on the jumpbox
   itself. See the [range access model](../README.md#range-access-model). (The
   jumpbox SSH SOCKS path, `ssh -i keys/id_ed25519 -D 1080 blueop@<jumpbox>`, still
   exists as an agent/admin convenience and a fallback, but it is **not** the engagement's
   initial access.)
3. **Mythic is the C2.** From that first beacon the engagement runs through C2:
   - Apollo built-ins (`net`, `ls`, token ops),
   - **execute-assembly** of .NET tooling (Rubeus, Certify/Certipy, SharpHound,
     PowerView, etc.),
   - the beacon's **SOCKS proxy** for Linux/Kali tools (impacket, certipy, nmap)
     run from the redStack Kali via proxychains.
4. **Operate from within redStack.** The operator works from the redStack
   operator boxes (Kali, and the Windows operator with MobaXterm/Chromium
   preloaded), driving the range through the beacon and its SOCKS; the range is
   never touched directly beyond that pivot. Kali is used where genuinely needed;
   the C2 is the driver.

Each step records which method was used, so we can see how much of the chain is
operable purely from within redStack.

> **Provider note (range access).** The public surface above (the jumpbox and the
> redirector) assumes a cloud backend, where both get an allocated public address.
> On an on-prem backend (`proxmox`, `esxi`, on the roadmap) there is no allocated
> external IP: you reach the jumpbox over your own network or VPN, whatever fronts
> the range. On
> every backend, cloud included, name resolution runs off static hosts entries
> (part 1). The attack chain itself is unchanged. See
> [Provider differences](#provider-differences) below.

## Which GOAD lab these pages target

These pages follow the **full GOAD** lab (`frontend/public/goad/goad.json`): three
domains (`sevenkingdoms.local`, `north.sevenkingdoms.local`, `essos.local`), DCs
kingslanding / winterfell / meereen, members castelblack / braavos, and the ADCS
and MSSQL surface across both forests. A step that names a host is naming a full
GOAD host.

**If you deployed a smaller lab, read that lab's own set instead of this one:**
[goad-light](../goad-light/README.md) is generated from these pages by
`python -m redstackpro.tools.gen_solutions`, filtered to what it carries, so a step
that has no target on your range is removed up front rather than footnoted at the
end of the section you just read. [goad-mini](../goad-mini/README.md) has its own
hand-written page, since its single-domain story does not follow these pages. The
pages below are the authored source and target full GOAD.

**The smaller labs are strict subsets, so a subset of these pages applies.** The
common one is **GOAD-Light** (`goad-light.json`): two domains
(`sevenkingdoms.local`, `north.sevenkingdoms.local`) and three Windows hosts -
kingslanding (DC, ADCS ESC1), winterfell (DC), castelblack (MSSQL/IIS member).
It has no `essos.local`, so meereen, braavos and every essos user
(khal.drogo and the rest) do not exist on it, and neither does the cross-forest
trust. The per-lab column in the parts table below says what each lab can reach.

## Read your own range briefing first

Every deploy writes a **`DEFENSE-BRIEFING.md`** into the export, filled in after
`terraform apply` with **this deploy's** real addresses, the exact user /
password / flaw table, patient zero, the trusts, and every planted vuln and ACL
chain. It is the source of truth for the range in front of you - hosts and
credentials both. **Read it before these pages**, and where a page and the
briefing disagree on an address or a password, the briefing is right: it was
generated from the topology you actually compiled.

## Attack infrastructure (redStack)

The infrastructure side (the attack range) is **redStack**
(`frontend/public/redstack.json`): Mythic / Sliver / Adaptix teamservers, an
Apache redirector, the jumpbox (Guacamole), Kali and Windows operators, and the
collector. Mythic is the C2 of record. redStack and the GOAD range are **separate
exports, deployed separately** (on GCP, typically one project each); the operator reaches the range
through the C2 (beacon + SOCKS), not by direct L2 adjacency. GOAD's range subnet
is `192.168.56.0/24`.

## Provider differences

redStackPRO compiles this range for cloud backends (`gcp`, `aws`, `azure`) and
on-prem backends (`proxmox`, `esxi`), which are on the roadmap and not yet
supported. The attack chain is identical on all of
them; what differs is the operator's path to the range, because the on-prem
backends declare fewer network capabilities (`src/redstackpro/schema/registry/providers/`).

| capability | cloud (gcp/aws/azure) | on-prem (proxmox/esxi) |
|------------|-----------------------|------------------------|
| public address | allocated: the jumpbox gets an external IP | none: reachability depends on the operator's own network and any upstream NAT or firewall |
| private DNS | none on any provider: no backend creates a managed zone, so use static hosts entries | none: use static hosts entries |
| network peering | managed: a jumpbox or collector in one network of the export can serve another network of the same export | none: joining networks is the host network's routing, which redStackPRO does not control |
| host firewall | per-VM firewall on gcp and aws, a Network Security Group per subnet on azure | proxmox has one, esxi has none (layer-2 VLAN isolation only) |

Two steps change in practice:

- **Range access and initial reachability.** On cloud the jumpbox has an
  allocated public address (still per-deploy and ephemeral, so read it from
  `DEFENSE-BRIEFING.md`). On on-prem there is no allocated external IP: reach the
  jumpbox over the operator's own network or VPN.
- **Name resolution.** No backend creates a managed DNS zone, on any provider,
  so populate static hosts entries (the
  operator's `/etc/hosts`, and the Windows hosts file where needed) from the
  internal IPs. Part 1 sets these up either way, so the commands stay identical.

Azure is supported from 0.10.0 (minilab, goad-light, goad-wazuh, goad and
dracarys are validated there). This lab is validated on Azure too: both forests
and the cross-forest trust, ADCS on ESSOS-CA, and MSSQL, with the Part 1, 2, 3, 6 and
7 checks run through a beacon from an Azure offense range.
Azure has an allocated public address and network peering, like GCP and AWS. It
declares no managed private DNS, so resolve range names with static hosts
entries, as on-prem.

## Standing objectives

Every base server, and the optional the-eyrie add-on, ran an Apollo beacon that
checked in through the redirector on a live range; persistence is not covered.

## Parts

The **GOAD-Light** column says whether the part has a target on that smaller lab:
✅ works as written, ◑ partial (the essos-independent half works), ➖ no target
(needs a host or trust GOAD-Light does not have).

| # | mayfly reference | redStack page | Full-GOAD status | GOAD-Light |
|---|------------------|---------------|------------------|------------|
| 1 | reconnaissance and scan | [part-01-recon.md](part-01-recon.md) | PASS (live) | ✅ fewer hosts, no essos |
| 2 | find users | [part-02-find-users.md](part-02-find-users.md) | PASS (live) | ✅ no essos accounts (khal.drogo) |
| 3 | enumeration with user | [part-03-enumeration-with-user.md](part-03-enumeration-with-user.md) | PASS (live) | ✅ |
| 4 | poison and relay | [part-04-poison-and-relay.md](part-04-poison-and-relay.md) | validated (cloud broadcast gap + coercion→relay) | ✅ coercion→relay to castelblack applies (both domains present); Step 1 Responder/mitm6 is the cloud gap regardless of lab |
| 5 | exploit with user | [part-05-exploit-with-user.md](part-05-exploit-with-user.md) | run - both chains (noPac + PrintNightmare) patch-blocked; fidelity toggles needed | ◑ winterfell present; same patch blocks |
| 6 | ADCS | [part-06-adcs.md](part-06-adcs.md) | PASS - ESC4→DA + Shadow Creds (Certifried patched) | ◑ kingslanding ESC1 only; ESC4 is on braavos/essos |
| 7 | MSSQL | [part-07-mssql.md](part-07-mssql.md) | PASS - impersonation/msdb RCE (trusted link self-maps) | ◑ castelblack impersonation works; cross-forest link is essos |
| 8 | privilege escalation | [part-08-privilege-escalation.md](part-08-privilege-escalation.md) | PASS - SeImpersonate→SYSTEM (PrintSpoofer) | ✅ on castelblack |
| 9 | lateral move | [part-09-lateral-move.md](part-09-lateral-move.md) | PASS - secretsdump + PTH/over-PTH | ✅ within sevenkingdoms/north |
| 10 | delegations | [part-10-delegations.md](part-10-delegations.md) | PASS - constrained + RBCD to DC admin | ✅ castelblack constrained delegation → winterfell |
| 11 | ACL | [part-11-acl.md](part-11-acl.md) | partial - edges/write-primitives work; shadow-creds gated by kingslanding LDAPS | ✅ sevenkingdoms ACL chain present |
| 12 | trusts | [part-12-trusts.md](part-12-trusts.md) | partial - topology confirmed; escalation needs a TGT/beacon | ◑ parent-child only; no essos forest trust |
| 13 | having fun inside a domain | [part-13-having-fun.md](part-13-having-fun.md) | plant verified; payoffs need victim/beacon | ◑ |
| 14 | ADCS 5/7/9/10/11/13/14/15 | [part-14-adcs-advanced.md](part-14-adcs-advanced.md) | PASS - ESC7→DA; ESC5/9/13/14 built, not yet run live (certipy-ad 5.1.0, no fork needed) | ➖ ADCS advanced surface is on braavos/essos |

Attribution: adapted from mayfly277's GOAD series (mayfly277.github.io) and the
Orange-Cyberdefense GOAD project. Rewritten in our own words for redStackPRO.
