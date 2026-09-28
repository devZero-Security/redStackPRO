# GOAD-Mini solution - redStackPRO edition

GOAD-Mini is the smallest lab in the family: a single domain,
`sevenkingdoms.local`, on one domain controller (`kingslanding`), plus the
jumpbox. It carries two things worth attacking, an ADCS ESC1 template on the DC
and the full sevenkingdoms ACL escalation chain to Domain Admin, and nothing
else. Because its whole story is one domain with an assumed foothold, it does
not follow the two-domain GOAD walkthrough, so this is a hand-written coverage
page rather than a filtered copy of [the GOAD series](../goad/README.md).

For the shared method and framing, read the
[GOAD series README](../goad/README.md); for the two techniques this lab
carries, the relevant GOAD source pages are linked under Attack coverage below,
to be read against this lab's single-domain shape.

## Methodology

Same external red team framing as the [GOAD series](../goad/README.md), and the
same [range access model](../README.md#range-access-model):

1. **External POV, C2 only.** The jumpbox is the only public host. The DC is
   private with no internet exposed port.
2. **Initial access is a beacon in an assumed foothold account, through the
   portal.** Enter at the Guacamole portal, open the foothold RDP tile, drop an
   Apollo payload on the GuacShare drive and run it. The beacon's SOCKS is the
   pivot. GOAD-Mini's path starts from a low `sevenkingdoms.local` domain user,
   not a poisoning or credential capture step, so the foothold is assumed rather
   than earned on this lab.
3. **Linux tooling runs through the pivot** (the beacon's SOCKS) with
   proxychains. Windows side work runs through the beacon.

## Topology under test

Domain `sevenkingdoms.local` (NetBIOS `SEVENKINGDOMS`), subnet
`192.168.56.0/24`, prefix `def` (defense mode). Cloud resource names carry the
prefix, Windows and AD names do not. Read your deploy's own
`DEFENSE-BRIEFING.md` for the per-deploy addresses and the foothold credential.

| host | AD name | address | role |
|------|---------|---------|------|
| def-jumpbox | - | 192.168.56.4 | foothold, Guacamole, ssh, wireguard, CA |
| def-kingslanding | KINGSLANDING | 192.168.56.10 | domain controller, ADCS |

The single domain carries the full Lannister and Baratheon cast (tywin, jaime,
cersei, tyron, robert, joffrey, renly, stannis) plus the Small Council
(petyer.baelish, lord.varys, maester.pycelle). `cersei.lannister` and
`robert.baratheon` are Domain Admins.

## Attack coverage

The lab shape decides which attacks exist. GOAD-Mini reaches two techniques,
both of which also exist in the full goad lab, so each maps to a GOAD source
page you can follow against this single domain.

Present:

| technique | what it is | GOAD page to follow |
|-----------|------------|---------------------|
| ADCS ESC1 | enrollee-supplied subject on an enabled template, `SEVENKINGDOMS-CA` on `kingslanding` | [part-06-adcs.md](../goad/part-06-adcs.md), the ESC1 section (ignore the essos ESC2/ESC3 sections, this lab has one CA and one template) |
| ACL chain to Domain Admin | the twelve edge sevenkingdoms chain, `tywin.lannister` through `GenericAll` on `kingslanding$`, plus `lord.varys` on Domain Admins and AdminSDHolder | [part-11-acl.md](../goad/part-11-acl.md), read entirely against the single domain |

When you follow those two GOAD pages, substitute this lab's shape: one domain
`sevenkingdoms.local`, one DC `kingslanding`, no `north` domain, no
`winterfell`, `castelblack` or `essos`, and no `north\hodor` patient zero. The
ACL chain and the ESC1 template are all sevenkingdoms objects on the one DC.

Absent, and why. These are lab shape limits, not gaps in the roles:

| technique | why not |
|-----------|---------|
| Kerberoasting / AS-REP roast | no user carries `spns` or `kerberoastable` |
| LLMNR/NBT-NS poisoning, NTLM relay | only one Windows host, nothing to poison or relay between |
| MSSQL, linked servers | no database host |
| Lateral movement, delegation, trusts | no member server, no delegation, single domain |

If any of these should be demonstrable, it is a **topology** change (add the
missing host or domain to the canvas), not a role change.

## What this lab is for

GOAD-Mini is the cheapest lab that still exercises the full platform path end to
end, so it is the right target for validating the deploy pipeline itself: the
canvas compile and `deploy.sh` single pass, jumpbox provisioning (Guacamole
portal, the assumed foothold account, key only ssh), DC promotion, and host vuln
dispatch reaching a Windows host. The ACL chain then gives it a complete low
user to Domain Admin story on a single small domain.

Attribution: a nod to the GOAD project (github.com/Orange-Cyberdefense/GOAD).
Recreated as a native redStackPRO topology, in our own words.
