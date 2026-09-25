# SCCM / MECM solution - redStackPRO edition

A redStackPRO adaptation of mayfly277's SCCM LAB series (part 0x0 to 0x3),
which in turn follows the [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager)
taxonomy: RECON, CRED, TAKEOVER, ELEVATE, EXEC. Those attack ids are used here
so a step can be matched back to both sources.

mayfly's part 0x0 is lab installation with Vagrant and VirtualBox. redStackPRO
replaces it entirely: the lab is compiled from the canvas and deployed with one
`deploy.sh`, so this series starts at recon.

## Methodology

Same external red team framing as the [GOAD series](../goad/README.md), and the same
rules apply. See [[range-access-model]]:

1. **External POV, C2 only.** The jumpbox is the only public host. Every SCCM
   host is private with no internet exposed port.
2. **Initial access is a beacon in patient zero's context, through the portal.**
   Enter at the Guacamole portal, open the patient-zero RDP tile, drop an Apollo
   payload on the GuacShare drive and run it. The beacon's SOCKS is the pivot.
   The jumpbox ssh SOCKS proxy remains an admin/agent convenience and a fallback,
   not the engagement's initial access.
3. **Linux tooling runs through the pivot** (the beacon's SOCKS) with
   proxychains. Windows side work runs through the beacon.

## Topology under test

Domain `sccm.lab`, subnet `192.168.56.0/24`, prefix `cysc` on the range's GCP
project. Cloud resource names carry the prefix, Windows and AD names do
not.

| host | AD name | address | role |
|------|---------|---------|------|
| cysc-jumpbox | - | 192.168.56.2 | foothold, Guacamole, ssh |
| cysc-mecm | MECM | 192.168.56.3 | site server, MECM primary site |
| cysc-client | CLIENT | 192.168.56.4 | Windows 10 client |
| cysc-dc | DC | 192.168.56.5 | domain controller |
| cysc-mssql | MSSQL | 192.168.56.6 | remote site database |

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
