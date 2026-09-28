# Solution walkthroughs

Each shipped lab gets a walkthrough here: the attack path an operator runs
against a live deploy, written against that lab's own topology. Read a lab's
`DEFENSE-BRIEFING.md` (written into the export at compile time, filled in with your deploy's real addresses after `terraform apply`)
alongside its walkthrough for the exact hosts, addresses, and credentials of
your deploy; the pages below name the template's hosts, which are not yours.

| lab | path | what it is |
|-----|------|------------|
| goad | [goad/README.md](goad/README.md) | full GOAD, three domains, the 14-part reference series |
| goad-light | [goad-light/README.md](goad-light/README.md) | two domains, three Windows hosts; generated from the goad series |
| goad-mini | [goad-mini/README.md](goad-mini/README.md) | the smallest lab; generated from the goad series |
| goad-minilab | [goad-minilab/README.md](goad-minilab/README.md) | one domain, a DC and a workstation; CredSSP delegation and scheduled-task abuse |
| goad-nha | [goad-nha/README.md](goad-nha/README.md) | Ninja Hack Academy, two forests, an ESC4 certificate-template takeover across the trust |
| goad-sccm | [goad-sccm/README.md](goad-sccm/README.md) | an SCCM/MECM site, recon through execution |
| goad-wazuh | [goad-wazuh/README.md](goad-wazuh/README.md) | GOAD-Light plus a Wazuh SIEM, the attack walked alongside what it should trip in detection |
| goad-dracarys | [goad-dracarys/README.md](goad-dracarys/README.md) | the DRACARYS challenge lab, no starting credentials to Domain Admin |
| harbor | [harbor/README.md](harbor/README.md) | redStackPRO's own range, a two-domain corporate forest |

[labs/README.md](labs/README.md) tracks, per lab, which techniques its topology
actually carries. It is the coverage matrix, not a walkthrough.

## Range access model

Every lab here uses the same access model. The jumpbox is the only public host
in the range; every other backend host is private, with no internet-exposed
port. The operator does not reach the range directly: they land a beacon on a
range host (patient zero) through the jumpbox's Guacamole portal, then work
through that beacon's SOCKS proxy for anything that needs to reach the rest of
the range, including Linux tooling run over `proxychains`. The jumpbox's own
SSH access still exists, as an admin and scripting convenience and as a
fallback, but it is not the walkthroughs' engagement path.

## Tests run through the beacon

Every step in these walkthroughs runs through the C2 beacon described above,
not over direct SSH into the range. That is the external-C2 point of view: an
operator with no network shortcut into the range, only the same foothold a
real engagement would land. On the rare step that cannot go through the
beacon, for example a relay listener that has to receive an inbound
connection rather than proxy an outbound one, the page says so and explains
why.
