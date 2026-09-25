# nha coverage

Two domains in their own forest, five Windows hosts, a service oriented layout
(web, sql, share) rather than the Game of Thrones naming goad uses. Most of its
chain is covered by the GOAD series, with a four technique delta.

## What is in it

- Domains: `ninja.hack`, `academy.ninja.lan`
- `dc-vil` - DC, ADCS, `administrator_folder`
- `dc-ac` - DC, `administrator_folder`
- `web` - IIS member, `iis_webshell`, `writable_share`, `enable_credssp_server`
- `sql` - MSSQL member, `mssql_impersonation`, `mssql_linked`
- `share` - file member, `enable_credssp_client`, `schedule`
- `jumpbox` - ssh, Guacamole, wireguard

## Part mapping

| goad part | applies | why |
|-----------|---------|-----|
| 1 recon | yes | five hosts, a real scan |
| 2 find users | yes | |
| 3 enumeration with user | yes | |
| 4 poison and relay | no | no poisoning vulns set on either DC |
| 5 exploit with user | no | no autologon, sysvol or GPO material |
| 6 ADCS | no | the authored part-6 page targets essos - but this lab has its own ESC4, served on [its own page](../goad-nha/README.md) |
| 7 MSSQL | yes | `mssql_impersonation` and `mssql_linked`, the full part 7 chain including the linked server hop |
| 8 privilege escalation | yes | `iis_webshell` then `writable_share` on web |
| 9 lateral move | yes | web, sql and share are all reachable targets |
| 10 delegations | no | no delegation flaws set |
| 11 ACL | **yes** | **nine ACL edges across both domains, see below** |
| 12 trusts | partial | **two forests, bidirectional forest trust** - the forest-to-forest step applies; child-to-parent does not, there is no child (corrected 2026-09-15, see below) |
| 13 having fun | yes | `writable_share` on web is exactly what the page's share-plant step needs |
| 14 ADCS advanced | no | ESC7 needs `manageCA` on a CA this lab does not plant |

## Delta: 4 techniques goad does not cover

### `enable_credssp_client` (share) and `enable_credssp_server` (web)

Same pair as [minilab](minilab.md), but here the two sides sit on **different
member servers**, so the delegation crosses hosts in a more realistic shape:
share is permitted to delegate, web is permitted to receive. Validate both WSMan
policies landed, then confirm the delegated credential is recoverable on web.

### `schedule` (share)

Scheduled task abuse on the file server. As in minilab, check the task's
principal and ACL before claiming an escalation.

### `administrator_folder` (all three members and both DCs)

A lab marker rather than an attack: a flag folder on the administrator desktop
that proves an operator genuinely reached that host as an administrator. It is
the per host proof of compromise for this lab. Note it is catalogued under "Lab
markers" and is deliberately host provided, so a missing folder means the host
vuln dispatch did not reach that host at all.

## Corrections to the table above (2026-09-14, audited against the template)

The rows were hand written and four of them were wrong. They were found by
recomputing every row from `nha.json` with the same extractor the generated labs
use, after the same defect turned up in goad-light, goad-mini and the coverage
matrix. Nothing here was verified on a live range; it is read off the template.

### 11 ACL was recorded "no" and the lab carries **nine** ACL edges

Across both domains, and they form real chains rather than isolated grants:

- `ninja.hack`: `Sanin -> Jonin` GenericAll, `olivia.davis -> rachel.philips`
  WriteDacl, `hokage -> Domain Admins` GenericAll, `hokage -> AdminSDHolder`
  GenericAll
- `academy.ninja.lan`: `backup -> Sensei` WriteOwner, `backup -> AdminSDHolder`
  WriteOwner, `gmsaNFS$ -> backup` ForceChangePassword, `SQL$ -> CN=Computers`
  GenericAll

The gMSA to `backup` to AdminSDHolder path is a full escalation in the child
domain, and `hokage -> Domain Admins` is one in the parent. **Part 11 applies,
and this lab is a better ACL target than the table implied.**

### 6 ADCS said "no ESC template is planted" and there is one

`Jonin` holds **GenericAll on the `SignatureValidation` certificate template**.
That is ESC4 - the authored part 6 calls its own ESC4 step "the win". ESC4 is
modelled as an ACL on the template object rather than as a vuln id, which is why
a scan for ESC ids missed it, and it chains directly off the `Sanin -> Jonin`
edge above.

Part 6 still reads "no" because the column answers *can I follow that page here*,
and **every step of the authored page names essos hosts**, so none of it runs on
nha even though the technique is present. That is the known generation limit:
steps are filtered by the host they name, not by the capability they need, so a
lab with its own ESC4 on a different host loses the step rather than having it
retargeted. **The ESC4 here is real and unserved by any page** - raising it
explicitly, because a "no" in the table would otherwise bury it.

### 12 trusts - this correction was itself wrong, and is now inverted (2026-09-15)

The 2026-09-14 pass recorded "the two domains are **parent and child in one
forest**, so the child-to-parent golden-ticket hop applies but the forest-to-forest
step does not." **That is backwards.** The compiled artifact says:

- `ninja.hack` - `parent_fqdn: null`
- `academy.ninja.lan` - `parent_fqdn: null`
- the trust between them - `type: forest`, `direction: bidirectional`

Two forest roots joined by a forest trust. For contrast, a real child domain
compiles differently: goad-light's `north.sevenkingdoms.local` carries
`parent_fqdn: sevenkingdoms.local` and `type: parent_child`. So on this lab the
**forest-to-forest step is the one that applies**, and the child-to-parent
golden-ticket hop is the one that does not - the exact opposite of the note it
replaces. The `.ninja.` in `academy.ninja.lan` reads like a child and is not one;
the suffixes differ (`.lan` against `.hack`), which is what makes them separate
forests.

This matters beyond the table. Every member server is in ACADEMY while the CA and
the ESC4 template are in NINJA, so the [ESC4 chain](../goad-nha/README.md) is reached
**across that forest trust** - the technique the old note said did not apply.

Part 14 stays correctly "no", for its own stated reason: ESC7 needs `manageCA`,
not templates.

### 13 having fun was "partial" and applies in full

The page's requirement is `openshares` or `writable_share`, and web carries
`writable_share`. The old note pointed at `administrator_folder`, which is a lab
marker and has nothing to do with that page.

## Stand-up gate

Compile clean, one pass `RUN EXITED ok=1`, portal and foothold on the jumpbox.
Then confirm `administrator_folder` landed on all five Windows hosts, which
doubles as a cheap check that host vuln dispatch reached every one of them.
