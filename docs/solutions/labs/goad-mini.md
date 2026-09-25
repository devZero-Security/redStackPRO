# goad-mini coverage

The smallest lab: one domain, one DC, one jumpbox. Its technique surface is
`esc1` on kingslanding plus `account_is_sensitive` on renly.baratheon, so it is a
strict subset of goad with **no delta**.

**If you deployed this lab, read [its own solution set](../goad-mini/README.md)**
rather than the full series: five parts, with everything this lab cannot reach
removed.

**It has no SPN material at all.** An earlier version of this page described the
surface as "`esc1` plus the SPN material on the domain's users", and there is
none: no user carries `spns`, and none is `kerberoastable`. That is why part 3's
kerberoasting step is dropped from this lab's generated copy.

Its value is not technique variety. It is the cheapest lab that still exercises
the full platform path end to end, which makes it the right target for
validating the deploy pipeline itself rather than an attack chain.

## What is in it

- Domain: `sevenkingdoms.local`
- `kingslanding` - DC, ADCS, `esc1`
- `jumpbox` - ssh, Guacamole, wireguard

## Part mapping

**Generated, not maintained here.** See
[the goad-mini solution set](../goad-mini/README.md), produced from this lab's
own canvas template by `python -m redstackpro.tools.gen_solutions`. It reaches **5 of the 14
parts**: 1 recon, 2 find users, 3 enumeration (minus kerberoasting), 6 ADCS
(the ESC1 page, not the essos one) and 11 ACL.

**The hand-written table this replaced said part 11 does not apply, and that was
wrong.** goad-mini carries the **entire twelve edge sevenkingdoms ACL chain**,
tywin.lannister through to `GenericAll` on `kingslanding$`, plus lord.varys on
Domain Admins and AdminSDHolder. Every one of those edges is a user, group or
computer object in the single domain this lab does deploy, so none of it needs
the second domain or the member server the table assumed. Part 11 applies in
full, which makes this lab considerably more interesting than "the deploy
smoke test".

The rest of the table was right: no poisoning or relay (no second host), no
credential material vulns, no MSSQL, no member server to escalate on, nowhere to
move laterally, no delegation, no trusts, nothing to plant a share payload in.

## Delta

None. Two techniques, both in goad.

## What it is actually for

Use goad-mini to validate the things that have nothing to do with the attack
chain, because a failure here is unambiguous:

- the canvas compile and `deploy.sh` single pass gate
- jumpbox provisioning: Guacamole portal, the assumed-breach foothold account,
  key-only ssh with the foothold exception
- DC promotion and the domain coming up at all
- host vuln dispatch reaching a Windows host

This is the lab the live-verify range was built from on 2026-09-08, and it is
where the jumpbox pass and the host vuln path bugs were caught.
