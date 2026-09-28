# goad-mini coverage

The smallest lab: one domain, one DC, one jumpbox. Its technique surface is
`esc1` on kingslanding plus `account_is_sensitive` on renly.baratheon, so it is a
strict subset of goad with **no delta**.

**If you deployed this lab, read [its own solution set](../goad-mini/README.md)**
rather than the full series: a hand-written coverage page scoped to the two
techniques this lab carries.

**It has no SPN material at all.** An earlier version of this page described the
surface as "`esc1` plus the SPN material on the domain's users", and there is
none: no user carries `spns`, and none is `kerberoastable`. That is why
kerberoasting does not apply on this lab.

Its value is not technique variety. It is the cheapest lab that still exercises
the full platform path end to end, which makes it the right target for
validating the deploy pipeline itself rather than an attack chain.

## What is in it

- Domain: `sevenkingdoms.local`
- `kingslanding` - DC, ADCS, `esc1`
- `jumpbox` - ssh, Guacamole, wireguard

## Coverage

See [the goad-mini solution set](../goad-mini/README.md) for the hand-written
walkthrough. Two techniques apply, each mapped to a goad source page to follow
against this single domain:

- **ADCS ESC1** on `kingslanding` (`SEVENKINGDOMS-CA`).
- **The full twelve edge sevenkingdoms ACL chain** to Domain Admin,
  `tywin.lannister` through `GenericAll` on `kingslanding$`, plus `lord.varys`
  on Domain Admins and AdminSDHolder. Every edge is a user, group or computer
  object in the single domain, so none of it needs a second domain or a member
  server. This is what makes the lab more interesting than a deploy smoke test.

Nothing else is reachable: no poisoning or relay (one Windows host), no
Kerberoasting or AS-REP (no `spns`, none `kerberoastable`), no MSSQL, no member
server to escalate on, no lateral movement, no delegation, no trusts, nothing to
plant a share payload in.

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
