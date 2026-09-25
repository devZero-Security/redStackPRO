# goad-light coverage

A two domain cut of goad. Every technique it carries is also in goad, so the
[GOAD series](../goad/README.md) covers it with **no delta**.

**If you deployed this lab, read [its own solution set](../goad-light/README.md)
rather than the full series** - same pages, with the steps this lab cannot reach
removed instead of footnoted after you have read them. This page is the coverage
record behind that folder.

## What is in it

- Domains: `sevenkingdoms.local`, `north.sevenkingdoms.local` (parent and child)
- `kingslanding` - DC, ADCS, `esc1`
- `winterfell` - DC, the poisoning and credential material set
- `castelblack` - member, MSSQL and IIS
- `jumpbox` - ssh, Guacamole, wireguard

Dropped relative to goad: the whole `essos.local` forest, so `meereen` and
`braavos` are gone with them.

## Part mapping

**The mapping is generated now, not maintained here.** See
[the goad-light solution set](../goad-light/README.md): a filtered copy of the
GOAD series carrying only the steps this lab can reach, produced from this lab's
own canvas template by `python tools/gen_solutions.py`. Its table is the
authority for which parts apply.

A hand-written table used to live here and **three of its fourteen rows were
wrong**, which is why it was replaced by generation rather than corrected:

- **10 delegations** was recorded as `constrained_delegation_kerberos` only,
  "no RBCD". The lab in fact carries the `stannis.baratheon -> kingslanding$`
  `GenericAll` edge, which is exactly the precondition part 10's RBCD step uses,
  and winterfell is a DC, so the unconstrained path is present too. Part 10
  applies in full.
- **11 ACL** was recorded as `gpo_abuse` only. The lab carries the **entire**
  sevenkingdoms ACL chain, all twelve edges from tywin.lannister through to
  `kingslanding$`, plus lord.varys on AdminSDHolder. Part 11 applies in full.
- **6 ADCS** was close but pointed the wrong way: the issue is not that only
  `esc1` applies, it is that every step of the authored part 6 targets essos, so
  the ESC1 path is the page on this lab.

The two techniques it genuinely lacks are `mssql_linked` (the cross-forest
linked-server hop in part 7) and the whole essos ADCS set (part 14).

## Delta

None. Its 22 techniques are a strict subset of goad's 35.

## Stand-up gate

Compile clean from the canvas, one pass `RUN EXITED ok=1`, portal and foothold
present on the jumpbox. Nothing lab specific beyond that.
