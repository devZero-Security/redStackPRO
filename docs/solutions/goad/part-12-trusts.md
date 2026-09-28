# GOAD Part 12 - Trusts (redStackPRO)
<!-- lab-requires: multi_domain -->

Reference: [mayfly - GOAD part 12](https://mayfly277.github.io/posts/GOADv2-pwning-part12/).
Child→parent escalation and forest→forest lateral move, **through the hodor
beacon's SOCKS proxy** (`proxychains -q` in front of the impacket calls; every
DC is internal, see [part 1](part-01-recon.md) Step 1).

> **Status legend:** ✅ PASS · ❌ blocked · ⚠ partial · ⏳ not run.

## Headline result

**Trust topology confirmed.** The trust-escalation *techniques* (golden+extra-SID,
trust ticket, SID history) all need a **TGT-level or krbtgt-level** foothold in
the source domain; the S4U service tickets from parts 6/10 aren't enough for
DCSync. All three domains are already owned by other paths (ESC4, constrained
delegation, RBCD), so this is a technique-coverage gap, not an access gap - it
completes cleanly from a Windows beacon or with a domain krbtgt hash.

| Technique | Result |
|-----------|--------|
| Enumerate trusts | ✅ north↔sevenkingdoms (WITHIN_FOREST, bidirectional) |
| Child→parent golden + extra-SID (EA -519) | ⚠ needs north krbtgt (DCSync via S4U ST fails) |
| Trust ticket (inter-realm TGT) | ⏳ same krbtgt/trust-key prerequisite |
| Forest golden w/ SID history (essos→sevenkingdoms) | ⏳ needs SID history enabled + a privileged RID>1000 group |
| MSSQL trusted link (forest→forest) | ✅ shown in [part 7](part-07-mssql.md) (present; self-maps) |
| Unconstrained delegation (child→parent) | ⏳ shown enumerable in [part 10](part-10-delegations.md) |

## Step 1 - Enumerate trusts

- [x] LDAP `(objectCategory=trustedDomain)` as north\jon.snow →
  `sevenkingdoms.local`, direction 3 (bidirectional), type 2 (uplevel),
  `trustAttributes 0x20` (**WITHIN_FOREST**) - the child/parent trust. `✅`
  BloodHound `MATCH p=(n:Domain)-->(m:Domain)` maps the north↔sevenkingdoms
  (child/parent) and essos↔sevenkingdoms (forest) trusts.

## Step 2 - Child → parent (golden ticket + extra-SID)

- [ ] Chain: DCSync the child (north) krbtgt → forge a golden ticket with
  `-extra-sid <parentSID>-519` (Enterprise Admins) → DCSync the parent. **⚠
  blocked at DCSync:** the admin@winterfell ticket from the constrained-delegation
  abuse (part 10) is a **CIFS service ticket**, and impacket `secretsdump -k`
  can't derive the DRSUAPI ticket from it - DCSync needs a **TGT** or the
  krbtgt/administrator **hash**. From a Windows beacon (Rubeus/mimikatz) or once a
  north DA hash is in hand, this completes. `impacket raiseChild.py` automates the
  whole chain given a child-DA credential.

## Step 3 - Forest → forest
<!-- lab-requires: essos -->

- [ ] **MSSQL trusted link** castelblack→braavos - already present (part 7); the
  one-shot RCE is gated by the link's self-mapping. `see part 7`
- [ ] **SID-history golden ticket** (essos→sevenkingdoms) - we hold the essos
  krbtgt (part 6), so a golden ticket is forgeable offline, but the cross-forest
  abuse needs **SID history enabled on the trust** and a **privileged group with
  RID > 1000** (SID filtering drops RID < 1000 across a forest trust). mayfly adds
  both via a lab upgrade (dragonrider RID 1132 + SID history). Verify/toggle on
  our build. `⏳`
- [ ] **Unconstrained delegation** (WINTERFELL$) - enumerated in part 10; needs a
  Windows beacon + Rubeus monitor to capture a coerced DC TGT. `⏳`

## Verify the trust

`nltest /domain_trusts` on winterfell returns `SEVENKINGDOMS` (Forest Tree Root)
and `NORTH` (child, within-forest), and `Get-ADForest` returns exactly those two
domains. The child/parent WITHIN_FOREST trust is present, so Step 2 (child→parent
golden + extra-SID) has its target.
