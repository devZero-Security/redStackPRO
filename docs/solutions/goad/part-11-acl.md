# GOAD Part 11 - ACL abuse (redStackPRO)
<!-- lab-requires: acls -->

Reference: [mayfly - GOAD part 11](https://mayfly277.github.io/posts/GOADv2-pwning-part11/).
The sevenkingdoms ACL killchain (tywin → … → kingslanding), plus GPO abuse and
LAPS, driven **through the hodor beacon's SOCKS proxy** (`proxychains -q` in
front of the impacket/bloodyAD/dacledit calls; the DC is internal, see
[part 1](part-01-recon.md) Step 1).

> **Status legend:** ✅ PASS · ❌ blocked · ⚠ partial · ⏳ not run.

## Headline result

**The ACL edges exist and the write-primitives work; two infra items gate the
full chain from the Linux foothold** (both known: kingslanding LDAPS, and the
RC4 etype from part 3). The relations are present - a Windows beacon or the
essos-style working LDAPS completes the chain.

| Primitive | Result |
|-----------|--------|
| dacledit read (enumerate ACEs) | ✅ |
| ForceChangePassword (tywin → jaime) | ✅ password reset |
| GenericWrite → add SPN (jaime → joffrey) | ✅ edge works |
| GenericWrite → targeted kerberoast TGS | ❌ `KDC_ERR_ETYPE_NOSUPP` (RC4, see part 3) |
| GenericWrite → shadow creds (sevenkingdoms) | ❌ kingslanding LDAPS reset |
| WriteDacl / WriteOwner (dacledit / owneredit) | ✅ tools present, edges enumerable |
| LAPS read | ➖ legacy `ms-Mcs-AdmPwd` not in schema |

## Verified edges

- [x] **dacledit read** shows tywin holds an object-ACE on jaime (chain entry
  present). `✅`
- [x] **ForceChangePassword tywin → jaime**: `changepasswd.py … -reset -altuser
  tywin.lannister -altpass powerkingftw135` → *"Password was changed
  successfully."* `✅`
- [x] **GenericWrite jaime → joffrey**: adding a `servicePrincipalName` to
  joffrey over LDAP (as jaime) succeeds. `✅` The write works - the ACL edge is
  real.

## Blocked from the Linux foothold (not ACL failures)

- [ ] **Targeted kerberoast** on joffrey → `KDC_ERR_ETYPE_NOSUPP`: the KDC won't
  issue an RC4 (`$krb5tgs$23`) ticket for a non-pinned account (same modern-KDC
  behavior fixed for the designated roastable accounts in
  [part 3](part-03-enumeration-with-user.md)). `❌`
- [ ] **Shadow credentials** (certipy, which needs LDAPS to write
  `msDS-KeyCredentialLink`) fails on **kingslanding** with `socket ssl wrapping
  error / Connection reset`. Essos LDAPS worked in [part 6](part-06-adcs.md), so
  this is a **per-DC LDAPS issue on the sevenkingdoms DC**. `❌`

## Not covered here

- [ ] Remainder of the chain (add-self/add-member on groups, WriteOwner →
  kingsguard → stannis → GenericAll on kingslanding → RBCD/silver-ticket) - the
  primitives are available; RBCD-to-kingslanding was already shown in
  [part 10](part-10-delegations.md). `⏳`
- [ ] **GPO abuse** (north, samwell) with pyGPOAbuse - tool not staged. `⏳`

## GOAD-Light applicability

All of the ACL killchain objects are sevenkingdoms objects, so this part applies on
GOAD-Light as well. The edges read off the live objects match the documented chain,
and the blocked items are infra and etype constraints, not ACL failures.
