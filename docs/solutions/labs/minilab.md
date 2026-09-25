# minilab coverage

A single domain, two Windows hosts. Small, but **not** a subset of goad: it is
the only small lab built around CredSSP and scheduled task abuse, and goad never
exercises either.

## What is in it

- Domain: `mini.lab`
- `dc` - DC, `stored_credential`, `schedule`, `enable_credssp_client`
- `ws` - Windows 10 workstation, `enable_credssp_server`
- `jumpbox` - ssh, Guacamole, wireguard

## Part mapping

| goad part | applies | why |
|-----------|---------|-----|
| 1 recon | yes | |
| 2 find users | yes | |
| 3 enumeration with user | partial | no user carries an SPN, so the kerberoasting step has no target |
| 4 poison and relay | no | no poisoning vulns set |
| 5 exploit with user | partial | `stored_credential` only |
| 6 ADCS | no | no ADCS |
| 7 MSSQL | no | no MSSQL |
| 8 privilege escalation | no | no IIS or writable share |
| 9 lateral move | yes | dc to ws, and the CredSSP pair below |
| 10 delegations | no | |
| 11 ACL | no | two ACL edges, but both are anonymous-read grants, see below |
| 12 trusts | no | single domain |
| 13 having fun | no | |
| 14 ADCS advanced | no | |

## Delta: 4 techniques goad does not cover

These have no page in the GOAD series, so they are the reason this lab exists.

### `enable_credssp_client` (dc) and `enable_credssp_server` (ws)

CredSSP delegates the caller's **plaintext** credentials to the target so the
target can act as them on a third host. That is what makes it a lab technique:
the credential lands in memory on the receiving host, where it can be recovered.

Validate as a pair, not individually. The client side is the host permitted to
delegate, the server side is the host permitted to receive. Confirm the policy
actually landed rather than trusting the role:

- client: `Get-Item WSMan:\localhost\Client\Auth\CredSSP` reports `true`, and the
  `AllowFreshCredentials` policy names the intended target
- server: `Get-Item WSMan:\localhost\Service\Auth\CredSSP` reports `true`
- end to end: a CredSSP authenticated session from dc to ws succeeds, and the
  delegated credential is recoverable from LSASS on ws

### `schedule` (dc)

A scheduled task abuse primitive. Confirm the task exists, note the principal it
runs as and who can modify it, then take the escalation only if the task's ACL
actually permits a lower privileged identity to rewrite its action.

### `stored_credential` (dc)

Shared with goad part 5. Credentials in the Windows Credential Manager,
recoverable without touching LSASS.

## Audited against the template (2026-09-14)

Every row above was recomputed from `minilab.json` after the same hand-written
tables were found wrong on goad-light, goad-mini and nha. Two notes came out of
it; the table is otherwise correct.

**11 ACL stays "no", and the reason is worth recording.** The lab does plant two
ACL edges, but both grant `NT AUTHORITY\ANONYMOUS LOGON` read over the domain
root. That configures anonymous LDAP enumeration, which is part 2 material - it
is not an escalation part 11 can walk, because there is no principal to become.
A first pass of the audit counted any ACL edge at all and wrongly credited this
lab with an ACL chain; `lab_targets` now ignores grants to the anonymous and
everyone principals, guarded by a test.

**5 exploit with user stays "partial".** The lab holds `stored_credential` and
none of the other four techniques that page covers. The extractor calls the part
"yes" because those sections carry no marker, and an unmarked section is always
kept - deliberately, so a missing marker shows a reader too much rather than
deleting a step. The hand-written "partial" is the more useful answer here, which
is why it was kept rather than machine-matched.

## Stand-up gate

Compile clean, one pass `RUN EXITED ok=1`, portal and foothold on the jumpbox.
Then confirm both CredSSP sides landed, since a silently missing WSMan policy is
the failure this lab is most likely to hide.
