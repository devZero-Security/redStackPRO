# goad-wazuh coverage and detection

goad-wazuh is a two-domain GOAD cut with a **Wazuh SIEM** and agents on the
Windows AD hosts. Its attack surface overlaps goad, so the [GOAD series](../goad/README.md)
covers the offense. What makes this lab its own is the **detection axis**: for
each technique, does it actually show up in Wazuh with the shipped config? That
is a question goad's solution never asks, and it is the reason this lab earns
a page instead of a pointer.

## What is in it

- Domains: `sevenkingdoms.local`, `north.sevenkingdoms.local`
- `kingslanding` - DC, Wazuh agent, `forcechangepassword`, `genericwrite`, `writedacl`, `ldap_signing_off`
- `winterfell` - DC, Wazuh agent, `kerberoasting`, `asreproasting`, `unconstrained_delegation`, `llmnr_poisoning`, `ldap_signing_off`
- `castelblack` - member (MSSQL + IIS), Wazuh agent, `iis_webshell`, `mssql_impersonation`, `gpp_password`, `password_in_description`, `weak_password`
- `ws01` - Windows 10 workstation, Defender
- `wazuh` - the SIEM (Ubuntu)
- `jumpbox`

## Telemetry the shipped config actually collects

This is the honest baseline, and it bounds every detection below. The
`siem_agent` role installs the **Wazuh agent with its default `ossec.conf`**,
which reads the Windows **Security, System, and Application** event channels and
applies Wazuh's built-in ruleset. It does **not**:

- install **Sysmon** (no process-creation, network-connection, image-load, or
  named-pipe telemetry beyond what the Security log carries), and
- enable **command-line / process-creation auditing** (Event ID 4688 with the
  command line is off, so process-level detections are blind).

So with the agent alone, detections rest on the **native Security log** (logons,
Kerberos service tickets, account and group changes) plus Wazuh's default rules.

**The `endpoint_telemetry` toggle closes this.** goad-wazuh sets it on its three
Wazuh-monitored hosts, so they install **Sysmon** and turn on **command-line
(4688)** and **directory-service (5136)** auditing at deploy. That is what moves
the *blind* rows below into range: process-level techniques and ACL abuse become
visible once Sysmon and the audit policy are on. A host without the toggle keeps
the quiet native-log-only baseline. The toggle is off by default (a plain lab
stays quiet); see the host overlay field `endpoint_telemetry`.

## Technique to detection map

Visibility with the shipped config: **good** (a native Security event Wazuh rules
on), **partial** (an event exists but needs auditing that is off by default, or
is noisy), **blind** (no host telemetry without Sysmon / 4688 / DS-access
auditing).

| technique | host | primary evidence | shipped visibility | what closes the gap |
|-----------|------|------------------|--------------------|---------------------|
| Kerberoasting | winterfell | 4769 TGS request, RC4 (0x17) for an SPN account | good | Wazuh rules on 4769; alert on RC4 + non-machine target |
| AS-REP roasting | winterfell | 4768 AS-REQ with pre-auth not required | good | rule on 4768 pre-auth flag |
| Weak / sprayable password | castelblack | burst of 4625 / 4771 across accounts | good | Wazuh brute-force / auth-failure correlation |
| ForceChangePassword | kingslanding | 4724 password-reset attempt | partial | 4724 is logged; alert when the actor is not a helpdesk principal |
| WriteDACL / GenericWrite | kingslanding | 5136 directory object modified | blind | needs **DS-access auditing** (off by default) |
| GPP cpassword | castelblack | SYSVOL file read of Groups.xml | blind | SYSVOL object-access auditing, or detect the decrypt off-host |
| Password in description | castelblack | LDAP read of the description attribute | blind | no native per-attribute read event; needs LDAP-tier logging |
| Unconstrained delegation abuse | winterfell | 4624/4769 around TGT capture | partial | subtle; correlate delegation logons |
| LLMNR poisoning | winterfell | none on the victim host | blind | network detection; a host sensor / Sysmon 22 (DNS) helps |
| IIS web shell | castelblack | child process of w3wp | blind | needs Sysmon 1 / 4688 command line |
| MSSQL impersonation | castelblack | SQL audit (not Windows) | blind | SQL Server audit to Wazuh |

## How to validate detection (when run live)

For each technique that is **good** or **partial**: run the attack from the GOAD
series against goad-wazuh, then confirm the expected event reached Wazuh and, if
a rule exists, fired an alert. Record PASS (alert fired), LOGGED (event arrived,
no alert), or BLIND (nothing), and note anything that would need Sysmon or an
audit-policy change. The **blind** rows are expected to stay blind with the
shipped agent config; they are the evidence for shipping Sysmon + auditing, not
failures of the lab.

## What has actually been verified live (2026-09-09, GCP range project)

The table above is a *prediction*. This section records what a live deploy proved,
so the two are never confused. Everything here is from a converged goad-wazuh with
`endpoint_telemetry` on its three Wazuh hosts.

**The telemetry pipeline works end to end.** Three questions, deliberately checked
separately, because passing one says nothing about the others:

1. *Planted* - `Sysmon64` service Running, the Sysmon operational log carrying
   events, `auditpol` reporting Process Creation "Success and Failure" and
   Directory Service Changes "Success", and `ProcessCreationIncludeCmdLine_Enabled
   = 1`. So 4688-with-command-line and 5136 auditing really are on.
2. *Agents connected* - all four (ws01, castelblack, kingslanding, winterfell)
   reported `Active` by `agent_control -l`.
3. *Events arriving at the manager* - 1458 alerts, of which `36x 4688`, `20x 4634`,
   `10x 4624`, `4x 4672`, plus 4 Sysmon-channel alerts.

**One detection row is confirmed, not predicted.** Five real failed logons were
generated against sevenkingdoms, and the manager recorded **5x event 4625** with the
rule firing `"Logon Failure - Unknown user or bad password"`. So the
*Weak / sprayable password* row is PASS: event arrived AND an alert fired.

**Still predicted, not proven.** 4769 (Kerberoasting) and 4768 (AS-REP) need an
actual roast, which needs the attack tooling from the GOAD series rather than a
credential check; that is the P0 solution arc. Their absence on a freshly
deployed lab is expected and is not evidence of a gap.

**A methodology note worth keeping.** The first pass of this verification reported
zero events for every ID, because the query matched `"id":"4688"` while Wazuh's
field is `eventID`. The pipeline was working the whole time. When a detection check
returns nothing, suspect the check before the pipeline, and give it a control that
is known to produce a hit.

## Coverage vs goad

### Which offense parts apply

This page had no part mapping, so a reader had to infer it. Computed from
`goad-wazuh.json` (2026-09-14) with the same extractor the generated labs use,
not verified live:

| goad part | applies | why |
|-----------|---------|-----|
| 1 recon | yes | six hosts across two domains |
| 2 find users | yes | |
| 3 enumeration with user | yes | kerberoasting and AS-REP are both planted |
| 4 poison and relay | yes | `llmnr_poisoning` on winterfell |
| 5 exploit with user | no | none of the five credential-material techniques are set |
| 6 ADCS | no | no CA and no ESC template |
| 7 MSSQL | partial | `mssql_impersonation` on castelblack; no linked server, so the cross-forest hop drops |
| 8 privilege escalation | yes | `iis_webshell` on castelblack |
| 9 lateral move | yes | four Windows hosts |
| 10 delegations | yes | `unconstrained_delegation` on winterfell |
| 11 ACL | yes | the full sevenkingdoms chain, twelve edges |
| 12 trusts | partial | parent and child, so the child-to-parent hop applies; no second forest |
| 13 having fun | no | no writable share or open share |
| 14 ADCS advanced | no | no CA |

The detection axis above is what makes this lab its own; this table is just so
the offense half is not left implicit.

The offense is covered by the [GOAD series](../goad/README.md). goad-wazuh models
kerberoasting and AS-REP roasting as **host vulns** where goad models them as
**user flaws**; both reach the same attack. It adds ACL abuse
(`genericwrite`/`writedacl`/`forcechangepassword`) and credential exposure
(`gpp_password`, `password_in_description`) not central to goad-mini/light. See
the [coverage README](README.md) for the two-dimension surface count.

## Stand-up gate

Compile clean, one-pass `RUN EXITED ok=1`, portal and foothold on the jumpbox,
plus: the Wazuh manager is up and every Windows agent shows **Active** in the
Wazuh agent list. An agent stuck Disconnected means no detection is possible,
so that check gates the detection work above.
