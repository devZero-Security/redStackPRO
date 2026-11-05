# Changelog

All notable changes to redStackPRO are recorded here. The project uses semantic
versioning, and dates are UTC.

## [0.10.0] (2026-11-04)

### Added

- Azure is a supported provider and selectable in the canvas, alongside GCP and AWS.
  Validated live on Azure: the `minimalc2-cli` and full `redstack` offense stacks
  (Mythic, Sliver, and Adaptix teamservers, the collector, and the Windows and Kali
  operators) passed `verify.py doors` and `verify.py stack`, with Let's Encrypt on the
  redirector; the `minilab`, `goad-light`, and `goad-wazuh` defense ranges deployed
  clean and validated, including child domain promotion, the parent/child trust,
  MSSQL, and the Wazuh manager and agents. Full `goad` (both forests, the cross-forest
  trust, ADCS on ESSOS-CA, MSSQL) and `dracarys` (the KeePass vault, a Linux host
  joined to the domain) deployed clean and validated too. From an Azure offense range,
  a Sliver beacon launched as patient zero in full GOAD called back through the
  redirector, and the playbook checks for recon, AS-REP roasting, Kerberoasting, ADCS
  enumeration, and MSSQL impersonation ran through it.
- An Azure export builds each range as one resource group (`resource_group` in
  `deploy.tfvars`), in `eastus2` by default, with VNet peering, a NAT gateway per VNet
  for egress from private hosts, and Network Security Group rules. Ingress fails
  closed as on GCP and AWS: the deploy stops until `operator_source_ranges` is set.
  The Kali operator starts from a Debian 13 image that the operator role converts to
  Kali, so no Marketplace plan acceptance is needed.
- Azure VM sizes per role. The defaults are the AMD v5 family: `Standard_D2as_v5`,
  `Standard_D4as_v5` for the SIEM, and `Standard_B2as_v2` for workstations.
  `deploy.tfvars` ships a commented `vm_sizes` map listing the topology's roles, and a
  partial map overrides only the roles it names.
- An Azure preflight. Before apply, `deploy.sh` runs `azure_preflight.py`, which ships
  in the export and also runs alone as `python azure_preflight.py .`. It is read only
  and checks that each VM size is offered and not restricted for the subscription in
  the region, the regional and per-family vCPU quotas, the public IP quota, and that
  the needed resource providers are registered. On a problem it stops before anything
  is created and prints a `vm_sizes` block that fits, the quota to raise, or the
  `az provider register` command. If it cannot reach Azure it warns and the deploy
  continues. `REDSTACKPRO_SKIP_PREFLIGHT=1` skips it.
- Azure lifecycle. `manage.sh status`, `start`, and `stop` run through the Azure CLI;
  `stop` deallocates the VMs, which halts compute billing, and the jumpbox keeps its
  public IP. `manage.sh teardown --force` deletes the whole resource group with
  `az group delete`. Those four need `az` installed and logged in. `deploy.sh` works with either `az login` or a
  service principal in `ARM_CLIENT_ID`, `ARM_CLIENT_SECRET`, `ARM_TENANT_ID`, and
  `ARM_SUBSCRIPTION_ID`.
- Azure auto-stop, as a per-VM DevTestLab shutdown schedule (it needs
  `Microsoft.DevTestLab` registered, which the preflight checks). The schedule takes a
  Windows timezone id: common IANA names in the topology are translated, and any other
  IANA name is refused at compile.
- The generated DEPLOYMENT-GUIDE has a Quotas section for each cloud provider in both
  modes, and an Azure section on `vm_sizes` and the preflight.
- The validator checks every value against the topology schema (`SCH001`). A value
  that used to compile and then fail in Terraform or Ansible (a malformed CIDR,
  address, prefix, URI prefix or header name, an unknown option) now stops the
  export with a message that names the field and gives an example, and the Inspector
  marks that field.
- New validator checks: a subnet outside its network (`NET007`), a malformed domain
  FQDN or NetBIOS name (`DOM001`), the jumpbox certificate authority turned off while
  collector TLS, a Windows operator or OpenVPN needs it (`JMP002`), and Stop at plus
  Stop after in a timezone other than UTC (`STP001`) are errors. A jumpbox with no
  Guacamole portal (`JMP001`), C2 route ports or protocols the redirector does not
  serve (`FRT003`), recorded hardening (`HRD001`), external and tree root trusts
  (`TRU001`), ACL names or rights that do not resolve (`ACL001`) and services that
  nothing installs (`SVC001`) are warnings.
- Findings have an info severity, which never blocks an export: Windows 10 and 11
  boot Server 2022 on GCP and AWS (`CAP005`), and firewall and appliance hosts are
  not built (`SVC002`).
- With nothing selected, the Inspector shows Topology settings: auto-stop (on or
  off, Stop at a time or Stop after a number of hours, and the timezone, limited to
  the zones Azure can map when deploying to Azure), region, address range and
  description. A finding about the whole topology opens this panel.
- Structured editors in the Inspector:
  - Trusts: type, direction and transitive. A new trust is typed parent and child
    when one domain sits under the other, otherwise forest; external and tree root
    say they are not built yet.
  - Access rights: principal and target are picked from the domain's users, groups,
    computers and OUs, a name that does not resolve is flagged, a missing group can
    be added to the domain in one click, and the rights list holds only the rights
    that apply, each with its meaning.
  - gMSA accounts and group nesting, which used to show `[object Object]`.
  - Domain users show only the flaws that take effect, with Description, Password,
    SPNs, Delegate to and Weak password inputs where a flaw needs them.
  - Delegate to, on a user with constrained delegation and on a computer with
    constrained delegation (Kerberos only), is picked from the services the
    domain's Windows hosts run (CIFS, HTTP, HOST, LDAP on a DC, MSSQL where SQL
    Server runs), or typed by hand. Ticking the delegation fills in CIFS on the
    domain controller.
  - A range host's vulnerability settings are a form. Each ticked vulnerability
    lists the settings it reads, with a picker where a setting names a user, group,
    host, OU or SPN in the topology, written in the format its Ansible role expects:
    `DOMAIN\user` from any domain in the range, or the bare name where the role
    looks it up in its own domain. MSSQL linked servers are picked from the SQL hosts
    in any domain, and ticking the vuln fills in the other SQL hosts. Ticking Stored
    credential sets its target to `TERMSRV/` and the host's name. EXECUTE AS grants,
    linked server logins and planted files are edited as rows. The JSON editor stays
    below as Edit as JSON, in step with the form, for keys the form does not show.
  - The SPNs of a Kerberoastable user offer the domain's SQL Server and IIS service
    SPNs.
  - Every vulnerability setting has a plain label, with its `vulns_vars` key shown
    small beside it.
- Windows range hosts have a User activity section under Vulnerabilities: the
  logon bot, a scheduled task, the share-browsing bot, the relay bot and a saved
  credential, each written as one sentence with pickers. Ticking a line ticks its
  vulnerability, and the settings form points there instead of repeating the keys.
  The scheduled task offers what it does as a choice: stays logged on, runs a file,
  browses a share, fetches a web page, your own PowerShell or your own script. The
  canvas writes the PowerShell with safe quoting and reads an existing command
  back. On GCP, AWS and Azure the share-browsing and relay bots show disabled, with
  the reason.
- The DEFENSE-BRIEFING has a User activity table: each bot, who it runs as, what it
  does and how often, with the bots the provider cannot plant marked.
- `RNG011` names the missing `vulns_vars` key as its field, so the finding shows
  next to that input.
- A domain takes a `groups` list for groups that only an access right names. The
  GOAD blueprints list theirs, so the domain controller creates them up front.

### Changed

- The logon bot (`rdp_scheduler`) logs on every 3 minutes by default, where it was
  every minute, and the interval is set per host in `vulns_vars.bot_interval_minutes`,
  a number in its User activity sentence. A value that is not a whole number from 1
  up runs at the default, one over 31 days (Task Scheduler's limit) runs at 31 days,
  and the canvas says so under the sentence. The DEFENSE-BRIEFING's User activity
  table shows the interval.
- As on GCP and AWS, the broadcast and multicast poisoning techniques
  (`llmnr_poisoning`, `nbtns_poisoning`, `responder`, `ntlm_relay`,
  `ldap_signing_off`) are not planted on Azure, whose network drops L2 broadcast and
  multicast. They stay limited to Proxmox and ESXi.
- `--provider` on `redstackpro compile`, `redstackpro validate`, and
  `python -m redstackpro.tools.registry` is checked against the registry, case
  insensitive, and an unknown name lists the valid providers instead of ending in a
  traceback.
- `manage.sh status`, `start`, and `stop` check that the cloud CLI (`gcloud`, `aws`,
  or `az`) is installed first, and exit nonzero when the call fails on any instance.
- The Export panel and the export's DEPLOYMENT-GUIDE say to extract the download to
  its own folder and run every step from there (the key command writes to `keys/`
  relative to it), and list the cloud CLI as a requirement. With Deploy from set to
  Windows, they give the `winget` command that installs it for Windows; on macOS and
  Linux, a link to its install steps.
- `deploy.sh` prints the AWS IAM note for any auto-stop, `after_hours` included, not
  only a fixed `at`.
- The `auto_stop.after_hours` schema description is corrected: the stop time counts
  from the first apply and is kept in Terraform state, so a re-apply does not move it.
  Only recreating the range, or replacing `time_offset.auto_stop`, does.
- The README and wiki say the AWS Kali Marketplace subscription is once per account,
  not per region.
- Security reports go to GitHub issues, and `SECURITY.md` is removed.
- The Inspector labels fields and options in words (Public address, Windows Server
  2019, Let's Encrypt) while the stored values stay the same. An empty select names
  what it compiles to, such as "default (Windows Server 2022)". `public_address`
  is a checkbox and ports are number inputs. Fields that do nothing on the selected
  node are hidden, and a stored value on such a field is shown with the reason.
  A value that misses its format shows red as you type.
- Jumpbox services offer SSH and Guacamole. The VPN server follows Access mode
  alone, and a defense jumpbox runs none. Member server services are a checklist of
  what a role installs, and the role select says what the chosen role installs.
- The hardening picker is read only and says the controls are recorded but not
  deployed, since no role applies them yet. A host with recorded hardening shows
  "hardening off" on the canvas, and goad-wazuh's ws01 no longer claims hardening.
- The palette no longer offers Firewall and Appliance, which were never built.
  Topologies that already have them still open.
- Domain controllers and servers dropped from the palette start as Windows Server
  2022 and workstations as Windows 11, a jumpbox starts with the Guacamole portal,
  and the File Server preset plants an open SMB share.
- The certificate source `provided` and the Splunk collector sink and SIEM product
  are removed. None of them could deploy: there was no way to supply the
  certificate or the Splunk download.
- A KeePass vault with no master password is an error, since it fails the host's
  provisioning.
- The Export panel lists the `deploy.tfvars` fields to set for the selected
  provider, shows the login command to run, and opens `deploy.tfvars` first.
- `deploy.tfvars` explains each value and where to find it. `deploy.sh` stops
  early on an empty GCP project, an empty Azure subscription, or a zone outside its
  region, and suggests your public IP when `operator_source_ranges` is unset.
- The DEPLOYMENT-GUIDE says when the range stops itself and how to change it, what
  to confirm for the provider, and how to enable the GCP Compute Engine API.
- The deploy needs Python 3.8 or newer on your machine, and the guide, README,
  wiki and Export panel now all say so. Ansible runs on the jumpbox. Running
  redStackPRO from source still needs 3.11.
- An Azure range's resource group defaults to `{prefix}-{topology name}-rg`, and
  the preflight stops when that group already exists outside this range's state.
- The DEFENSE-BRIEFING shows Defender as off unless `defender_enabled` is set, and
  marks vulns the target provider cannot carry. Blueprint descriptions say poisoning
  plants on Proxmox and ESXi only.
- The prefix field accepts 1 to 8 lowercase letters or digits starting with a
  letter and explains the 15 character limit. The topology name field has a
  placeholder, and an emptied name or prefix goes back to its previous value. The
  line role picker and Connections offer only the lines two nodes can carry, with
  plain labels and full host names.
- Stop after (`auto_stop.after_hours`) is scheduled in UTC, so the range stops the
  given number of hours after apply whatever timezone the topology names.
- The deploy target is saved with the topology (`provider`) and comes back on
  reload, and the Download button names it.
- GOAD extensions follow the blueprint a topology started from (`blueprint`), so
  renaming it or saving a copy keeps them available.
- The canvas legend uses the Inspector's line names, and info findings are counted
  and listed apart from warnings.
- The palette and the side panel can be dragged wider or narrower from their inner
  edge (double-click resets, arrow keys work on a focused handle), and the widths
  are kept in the browser. Both open at their widest, scaled down on a narrower
  screen so the canvas keeps at least 480 pixels. Inspector and Export share one
  width, so switching tabs no longer resizes the panel.
- The header wraps onto a second row when its controls do not fit, where it used to
  push the whole page into a sideways scroll.
- `deploy.sh` output is laid out to be followed at a glance. It opens on a title box
  naming the topology, provider and region, prints numbered phases (`[1/7]` to
  `[7/7]`, or eight on Azure with the preflight first) that each end on an `ok` line
  with a short result, and ends on a `DONE` box (portal, logins command, the ssh line
  to watch provisioning, the expected time, the log path) or a `FAILED` box naming
  the phase, the reason and the exit code. Terraform's output is unchanged, and so
  are the exit codes. Run from `deploy.ps1`, the box writes Windows paths
  (`keys\id_ed25519`).
- The deploy log ends on `result: ok` or `result: FAILED (exit N) in phase ...`, so a
  log attached to an issue records how the run ended. The version and system header
  goes to the log only.
- `~/provision/run.log` on the jumpbox gives each stage a heading, leaves out skipped
  hosts and task banners with nothing else under them, marks failed tasks with `!!`,
  and ends on `RUN EXITED` followed by the last PLAY RECAP line for every host. Every
  line Ansible printed is in `~/provision/run-full.log`. The `RUN EXITED ok=<0|1>`
  and `PLAYBOOK SUCCEEDED` lines are still there for anything that greps for them.
- Noise removed from the deploy: the debconf frontend warnings (sudo dropped
  `DEBIAN_FRONTEND`), pip's warnings that `~/.local/bin` is not on PATH, one
  `filled ...` line per inventory file (now one count line; `python tf_inventory.py`
  still lists the files), the Azure preflight table on a pass (now one summary line;
  `python azure_preflight.py .` prints the table), tar's "time stamp in the future"
  warnings, and "No screen session found." on a first deploy.
- A new workstation (`wks`) defaults to Windows 11: the canvas seeds `windows_11`,
  and a workstation with no `os` compiles to it (a `dc` or `srv` stays Windows Server
  2022). GCP and AWS still boot Windows Server 2022 for it (`CAP005`). On Azure that
  is the `windows-11` Marketplace image, release `win11-26h2-pro` (the 23H2 SKU the
  earlier mapping named is no longer offered).
- Windows 10 is marked past end of support (Microsoft ended it on 2025-10-14). The
  Inspector lists it as "Windows 10 (past end of support)" with the date under the
  picker, and a host set to `windows_10` on Azure, Proxmox or ESXi gets an info note
  (`CAP006`) that never blocks an export. The stored values are unchanged.
- The shipped blueprints' Windows 10 workstations are Windows 11: `ws01` in
  `goad-wazuh`, `ws` in `minilab`, `client` in `sccm` and `fr-wks01` in `harbor`, and
  the ws01 extension's workstation. Their solution pages say so.
- On Azure, the DEPLOYMENT-GUIDE (when the topology has a Windows 10 or 11 host) and
  the README note that Microsoft licenses Windows client VMs on Azure only for
  customers with a qualifying license, and that redStackPRO does not set
  `license_type`, so license eligibility is the user's to confirm.
- `manage.sh` and `manage.ps1` with no command, `help`, `-h` or `--help` print a help
  screen for the export: the range name, provider, region and resource group, GCP
  project or AWS profile (read from `deploy.tfvars`), each command and what it does on
  that provider (what still bills after `stop`, what `teardown --force` deletes
  first), the auto-stop schedule, and the CLI and login it needs. Usage and examples
  are written as `.\manage.ps1` when run from PowerShell and `bash manage.sh`
  otherwise. An unknown command or option prints the screen and exits 1. On Proxmox
  and ESXi it says only `teardown` is available.
- `teardown` shows what it is about to delete and asks for the range name (or `yes`)
  first, and any other answer deletes nothing. `--yes` skips the question, in either
  order with `--force`. `manage.ps1` asks with Read-Host. `manage.sh` asks only on a
  terminal; without one and without `--yes`, it stops and deletes nothing, so a
  script cannot hang on the question.
- `manage.sh status` prints one table for the range (one `az vm list` or
  `gcloud compute instances list` call) instead of a table per VM. AWS `status`,
  `start` and `stop` pass the region from `deploy.tfvars`, so a different AWS CLI
  default region no longer misses the instances.
- `deploy.sh` and `manage.sh` share one look. Both open on a redStackPRO wordmark
  (`deploy.sh` and the `manage.sh` help) and a title box with the range name,
  provider, region and resource group, project or profile. The help lists COMMANDS
  and EXAMPLES in sections, wraps descriptions to the box width and never splits a
  command in parentheses. `status`, `start`, `stop` and `teardown` open on the same
  box (`status` shows the portal address in it), `teardown` steps print like deploy
  phases, and teardown ends on a `DONE` or `FAILED` box.
- Colour on the terminal: red rules and wordmark, bold phase lines, green `ok` and
  `DONE`, red `FAILED` and failure reasons, yellow notes and warnings, cyan commands.
  It is on when the output is a terminal, or when `deploy.ps1` or `manage.ps1` see a
  console that renders it. `NO_COLOR` turns it off, and output to a file or a pipe
  gets none. The deploy log stays plain text.

### Fixed

- The deploy log held terraform's colour escape codes (over a thousand lines of
  them in a plan of about 50 resources). `deploy.sh` now writes the log through a
  filter that removes escape codes, so the file attached to an issue reads as text.

- `manage.ps1 status`, `start` and `stop` work from Windows on Azure and GCP. Python
  and gcloud on Windows end lines with `\r\n`, and Git Bash kept the `\r` on each VM's
  resource group or zone, so every call failed (Azure answered Bad Request). The GCP
  `teardown --force` sweep had the same fault and failed silently.
- The stored credential (`stored_credential`) is planted. The plant script was written
  by the admin account into `C:\Windows\Temp`, which the vault owner's scheduled task
  could not read, so no credential was ever saved and the role still reported a
  change. The owner is now granted read on the script, the task fails if the
  credential was not saved, and the script, which holds the password, is deleted.
- Windows 10 and 11 workstations on Azure, Proxmox and ESXi ran none of their user
  activity bots (the logon bot, the scheduled task, the poisoning bots), and the stored
  credential was never saved. A client edition of Windows starts a user's scheduled
  task only after someone has signed in at the console since boot, and on a VM nobody
  does. The host's bot user is now signed in at the console at every boot, with the
  password kept as an LSA secret rather than in the Winlogon registry key, and the host
  reboots once when that is first set. The DEFENSE-BRIEFING and the canvas list the
  sign-in for that host. Server editions, and GCP and AWS workstations, which boot
  Windows Server 2022, are unchanged.
- SMBv1 (`smbv1`) is on after the deploy. Enabling the feature needs a reboot before
  the server offers the dialect, and the role never rebooted. It now reboots when the
  server still reports SMBv1 off.
- The downloaded zip stamps its files with the browser's local time. The server
  clock is UTC in the Docker image and unzip reads zip times as local time, so files
  extracted in a US timezone were hours in the future. The jumpbox also extracts the
  Ansible tree with `tar -m`, so the file times on the operator's machine no longer
  matter there.
- `manage.ps1` forwards every argument to `manage.sh`, so
  `.\manage.ps1 teardown --force` works on Windows.
- `verify.py stack` reaches a defense range's jumpbox at its public address rather
  than its private one.
- `verify.py stack` finds the SSH key where `deploy.sh` does (`--key` or
  `REDSTACKPRO_SSH_KEY`, then the one key in `keys/`, then `~/.ssh/id_ed25519`), and
  when SSH cannot get in it says so once instead of reporting every check as failed.
- Windows hosts whose image ships a .NET Framework older than 4.8 (Azure's Windows
  Server 2019 ships 4.7.2) get 4.8 installed before chocolatey, which needs it, on the
  MSSQL and KeePass vault paths.
- A failed MSSQL install names the missing service in its error again. A PowerShell
  variable had shadowed the service name.
- `rsp-launch-beacon`, the headless patient-zero launch on a range jumpbox, works for
  a Domain Users patient zero. It grants that user batch logon and read on the staged
  beacon, which a scheduled task needs, and fails with the task's result when the
  beacon does not start. Before, it reported success with nothing running.
- The jumpbox's Guacamole schema check retries through the Postgres container's
  first-start restart instead of failing the jumpbox play on "database system is
  shutting down".
- An export's static module read refuses a provider name that is not a bare name, so
  it can never read outside the bundled module tree.
- The `deploy.sh` refusal for a stop time too close to the build names `auto_stop.at`,
  the only setting it applies to, instead of saying to recompile.
- A ticked host vuln that would plant nothing now raises a validator warning:
  one declared where no role plants it (`RNG010`, e.g. `constrained_delegation` on a
  host instead of a user), one missing a required `vulns_vars` key (`RNG011`, e.g.
  `constrained_delegation_kerberos` with no `delegate_to`), and a `vulns_vars` that is
  not a JSON object (`RNG012`). The Inspector edits `vulns_vars` as JSON, where it
  used to show `[object Object]` and save typed text as a string, and lists under it
  the keys each ticked vuln reads, required or optional, with an example.
- A domain controller, server or workstation with no OS set was built as Windows
  but provisioned as Linux. It now builds and provisions as Windows: Server 2022,
  or Windows 11 for a workstation.
- A host with no hostname uses its node id, and a domain with no NetBIOS name uses
  its first DNS label, uppercased. A domain controller with no hostname used to fail
  at the rename step.
- A trust with no type built nothing. It now becomes parent and child when one
  domain sits under the other, otherwise forest. A child domain promotes into its
  parent whichever way the line was drawn, a trust with no direction is two way
  (it used to build one way only), and forest trusts honour an inbound direction.
- Firewall and appliance nodes no longer stop provisioning of the whole range. Their
  Ansible roles did not exist; they are now left out, and the briefing lists them as
  not built.
- The access rights ForceChangePassword and AddMember were skipped at apply. They
  now map to rights the script applies, as does WriteSPN.
- The account flaws password in description and reversible encryption take effect,
  kerberoastable accounts use their own SPNs, disabled accounts stay disabled, and
  re-running a constrained delegation account no longer fails.
- nha plants its linked server and harbor plants its stored credential. The stored
  credential task grants its owner batch logon first, which a Domain Users owner
  needs for the task to run.
- Loading a shipped blueprint no longer renames its hosts (redStack's `ops-sub01`
  became `mgmt-sub02`) or marks it unsaved.
- Stop after with a timezone other than UTC fired at the UTC clock time read in that
  timezone, hours off the requested stop.
- A comma typed into a list field was deleted, so a second entry could only be
  pasted.
- A box on the canvas with contents but no stored size was drawn at least 420 by
  260, so in dracarys, minilab, nha and sccm a domain covered the jumpbox or the
  domain below it. Such a box now fits its contents; an empty one keeps the larger
  size as a drop target.
- The bots that run as a domain user (the logon bot, the scheduled task, the
  share-browsing bot and the relay bot) grant that user Log on as a batch job before
  creating their task. An ordinary domain user lacks that right, so the task never
  ran, and nothing reported it.
- The scheduled task bot's default task name is `schedule_bot`. It shared
  `connect_bot` with the logon bot, so a host with both kept only one.
- The `deploy.sh` check that a build has time to finish before its auto-stop
  measured to the stop time in UTC on Windows. Python there has no timezone
  database unless `tzdata` is installed, and the check read any IANA zone as UTC,
  so a deploy at 12:34 New York time with an 18:00 `America/New_York` stop was
  refused as 25 minutes away. The export now carries the zone's UTC offset, taken
  at export, and the check uses it when Python cannot load the zone. redStackPRO
  depends on `tzdata`, so the compiler can always resolve the zone.
- A deploy started with `deploy.ps1` printed its override and recovery commands in
  bash form (`REDSTACKPRO_MIN_STOP_LEAD=0 bash deploy.sh`,
  `bash manage.sh teardown --force`), which fail at a PowerShell prompt or run WSL's
  bash. From `deploy.ps1` they are now written for PowerShell
  (`$env:REDSTACKPRO_MIN_STOP_LEAD = '0'; .\deploy.ps1`,
  `.\manage.ps1 teardown --force`), the Azure preflight's override included, and
  each sits alone on its own line.
- The `DONE` box split the command that watches provisioning over two lines, so a
  user who copied the first line got an interactive ssh session and then ran
  `tail -f` in PowerShell. It is now one line,
  `ssh -i keys\id_ed25519 blueop@<jumpbox> "tail -f ~/provision/run.log"`, with the
  key path in the form of the shell the deploy ran from. Every command the deploy
  prints, in the `DONE` box and in the reasons it stops (the cloud sign-in, an empty
  `project` or `subscription_id`, a missing key, an unregistered Azure provider),
  sits alone on its own line under a label ending `run:`.
- `manage.sh teardown --force` on GCP and AWS deleted every redStackPRO instance in
  the project or region, so a team running several ranges there lost all of them.
  Every GCP and AWS instance now carries a `redstackpro_deploy` label or tag, a
  random id Terraform keeps in that deployment's state, and the sweep deletes only
  the instances in this deployment's state and those carrying its id, which still
  finds one an interrupted apply created but never recorded. With no state it
  deletes no instance. The help screen, the teardown summary and the
  DEPLOYMENT-GUIDE say so.

## [0.9.2] (2026-11-04)

### Fixed

- Leaving `ssh_public_key` empty in `deploy.tfvars` now works, as 0.9.1 described.
  The derived key was exported as a `TF_VAR_` environment variable, which Terraform
  ranks below the copied `terraform.tfvars`, so the empty value won and the run
  stopped at variable validation. The derived key is now written to
  `terraform/zz-derived.auto.tfvars`, which Terraform loads last, and the file stays
  so a later teardown still has it.
- The tagged 0.9.1 source predates the redirector DNS reminder fix listed under
  0.9.1 (the published 0.9.1 image carried it). 0.9.2 carries it in both.
- The Kali operator role installs `gnupg` before adding the Kali apt repository, so it
  provisions on a minimal Debian base that ships without it.

### Changed

- Azure provider work toward a later release: VNet peering, the offense firewall
  rules, NAT gateway egress, fail-closed ingress, a credential preflight that accepts
  `az login` or a service principal, `manage.sh` status/start/stop and
  `teardown --force` on Azure, Gen2 Windows images, and IANA timezones for auto-stop.
  Azure is still preview and not selectable in the canvas.
- The generated DEPLOYMENT-GUIDE covers recovering from an interrupted deploy with
  `manage.sh teardown --force`.

## [0.9.1] (2026-10-03)

### Fixed

- The redirector DNS reminder no longer aborts the deploy. It resolves the cover
  hostname to compare against the new public IP; on a name that does not resolve yet
  (the normal first deploy) that lookup failed under `set -e` and killed the run right
  after apply. The lookup is now guarded, so the deploy continues and prints the A
  record to set.
- Jumpbox SSH no longer stalls on a fresh deploy. A new jumpbox answers port 22
  before cloud-init writes the operator key, so the key was briefly refused and ssh
  dropped to a password prompt. SSH is now non-interactive (BatchMode) and the
  connection retries until cloud-init finishes. (#2)
- SSH key permissions on Windows drives. A key on a WSL-mounted drive reports 0777,
  which StrictModes rejects, dropping the deploy to password auth. The deploy now
  connects with a 0600 copy on a real filesystem, and skips that copy on Git Bash.
- deploy.sh now stops at the real error when a step fails. It had no top-level
  `set -e`, so a failed `terraform apply` ran on and ended on a misleading "unfilled
  address placeholders remain"; it now aborts at the failure with its own message,
  and empty terraform outputs no longer provision a blank credential or an empty host.
- Interrupting a deploy no longer leaves instances teardown cannot remove.
  `manage.sh teardown --force` sweeps the range's instances (ones an interrupted
  apply created but never wrote to state) so `terraform destroy` can finish.

### Changed

- deploy.sh derives `ssh_public_key` from your private key when the tfvars field is
  left empty, so you no longer copy the public half in by hand.
- `operator_source_ranges` now ships unset and fails closed (it was `0.0.0.0/0`); the
  deploy stops until you set it, so a range is never exposed by default.
- AWS deploys check credentials (`aws sts get-caller-identity`) before apply and flag
  Elastic IP / vCPU quota and the Kali Marketplace subscription up front, rather than
  failing late.

### Added

- `verify.py` ships at the root of every export. `python verify.py doors .` checks
  the redirector front doors from outside, `python verify.py stack .` checks the
  range over SSH from the jumpbox, and `--plan` lists the checks without running them.
- `rsp-check`, an on-box redirector check at `/usr/local/sbin/rsp-check`
  (`sudo rsp-check`), confirms the C2 path from the redirector itself.
- The generated `OFFENSE-BRIEFING.md` now carries the C2 payload recipe: callback
  domain, gating header, and URI-prefix route per redirector.
- The canvas shows the running server version under the wordmark, read from the
  API health endpoint.

### Thanks

- V.S., for the deploy logs and reports behind the SSH fixes.

## [0.9.0] (2026-09-28)

Initial public release.
