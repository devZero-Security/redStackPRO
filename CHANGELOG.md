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

### Changed

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
- `deploy.sh` prints the AWS IAM note for any auto-stop, `after_hours` included, not
  only a fixed `at`.
- The `auto_stop.after_hours` schema description is corrected: the stop time counts
  from the first apply and is kept in Terraform state, so a re-apply does not move it.
  Only recreating the range, or replacing `time_offset.auto_stop`, does.
- The README and wiki say the AWS Kali Marketplace subscription is once per account,
  not per region.
- Security reports go to GitHub issues, and `SECURITY.md` is removed.

### Fixed

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
