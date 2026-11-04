# Changelog

All notable changes to redStackPRO are recorded here. The project uses semantic
versioning, and dates are UTC.

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
