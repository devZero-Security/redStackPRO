# Changelog

All notable changes to redStackPRO are recorded here. The project uses semantic
versioning, and dates are UTC.

## [0.9.1] (2026-10-03)

### Fixed

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
