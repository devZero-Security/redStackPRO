---
name: Deploy failure
about: A deploy that failed, or a range that came up broken
title: "[deploy] "
labels: deploy
---

## What happened

Describe what failed or what is not working.

## Attach the deploy log

Every `bash deploy.sh` run writes a timestamped log to `logs/` in the export
(for example `logs/deploy-20260926-140355Z.log`). It records the redStackPRO
version, the provider, your terraform version, and where the run stopped, and it
is scrubbed of secrets (private keys and passwords) before it is written, so it
is safe to attach here.

Drag the newest `logs/deploy-*.log` onto this issue.

## Environment

- Provider (gcp / aws / azure / proxmox / esxi):
- Template or topology you deployed:
- Fresh deploy, or a re-run over an existing one:

## Anything else

Steps you took, what you expected, and anything you already tried.
