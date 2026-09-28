# Security policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue.

- Preferred: GitHub Private Vulnerability Reporting on this repository
  (the "Report a vulnerability" button under the Security tab).
- Or email mike@devzerosecurity.com.

Include the version or commit, the steps to reproduce, and the impact. We aim
to acknowledge a report within a few business days and to keep you updated as we
work a fix.

## Scope

redStackPRO compiles a topology to a Terraform and Ansible working directory that
you run from your own machine. It never holds your cloud credentials and never
deploys anything itself; the export is the handoff boundary (ADR 0001). In scope:

- the compiler, validator, API, and canvas
- the generated Terraform and Ansible (for example, an insecure default that
  would harm a user who runs the export as shipped)
- the CI and release tooling

Out of scope: the deliberately vulnerable lab content in the GOAD derived ranges.
Those weak credentials and misconfigurations are the point of a validation range
and are shipped on purpose.

## Supported versions

redStackPRO is 0.9.0, a pre-release. Fixes land on the latest `main`. There is no
long term support branch yet.
