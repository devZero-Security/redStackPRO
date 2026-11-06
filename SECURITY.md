# Security policy

## Reporting a vulnerability

Please report security vulnerabilities privately, not in a public issue.

Use GitHub's private reporting: on this repository's **Security** tab, choose
**Report a vulnerability** (Security, then Advisories, then Report a vulnerability).
That opens a private advisory visible only to you and the maintainers.

Include what you found, how to reproduce it, and the impact you see. We will
acknowledge the report and work with you on a fix and on disclosure.

## Scope

redStackPRO composes and compiles red team infrastructure and deliberately
vulnerable ranges. It never holds cloud credentials and never deploys anything
itself; the export is the boundary. A report is most useful when it concerns the
tool or its generated output rather than the intended weakness of a range, for
example:

- the canvas or the API, such as a way to make the compiler emit something unsafe
  that the operator did not ask for
- a generated export that exposes a credential, or opens access wider than the
  topology declares
- the published Docker image

The ranges are vulnerable on purpose. Run them only in lab environments you own or
are authorized to use.
