# Lab coverage matrices

The [GOAD series](../goad/README.md) is the deep solution: 14 parts
adapted from mayfly277's GOAD pwning series, run live and marked PASS/FAIL per
step. It is written against the **goad** lab.

The other labs are not all smaller copies of goad. This folder records, per lab,
which parts of the goad series apply unchanged and which techniques that series
never exercises. A lab page is a validation checklist first and documentation
second.

## How a lab's technique surface is measured

A lab's attack surface has **two** dimensions, and counting either one alone is
misleading:

- **host vulns** - `overlay.vulns` on a host node (`esc1`, `iis_webshell`, ...)
- **user flaws** - `overlay.users[].flaws` on a domain node, plus `spns` and
  `delegate_to` (`kerberoastable`, `asrep_roastable`, `constrained_delegation`)

goad reaches kerberoasting and ASREProasting through **user flaws**, while
goad-wazuh reaches the same attacks through **host vulns** of the same name. A
vulns-only audit therefore understates goad by six techniques and overstates the
difference between the two labs. Both dimensions are counted below.

## Coverage at a glance

| lab | domains | hosts | surface | relationship to goad |
|-----|---------|-------|---------|----------------------|
| [goad](../goad/README.md) | 3 | 6 | 39 | the reference series, 14 parts |
| [goad-light](goad-light.md) | 2 | 4 | 22 | strict subset, no delta |
| [goad-mini](goad-mini.md) | 1 | 2 | 2 | strict subset, no delta |
| [goad-wazuh](goad-wazuh.md) | 2 | 6 | 11 | 4 unique, plus the detection axis. Detection page |
| [nha](nha.md) | 2 | 6 | 10 | 4 unique |
| [minilab](minilab.md) | 1 | 3 | 5 | 4 unique |
| dracarys | 1 | 4 | 6 | 5 unique, plus a Linux member. Gets its own solution |
| sccm | 1 | 5 | 2 | surface is the MECM service, not vulns. Gets its own solution |
| [harbor](../harbor/README.md) | 2 | 5 | 10 | 3 unique techniques on redStackPRO's own range, not a GOAD lab. Gets its own solution |

"Surface" counts host vulns and user flaws together. It measures technique
variety, not difficulty or host count.

## Which labs get a full solution

Every range now has an authored solution folder (ADR 0061). Some follow an
upstream write-up; the rest are hand-authored from the lab's own template and
carry an "authored, not yet run live" banner until a live pass covers them. The
coverage pages in this folder stay as the technique and detection checklists the
solutions build on, so the per-lab pages here are not replaced.

| lab | solution | source |
|-----|----------|--------|
| goad | [14 parts](../goad/README.md) | GOADv2 pwning part1-13 plus ADCS part14, run live per step |
| goad-light, goad-mini | [goad-light](goad-light.md), [goad-mini](goad-mini.md) | generated from the goad series by `python -m redstackpro.tools.gen_solutions` |
| sccm | [goad-sccm](../goad-sccm/README.md) | mayfly SCCM-LAB part0x0-0x3 |
| dracarys | [goad-dracarys](../goad-dracarys/README.md) | reconstructed (mayfly publishes no solution) |
| nha | [goad-nha](../goad-nha/README.md) | hand-authored from the template |
| minilab | [goad-minilab](../goad-minilab/README.md) | hand-authored from the template |
| goad-wazuh | [goad-wazuh](../goad-wazuh/README.md) | hand-authored, the detection axis is the point |
| harbor | [harbor](../harbor/README.md) | redStackPRO original, not a GOAD lab |

## Standing rule

Every lab still has to clear the **stand-up gate**: it compiles from the canvas
with no errors, `deploy.sh` reaches `RUN EXITED ok=1` in a single pass, and the
jumpbox comes up with the Guacamole portal and the assumed-breach foothold
account. That gate is independent of technique coverage and applies to all nine.

## Measured deploy runtimes (2026-09-09, GCP us-east4 / AWS us-east-1)

Wall clock from `deploy.sh` launch to `RUN EXITED`, from the live round that stood
every lab up. Read the attempt count with the time: the retry loop is generous, so
a lab that hit a bug spent most of its wall clock replaying, not building. Only the
single-pass rows describe how long a lab actually takes.

| lab | hosts | attempts | wall clock | note |
|-----|-------|----------|-----------|------|
| nha | 6 | **1** | **~24 min** | clean single pass, the honest reference number |
| dracarys | 4 | 2 | ~20 min | one post-join WinRM flap |
| AWS goad | 9 | 3 | ~47 min | attempts 1-2 lost to the bare `Get-ADDomain` bug |
| goad-wazuh | 6 | 5 | ~56 min | attempts 1-4 lost to the Sysmon stderr and YAML-null bugs |
| goad-light | 5 | 3 | ~82 min | child-domain password-policy revert |
| minilab | 3 | 1 (re-run) | ~3 min | on already-built hosts; its first run exhausted 8 attempts |

Two things worth carrying: a ~6 host AD lab builds in well under half an hour when
nothing is broken, and each failed attempt costs roughly the full play time plus a
150 s backoff, so a single mid-play bug can quadruple the wall clock. That is why
the failures above were worth fixing rather than retrying around.

These numbers predate the fixes for the bugs named in the notes, so the affected
labs should now land far closer to the nha figure. Re-measure after a clean round.
