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
| [goad-wazuh](goad-wazuh.md) | 2 | 6 | 11 | 4 unique, plus the detection axis |
| [nha](nha.md) | 2 | 6 | 10 | 4 unique |
| [minilab](minilab.md) | 1 | 3 | 5 | 4 unique |
| [dracarys](../goad-dracarys/README.md) | 1 | 4 | 6 | 5 unique, plus a Linux member. Gets its own solution |
| [sccm](../goad-sccm/README.md) | 1 | 5 | 1 | surface is the MECM service, not vulns. Gets its own solution |
| [harbor](../harbor/README.md) | 2 | 5 | 10 | 3 unique techniques on redStackPRO's own range, not a GOAD lab. Gets its own solution |

"Surface" counts host vulns and user flaws together. It measures technique
variety, not difficulty or host count.

## Which labs get a full solution

Every range now has an authored solution folder. Some follow an
upstream write-up; the rest are hand-authored from the lab's own blueprint and
carry an "authored, not yet run live" banner until a live pass covers them. The
coverage pages in this folder stay as the technique and detection checklists the
solutions build on, so the per-lab pages here are not replaced.

| lab | solution | source |
|-----|----------|--------|
| goad | [14 parts](../goad/README.md) | GOADv2 pwning part1-13 plus ADCS part14, run live per step |
| goad-light | [goad-light](../goad-light/README.md) | generated from the goad series by `python -m redstackpro.tools.gen_solutions` |
| goad-mini | [goad-mini](../goad-mini/README.md) | hand-written coverage; single domain, ESC1 and the sevenkingdoms ACL chain |
| sccm | [goad-sccm](../goad-sccm/README.md) | mayfly SCCM-LAB part0x0-0x3 |
| dracarys | [goad-dracarys](../goad-dracarys/README.md) | reconstructed (mayfly publishes no solution) |
| nha | [goad-nha](../goad-nha/README.md) | hand-authored from the blueprint |
| minilab | [goad-minilab](../goad-minilab/README.md) | hand-authored from the blueprint |
| goad-wazuh | [goad-wazuh](../goad-wazuh/README.md) | hand-authored, the detection axis is the point |
| harbor | [harbor](../harbor/README.md) | redStackPRO original, not a GOAD lab |

## Standing rule

Every lab still has to clear the **stand-up gate**: it compiles from the canvas
with no errors, `deploy.sh` reaches `RUN EXITED ok=1` in a single pass, and the
jumpbox comes up with the Guacamole portal and the assumed-breach foothold
account. That gate is independent of technique coverage and applies to all nine.
