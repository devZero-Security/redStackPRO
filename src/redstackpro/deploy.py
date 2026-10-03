"""Generate the deploy.sh an export ships.

The managed hosts of a range or an offense platform sit on a private subnet that
only the jumpbox can reach, so a deploy cannot be driven from the operator's
machine: it applies Terraform, then stages the Ansible tree onto the jumpbox and
runs it there. This encodes the operational details that are otherwise easy to
get wrong -- the jumpbox provisions itself over a local connection (a cloud VM
cannot ssh to its own public address), a fresh cloud Windows box needs an
authenticated win_ping before it is promoted, and the play is idempotent so it
is retried to ride the WinRM/boot flap. See the mode briefing and 0022.

The script is generated (not static) because it bakes in the jumpbox's rendered
name and the topology's mode, the same way the inventory and site.yml are derived.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .naming import platform_account
from .terraform.plan import TerraformPlan
from .validate import Context


def _redstackpro_version():
    try:
        return _pkg_version("redstackpro")
    except PackageNotFoundError:
        return "unknown"


# The deployment log. Everything deploy.sh prints (terraform apply and the whole
# jumpbox-staged provision) is tee'd to one timestamped file, so a user who hits a
# failed or broken deploy has a single artifact to attach to a GitHub issue and we
# can see what went wrong. Secrets are scrubbed on exit so the file is safe to
# share on a public tracker. Built here rather than inline in the template so the
# bash keeps single braces (the template goes through str.format). See 0022.
_LOGGING_SETUP = r'''
mkdir -p logs
LOG="logs/deploy-$(date -u +%Y%m%d-%H%M%SZ).log"
exec 3>&1 4>&2
exec > >(tee -a "$LOG") 2>&1

# Redact the obvious secrets from the log before it is shared: private key blocks
# and password/secret/token assignments. deploy.sh does not print the lab password
# or keys itself, so this is a safety net for anything a tool underneath prints.
scrub_log(){
  [ -n "${PY:-}" ] || return 0
  [ -f "$LOG" ] || return 0
  "$PY" - "$LOG" <<'PYSCRUB'
import re, sys
p = sys.argv[1]
try:
    t = open(p, encoding="utf-8", errors="replace").read()
except OSError:
    sys.exit(0)
# The PEM marker is assembled from pieces so this generated script does not itself
# ship the literal header the export's own leak scan forbids (test_api).
d = "-" * 5
key = d + r"BEGIN [A-Z0-9 ]*PRIVATE KEY" + d + r".*?" + d + r"END [A-Z0-9 ]*PRIVATE KEY" + d
t = re.sub(key, "[redacted private key]", t, flags=re.S)
t = re.sub(r"(?im)((?:password|passphrase|secret|token|pgpassword)[\"']?\s*[:=]\s*)\S+",
           r"\1[redacted]", t)
open(p, "w", encoding="utf-8").write(t)
PYSCRUB
}

# Runs on every exit, success or failure: flush and scrub the log, restore the
# real stdout, and point a failed run at the issue tracker.
finish(){
  rc=$?
  rm -f "${KEYSAFE:-}" 2>/dev/null || true
  scrub_log
  exec 1>&3 2>&4
  if [ "$rc" -eq 0 ]; then
    echo "== deploy log saved (secrets scrubbed): $LOG =="
  else
    echo "== deploy FAILED (exit $rc). Log saved (secrets scrubbed): $LOG =="
    echo "   Attach that file to a new issue so we can see what went wrong:"
    echo "   https://github.com/devZero-Security/redStackPRO/issues/new/choose"
  fi
}
trap finish EXIT

{
  echo "redStackPRO deploy log"
  echo "version:   @@VERSION@@"
  echo "provider:  @@PROVIDER@@"
  echo "started:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "system:    $(uname -a 2>/dev/null || echo unknown)"
  echo "terraform: $(terraform version 2>/dev/null | head -1 || echo 'not found')"
  echo "----------------------------------------------------------------------"
}
'''


# Auto stop is a DAILY wall-clock time. A build applied shortly before that time
# stops itself during provisioning, which runs up to 75 minutes, leaving a
# half-built range behind a run that reported no error at all. So the guard goes
# at the APPLY boundary, which is where the trap springs, not at compile, which
# is where it is set. It aborts the way the cloud credential check does: name the
# one-line fix, and offer an explicit override rather than a flag nobody would
# find. 150 minutes is the 75-minute provision plus the same again, so a build
# that passes has time to finish and be looked at.
#
# This is emitted ONLY for a fixed `at`. `after_hours` used to be resolved at
# compile, so a build staged in the morning and applied that afternoon had
# already eaten the gap, and that was the case this guard was written for. It is
# now resolved at apply by time_offset (see plan.auto_stop), so the lead is
# always the full N hours and there is nothing left to warn about: emitting it
# would refuse a sound build and tell the operator to re-compile, which would
# change nothing. A topology carrying both still gets the guard, because the `at`
# side can still bind early.
_TTL_PREFLIGHT = """# Refuse to start a build that would stop itself before it finishes.
RSP_STOP_LEAD=$("$PY" -c '
import datetime as dt
try:
    from zoneinfo import ZoneInfo
    tz = ZoneInfo("%(timezone)s")
except Exception:
    tz = dt.timezone.utc
now = dt.datetime.now(tz)
stop = now.replace(hour=%(hour)d, minute=%(minute)d, second=0, microsecond=0)
if stop <= now:
    stop += dt.timedelta(days=1)
print(int((stop - now).total_seconds() // 60))
')
# A check that cannot run must not read as a check that passed. The first cut of
# this defaulted to a large lead on failure, which turned a broken interpreter into
# a silent all-clear -- the same shape as an audit script printing 0 for every
# resource because its token had expired. Say so and stop instead.
case "$RSP_STOP_LEAD" in
  ''|*[!0-9]*)
    echo "Could not work out when this build stops itself -- the check did not run."
    echo "This build carries a daily stop at %(hour)02d:%(minute)02d %(timezone)s."
    echo "Confirm that is more than a build away, then:"
    echo "  Override: REDSTACKPRO_MIN_STOP_LEAD=0 bash deploy.sh"
    exit 1 ;;
esac
if [ "$RSP_STOP_LEAD" -lt "${REDSTACKPRO_MIN_STOP_LEAD:-150}" ]; then
  echo "This build stops itself at %(hour)02d:%(minute)02d %(timezone)s, which is $RSP_STOP_LEAD minutes away."
  echo "Provisioning takes up to 75 minutes, so the range would stop part-built."
  echo
  echo "  Override: REDSTACKPRO_MIN_STOP_LEAD=0 bash deploy.sh -- use this when you are"
  echo "            re-deploying an existing export, where there is no compile to re-run."
  echo "  Recompile: re-run the compile now -- auto_stop.after_hours counts from the"
  echo "            COMPILE, not the apply, so a fresh compile resets the clock."
  exit 1
fi
"""


# The Windows front door. It exists because of one specific trap: typing
# `bash deploy.sh` at a PowerShell prompt does NOT run Git Bash. `bash` resolves
# to C:\Windows\System32\bash.exe, the WSL launcher, so the deploy runs inside a
# different filesystem with a different home directory and, usually, different
# cloud credentials -- and it fails for reasons that look nothing like the cause.
# Nobody should have to know that, so this finds Git Bash and calls it properly.
DEPLOY_PS1 = r"""# redStackPRO deploy, for Windows PowerShell.
#
#   .\deploy.ps1
#
# This is a wrapper. The deploy itself is deploy.sh beside it, and it is the same
# script macOS and Linux run -- there is one deploy, not two.
#
# Why a wrapper at all: `bash deploy.sh` at a PowerShell prompt does not run Git
# Bash. `bash` resolves to C:\Windows\System32\bash.exe, which is the WSL
# launcher, so the deploy would run in a different filesystem with a different
# home and different cloud credentials. This calls Git Bash explicitly instead.
$ErrorActionPreference = 'Stop'

$candidates = @(
  "$env:ProgramFiles\Git\bin\bash.exe",
  "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
  "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
)
$bash = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $bash) {
  Write-Host "Git Bash was not found, and it is what runs the deploy."
  Write-Host "Install Git for Windows: https://git-scm.com/download/win"
  exit 1
}

# Git Bash reads a drive letter path happily as long as the separators are
# forward slashes, so no /c/-style translation is needed.
$here = (Split-Path -Parent $MyInvocation.MyCommand.Path) -replace '\\', '/'
& $bash -lc "cd '$here' && bash deploy.sh"
exit $LASTEXITCODE
"""


# Find a Python that actually RUNS, rather than one that merely sits on PATH.
# `command -v python3` is not enough: Windows ships a Microsoft Store stub named
# python3 that is on PATH by default, prints an advert and exits non-zero. A PATH
# check passes, and the first real call then fails for a reason that reads
# unrelated to Python. A check must execute its candidate. Shared between
# deploy.sh and manage.sh, both of which parse a `terraform output -json` with it.
_FIND_PYTHON = r'''# Find a Python that actually RUNS, rather than one that merely sits on PATH.
# `command -v python3` is not enough: Windows ships a Microsoft Store stub named
# python3 that is on PATH by default, prints an advert and exits non-zero. A PATH
# check passes, and the first real call then fails for a reason that reads
# unrelated to Python. A check must execute its candidate.
PY=""
for c in python3 python py; do
  command -v "$c" >/dev/null 2>&1 || continue
  "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' \
    >/dev/null 2>&1 && { PY="$c"; break; }
done
[ -n "$PY" ] || {
  echo "no working Python 3.8 or newer found (tried: python3, python, py)."
  echo "One of them may be on PATH but not runnable -- on Windows the Microsoft"
  echo "Store stub does exactly that. Install Python and re-run."
  exit 1
}
'''


def _jumpbox_name(ctx):
    for node in ctx.hosts():
        if ctx.kind(node["id"]) == "jumpbox":
            return ctx.name(node["id"])
    return None


_AWS_TTL_IAM_NOTE = """# auto_stop creates an IAM role and policy for the shutdown schedule, the stack's
# first IAM resources. A caller who cannot create roles fails there, on a resource
# they did not add by hand, so say so before the apply rather than after.
echo "note: this range has an auto-stop schedule; the AWS apply needs iam:CreateRole and iam:PutRolePolicy, or it fails creating the scheduler role. Grant those, or recompile without an auto_stop TTL."
"""


def generate_deploy_script(topology, registry=None, provider=None):
    """Return deploy.sh contents, or None when the topology has no jumpbox (there is
    nothing to stage a provision through).

    ``provider`` adds provider-specific preflight: a GCP deploy checks for
    Application Default Credentials up front, so a missing login is a one-line fix
    rather than a Terraform stack trace."""
    ctx = Context(topology, registry)
    jumpbox = _jumpbox_name(ctx)
    if not jumpbox:
        return None
    is_range = topology.get("mode") == "defense"

    cloud_preflight = ""
    if provider == "gcp":
        cloud_preflight = (
            "if ! gcloud auth application-default print-access-token "
            ">/dev/null 2>&1; then\n"
            '  echo "GCP credentials are not set. Run:  gcloud auth login  &&  '
            'gcloud auth application-default login"; exit 1\n'
            "fi\n"
        )

    # Resolved through TerraformPlan rather than re-read from the topology, so the
    # clock this checks is the same one the generated schedule was built from.
    # Both run in the same compile, seconds apart.
    stop = TerraformPlan(topology, registry).auto_stop
    if stop and stop["at_minute"] is not None:
        # The clock in the message is the `at` the operator set, not the
        # combined value: it is the only half that can bind before the apply.
        cloud_preflight += _TTL_PREFLIGHT % dict(
            stop,
            hour=stop["at_minute"] // 60,
            minute=stop["at_minute"] % 60,
        )
        if provider == "aws":
            cloud_preflight += _AWS_TTL_IAM_NOTE

    # The provision runner that lands on the jumpbox. Mode is baked in here rather
    # than branched at run time, so the emitted runner is straight-line.
    if is_range:
        gate = (
            "  # The jumpbox play runs FIRST, in a pass of its own. The AD loop\n"
            "  # below excludes jumpboxes so the portal does not ride the WinRM\n"
            "  # wait or the Windows retry cadence -- Guacamole and the\n"
            "  # assumed-breach foothold are how the operator reaches the range at\n"
            "  # all, so they must not wait on a Windows box finishing its boot.\n"
            "  # This pass is what provisions the jumpbox: without it the excluded\n"
            "  # play ran nowhere, and the range came up with no portal and no\n"
            "  # foothold account even though the run reported ok=1.\n"
            "  for i in 1 2 3; do\n"
            '    echo "== jumpbox pass $i $(date) ==" | tee -a run.log\n'
            '    ansible-playbook -i ansible/inventory.yml ansible/site.yml --limit jumpboxes "${C[@]}" 2>&1 | tee -a run.log && break\n'
            '    echo "== jumpbox pass $i failed; retry in 60s ==" | tee -a run.log\n'
            "    sleep 60\n"
            "  done\n"
            "  # A fresh cloud Windows box sets its Administrator password a few\n"
            "  # minutes after WinRM starts; wait for an AUTHENTICATED win_ping\n"
            "  # before the promotion, a port check is not enough.\n"
            '  echo "== waiting for authenticated WinRM ==" | tee -a run.log\n'
            "  for i in $(seq 1 60); do\n"
            '    ansible -i ansible/inventory.yml windows -m ansible.windows.win_ping "${C[@]}" >/dev/null 2>&1 && break\n'
            "    sleep 30\n"
            "  done\n"
        )
        # The jumpbox got its own pass above; the AD plays run on everything else.
        limit = "--limit 'all:!jumpboxes' "
    else:
        gate = ""
        limit = ""

    # A redirector that gets a Let's Encrypt certificate needs its domain pointed
    # at its public address, and only the operator can create that DNS record.
    # Print the exact record the moment the address exists (right after apply),
    # so they can set it at their registrar while the build runs; the redirector
    # role then waits for it to resolve before issuance. See the redirector role.
    dns_targets = [
        (ctx.name(n["id"]), ctx.overlay(n["id"], "hostname", ""))
        for n in ctx.hosts()
        if ctx.kind(n["id"]) == "redirector"
        and (ctx.overlay(n["id"], "tls", {}) or {}).get("cert_source") == "letsencrypt"
        and ctx.overlay(n["id"], "hostname", "")
    ]
    dns_actions = ""
    if dns_targets:
        pairs = " ".join('"%s|%s"' % (name, host) for name, host in dns_targets)
        dns_actions = (
            'say "DNS action required before the redirector certificate can issue"\n'
            'RSP_ADDRS="$(terraform -chdir=terraform output -json redstackpro_addresses)" || { echo "   >> could not read addresses for the DNS reminder -- set the redirector A record by hand once the box is up"; RSP_ADDRS=""; }\n'
            "for pair in " + pairs + "; do\n"
            '  rsp_host="${pair##*|}"\n'
            "  rsp_ip=\"$(printf '%s' \"$RSP_ADDRS\" | \"$PY\" -c "
            "\"import json,sys;print(json.load(sys.stdin).get('${pair%%|*}',{}).get('public_address') or '')\")\"\n"
            '  [ -n "$rsp_ip" ] || continue\n'
            # Show what the name resolves to TODAY, not just what it must become.
            # Every apply mints a new address while the canvas hands out a static
            # hostname, so a STALE record is the default state rather than an
            # accident -- and "create an A record" reads as already-done to an
            # operator whose record exists and is simply pointing at the last
            # deploy. That misread cost a whole session of beacon callbacks on
            # 2026-09-14. Printing both halves makes the delta unmissable.
            '  rsp_cur="$("$PY" -c "import socket;print(socket.gethostbyname(\'$rsp_host\'))" 2>/dev/null)"\n'
            '  if [ "$rsp_cur" = "$rsp_ip" ]; then\n'
            '    echo "   >> $rsp_host already resolves to $rsp_ip -- nothing to do"\n'
            "  else\n"
            '    echo "   >> at your DNS registrar, set this A record NOW:"\n'
            '    echo "         $rsp_host   ->   $rsp_ip"\n'
            '    if [ -n "$rsp_cur" ]; then\n'
            '      echo "      it currently points at $rsp_cur -- STALE, from an earlier deploy"\n'
            "    else\n"
            '      echo "      it does not resolve at all right now"\n'
            "    fi\n"
            '    echo "      issuance waits ~15 min for it, then continues on a self-signed cert"\n'
            "  fi\n"
            "done\n"
        )

    logging_setup = (_LOGGING_SETUP
                     .replace("@@VERSION@@", _redstackpro_version())
                     .replace("@@PROVIDER@@", provider or "not specified"))
    return _TEMPLATE.format(jumpbox=jumpbox,
                            jumpuser=platform_account(topology.get("mode")),
                            is_range="true" if is_range else "false",
                            gate=gate, limit=limit, dns_actions=dns_actions,
                            cloud_preflight=cloud_preflight,
                            logging_setup=logging_setup,
                            find_python=_FIND_PYTHON)


_TEMPLATE = r"""#!/usr/bin/env bash
# Generated by redStackPRO. Do not edit; re-run the compile to regenerate.
#
# One-command deploy. The managed hosts sit on a private subnet only the jumpbox
# can reach, so this applies Terraform, then stages the Ansible tree onto the
# jumpbox and provisions from there. Run it from the export root (the directory
# holding this script, terraform/ and ansible/).
#
# Needs on your machine: terraform, ssh, tar, and a Python 3. Ansible is installed
# on the jumpbox automatically -- you do not need it locally. Every one of these
# ships with Git for Windows, macOS and any Linux, so this runs the same way on
# all three. On Windows run it from Git Bash, or use deploy.ps1 beside this file.
#
#   1. fill deploy.tfvars in this directory
#   2. bash deploy.sh
#
# Re-running is safe: Terraform reconciles and the playbook is idempotent.
set -uo pipefail

JUMPBOX="{jumpbox}"
IS_RANGE={is_range}
JUMPUSER={jumpuser}

cd "$(dirname "$0")"
say(){{ echo "== [$(date +%H:%M:%S)] $* =="; }}
{logging_setup}
for t in terraform ssh tar; do
  command -v "$t" >/dev/null || {{ echo "$t not found on PATH -- install it first"; exit 1; }}
done

{find_python}
# The PRIVATE key whose public half is in deploy.tfvars
# (ssh_public_key), looked for where a person would expect it:
#   1. $REDSTACKPRO_SSH_KEY, when you set it
#   2. a key you dropped in keys/, beside this script
#   3. ~/.ssh/id_ed25519
# keys/ exists so the export is self contained: extract it, drop your key in,
# deploy. Nothing is ever written there by us and it is not in the download.
if [ -n "${{REDSTACKPRO_SSH_KEY:-}}" ]; then
  KEY="$REDSTACKPRO_SSH_KEY"
else
  RSP_KEYS=""
  RSP_N=0
  for f in keys/*; do
    [ -f "$f" ] || continue
    case "$f" in *.pub|*README*) continue ;; esac
    RSP_KEYS="$RSP_KEYS $f"
    RSP_N=$((RSP_N + 1))
  done
  if [ "$RSP_N" -eq 1 ]; then
    KEY="${{RSP_KEYS# }}"
  elif [ "$RSP_N" -gt 1 ]; then
    echo "more than one private key in keys/:$RSP_KEYS"
    echo "say which:  REDSTACKPRO_SSH_KEY=keys/<name> bash deploy.sh"
    exit 1
  else
    KEY="$HOME/.ssh/id_ed25519"
  fi
fi
[ -f "$KEY" ] || {{
  echo "no ssh private key found."
  echo "  looked at: \$REDSTACKPRO_SSH_KEY, then keys/, then $HOME/.ssh/id_ed25519"
  echo
  echo "  make one:  ssh-keygen -t ed25519 -f keys/id_ed25519 -N \"\""
  echo "  then put the contents of keys/id_ed25519.pub into"
  echo "  deploy.tfvars as ssh_public_key, and re-run."
  exit 1
}}

# SSH enforces private-key perms on Linux and macOS (StrictModes): a group- or
# world-readable key is refused and it drops to a password the later non-interactive
# scp/ssh cannot answer. On a Windows drive mounted in WSL the key reports 0777 and
# chmod does not stick, so copy it to a 600 path on a real filesystem and connect
# with that copy. $KEY stays the path shown in the hints below; the copy is removed
# on exit by finish. Git Bash (MSYS/MinGW) governs perms by ACL, does not enforce
# the unix mode, and its temp dirs are NTFS where chmod cannot make 600, so there
# the copy neither helps nor is needed: use $KEY as is.
KEYSAFE=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) ;;
  *)
    KEYBASE="${{TMPDIR:-/tmp}}"; case "$KEYBASE" in *" "*) KEYBASE="/tmp" ;; esac
    KEYSAFE="$(mktemp "$KEYBASE/rsp-key.XXXXXX")"
    cp "$KEY" "$KEYSAFE" && chmod 600 "$KEYSAFE"
    ;;
esac
SSHKEY="${{KEYSAFE:-$KEY}}"
# BatchMode=yes: never fall back to an interactive password prompt. Without it, a
# fresh jumpbox whose cloud-init has not yet written redop's authorized_keys answers
# port 22 but refuses the key, ssh prompts for a password, and the "wait for ssh"
# probe below stalls on that prompt instead of retrying (and the first heredoc step
# dies with "Permission denied, please try again"). With it, the probe fails fast and
# rides out the cloud-init race, which is what its retry loop was written to do.
SSH="ssh -i $SSHKEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 -o BatchMode=yes"

{cloud_preflight}# Refuse to apply when management ingress is open to the whole internet.
# operator_source_ranges is a tfvars value the topology validator never sees, so
# the check happens here, at apply time. A range can hold deliberately vulnerable
# hosts, so a literal 0.0.0.0/0 entry is a blocking abort, not a warning; it aborts
# the same way the auto-stop guard does, with an explicit override. Subnet-scoped
# values do not trip it: only the literal 0.0.0.0/0 does. The pattern is loose on
# spacing and quoting and catches 0.0.0.0/0 as one entry among several.
if grep -Eq 'operator_source_ranges[^#]*"0\.0\.0\.0/0"' deploy.tfvars 2>/dev/null; then
  if [ "${{REDSTACKPRO_ALLOW_OPEN_INGRESS:-0}}" = "1" ]; then
    echo "WARNING: operator_source_ranges is 0.0.0.0/0 (ssh and the portal are open to the whole internet). Narrow it in deploy.tfvars."
    # Let the Terraform precondition through too (it fails closed by default).
    export TF_VAR_allow_open_ingress=true
  else
    echo "operator_source_ranges is 0.0.0.0/0, which exposes ssh and the portal to the"
    echo "entire internet. This range may contain deliberately vulnerable hosts, so an"
    echo "open range is a mistake, not a shortcut."
    echo
    echo "  Fix:      set operator_source_ranges to your own IP/CIDR in deploy.tfvars,"
    echo '            for example ["203.0.113.5/32"].'
    echo "  Override: REDSTACKPRO_ALLOW_OPEN_INGRESS=1 bash deploy.sh"
    exit 1
  fi
fi
# deploy.tfvars is the one config file you edit, here in the export root. Terraform
# auto-loads terraform/terraform.tfvars, so copy it into place for apply and destroy.
[ -f deploy.tfvars ] || {{ echo "deploy.tfvars not found next to this script. Fill it in first (see DEPLOYMENT-GUIDE.md)."; exit 1; }}
cp deploy.tfvars terraform/terraform.tfvars
# Fail fast from here on. Without this a failed apply ran on and the user saw a
# misleading "unfilled address placeholders remain" instead of the real error;
# the tolerant spots below guard themselves (|| true, trailing true, if/&&).
set -e
say "terraform apply"
terraform -chdir=terraform init -input=false -upgrade >/dev/null || {{ echo "terraform init failed -- check the provider download and your network"; exit 1; }}
terraform -chdir=terraform apply -auto-approve -input=false || {{ echo "terraform apply failed (its error is above) -- nothing was provisioned; fix it and re-run"; exit 1; }}

# Both modes. Terraform calls this "the shared password for the admin account,
# the Windows operator, and the portal" and emits it either way, but only a range
# used to read it back, so nothing an ops stack provisioned could reach the one
# credential the operator is actually given. A teamserver that wants to put that
# password in its own config had no way to learn it.
REDSTACKPRO_LAB_PASSWORD="$(terraform -chdir=terraform output -raw lab_password)" || {{ echo "could not read lab_password from terraform output -- did apply finish?"; exit 1; }}
# An empty value here would provision the Windows hosts and the portal with a
# blank credential, so stop rather than carry it forward.
[ -n "$REDSTACKPRO_LAB_PASSWORD" ] || {{ echo "lab_password came back empty -- apply looks incomplete; re-run before provisioning"; exit 1; }}
export REDSTACKPRO_LAB_PASSWORD

say "fill inventory addresses from terraform output"
"$PY" tf_inventory.py || {{ echo "filling the inventory from terraform output failed"; exit 1; }}
# Scan the whole ansible tree (and the mode briefing, DEFENSE-/OFFENSE-BRIEFING.md),
# not a fixed pair of subdirectories: an ops export has no ansible/vars, which made
# the old grep exit non-zero on the missing path and skip the check entirely. Pipe
# to grep -q so the result is decided by whether any file still holds a token, not
# by grep's exit code over a path that may not exist.
if grep -rl "<<tf:" ansible *-BRIEFING.md 2>/dev/null | grep -q .; then
  echo "unfilled address placeholders remain -- aborting"; exit 1
fi

JUMP=$(terraform -chdir=terraform output -json redstackpro_addresses \
  | "$PY" -c "import json,sys;print(json.load(sys.stdin)['$JUMPBOX']['public_address'])") || {{ echo "could not read the jumpbox address from terraform output"; exit 1; }}
[ -n "$JUMP" ] || {{ echo "the jumpbox address is empty -- apply may not have created it"; exit 1; }}
say "jumpbox public address: $JUMP"
{dns_actions}

say "wait for the jumpbox to accept ssh"
ssh-keygen -f "$HOME/.ssh/known_hosts" -R "$JUMP" >/dev/null 2>&1 || true
ok_ssh=0
for i in $(seq 1 30); do $SSH "$JUMPUSER@$JUMP" true 2>/dev/null && {{ ok_ssh=1; break; }}; sleep 10; done
[ "$ok_ssh" = 1 ] || {{ echo "jumpbox $JUMP never accepted ssh after ~5 min -- check it booted and 22 is open to your operator_source_ranges"; exit 1; }}

say "install prerequisites on the jumpbox"
$SSH "$JUMPUSER@$JUMP" 'bash -s' <<'BOOT'
set -e
export DEBIAN_FRONTEND=noninteractive
# Each prerequisite is checked on its own. They used to ride on a single
# `command -v rsync && command -v screen` test, so an image that already had
# screen installed nothing -- which was harmless only while rsync was also
# required and usually absent. Dropping rsync made that test true on its own and
# python3-pip stopped being installed, surfacing two steps later as
# `pip: command not found` and then as ansible-galaxy failing, which reads like a
# network problem rather than a missing package.
RSP_NEED=""
command -v screen >/dev/null 2>&1 || RSP_NEED="$RSP_NEED screen"
python3 -m pip --version >/dev/null 2>&1 || RSP_NEED="$RSP_NEED python3-pip"
if [ -n "$RSP_NEED" ]; then sudo apt-get update -qq; sudo apt-get install -y -qq $RSP_NEED >/dev/null; fi
# `python3 -m pip` rather than `pip`: the Debian package installs the module but
# does not always leave a `pip` on PATH for a non-root user.
command -v ansible-playbook >/dev/null 2>&1 || ~/.local/bin/ansible-playbook --version >/dev/null 2>&1 || python3 -m pip install --user --break-system-packages -q "ansible-core>=2.16" pypsrp PySocks requests
mkdir -p ~/provision ~/.ssh && chmod 700 ~/.ssh
BOOT

say "stage the ansible tree and the connection key onto the jumpbox"
scp -i "$SSHKEY" -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$SSHKEY" "$JUMPUSER@$JUMP:.ssh/deploy-key" >/dev/null
$SSH "$JUMPUSER@$JUMP" 'chmod 600 ~/.ssh/deploy-key'
# Staged with tar over ssh rather than rsync. rsync is not on a stock Windows box
# and there is no rsync package in chocolatey or winget, so requiring it meant the
# export simply could not be launched from Windows; tar ships with Git for
# Windows, macOS and every Linux. The remote delete reproduces rsync --delete:
# without it a re-deploy into a reused export would leave files the new compile no
# longer emits, and ansible would happily run them.
tar czf - ansible ansible.cfg \
  | $SSH "$JUMPUSER@$JUMP" 'rm -rf ~/provision/ansible ~/provision/ansible.cfg; mkdir -p ~/provision; tar xzf - -C ~/provision'
$SSH "$JUMPUSER@$JUMP" 'export PATH="$HOME/.local/bin:$PATH"; for i in 1 2 3 4 5; do ansible-galaxy collection install -r ~/provision/ansible/requirements.yml > ~/provision/galaxy.log 2>&1 && exit 0; echo "galaxy install attempt $i failed; retry in 20s" | tee -a ~/provision/galaxy.log; sleep 20; done; exit 1' || {{ echo "ansible-galaxy failed on the jumpbox after 5 tries -- see ~/provision/galaxy.log on $JUMP"; exit 1; }}

# The jumpbox provisions itself over a LOCAL connection: a cloud VM cannot ssh to
# its own public address, so its own play must not go over the network.
$SSH "$JUMPUSER@$JUMP" "grep -q 'ansible_connection: local' ~/provision/ansible/host_vars/$JUMPBOX.yml 2>/dev/null || echo 'ansible_connection: local' >> ~/provision/ansible/host_vars/$JUMPBOX.yml"

printf '%s' "$REDSTACKPRO_LAB_PASSWORD" | $SSH "$JUMPUSER@$JUMP" 'cat > ~/provision/.labpw && chmod 600 ~/provision/.labpw'

say "write the provision runner on the jumpbox"
$SSH "$JUMPUSER@$JUMP" "cat > ~/provision/run.sh" <<'RUNNER'
#!/usr/bin/env bash
set -uo pipefail
cd ~/provision
export PATH="$HOME/.local/bin:$PATH" ANSIBLE_HOST_KEY_CHECKING=False
C=(-e ansible_ssh_common_args='' -e redstackpro_ssh_key_path=$HOME/.ssh/deploy-key)
# The operator's one password, in both modes. A range needs it to provision
# Windows; an ops stack needs it so a service can put the operator's own
# credential in its config instead of whatever its upstream sample shipped.
[ -f ~/provision/.labpw ] && export REDSTACKPRO_LAB_PASSWORD="$(cat ~/provision/.labpw)"
: > run.log
{gate}ok=0
for attempt in 1 2 3 4 5 6 7 8; do
  echo "== site.yml attempt $attempt $(date) ==" | tee -a run.log
  if ansible-playbook -i ansible/inventory.yml ansible/site.yml {limit}"${{C[@]}}" 2>&1 | tee -a run.log; then
    echo "== PLAYBOOK SUCCEEDED (attempt $attempt) ==" | tee -a run.log; ok=1; break
  fi
  echo "== attempt $attempt failed; retry in 150s (idempotent; rides the WinRM/boot flap) ==" | tee -a run.log
  sleep 150
done
echo "== RUN EXITED ok=$ok $(date) ==" | tee -a run.log
RUNNER
# Quitting the screen does not reap the ansible-playbook it launched: that process
# reparents to init and keeps running, so a re-deploy would leave the previous run
# racing the new one over the same hosts (a hang that looks like a stall). Reap any
# lingering runner and playbook in a SEPARATE step from the launch: killing them in
# the same command that names run.sh would match that very command line and kill
# the launching shell. The bracketed patterns ([r], [p]) keep pgrep from matching
# its own command line either.
$SSH "$JUMPUSER@$JUMP" 'screen -S provision -X quit 2>/dev/null; for p in $(pgrep -f "ansible-[p]laybook -i ansible/inventory.yml"); do kill -9 "$p" 2>/dev/null; done; for p in $(pgrep -f "provision/[r]un.sh"); do kill -9 "$p" 2>/dev/null; done; true'
$SSH "$JUMPUSER@$JUMP" 'chmod +x ~/provision/run.sh; screen -dmS provision ~/provision/run.sh; sleep 2; screen -ls | grep -qi provision' || {{ echo "the provision screen did not start on the jumpbox"; exit 1; }}

say "provisioning launched under screen 'provision' on the jumpbox"
echo "   watch it:   ssh -i $KEY $JUMPUSER@$JUMP   then   screen -r provision"
echo "   or tail it: ssh -i $KEY $JUMPUSER@$JUMP 'tail -f ~/provision/run.log'"
echo
echo "The build continues on the jumpbox even if you disconnect. When run.log"
echo "shows 'RUN EXITED ok=1', the deploy is complete; open the Guacamole portal"
echo "at https://$JUMP/guacamole (credentials: terraform -chdir=terraform output guacamole)."
"""


# manage.sh: the other half of managing a deployed range. deploy.sh answers "get
# it running"; this answers "check on it, turn it off overnight, turn it back
# on, tear it down." Built with plain concatenation, not str.format, because
# the pieces below are already complete bash and every provider block below
# carries its own literal braces (bash blocks, a JMESPath query); doubling
# them for a .format() pass this script does not need would only invite the
# exact bug that convention exists to prevent.
#
# status/start/stop target exactly this range's own instances, read from the
# terraform root output redstackpro_instances (see plan.outputs), never the
# whole account or project. teardown is a plain `terraform destroy`, which
# walks local state the same way for every provider, so it needs none of that.
_MANAGE_HEAD = r'''#!/usr/bin/env bash
# Generated by redStackPRO. Do not edit; re-run the compile to regenerate.
#
# Manage a deployed range or stack: check status, start it, stop it, or tear
# it down. Run it from the export root (the directory holding this script,
# terraform/ and deploy.tfvars).
#
#   bash manage.sh status
#   bash manage.sh start
#   bash manage.sh stop
#   bash manage.sh teardown
#
# status, start and stop act on exactly this range's own instances, never the
# whole cloud account or project. teardown runs terraform destroy.
#
# On Windows run it from Git Bash, or use manage.ps1 beside this file.
set -uo pipefail

cd "$(dirname "$0")"
say(){ echo "== [$(date +%H:%M:%S)] $* =="; }

cmd="${1:-}"
case "$cmd" in
  status|start|stop|teardown) ;;
  *)
    echo "usage: bash manage.sh status|start|stop|teardown"
    exit 1
    ;;
esac

command -v terraform >/dev/null 2>&1 || { echo "terraform not found on PATH -- install it first"; exit 1; }

'''

_MANAGE_TEARDOWN = r'''
if [ "$cmd" = "teardown" ]; then
  # Same handoff as deploy.sh: the editable config lives at the export root as
  # deploy.tfvars and terraform auto-loads terraform/terraform.tfvars, so copy
  # it into place first, or destroy runs with no vars at all.
  [ -f deploy.tfvars ] || { echo "deploy.tfvars not found next to this script."; exit 1; }
  cp deploy.tfvars terraform/terraform.tfvars
  say "terraform destroy"
  terraform -chdir=terraform init -input=false -upgrade >/dev/null
  terraform -chdir=terraform destroy -auto-approve
  exit $?
fi

'''

_MANAGE_STATUS_PORTAL = r'''if [ "$cmd" = "status" ]; then
  GUAC_URL="$(terraform -chdir=terraform output -json guacamole 2>/dev/null | "$PY" -c "import json,sys; print(json.load(sys.stdin).get('url',''))" 2>/dev/null)"
  [ -n "$GUAC_URL" ] && echo "portal: $GUAC_URL"
fi

'''

# Per-provider status/start/stop. Each reads redstackpro_instances, which
# carries exactly what that provider's CLI needs to address a host: an AWS
# instance id, or a GCP instance name plus its zone. See plan.outputs.
_MANAGE_PROVIDER_BLOCK = {
    "aws": r'''INSTANCES="$(terraform -chdir=terraform output -json redstackpro_instances 2>/dev/null)"
if [ -z "$INSTANCES" ] || [ "$INSTANCES" = "null" ]; then
  echo "no redstackpro_instances output found -- has terraform applied yet?"
  exit 1
fi
IDS="$(printf '%s' "$INSTANCES" | "$PY" -c "import json,sys; print(' '.join(v['instance_id'] for v in json.load(sys.stdin).values()))")"
[ -n "$IDS" ] || { echo "no instances found in this range."; exit 1; }

case "$cmd" in
  status)
    aws ec2 describe-instances --instance-ids $IDS \
      --query 'Reservations[].Instances[].{name:Tags[?Key==`Name`]|[0].Value,state:State.Name,ip:PublicIpAddress}' \
      --output table
    ;;
  start)
    aws ec2 start-instances --instance-ids $IDS
    ;;
  stop)
    aws ec2 stop-instances --instance-ids $IDS
    ;;
esac
''',
    "gcp": r'''INSTANCES="$(terraform -chdir=terraform output -json redstackpro_instances 2>/dev/null)"
if [ -z "$INSTANCES" ] || [ "$INSTANCES" = "null" ]; then
  echo "no redstackpro_instances output found -- has terraform applied yet?"
  exit 1
fi
# Target the deploy's own project, read from deploy.tfvars, so gcloud does not
# silently act on the caller's default project when it differs. Empty falls back.
PROJECT="$(grep -E '^[[:space:]]*project[[:space:]]*=' deploy.tfvars 2>/dev/null | head -1 | sed -E 's/[^=]*=[[:space:]]*"?([^"]*)"?.*/\1/')"
PROJ_ARG=""
[ -n "$PROJECT" ] && PROJ_ARG="--project $PROJECT"
if [ "$cmd" = "status" ]; then
  RSP_ANY=0
  while IFS=' ' read -r name zone; do
    [ -n "$name" ] || continue
    RSP_ANY=1
    gcloud compute instances describe "$name" --zone "$zone" $PROJ_ARG \
      --format='table(name,status,networkInterfaces[0].accessConfigs[0].natIP)'
  done < <(printf '%s' "$INSTANCES" | "$PY" -c "import json,sys
for v in json.load(sys.stdin).values():
    print(v['name'], v['zone'])")
  [ "$RSP_ANY" -eq 1 ] || { echo "no instances found in this range."; exit 1; }
else
  # start/stop: one gcloud call per zone acts on all that zone's instances at
  # once, instead of a blocking call per instance (a multi-VM range was slow
  # that way). --zone is required and a topology can span zones, so group first.
  RSP_ANY=0
  while IFS=' ' read -r zone names; do
    [ -n "$zone" ] || continue
    RSP_ANY=1
    gcloud compute instances "$cmd" $names --zone "$zone" $PROJ_ARG
  done < <(printf '%s' "$INSTANCES" | "$PY" -c "import json,sys
z={}
for v in json.load(sys.stdin).values():
    z.setdefault(v['zone'], []).append(v['name'])
for zone, names in z.items():
    print(zone, ' '.join(names))")
  [ "$RSP_ANY" -eq 1 ] || { echo "no instances found in this range."; exit 1; }
fi
''',
}

# Any other provider still tears down (a plain terraform destroy needs no
# per-instance targeting) but is told plainly that live control is not wired
# up for it yet, rather than failing in some less legible way further down.
_MANAGE_NO_LIVE_CONTROL = r'''echo "status/start/stop is not implemented yet for this provider."
echo "Use terraform -chdir=terraform state list, or your provider's own console."
exit 1
'''


def generate_manage_script(topology, registry=None, provider=None):
    """Return manage.sh contents, or None when the topology has no jumpbox (there
    is nothing to have deployed in the first place). Mirrors generate_deploy_script:
    same gate, same reason.

    status/start/stop are wired for aws and gcp, the two tested native
    providers; teardown is provider agnostic and works everywhere."""
    ctx = Context(topology, registry)
    if not _jumpbox_name(ctx):
        return None
    provider_block = _MANAGE_PROVIDER_BLOCK.get(provider, _MANAGE_NO_LIVE_CONTROL)
    return (_MANAGE_HEAD + _FIND_PYTHON + _MANAGE_TEARDOWN + _MANAGE_STATUS_PORTAL
            + provider_block)


# The Windows front door for manage.sh, the same trap and the same fix as
# DEPLOY_PS1: `bash manage.sh` at a PowerShell prompt runs WSL's bash, not Git
# Bash, so this finds Git Bash and calls it properly, forwarding the one
# subcommand argument through.
MANAGE_PS1 = r"""# redStackPRO range control, for Windows PowerShell.
#
#   .\manage.ps1 status
#   .\manage.ps1 start
#   .\manage.ps1 stop
#   .\manage.ps1 teardown
#
# This is a wrapper. The command itself is manage.sh beside it, the same script
# macOS and Linux run -- there is one range control script, not two. See
# deploy.ps1 for why a wrapper exists at all: `bash manage.sh` at a PowerShell
# prompt does not run Git Bash. `bash` resolves to
# C:\Windows\System32\bash.exe, the WSL launcher, so the command would run in
# a different filesystem with different cloud credentials.
$ErrorActionPreference = 'Stop'

$candidates = @(
  "$env:ProgramFiles\Git\bin\bash.exe",
  "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
  "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
)
$bash = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $bash) {
  Write-Host "Git Bash was not found, and it is what runs manage.sh."
  Write-Host "Install Git for Windows: https://git-scm.com/download/win"
  exit 1
}

$cmd = if ($args.Count -gt 0) { $args[0] } else { "" }
$here = (Split-Path -Parent $MyInvocation.MyCommand.Path) -replace '\\', '/'
& $bash -lc "cd '$here' && bash manage.sh $cmd"
exit $LASTEXITCODE
"""
