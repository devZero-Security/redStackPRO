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


# How a deploy reads on screen: a title box, numbered phases "[n/N] Title ....
# HH:MM" that each end on an indented "ok" line, and a closing DONE or FAILED box
# that says what to do next. Plain ASCII and no colour, because every line is
# also written to the log. The run.log on the jumpbox uses the same rules.
RULE = "=" * 62
THIN = "-" * 62
# Title, dot leader and HH:MM fill this many columns.
PHASE_WIDTH = 58

# Phase titles, in order. Azure alone has a provider preflight, so N is 8 there
# and 7 elsewhere. The Wait title carries the address, known only at run time.
PREFLIGHT_PHASE = "Preflight: VM sizes, quota, providers"
PHASES = (
    "Terraform apply",
    "Fill the inventory from Terraform",
    "Wait for the jumpbox $JUMP",
    "Install prerequisites on the jumpbox",
    "Stage the Ansible tree and the key",
    "Write the provision runner",
    "Launch provisioning on the jumpbox",
)


def phase_titles(provider):
    """The phase titles a deploy.sh for this provider prints, in order."""
    return ((PREFLIGHT_PHASE,) if provider == "azure" else ()) + PHASES


# Shown in the title box. The region comes from deploy.tfvars at run time, so the
# box names where this run actually goes.
_PROVIDER_LABEL = {"gcp": "GCP", "aws": "AWS", "azure": "Azure",
                   "proxmox": "Proxmox", "esxi": "ESXi"}
_REGION_VAR = {"gcp": "region", "aws": "region", "azure": "location"}

# The provisioning estimates the export guide states, per mode.
_ETA = {True: "45-75 min", False: "60-75 min"}


# The output helpers every later block uses. `say` indents a line under the
# current phase; `die` and `fail` stop the run and keep the reason for the
# closing box. Built apart from the template so the bash keeps single braces.
_OUTPUT = r'''# Output helpers. Plain ASCII and no colour: every line also lands in the log.
RSP_PH=0
RSP_PHASE="local checks"
RSP_REASON=""
RSP_ERR=""
RSP_DNS_TODO=""
RSP_T0=$(date +%s)
RSP_RULE="@@RULE@@"
RSP_THIN="@@THIN@@"
RSP_DOTS="@@DOTS@@"
say(){ for rsp_l in "$@"; do if [ -n "$rsp_l" ]; then printf '      %s\n' "$rsp_l"; else echo; fi; done; }
indent(){ sed 's/^./      &/'; }
note(){ say "note  $1"; shift; for rsp_l in "$@"; do say "      $rsp_l"; done; }
phase(){
  RSP_PH=$((RSP_PH + 1)); RSP_T0=$(date +%s); RSP_PHASE="[$RSP_PH/$RSP_PHASES] $1"
  rsp_n=$((@@DOTW@@ - ${#RSP_PHASE})); [ "$rsp_n" -ge 3 ] || rsp_n=3
  echo
  echo "$RSP_PHASE ${RSP_DOTS:0:$rsp_n} $(date +%H:%M)"
}
ok(){ say "ok${1:+  $1}"; }
took(){
  rsp_s=$(( $(date +%s) - RSP_T0 ))
  if [ "$rsp_s" -ge 60 ]; then printf '%dm%02ds' $((rsp_s / 60)) $((rsp_s % 60)); else printf '%ds' "$rsp_s"; fi
}
# die: the deploy's own checks, exit 1. fail, after `cmd ||`: exit with that
# command's status, the code set -e gave these steps before they named themselves.
die(){ RSP_REASON="$1"; say "$@"; exit 1; }
fail(){ rsp_rc=$?; [ "$rsp_rc" -ne 0 ] || rsp_rc=1; RSP_REASON="$1"; say "$@"; exit "$rsp_rc"; }
# deploy.ps1 sets REDSTACKPRO_FROM_PS1, so the closing box writes paths the way
# PowerShell does (keys\id_ed25519) and its ssh line pastes as is.
rsp_path(){
  if [ "${REDSTACKPRO_FROM_PS1:-}" = "1" ]; then
    case "$1" in
      /*) if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; return; fi ;;
    esac
    printf '%s\n' "$1" | tr '/' '\\'
  else
    printf '%s\n' "$1"
  fi
}
'''


# The deployment log. Everything deploy.sh prints (terraform apply and the whole
# jumpbox-staged provision) is tee'd to one timestamped file, so a user who hits a
# failed or broken deploy has a single artifact to attach to a GitHub issue and we
# can see what went wrong. Secrets are scrubbed on exit so the file is safe to
# share on a public tracker. The file ends on a `result:` line, so a log attached
# to an issue says how the run ended. See 0022.
_LOGGING_SETUP = r'''
mkdir -p logs
LOG="logs/deploy-$(date -u +%Y%m%d-%H%M%SZ).log"
# The triage header goes to the log only; the terminal gets the title box.
{
  echo "redStackPRO deploy log"
  echo "version:   @@VERSION@@"
  echo "provider:  @@PROVIDER@@"
  echo "started:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "system:    $(uname -a 2>/dev/null || echo unknown)"
  echo "terraform: $(terraform version 2>/dev/null | head -1 || echo 'not found')"
  echo "----------------------------------------------------------------------"
} > "$LOG"
exec 3>&1 4>&2
# tee writes down its own pid so finish can wait for it to drain before the
# closing lines and the scrub: bash 3.2 gives no handle on a process substitution.
RSP_TEE_PID="$LOG.tee-pid"
exec > >(sh -c 'echo $$ > "$1"; exec tee -a "$2"' rsp "$RSP_TEE_PID" "$LOG") 2>&1

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

rsp_drain(){
  rsp_pid="$(cat "$RSP_TEE_PID" 2>/dev/null)"
  rm -f "$RSP_TEE_PID"
  [ -n "$rsp_pid" ] || { sleep 1; return 0; }
  for rsp_i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    kill -0 "$rsp_pid" 2>/dev/null || return 0
    sleep 0.1
  done
}

rsp_done(){
  echo
  echo "$RSP_RULE"
  echo " DONE  Infrastructure is up. Provisioning is running."
  echo "$RSP_THIN"
  echo " Portal    https://$JUMP/guacamole"
  echo " Logins    terraform -chdir=terraform output guacamole"
  echo " Watch     ssh -i $(rsp_path "$KEY") $JUMPUSER@$JUMP"
  echo "           tail -f ~/provision/run.log"
  echo " Finished  when run.log shows RUN EXITED ok=1 (@@ETA@@)"
  printf '%s' "$RSP_DNS_TODO" | while IFS= read -r rsp_l; do
    [ -z "$rsp_l" ] || echo " DNS       set the A record $rsp_l"
  done
  echo " Log       $(rsp_path "$LOG")"
  echo "$RSP_RULE"
}

rsp_failed(){
  rsp_why="${RSP_REASON:-$RSP_ERR}"
  if [ -z "$rsp_why" ]; then
    if [ "$1" -eq 130 ]; then rsp_why="interrupted (Ctrl-C)"; else rsp_why="see the output above"; fi
  fi
  echo
  echo "$RSP_RULE"
  echo " FAILED  $RSP_PHASE"
  echo "$RSP_THIN"
  echo " Reason    $rsp_why"
  echo " Exit      $1"
  echo " Log       $(rsp_path "$LOG") (secrets scrubbed)"
  echo " Report    attach the log to a new issue:"
  echo "           https://github.com/devZero-Security/redStackPRO/issues/new/choose"
  echo "$RSP_RULE"
}

# Runs on every exit, success or failure. tee is stopped and drained first, so
# the closing box lands after everything it follows, in the terminal and in the
# log, and the result line is the log's last line before the scrub.
finish(){
  rc=$?
  set +e
  trap - ERR
  rm -f "${KEYSAFE:-}" 2>/dev/null
  exec 1>&3 2>&4
  rsp_drain
  if [ "$rc" -eq 0 ]; then
    rsp_done | tee -a "$LOG"
    echo "result: ok" >> "$LOG"
  else
    rsp_failed "$rc" | tee -a "$LOG"
    echo "result: FAILED (exit $rc) in phase $RSP_PHASE" >> "$LOG"
  fi
  scrub_log
  exit "$rc"
}
trap finish EXIT
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
TZ = "%(timezone)s"
try:
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(TZ)
except Exception:
    # A missing IANA tz database still lets an IANA name mean UTC closely enough to
    # guard on; a non-IANA id (an Azure Windows zone like "GMT Standard Time")
    # cannot, so the lead is left uncomputed and the "could not run" branch below
    # handles it honestly rather than guessing the stop time in the wrong zone.
    if "/" in TZ or TZ == "UTC":
        tz = dt.timezone.utc
    else:
        raise SystemExit(1)
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
    die "Could not work out when this build stops itself -- the check did not run." \\
      "This build carries a daily stop at %(hour)02d:%(minute)02d %(timezone)s." \\
      "Confirm that is more than a build away, then:" \\
      "  Override: REDSTACKPRO_MIN_STOP_LEAD=0 bash deploy.sh" ;;
esac
if [ "$RSP_STOP_LEAD" -lt "${REDSTACKPRO_MIN_STOP_LEAD:-150}" ]; then
  die "This build stops itself at %(hour)02d:%(minute)02d %(timezone)s, which is $RSP_STOP_LEAD minutes away." \\
    "Provisioning takes up to 75 minutes, so the range would stop part-built." \\
    "" \\
    "  Override: REDSTACKPRO_MIN_STOP_LEAD=0 bash deploy.sh" \\
    "  Or set a later stop time:" \\
    "  In the canvas, click empty space, then Topology settings > Auto-stop, and export again." \\
    "  It is a daily clock time, so exporting again with the same time changes" \\
    "  nothing; a stop after N hours counts from the apply and never trips this check."
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
# REDSTACKPRO_FROM_PS1 has deploy.sh print its closing paths the PowerShell way
# (keys\id_ed25519). Set for that one process, so it does not stay in the session.
& $bash -lc "cd '$here' && REDSTACKPRO_FROM_PS1=1 bash deploy.sh"
exit $LASTEXITCODE
"""


# Find a Python that actually RUNS, rather than one that merely sits on PATH.
# `command -v python3` is not enough: Windows ships a Microsoft Store stub named
# python3 that is on PATH by default, prints an advert and exits non-zero. A PATH
# check passes, and the first real call then fails for a reason that reads
# unrelated to Python. A check must execute its candidate. Shared between
# deploy.sh and manage.sh, both of which parse a `terraform output -json` with it;
# only the way each stops differs.
_PYTHON_PROBE = r'''# Find a Python that actually RUNS, rather than one that merely sits on PATH.
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
'''

_FIND_PYTHON = _PYTHON_PROBE + r'''[ -n "$PY" ] || {
  echo "no working Python 3.8 or newer found (tried: python3, python, py)."
  echo "One of them may be on PATH but not runnable -- on Windows the Microsoft"
  echo "Store stub does exactly that. Install Python and re-run."
  exit 1
}
'''

_FIND_PYTHON_DEPLOY = _PYTHON_PROBE + r'''[ -n "$PY" ] || die "no working Python 3.8 or newer found (tried: python3, python, py)." \
  "One of them may be on PATH but not runnable -- on Windows the Microsoft" \
  "Store stub does exactly that. Install Python and re-run."
'''


def _jumpbox_name(ctx):
    for node in ctx.hosts():
        if ctx.kind(node["id"]) == "jumpbox":
            return ctx.name(node["id"])
    return None


_AWS_TTL_IAM_NOTE = """# auto_stop creates an IAM role and policy for the shutdown schedule, the stack's
# first IAM resources. A caller who cannot create roles fails there, on a resource
# they did not add by hand, so say so before the apply rather than after.
note "this range has an auto-stop schedule; the AWS apply needs iam:CreateRole and" \\
  "iam:PutRolePolicy, or it fails creating the scheduler role. Grant those, or turn" \\
  "auto-stop off. In the canvas, click empty space, then Topology settings >" \\
  "Auto-stop, and export again."
"""


# Values in deploy.tfvars that otherwise fail deep inside terraform. A value set
# in the file wins over TF_VAR_*, the same precedence terraform applies, so the
# environment is read only when the file leaves the line out. Emitted for every
# provider: the title box reads the region with it too.
_TFVAR_HELPER = r'''rsp_tfvar(){
  if grep -Eq "^[[:space:]]*$1[[:space:]]*=" deploy.tfvars 2>/dev/null; then
    grep -E "^[[:space:]]*$1[[:space:]]*=" deploy.tfvars | tail -1 \
      | sed -E 's/[^=]*=[[:space:]]*"?([^"#]*)"?.*/\1/' | tr -d '[:space:]'
  else
    rsp_env="TF_VAR_$1"
    printf '%s' "${!rsp_env:-}"
  fi
}
'''

_TFVARS_PREFLIGHT = {
    "gcp": r'''if [ -f deploy.tfvars ]; then
  RSP_PROJECT="$(rsp_tfvar project)"
  if [ -z "$RSP_PROJECT" ]; then
    die "project is empty in deploy.tfvars. Set it to your GCP project ID (gcloud config get-value project)."
  fi
  RSP_REGION="$(rsp_tfvar region)"; RSP_ZONE="$(rsp_tfvar zone)"
  if [ -n "$RSP_REGION" ] && [ -n "$RSP_ZONE" ]; then
    case "$RSP_ZONE" in
      "$RSP_REGION"-*) ;;
      *) die "zone $RSP_ZONE is not in region $RSP_REGION. Pick a zone that starts with $RSP_REGION-, e.g. $RSP_REGION-a." ;;
    esac
  fi
fi
''',
    "aws": r'''if [ -f deploy.tfvars ]; then
  RSP_REGION="$(rsp_tfvar region)"; RSP_ZONE="$(rsp_tfvar availability_zone)"
  if [ -n "$RSP_REGION" ] && [ -n "$RSP_ZONE" ] && [ "$RSP_ZONE" != "null" ]; then
    case "$RSP_ZONE" in
      "$RSP_REGION"[a-z]) ;;
      *) die "availability_zone $RSP_ZONE is not in region $RSP_REGION. Pick a zone that starts with $RSP_REGION, e.g. ${RSP_REGION}a." ;;
    esac
  fi
fi
''',
    "azure": r'''if [ -f deploy.tfvars ]; then
  RSP_SUB="$(rsp_tfvar subscription_id)"
  # azurerm falls back to ARM_SUBSCRIPTION_ID when subscription_id is empty.
  if [ -z "$RSP_SUB" ] && [ -z "${ARM_SUBSCRIPTION_ID:-}" ]; then
    die "subscription_id is empty in deploy.tfvars. Set it to: az account show --query id -o tsv"
  fi
fi
''',
}


_INIT = ('terraform -chdir=terraform init -input=false -upgrade >/dev/null '
         '|| die "terraform init failed -- check the provider download and your network"\n')

# Azure subscriptions differ in which VM sizes they may allocate and how many
# vCPUs and public IPs they get, and a no otherwise arrives mid-apply. After
# init, because the check asks terraform for the effective sizes. --brief keeps
# the size and quota table for a failure and makes a pass one summary line; run
# `python azure_preflight.py .` for the full table.
_AZURE_PREFLIGHT = 'phase "' + PREFLIGHT_PHASE + '"\n' + _INIT + r'''if RSP_OUT="$("$PY" azure_preflight.py . --brief 2>&1 | tr -d '\r')"; then
  printf '%s\n' "$RSP_OUT" | grep -v '^summary: ' | indent || true
  ok "$(printf '%s\n' "$RSP_OUT" | sed -n 's/^summary: //p' | tail -1)"
else
  printf '%s\n' "$RSP_OUT" | indent
  RSP_REASON="$(printf '%s\n' "$RSP_OUT" | sed -n 's/^FAIL: //p' | head -1)"
  RSP_REASON="${RSP_REASON:-the azure preflight stopped the deploy; nothing was created}"
  exit 1
fi
'''


def _rules(text):
    """Fill the rule, dot leader and width tokens deploy.sh and run.sh share."""
    return (text.replace("@@RULE@@", RULE).replace("@@THIN@@", THIN)
            .replace("@@DOTS@@", "." * 60).replace("@@DOTW@@", str(PHASE_WIDTH - 7)))


def output_helpers():
    """The bash output helpers deploy.sh opens with (phase, ok, say, die, fail)."""
    return _rules(_OUTPUT)


def _shell_word(text):
    """A single-quoted bash word holding printable ASCII only."""
    clean = "".join(c if 32 <= ord(c) < 127 else "?" for c in (text or ""))
    return "'" + clean.replace("'", "'\\''") + "'"


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
            '  die "GCP credentials are not set. Run:  gcloud auth login  &&  '
            'gcloud auth application-default login"\n'
            "fi\n"
        )
    elif provider == "aws":
        cloud_preflight = (
            "if ! aws sts get-caller-identity >/dev/null 2>&1; then\n"
            '  die "AWS credentials are not set or not working. Run:  aws configure  '
            '(then check:  aws sts get-caller-identity)"\n'
            "fi\n"
            'note "an AWS range needs Elastic IP and vCPU quota headroom, and a Kali operator" \\\n'
            '  "needs a one-time Marketplace subscription; see DEPLOYMENT-GUIDE.md if apply" \\\n'
            '  "hits a limit or an OptInRequired error."\n'
        )
    elif provider == "azure":
        # Accept either auth path: an `az login` session (az account show) OR a
        # service principal in the environment (ARM_CLIENT_ID et al, which the
        # azurerm provider reads directly and which az account show does not see).
        cloud_preflight = (
            'if ! az account show >/dev/null 2>&1 && [ -z "${ARM_CLIENT_ID:-}" ]; then\n'
            '  die "Azure credentials are not set. Run:  az login  (or set '
            "ARM_CLIENT_ID/ARM_CLIENT_SECRET/ARM_TENANT_ID/ARM_SUBSCRIPTION_ID for a "
            'service principal)"\n'
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
    # aws.py emits the scheduler role for any auto_stop, after_hours included.
    if stop and provider == "aws":
        cloud_preflight += _AWS_TTL_IAM_NOTE

    # The provision runner that lands on the jumpbox. Mode is baked in here rather
    # than branched at run time, so the emitted runner is straight-line.
    if is_range:
        gate = _RANGE_GATE
        # The jumpbox got its own pass above; the AD plays run on everything else.
        limit = " --limit 'all:!jumpboxes'"
    else:
        gate = ""
        limit = ""
    runner = _rules(_RUNNER.replace("@@GATE@@", gate).replace("@@LIMIT@@", limit))

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
            'RSP_ADDRS="$(terraform -chdir=terraform output -json redstackpro_addresses)" || { say "could not read addresses for the DNS reminder -- set the redirector A record by hand once the box is up"; RSP_ADDRS=""; }\n'
            "for pair in " + pairs + "; do\n"
            '  rsp_host="${pair##*|}"\n'
            "  rsp_ip=\"$(printf '%s' \"$RSP_ADDRS\" | \"$PY\" -c "
            "\"import json,sys;print(json.load(sys.stdin).get('${pair%%|*}',{}).get('public_address') or '')\" 2>/dev/null | tr -d '\\r' || true)\"\n"
            '  [ -n "$rsp_ip" ] || continue\n'
            # Show what the name resolves to TODAY, not just what it must become.
            # Every apply mints a new address while the canvas hands out a static
            # hostname, so a STALE record is the default state rather than an
            # accident -- and "create an A record" reads as already-done to an
            # operator whose record exists and is simply pointing at the last
            # deploy. That misread cost a whole session of beacon callbacks on
            # 2026-09-14. Printing both halves makes the delta unmissable.
            # || true: gethostbyname raises on an unresolved name (the normal first-deploy
            # case), which under set -e would kill the deploy here instead of printing the
            # "does not resolve" branch below. Keep the substitution exit 0, empty on failure.
            '  rsp_cur="$("$PY" -c "import socket;print(socket.gethostbyname(\'$rsp_host\'))" 2>/dev/null | tr -d \'\\r\' || true)"\n'
            '  if [ "$rsp_cur" = "$rsp_ip" ]; then\n'
            '    say "DNS   $rsp_host already resolves to $rsp_ip -- nothing to do"\n'
            "  else\n"
            '    say "DNS   at your DNS registrar, set this A record NOW:" \\\n'
            '      "         $rsp_host   ->   $rsp_ip"\n'
            '    if [ -n "$rsp_cur" ]; then\n'
            '      say "      it currently points at $rsp_cur -- STALE, from an earlier deploy"\n'
            "    else\n"
            '      say "      it does not resolve at all right now"\n'
            "    fi\n"
            '    say "      issuance waits ~15 min for it, then continues on a self-signed cert"\n'
            '    RSP_DNS_TODO="$RSP_DNS_TODO$rsp_host -> $rsp_ip\n"\n'
            "  fi\n"
            "done\n"
        )

    region_var = _REGION_VAR.get(provider)
    label = _PROVIDER_LABEL.get(provider, provider or "")
    where = ('RSP_WHERE="%s $(rsp_tfvar %s)"; RSP_WHERE="${RSP_WHERE%% }"\n'
             % (label, region_var)) if region_var else 'RSP_WHERE="%s"\n' % label
    logging_setup = (_LOGGING_SETUP
                     .replace("@@VERSION@@", _redstackpro_version())
                     .replace("@@PROVIDER@@", provider or "not specified")
                     .replace("@@ETA@@", _ETA[is_range]))
    script = _TEMPLATE
    for token, value in (
            ("@@JUMPBOX@@", jumpbox),
            ("@@JUMPUSER@@", platform_account(topology.get("mode"))),
            ("@@IS_RANGE@@", "true" if is_range else "false"),
            ("@@NAME@@", _shell_word(topology.get("name"))),
            ("@@PHASES@@", str(len(phase_titles(provider)))),
            ("@@OUTPUT@@", output_helpers()),
            ("@@LOGGING_SETUP@@", logging_setup),
            ("@@TFVAR_HELPER@@", _TFVAR_HELPER),
            ("@@WHERE@@", where),
            ("@@FIND_PYTHON@@", _FIND_PYTHON_DEPLOY),
            ("@@CLOUD_PREFLIGHT@@", cloud_preflight),
            ("@@TFVARS_PREFLIGHT@@", _TFVARS_PREFLIGHT.get(provider, "")),
            ("@@AZURE_PREFLIGHT@@", _AZURE_PREFLIGHT if provider == "azure" else ""),
            ("@@INIT@@", "" if provider == "azure" else _INIT),
            ("@@DNS_ACTIONS@@", dns_actions),
            ("@@RUNNER@@", runner)):
        script = script.replace(token, value)
    assert "@@" not in script, "an unfilled token in the deploy template"
    return script


# The defense half of the runner: the jumpbox pass, then the WinRM gate.
_RANGE_GATE = r'''# The jumpbox play runs FIRST, in a pass of its own. The AD loop below
# excludes jumpboxes so the portal does not ride the WinRM wait or the Windows
# retry cadence -- Guacamole and the assumed-breach foothold are how the operator
# reaches the range at all, so they must not wait on a Windows box finishing its
# boot. This pass is what provisions the jumpbox: without it the excluded play
# ran nowhere, and the range came up with no portal and no foothold account even
# though the run reported ok=1.
for i in 1 2 3; do
  stage "Jumpbox pass $i of 3"
  if play --limit jumpboxes; then say "      ok  jumpbox pass $i done in $(took "$T0")"; break; fi
  say "      FAILED  jumpbox pass $i after $(took "$T0"); retry in 60s"
  sleep 60
done
JB_RECAP="$LAST_RECAP"
# A fresh cloud Windows box sets its Administrator password a few minutes after
# WinRM starts; wait for an AUTHENTICATED win_ping before the promotion, a port
# check is not enough.
stage "Waiting for authenticated WinRM"
winrm=0
for i in $(seq 1 60); do
  ansible -i ansible/inventory.yml windows -m ansible.windows.win_ping "${C[@]}" >/dev/null 2>&1 && { winrm=1; break; }
  sleep 30
done
if [ "$winrm" = 1 ]; then
  say "      ok  WinRM answered after $(took "$T0")"
else
  say "      !! no authenticated WinRM after $(took "$T0"); running site.yml anyway"
fi
'''


# ~/provision/run.sh. run.log is the view to follow: skipped hosts hidden, a task
# banner shown only once that task reports something, failed results marked
# "!! ". run-full.log keeps every line Ansible printed. The filter is a few lines
# of python3, which the jumpbox has because ansible runs on it, and it never
# stops reading, so a fault in it cannot stall the play upstream.
_RUNNER = r'''#!/usr/bin/env bash
set -uo pipefail
cd ~/provision
export PATH="$HOME/.local/bin:$PATH" ANSIBLE_HOST_KEY_CHECKING=False
C=(-e ansible_ssh_common_args='' -e redstackpro_ssh_key_path=$HOME/.ssh/deploy-key)
# The operator's one password, in both modes. A range needs it to provision
# Windows; an ops stack needs it so a service can put the operator's own
# credential in its config instead of whatever its upstream sample shipped.
[ -f ~/provision/.labpw ] && export REDSTACKPRO_LAB_PASSWORD="$(cat ~/provision/.labpw)"
: > run.log
: > run-full.log
RULE="@@RULE@@"
THIN="@@THIN@@"
DOTS="@@DOTS@@"
START=$(date +%s)
T0=$START
say(){ printf '%s\n' "$@" | tee -a run.log run-full.log; }
took(){ s=$(( $(date +%s) - $1 )); if [ "$s" -ge 60 ]; then printf '%dm%02ds' $((s / 60)) $((s % 60)); else printf '%ds' "$s"; fi; }
stage(){ T0=$(date +%s); n=$((@@DOTW@@ - ${#1})); [ "$n" -ge 3 ] || n=3; say "" "$1 ${DOTS:0:$n} $(date +%H:%M)"; }
CONDENSE=$(cat <<'PY'
import sys
TASK = (b"TASK [", b"RUNNING HANDLER [")
PLAY = (b"PLAY [", b"PLAY RECAP")
FAIL = (b"fatal: [", b"failed: [", b"ERROR!", b"[ERROR]")
out = sys.stdout.buffer


def put(data):
    try:
        out.write(data)
        out.flush()
    except Exception:
        pass


held = b""
for line in iter(sys.stdin.buffer.readline, b""):
    try:
        text = line.strip()
        if text.startswith(b"skipping: ["):
            continue
        if line.startswith(TASK):
            held = b"\n" + line
            continue
        if not text:
            held = held or b"\n"
            continue
        if line.startswith(PLAY):
            held = b"\n"
        elif line.startswith(FAIL):
            line = b"!! " + line
        put(held + line)
        held = b""
    except Exception:
        put(line)
PY
)
LAST_RECAP=""
# The playbook's own exit status, not the filter's, decides an attempt. The
# recap of this run alone is kept for the summary at the end.
play(){
  from=$(( $(wc -l < run-full.log) + 1 ))
  ansible-playbook -i ansible/inventory.yml ansible/site.yml "$@" "${C[@]}" 2>&1 \
    | tee -a run-full.log | python3 -u -c "$CONDENSE" | tee -a run.log
  rc=${PIPESTATUS[0]}
  LAST_RECAP="$(tail -n +"$from" run-full.log | awk '/^PLAY RECAP/ {r = ""; f = 1; next} f && !NF {f = 0} f {sub(/[ \t]+$/, ""); r = r " " $0 "\n"} END {printf "%s", r}')"
  return "$rc"
}
say "$RULE" " redStackPRO provision . $(hostname) . started $(date '+%Y-%m-%d %H:%M %Z')" \
  " This view hides skipped hosts and marks failed tasks with !!" \
  " Every line Ansible printed: ~/provision/run-full.log" "$RULE"
JB_RECAP=""
@@GATE@@ok=0
for attempt in 1 2 3 4 5 6 7 8; do
  stage "site.yml attempt $attempt of 8"
  if play@@LIMIT@@; then
    say "      ok  PLAYBOOK SUCCEEDED (attempt $attempt, $(took "$T0"))"; ok=1; break
  fi
  say "      FAILED  attempt $attempt after $(took "$T0"); retry in 150s (idempotent; rides the WinRM/boot flap)"
  sleep 150
done
SITE_RECAP="$LAST_RECAP"
say "" "$RULE" " RUN EXITED ok=$ok at $(date '+%Y-%m-%d %H:%M %Z'), $(took "$START") in all" "$THIN" \
  " PLAY RECAP, the last run of each pass:"
[ -n "$JB_RECAP$SITE_RECAP" ] || say " (none: Ansible stopped before a play finished)"
for r in "$JB_RECAP" "$SITE_RECAP"; do
  [ -z "$r" ] || printf '%s\n' "$r" | tee -a run.log run-full.log
done
say "$THIN"
[ "$ok" = 1 ] || say " The last attempt failed. Lines marked !! above name the failed tasks."
say " Every line Ansible printed: ~/provision/run-full.log" "$RULE"
'''


_TEMPLATE = r"""#!/usr/bin/env bash
# Generated by redStackPRO. Do not edit; re-run the compile to regenerate.
#
# One-command deploy. The managed hosts sit on a private subnet only the jumpbox
# can reach, so this applies Terraform, then stages the Ansible tree onto the
# jumpbox and provisions from there. Run it from the export root (the directory
# holding this script, terraform/ and ansible/).
#
# Needs on your machine: terraform, ssh, tar, and Python 3.8+. Ansible is installed
# on the jumpbox automatically -- you do not need it locally. Every one of these
# ships with Git for Windows, macOS and any Linux, so this runs the same way on
# all three. On Windows run it from Git Bash, or use deploy.ps1 beside this file.
#
#   1. fill deploy.tfvars in this directory
#   2. bash deploy.sh
#
# Re-running is safe: Terraform reconciles and the playbook is idempotent.
set -uo pipefail

JUMPBOX="@@JUMPBOX@@"
IS_RANGE=@@IS_RANGE@@
JUMPUSER=@@JUMPUSER@@
RSP_NAME=@@NAME@@
RSP_PHASES=@@PHASES@@

cd "$(dirname "$0")"
@@OUTPUT@@@@LOGGING_SETUP@@
@@TFVAR_HELPER@@@@WHERE@@RSP_TITLE="redStackPRO deploy"
[ -z "$RSP_NAME" ] || RSP_TITLE="$RSP_TITLE . $RSP_NAME"
[ -z "$RSP_WHERE" ] || RSP_TITLE="$RSP_TITLE . $RSP_WHERE"
echo "$RSP_RULE"
echo " $RSP_TITLE"
echo "$RSP_RULE"

for t in terraform ssh tar; do
  command -v "$t" >/dev/null || die "$t not found on PATH -- install it first"
done

@@FIND_PYTHON@@
# The PRIVATE key whose public half is in deploy.tfvars
# (ssh_public_key), looked for where a person would expect it:
#   1. $REDSTACKPRO_SSH_KEY, when you set it
#   2. a key you dropped in keys/, beside this script
#   3. ~/.ssh/id_ed25519
# keys/ exists so the export is self contained: extract it, drop your key in,
# deploy. Nothing is ever written there by us and it is not in the download.
if [ -n "${REDSTACKPRO_SSH_KEY:-}" ]; then
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
    KEY="${RSP_KEYS# }"
  elif [ "$RSP_N" -gt 1 ]; then
    die "more than one private key in keys/:$RSP_KEYS" \
      "say which:  REDSTACKPRO_SSH_KEY=keys/<name> bash deploy.sh"
  else
    KEY="$HOME/.ssh/id_ed25519"
  fi
fi
[ -f "$KEY" ] || die "no ssh private key found." \
  "  looked at: \$REDSTACKPRO_SSH_KEY, then keys/, then $HOME/.ssh/id_ed25519" \
  "" \
  "  make one:  ssh-keygen -t ed25519 -f keys/id_ed25519 -N \"\"" \
  "  then put the contents of keys/id_ed25519.pub into" \
  "  deploy.tfvars as ssh_public_key, and re-run."

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
    KEYBASE="${TMPDIR:-/tmp}"; case "$KEYBASE" in *" "*) KEYBASE="/tmp" ;; esac
    KEYSAFE="$(mktemp "$KEYBASE/rsp-key.XXXXXX")"
    cp "$KEY" "$KEYSAFE" && chmod 600 "$KEYSAFE"
    ;;
esac
SSHKEY="${KEYSAFE:-$KEY}"
# BatchMode=yes: never fall back to an interactive password prompt. Without it, a
# fresh jumpbox whose cloud-init has not yet written redop's authorized_keys answers
# port 22 but refuses the key, ssh prompts for a password, and the "wait for ssh"
# probe below stalls on that prompt instead of retrying (and the first heredoc step
# dies with "Permission denied, please try again"). With it, the probe fails fast and
# rides out the cloud-init race, which is what its retry loop was written to do.
SSH="ssh -i $SSHKEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 -o BatchMode=yes"

@@CLOUD_PREFLIGHT@@# Refuse to apply when management ingress is open to the whole internet.
# operator_source_ranges is a tfvars value the topology validator never sees, so
# the check happens here, at apply time. A range can hold deliberately vulnerable
# hosts, so a literal 0.0.0.0/0 entry is a blocking abort, not a warning; it aborts
# the same way the auto-stop guard does, with an explicit override. Subnet-scoped
# values do not trip it: only the literal 0.0.0.0/0 does. The pattern is loose on
# spacing and quoting and catches 0.0.0.0/0 as one entry among several.
# First: it must be set at all. The export ships it commented, so a range is never
# exposed by default; the deploy stops here until the operator names their range.
if [ -f deploy.tfvars ] && ! grep -Eq '^[[:space:]]*operator_source_ranges[[:space:]]*=[[:space:]]*\[[^]]*"' deploy.tfvars; then
  # A hint only: omitted when the lookup fails or returns something unexpected.
  RSP_MYIP="$(curl -s --max-time 5 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')"
  RSP_HINT=""
  case "$RSP_MYIP" in
    ''|*[!0-9.]*) ;;
    *) RSP_HINT="  Your current public IP looks like $RSP_MYIP; use [\"$RSP_MYIP/32\"]." ;;
  esac
  die "operator_source_ranges is not set in deploy.tfvars." \
    '  Set it to the IP/CIDR operators connect from, for example ["203.0.113.5/32"].' \
    ${RSP_HINT:+"$RSP_HINT"} \
    "  A range is never exposed by default, so the deploy stops until you set this."
fi
if grep -Eq 'operator_source_ranges[^#]*"0\.0\.0\.0/0"' deploy.tfvars 2>/dev/null; then
  if [ "${REDSTACKPRO_ALLOW_OPEN_INGRESS:-0}" = "1" ]; then
    say "WARNING: operator_source_ranges is 0.0.0.0/0 (ssh and the portal are open to" \
      "         the whole internet). Narrow it in deploy.tfvars."
    # Let the Terraform precondition through too (it fails closed by default).
    export TF_VAR_allow_open_ingress=true
  else
    die "operator_source_ranges is 0.0.0.0/0, which exposes ssh and the portal to the whole internet." \
      "This range may contain deliberately vulnerable hosts, so an open range is a" \
      "mistake, not a shortcut." \
      "" \
      "  Fix:      set operator_source_ranges to your own IP/CIDR in deploy.tfvars," \
      '            for example ["203.0.113.5/32"].' \
      "  Override: REDSTACKPRO_ALLOW_OPEN_INGRESS=1 bash deploy.sh"
  fi
fi
@@TFVARS_PREFLIGHT@@# deploy.tfvars is the one config file you edit, here in the export root. Terraform
# auto-loads terraform/terraform.tfvars, so copy it into place for apply and destroy.
[ -f deploy.tfvars ] || die "deploy.tfvars not found next to this script. Fill it in first (see DEPLOYMENT-GUIDE.md)."
cp deploy.tfvars terraform/terraform.tfvars
# If ssh_public_key is left empty, derive it from the private key resolved above so
# the operator never hand-copies it and the two halves cannot drift. A value the
# operator set is kept. A tfvars value beats a TF_VAR_ env var, so the derived key
# cannot ride in the environment: the empty ssh_public_key in terraform.tfvars would
# win. Write it to a *.auto.tfvars instead, which terraform loads AFTER
# terraform.tfvars and so overrides the empty value. The file persists in terraform/,
# so a later `manage.sh teardown` (which re-copies the empty deploy.tfvars, and has no
# key to re-derive from) still destroys cleanly. stdin from /dev/null so a passphrased
# key fails fast instead of prompting.
rm -f terraform/zz-derived.auto.tfvars
if grep -Eq '^[[:space:]]*ssh_public_key[[:space:]]*=[[:space:]]*""[[:space:]]*$' deploy.tfvars; then
  RSP_PUBKEY="$(ssh-keygen -y -f "$SSHKEY" </dev/null 2>/dev/null)" || die "ssh_public_key is empty and deriving it from $KEY failed -- paste keys/<name>.pub into deploy.tfvars"
  printf 'ssh_public_key = "%s"\n' "$RSP_PUBKEY" > terraform/zz-derived.auto.tfvars
  note "ssh_public_key was empty in deploy.tfvars; derived it from $KEY"
fi
# Fail fast from here on. Without this a failed apply ran on and the user saw a
# misleading "unfilled address placeholders remain" instead of the real error;
# the tolerant spots below guard themselves (|| true, trailing true, if/&&).
# A command that stops the run without naming a reason names itself instead.
set -e
trap 'RSP_ERR="exit $? from: $BASH_COMMAND"' ERR
@@AZURE_PREFLIGHT@@
phase "Terraform apply"
@@INIT@@terraform -chdir=terraform apply -auto-approve -input=false || die "terraform apply failed (its error is above) -- nothing was provisioned." \
  "If it reports resources that already exist, an earlier run was interrupted and" \
  "left them outside the state. Reconcile with: bash manage.sh teardown --force" \
  "(then re-run deploy.sh)."
RSP_RES="$(terraform -chdir=terraform state list 2>/dev/null | grep -Evc '(^|\.)data\.' || true)"
case "$RSP_RES" in
  ''|*[!0-9]*|0) ok "applied in $(took)" ;;
  *) ok "$RSP_RES resources in $(took)" ;;
esac

phase "Fill the inventory from Terraform"
# Both modes. Terraform calls this "the shared password for the admin account,
# the Windows operator, and the portal" and emits it either way, but only a range
# used to read it back, so nothing an ops stack provisioned could reach the one
# credential the operator is actually given. A teamserver that wants to put that
# password in its own config had no way to learn it.
REDSTACKPRO_LAB_PASSWORD="$(terraform -chdir=terraform output -raw lab_password)" || die "could not read lab_password from terraform output -- did apply finish?"
# An empty value here would provision the Windows hosts and the portal with a
# blank credential, so stop rather than carry it forward.
[ -n "$REDSTACKPRO_LAB_PASSWORD" ] || die "lab_password came back empty -- apply looks incomplete; re-run before provisioning"
export REDSTACKPRO_LAB_PASSWORD
# --quiet prints one count line; run python tf_inventory.py by hand for the
# per-file list.
RSP_OUT="$("$PY" tf_inventory.py --quiet 2>&1 | tr -d '\r')" || { printf '%s\n' "$RSP_OUT" | indent; die "filling the inventory from terraform output failed"; }
# Scan the whole ansible tree (and the mode briefing, DEFENSE-/OFFENSE-BRIEFING.md),
# not a fixed pair of subdirectories: an ops export has no ansible/vars, which made
# the old grep exit non-zero on the missing path and skip the check entirely. Pipe
# to grep -q so the result is decided by whether any file still holds a token, not
# by grep's exit code over a path that may not exist.
if grep -rl "<<tf:" ansible *-BRIEFING.md 2>/dev/null | grep -q .; then
  die "unfilled address placeholders remain -- aborting"
fi
JUMP=$(terraform -chdir=terraform output -json redstackpro_addresses \
  | "$PY" -c "import json,sys;print(json.load(sys.stdin)['$JUMPBOX']['public_address'])") || die "could not read the jumpbox address from terraform output"
[ -n "$JUMP" ] || die "the jumpbox address is empty -- apply may not have created it"
@@DNS_ACTIONS@@ok "$(printf '%s\n' "$RSP_OUT" | tail -1)"

phase "Wait for the jumpbox $JUMP"
ssh-keygen -f "$HOME/.ssh/known_hosts" -R "$JUMP" >/dev/null 2>&1 || true
ok_ssh=0
for i in $(seq 1 30); do $SSH "$JUMPUSER@$JUMP" true 2>/dev/null && { ok_ssh=1; break; }; sleep 10; done
[ "$ok_ssh" = 1 ] || die "jumpbox $JUMP never accepted ssh after ~5 min -- check it booted and 22 is open to your operator_source_ranges"
ok "ssh is up after $(took)"

phase "Install prerequisites on the jumpbox"
$SSH "$JUMPUSER@$JUMP" 'bash -s' <<'BOOT' || fail "installing screen, pip and Ansible on the jumpbox failed (its output is above)"
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
# sudo drops the exported DEBIAN_FRONTEND, so it is passed to apt-get itself;
# without it debconf prints a page of "unable to initialize frontend" warnings.
if [ -n "$RSP_NEED" ]; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $RSP_NEED >/dev/null
fi
# `python3 -m pip` rather than `pip`: the Debian package installs the module but
# does not always leave a `pip` on PATH for a non-root user. The runner puts
# ~/.local/bin on PATH itself, so pip's warning that it is not is noise.
command -v ansible-playbook >/dev/null 2>&1 || ~/.local/bin/ansible-playbook --version >/dev/null 2>&1 || python3 -m pip install --user --break-system-packages -q --no-warn-script-location "ansible-core>=2.16" pypsrp PySocks requests
mkdir -p ~/provision ~/.ssh && chmod 700 ~/.ssh
BOOT
ok "screen, pip and Ansible ready in $(took)"

phase "Stage the Ansible tree and the key"
scp -i "$SSHKEY" -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$SSHKEY" "$JUMPUSER@$JUMP:.ssh/deploy-key" >/dev/null || fail "copying the connection key to the jumpbox failed"
$SSH "$JUMPUSER@$JUMP" 'chmod 600 ~/.ssh/deploy-key' || fail "setting the connection key's mode on the jumpbox failed"
# Staged with tar over ssh rather than rsync. rsync is not on a stock Windows box
# and there is no rsync package in chocolatey or winget, so requiring it meant the
# export simply could not be launched from Windows; tar ships with Git for
# Windows, macOS and every Linux. The remote delete reproduces rsync --delete:
# without it a re-deploy into a reused export would leave files the new compile no
# longer emits, and ansible would happily run them. -m: the files get the
# jumpbox's clock, not the archive's, which may be hours ahead when the download
# was stamped in another timezone and would warn once per file.
tar czf - ansible ansible.cfg \
  | $SSH "$JUMPUSER@$JUMP" 'rm -rf ~/provision/ansible ~/provision/ansible.cfg; mkdir -p ~/provision; tar xzmf - -C ~/provision' || fail "copying the Ansible tree to the jumpbox failed"
$SSH "$JUMPUSER@$JUMP" 'export PATH="$HOME/.local/bin:$PATH"; for i in 1 2 3 4 5; do ansible-galaxy collection install -r ~/provision/ansible/requirements.yml > ~/provision/galaxy.log 2>&1 && exit 0; echo "galaxy install attempt $i failed; retry in 20s" | tee -a ~/provision/galaxy.log; sleep 20; done; exit 1' || die "ansible-galaxy failed on the jumpbox after 5 tries -- see ~/provision/galaxy.log on $JUMP"

# The jumpbox provisions itself over a LOCAL connection: a cloud VM cannot ssh to
# its own public address, so its own play must not go over the network.
$SSH "$JUMPUSER@$JUMP" "grep -q 'ansible_connection: local' ~/provision/ansible/host_vars/$JUMPBOX.yml 2>/dev/null || echo 'ansible_connection: local' >> ~/provision/ansible/host_vars/$JUMPBOX.yml" || fail "setting the jumpbox's local connection failed"

printf '%s' "$REDSTACKPRO_LAB_PASSWORD" | $SSH "$JUMPUSER@$JUMP" 'cat > ~/provision/.labpw && chmod 600 ~/provision/.labpw' || fail "copying the lab password to the jumpbox failed"
ok "staged in $(took)"

phase "Write the provision runner"
$SSH "$JUMPUSER@$JUMP" "cat > ~/provision/run.sh" <<'RUNNER' || fail "writing ~/provision/run.sh on the jumpbox failed"
@@RUNNER@@RUNNER
ok "~/provision/run.sh written"

phase "Launch provisioning on the jumpbox"
# Quitting the screen does not reap the ansible-playbook it launched: that process
# reparents to init and keeps running, so a re-deploy would leave the previous run
# racing the new one over the same hosts (a hang that looks like a stall). Reap any
# lingering runner and playbook in a SEPARATE step from the launch: killing them in
# the same command that names run.sh would match that very command line and kill
# the launching shell. The bracketed patterns ([r], [p]) keep pgrep from matching
# its own command line either.
$SSH "$JUMPUSER@$JUMP" 'screen -S provision -X quit >/dev/null 2>&1; for p in $(pgrep -f "ansible-[p]laybook -i ansible/inventory.yml"); do kill -9 "$p" 2>/dev/null; done; for p in $(pgrep -f "provision/[r]un.sh"); do kill -9 "$p" 2>/dev/null; done; true' || fail "clearing an earlier provision run on the jumpbox failed"
$SSH "$JUMPUSER@$JUMP" 'chmod +x ~/provision/run.sh; screen -dmS provision ~/provision/run.sh; sleep 2; screen -ls | grep -qi provision' || die "the provision screen did not start on the jumpbox"
ok "running in screen 'provision'; it keeps going if you disconnect"
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
#   bash manage.sh teardown [--force]
#
# status, start and stop act on exactly this range's own instances, never the
# whole cloud account or project. teardown runs terraform destroy; add --force to
# first delete redStackPRO instances the cloud still has (e.g. from an interrupted
# apply) so orphaned instances cannot block the destroy.
#
# On Windows run it from Git Bash, or use manage.ps1 beside this file.
set -uo pipefail

cd "$(dirname "$0")"
say(){ echo "== [$(date +%H:%M:%S)] $* =="; }

cmd="${1:-}"
case "$cmd" in
  status|start|stop|teardown) ;;
  *)
    echo "usage: bash manage.sh status|start|stop|teardown [--force]"
    exit 1
    ;;
esac

command -v terraform >/dev/null 2>&1 || { echo "terraform not found on PATH -- install it first"; exit 1; }

'''

# teardown has two halves so a per-provider instance sweep can be injected between
# them for `--force`. The sweep deletes instances created by an interrupted apply
# but never written to state: terraform destroy cannot see them, and because they
# still hold a subnet/policy terraform does own, they make the plain destroy fail
# with resourceInUseByAnotherResource. Deleting them first unblocks it.
_MANAGE_TEARDOWN_HEAD = r'''
if [ "$cmd" = "teardown" ]; then
  # Same handoff as deploy.sh: the editable config lives at the export root as
  # deploy.tfvars and terraform auto-loads terraform/terraform.tfvars, so copy
  # it into place first, or destroy runs with no vars at all.
  [ -f deploy.tfvars ] || { echo "deploy.tfvars not found next to this script."; exit 1; }
  cp deploy.tfvars terraform/terraform.tfvars
  if [ "${2:-}" = "--force" ]; then
'''

_MANAGE_SWEEP = {
    "gcp": r'''    say "force teardown: sweeping redStackPRO instances in the cloud first"
    PROJECT="$(grep -E '^[[:space:]]*project[[:space:]]*=' deploy.tfvars 2>/dev/null | head -1 | sed -E 's/[^=]*=[[:space:]]*"?([^"]*)"?.*/\1/')"
    PROJ_ARG=""; [ -n "$PROJECT" ] && PROJ_ARG="--project $PROJECT"
    gcloud compute instances list $PROJ_ARG --filter="labels.redstackpro_kind:*" --format="value(name,zone)" 2>/dev/null \
      | tr -d '\r' | while IFS=$'\t' read -r sweep_name sweep_zone; do
          [ -n "$sweep_name" ] || continue
          echo "  deleting $sweep_name ($sweep_zone)"
          gcloud compute instances delete "$sweep_name" --zone "$sweep_zone" $PROJ_ARG --quiet 2>/dev/null || true
        done
''',
    "aws": r'''    say "force teardown: sweeping redStackPRO instances in the cloud first"
    REGION="$(grep -E '^[[:space:]]*region[[:space:]]*=' deploy.tfvars 2>/dev/null | head -1 | sed -E 's/[^=]*=[[:space:]]*"?([^"]*)"?.*/\1/')"
    REG_ARG=""; [ -n "$REGION" ] && REG_ARG="--region $REGION"
    SWEEP_IDS="$(aws ec2 describe-instances $REG_ARG --filters Name=tag:redstackpro,Values=true Name=instance-state-name,Values=pending,running,stopping,stopped --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null)"
    if [ -n "$SWEEP_IDS" ]; then
      echo "  terminating: $SWEEP_IDS"
      aws ec2 terminate-instances $REG_ARG --instance-ids $SWEEP_IDS >/dev/null 2>&1 || true
      aws ec2 wait instance-terminated $REG_ARG --instance-ids $SWEEP_IDS 2>/dev/null || true
    fi
''',
    "azure": r'''    say "force teardown: deleting the whole resource group (clears anything a failed apply left behind)"
    # A range is one dedicated resource group, so the sure way to clear an interrupted
    # deploy is to delete the group itself. terraform destroy alone stalls when a failed
    # apply left a resource it does not fully track (a stranded NIC pins its subnet, which
    # pins the VNet), and azurerm will not delete a group that still holds resources. az
    # group delete removes the group and everything in it server side, in dependency
    # order. The plain `teardown` (no --force) still uses terraform destroy, which is
    # enough after a clean apply.
    RG="$(grep -E '^[[:space:]]*resource_group[[:space:]]*=' deploy.tfvars 2>/dev/null | head -1 | sed -E 's/[^=]*=[[:space:]]*"?([^"]*)"?.*/\1/')"
    RG="${RG:-@@DEFAULT_RG@@}"
    if command -v az >/dev/null 2>&1; then
      echo "  deleting resource group $RG and every resource in it"
      az group delete -n "$RG" --yes 2>/dev/null || echo "  az group delete did not finish; terraform destroy will try next"
    else
      echo "  the az CLI is not installed, so a forced resource-group delete is not available here."
      echo "  terraform destroy runs next; if it stalls on resources a partial apply left untracked,"
      echo "  install az and re-run, or delete the resource group $RG in the portal."
    fi
''',
}

# Providers without a wired sweep still accept --force; it just means "plain
# destroy" for them rather than failing on an unknown flag.
_MANAGE_SWEEP_NONE = r'''    echo "note: a --force instance sweep is not wired for this provider; running a plain destroy."
'''

_MANAGE_TEARDOWN_TAIL = r'''  fi
  say "terraform destroy"
  terraform -chdir=terraform init -input=false -upgrade >/dev/null
  terraform -chdir=terraform destroy -auto-approve
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "teardown did not finish cleanly."
    echo "If it said an instance still holds a subnet or policy, an interrupted apply left"
    echo "instances outside the state; clear them with:  bash manage.sh teardown --force"
  fi
  exit $rc
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
# Every `read` loop strips \r: Python and gcloud on Windows end lines with \r\n,
# and Git Bash's read keeps the \r (its $() drops it), so the last field of each
# line reached the CLI with a \r on it and every call failed.
_MANAGE_PROVIDER_BLOCK = {
    "aws": r'''command -v aws >/dev/null 2>&1 || { echo "aws (the AWS CLI) not found on PATH -- install it and run: aws configure"; exit 1; }
INSTANCES="$(terraform -chdir=terraform output -json redstackpro_instances 2>/dev/null)"
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
    "gcp": r'''command -v gcloud >/dev/null 2>&1 || { echo "gcloud not found on PATH -- install the Google Cloud CLI and run: gcloud auth login"; exit 1; }
INSTANCES="$(terraform -chdir=terraform output -json redstackpro_instances 2>/dev/null)"
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
  RSP_ANY=0; RSP_FAIL=0
  while IFS=' ' read -r name zone; do
    [ -n "$name" ] || continue
    RSP_ANY=1
    gcloud compute instances describe "$name" --zone "$zone" $PROJ_ARG \
      --format='table(name,status,networkInterfaces[0].accessConfigs[0].natIP)' || RSP_FAIL=1
  done < <(printf '%s' "$INSTANCES" | "$PY" -c "import json,sys
for v in json.load(sys.stdin).values():
    print(v['name'], v['zone'])" | tr -d '\r')
  [ "$RSP_ANY" -eq 1 ] || { echo "no instances found in this range."; exit 1; }
  [ "$RSP_FAIL" -eq 0 ] || { echo "$cmd failed on at least one instance (see above)."; exit 1; }
else
  # start/stop: one gcloud call per zone acts on all that zone's instances at
  # once, instead of a blocking call per instance (a multi-VM range was slow
  # that way). --zone is required and a topology can span zones, so group first.
  RSP_ANY=0; RSP_FAIL=0
  while IFS=' ' read -r zone names; do
    [ -n "$zone" ] || continue
    RSP_ANY=1
    gcloud compute instances "$cmd" $names --zone "$zone" $PROJ_ARG || RSP_FAIL=1
  done < <(printf '%s' "$INSTANCES" | "$PY" -c "import json,sys
z={}
for v in json.load(sys.stdin).values():
    z.setdefault(v['zone'], []).append(v['name'])
for zone, names in z.items():
    print(zone, ' '.join(names))" | tr -d '\r')
  [ "$RSP_ANY" -eq 1 ] || { echo "no instances found in this range."; exit 1; }
  [ "$RSP_FAIL" -eq 0 ] || { echo "$cmd failed on at least one instance (see above)."; exit 1; }
fi
''',
    "azure": r'''command -v az >/dev/null 2>&1 || { echo "az (the Azure CLI) not found on PATH -- install it and run: az login (or az login --service-principal)"; exit 1; }
INSTANCES="$(terraform -chdir=terraform output -json redstackpro_instances 2>/dev/null)"
if [ -z "$INSTANCES" ] || [ "$INSTANCES" = "null" ]; then
  echo "no redstackpro_instances output found -- has terraform applied yet?"
  exit 1
fi
# Target this range's own VMs by name + resource group (from the output). stop
# uses deallocate, which halts billing; a plain `az vm stop` would keep charging.
RSP_ANY=0; RSP_FAIL=0
while IFS=' ' read -r vm rg; do
  [ -n "$vm" ] || continue
  RSP_ANY=1
  case "$cmd" in
    status) az vm show -g "$rg" -n "$vm" -d --query "{name:name,state:powerState,ip:publicIps}" -o table || RSP_FAIL=1 ;;
    start)  az vm start -g "$rg" -n "$vm" || RSP_FAIL=1 ;;
    stop)   az vm deallocate -g "$rg" -n "$vm" || RSP_FAIL=1 ;;
  esac
done < <(printf '%s' "$INSTANCES" | "$PY" -c "import json,sys
for v in json.load(sys.stdin).values():
    print(v['name'], v['resource_group'])" | tr -d '\r')
[ "$RSP_ANY" -eq 1 ] || { echo "no instances found in this range."; exit 1; }
[ "$RSP_FAIL" -eq 0 ] || { echo "$cmd failed on at least one instance (see above)."; exit 1; }
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

    status/start/stop are wired for aws, gcp and azure, each through its own
    CLI; teardown is provider agnostic and works everywhere."""
    ctx = Context(topology, registry)
    if not _jumpbox_name(ctx):
        return None
    provider_block = _MANAGE_PROVIDER_BLOCK.get(provider, _MANAGE_NO_LIVE_CONTROL)
    sweep = _MANAGE_SWEEP.get(provider, _MANAGE_SWEEP_NONE)
    if provider == "azure":
        from .terraform.azure import default_resource_group
        sweep = sweep.replace("@@DEFAULT_RG@@", default_resource_group(
            TerraformPlan(topology, registry, provider="azure")))
    teardown = _MANAGE_TEARDOWN_HEAD + sweep + _MANAGE_TEARDOWN_TAIL
    return (_MANAGE_HEAD + _FIND_PYTHON + teardown + _MANAGE_STATUS_PORTAL
            + provider_block)


# The Windows front door for manage.sh, the same trap and the same fix as
# DEPLOY_PS1: `bash manage.sh` at a PowerShell prompt runs WSL's bash, not Git
# Bash, so this finds Git Bash and calls it properly, forwarding every argument
# through.
MANAGE_PS1 = r"""# redStackPRO range control, for Windows PowerShell.
#
#   .\manage.ps1 status
#   .\manage.ps1 start
#   .\manage.ps1 stop
#   .\manage.ps1 teardown [--force]
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

# Every argument goes through, not just the first (teardown --force needs its
# flag), each single-quoted for bash so a space or a quote cannot split it.
function ConvertTo-BashWord([string]$s) { "'" + ($s -replace "'", "'\''") + "'" }
$fwd = ($args | ForEach-Object { ConvertTo-BashWord $_ }) -join ' '
$here = ConvertTo-BashWord ((Split-Path -Parent $MyInvocation.MyCommand.Path) -replace '\\', '/')
& $bash -lc "cd $here && bash manage.sh $fwd"
exit $LASTEXITCODE
"""
