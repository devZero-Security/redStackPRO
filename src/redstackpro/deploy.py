"""Generate the deploy.sh an export ships.

The managed hosts of a range or an offense platform sit on a private subnet that
only the jumpbox can reach, so a deploy cannot be driven from the operator's
machine: it applies Terraform, then stages the Ansible tree onto the jumpbox and
runs it there. This encodes the operational details that are otherwise easy to
get wrong -- the jumpbox provisions itself over a local connection (a cloud VM
cannot ssh to its own public address), a fresh cloud Windows box needs an
authenticated win_ping before it is promoted, and the play is idempotent so it
is retried to ride the WinRM/boot flap. See the RANGE-BRIEFING and 0022.

The script is generated (not static) because it bakes in the jumpbox's rendered
name and the topology's mode, the same way the inventory and site.yml are derived.
"""

from .naming import platform_account
from .terraform.plan import TerraformPlan
from .validate import Context


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
  echo "  Fix:      re-run the compile now -- auto_stop.after_hours counts from"
  echo "            the COMPILE, not the apply, so a fresh compile resets the clock."
  echo "  Override: REDSTACKPRO_MIN_STOP_LEAD=0 bash deploy.sh"
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


# Shipped inside keys/ so the folder survives the zip (an empty directory does
# not) and so the first person to open it is told what goes there.
KEYS_README = """# keys

Put the **private** ssh key for this deploy here, and `deploy.sh` will find it.

**macOS, Linux, Git Bash:**

    ssh-keygen -t ed25519 -f keys/id_ed25519 -N ""

**Windows PowerShell** -- note the quoting, it is not the same:

    ssh-keygen -t ed25519 -f keys\\id_ed25519 -N ''

`-N ''` with single quotes. PowerShell passes `-N ""` through as two literal
quote characters, so the key gets a passphrase of `""` instead of no passphrase.
Nothing complains at the time: it surfaces later as
`Permission denied (publickey)` from the jumpbox, after the deploy has retried
for several minutes. If that happens, check the key with
`ssh-keygen -y -P "" -f keys/id_ed25519` -- it prints the public half if the key
has no passphrase, and fails if it has one.

Then open `keys/id_ed25519.pub`, and paste its one line into
`terraform/terraform.tfvars` as `ssh_public_key`. The two halves have to match:
Terraform puts the public half on every host, and the deploy authenticates with
the private half.

`deploy.sh` looks in three places, in order:

1. `$REDSTACKPRO_SSH_KEY`, if you set it
2. a single key in this folder
3. `~/.ssh/id_ed25519`

If you keep more than one key here it will not guess between them; name the one
you want with `REDSTACKPRO_SSH_KEY=keys/<name>`.

Nothing in this folder is ever uploaded anywhere except to your own jumpbox, and
nothing here came in the download. Do not commit it.

## Change the key AFTER a deploy and it will not take

The public key is written into each host's metadata when the host is created,
and Terraform is told to ignore later changes to it, because the cloud's own
guest agent rewrites that field and every plan would otherwise show a diff that
is not yours.

So editing `ssh_public_key` in `terraform.tfvars` and re-running `deploy.sh`
does **nothing** to hosts that already exist: Terraform reads the new value,
compares it to a field it has been told to ignore, and reports no changes. Get
the key right before the first apply. If you have to change it afterwards,
either destroy and re-apply, or add it by hand, for example on GCP:

    gcloud compute instances add-metadata <host> --zone <zone> \\
      --metadata-from-file ssh-keys=<file>

and include every key already in that field, or you will remove the portal's own
access along with the old one.
"""


def _jumpbox_name(ctx):
    for node in ctx.hosts():
        if ctx.kind(node["id"]) == "jumpbox":
            return ctx.name(node["id"])
    return None


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
    is_range = topology.get("mode") == "range"

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
            'RSP_ADDRS="$(terraform -chdir=terraform output -json redstackpro_addresses)"\n'
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

    return _TEMPLATE.format(jumpbox=jumpbox,
                            jumpuser=platform_account(topology.get("mode")),
                            is_range="true" if is_range else "false",
                            gate=gate, limit=limit, dns_actions=dns_actions,
                            cloud_preflight=cloud_preflight)


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
#   1. cd terraform && fill terraform.tfvars, then cd ..
#   2. bash deploy.sh
#
# Re-running is safe: Terraform reconciles and the playbook is idempotent.
set -uo pipefail

JUMPBOX="{jumpbox}"
IS_RANGE={is_range}
JUMPUSER={jumpuser}

cd "$(dirname "$0")"
say(){{ echo "== [$(date +%H:%M:%S)] $* =="; }}

for t in terraform ssh tar; do
  command -v "$t" >/dev/null || {{ echo "$t not found on PATH -- install it first"; exit 1; }}
done

# Find a Python that actually RUNS, rather than one that merely sits on PATH.
# `command -v python3` is not enough: Windows ships a Microsoft Store stub named
# python3 that is on PATH by default, prints an advert and exits non-zero. A PATH
# check passes, and the first real call then fails for a reason that reads
# unrelated to Python. A check must execute its candidate. Same rule as the stop
# preflight below and for the same reason.
PY=""
for c in python3 python py; do
  command -v "$c" >/dev/null 2>&1 || continue
  "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' \
    >/dev/null 2>&1 && {{ PY="$c"; break; }}
done
[ -n "$PY" ] || {{
  echo "no working Python 3.8 or newer found (tried: python3, python, py)."
  echo "One of them may be on PATH but not runnable -- on Windows the Microsoft"
  echo "Store stub does exactly that. Install Python and re-run."
  exit 1
}}

# The PRIVATE key whose public half is in terraform/terraform.tfvars
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
SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20"

[ -f "$KEY" ] || {{
  echo "no ssh private key found."
  echo "  looked at: \$REDSTACKPRO_SSH_KEY, then keys/, then $HOME/.ssh/id_ed25519"
  echo
  echo "  make one:  ssh-keygen -t ed25519 -f keys/id_ed25519 -N \"\""
  echo "  then put the contents of keys/id_ed25519.pub into"
  echo "  terraform/terraform.tfvars as ssh_public_key, and re-run."
  exit 1
}}

{cloud_preflight}say "terraform apply"
terraform -chdir=terraform init -input=false -upgrade >/dev/null
terraform -chdir=terraform apply -auto-approve -input=false

# Both modes. Terraform calls this "the shared password for the admin account,
# the Windows operator, and the portal" and emits it either way, but only a range
# used to read it back, so nothing an ops stack provisioned could reach the one
# credential the operator is actually given. A teamserver that wants to put that
# password in its own config had no way to learn it.
REDSTACKPRO_LAB_PASSWORD="$(terraform -chdir=terraform output -raw lab_password)"
export REDSTACKPRO_LAB_PASSWORD

say "fill inventory addresses from terraform output"
"$PY" tf_inventory.py
# Scan the whole ansible tree (and the range briefing), not a fixed pair of
# subdirectories: an ops export has no ansible/vars, which made the old grep exit
# non-zero on the missing path and skip the check entirely. Pipe to grep -q so
# the result is decided by whether any file still holds a token, not by grep's
# exit code over a path that may not exist.
if grep -rl "<<tf:" ansible RANGE-BRIEFING.md 2>/dev/null | grep -q .; then
  echo "unfilled address placeholders remain -- aborting"; exit 1
fi

JUMP=$(terraform -chdir=terraform output -json redstackpro_addresses \
  | "$PY" -c "import json,sys;print(json.load(sys.stdin)['$JUMPBOX']['public_address'])")
say "jumpbox public address: $JUMP"
{dns_actions}

say "wait for the jumpbox to accept ssh"
ssh-keygen -f "$HOME/.ssh/known_hosts" -R "$JUMP" >/dev/null 2>&1 || true
for i in $(seq 1 30); do $SSH "$JUMPUSER@$JUMP" true 2>/dev/null && break; sleep 10; done

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
scp -i "$KEY" -o StrictHostKeyChecking=accept-new "$KEY" "$JUMPUSER@$JUMP:.ssh/deploy-key" >/dev/null
$SSH "$JUMPUSER@$JUMP" 'chmod 600 ~/.ssh/deploy-key'
# Staged with tar over ssh rather than rsync. rsync is not on a stock Windows box
# and there is no rsync package in chocolatey or winget, so requiring it meant the
# export simply could not be launched from Windows; tar ships with Git for
# Windows, macOS and every Linux. The remote delete reproduces rsync --delete:
# without it a re-deploy into a reused export would leave files the new compile no
# longer emits, and ansible would happily run them.
tar czf - ansible ansible.cfg \
  | $SSH "$JUMPUSER@$JUMP" 'rm -rf ~/provision/ansible ~/provision/ansible.cfg; mkdir -p ~/provision; tar xzf - -C ~/provision'
$SSH "$JUMPUSER@$JUMP" 'export PATH="$HOME/.local/bin:$PATH"; for i in 1 2 3 4 5; do ansible-galaxy collection install -r ~/provision/ansible/requirements.yml > ~/provision/galaxy.log 2>&1 && break; echo "galaxy install attempt $i failed; retry in 20s" | tee -a ~/provision/galaxy.log; sleep 20; done'

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
$SSH "$JUMPUSER@$JUMP" 'chmod +x ~/provision/run.sh; screen -dmS provision ~/provision/run.sh; sleep 2; screen -ls | grep -i provision'

say "provisioning launched under screen 'provision' on the jumpbox"
echo "   watch it:   ssh -i $KEY $JUMPUSER@$JUMP   then   screen -r provision"
echo "   or tail it: ssh -i $KEY $JUMPUSER@$JUMP 'tail -f ~/provision/run.log'"
echo
echo "The build continues on the jumpbox even if you disconnect. When run.log"
echo "shows 'RUN EXITED ok=1', the deploy is complete; open the Guacamole portal"
echo "at https://$JUMP/guacamole (credentials: terraform -chdir=terraform output guacamole)."
"""
