"""Export assembly.

A compile produces the complete working directory: generated code plus the
static modules and roles. Both halves live here so the API and the CLI cannot
produce different output.

Static assets ship inside the package because the API needs them at runtime.
They are still ordinary version controlled files, reviewable and editable, just
under src/redstackpro/assets/ rather than at the repo root.
"""

import copy
import os
import re
import textwrap
from pathlib import Path

from .ansible import (generate as generate_ansible, _randomize_gating,
                      apply_compile_defaults)
from .deploy import (_PROVIDER_LABEL, generate_deploy_script, generate_manage_script,
                     phase_titles)
from .naming import platform_account
from .registry import Registry
from .terraform import GenerationError
from .terraform import generate as generate_terraform

ASSETS = Path(__file__).resolve().parent / "assets"

# What has to be filled in before apply, per provider. The variables differ
# because the providers do: GCP scopes everything to a project and AWS does not.
TFVARS_TO_FILL = {
    "gcp": "project, operator_source_ranges, region, zone",
    "aws": "operator_source_ranges, region",
    "azure": "subscription_id, operator_source_ranges, location",
}

# Things the account has to have done before apply, which an export cannot do
# for you because redStackPRO touches no account.
ACCOUNT_PRECONDITIONS = {
    "aws": """
## Before apply

The Kali image is a Marketplace listing, so the account needs a one time
subscription to it before an operator box with `os: kali` will launch. Without
it `terraform apply` stops with `OptInRequired`. redStackPRO generates code and
touches no account, so this is yours to do once.
""",
}

# Provider notes for both modes, ahead of the deploy step. Its own section, apart
# from the quota note under "Notes that save an hour", so the two can change
# independently.
PROVIDER_NOTES = {
    "azure": """
## Azure: VM sizes and the preflight

Azure subscriptions differ in which VM sizes they may use in a location and in
how many vCPUs each size family gets, so a size that works on one subscription
can be refused on another. Each host takes the size of its role (jumpbox, dc,
teamserver, and so on). `deploy.tfvars` lists the roles in this topology with
their default sizes, commented out. To change some, uncomment `vm_sizes` and
keep only the roles you change; the rest keep their default:

```hcl
vm_sizes = {
  jumpbox = "Standard_D2as_v7"
}
```

After `terraform init` and before `terraform apply`, `deploy.sh` runs
`azure_preflight.py`. It asks your subscription, read only, whether each size is
offered in the location and not restricted for you, whether the regional vCPU,
per-family vCPU and public IP quotas have room, and whether the resource
providers the export needs are registered. On a problem it stops before
anything is created and says what to change: a `vm_sizes` block that fits, a
quota to raise, or a provider to register. If it cannot reach Azure it warns and
the deploy continues. `REDSTACKPRO_SKIP_PREFLIGHT=1` skips it, and
`python azure_preflight.py .` runs it on its own at any time.
""",
}

# Only when a host boots a client image. redStackPRO never sets license_type.
AZURE_CLIENT_LICENSING = """
## Azure: Windows client licensing

Hosts on Windows 10 or 11 boot Microsoft's client images, which Microsoft licenses
on Azure only for customers with a qualifying license, for example Windows
Enterprise E3 or E5 per user, a Microsoft 365 plan that includes it, or a Visual
Studio subscription for dev and test. redStackPRO does not set `license_type` on
these VMs, so license eligibility is yours to confirm; see
https://learn.microsoft.com/azure/virtual-machines/windows/windows-desktop-multitenant-hosting-deployment
"""

CLIENT_BUILDS = ("windows_10", "windows_11")


def provider_notes(document, provider):
    """The guide's provider section, plus the licensing note on an Azure export
    with a Windows client host. Reads os after apply_compile_defaults."""
    notes = PROVIDER_NOTES.get(provider, "")
    if provider == "azure" and any(
            (n.get("overlay") or {}).get("os") in CLIENT_BUILDS
            for n in (document or {}).get("nodes", [])):
        notes += AZURE_CLIENT_LICENSING
    return notes


# How to authenticate, per provider. Kept beside the tfvars list because they are
# the same kind of fact: the one thing an export cannot do for you.
CLOUD_AUTH = {
    "gcp": """```bash
gcloud auth login
gcloud auth application-default login
gcloud services enable compute.googleapis.com --project <your-project-id>
```

Run the first two. Terraform reads only the second, and only the first is obvious
when it lapses, which is how a deploy fails here with everything else set up
correctly. The third turns on the Compute Engine API, which a new project has
off; it is a no-op once it is on.""",
    "aws": """```bash
aws configure
aws sts get-caller-identity   # should name your account
```""",
    "azure": """```bash
az login
```""",
}

# The cloud's own CLI: deploy.sh checks the login with it and manage.sh runs
# status, stop, start and teardown through it. Same names, winget ids and pages
# as PROVIDER_SETUP in frontend/src/deployTarget.js.
CLI_INSTALL = {
    "gcp": ("Google Cloud CLI", "Google.CloudSDK",
            "https://cloud.google.com/sdk/docs/install"),
    "aws": ("AWS CLI", "Amazon.AWSCLI",
            "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"),
    "azure": ("Azure CLI", "Microsoft.AzureCLI",
              "https://learn.microsoft.com/cli/azure/install-azure-cli"),
}


def install_cli(provider):
    """Step 3's install paragraph, or "" when the provider has no CLI."""
    if provider not in CLI_INSTALL:
        return ""
    name, winget, docs = CLI_INSTALL[provider]
    return """Install the %s first. `deploy.sh` checks your login with it, and
`manage.sh` runs status, stop, start and teardown through it.

**Windows** (PowerShell):

```powershell
winget install -e --id %s
```

The install only updates PATH for new windows, so open a new PowerShell window in
this folder before you log in.

**macOS and Linux**: follow %s.

Then log in, from this folder:

""" % (name, winget, docs)


def _needs(provider):
    """The guide's two "What you need" phrasings, with the provider's CLI."""
    cli = CLI_INSTALL.get(provider)
    if not cli:
        return ("`terraform`, `ssh`, `tar`, and a Python 3.8+",
                "`terraform` and a Python 3.8+")
    return ("`terraform`, `ssh`, `tar`, a Python 3.8+, and the %s" % cli[0],
            "`terraform`, a Python 3.8+ and the %s (step 3)" % cli[0])


# The last step-2 bullet: what else in deploy.tfvars to check, per provider.
CONFIRM_TFVARS = {
    "gcp": """- `project`: your GCP project ID, not its name or number
  (`gcloud config get-value project`). Confirm `region` and `zone` are where you
  mean to deploy; the zone has to be inside the region.""",
    "aws": """- Confirm `region` is the one you mean to deploy into. Every subnet lands in one
  availability zone, the region's first unless you set `availability_zone` (inside
  that region). Credentials come from your AWS CLI profile, not this file.""",
    "azure": """- `subscription_id`: `az account show --query id -o tsv`. Confirm `location` is
  where you mean to deploy. `resource_group` is created by this deploy and deleted
  by teardown, so it must not already exist; keep one per range.""",
}


def auto_stop_section(document, registry=None, noun="range"):
    """The guide's auto-stop note, or "" when the topology does not stop
    itself. Read through TerraformPlan so it states the same schedule the
    export builds."""
    from .terraform.plan import TerraformPlan
    stop = TerraformPlan(document, registry).auto_stop
    if not stop:
        return ""
    hours, at = stop["after_hours"], stop["at_minute"]
    tz = stop["timezone"]
    clock = None if at is None else "%02d:%02d %s" % (at // 60, at % 60, tz)
    if hours and clock:
        when = ("daily at %s, or %d hours after the first apply if that comes "
                "first, then daily at that time" % (clock, hours))
    elif hours:
        when = "%d hours after the first apply, then daily at that time" % hours
    else:
        when = "daily at %s" % clock
    return """## Auto-stop

This %s stops itself %s.
Start it again with `bash manage.sh start` (`.\\manage.ps1 start` on Windows). The
instances are stopped, not destroyed, so it comes back as it was; disks and
reserved addresses still bill while it is stopped.

To change the time or turn it off: in the canvas, open the Inspector tab and click
empty space, then Topology settings > Auto-stop (on a shipped defense blueprint,
click Unlock to edit first), and export again.

""" % (noun, when)


# What teardown does before it deletes, shared by both guides.
TEARDOWN_ASKS = """`teardown` first shows the range name, the provider, and where it
lives, and asks you to type the range name (or `yes`); any other answer deletes
nothing. Add `--yes` to skip the question, for example in a script: without a
terminal to ask on and without `--yes`, it stops and deletes nothing. It then runs
`terraform -chdir=terraform destroy -auto-approve` after copying `deploy.tfvars`
into place, the same handoff the deploy uses. Running that command yourself from
this folder works too, as does `terraform destroy` from inside `terraform/`, once
`terraform/terraform.tfvars` is there. Teardown writes its own log to
`logs/teardown-<timestamp>.log`, named in its closing box; if a teardown fails,
attach that log to an issue."""

# What `teardown --force` deletes first, per provider. The GCP and AWS sweeps
# match this deployment's own id, so another range in the project or region is
# never touched. See deploy._SWEEP_STATE.
FORCE_SWEEP = {
    "gcp": """It first deletes this deployment's instances, then destroys the rest.
It finds them by the instances in the Terraform state
and by the `redstackpro_deploy` label every instance carries, a random id kept in
that state, so it also finds an instance an interrupted apply created but never
recorded. It never touches another deployment in the same project. With no
Terraform state it deletes no instance. The sweep covers instances only, so check
the console afterwards for a leftover static IP.""",
    "aws": """It first terminates this deployment's instances, then destroys the
rest. It finds them by the instances in the Terraform
state and by the `redstackpro_deploy` tag every instance carries, a random id kept
in that state, so it also finds an instance an interrupted apply created but never
recorded. It never touches another deployment in the same region. With no
Terraform state it terminates no instance. The sweep covers instances only, so
check the console afterwards for a leftover Elastic IP or NAT gateway.""",
    "azure": """It first deletes the deployment's resource group and everything in
it, then destroys the rest, so nothing is left billing.""",
}


# The account limits a deploy runs into, per provider. Proxmox and ESXi have none
# the export can name: the hardware is the operator's own.
QUOTA_NOTES = {
    "gcp": """
## Quotas

A large topology can exceed the default GCP per-project vCPU quota
(`CPUS_ALL_REGIONS`, 32 on many new projects); raise it before deploying. Find it
on the quotas page, https://console.cloud.google.com/iam-admin/quotas, filtered to
`CPUS_ALL_REGIONS`, and request the increase there.
""",
    "aws": """
## Quotas

AWS allows 5 Elastic IPs per region by default. A defense range takes 2 (the
jumpbox and the NAT gateway) and an offense stack 3 (the jumpbox, the NAT gateway,
and one per redirector), so the default holds only one or two at a time. The
running On-Demand Standard vCPU quota also caps a region, and a large forest or
several ranges at once can exceed a new account's default. Raise both in Service
Quotas before deploying: a shortfall (`AddressLimitExceeded`, `VcpuLimitExceeded`)
stops the apply with instances already running, and `bash manage.sh teardown`
(`.\\manage.ps1 teardown`) clears them.
""",
    "azure": """
## Quotas

Azure caps vCPUs per region twice, as a total regional quota and as a quota per
VM size family, and a large topology can exceed either. Both show in
`az vm list-usage --location <region> -o table`. A subscription can also be
barred from a size in a region, which apply reports as `SkuNotAvailable`.
""",
}

# Making the key is the OTHER place the platforms differ. Windows PowerShell 5.1
# drops an empty argument to a native program, so `-N ''` and `-N ""` both leave
# -N without a value and ssh-keygen stops; PowerShell 7 passes either. Leaving -N
# off and pressing Enter twice works on both. The key must have no passphrase:
# deploy.sh connects with BatchMode=yes.
MAKE_A_KEY = """Extract the download to its own folder, for example `C:\\redstackpro\\my-range` on
Windows or `~/redstackpro/my-range` on macOS and Linux, and open PowerShell or a
terminal in it. On Windows the path must not contain an apostrophe: `deploy.ps1`
cannot run from one. Every command in this guide runs from that folder, the one
this guide is in: `keys/` below is relative to it, and `manage.sh` runs from it
after the deploy, so keep it.

This is an SSH key you generate yourself. It is not your cloud
credentials: your cloud login (`aws configure`, `gcloud auth login`, or `az login`,
step 3) is separate and is what applies the Terraform. This key is only how you log
into the range hosts once they exist.

**macOS, Linux, or Git Bash on Windows:**

```bash
ssh-keygen -t ed25519 -f keys/id_ed25519 -N ""
```

**Windows PowerShell** (5.1 or 7). Leave `-N` off and press Enter twice when it asks
for a passphrase. The deploy needs a key with no passphrase, and Windows PowerShell
5.1 drops an empty `-N ''`, so ssh-keygen stops without writing a key:

```powershell
ssh-keygen -t ed25519 -f keys\\id_ed25519
```

That writes two files: the private key `keys/id_ed25519` (leave it in `keys/`, the
deploy finds it there) and the public key `keys/id_ed25519.pub` (step 2 can leave
`ssh_public_key` empty; the deploy fills it from this key). Already have a key? Point
at it instead: `REDSTACKPRO_SSH_KEY=/path/to/key bash deploy.sh`, or in PowerShell
`$env:REDSTACKPRO_SSH_KEY = 'C:/path/to/key'; .\\deploy.ps1`.

Get this right before the first apply. The public key is written into each host at
creation and Terraform ignores later changes to it, so changing it afterwards means
destroying and re-applying."""

# What a person sees while deploy.sh runs and on the jumpbox afterwards. The
# phase list comes from deploy.py, so the guide names the phases the script prints.
_COUNT = {7: "seven", 8: "eight"}


def _para(text):
    # A code span is kept on one line.
    held = re.sub(r"`[^`]*`", lambda m: m.group(0).replace(" ", "\0"), text)
    return textwrap.fill(held, width=82, break_long_words=False,
                         break_on_hyphens=False).replace("\0", " ")


def deploy_output(provider):
    """The guide's paragraph on deploy.sh's own output, for this provider."""
    titles = phase_titles(provider)
    n = len(titles)
    return _para(
        "The run prints %s numbered phases, from `[1/%d] %s` to `[%d/%d] %s`. Each "
        "ends on an `ok` line, and Terraform's own output stays inside its phase, "
        "because that is where a real error shows. A run that gets through ends on a "
        "`DONE` box with the portal address, the command that prints the logins, the "
        "ssh line to watch provisioning, and the log's path. A run that stops ends on "
        "a `FAILED` box naming the phase, the reason and the exit code."
        % (_COUNT.get(n, str(n)), n, titles[0], n, n, titles[-1]))


def run_log(is_range):
    """The guide's paragraph on run.log and run-full.log."""
    stages = ("`Jumpbox pass 1 of 3`, `Waiting for authenticated WinRM`, then "
              "`site.yml attempt 1 of 8`" if is_range else "`site.yml attempt 1 of 8`")
    return _para(
        "`run.log` gives each stage a heading (%s, and so on), leaves out hosts a "
        "task skipped, and marks a failed task `!!`. It ends on a `RUN EXITED` line "
        "and the last PLAY RECAP line for every host. Every line Ansible printed, "
        "skips included, is in `~/provision/run-full.log`." % stages)


# The deploy step is the one place the two platforms genuinely differ, so it is
# the one place the instructions split. Everything above and below it is shared.
# deploy.ps1 is a wrapper around the same deploy.sh, not a second implementation.
RUN_THE_DEPLOY = """**Windows** (PowerShell, from this folder):

```powershell
.\\deploy.ps1
```

`deploy.ps1` and `manage.ps1` are unsigned, so PowerShell's execution policy has
to allow them.

**macOS and Linux**:

```bash
bash deploy.sh
```

On Windows, do not run `bash deploy.sh` at a PowerShell prompt. `bash` there is
`C:\\Windows\\System32\\bash.exe`, the WSL launcher, so the deploy would run in a
different filesystem with a different home and different cloud credentials.
`deploy.ps1` finds Git Bash and calls it properly. From Git Bash itself,
`bash deploy.sh` is correct."""

README = """# {name}

Attack infrastructure for **{provider}**, generated by redStackPRO. Nothing here
has been applied and nothing here holds a credential.

**Read `OFFENSE-BRIEFING.md` next.** It lists the access model, the Guacamole
portal and operator accounts, where to fetch each operator's VPN credential, and
every host in this stack. This file is only how to stand it up.

## What you need

| | |
|---|---|
| On your machine | {machine_needs} |
| On the hosts | nothing: Ansible is installed on the jumpbox for you |
| Time | roughly 60 to 75 minutes, most of it building C2 agents |

`ssh` and `tar` are already on macOS and Linux and ship with Git for Windows;
install {install_yourself} yourself.
The deploy then runs the same way on all three.

## 1. Make an ssh key

{make_a_key}

## 2. Fill in `deploy.tfvars`

`deploy.tfvars` is in this folder, beside this guide. The deploy copies it into
`terraform/` for you, so this is the only config file you edit. Set: **{tfvars}**

- `ssh_public_key`: leave it empty and `deploy.sh` fills it from the key in
  `keys/`, or paste the one line in `keys/id_ed25519.pub`, the PUBLIC half from
  step 1. The PRIVATE half stays in `keys/` and is never pasted anywhere; the two
  halves have to match, since Terraform puts the public half on every host and
  the deploy authenticates with the private half.
- `operator_source_ranges`: the IPs operators connect from, for example
  `["203.0.113.5/32", "198.51.100.7/32"]` (one /32 per operator, or a CIDR). Your
  own public IP is what `curl https://checkip.amazonaws.com` prints. This is
  what can reach ssh and the portal, so leaving it wide open is a mistake, not a
  shortcut.
{confirm}

## 3. Authenticate to your cloud

{cloud_auth}
{preconditions}{quotas}{provider_notes}
## 4. Run the deploy

{run_the_deploy}

## What happens then

`deploy.sh` is the whole deploy. It applies the Terraform, fills the address
placeholders from `terraform output`, stages the Ansible tree onto the jumpbox,
and provisions **from the jumpbox**: the other hosts sit on a private subnet
only it can reach, so the playbook cannot be driven from your machine.

It refuses early, with a reason, if a tool is missing, if your cloud credentials
are not set, or if the build's own auto-stop would fire before it finished.

{deploy_output}

Provisioning runs in a detached `screen` and keeps going if you disconnect. The
`DONE` box prints the line that watches it, with your key and the jumpbox address
filled in, as one command that pastes into PowerShell or bash alike:

```bash
ssh -i keys/id_ed25519 {jumpuser}@<jumpbox> "tail -f ~/provision/run.log"
```

Ctrl-C stops the watching, not the build.

{run_log}

`RUN EXITED ok=1` means it is done. Then open the portal at
`https://<jumpbox>/guacamole`, with
`terraform -chdir=terraform output guacamole` for the credentials. On a
`wireguard` or `openvpn` access mode the portal is closed to the internet and
reached over the tunnel instead, so bring your VPN up first; `OFFENSE-BRIEFING.md`
has the VPN endpoint and where on the jumpbox to fetch each operator's credential.

Every run also writes a full log to `logs/deploy-<timestamp>.log`. If a deploy
fails or a range comes up wrong, that file is what to attach to a GitHub issue: it
records the versions, the provider, and every phase, its last line says how the
run ended (`result: ok`, or `result: FAILED (exit N) in phase ...`), and it is
scrubbed of secrets (private keys and passwords) when the run ends. The closing
box prints its path, and a `FAILED` box adds the link to open an issue. Bug
reports and feedback are welcome any time in GitHub Issues.

If a redirector uses Let's Encrypt, `deploy.sh` prints the exact DNS A record to
create the moment the address exists, and repeats it in the `DONE` box. Create it
while the build runs: issuance waits about 15 minutes, then carries on with a
self-signed certificate that `sudo rsp-issue-cert` can replace later without
redeploying.

## Checking the redirectors

`OFFENSE-BRIEFING.md` lists, per redirector, the domain to call, each teamserver's
URI prefix, and the gating header your payload must send. Two checks confirm the
route actually works:

```bash
python verify.py doors .
```

probes each front door from outside: it confirms the redirector forwards a request
carrying the gating header and serves the decoy to one that does not. It reads this
export, so it needs no arguments beyond the directory (`.`) and PyYAML
(`pip install pyyaml`). `python verify.py stack .` runs the from-jumpbox checks.

On the redirector itself, `sudo rsp-check` is the on-box eyeball version: web
server, decoy, per-teamserver gating, and backend reachability, in one command.

## Notes that save an hour

A Windows operator box is reached over `psrp` on 5986, not ssh. The deploy runs
Ansible on the jumpbox, which reaches it directly on the private subnet, so there
is nothing to set. To run a play against it yourself, run it from the jumpbox.

The jumpbox builds a certificate authority first and everything else validates
against it, which is why its play runs before the rest. Play order comes from the
topology, so this happens on its own.

A Windows box boots with a self-signed WinRM listener so that it is reachable at
all; an early play signs that listener from the jumpbox authority and rebinds it.
That first connection is the one place validation is off, it needs no flag from
you, and a re-run that finds the listener already signed does not repeat it.

{auto_stop}## Managing the deployment

Once it is up, `manage.ps1` (or `manage.sh` from Git Bash, macOS, or Linux) checks
on it and tears it down. Same wrapper pattern as the deploy: `.\\manage.ps1` on
Windows, `bash manage.sh` everywhere else. Run it with no command for a help
screen that says what each command does on this provider.

```powershell
.\\manage.ps1 status
.\\manage.ps1 start
.\\manage.ps1 stop
.\\manage.ps1 teardown
```

```bash
bash manage.sh status
bash manage.sh start
bash manage.sh stop
bash manage.sh teardown
```

`status` prints the Guacamole portal URL and one table with the state of every
host. `start` and `stop` act on exactly this deployment's own instances, never
the whole cloud account or project.

{teardown_asks}

To pause overnight and keep the cost down, use `bash manage.sh stop`
(`.\\manage.ps1 stop` on Windows) and then `bash manage.sh start` the next day:
this halts the instances without destroying anything, so the same deployment
comes back. Save `teardown` for when you are finished with it.

**Recovering from an interrupted deploy.** If you stop `deploy.sh` partway (Ctrl-C,
or a closed terminal), the cloud can hold instances Terraform created but did not
record in its state. A plain `teardown` cannot see those, and may fail trying to
destroy a network they still sit in. Run `bash manage.sh teardown --force` (or
`.\\manage.ps1 teardown --force`).
{force_sweep}
It asks first, the same as a plain teardown. Once a teardown finishes cleanly,
re-running `deploy.sh` starts fresh.

## What redStackPRO did not do

It did not run Terraform, hold a credential, or reach any environment. It
generated files. Everything above happens on your machine under your credentials.

The download holds no credentials, no key material and no tfvars values. The
certificate authority key is generated on your hosts at run time and never leaves
them. The shared lab password, which is also the portal password, is generated by
Terraform at apply (unless you set `lab_password` in `deploy.tfvars`) and kept in
the Terraform state under `terraform/`; read it with
`terraform -chdir=terraform output guacamole`.

Terraform is not bundled; install your own. Ansible installs itself on the jumpbox
during the deploy, so you do not need it on your machine.
"""


RANGE_README = """# {name}

A defensive range for **{provider}**: an Active Directory forest recreated
natively from the canvas, not imported or wrapped. Generated by redStackPRO.
Nothing here has been applied and nothing here holds a credential.

**Read `DEFENSE-BRIEFING.md` next.** It lists every host, account, lab user, trust
and planted weakness in this specific range. It is the source of truth for what
you are attacking; this file is only how to stand it up.

## What you need

| | |
|---|---|
| On your machine | {machine_needs} |
| On the hosts | nothing: Ansible is installed on the jumpbox for you |
| Time | roughly 45 to 75 minutes, longer for a large forest |

`ssh` and `tar` are already on macOS and Linux and ship with Git for Windows;
install {install_yourself} yourself.
The deploy then runs the same way on all three.

## 1. Make an ssh key

{make_a_key}

## 2. Fill in `deploy.tfvars`

`deploy.tfvars` is in this folder, beside this guide. The deploy copies it into
`terraform/` for you, so this is the only config file you edit. Set: **{tfvars}**

- `ssh_public_key`: leave it empty and `deploy.sh` fills it from the key in
  `keys/`, or paste the one line in `keys/id_ed25519.pub`, the PUBLIC half from
  step 1. The PRIVATE half stays in `keys/` and is never pasted anywhere; the two
  halves have to match, since Terraform puts the public half on every host and
  the deploy authenticates with the private half.
- `operator_source_ranges`: the IPs operators connect from, for example
  `["203.0.113.5/32", "198.51.100.7/32"]` (one /32 per operator, or a CIDR). Your
  own public IP is what `curl https://checkip.amazonaws.com` prints. This is
  what can reach ssh and the portal, so leaving it wide open is a mistake, not a
  shortcut.
{confirm}

## 3. Authenticate to your cloud

{cloud_auth}
{quotas}{provider_notes}
## 4. Run the deploy

{run_the_deploy}

## What happens then

`deploy.sh` is the whole deploy. It applies the Terraform, captures the shared
lab password from `terraform output` (it is never written into this export),
fills the address placeholders, stages the Ansible tree onto the jumpbox, and
builds the directory **from the jumpbox**: the controllers and members sit on a
private lab subnet only it can reach.

Standing up a forest is slower than it looks and that is expected: the deploy
waits for each fresh Windows host to answer an *authenticated* WinRM ping before
promoting it, and retries to ride the WinRM flap a freshly promoted domain
controller shows. An attempt that fails and is retried is normal, not a fault.

{deploy_output}

Provisioning runs in a detached `screen` and keeps going if you disconnect. The
`DONE` box prints the line that watches it, with your key and the jumpbox address
filled in, as one command that pastes into PowerShell or bash alike:

```bash
ssh -i keys/id_ed25519 {jumpuser}@<jumpbox> "tail -f ~/provision/run.log"
```

Ctrl-C stops the watching, not the build.

{run_log}

`RUN EXITED ok=1` means it is done. Then open the portal at
`https://<jumpbox>/guacamole`, with
`terraform -chdir=terraform output guacamole` for the credentials. The portal is
the way in: it has a tile for each host, including one that logs you in as the
range's assumed-breach user.

Every run also writes a full log to `logs/deploy-<timestamp>.log`. If a deploy
fails or the range comes up wrong, that file is what to attach to a GitHub issue:
it records the versions, the provider, and every phase, its last line says how
the run ended (`result: ok`, or `result: FAILED (exit N) in phase ...`), and it
is scrubbed of secrets when the run ends. The closing box prints its path, and a
`FAILED` box adds the link to open an issue. Bug reports and feedback are welcome
any time in GitHub Issues.

## What this builds

redStackPRO's own Terraform stands up the hosts and its own Ansible builds the
directory: the forest root and any child domains, the trusts between them, the
domain controllers, and the member servers and workstations that join them, with
the users and groups the canvas defined. There is no GOAD toolchain and no
`goad.py`. GOAD is the inspiration and the fidelity benchmark; this lab is
recreated natively from the range you drew.

## Reaching the hosts yourself

The Windows hosts are provisioned over WinRM (psrp) as the local Administrator,
whose password is the shared lab password above. A range is an isolated subnet,
so the listener is self-signed and the control node does not validate it.

A Linux member or SIEM box is reached over ssh through the jumpbox with a
ProxyJump. ssh does not pass your `-i` key to the jump host, so add it to an
agent first or the jump falls back to a password and fails:

```bash
ssh-add keys/id_ed25519
```

Working from the jumpbox itself avoids the proxy and the agent entirely.

{auto_stop}## Managing the range

Once it is up, `manage.ps1` (or `manage.sh` from Git Bash, macOS, or Linux) checks
on it and tears it down. Same wrapper pattern as the deploy: `.\\manage.ps1` on
Windows, `bash manage.sh` everywhere else. Run it with no command for a help
screen that says what each command does on this provider.

```powershell
.\\manage.ps1 status
.\\manage.ps1 start
.\\manage.ps1 stop
.\\manage.ps1 teardown
```

```bash
bash manage.sh status
bash manage.sh start
bash manage.sh stop
bash manage.sh teardown
```

`status` prints the Guacamole portal URL and one table with the state of every
host. `start` and `stop` act on exactly this range's own instances, never the
whole cloud account or project.

{teardown_asks}

To pause the range overnight and keep the cost down, use `bash manage.sh stop`
(`.\\manage.ps1 stop` on Windows) and then `bash manage.sh start` the next day:
this halts the instances without destroying anything, so the same range comes
back. Save `teardown` for when you are finished with it.

**Recovering from an interrupted deploy.** If you stop `deploy.sh` partway (Ctrl-C,
or a closed terminal), the cloud can hold instances Terraform created but did not
record in its state. A plain `teardown` cannot see those, and may fail trying to
destroy a network they still sit in. Run `bash manage.sh teardown --force` (or
`.\\manage.ps1 teardown --force`).
{force_sweep}
It asks first, the same as a plain teardown. Once a teardown finishes cleanly,
re-running `deploy.sh` starts fresh.

## What redStackPRO did not do

It did not run Terraform, hold a credential, or reach any environment. It
generated files. Everything above happens on your machine under your credentials.
Terraform is not bundled; install your own. Ansible installs itself on the jumpbox
during the deploy, so you do not need it on your machine.
"""


def _read_tree(root, prefix):
    """Static files, keyed by their path in the export."""
    files = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        files["%s/%s" % (prefix, path.relative_to(root).as_posix())] = \
            path.read_text(encoding="utf-8")
    return files


def static_files(provider="gcp"):
    """Modules for the target provider only, plus the whole role library.

    Shipping three providers' modules in one export would leave two thirds of
    the tree unreferenced, and `terraform init` reads every directory it can
    reach.
    """
    files = {}

    # provider names a directory, so it must stay a bare name inside modules/.
    # The API and CLI already refuse an unknown provider; this keeps the file
    # read safe on its own (no "../" walk out of the asset tree).
    base = os.path.normpath(str(ASSETS / "terraform/modules"))
    target = os.path.normpath(os.path.join(base, str(provider)))
    if (not re.fullmatch(r"[a-z][a-z0-9_]*", str(provider))
            or not target.startswith(base + os.sep)):
        raise FileNotFoundError("no static modules for provider %r" % provider)
    modules = Path(target)
    if not modules.is_dir():
        raise FileNotFoundError(
            "no static modules for provider %r; expected %s" % (provider, modules))
    files.update(_read_tree(modules, "terraform/modules/%s" % provider))

    # Provider-agnostic boot scripts referenced by the generated terraform via
    # file() -- the offense Windows operator's setup, delivered as a metadata key
    # and run once at boot. Shipped for every provider so the file() resolves.
    files.update(_read_tree(ASSETS / "terraform/scripts", "terraform/scripts"))

    files.update(_read_tree(ASSETS / "ansible/roles", "ansible/roles"))
    files["ansible/requirements.yml"] = (
        ASSETS / "ansible/requirements.yml").read_text(encoding="utf-8")
    files["ansible/.ansible-lint"] = (
        ASSETS / "ansible/.ansible-lint").read_text(encoding="utf-8")
    files["ansible.cfg"] = (ASSETS / "ansible.cfg").read_text(encoding="utf-8")

    tool = ASSETS / "tf_inventory.py"
    if tool.is_file():
        files["tf_inventory.py"] = tool.read_text(encoding="utf-8")
    # The scripted redirector/stack check. Self contained (stdlib + PyYAML), reads
    # the export it ships in, so it runs as `python verify.py doors .`. See verify.py
    # and the on-box `rsp-check` the redirector role installs.
    checker = ASSETS.parent / "tools" / "verify.py"
    if checker.is_file():
        files["verify.py"] = checker.read_text(encoding="utf-8")
    return files


# Every native backend knows the Windows host kinds, which in the registry is the
# `windows_image` capability. Module scope rather than a local, because the canvas
# offers the same set and test_MANAGE_providers_sync pins the two together -- this
# list and the toolbar's used to disagree, and esxi was the casualty.
RANGE_PROVIDERS = ("aws", "gcp", "proxmox", "azure", "esxi")


def compile_topology(document, registry=None, provider="gcp", region=None):
    """The whole working directory as {path: contents}.

    This is the primary artifact. The archive endpoint and the CLI
    are both formatters over it. Both an offense range and a defense range
    compile to a redStackPRO terraform + ansible working directory through the
    same native pipeline: a defense range is an Active Directory forest recreated
    natively on the canvas, not a GOAD package. GOAD is the inspiration and the
    fidelity benchmark; redStackPRO is the engine.
    """
    is_range = (document or {}).get("mode") == "defense"

    if is_range and provider not in RANGE_PROVIDERS:
        # Rather than emit a broken tree for a provider without one, say so.
        raise GenerationError(
            "a native defense range targets %s; %r is not a native range "
            "provider." % (", ".join(RANGE_PROVIDERS), provider))

    registry = registry or Registry()
    # Materialize the per-redirector gating token once, on a copy we own, so the
    # briefing and the Ansible host_vars carry the SAME value. generate_ansible
    # randomizes its own deepcopy too, but that is idempotent once the value is set
    # here, so both reads agree. See ansible._randomize_gating.
    document = copy.deepcopy(document or {})
    _randomize_gating(document)
    # Defaults for fields the canvas may leave empty (os, hostname, netbios,
    # trust type), applied once so Terraform, Ansible and the briefing agree.
    apply_compile_defaults(document)
    files = {}
    files.update(generate_terraform(document, registry, provider=provider,
                                    region=region))
    files.update(generate_ansible(document, registry, provider=provider))
    files.update(static_files(provider))
    # The Azure subscription check deploy.sh runs before apply. Stdlib only and
    # reads terraform/preflight.json, which the azure backend writes. See
    # tools/azure_preflight.py.
    if provider == "azure":
        files["azure_preflight.py"] = (
            ASSETS.parent / "tools" / "azure_preflight.py").read_text(encoding="utf-8")
    # The one-command deploy: apply Terraform, then provision from the jumpbox
    # (the managed hosts are on a private subnet only it can reach). Emitted only
    # when the topology has a jumpbox to stage through. Provider-aware: a GCP export
    # gets the cloud-auth and Kali-image preflight. See deploy.py.
    deploy = generate_deploy_script(document, registry, provider=provider)
    if deploy:
        files["deploy.sh"] = deploy
        # The Windows front door, and the folder the operator's own key goes in.
        # Both ship with the deploy or not at all: they are only meaningful when
        # there is a jumpbox to deploy through. See deploy.py for why the wrapper
        # has to exist at all (`bash` at a PowerShell prompt is the WSL launcher).
        from .deploy import DEPLOY_PS1
        files["deploy.ps1"] = DEPLOY_PS1
        # keys/ has to exist for ssh-keygen to write into and for deploy.sh to find
        # a key in, and an empty directory does not survive a zip. A dotfile, not a
        # README: the export ships exactly one doc, DEPLOYMENT-GUIDE.md, at its root.
        files["keys/.keep"] = ""
        # The config you edit lives at the export root as deploy.tfvars, not buried
        # under terraform/. deploy.sh copies it into terraform/ at apply, where
        # terraform auto-loads it for apply and destroy alike. Only moved when there
        # is a deploy to run it; a no-jumpbox export keeps terraform/terraform.tfvars
        # for a direct terraform run.
        if "terraform/terraform.tfvars" in files:
            files["deploy.tfvars"] = files.pop("terraform/terraform.tfvars")
        # Managing what deploy.sh stood up: status, start, stop, teardown.
        # Ships alongside deploy.sh/.ps1 under the same condition, a jumpbox to
        # act through, and never without it. See deploy.py generate_manage_script.
        manage_script = generate_manage_script(document, registry, provider=provider,
                                               region=region)
        if manage_script:
            files["manage.sh"] = manage_script
            from .deploy import MANAGE_PS1
            files["manage.ps1"] = MANAGE_PS1
    machine_needs, install_yourself = _needs(provider)
    files["DEPLOYMENT-GUIDE.md"] = (RANGE_README if is_range else README).format(
        name=document.get("name", "redStackPRO export"),
        provider=_PROVIDER_LABEL.get(provider, provider),
        jumpuser=platform_account((document or {}).get("mode")),
        tfvars=TFVARS_TO_FILL.get(provider, "see variables.tf"),
        machine_needs=machine_needs,
        install_yourself=install_yourself,
        cloud_auth=install_cli(provider) + CLOUD_AUTH.get(
            provider, "However your provider expects. redStackPRO never holds "
                      "a credential."),
        make_a_key=MAKE_A_KEY,
        run_the_deploy=RUN_THE_DEPLOY,
        teardown_asks=TEARDOWN_ASKS,
        force_sweep=FORCE_SWEEP.get(
            provider, "On this provider it runs a plain destroy, with no instance "
                      "sweep."),
        deploy_output=deploy_output(provider),
        run_log=run_log(is_range),
        quotas=QUOTA_NOTES.get(provider, ""),
        preconditions="" if is_range else ACCOUNT_PRECONDITIONS.get(provider, ""),
        provider_notes=provider_notes(document, provider),
        confirm=CONFIRM_TFVARS.get(
            provider, "- Confirm the connection values in `deploy.tfvars` are the "
                      "ones for your environment."),
        auto_stop=auto_stop_section(document, registry,
                                    "range" if is_range else "deployment"))
    # The hand-off summary: every box, account, lab user, trust, attack path, and
    # SIEM dashboard, joined from the document and the terraform address tokens.
    # tf_inventory fills the addresses after apply. Named by mode
    # (DEFENSE-BRIEFING.md / OFFENSE-BRIEFING.md); tf_inventory and the deploy script
    # find it by the *-BRIEFING.md glob. See briefing.py.
    from .briefing import briefing_filename, range_briefing
    files[briefing_filename((document or {}).get("mode"))] = range_briefing(
        document, registry, provider=provider)

    # Every file ships with LF line endings, uniformly across all providers and
    # both modes. This is the single choke point every export passes through, so
    # a static asset that was checked out with CRLF (or any future emitter) can
    # never leave a stray \r -- which on the operator's box would break a shell
    # script's shebang (`env: bash\r`) or a heredoc. The whole tree is text.
    return {path: _lf(contents) for path, contents in files.items()}


def _lf(text):
    """Normalize to LF."""
    return text.replace("\r\n", "\n").replace("\r", "\n")
