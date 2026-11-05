"""The export has to be launchable from Windows, macOS and Linux alike.

It was not. `deploy.sh` required rsync, which is not on a stock Windows box and
has no package in chocolatey or winget, so the README's "cd export && bash
deploy.sh" was impossible there with no route out. It also called `python3`,
which on Windows resolves to a Microsoft Store stub that sits on PATH, prints an
advert and exits non-zero.

That second one is the more interesting failure: `command -v python3` SUCCEEDS
against the stub, so the preflight passed and the script died later for a reason
that read nothing like "your Python does not work". A check must execute its
candidate, not merely find it. The executed test at the bottom is the one that
matters here; the rest would pass against a script that never runs.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from redstackpro import Registry
from redstackpro.deploy import generate_deploy_script, generate_manage_script
from redstackpro.export import compile_topology

from shipped import example

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "frontend/public"


def _bash():
    """Git Bash on Windows, or the system bash elsewhere.

    Never plain "bash" on Windows: that resolves to C:\\Windows\\System32\\bash.exe,
    the WSL launcher, which is a different filesystem with a different home. It is
    exactly the trap deploy.ps1 exists to spare the operator, so a test that fell
    into it would be testing the wrong shell.
    """
    if os.name == "nt":
        for candidate in (r"C:\Program Files\Git\bin\bash.exe",
                          r"C:\Program Files (x86)\Git\bin\bash.exe"):
            if Path(candidate).exists():
                return candidate
        return None
    return shutil.which("bash")


@pytest.fixture(scope="module")
def script():
    return generate_deploy_script(example("redstack.json"), Registry(), provider="gcp")


def _code(script, local_only=False):
    """The script with its comments removed, and optionally its remote blocks.

    These assertions are about what RUNS. Both of the words they look for still
    appear in the commentary, explaining why they are not called any more, and an
    assertion over the raw text would fail on its own explanation.

    `local_only` also drops the two heredocs that are sent to the jumpbox. What
    runs there is a known Linux box with python3 and apt, so `python3 -m pip` is
    right in the BOOT block and wrong on the operator's machine. Conflating the
    two made this file fail on the fix for a bug it had just caught.
    """
    remote = {"BOOT": False, "RUNNER": False}
    lines = []
    skipping = None
    for line in script.splitlines():
        stripped = line.strip()
        if local_only and skipping is None:
            for marker in remote:
                if "<<'%s'" % marker in stripped:
                    skipping = marker
                    break
            if skipping:
                continue
        if local_only and skipping is not None:
            if stripped == skipping:
                skipping = None
            continue
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _remote_block(script, marker):
    """The body of a heredoc sent to the jumpbox, e.g. BOOT or RUNNER."""
    body, inside = [], False
    for line in script.splitlines():
        if not inside and "<<'%s'" % marker in line:
            inside = True
            continue
        if inside:
            if line.strip() == marker:
                break
            body.append(line)
    assert body, "no %s block found in the script" % marker
    return "\n".join(body)


def test_a_wide_open_operator_source_ranges_aborts_before_apply(script):
    """operator_source_ranges left at 0.0.0.0/0 opens the jumpbox ssh and the
    Guacamole portal to the whole internet, and a range can hold deliberately
    vulnerable hosts. It is a tfvars value, not a topology field, so the topology
    validator never sees it and the check lives here. It is a BLOCKING abort before
    terraform apply, bypassable only with an explicit override env var."""
    code = _code(script)
    assert "operator_source_ranges" in code
    # The literal 0.0.0.0/0 entry is what trips it; subnet-scoped values do not.
    assert '"0\\.0\\.0\\.0/0"' in code
    # An abort with the override env var, mirroring the auto-stop guard.
    assert "REDSTACKPRO_ALLOW_OPEN_INGRESS" in code
    # The abort is before apply, and it exits.
    abort_at = code.index("REDSTACKPRO_ALLOW_OPEN_INGRESS")
    assert code.index("die ", abort_at) < code.index('phase "Terraform apply"')


def test_open_ingress_override_downgrades_the_abort_to_a_warning(script):
    """The escape hatch for an operator who truly means an open range: setting
    REDSTACKPRO_ALLOW_OPEN_INGRESS=1 prints the old warning and proceeds instead of
    aborting, the same shape as REDSTACKPRO_MIN_STOP_LEAD on the auto-stop guard."""
    code = _code(script)
    assert 'REDSTACKPRO_ALLOW_OPEN_INGRESS:-0' in code
    warn = "WARNING: operator_source_ranges is 0.0.0.0/0"
    assert warn in script
    # The message tells the user the one-line fix and the override.
    assert "REDSTACKPRO_ALLOW_OPEN_INGRESS=1 bash deploy.sh" in script


def test_the_deploy_does_not_need_rsync(script):
    """Not on Windows, and not installable there: chocolatey and winget both have
    no rsync package at all. Requiring it made the export un-launchable rather
    than inconvenient."""
    assert "rsync" not in _code(script)


def test_the_ansible_tree_is_staged_with_tar(script):
    """tar ships with Git for Windows, macOS and every Linux."""
    assert "tar czf -" in script
    assert "tar xzmf -" in script


def test_staging_still_clears_what_it_replaces(script):
    """rsync carried --delete. Without an equivalent, a re-deploy into a reused
    export leaves files the new compile no longer emits and ansible runs them."""
    stage = [line for line in script.splitlines() if "tar xzmf -" in line][0]
    assert "rm -rf ~/provision/ansible" in stage, (
        "the tar staging does not clear the old tree first: %s" % stage)


def test_the_interpreter_is_probed_by_running_it(script):
    """The whole point. A PATH check passes against the Windows Store stub."""
    code = _code(script, local_only=True)
    assert "raise SystemExit(0 if sys.version_info" in code, (
        "the probe does not execute its candidate, so a stub on PATH passes it")
    # Every LOCAL use after the probe goes through what it resolved. Scoped past
    # the probe, whose candidate list legitimately names python3, and to the
    # local half only: the jumpbox is a known Linux box and calls python3 itself.
    body = code.split('[ -n "$PY" ]', 1)[1]
    for call in ('python3 ', 'python3\t', '| python3', '$(python3'):
        assert call not in body, (
            "a later call bypasses the resolved interpreter: %r" % call)
    assert code.count('"$PY"') >= 4, (
        "fewer uses of the resolved interpreter than the script has work to do")


def test_each_jumpbox_prerequisite_is_checked_on_its_own(script):
    """Found on a live deploy, and caused by removing rsync.

    The jumpbox prerequisites used to install on a single combined test,
    `command -v rsync && command -v screen`. The GCP image ships screen but not
    pip, so that test was only ever false because rsync was missing too. Dropping
    rsync made it true on its own, nothing was installed, and the run failed two
    steps later with `pip: command not found` and then a string of ansible-galaxy
    failures that read like a network problem.
    """
    # Comments stripped: the block explains this very history in prose, and the
    # assertion below would otherwise fail on its own explanation.
    boot = _code(_remote_block(script, "BOOT"))
    assert "command -v screen" in boot
    assert "python3 -m pip --version" in boot, (
        "pip is not checked for separately, so an image with screen installs nothing")
    # And the install must not be chained off a single test again.
    assert "command -v rsync" not in boot


# Every shipped example carries a jumpbox, so each produces a deploy script.
JUMPBOX_EXAMPLES = ["minimal.json", "parallel-chains.json", "peered.json", "redstack.json"]


@pytest.mark.parametrize("name", JUMPBOX_EXAMPLES)
@pytest.mark.parametrize("provider", ["gcp", "aws"])
def test_ssh_to_the_jumpbox_is_non_interactive_everywhere(provider, name):
    """Found on a live AWS deploy (six retries, all stalled at the jumpbox).

    A fresh box answers port 22 before cloud-init has written the operator user's
    authorized_keys, so the key is briefly refused. Without BatchMode, ssh then
    prompts for a password: the wait-for-ssh probe stalls on that prompt instead of
    retrying, and the first heredoc step dies with `Permission denied, please try
    again`.

    The jumpbox SSH path is shared, the provider only swaps the preflight and the
    DNS reminder, never the connection, so the guarantee is asserted across both
    providers and every jumpbox-bearing blueprint: every operator-side ssh goes
    through $SSH, which sets BatchMode, every scp sets it too, and nothing runs a
    bare `ssh` that could fall back to a password. A not-yet-ready key then fails
    fast and the retry loop rides out the cloud-init race, the job it was written for.
    """
    script = generate_deploy_script(example(name), Registry(), provider=provider)
    assert script, (name, provider, "a jumpbox topology must produce a deploy script")
    # Operator-side only: the BOOT/RUNNER heredocs run locally on the jumpbox, where
    # a prompt cannot happen and is not the failure this guards.
    lines = _code(script, local_only=True).splitlines()

    ssh_def = [ln for ln in lines if ln.strip().startswith("SSH=")]
    assert ssh_def and all("BatchMode=yes" in ln for ln in ssh_def), (name, provider, ssh_def)

    scp_lines = [ln for ln in lines if ln.strip().startswith("scp ")]
    assert scp_lines and all("BatchMode=yes" in ln for ln in scp_lines), (name, provider, scp_lines)

    # No executed ssh bypasses $SSH. The SSH= assignment and the echoed "watch it"
    # hints do not start with "ssh ", so only a bare executed ssh would trip this.
    bare = [ln for ln in lines if ln.strip().startswith("ssh ")]
    assert not bare, (name, provider, bare)


def test_pip_is_invoked_as_a_python_module(script):
    """`pip` is not always on PATH for a non-root user even once python3-pip is
    installed; `python3 -m pip` is."""
    assert "python3 -m pip install --user" in script
    assert "|| pip install" not in script


def test_windows_gets_a_wrapper_that_avoids_the_wsl_bash(tmp_path):
    """`bash deploy.sh` at a PowerShell prompt runs WSL's bash, in a different
    filesystem with different credentials, and fails for unrelated-looking
    reasons. The wrapper names Git Bash explicitly."""
    files = compile_topology(example("redstack.json"), Registry(), provider="gcp")
    assert "deploy.ps1" in files
    wrapper = files["deploy.ps1"]
    assert "Git\\bin\\bash.exe" in wrapper
    assert "System32" in wrapper, "the wrapper does not explain the trap it avoids"


def test_the_export_ships_a_place_for_the_operators_key(tmp_path):
    """An empty directory does not survive a zip, so the folder carries a
    non-readme marker file: the export ships exactly one doc, at its root."""
    files = compile_topology(example("redstack.json"), Registry(), provider="gcp")
    assert "keys/.keep" in files


def test_the_editable_tfvars_lives_at_the_root_and_deploy_copies_it():
    """The config the operator edits ships at the export ROOT as deploy.tfvars, not
    buried under terraform/, so it is not something to hunt for. deploy.sh copies it
    into terraform/ at apply, where terraform auto-loads it for apply and destroy."""
    files = compile_topology(example("redstack.json"), Registry(), provider="gcp")
    assert "deploy.tfvars" in files
    assert "terraform/terraform.tfvars" not in files
    assert "ssh_public_key" in files["deploy.tfvars"]
    assert "cp deploy.tfvars terraform/terraform.tfvars" in files["deploy.sh"]


def test_a_no_jumpbox_export_keeps_terraform_tfvars_in_place():
    """Without a jumpbox there is no deploy.sh to copy the root file, so the tfvars
    stays under terraform/ for a direct terraform run."""
    document = {"schema_version": "0.7.0", "mode": "offense", "name": "no jumpbox",
                "nodes": [], "edges": []}
    files = compile_topology(document, Registry(), provider="gcp")
    assert "deploy.tfvars" not in files
    assert "terraform/terraform.tfvars" in files


def test_a_topology_with_no_jumpbox_gets_neither_wrapper_nor_keys():
    """Both only mean anything alongside a deploy, and a topology with no jumpbox
    has nothing to deploy through."""
    document = {"schema_version": "0.7.0", "mode": "offense", "name": "no jumpbox",
                "nodes": [], "edges": []}
    files = compile_topology(document, Registry(), provider="gcp")
    assert "deploy.sh" not in files
    assert "deploy.ps1" not in files
    assert "keys/.keep" not in files


# --------------------------------------------------------------------------
# The executed tests. Everything above would pass against a script that cannot
# run at all, which is the mistake this file is here to avoid repeating.


def _run(script_dir, stub_dir, env_extra=None):
    """Run the emitted script with ONLY the stubs and bash's own utilities.

    PATH is exported INSIDE bash rather than through the process environment. On
    Windows a POSIX `a:b:c` PATH handed to a Windows process is not what MSYS
    parses, so the setting was quietly ignored and the script ran against the
    real PATH -- which made the broken-interpreter test pass for the wrong
    reason, by finding a Python that worked. Setting it inside the shell puts it
    where POSIX semantics actually apply.
    """
    bash = _bash()
    env = dict(os.environ)
    env.pop("REDSTACKPRO_SSH_KEY", None)
    env.update(env_extra or {})
    command = 'export PATH="%s:/usr/bin:/bin"; exec bash deploy.sh' % _msys(stub_dir)
    return subprocess.run([bash, "-c", command], cwd=script_dir, env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=120)


def _msys(path):
    """C:\\x -> /c/x. A drive letter cannot go in a POSIX PATH: the colon is the
    separator, so "C:/tmp/stubs" reads as "C" plus "/tmp/stubs" and the stubs are
    never found."""
    path = Path(path)
    if path.drive:
        return "/%s%s" % (path.drive[0].lower(), path.as_posix()[2:])
    return path.as_posix()


def _stub(directory, name, body):
    path = directory / name
    path.write_text("#!/bin/sh\n%s\n" % body, encoding="utf-8", newline="\n")
    path.chmod(0o755)


@pytest.fixture
def staged(tmp_path):
    """A compiled export plus a stub PATH, with no cloud credentials anywhere.

    The absence of gcloud is deliberate and essential: it is the checkpoint
    immediately after the interpreter probe, so a run that reaches it has proved
    the probe passed, and no run can ever reach `terraform apply`.
    """
    files = compile_topology(example("redstack.json"), Registry(), provider="gcp")
    export = tmp_path / "export"
    for path, contents in files.items():
        target = export / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8", newline="\n")
    (export / "keys").mkdir(exist_ok=True)
    (export / "keys/id_ed25519").write_text("not a real key", encoding="utf-8")

    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for tool in ("terraform", "ssh", "tar"):
        _stub(stubs, tool, "exit 0")
    return export, stubs


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_python_that_is_on_path_but_broken_is_refused(staged):
    """THE regression this file exists for.

    All three candidates are present and all three fail, which is what the
    Windows Store stub does. A PATH check would pass here.
    """
    export, stubs = staged
    for name in ("python3", "python", "py"):
        _stub(stubs, name, 'echo "Python was not found; install from the Store" >&2\nexit 9009')

    done = _run(export, stubs)
    assert done.returncode == 1
    assert "no working Python" in done.stdout, done.stdout + done.stderr
    # It must not have carried on into the deploy.
    assert "] Terraform apply" not in done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_working_python_under_any_of_the_three_names_is_accepted(staged):
    """Positive control, and it proves the fallback: only `python` works here,
    which is the normal state of a Windows install.
    """
    export, stubs = staged
    _stub(stubs, "python3", 'echo stub >&2; exit 9009')
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())

    done = _run(export, stubs)
    # Past the probe, stopped at the credential check that follows it.
    assert "no working Python" not in done.stdout, done.stdout
    assert "GCP credentials are not set" in done.stdout, done.stdout + done.stderr


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_the_key_is_found_in_the_keys_folder(staged):
    """The operator drops a key beside the script and nothing else is needed."""
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())

    done = _run(export, stubs)
    assert "no ssh private key found" not in done.stdout, done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_two_keys_in_the_folder_are_not_guessed_between(staged):
    """Picking one would eventually fail an ssh handshake with a message about
    permissions, a long way from the cause."""
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    (export / "keys/another").write_text("also not a key", encoding="utf-8")

    done = _run(export, stubs)
    assert done.returncode == 1
    assert "more than one private key" in done.stdout, done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_missing_key_says_how_to_make_one(staged):
    """The old message named a path and stopped. This is the first wall a new
    user hits, so it has to carry the next step."""
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    (export / "keys/id_ed25519").unlink()

    done = _run(export, stubs, env_extra={"HOME": _msys(export / "nowhere")})
    assert done.returncode == 1
    assert "ssh-keygen -t ed25519 -f keys/id_ed25519" in done.stdout, done.stdout
    assert "ssh_public_key" in done.stdout


def test_each_provider_checks_its_credentials_before_apply():
    """GCP blocked early on ADC; AWS had no credential preflight and failed late.
    Both now verify credentials before terraform apply."""
    gcp = generate_deploy_script(example("redstack.json"), Registry(), provider="gcp")
    aws = generate_deploy_script(example("redstack.json"), Registry(), provider="aws")
    assert "gcloud auth application-default print-access-token" in gcp
    assert gcp.index("application-default print-access-token") < gcp.index('phase "Terraform apply"')
    assert "aws sts get-caller-identity" in aws
    assert aws.index("aws sts get-caller-identity") < aws.index('phase "Terraform apply"')


def _past_preflight_tfvars(export):
    """Overwrite deploy.tfvars so a run gets past the ingress/key preflight to
    terraform. Narrow ingress and a plausible public key keep every guard happy."""
    (export / "deploy.tfvars").write_text(
        'project = "p"\nregion = "us-central1"\nzone = "us-central1-a"\n'
        'ssh_public_key = "ssh-ed25519 AAAATEST test"\n'
        'operator_source_ranges = ["203.0.113.5/32"]\n',
        encoding="utf-8", newline="\n")


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_failed_apply_stops_with_its_own_error_not_the_placeholder_message(staged):
    """Found on a live GCP deploy. With no `set -e`, a failed `terraform apply` ran
    on and the run ended on the MISLEADING "unfilled address placeholders remain",
    burying the real error. It must stop at the apply with the apply's own message."""
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "gcloud", "echo token")  # pass the GCP ADC preflight
    _stub(stubs, "terraform", 'case "$*" in *apply*) exit 1;; *) exit 0;; esac')
    _past_preflight_tfvars(export)

    done = _run(export, stubs)
    assert done.returncode == 1
    assert "terraform apply failed" in done.stdout, done.stdout + done.stderr
    assert "unfilled address placeholders" not in done.stdout, done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_an_empty_lab_password_aborts_before_provisioning_a_blank_credential(staged):
    """An empty `terraform output -raw lab_password` (a partial/odd apply) would
    otherwise provision the Windows hosts and the portal with a blank credential.
    The run must stop instead of carrying an empty secret forward."""
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "gcloud", "echo token")
    # apply "succeeds" but lab_password comes back empty.
    _stub(stubs, "terraform",
          'case "$*" in *"output -raw lab_password"*) echo "";; *) exit 0;; esac')
    _past_preflight_tfvars(export)

    done = _run(export, stubs)
    assert done.returncode == 1
    assert "lab_password came back empty" in done.stdout, done.stdout + done.stderr


@pytest.fixture
def azure_staged(tmp_path):
    """A compiled AZURE export plus a stub PATH, no cloud credentials anywhere.
    Azure's deploy.sh preflight (az account show) and its fail-closed ingress are
    exercised the same executed way as the gcp path above."""
    files = compile_topology(example("redstack.json"), Registry(), provider="azure")
    export = tmp_path / "export"
    for path, contents in files.items():
        target = export / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8", newline="\n")
    (export / "keys").mkdir(exist_ok=True)
    (export / "keys/id_ed25519").write_text("not a real key", encoding="utf-8")
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for tool in ("terraform", "ssh", "tar"):
        _stub(stubs, tool, "exit 0")
    return export, stubs


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_azure_deploy_aborts_without_az_credentials(azure_staged):
    """deploy.sh emitted no credential preflight for azure before; a missing az
    login now aborts early with a one-line fix, not a terraform stack trace."""
    export, stubs = azure_staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    # az is absent from the stub PATH, so `az account show` fails -> abort.
    done = _run(export, stubs)
    assert done.returncode == 1
    assert "Azure credentials are not set" in done.stdout, done.stdout + done.stderr
    assert "] Terraform apply" not in done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_azure_deploy_aborts_on_unset_ingress(azure_staged):
    """The azure tfvars ships operator_source_ranges commented out (fail closed), so
    a run past the az credential check stops until the operator sets it."""
    export, stubs = azure_staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "az", "exit 0")  # pass the credential preflight
    done = _run(export, stubs)
    assert done.returncode == 1
    assert "operator_source_ranges is not set" in done.stdout, done.stdout
    assert "] Terraform apply" not in done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_azure_service_principal_env_passes_the_credential_preflight(azure_staged):
    """The deploy accepts a service principal (ARM_* env) in place of an az login
    session: with ARM_CLIENT_ID set the preflight passes even when az is absent, so
    the run gets past credentials to the ingress check."""
    export, stubs = azure_staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    # az absent from PATH, but a service principal is in the environment.
    done = _run(export, stubs,
                env_extra={"ARM_CLIENT_ID": "00000000-0000-0000-0000-000000000000"})
    assert "Azure credentials are not set" not in done.stdout, done.stdout
    assert "operator_source_ranges is not set" in done.stdout, done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_failed_azure_preflight_stops_before_apply(azure_staged):
    """The preflight runs after init and its failure ends the deploy there: apply
    is never called. The real script is swapped for one that fails, so this
    checks the wiring, not Azure."""
    export, stubs = azure_staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "az", "exit 0")
    calls = export / "terraform-calls.log"
    _stub(stubs, "terraform", 'echo "$*" >> "%s"; exit 0' % _msys(calls))
    (export / "deploy.tfvars").write_text(
        'subscription_id = "s"\nlocation = "eastus2"\n'
        'ssh_public_key = "ssh-ed25519 AAAATEST test"\n'
        'operator_source_ranges = ["203.0.113.5/32"]\n', encoding="utf-8", newline="\n")
    (export / "azure_preflight.py").write_text(
        'print("preflight says no"); raise SystemExit(1)\n', encoding="utf-8")

    done = _run(export, stubs)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "preflight says no" in done.stdout
    ran = calls.read_text(encoding="utf-8")
    assert "init" in ran and "apply" not in ran


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_unset_operator_source_ranges_aborts_until_set(staged):
    """The export now ships operator_source_ranges commented out (fail closed), so a
    real run must stop and say to set it, rather than deploy an unreachable range or
    an open one."""
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "gcloud", "exit 0")  # reach the ingress check after the creds check

    done = _run(export, stubs)
    assert done.returncode == 1
    assert "operator_source_ranges is not set" in done.stdout, done.stdout
    assert "] Terraform apply" not in done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_explicit_open_ingress_aborts_and_the_override_reaches_apply(staged):
    """A literal 0.0.0.0/0 the operator set themselves is a blocking abort, and only
    the explicit override carries it past."""
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "gcloud", "exit 0")
    _stub(stubs, "terraform", "exit 0")
    (export / "deploy.tfvars").write_text(
        'project = "p"\nregion = "us-central1"\nzone = "us-central1-a"\n'
        'ssh_public_key = "ssh-ed25519 AAAATEST test"\n'
        'operator_source_ranges = ["0.0.0.0/0"]\n',
        encoding="utf-8", newline="\n")

    blocked = _run(export, stubs)
    assert blocked.returncode == 1
    assert "which exposes ssh and the portal" in blocked.stdout, blocked.stdout
    assert "] Terraform apply" not in blocked.stdout

    allowed = _run(export, stubs, env_extra={"REDSTACKPRO_ALLOW_OPEN_INGRESS": "1"})
    assert "which exposes ssh and the portal" not in allowed.stdout, allowed.stdout
    assert "] Terraform apply" in allowed.stdout, allowed.stdout + allowed.stderr


def test_an_empty_ssh_public_key_is_derived_from_the_private_key(script):
    """The operator need not copy keys/<name>.pub into deploy.tfvars: when it is left
    empty, deploy.sh derives the public half from the private key it already found,
    so the two halves cannot drift and a manual copy step disappears.

    The derived key must land where terraform actually reads it. A tfvars value beats
    a TF_VAR_ env var, so exporting TF_VAR_ssh_public_key (the old approach) was silently
    overridden by the empty ssh_public_key in the copied terraform.tfvars and apply
    failed the variable validation. The key is written to a *.auto.tfvars instead, which
    terraform loads after terraform.tfvars and so wins, and which persists for teardown."""
    code = _code(script)
    assert "ssh-keygen -y -f" in code
    # Written to an auto-loaded overriding tfvars, not exported as an env var that loses.
    assert ".auto.tfvars" in code
    assert "ssh_public_key = " in code
    assert "TF_VAR_ssh_public_key" not in code


# -- the deployment log (issue-triage artifact)

def test_the_deploy_tees_a_scrubbed_log_and_points_a_failure_at_the_tracker(script):
    """Every deploy writes one timestamped log under logs/, so a user who hits a
    failed or broken deploy has a single artifact to attach to a GitHub issue. It
    is scrubbed of private keys and secret assignments before it is shared, and a
    failed run prints where the log is and where to raise the issue."""
    # One consolidated log, redirected so terraform and the provision both land in it.
    assert 'LOG="logs/deploy-' in script
    assert 'tee -a "$LOG"' in script
    # A header for triage: version and provider.
    assert "redStackPRO deploy log" in script
    from importlib.metadata import version
    assert "version:   %s" % version("redstackpro") in script
    assert "provider:  gcp" in script
    # Scrubbed on exit: private keys and secret assignments do not reach the file.
    assert "redacted private key" in script
    assert "trap finish EXIT" in script
    # A failure names the log and the issue tracker.
    assert "issues/new/choose" in script


def test_a_topology_with_no_jumpbox_has_no_deploy_script_to_log():
    """The log lives in deploy.sh, which only exists when there is a jumpbox to
    stage through, so the two appear and disappear together."""
    from shipped import example
    doc = example("redstack.json")
    doc["nodes"] = [n for n in doc["nodes"] if n["kind"] != "jumpbox"]
    doc["edges"] = [e for e in doc["edges"]
                    if not (e["source"].startswith("jump") or e["target"].startswith("jump"))]
    assert generate_deploy_script(doc, Registry()) is None


# -- manage.sh (status/start/stop/teardown, the other half of managing a deploy)

@pytest.fixture(scope="module")
def manage_script():
    return generate_manage_script(example("redstack.json"), Registry(), provider="gcp")


def test_manage_script_absent_without_a_jumpbox():
    """Nothing was deployed through a jumpbox, so there is nothing for manage.sh to
    manage. Mirrors deploy.sh's own gate."""
    doc = example("redstack.json")
    doc["nodes"] = [n for n in doc["nodes"] if n["kind"] != "jumpbox"]
    doc["edges"] = [e for e in doc["edges"]
                    if not (e["source"].startswith("jump") or e["target"].startswith("jump"))]
    assert generate_manage_script(doc, Registry()) is None


def test_manage_script_has_all_four_subcommands(manage_script):
    for word in ("status", "start", "stop", "teardown"):
        assert word in manage_script
    assert "usage: bash manage.sh status|start|stop|teardown" in manage_script


def test_manage_script_rejects_an_unknown_subcommand(manage_script):
    usage = manage_script.index("usage: bash manage.sh")
    exit1 = manage_script.index("exit 1", usage)
    assert exit1 > usage, "an unrecognized subcommand does not print usage and stop"


@pytest.mark.parametrize("provider", ["gcp", "aws", "azure"])
def test_manage_read_loops_strip_carriage_returns(provider):
    """Python and gcloud on Windows end lines with \\r\\n, and Git Bash's read keeps
    the \\r, so every name a read loop handed the CLI ended in \\r. Found live from
    Windows on Azure: az vm show answered Bad Request for every VM."""
    script = generate_manage_script(example("redstack.json"), Registry(), provider=provider)
    lines = script.splitlines()
    loops = 0
    for i, line in enumerate(lines):
        if "done < <(" in line:
            loops += 1
            # the line that closes the python -c string ends the substitution
            j = i
            while not (lines[j].rstrip().endswith('")') or "| tr -d" in lines[j]):
                j += 1
            assert "tr -d '\\r')" in lines[j], "read loop input keeps \\r: " + lines[j]
        if "| while" in line and "read -r" in line:
            loops += 1
            assert "tr -d '\\r' |" in line, "piped read loop keeps \\r: " + line
    if provider in ("gcp", "azure"):
        assert loops, "expected the per-instance read loops"


def test_teardown_copies_deploy_tfvars_before_destroying(manage_script):
    """Same handoff as deploy.sh: the editable config lives at the export root as
    deploy.tfvars, and terraform only auto-loads terraform/terraform.tfvars, so
    destroy needs that copy too or it runs with no vars at all."""
    teardown = manage_script[manage_script.index('"$cmd" = "teardown"'):]
    assert "cp deploy.tfvars terraform/terraform.tfvars" in teardown
    copy_at = teardown.index("cp deploy.tfvars")
    destroy_at = teardown.index("terraform -chdir=terraform destroy -auto-approve")
    assert copy_at < destroy_at


def test_status_start_stop_never_run_before_the_teardown_check(manage_script):
    """teardown must not fall through into the instance lookup meant for the
    other three subcommands: it has its own exit, before either one is reached."""
    teardown_at = manage_script.index('"$cmd" = "teardown"')
    exit_at = manage_script.index("exit $rc", teardown_at)
    status_at = manage_script.index('"$cmd" = "status"', teardown_at)
    instances_at = manage_script.index("redstackpro_instances", teardown_at)
    assert teardown_at < exit_at < status_at < instances_at


def test_status_prints_the_guacamole_portal_url(manage_script):
    assert 'output -json guacamole' in manage_script
    assert "portal:" in manage_script


def test_aws_targets_instances_by_id():
    aws = generate_manage_script(example("redstack.json"), Registry(), provider="aws")
    assert "redstackpro_instances" in aws
    assert "aws ec2 start-instances --instance-ids" in aws
    assert "aws ec2 stop-instances --instance-ids" in aws
    assert "aws ec2 describe-instances --instance-ids" in aws
    assert "gcloud" not in aws


def test_gcp_targets_instances_by_name_and_zone():
    gcp = generate_manage_script(example("redstack.json"), Registry(), provider="gcp")
    assert "redstackpro_instances" in gcp
    # status describes each instance; start/stop batch a zone's instances into a
    # single call ("$cmd" is start or stop) instead of one blocking call each.
    assert 'gcloud compute instances describe "$name" --zone "$zone"' in gcp
    assert 'gcloud compute instances "$cmd" $names --zone "$zone"' in gcp


def test_teardown_force_sweeps_orphan_instances_before_destroy():
    """Found on a live GCP deploy: an interrupted apply orphaned instances (created
    but never in state), which terraform destroy could not clean and which blocked
    it. teardown --force deletes redStackPRO instances by label/tag first, scoped to
    the deploy, so the destroy can finish. A failed destroy also points here."""
    gcp = generate_manage_script(example("redstack.json"), Registry(), provider="gcp")
    aws = generate_manage_script(example("redstack.json"), Registry(), provider="aws")
    for s in (gcp, aws):
        assert '"${2:-}" = "--force"' in s, "teardown --force is recognized"
        assert "manage.sh teardown --force" in s, "a failed destroy points at --force"
    assert "labels.redstackpro_kind" in gcp and "gcloud compute instances delete" in gcp
    assert "tag:redstackpro,Values=true" in aws and "aws ec2 terminate-instances" in aws
    assert "aws ec2" not in gcp


def test_aws_auto_stop_warns_about_iam_before_apply():
    """auto_stop's first resources are an IAM role + policy; a restricted caller
    fails there on a resource they never added. deploy.sh says so up front on aws,
    and only when a TTL is actually set."""
    doc = example("redstack.json")
    doc["auto_stop"] = {"enabled": True, "at": "02:00"}
    aws = generate_deploy_script(doc, Registry(), provider="aws")
    assert "iam:CreateRole" in aws
    gcp = generate_deploy_script(doc, Registry(), provider="gcp")
    assert "iam:CreateRole" not in gcp
    no_ttl = generate_deploy_script(example("redstack.json"), Registry(), provider="aws")
    assert "iam:CreateRole" not in no_ttl


def test_aws_iam_note_also_covers_an_after_hours_ttl():
    """minimalc2-cli ships auto_stop.after_hours and no fixed `at`. The IAM role
    is created for that too, but the note sat inside the fixed-`at` branch, so
    the shipped blueprint applied with no warning at all."""
    from shipped import load
    doc = load(TEMPLATES / "minimalc2-cli.json")
    assert doc["auto_stop"].get("after_hours") and not doc["auto_stop"].get("at")
    files = compile_topology(doc, Registry(), provider="aws")
    terraform = "".join(v for k, v in files.items() if k.startswith("terraform/"))
    assert 'resource "aws_iam_role" "auto_stop"' in terraform
    assert "iam:CreateRole" in files["deploy.sh"]
    gcp = generate_deploy_script(doc, Registry(), provider="gcp")
    assert "iam:CreateRole" not in gcp


def test_an_untested_provider_still_gets_teardown_but_says_so_for_the_rest():
    """aws, gcp and azure are wired for live status/start/stop. A provider without
    that support must not block the export or the teardown path, which is
    provider agnostic; it just has to say plainly that the rest is not there."""
    other = generate_manage_script(example("redstack.json"), Registry(), provider="proxmox")
    assert other is not None
    assert "terraform -chdir=terraform destroy -auto-approve" in other
    assert "not implemented" in other


def test_azure_is_wired_for_live_control_and_a_credential_preflight():
    """Azure gained status/start/stop (stop via deallocate so it halts billing), a
    --force teardown that deletes the whole dedicated resource group, and an
    `az account show` credential preflight it did not have before (deploy.sh emitted
    an empty preflight for azure)."""
    manage = generate_manage_script(example("redstack.json"), Registry(), provider="azure")
    assert "az vm start" in manage and "az vm deallocate" in manage
    # --force deletes the whole range resource group, so an interrupted apply that
    # stranded an untracked NIC (which pins its subnet, then the VNet) still clears.
    assert "az group delete" in manage
    assert "not implemented" not in manage
    deploy = generate_deploy_script(example("redstack.json"), Registry(), provider="azure")
    assert "az account show" in deploy


def test_MANAGE_sh_is_syntactically_valid_bash(manage_script):
    """The executed check for this file: a template edited by hand is exactly
    how a stray unmatched brace or quote gets shipped to every export."""
    bash = _bash()
    if bash is None:
        pytest.skip("no bash to syntax-check the emitted script")
    done = subprocess.run([bash, "-n", "-c", manage_script],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_MANAGE_ps1_wraps_git_bash_and_forwards_the_subcommand(tmp_path):
    files = compile_topology(example("redstack.json"), Registry(), provider="gcp")
    assert "manage.ps1" in files
    wrapper = files["manage.ps1"]
    assert "Git\\bin\\bash.exe" in wrapper
    assert "System32" in wrapper, "the wrapper does not explain the trap it avoids"
    assert "manage.sh" in wrapper


def test_MANAGE_ps1_forwards_every_argument_not_just_the_first():
    """It used to forward $args[0] alone, so `.\\manage.ps1 teardown --force`
    silently ran a plain teardown, the one that cannot clear an interrupted
    apply."""
    from redstackpro.deploy import MANAGE_PS1
    assert "$args[0]" not in MANAGE_PS1
    assert "$args | ForEach-Object" in MANAGE_PS1
    assert "bash manage.sh $fwd" in MANAGE_PS1


def _powershell():
    if os.name != "nt":
        return None
    return shutil.which("powershell") or shutil.which("pwsh")


def test_MANAGE_ps1_hands_teardown_force_to_manage_sh(tmp_path):
    """Executed: the wrapper runs a stub manage.sh that echoes what it got. A
    space and an apostrophe ride along to prove each argument stays one word."""
    from redstackpro.deploy import MANAGE_PS1
    ps = _powershell()
    if ps is None or _bash() is None:
        pytest.skip("needs Windows PowerShell and Git Bash")
    (tmp_path / "manage.ps1").write_text(MANAGE_PS1, encoding="utf-8")
    (tmp_path / "manage.sh").write_text(
        "printf '[%s]\\n' \"$@\"\n", encoding="utf-8", newline="\n")
    done = subprocess.run(
        [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(tmp_path / "manage.ps1"), "teardown", "--force", "a b", "it's"],
        capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    got = [line for line in done.stdout.splitlines() if line.startswith("[")]
    assert got == ["[teardown]", "[--force]", "[a b]", "[it's]"], done.stdout


def test_manage_scripts_ship_only_alongside_the_deploy():
    """Both only mean anything once something has been deployed through a
    jumpbox, exactly like deploy.sh/deploy.ps1."""
    doc = {"schema_version": "0.7.0", "mode": "offense", "name": "no jumpbox",
           "nodes": [], "edges": []}
    files = compile_topology(doc, Registry(), provider="gcp")
    assert "manage.sh" not in files
    assert "manage.ps1" not in files


# -- manage.sh live control, executed against stub CLIs

_INSTANCES = {
    "aws": '{"jump": {"instance_id": "i-0123"}}',
    "gcp": '{"jump": {"name": "jump", "zone": "us-east4-a"}}',
    "azure": '{"jump": {"name": "jump", "resource_group": "rg"}}',
}
_CLI = {"aws": "aws", "gcp": "gcloud", "azure": "az"}


def _manage_staged(tmp_path, provider, cli_body):
    files = compile_topology(example("redstack.json"), Registry(), provider=provider)
    export = tmp_path / "export"
    for path, contents in files.items():
        target = export / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8", newline="\n")
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    _stub(stubs, "terraform", "case \"$*\" in *redstackpro_instances*) echo '%s' ;; "
                              "*) echo '{}' ;; esac" % _INSTANCES[provider])
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    if cli_body is not None:
        _stub(stubs, _CLI[provider], cli_body)
    command = 'export PATH="%s:/usr/bin:/bin"; exec bash manage.sh status' % _msys(stubs)
    return subprocess.run([_bash(), "-c", command], cwd=export, env=dict(os.environ),
                          capture_output=True, text=True, timeout=120)


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
@pytest.mark.parametrize("provider", ["aws", "gcp", "azure"])
def test_manage_fails_loudly_when_the_cloud_cli_is_missing_or_fails(tmp_path, provider):
    """Live 2026-11-04: on a box without az, `manage.sh stop` printed `az: command
    not found` per VM and exited 0, so a range that kept billing read as stopped.
    The CLI is checked up front, and any failed call makes the run exit nonzero."""
    missing = _manage_staged(tmp_path / "missing", provider, None)
    assert missing.returncode == 1, missing.stdout + missing.stderr
    assert "%s" % _CLI[provider] in missing.stdout and "not found on PATH" in missing.stdout
    failing = _manage_staged(tmp_path / "failing", provider, "echo boom >&2; exit 1")
    assert failing.returncode != 0, failing.stdout + failing.stderr
    working = _manage_staged(tmp_path / "working", provider, "exit 0")
    assert working.returncode == 0, working.stdout + working.stderr


# -- deploy.tfvars values that otherwise fail deep inside terraform

def _tfvars(export, body):
    (export / "deploy.tfvars").write_text(body, encoding="utf-8", newline="\n")


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_unset_ingress_suggests_the_callers_public_ip(staged):
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "gcloud", "exit 0")
    _stub(stubs, "curl", "echo 198.51.100.23")
    done = _run(export, stubs)
    assert done.returncode == 1
    assert ('Your current public IP looks like 198.51.100.23; use '
            '["198.51.100.23/32"].') in done.stdout, done.stdout

    _stub(stubs, "curl", "exit 7")
    done = _run(export, stubs)
    assert done.returncode == 1
    assert "operator_source_ranges is not set" in done.stdout
    assert "looks like" not in done.stdout, done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_an_empty_gcp_project_stops_before_terraform(staged):
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "gcloud", "exit 0")
    _tfvars(export, 'project        = ""\nregion = "us-central1"\nzone = "us-central1-a"\n'
                    'ssh_public_key = ""\noperator_source_ranges = ["203.0.113.5/32"]\n')
    done = _run(export, stubs)
    assert done.returncode == 1
    assert ("project is empty in deploy.tfvars. Set it to your GCP project ID "
            "(gcloud config get-value project).") in done.stdout, done.stdout
    assert "] Terraform apply" not in done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_zone_outside_the_region_stops_before_terraform(staged):
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "gcloud", "exit 0")
    _tfvars(export, 'project = "p"\nregion = "us-central1"\nzone   = "us-east4-a"  # moved\n'
                    'ssh_public_key = ""\noperator_source_ranges = ["203.0.113.5/32"]\n')
    done = _run(export, stubs)
    assert done.returncode == 1
    assert ("zone us-east4-a is not in region us-central1. Pick a zone that starts "
            "with us-central1-, e.g. us-central1-a.") in done.stdout, done.stdout
    assert "] Terraform apply" not in done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_an_empty_azure_subscription_stops_unless_the_environment_names_one(azure_staged):
    export, stubs = azure_staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    _stub(stubs, "az", "exit 0")
    _tfvars(export, 'subscription_id = ""\nlocation = "eastus2"\n'
                    'ssh_public_key = "ssh-ed25519 AAAATEST test"\n'
                    'operator_source_ranges = ["203.0.113.5/32"]\n')
    done = _run(export, stubs)
    assert done.returncode == 1
    assert ("subscription_id is empty in deploy.tfvars. Set it to: az account show "
            "--query id -o tsv") in done.stdout, done.stdout

    done = _run(export, stubs, env_extra={"ARM_SUBSCRIPTION_ID": "s"})
    assert "subscription_id is empty" not in done.stdout, done.stdout


def test_aws_checks_the_availability_zone_against_the_region():
    body = generate_deploy_script(example("redstack.json"), Registry(), provider="aws")
    assert "availability_zone $RSP_ZONE is not in region $RSP_REGION" in body
    assert body.index("rsp_tfvar availability_zone") < body.index('phase "Terraform apply"')


@pytest.mark.parametrize("path", [
    "src/redstackpro/assets/tf_inventory.py",
    "src/redstackpro/tools/verify.py",
    "src/redstackpro/tools/azure_preflight.py",
])
def test_scripts_the_export_ships_parse_as_python_3_8(path):
    # deploy.sh accepts Python 3.8+, and these run on the user's machine.
    import ast
    src = (Path(__file__).resolve().parents[1] / path).read_text(encoding="utf-8")
    ast.parse(src, feature_version=(3, 8))


def test_deploy_accepts_python_3_8_like_the_guide_says(script):
    assert "sys.version_info >= (3, 8)" in script


# -- what the deploy prints: numbered phases, the DONE and FAILED boxes, the log's
# result line, and the condensed run.log on the jumpbox

import re

from redstackpro.deploy import DEPLOY_PS1, PHASE_WIDTH, output_helpers, phase_titles

from shipped import load

GOAD_LIGHT = TEMPLATES / "goad/goad-light.json"
JUMP_IP = "20.114.255.159"


@pytest.mark.parametrize("provider", ["gcp", "aws", "azure"])
def test_phases_are_numbered_against_the_count_the_script_prints(provider):
    """N in [n/N] is baked in, and a phase only Azure has must not leave the
    others counting to a number they never reach."""
    script = generate_deploy_script(example("redstack.json"), Registry(), provider=provider)
    called = re.findall(r'^phase "([^"]+)"$', _code(script, local_only=True), re.M)
    assert called == list(phase_titles(provider))
    assert len(called) == (8 if provider == "azure" else 7)
    assert "\nRSP_PHASES=%d\n" % len(called) in script


@pytest.mark.skipif(_bash() is None, reason="no bash to run the helpers")
def test_the_phase_and_ok_lines_render_as_designed():
    body = output_helpers() + "\n".join([
        "RSP_PHASES=8",
        'phase "Preflight: VM sizes, quota, providers"',
        'ok "5 VMs on Standard_D2as_v7, quota 10 of 10 vCPU"',
        'phase "Terraform apply"',
        "RSP_T0=$(( $(date +%s) - 417 ))",
        'ok "47 resources in $(took)"',
        'phase "Wait for the jumpbox %s"' % JUMP_IP,
        "ok",
    ])
    done = subprocess.run([_bash(), "-c", body], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    lines = re.sub(r"\d\d:\d\d$", "HH:MM", done.stdout, flags=re.M).splitlines()
    assert lines[0] == lines[3] == lines[6] == ""
    assert lines[1] == "[1/8] Preflight: VM sizes, quota, providers ........ HH:MM"
    assert lines[2] == "      ok  5 VMs on Standard_D2as_v7, quota 10 of 10 vCPU"
    assert lines[4] == "[2/8] Terraform apply .............................. HH:MM"
    assert re.fullmatch(r"      ok  47 resources in 6m5[78]s", lines[5]), lines[5]
    assert lines[7] == "[3/8] Wait for the jumpbox %s .......... HH:MM" % JUMP_IP
    assert lines[8] == "      ok"
    assert {len(lines[i]) for i in (1, 4, 7)} == {PHASE_WIDTH}


@pytest.mark.skipif(_bash() is None, reason="no bash to run the helpers")
def test_die_exits_1_and_fail_keeps_the_failed_commands_status():
    """fail replaced bare set -e exits, so it must keep their codes."""
    for line, rc in (('die "nope" "detail"', 1), ('(exit 100) || fail "boot failed"', 100)):
        done = subprocess.run([_bash(), "-c", output_helpers() + line],
                              capture_output=True, text=True)
        assert done.returncode == rc, (line, done.stdout, done.stderr)
        assert done.stdout.startswith("      ")


def _range_export(tmp_path, preflight="pass", boot_rc=0):
    """An Azure defense export, its stub PATH, and the calls terraform saw. Every
    step runs; only the network and the cloud are stubbed."""
    doc = load(GOAD_LIGHT)
    files = compile_topology(doc, Registry(), provider="azure")
    export = tmp_path / "export"
    for path, contents in files.items():
        target = export / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8", newline="\n")
    (export / "keys/id_ed25519").write_text("not a real key", encoding="utf-8")
    (export / "deploy.tfvars").write_text(
        'subscription_id = "s"\nlocation = "eastus2"\n'
        'ssh_public_key = "ssh-ed25519 AAAATEST test"\n'
        'operator_source_ranges = ["203.0.113.5/32"]\n', encoding="utf-8", newline="\n")
    # tf_inventory calls terraform itself, which a Windows Python cannot reach as a
    # shell stub, so a stand-in fills the tokens the same way.
    (export / "tf_inventory.py").write_text(
        "import pathlib\n"
        "n = 0\n"
        "for p in list(pathlib.Path('ansible').rglob('*.yml')) + "
        "list(pathlib.Path('.').glob('*-BRIEFING.md')):\n"
        "    t = p.read_text(encoding='utf-8')\n"
        "    if '<<tf:' in t:\n"
        "        p.write_text(t.replace('<<tf:', 'filled:'), encoding='utf-8')\n"
        "        n += 1\n"
        "print('%d files filled' % n)\n", encoding="utf-8")
    if preflight == "pass":
        body = "print('summary: 5 VMs on Standard_D2as_v7, quota 10 of 10 vCPU')\n"
    else:
        body = ("print('   quota   need  used  limit  status')\n"
                "print('FAIL: Standard_D2as_v7 is not offered in eastus2. Roles using it: dc.')\n"
                "print('azure preflight failed, so apply was not started and nothing was created.')\n"
                "raise SystemExit(1)\n")
    (export / "azure_preflight.py").write_text(body, encoding="utf-8")
    jumpbox = re.search(r'^JUMPBOX="([^"]+)"', files["deploy.sh"], re.M).group(1)
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    calls = tmp_path / "terraform-calls.log"
    _stub(stubs, "terraform", "\n".join([
        'echo "$*" >> "%s"' % _msys(calls),
        'case "$*" in',
        '  *"output -raw lab_password"*) echo "Lab-Pass-123" ;;',
        "  *\"output -json redstackpro_addresses\"*) echo '{\"%s\": {\"public_address\": \"%s\"}}' ;;"
        % (jumpbox, JUMP_IP),
        '  *"state list"*) for r in a b c; do echo "azurerm_x.$r"; done; echo data.azurerm_y.z ;;',
        '  *apply*) echo "lab_password = Lab-Pass-123"; echo "Apply complete!" ;;',
        "esac",
        "exit 0"]))
    _stub(stubs, "ssh", "\n".join([
        'case "$*" in',
        '  *"bash -s"*) cat >/dev/null; exit %d ;;' % boot_rc,
        '  *"cat >"*|*"tar xzmf"*) cat >/dev/null ;;',
        "esac",
        "exit 0"]))
    for tool in ("scp", "ssh-keygen", "tar", "az"):
        _stub(stubs, tool, "exit 0")
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    return export, stubs, calls


def _log(export):
    logs = sorted((export / "logs").iterdir())
    assert [p.suffix for p in logs] == [".log"], "a stray file in logs/: %s" % logs
    return logs[0].read_text(encoding="utf-8")


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_full_run_prints_every_phase_then_the_done_box(tmp_path):
    export, stubs, _ = _range_export(tmp_path)
    done = _run(export, stubs)
    assert done.returncode == 0, done.stdout + done.stderr
    out = done.stdout
    heads = re.findall(r"^\[(\d)/8\] (.+?) \.{3,} \d\d:\d\d$", out, re.M)
    assert [int(n) for n, _ in heads] == list(range(1, 9))
    assert [t for _, t in heads] == [
        t.replace("$JUMP", JUMP_IP) for t in phase_titles("azure")]
    # Every phase closes on an ok line before the next one opens.
    for block in re.split(r"^\[\d/8\] .*$", out, flags=re.M)[1:]:
        assert re.search(r"^      ok\b", block, re.M), block
    box = out[out.index(" DONE  "):].splitlines()
    assert box[:7] == [
        " DONE  Infrastructure is up. Provisioning is running.",
        "-" * 62,
        " Portal    https://%s/guacamole" % JUMP_IP,
        " Logins    terraform -chdir=terraform output guacamole",
        " Watch     ssh -i keys/id_ed25519 blueop@%s" % JUMP_IP,
        "           tail -f ~/provision/run.log",
        " Finished  when run.log shows RUN EXITED ok=1 (45-75 min)"]
    assert re.fullmatch(r" Log       logs/deploy-\d{8}-\d{6}Z\.log", box[7]), box[7]
    assert box[8] == "=" * 62
    # The triage header is the log's alone, and the old stage markers are gone.
    assert "redStackPRO deploy log" not in out
    assert "== [" not in out
    log = _log(export)
    assert log.startswith("redStackPRO deploy log\n")
    assert log.splitlines()[-1] == "result: ok"
    assert " DONE  Infrastructure is up." in log
    # The scrub still covers what a tool printed, and runs after the closing lines.
    assert "Lab-Pass-123" not in log


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_from_deploy_ps1_the_done_box_writes_windows_paths(tmp_path):
    export, stubs, _ = _range_export(tmp_path)
    done = _run(export, stubs, env_extra={"REDSTACKPRO_FROM_PS1": "1"})
    assert done.returncode == 0, done.stdout + done.stderr
    assert " Watch     ssh -i keys\\id_ed25519 blueop@%s" % JUMP_IP in done.stdout
    assert re.search(r"^ Log       logs\\deploy-\d{8}-\d{6}Z\.log$", done.stdout, re.M)


def test_deploy_ps1_tells_deploy_sh_it_came_from_powershell(tmp_path):
    """Executed: the wrapper runs a stub deploy.sh that prints what it was told,
    and the variable is not left behind in the PowerShell session."""
    ps = _powershell()
    if ps is None or _bash() is None:
        pytest.skip("needs Windows PowerShell and Git Bash")
    (tmp_path / "deploy.ps1").write_text(DEPLOY_PS1, encoding="utf-8")
    (tmp_path / "deploy.sh").write_text(
        'echo "from-ps1=${REDSTACKPRO_FROM_PS1:-unset}"\n', encoding="utf-8", newline="\n")
    done = subprocess.run(
        [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
         "& '%s'; Write-Host \"after=$env:REDSTACKPRO_FROM_PS1\"" % (tmp_path / "deploy.ps1")],
        capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "from-ps1=1" in done.stdout
    assert re.search(r"^after=$", done.stdout, re.M), done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_failed_preflight_ends_on_a_failed_box_and_the_log_says_so(tmp_path):
    export, stubs, calls = _range_export(tmp_path, preflight="fail")
    done = _run(export, stubs)
    assert done.returncode == 1, done.stdout + done.stderr
    out = done.stdout
    phase = "[1/8] Preflight: VM sizes, quota, providers"
    assert " FAILED  %s" % phase in out
    assert " Reason    Standard_D2as_v7 is not offered in eastus2. Roles using it: dc." in out
    assert " Exit      1" in out
    assert "issues/new/choose" in out
    assert "] Terraform apply" not in out
    assert "apply" not in calls.read_text(encoding="utf-8")
    assert _log(export).splitlines()[-1] == "result: FAILED (exit 1) in phase %s" % phase


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_failed_jumpbox_step_keeps_its_own_exit_code(tmp_path):
    """The BOOT step used to end the run through set -e with ssh's status. It now
    names itself in the FAILED box, with the same status."""
    export, stubs, _ = _range_export(tmp_path, boot_rc=100)
    done = _run(export, stubs)
    assert done.returncode == 100, done.stdout + done.stderr
    assert " FAILED  [5/8] Install prerequisites on the jumpbox" in done.stdout
    assert " Exit      100" in done.stdout
    assert _log(export).splitlines()[-1] == (
        "result: FAILED (exit 100) in phase [5/8] Install prerequisites on the jumpbox")


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_local_check_failure_is_named_and_logged(staged):
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    done = _run(export, stubs)  # no gcloud: the credential check stops it
    assert done.returncode == 1
    assert " FAILED  local checks" in done.stdout
    assert " Reason    GCP credentials are not set." in done.stdout
    assert _log(export).splitlines()[-1] == "result: FAILED (exit 1) in phase local checks"


def test_the_jumpbox_noise_is_cut_at_the_source(script):
    boot = _code(_remote_block(script, "BOOT"))
    # sudo drops an exported DEBIAN_FRONTEND, so apt-get has to get it directly.
    apt = [ln for ln in boot.splitlines() if "apt-get" in ln]
    assert apt and all("sudo DEBIAN_FRONTEND=noninteractive apt-get" in ln for ln in apt), apt
    assert "--no-warn-script-location" in boot
    # A zip stamped in another timezone must not warn once per file on extract.
    assert "tar xzmf - -C ~/provision" in script
    # "No screen session found." on a first deploy.
    assert "screen -S provision -X quit >/dev/null 2>&1" in script


def test_the_long_steps_print_one_line_each(script):
    assert '"$PY" tf_inventory.py --quiet' in script
    azure = generate_deploy_script(example("redstack.json"), Registry(), provider="azure")
    assert '"$PY" azure_preflight.py . --brief' in azure


def _tf_inventory():
    import importlib.util
    path = ROOT / "src/redstackpro/assets/tf_inventory.py"
    spec = importlib.util.spec_from_file_location("shipped_tf_inventory", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("quiet", [False, True])
def test_tf_inventory_quiet_prints_one_count_line(tmp_path, monkeypatch, capsys, quiet):
    tool = _tf_inventory()
    for name in ("a", "b"):
        path = tmp_path / ("ansible/host_vars/%s.yml" % name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ansible_host: <<tf:%s:private_address>>\n" % name, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tool, "lookup_table", lambda tf_dir: {
        "a": {"private_address": "10.0.0.4"}, "b": {"private_address": "10.0.0.5"}})
    monkeypatch.setattr(sys, "argv", ["tf_inventory.py"] + (["--quiet"] if quiet else []))
    tool.main()
    lines = capsys.readouterr().out.splitlines()
    if quiet:
        assert lines == ["2 files filled"]
    else:
        assert lines == ["filled %s" % Path("ansible/host_vars/a.yml"),
                         "filled %s" % Path("ansible/host_vars/b.yml")]
    assert "10.0.0.5" in (tmp_path / "ansible/host_vars/b.yml").read_text(encoding="utf-8")


def _runner(document, provider="azure"):
    script = generate_deploy_script(document, Registry(), provider=provider)
    return _remote_block(script, "RUNNER") + "\n"


def test_run_log_keeps_the_strings_its_watchers_grep_for():
    """verify.py, the export guide, the lab docs and live watchers all read these."""
    for doc in (load(GOAD_LIGHT), example("redstack.json")):
        runner = _runner(doc)
        assert ": > run.log" in runner and ": > run-full.log" in runner
        assert "RUN EXITED ok=$ok" in runner
        assert "PLAYBOOK SUCCEEDED (attempt $attempt" in runner
        assert "for attempt in 1 2 3 4 5 6 7 8; do" in runner
    script = generate_deploy_script(load(GOAD_LIGHT), Registry(), provider="azure")
    assert "screen -dmS provision ~/provision/run.sh" in script


_PLAY_JUMPBOX = """
PLAY [jumpboxes] ***************************************************************

TASK [Gathering Facts] *********************************************************
ok: [def-jumpbox]

TASK [redstackpro.jumpbox : Configure wireguard] *******************************
skipping: [def-jumpbox]

TASK [redstackpro.jumpbox : Start guacamole] ***********************************
changed: [def-jumpbox]

PLAY RECAP *********************************************************************
def-jumpbox                : ok=61   changed=38   unreachable=0    failed=0    skipped=14
"""

_PLAY_FAILS = """
PLAY [domain_controllers] ******************************************************

TASK [redstackpro.dc : Wait for the parent forest] *****************************
skipping: [def-kingslanding]
fatal: [def-winterfell]: FAILED! => {"changed": false, "msg": "WinRM reset"}

PLAY RECAP *********************************************************************
def-kingslanding           : ok=40   changed=21   unreachable=0    failed=0    skipped=9
def-winterfell             : ok=12   changed=4    unreachable=0    failed=1    skipped=3
"""

_PLAY_PASSES = """
PLAY [domain_controllers] ******************************************************

TASK [redstackpro.dc : Promote] ************************************************
changed: [def-winterfell]

TASK [redstackpro.dc : Linux only] *********************************************
skipping: [def-kingslanding]
skipping: [def-winterfell]

PLAY RECAP *********************************************************************
def-kingslanding           : ok=88   changed=41   unreachable=0    failed=0    skipped=20
def-winterfell             : ok=79   changed=40   unreachable=0    failed=0    skipped=18
"""


def _run_runner(tmp_path, runner):
    """run.sh against a fake ansible: the jumpbox pass passes, site.yml fails once
    and then passes. sleep is stubbed so the retry costs nothing."""
    home = tmp_path / "home"
    (home / "provision").mkdir(parents=True)
    (home / "provision/run.sh").write_text(runner, encoding="utf-8", newline="\n")
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name, text in (("jb", _PLAY_JUMPBOX), ("fail", _PLAY_FAILS), ("ok", _PLAY_PASSES)):
        (tmp_path / ("%s.txt" % name)).write_text(text, encoding="utf-8", newline="\n")
    work, count = _msys(tmp_path), _msys(tmp_path / "count")
    _stub(stubs, "ansible-playbook", "\n".join([
        'case "$*" in *"--limit jumpboxes"*) cat "%s/jb.txt"; exit 0 ;; esac' % work,
        'n=$(cat "%s" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "%s"' % (count, count),
        'if [ $n -eq 1 ]; then cat "%s/fail.txt"; exit 2; fi' % work,
        'cat "%s/ok.txt"' % work]))
    for name in ("ansible", "sleep"):
        _stub(stubs, name, "exit 0")
    _stub(stubs, "hostname", "echo def-jumpbox")
    _stub(stubs, "python3", 'exec %s "$@"' % Path(sys.executable).as_posix())
    env = dict(os.environ, HOME=_msys(home))
    command = 'export PATH="%s:/usr/bin:/bin"; exec bash ~/provision/run.sh' % _msys(stubs)
    done = subprocess.run([_bash(), "-c", command], env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=120)

    def read(name):
        return (home / "provision" / name).read_text(encoding="utf-8")
    return done, read("run.log"), read("run-full.log")


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted runner")
def test_run_log_is_condensed_and_run_full_log_is_not(tmp_path):
    done, view, full = _run_runner(tmp_path, _runner(load(GOAD_LIGHT)))
    assert done.returncode == 0, done.stdout + done.stderr
    # What screen shows is what run.log holds.
    assert done.stdout == view
    # Skipped hosts, and a task banner with nothing but skips under it, are hidden.
    assert "skipping: [" not in view and "skipping: [def-kingslanding]" in full
    assert "Configure wireguard" not in view and "Configure wireguard" in full
    assert "Linux only" not in view
    assert "TASK [redstackpro.jumpbox : Start guacamole]" in view
    # A failed task stands out; the full log keeps Ansible's own line.
    assert '!! fatal: [def-winterfell]: FAILED! => {"changed": false' in view
    assert "\nfatal: [def-winterfell]" in full
    lines = view.splitlines()
    for stage in ("Jumpbox pass 1 of 3", "Waiting for authenticated WinRM",
                  "site.yml attempt 1 of 8", "site.yml attempt 2 of 8"):
        assert any(re.fullmatch(r"%s \.{3,} \d\d:\d\d" % re.escape(stage), ln)
                   for ln in lines), stage
    assert any(re.fullmatch(r"      ok  WinRM answered after \d+s", ln) for ln in lines)
    assert any(ln.startswith("      FAILED  attempt 1 after") for ln in lines)
    # The strings watchers grep for, each on a line of its own, once.
    succeeded = [ln for ln in lines if "PLAYBOOK SUCCEEDED" in ln]
    assert len(succeeded) == 1
    assert succeeded[0].startswith("      ok  PLAYBOOK SUCCEEDED (attempt 2,")
    exited = [ln for ln in lines if "RUN EXITED" in ln]
    assert len(exited) == 1 and exited[0].startswith(" RUN EXITED ok=1 at ")
    # The closing summary: one recap line per host, the jumpbox pass included.
    summary = view[view.index(" RUN EXITED"):]
    recap = [ln.split()[0] for ln in summary.splitlines() if " : ok=" in ln]
    assert recap == ["def-jumpbox", "def-kingslanding", "def-winterfell"]
    assert "~/provision/run-full.log" in summary
    assert "RUN EXITED ok=1" in full


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted runner")
def test_an_offense_run_log_has_no_jumpbox_pass_or_winrm_gate(tmp_path):
    done, view, _ = _run_runner(tmp_path, _runner(example("redstack.json"), "gcp"))
    assert done.returncode == 0, done.stdout + done.stderr
    assert "Jumpbox pass" not in view and "authenticated WinRM" not in view
    assert "      ok  PLAYBOOK SUCCEEDED (attempt 2," in view
    assert re.search(r"^ RUN EXITED ok=1 at ", view, re.M)


@pytest.mark.parametrize("provider", ["gcp", "aws", "azure", "proxmox"])
@pytest.mark.parametrize("name", ["redstack.json", "minimal.json"])
def test_deploy_sh_and_its_runner_are_valid_bash(provider, name):
    bash = _bash()
    if bash is None:
        pytest.skip("no bash to syntax-check the emitted script")
    script = generate_deploy_script(example(name), Registry(), provider=provider)
    for body in (script, _remote_block(script, "RUNNER")):
        done = subprocess.run([bash, "-n", "-c", body], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
