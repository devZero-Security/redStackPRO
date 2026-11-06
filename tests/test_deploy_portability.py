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

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from redstackpro import Registry
from redstackpro.deploy import WORDMARK, generate_deploy_script, generate_manage_script
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
    warn = "WARNING${C_OFF}: operator_source_ranges is 0.0.0.0/0"
    assert warn in script
    # The message tells the user the one-line fix and the override.
    assert '"    $(rsp_cmd deploy REDSTACKPRO_ALLOW_OPEN_INGRESS=1)"' in script


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


def test_the_wrapper_makes_an_open_key_owner_only_and_deploy_says_so():
    """A key copied into keys\\ takes the folder's ACL, Windows ssh then refuses it,
    and every ssh line the deploy prints for PowerShell fails (found live
    2026-11-06). The wrapper resets it and hands the name to deploy.sh's note."""
    files = compile_topology(example("redstack.json"), Registry(), provider="gcp")
    wrapper = files["deploy.ps1"]
    assert "@@" not in wrapper
    assert "/inheritance:r /grant:r" in wrapper
    assert "REDSTACKPRO_KEY_ACL='$keyacl' bash deploy.sh" in wrapper
    assert 'note "$REDSTACKPRO_KEY_ACL was readable by other Windows accounts' in files["deploy.sh"]


def _windows_powershell():
    if os.name != "nt":
        return None
    return shutil.which("powershell.exe")


@pytest.mark.skipif(_windows_powershell() is None, reason="needs Windows PowerShell")
def test_the_key_acl_snippet_runs_on_windows_powershell(tmp_path):
    """Executed, on the oldest PowerShell the export supports: an open key is reset
    to owner, SYSTEM and Administrators, the .pub is left alone, and a second run
    reports nothing because there is nothing left to fix."""
    from redstackpro.deploy import _PS1_KEY_ACL

    keys = tmp_path / "keys"
    keys.mkdir()
    for name in ("id_ed25519", "id_ed25519.pub", ".keep"):
        (keys / name).write_text("x\n", encoding="utf-8")
    for name in ("id_ed25519", "id_ed25519.pub"):
        subprocess.run(["icacls", str(keys / name), "/grant", "*S-1-5-11:(R)"],
                       check=True, capture_output=True)
    runner = tmp_path / "run.ps1"
    runner.write_text("$root = '%s'\n%s\nWrite-Output \"KEYACL=$keyacl\"\n"
                      % (tmp_path, _PS1_KEY_ACL), encoding="utf-8")

    def run():
        out = subprocess.run([_windows_powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass",
                              "-File", str(runner)], capture_output=True, text=True, check=True)
        return out.stdout

    def acl(name):
        return subprocess.run(["icacls", str(keys / name)], capture_output=True,
                              text=True).stdout

    assert "KEYACL=keys/id_ed25519" in run()
    assert "Authenticated Users" not in acl("id_ed25519")
    assert "Users:" not in acl("id_ed25519").replace("Authenticated Users", "")
    assert "Authenticated Users" in acl("id_ed25519.pub")
    assert "KEYACL=\n" in run().replace("\r", "")


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
    for name in ("REDSTACKPRO_SSH_KEY", "REDSTACKPRO_COLOR", "NO_COLOR"):
        env.pop(name, None)
    env.update(env_extra or {})
    command = 'export PATH="%s:/usr/bin:/bin"; exec bash deploy.sh' % _msys(stub_dir)
    return subprocess.run([bash, "-c", command], cwd=script_dir, env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, encoding="utf-8", timeout=120)


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
    assert "\n        REDSTACKPRO_SSH_KEY=keys/<name> bash deploy.sh\n" in done.stdout
    ps1 = _run(export, stubs, env_extra={"REDSTACKPRO_FROM_PS1": "1"})
    assert ("\n        $env:REDSTACKPRO_SSH_KEY = 'keys/<name>'; .\\deploy.ps1\n"
            in ps1.stdout), ps1.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the helpers")
@pytest.mark.parametrize("args,bash,ps1", [
    ("deploy", "bash deploy.sh", ".\\deploy.ps1"),
    ("deploy REDSTACKPRO_MIN_STOP_LEAD=0", "REDSTACKPRO_MIN_STOP_LEAD=0 bash deploy.sh",
     "$env:REDSTACKPRO_MIN_STOP_LEAD = '0'; .\\deploy.ps1"),
    ("deploy REDSTACKPRO_SKIP_PREFLIGHT=1", "REDSTACKPRO_SKIP_PREFLIGHT=1 bash deploy.sh",
     "$env:REDSTACKPRO_SKIP_PREFLIGHT = '1'; .\\deploy.ps1"),
    ("manage teardown --force", "bash manage.sh teardown --force",
     ".\\manage.ps1 teardown --force"),
])
def test_a_hint_is_written_for_the_shell_the_user_typed_it_in(tmp_path, args, bash, ps1):
    """deploy.ps1 and manage.ps1 set REDSTACKPRO_FROM_PS1. A bash line pasted at a
    PowerShell prompt fails, or runs WSL's bash."""
    # A file, not bash -c: Git Bash halves the backslashes of a Windows argv.
    script = tmp_path / "hint.sh"
    script.write_text(output_helpers() + "rsp_cmd " + args + "\n", encoding="utf-8",
                      newline="\n")
    for env, expect in (({}, bash), ({"REDSTACKPRO_FROM_PS1": "1"}, ps1)):
        environ = dict(os.environ)
        environ.pop("REDSTACKPRO_FROM_PS1", None)
        environ.update(env)
        done = subprocess.run([_bash(), script.name], cwd=tmp_path,
                              capture_output=True, text=True, env=environ)
        assert (done.returncode, done.stdout) == (0, expect + "\n"), done.stderr


@pytest.mark.parametrize("provider", ["gcp", "aws", "azure", "proxmox"])
def test_every_command_hint_goes_through_rsp_cmd(provider):
    """One helper writes every deploy or manage command a user is told to run,
    so none is left in bash form from PowerShell."""
    doc = example("redstack.json")
    doc["auto_stop"] = {"enabled": True, "at": "02:00", "timezone": "UTC"}
    for script in (generate_deploy_script(doc, Registry(), provider=provider),
                   generate_manage_script(doc, Registry(), provider=provider)):
        code = _code(script, local_only=True)
        assert "bash deploy.sh" not in code and "bash manage.sh" not in code
        assert ".ps1" not in code.replace('".\\\\$rsp_c_s.ps1"', "")
    deploy = generate_deploy_script(doc, Registry(), provider=provider)
    for hint in ("$(rsp_cmd deploy REDSTACKPRO_MIN_STOP_LEAD=0)",
                 "$(rsp_cmd deploy REDSTACKPRO_ALLOW_OPEN_INGRESS=1)",
                 "$(rsp_cmd deploy 'REDSTACKPRO_SSH_KEY=keys/<name>')",
                 "$(rsp_cmd manage teardown --force)"):
        assert hint in deploy, hint


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_missing_key_says_how_to_make_one(staged):
    """The old message named a path and stopped. This is the first wall a new
    user hits, so it has to carry the next step."""
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    (export / "keys/id_ed25519").unlink()

    done = _run(export, stubs, env_extra={"HOME": _msys(export / "nowhere")})
    assert done.returncode == 1
    assert 'ssh-keygen -t ed25519 -f keys/id_ed25519 -N ""' in done.stdout, done.stdout
    assert "ssh_public_key" in done.stdout

    # From deploy.ps1 the hint is the PowerShell form. Windows PowerShell 5.1 drops
    # an empty -N '' argument, so it leaves -N off and says to press Enter twice.
    ps1 = _run(export, stubs, env_extra={"HOME": _msys(export / "nowhere"),
                                         "REDSTACKPRO_FROM_PS1": "1"})
    assert ps1.returncode == 1
    assert "ssh-keygen -t ed25519 -f keys\\id_ed25519\n" in ps1.stdout, ps1.stdout
    assert "press Enter twice" in ps1.stdout
    assert "id_ed25519 -N" not in ps1.stdout


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
    assert 'RSP_SPLIT_TO="$LOG" sh -c' in script
    assert 'rsp_done | rsp_split "$LOG"' in script
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
    assert "  status|start|stop|teardown|_teardown_summary) shift ;;" in manage_script
    assert '""|help|-h|--help) rsp_help; exit 0 ;;' in manage_script


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
    instances_at = manage_script.index("output -json redstackpro_instances", teardown_at)
    assert teardown_at < exit_at < status_at < instances_at


def test_status_prints_the_guacamole_portal_url(manage_script):
    assert 'output -json guacamole' in manage_script
    assert 'rsp_row Portal "$C_CYN$GUAC_URL$C_OFF"' in manage_script


def test_aws_targets_instances_by_id():
    aws = generate_manage_script(example("redstack.json"), Registry(), provider="aws")
    assert "redstackpro_instances" in aws
    # In the deploy's own region, not whatever the CLI defaults to.
    assert "aws ec2 start-instances $REG_ARG --instance-ids" in aws
    assert "aws ec2 stop-instances $REG_ARG --instance-ids" in aws
    assert "aws ec2 describe-instances $REG_ARG --instance-ids" in aws
    assert 'REG_ARG="--region $RSP_REGION"' in aws
    assert "gcloud" not in aws


def test_gcp_targets_instances_by_name_and_zone():
    gcp = generate_manage_script(example("redstack.json"), Registry(), provider="gcp")
    assert "redstackpro_instances" in gcp
    # status lists the range in one call; start/stop batch a zone's instances
    # into a single call ("$cmd" is start or stop) instead of one blocking call each.
    assert ('gcloud compute instances list $PROJ_ARG --zones "$RSP_ZONES" '
            '--filter="name=($RSP_NAMES)"') in gcp
    assert "gcloud compute instances describe" not in gcp
    assert 'gcloud compute instances "$cmd" $names --zone "$zone"' in gcp


def test_teardown_force_sweeps_orphan_instances_before_destroy():
    """Found on a live GCP deploy: an interrupted apply orphaned instances (created
    but never in state), which terraform destroy could not clean and which blocked
    it. teardown --force deletes redStackPRO instances by label/tag first, scoped to
    the deploy, so the destroy can finish. A failed destroy also points here."""
    gcp = generate_manage_script(example("redstack.json"), Registry(), provider="gcp")
    aws = generate_manage_script(example("redstack.json"), Registry(), provider="aws")
    for s in (gcp, aws):
        assert '"teardown --force") RSP_FORCE=1 ;;' in s, "teardown --force is recognized"
        assert 'echo "   $C_CYN$RSP_RUN teardown --force$C_OFF"' in s, \
            "a failed destroy points at --force"
    assert "labels.redstackpro_deploy=$RSP_DEPLOY" in gcp
    assert "gcloud compute instances delete" in gcp
    assert "Name=tag:redstackpro_deploy,Values=$RSP_DEPLOY" in aws
    assert "aws ec2 terminate-instances" in aws
    assert "aws ec2" not in gcp
    # Never the label or tag every redStackPRO range carries.
    assert "labels.redstackpro_kind" not in gcp
    assert "tag:redstackpro,Values=true" not in aws


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
    assert "status, start and stop are not available for" in other


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
    assert "only teardown is" not in manage
    deploy = generate_deploy_script(example("redstack.json"), Registry(), provider="azure")
    assert "az account show" in deploy


def test_MANAGE_sh_is_syntactically_valid_bash(manage_script):
    """The executed check for this file: a template edited by hand is exactly
    how a stray unmatched brace or quote gets shipped to every export."""
    bash = _bash()
    if bash is None:
        pytest.skip("no bash to syntax-check the emitted script")
    # On stdin, as a file would be: a Windows command line mangles a long script
    # passed as an argument before Git Bash sees it.
    done = subprocess.run([bash, "-n"], input=manage_script,
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
    assert "$words = @($args)" in MANAGE_PS1
    assert "$fwd = ($words | ForEach-Object { ConvertTo-BashWord $_ }) -join ' '" in MANAGE_PS1
    assert "REDSTACKPRO_FROM_PS1=1 REDSTACKPRO_COLOR=$color bash manage.sh $fwd" in MANAGE_PS1


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
         str(tmp_path / "manage.ps1"), "teardown", "--force", "--yes", "a b", "it's"],
        capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    assert done.returncode == 0, done.stderr
    got = [line for line in done.stdout.splitlines() if line.startswith("[")]
    assert got == ["[teardown]", "[--force]", "[--yes]", "[a b]", "[it's]"], done.stdout


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


# -- manage.sh help, teardown confirmation and the one-table status, executed

def _smoketest_gl():
    """goad-light as a person names it, with a wall-clock auto-stop."""
    doc = load(GOAD_LIGHT)
    doc["name"] = "smoketest-gl"
    doc["prefix"] = "smk"
    doc["auto_stop"] = {"enabled": True, "at": "18:00", "timezone": "America/New_York"}
    return doc


_TFVARS = {
    "azure": 'subscription_id = "s"\nlocation = "westus3"\nresource_group = "smk-lab-rg"\n',
    "gcp": 'project = "example-project"\nregion = "us-central1"\nzone = "us-central1-a"\n',
    "aws": 'region = "eu-west-2"\n',
    "proxmox": 'proxmox_endpoint = "https://pve.lab:8006/"\n',
}

# Two hosts, so a per-VM call would show as two.
_TWO_INSTANCES = {
    "aws": '{"a": {"instance_id": "i-1"}, "b": {"instance_id": "i-2"}}',
    "gcp": '{"a": {"name": "smk-jump", "zone": "us-central1-a"}, '
           '"b": {"name": "smk-dc01", "zone": "us-central1-b"}}',
    "azure": '{"a": {"name": "smk-jump", "resource_group": "smk-lab-rg"}, '
             '"b": {"name": "smk-dc01", "resource_group": "smk-lab-rg"}}',
}


def _manage_export(tmp_path, provider, doc=None, tfvars=True):
    """A compiled export and a stub PATH. Every stub, terraform and the cloud
    CLI alike, appends its argv to calls.log, so a test can prove what ran."""
    files = compile_topology(doc or _smoketest_gl(), Registry(), provider=provider)
    export = tmp_path / "export"
    for path, contents in files.items():
        target = export / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8", newline="\n")
    if tfvars:
        _tfvars(export, _TFVARS[provider])
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    calls = tmp_path / "calls.log"
    log = 'echo "$(basename "$0") $*" >> "%s"' % _msys(calls)
    _stub(stubs, "terraform", "\n".join([
        log, 'case "$*" in',
        "  *redstackpro_instances*) echo '%s' ;;" % _TWO_INSTANCES.get(provider, "{}"),
        "  *guacamole*) echo '{\"url\": \"https://203.0.113.9/guacamole\"}' ;;",
        "esac"]))
    for cli in ("az", "gcloud", "aws"):
        _stub(stubs, cli, log)
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    return export, stubs, calls


def _manage(export, stubs, *args, ps1=False, path_extra=":/usr/bin:/bin", stdin=None,
            env_extra=None):
    env = dict(os.environ)
    for name in ("REDSTACKPRO_FROM_PS1", "AWS_PROFILE", "AWS_ACCESS_KEY_ID",
                 "REDSTACKPRO_COLOR", "NO_COLOR"):
        env.pop(name, None)
    if ps1:
        env["REDSTACKPRO_FROM_PS1"] = "1"
    env.update(env_extra or {})
    words = " ".join("'%s'" % a for a in args)
    command = 'export PATH="%s%s"; exec bash manage.sh %s' % (_msys(stubs), path_extra, words)
    return subprocess.run([_bash(), "-c", command], cwd=export, env=env,
                          stdin=stdin if stdin is not None else subprocess.DEVNULL,
                          capture_output=True, text=True, encoding="utf-8", timeout=120)


def _calls(calls):
    return calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []


_HELP_ROWS = {
    "azure": ["  status            Each VM's power state and the portal",
              "  stop              Deallocate every VM. Compute billing",
              "                    stops; disks, the jumpbox public IP and",
              "                    the NAT gateway still bill. Nothing is",
              "                    deleted.",
              "  start             Start every VM again. Provisioning is not",
              "  teardown          Delete the whole range",
              "                    (terraform destroy). Cannot be undone.",
              "  teardown --force  Delete the resource group directly first;"],
    "gcp": ["  status            Each instance's status and the portal",
            "  stop              Stop every instance. Compute billing",
            "                    stops; disks and the jumpbox static IP",
            "  teardown --force  Delete this range's instances first,",
            "                    including any an interrupted apply left",
            "                    out of the state, but never another"],
    "aws": ["  status            Each instance's state and the portal",
            "  stop              Stop every instance. Compute billing",
            "                    stops; EBS volumes, the jumpbox Elastic IP",
            "                    and the NAT gateway still bill. Nothing is",
            "  teardown --force  Terminate this range's instances first,"],
}
# The box rows under the title, after the wordmark.
_HELP_HEAD = {
    "azure": [" Provider        Azure westus3", " Resource group  smk-lab-rg"],
    "gcp": [" Provider        GCP us-central1", " Project         example-project"],
    "aws": [" Provider        AWS eu-west-2", " Profile         default"],
}
# A (parenthesized) command is never split over two lines.
_HELP_FOOT = {
    "azure": [" Auto-stop       every day at 18:00 Eastern Standard Time",
              " Needs           the Azure CLI, signed in (az login)"],
    "gcp": [" Auto-stop       every day at 18:00 America/New_York",
            " Needs           the Google Cloud CLI, signed in",
            "                 (gcloud auth login)"],
    "aws": [" Auto-stop       every day at 18:00 America/New_York",
            " Needs           the AWS CLI, signed in (aws configure)"],
}
# What each provider's stop really runs; the help's stop row describes it.
_STOP_CALL = {"azure": 'az vm deallocate -g "$rg" -n "$vm"',
              "gcp": 'gcloud compute instances "$cmd" $names',
              "aws": "aws ec2 stop-instances $REG_ARG --instance-ids $IDS"}


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
@pytest.mark.parametrize("provider", ["azure", "gcp", "aws"])
def test_manage_with_no_command_prints_the_help_screen(tmp_path, provider):
    """It printed one usage line, with bash syntax even from PowerShell. The
    header reads deploy.tfvars, so it names where teardown would act."""
    export, stubs, calls = _manage_export(tmp_path, provider)
    done = _manage(export, stubs)
    assert done.returncode == 0, done.stdout + done.stderr
    lines = done.stdout.splitlines()
    assert lines[:5] == WORDMARK.splitlines()
    assert lines[5:10] == ["=" * 62, " MANAGE   smoketest-gl", "-" * 62] + _HELP_HEAD[provider]
    foot = _HELP_FOOT[provider]
    assert lines[10:11 + len(foot)] == foot + ["=" * 62]
    for row in _HELP_ROWS[provider]:
        assert row in lines, (row, done.stdout)
    assert lines[lines.index(" EXAMPLES"):] == [
        " EXAMPLES", " --------", "  bash manage.sh status", "  bash manage.sh teardown"]
    assert max(len(line) for line in lines) <= 62
    assert "\x1b" not in done.stdout, "colour with no terminal"
    assert _STOP_CALL[provider] in (export / "manage.sh").read_text(encoding="utf-8")
    assert _calls(calls) == [], "the help ran something"

    ps1 = _manage(export, stubs, ps1=True)
    assert ps1.returncode == 0
    assert ps1.stdout.endswith("  .\\manage.ps1 status\n  .\\manage.ps1 teardown\n")
    assert "bash manage.sh" not in ps1.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_help_words_exit_0_and_an_unknown_command_exits_1_with_the_same_screen(tmp_path):
    export, stubs, calls = _manage_export(tmp_path, "azure")
    screen = _manage(export, stubs).stdout
    for word in ("help", "-h", "--help"):
        done = _manage(export, stubs, word)
        assert (done.returncode, done.stdout) == (0, screen), word
    done = _manage(export, stubs, "restart")
    assert done.returncode == 1
    assert done.stdout == "unknown command: restart\n\n" + screen
    done = _manage(export, stubs, "teardown", "--forse")
    assert done.returncode == 1
    assert done.stdout == "unknown option for teardown: --forse\n\n" + screen
    done = _manage(export, stubs, "status", "--yes")
    assert done.returncode == 1 and done.stdout.startswith("unknown option for status: --yes")
    assert _calls(calls) == []


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_the_help_needs_no_terraform_and_falls_back_to_the_compiled_defaults(tmp_path):
    export, stubs, _ = _manage_export(tmp_path, "azure", tfvars=False)
    (stubs / "terraform").unlink()
    (export / "deploy.tfvars").unlink()
    done = _manage(export, stubs)
    assert done.returncode == 0, done.stdout
    assert done.stdout.splitlines()[8:10] == [
        " Provider        Azure eastus2",
        " Resource group  smk-smoketest-gl-rg"]


@pytest.mark.parametrize("doc_stop,expect", [
    ({"enabled": False}, "Auto-stop  off"),
    ({"enabled": True, "after_hours": 8},
     "Auto-stop  8 hours after the first apply, then daily at that time"),
    ({"enabled": True, "at": "21:30", "timezone": "Europe/London"},
     "every day at 21:30 GMT Standard Time"),
])
def test_the_help_states_the_compiled_auto_stop(doc_stop, expect):
    doc = _smoketest_gl()
    doc["auto_stop"] = doc_stop
    script = generate_manage_script(doc, Registry(), provider="azure")
    footer = script[script.index("rsp_row 'Auto-stop'"):].splitlines()
    rows = [footer[0]] + [r for r in footer[1:3] if r.startswith("  rsp_row '' ")]
    said = " ".join(r.rsplit(" '", 1)[1].rstrip("'") for r in rows)
    assert said.endswith(expect.replace("Auto-stop  ", "")), footer


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_provider_without_live_control_offers_only_teardown(tmp_path):
    files = compile_topology(load(GOAD_LIGHT), Registry(), provider="proxmox")
    export = tmp_path / "export"
    export.mkdir()
    (export / "manage.sh").write_text(files["manage.sh"], encoding="utf-8", newline="\n")
    _tfvars(export, _TFVARS["proxmox"])
    done = subprocess.run([_bash(), "manage.sh"], cwd=export, capture_output=True,
                          text=True, stdin=subprocess.DEVNULL, timeout=120)
    assert done.returncode == 0
    out = done.stdout
    assert (" MANAGE   GOAD-Light\n" + "-" * 62 + "\n Provider        Proxmox\n"
            " Endpoint        https://pve.lab:8006/\n") in out
    assert "  status " not in out and "  teardown --force" not in out
    assert "  status, start and stop are not available for Proxmox; only\n" in out
    assert out.endswith(" EXAMPLES\n --------\n  bash manage.sh teardown\n")
    assert " Auto-stop       not available for Proxmox\n" in out


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
@pytest.mark.parametrize("force", [[], ["--force"]])
def test_teardown_without_a_terminal_or_yes_refuses_and_runs_nothing(tmp_path, force):
    export, stubs, calls = _manage_export(tmp_path, "azure")
    done = _manage(export, stubs, "teardown", *force)
    assert done.returncode == 1, done.stdout
    out = done.stdout.splitlines()
    assert out[:5] == ["=" * 62, " TEARDOWN   smoketest-gl", "-" * 62,
                       " Provider        Azure westus3",
                       " Resource group  smk-lab-rg"]
    rest = out[5:]
    if force:
        assert rest.pop(0) == " --force         deletes the resource group directly first"
    assert rest[:4] == ["=" * 62, "", " This deletes the whole range. It cannot be undone.", ""]
    assert rest[-3:] == ["To delete it without the question, run:",
                         "  bash manage.sh teardown%s --yes" % (" --force" if force else ""),
                         "Nothing was deleted."]
    assert _calls(calls) == [], "terraform or the cloud CLI ran"
    assert not (export / "terraform/terraform.tfvars").exists()


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
@pytest.mark.parametrize("flags", [["--yes"], ["--yes", "--force"], ["--force", "--yes"]])
def test_teardown_yes_skips_the_question_in_any_order(tmp_path, flags):
    export, stubs, calls = _manage_export(tmp_path, "azure")
    done = _manage(export, stubs, "teardown", *flags)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "This deletes the whole range" not in done.stdout
    ran = _calls(calls)
    assert ran[-1] == "terraform -chdir=terraform destroy -auto-approve", ran
    swept = "az group delete -n smk-lab-rg --yes" in ran
    assert swept == ("--force" in flags), ran


_TF_DESTROY_OUT = "\n".join([
    "module.smk_net01.azurerm_nat_gateway.this[0]: Refreshing state... "
    "[id=/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/natGateways/smk-net01-nat]",
    "Plan: 0 to add, 0 to change, 2 to destroy.",
    "module.smk_net01.azurerm_nat_gateway.this[0]: Destroying... "
    "[id=/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/natGateways/smk-net01-nat]",
    "module.smk_net01.azurerm_nat_gateway.this[0]: Still destroying... [10s elapsed]",
    "module.smk_net01.azurerm_nat_gateway.this[0]: Destruction complete after 12s",
    "random_password.lab: Destroying... [id=none]",
    "random_password.lab: Destruction complete after 0s",
    "Destroy complete! Resources: 2 destroyed.",
])


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_teardown_is_condensed_on_screen_and_whole_in_its_own_log(tmp_path):
    export, stubs, calls = _manage_export(tmp_path, "azure")
    out = stubs / "destroy.out"
    out.write_text(_TF_DESTROY_OUT + "\n", encoding="utf-8", newline="\n")
    tf = stubs / "terraform"
    tf.write_text(tf.read_text(encoding="utf-8").replace(
        'case "$*" in', 'case "$*" in\n  *destroy*) cat "%s" ;;' % _msys(out)),
        encoding="utf-8", newline="\n")
    done = _manage(export, stubs, "teardown", "--yes", ps1=True)
    assert done.returncode == 0, done.stdout + done.stderr
    lines = done.stdout.splitlines()
    at = [i for i, line in enumerate(lines) if line.startswith("terraform destroy ")][0]
    assert lines[at + 1:at + 4] == [
        "      plan  0 to add, 0 to change, 2 to destroy",
        "      -    12s  smk-net01-nat (nat gateway)",
        "      -     0s  lab (password)"]
    assert re.fullmatch(r"      ok  2 destroyed in \d+s", lines[at + 4]), lines[at + 4]
    assert lines[at + 5:at + 9] == ["", "=" * 62, " DONE  The range is deleted.", "-" * 62]
    assert re.fullmatch(r" Log       logs\\teardown-\d{8}-\d{6}Z\.log", lines[at + 9]), lines[at + 9]
    assert "Refreshing state" not in done.stdout
    logs = list((export / "logs").glob("teardown-*.log"))
    assert len(logs) == 1, logs
    log = logs[0].read_text(encoding="utf-8")
    assert log.startswith("redStackPRO teardown log\nrange:     smoketest-gl\n")
    assert _TF_DESTROY_OUT in log
    assert log.splitlines()[-1] == "result: ok"


# This range's state as `terraform state pull` prints it: its deploy id and two
# instances in redstackpro_instances. A random_id.deploy inside a module is not
# the root one and must not be read.
def _state(hex_id, instances):
    return json.dumps({
        "version": 4,
        "resources": [
            {"mode": "managed", "type": "random_id", "name": "deploy",
             "instances": [{"attributes": {"hex": hex_id}}]},
            {"module": "module.other", "mode": "managed", "type": "random_id",
             "name": "deploy", "instances": [{"attributes": {"hex": "ffff0000"}}]},
        ],
        "outputs": {"redstackpro_instances": {"value": instances}},
    })


_SWEEP_STATE = {
    "gcp": {"a": {"name": "smk-jump", "zone": "us-central1-a"},
            "b": {"name": "smk-dc01", "zone": "us-central1-b"}},
    "aws": {"a": {"instance_id": "i-0aaa"}, "b": {"instance_id": "i-0gone"}},
}
# What each cloud CLI answers. The label or tag query finds the orphan an
# interrupted apply left, plus a tracked instance; the instance-id query on AWS
# drops the id that no longer exists. Lines end in \r\n, as on Windows.
_SWEEP_CLI = {
    "gcp": ('case "$*" in *"instances list"*) '
            "printf 'smk-orphan\\tus-central1-a\\r\\nsmk-jump\\tus-central1-a\\r\\n' ;; esac"),
    "aws": ('case "$*" in *"tag:redstackpro_deploy"*) printf \'i-0orphan\\ti-0aaa\\r\\n\' ;; '
            "*\"instance-id,Values=\"*) printf 'i-0aaa\\r\\n' ;; esac"),
}


def _sweep_export(tmp_path, provider, state):
    export, stubs, calls = _manage_export(tmp_path, provider)
    (export / "state.json").write_text(state, encoding="utf-8", newline="\n")
    log = 'echo "$(basename "$0") $*" >> "%s"' % _msys(calls)
    _stub(stubs, "terraform", "\n".join([
        log, 'case "$*" in', '  *"state pull"*) cat state.json ;;', "esac"]))
    cli = {"gcp": "gcloud", "aws": "aws"}[provider]
    _stub(stubs, cli, log + "\n" + _SWEEP_CLI[provider])
    return export, stubs, calls


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
@pytest.mark.parametrize("provider,swept", [
    ("gcp", ["gcloud compute instances list --project example-project "
             "--filter=labels.redstackpro_deploy=abcd1234 "
             "--format=value(name,zone.basename())",
             "gcloud compute instances delete smk-dc01 --zone us-central1-b "
             "--project example-project --quiet",
             "gcloud compute instances delete smk-jump --zone us-central1-a "
             "--project example-project --quiet",
             "gcloud compute instances delete smk-orphan --zone us-central1-a "
             "--project example-project --quiet"]),
    ("aws", ["aws ec2 describe-instances --region eu-west-2 --filters "
             "Name=tag:redstackpro_deploy,Values=abcd1234 "
             "Name=instance-state-name,Values=pending,running,stopping,stopped "
             "--query Reservations[].Instances[].InstanceId --output text",
             "aws ec2 describe-instances --region eu-west-2 --filters "
             "Name=instance-id,Values=i-0aaa,i-0gone "
             "Name=instance-state-name,Values=pending,running,stopping,stopped "
             "--query Reservations[].Instances[].InstanceId --output text",
             "aws ec2 terminate-instances --region eu-west-2 --instance-ids i-0aaa i-0orphan",
             "aws ec2 wait instance-terminated --region eu-west-2 --instance-ids "
             "i-0aaa i-0orphan"]),
])
def test_teardown_force_deletes_only_this_ranges_instances(tmp_path, provider, swept):
    """The sweep used to match the label or tag every redStackPRO range carries,
    so a team with several ranges in one project or region lost all of them. It
    now takes this range's instances from its state, plus whatever carries its
    own deploy id, which finds the instances an interrupted apply never recorded."""
    export, stubs, calls = _sweep_export(tmp_path, provider, _state("abcd1234", _SWEEP_STATE[provider]))
    done = _manage(export, stubs, "teardown", "--force", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    ran = _calls(calls)
    cli = [c for c in ran if not c.startswith("terraform ")]
    assert cli == swept, ran
    assert ran[-1] == "terraform -chdir=terraform destroy -auto-approve"
    assert ran.index("terraform -chdir=terraform state pull") < ran.index(cli[0])


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
@pytest.mark.parametrize("provider", ["gcp", "aws"])
@pytest.mark.parametrize("state", ["", _state("*", {})], ids=["no-state", "wildcard-id"])
def test_teardown_force_without_this_ranges_state_deletes_nothing(tmp_path, provider, state):
    """No state, or a deploy id that is not one (a * would match every range),
    proves nothing about which instance is this range's."""
    export, stubs, calls = _sweep_export(tmp_path, provider, state)
    done = _manage(export, stubs, "teardown", "--force", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "no terraform state for this range" in done.stdout
    ran = _calls(calls)
    assert [c for c in ran if not c.startswith("terraform ")] == [], ran
    assert ran[-1] == "terraform -chdir=terraform destroy -auto-approve"


@pytest.mark.skipif(not hasattr(os, "openpty") or _bash() is None,
                    reason="needs a POSIX pty to stand in for a terminal")
@pytest.mark.parametrize("answer,deleted", [
    ("nope", False), ("", False), ("smoketest", False),
    ("smoketest-gl", True), ("  SmokeTest-GL ", True), ("yes", True), ("YES", True)])
def test_teardown_on_a_terminal_deletes_only_on_the_name_or_yes(tmp_path, answer, deleted):
    export, stubs, calls = _manage_export(tmp_path, "gcp")
    leader, follower = os.openpty()
    try:
        os.write(leader, (answer + "\n").encode())
        done = _manage(export, stubs, "teardown", stdin=follower)
    finally:
        os.close(follower)
        os.close(leader)
    assert "\n Project         example-project\n" in done.stdout
    assert "Type the range name (smoketest-gl) or yes to delete it: " in done.stdout
    ran = _calls(calls)
    if deleted:
        assert done.returncode == 0, done.stdout
        assert ran[-1] == "terraform -chdir=terraform destroy -auto-approve"
    else:
        assert done.returncode == 1
        assert done.stdout.rstrip().endswith("Not confirmed. Nothing was deleted.")
        assert ran == []


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_the_teardown_summary_manage_ps1_reads_is_the_same_text(tmp_path):
    export, stubs, calls = _manage_export(tmp_path, "gcp")
    done = _manage(export, stubs, "_teardown_summary", "--force", ps1=True)
    assert done.returncode == 0, done.stdout
    assert done.stdout.splitlines() == [
        "=" * 62, " TEARDOWN   smoketest-gl", "-" * 62,
        " Provider        GCP us-central1",
        " Project         example-project",
        " --force         first deletes this range's instances, also",
        "                 any left out of its state",
        "=" * 62, "",
        " This deletes the whole range. It cannot be undone.", "",
        "prompt=Type the range name (smoketest-gl) or yes to delete it",
        "name=smoketest-gl"]
    assert _calls(calls) == []
    (export / "deploy.tfvars").unlink()
    gone = _manage(export, stubs, "_teardown_summary", ps1=True)
    assert gone.returncode == 1 and "deploy.tfvars not found" in gone.stdout


def test_MANAGE_ps1_asks_with_read_host_and_then_passes_yes():
    from redstackpro.deploy import MANAGE_PS1
    assert "$words[0] -ceq 'teardown' -and $words -cnotcontains '--yes'" in MANAGE_PS1
    assert "@('_teardown_summary')" in MANAGE_PS1
    assert "Read-Host $prompt" in MANAGE_PS1
    assert "$words += '--yes'" in MANAGE_PS1
    assert MANAGE_PS1.index("Read-Host") < MANAGE_PS1.index("$words += '--yes'") \
        < MANAGE_PS1.index("bash manage.sh $fwd")


_SUMMARY_STUB = """case "$1" in
  _teardown_summary) echo "This deletes the whole range. It cannot be undone."
    echo "prompt=Type the range name (Lab One) or yes to delete it"; echo "name=Lab One" ;;
  *) echo "from-ps1=${REDSTACKPRO_FROM_PS1:-unset}"; for a in "$@"; do echo "[$a]"; done ;;
esac
"""


@pytest.mark.parametrize("answer,ran", [
    ("lab one", True), ("YES", True), ("nope", False), ("", False), (None, False)])
def test_MANAGE_ps1_runs_teardown_only_on_a_confirmed_answer(tmp_path, answer, ran):
    from redstackpro.deploy import MANAGE_PS1
    ps = _powershell()
    if ps is None or _bash() is None:
        pytest.skip("needs Windows PowerShell and Git Bash")
    (tmp_path / "manage.ps1").write_text(MANAGE_PS1, encoding="utf-8")
    (tmp_path / "manage.sh").write_text(_SUMMARY_STUB, encoding="utf-8", newline="\n")
    done = subprocess.run(
        [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(tmp_path / "manage.ps1"), "teardown", "--force"],
        input=None if answer is None else answer + "\n",
        stdin=subprocess.DEVNULL if answer is None else None,
        capture_output=True, text=True, timeout=120)
    assert "This deletes the whole range. It cannot be undone." in done.stdout
    assert "name=" not in done.stdout and "prompt=" not in done.stdout
    if ran:
        assert done.returncode == 0, done.stdout + done.stderr
        assert "from-ps1=1\n[teardown]\n[--force]\n[--yes]\n" in done.stdout
    else:
        assert done.returncode == 1
        assert "[teardown]" not in done.stdout
        assert "Nothing was deleted." in done.stdout


def test_MANAGE_ps1_prints_the_powershell_help_from_a_real_export(tmp_path):
    ps = _powershell()
    if ps is None or _bash() is None:
        pytest.skip("needs Windows PowerShell and Git Bash")
    files = compile_topology(_smoketest_gl(), Registry(), provider="azure")
    for name in ("manage.ps1", "manage.sh", "deploy.tfvars"):
        (tmp_path / name).write_text(files[name], encoding="utf-8", newline="\n")
    done = subprocess.run(
        [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(tmp_path / "manage.ps1")],
        capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.startswith(WORDMARK + "=" * 62 + "\n MANAGE   smoketest-gl\n"
                                  + "-" * 62 + "\n Provider        Azure eastus2\n"
                                  " Resource group  smk-smoketest-gl-rg\n")
    assert done.stdout.endswith("  .\\manage.ps1 status\n  .\\manage.ps1 teardown\n")
    # PowerShell's output is redirected here, so it asks for no colour.
    assert "\x1b" not in done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
@pytest.mark.parametrize("provider,expect", [
    ("azure", "az vm list -g smk-lab-rg -d --query sort_by([?contains(['smk-dc01','smk-jump'], "
              "name)], &name)[].{Name:name, State:powerState, PublicIP:publicIps} -o table"),
    ("gcp", "gcloud compute instances list --project example-project --zones "
            "us-central1-a,us-central1-b --filter=name=(smk-dc01 smk-jump) --sort-by=name "
            "--format=table(name,zone.basename(),status,"
            "networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP)"),
    ("aws", "aws ec2 describe-instances --region eu-west-2 --instance-ids i-1 i-2 --query "
            "Reservations[].Instances[].{name:Tags[?Key==`Name`]|[0].Value,state:State.Name,"
            "ip:PublicIpAddress} --output table"),
])
def test_status_is_one_list_call_for_the_whole_range(tmp_path, provider, expect):
    """Live on Azure: status printed a header block per VM, five for a five-VM
    range. One call returns one table."""
    export, stubs, calls = _manage_export(tmp_path, provider)
    done = _manage(export, stubs, "status")
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.splitlines()[1] == " STATUS   smoketest-gl"
    assert " Portal          https://203.0.113.9/guacamole\n" + "=" * 62 + "\n" in done.stdout
    cloud = [c for c in _calls(calls) if not c.startswith("terraform ")]
    assert cloud == [expect]


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
    assert ("      project is empty in deploy.tfvars. Set it to your GCP project ID.\n"
            "      To see the current one, run:\n"
            "        gcloud config get-value project\n") in done.stdout, done.stdout
    assert (" Reason    project is empty in deploy.tfvars. Set it to your GCP project "
            "ID.\n") in done.stdout
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
    assert ("      To see it, run:\n"
            "        az account show --query id -o tsv\n") in done.stdout, done.stdout
    assert (" Reason    subscription_id is empty in deploy.tfvars. Set it to your "
            "subscription id.\n") in done.stdout

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
JUMP_IP = "198.51.100.159"


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
    # Each command alone on its own line under a "run:" label, so a copied line
    # is the whole command. The Watch command was split over two lines, and the
    # second half got pasted into PowerShell after the first opened a shell.
    assert box[:11] == [
        " DONE  Infrastructure is up. Provisioning is running.",
        "-" * 62,
        " Portal    https://%s/guacamole" % JUMP_IP,
        "",
        " Logins, run:",
        "   terraform -chdir=terraform output guacamole",
        "",
        " Watch provisioning, run (Ctrl-C stops watching, not the build):",
        '   ssh -i keys/id_ed25519 blueop@%s "tail -f ~/provision/run.log"' % JUMP_IP,
        "",
        " Finished  when run.log shows RUN EXITED ok=1 (45-75 min)"]
    assert re.fullmatch(r" Log       logs/deploy-\d{8}-\d{6}Z\.log", box[11]), box[11]
    assert box[12] == "=" * 62
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
    assert ('\n   ssh -i keys\\id_ed25519 blueop@%s "tail -f ~/provision/run.log"\n'
            % JUMP_IP) in done.stdout
    assert re.search(r"^ Log       logs\\deploy-\d{8}-\d{6}Z\.log$", done.stdout, re.M)


# terraform apply as it prints on Azure: colour codes, refresh lines, the plan,
# progress, a warning box and the completion lines with ids.
_TF_APPLY_OUT = "\n".join([
    "random_password.lab: Refreshing state... [id=none]",
    "\x1b[0m\x1b[1mmodule.smk_jumpbox.azurerm_public_ip.this\x1b[0m will be created",
    "  \x1b[32m+\x1b[0m resource \"azurerm_public_ip\" \"this\" {",
    "\x1b[1mPlan:\x1b[0m 2 to add, 0 to change, 0 to destroy.",
    "module.smk_jumpbox.azurerm_public_ip.this: Creating...",
    "module.smk_jumpbox.azurerm_public_ip.this: Creation complete after 2s "
    "[id=/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/smk-jumpbox]",
    "module.smk_wks01.azurerm_virtual_machine_extension.winrm[0]: Still creating... [10s elapsed]",
    "module.smk_wks01.azurerm_virtual_machine_extension.winrm[0]: Creation complete after 1m55s "
    "[id=/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/smk-wks01"
    "/extensions/redstackpro-winrm]",
    "╷", "│ Warning: Argument is deprecated", "│ ", "│ use another", "╵",
    "Apply complete! Resources: 2 added, 0 changed, 0 destroyed.",
    "lab_password = Lab-Pass-123",
])


def _apply_prints(stubs, text):
    """Have the terraform stub print text on apply, as terraform would."""
    out = stubs / "terraform-apply.out"
    out.write_text(text + "\n", encoding="utf-8", newline="\n")
    tf = stubs / "terraform"
    tf.write_text(tf.read_text(encoding="utf-8").replace(
        '*apply*) echo "lab_password = Lab-Pass-123"; echo "Apply complete!" ;;',
        '*apply*) cat "%s" ;;' % _msys(out)), encoding="utf-8", newline="\n")


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_terraform_apply_is_condensed_on_screen_and_whole_in_the_log(tmp_path):
    """The apply printed the whole plan, about 1000 lines for a 5-VM range."""
    export, stubs, _ = _range_export(tmp_path)
    _apply_prints(stubs, _TF_APPLY_OUT)
    done = _run(export, stubs)
    assert done.returncode == 0, done.stdout + done.stderr
    out = done.stdout
    apply = out[out.index("[2/8] Terraform apply"):out.index("[3/8]")].splitlines()[1:]
    shown = [line for line in apply if line]
    assert shown[:-1] == [
        "      plan  2 to add, 0 to change, 0 to destroy",
        "      +     2s  smk-jumpbox (public ip)",
        "      +  1m55s  smk-wks01/redstackpro-winrm (virtual machine extension)",
        "      warning  Argument is deprecated"], apply
    assert re.fullmatch(r"      ok  3 resources in \d+s", shown[-1]), shown
    log = _log(export)
    for line in _TF_APPLY_OUT.splitlines():
        if "Lab-Pass" not in line:
            assert re.sub("\x1b\\[[0-9;]*m", "", line) in log, line
    assert "Lab-Pass-123" not in log
    assert "\x01" not in out + log and "\x02" not in out + log


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_failed_apply_shows_the_error_block_whole(tmp_path):
    export, stubs, _ = _range_export(tmp_path)
    _apply_prints(stubs, "\n".join([
        "Plan: 1 to add, 0 to change, 0 to destroy.",
        "╷", "│ Error: creating Windows Virtual Machine: QuotaExceeded",
        "│ ", "│   with module.smk_dc01.azurerm_windows_virtual_machine.this,", "╵"]))
    tf = stubs / "terraform"
    tf.write_text(tf.read_text(encoding="utf-8").replace(
        "\nexit 0", '\ncase "$*" in *apply*) exit 1 ;; esac\nexit 0'),
        encoding="utf-8", newline="\n")
    done = _run(export, stubs)
    assert done.returncode == 1, done.stdout
    assert ("      │ Error: creating Windows Virtual Machine: QuotaExceeded\n"
            "      │ \n"
            "      │   with module.smk_dc01.azurerm_windows_virtual_machine.this,\n") in done.stdout
    assert " FAILED  [2/8] Terraform apply" in done.stdout


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_colour_reaches_the_terminal_and_never_the_log(tmp_path):
    """The log is the file a user attaches to an issue. terraform's own plan
    colours once filled 1028 lines of it with escape codes."""
    export, stubs, _ = _range_export(tmp_path)
    _apply_prints(stubs, _TF_APPLY_OUT)
    done = _run(export, stubs, env_extra={"REDSTACKPRO_COLOR": "1"})
    assert done.returncode == 0, done.stdout + done.stderr
    out = done.stdout
    assert "\x1b[32m+\x1b[0m     2s  smk-jumpbox (public ip)" in out
    assert "\x1b[32mok\x1b[0m" in out
    assert "\x1b[32m\x1b[1mDONE\x1b[0m" in out
    log = _log(export)
    assert "\x1b" not in log
    assert "Creation complete after 2s [id=/subscriptions/s/" in log
    assert " DONE  Infrastructure is up. Provisioning is running." in log
    assert log.splitlines()[-1] == "result: ok"
    # The wordmark is the terminal's alone.
    assert out.startswith("\x1b[31m\x1b[1m" + WORDMARK)
    assert WORDMARK not in log


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_no_color_wins_and_a_pipe_gets_no_colour(tmp_path):
    export, stubs, _ = _range_export(tmp_path)
    for env in ({"REDSTACKPRO_COLOR": "1", "NO_COLOR": "1"}, {}):
        done = _run(export, stubs, env_extra=env)
        assert done.returncode == 0, done.stdout + done.stderr
        assert "\x1b" not in done.stdout, env
    (tmp_path / "m").mkdir()
    export, stubs, _ = _manage_export(tmp_path / "m", "azure")
    on = _manage(export, stubs, env_extra={"REDSTACKPRO_COLOR": "1"}).stdout
    assert "  \x1b[36mstatus          \x1b[0m  " in on
    assert "\x1b[33mCannot be undone.\x1b[0m" in on
    off = _manage(export, stubs, env_extra={"REDSTACKPRO_COLOR": "1", "NO_COLOR": "1"}).stdout
    assert "\x1b" not in off
    assert off == re.sub("\x1b\\[[0-9;]*m", "", on), "colour is all that differs"


def test_the_ps1_wrappers_pass_their_colour_choice():
    from redstackpro.deploy import MANAGE_PS1
    for ps1 in (DEPLOY_PS1, MANAGE_PS1):
        assert "-not [Console]::IsOutputRedirected -and $Host.UI.SupportsVirtualTerminal" in ps1
        assert "-not $env:NO_COLOR" in ps1
        assert "@@" not in ps1
    assert "REDSTACKPRO_COLOR=$color REDSTACKPRO_KEY_ACL='$keyacl' bash deploy.sh" in DEPLOY_PS1
    assert MANAGE_PS1.count("REDSTACKPRO_COLOR=$color bash manage.sh") == 2


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_a_key_path_with_a_space_is_quoted_in_the_watch_command(tmp_path):
    export, stubs, _ = _range_export(tmp_path)
    key = export / "my keys" / "id_ed25519"
    key.parent.mkdir()
    key.write_text("not a real key", encoding="utf-8")
    done = _run(export, stubs, env_extra={"REDSTACKPRO_SSH_KEY": "my keys/id_ed25519"})
    assert done.returncode == 0, done.stdout + done.stderr
    assert ('\n   ssh -i "my keys/id_ed25519" blueop@%s "tail -f ~/provision/run.log"\n'
            % JUMP_IP) in done.stdout


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
    assert " Reason    GCP credentials are not set.\n" in done.stdout
    # Two commands, each alone on its own line, not joined with && on the reason.
    assert ("      To sign in, run both:\n        gcloud auth login\n"
            "        gcloud auth application-default login\n") in done.stdout
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


_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'')


@pytest.mark.parametrize("provider", ["gcp", "aws", "azure", "proxmox"])
def test_script_messages_use_no_double_hyphen_as_a_dash(provider):
    """' -- ' read as a dash in 22 messages; the house rule is plain punctuation.
    A double hyphen inside a quoted string on a code line is a message."""
    # The offense example does not validate on Proxmox (no peering there).
    docs = [load(GOAD_LIGHT)] + ([] if provider == "proxmox" else [example("redstack.json")])
    for doc in docs:
        files = compile_topology(doc, Registry(), provider=provider)
        for name in ("deploy.sh", "manage.sh", "deploy.ps1", "manage.ps1"):
            for n, line in enumerate((files.get(name) or "").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                for text in _QUOTED.findall(line):
                    assert " -- " not in text, "%s:%d %s" % (name, n, line.strip())


def test_role_task_names_and_labels_use_no_double_hyphen_as_a_dash():
    roles = Path(__file__).resolve().parents[1] / "src/redstackpro/assets/ansible/roles"
    for path in roles.rglob("*.yml"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.match(r"\s*(- )?(name|label|msg):", line):
                assert " -- " not in line, "%s:%d %s" % (path.relative_to(roles), n, line.strip())


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
def test_deploy_sh_and_its_runner_are_valid_bash(tmp_path, provider, name):
    bash = _bash()
    if bash is None:
        pytest.skip("no bash to syntax-check the emitted script")
    script = generate_deploy_script(example(name), Registry(), provider=provider)
    # Files, not bash -c: deploy.sh outgrew what a Windows command line carries,
    # and Git Bash silently cut the -c argument short.
    for i, body in enumerate((script, _remote_block(script, "RUNNER"))):
        path = tmp_path / ("check%d.sh" % i)
        path.write_text(body, encoding="utf-8", newline="\n")
        done = subprocess.run([bash, "-n", path.name], cwd=tmp_path,
                              capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
