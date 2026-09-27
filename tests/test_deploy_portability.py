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
                if stripped.endswith("<<'%s'" % marker):
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
        if not inside and line.strip().endswith("<<'%s'" % marker):
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
    assert code.index("exit 1", abort_at) < code.index('say "terraform apply"')


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
    assert "tar xzf -" in script


def test_staging_still_clears_what_it_replaces(script):
    """rsync carried --delete. Without an equivalent, a re-deploy into a reused
    export leaves files the new compile no longer emits and ansible runs them."""
    stage = [line for line in script.splitlines() if "tar xzf -" in line][0]
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
    document = {"schema_version": "0.6.0", "mode": "artie", "name": "no jumpbox",
                "nodes": [], "edges": []}
    files = compile_topology(document, Registry(), provider="gcp")
    assert "deploy.tfvars" not in files
    assert "terraform/terraform.tfvars" in files


def test_a_topology_with_no_jumpbox_gets_neither_wrapper_nor_keys():
    """Both only mean anything alongside a deploy, and a topology with no jumpbox
    has nothing to deploy through."""
    document = {"schema_version": "0.6.0", "mode": "artie", "name": "no jumpbox",
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
    return subprocess.run([bash, "-c", command], cwd=script_dir, env=env,
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

    The absence of gcloud is deliberate and load bearing: it is the checkpoint
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
    assert "terraform apply" not in done.stdout


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


@pytest.mark.skipif(_bash() is None, reason="no bash to run the emitted script")
def test_open_ingress_aborts_the_run_and_the_override_lets_it_through(staged):
    """Executed. The shipped example's tfvars carries operator_source_ranges
    0.0.0.0/0, so a real run must abort at the ingress check, and only the explicit
    override may carry it past."""
    export, stubs = staged
    _stub(stubs, "python", 'exec %s "$@"' % Path(sys.executable).as_posix())
    # gcloud must succeed so the run reaches the ingress check that follows it.
    _stub(stubs, "gcloud", "exit 0")

    blocked = _run(export, stubs)
    assert blocked.returncode == 1
    assert "operator_source_ranges is 0.0.0.0/0" in blocked.stdout, blocked.stdout
    assert "terraform apply" not in blocked.stdout

    allowed = _run(export, stubs, env_extra={"REDSTACKPRO_ALLOW_OPEN_INGRESS": "1"})
    # The abort message names the exposure; the warning does not. Only the abort
    # must be gone, and the run must reach apply.
    assert "which exposes ssh and the portal" not in allowed.stdout, allowed.stdout
    assert "terraform apply" in allowed.stdout, allowed.stdout + allowed.stderr


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
    assert "version:   0.9.0" in script
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
    exit_at = manage_script.index("exit $?", teardown_at)
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
    assert "aws ec2" not in gcp


def test_an_untested_provider_still_gets_teardown_but_says_so_for_the_rest():
    """Only aws and gcp are wired for live status/start/stop. A provider without
    that support must not block the export or the teardown path, which is
    provider agnostic; it just has to say plainly that the rest is not there."""
    other = generate_manage_script(example("redstack.json"), Registry(), provider="azure")
    assert other is not None
    assert "terraform -chdir=terraform destroy -auto-approve" in other
    assert "not implemented" in other


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


def test_manage_scripts_ship_only_alongside_the_deploy():
    """Both only mean anything once something has been deployed through a
    jumpbox, exactly like deploy.sh/deploy.ps1."""
    doc = {"schema_version": "0.6.0", "mode": "artie", "name": "no jumpbox",
           "nodes": [], "edges": []}
    files = compile_topology(doc, Registry(), provider="gcp")
    assert "manage.sh" not in files
    assert "manage.ps1" not in files
