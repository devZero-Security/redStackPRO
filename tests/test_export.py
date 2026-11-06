"""Export assembly is the artifact 0010 makes primary: the archive endpoint and
the CLI are both formatters over compile_topology, so the assembly is tested here
rather than through either one. It joins generated code to the static modules and
roles, and it ships one provider's modules, not all three. See 0010 and 0015.
"""

import json
from pathlib import Path

import pytest

from redstackpro import Registry
from redstackpro.deploy import generate_deploy_script
from redstackpro.export import CLI_INSTALL, compile_topology, static_files

GOAD_LIGHT = (Path(__file__).resolve().parent.parent
              / "frontend/public/goad/goad-light.json")


def _topology(mode, nodes):
    return {"schema_version": "0.4.0", "mode": mode, "nodes": nodes, "edges": []}


def test_compile_ships_a_deploy_script_for_a_topology_with_a_jumpbox(redstack, registry):
    files = compile_topology(redstack, registry=registry, provider="gcp")
    assert "deploy.sh" in files
    body = files["deploy.sh"]
    # The one-command deploy: apply, then provision from the jumpbox (the managed
    # hosts are on a private subnet only it can reach).
    assert "terraform -chdir=terraform apply" in body
    assert "provision" in body


def test_deploy_script_is_mode_aware(registry):
    jb = {"id": "jump", "kind": "jumpbox",
          "overlay": {"services": ["ssh", "guacamole"]}}
    rng = generate_deploy_script(_topology("defense", [jb]), registry)
    ops = generate_deploy_script(_topology("offense", [jb]), registry)
    # A range waits for an authenticated win_ping before promoting a fresh Windows
    # host and leaves the jumpbox out of the AD plays; an offense platform neither
    # gates on win_ping nor limits the jumpbox out.
    assert "win_ping" in rng and "!jumpboxes" in rng
    assert "win_ping" not in ops and "!jumpboxes" not in ops


def test_MANAGE_deploy_script_provisions_the_jumpbox_in_a_pass_of_its_own(registry):
    # A range limits the jumpbox out of the AD retry loop, so something else has
    # to run its play: for the first year nothing did, and every range came up
    # with no Guacamole portal and no assumed-breach foothold account while the
    # run still reported ok=1. The jumpbox pass must exist, and it must come
    # BEFORE the win_ping gate -- the portal is how the operator reaches the
    # range, so it cannot wait on a Windows box finishing its boot.
    jb = {"id": "jump", "kind": "jumpbox",
          "overlay": {"services": ["ssh", "guacamole"]}}
    rng = generate_deploy_script(_topology("defense", [jb]), registry)
    assert "--limit jumpboxes" in rng
    assert rng.index("--limit jumpboxes") < rng.index("win_ping")


def test_deploy_script_absent_without_a_jumpbox(registry):
    # Nothing to stage a provision through, so no deploy.sh is emitted.
    ts = {"id": "ts", "kind": "teamserver", "overlay": {}}
    assert generate_deploy_script(_topology("offense", [ts]), registry) is None


@pytest.mark.parametrize("provider", ["aws", "gcp"])
def test_every_compiled_file_ships_with_lf_line_endings(redstack, registry, provider):
    # Uniform across every provider and mode: no stray CR that would break a
    # shell script's shebang or a heredoc on the operator's box. The whole tree
    # is normalized at the compile choke point.
    for path, contents in compile_topology(
            redstack, registry=registry, provider=provider).items():
        assert "\r" not in contents, "CR in %s" % path


def test_gcp_deploy_script_checks_cloud_credentials(redstack, registry):
    gcp = compile_topology(redstack, registry=registry, provider="gcp")["deploy.sh"]
    aws = compile_topology(redstack, registry=registry, provider="aws")["deploy.sh"]
    assert "gcloud auth application-default" in gcp
    assert "gcloud auth application-default" not in aws


def _stopping_topology(registry_nodes=None):
    jb = {"id": "jump", "kind": "jumpbox",
          "overlay": {"services": ["ssh", "guacamole"]}}
    doc = _topology("defense", registry_nodes or [jb])
    doc["auto_stop"] = {"enabled": True, "at": "02:00", "timezone": "UTC"}
    return doc


def test_a_build_that_would_stop_mid_provision_refuses_to_start(registry):
    """auto_stop is a DAILY wall-clock time and after_hours is resolved at COMPILE
    time, because a cron schedule cannot count from an apply. So a build compiled
    hours before it is applied has already eaten that gap, and the stop can fire
    during a provision that runs up to 75 minutes -- leaving a half-built range
    behind a run that reported no error. The guard belongs at the apply boundary,
    which is where the trap springs, not at compile time, where it is set.
    """
    body = generate_deploy_script(_stopping_topology(), registry, provider="gcp")
    # It must guard the apply, not merely mention the stop somewhere.
    assert body.index("RSP_STOP_LEAD") < body.index("terraform -chdir=terraform apply")
    assert 'REDSTACKPRO_MIN_STOP_LEAD:-150' in body
    # The one-line fix has to be named: a refusal the operator cannot act on is
    # just an obstacle. The guard is only emitted for a fixed `at`, so the fix is
    # moving that time (re-exporting the same value changes nothing).
    assert ("In the canvas, open the Inspector tab and click empty space, then "
            "Topology settings > Auto-stop, and export again.") in body
    assert "re-run the compile now" not in body
    assert "REDSTACKPRO_MIN_STOP_LEAD=0" in body, "an override must exist"


def test_the_stop_check_cannot_pass_by_failing(registry):
    """The first cut defaulted to a large lead when python3 failed, which turned a
    broken check into a silent all-clear -- the same shape as an audit script
    printing 0 for every resource because its token had expired. "Could not ask"
    must never be indistinguishable from "nothing to worry about".
    """
    body = generate_deploy_script(_stopping_topology(), registry, provider="gcp")
    assert "${RSP_STOP_LEAD:-9999}" not in body, "a safe default hides a broken check"
    # A non-numeric result (python3 missing, or erroring) takes the abort path.
    guard = body[body.index('case "$RSP_STOP_LEAD"'):]
    assert "''|*[!0-9]*)" in guard
    assert guard.index("die ") < guard.index("esac")


def test_no_ttl_means_no_stop_preflight(registry):
    """A topology that never asked for a TTL should not meet a check about one."""
    jb = {"id": "jump", "kind": "jumpbox",
          "overlay": {"services": ["ssh", "guacamole"]}}
    body = generate_deploy_script(_topology("defense", [jb]), registry, provider="gcp")
    assert "RSP_STOP_LEAD" not in body


# -- the stop lead is measured in the stop's own zone, tz database or not

def _has_tz_database():
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo("America/New_York")
        return True
    except Exception:
        return False


needs_tz_database = pytest.mark.skipif(
    not _has_tz_database(),
    reason="no IANA tz database here; tzdata is a dependency (pip install -e .)")


def _lead_topology(tz, offset_minutes):
    """A stop five hours from now on the clock of a zone at that UTC offset."""
    import datetime as dt
    now = dt.datetime.now(dt.timezone(dt.timedelta(minutes=offset_minutes)))
    at = now + dt.timedelta(hours=5)
    doc = _stopping_topology()
    doc["auto_stop"] = {"enabled": True, "at": at.strftime("%H:%M"), "timezone": tz}
    return doc


def _lead(body, zoneinfo):
    """Run the guard's Python as deploy.sh does, optionally with zoneinfo gone, as
    on a Python with no tz database to find."""
    import subprocess
    import sys
    marker = "RSP_STOP_LEAD=$(\"$PY\" -c '"
    code = body[body.index(marker) + len(marker):]
    code = code[:code.index("\n')")]
    assert "'" not in code, "the guard sits in single quotes in deploy.sh"
    block = "" if zoneinfo else "sys.modules['zoneinfo'] = None; "
    return subprocess.run(
        [sys.executable, "-c", "import sys; %sexec(sys.argv[1])" % block, code],
        capture_output=True, text=True, timeout=60)


def _assert_lead_is_five_hours(done):
    assert done.returncode == 0, done.stderr
    # 300 minutes, less the seconds already gone in this minute. Read in UTC it
    # would be off by the zone's offset.
    assert 298 <= int(done.stdout) <= 300, done.stdout


def test_without_a_tz_database_the_stop_lead_uses_the_offset_from_export(registry, monkeypatch):
    """Found live on Windows: zoneinfo had no database, the guard read
    America/New_York as UTC, and a build at 12:34 with an 18:00 stop was refused
    as 25 minutes away. The export now carries the zone's offset for that case."""
    import redstackpro.deploy as deploy
    monkeypatch.setattr(deploy, "_stop_zone", lambda tz: ("Asia/Kolkata", 330))
    body = generate_deploy_script(_lead_topology("Asia/Kolkata", 330), registry,
                                  provider="gcp")
    assert "OFFSET = 330" in body
    _assert_lead_is_five_hours(_lead(body, zoneinfo=False))
    _assert_lead_is_five_hours(_lead(body, zoneinfo=True))


@needs_tz_database
@pytest.mark.parametrize("tz,provider", [
    ("America/New_York", "gcp"), ("Asia/Kolkata", "aws"),
    ("Europe/London", "azure"), ("Eastern Standard Time", "azure")])
def test_the_stop_lead_is_measured_in_the_stop_zone(registry, tz, provider):
    import datetime as dt
    from zoneinfo import ZoneInfo
    from redstackpro.deploy import _stop_zone
    zone, offset = _stop_zone(tz)
    assert zone == ("America/New_York" if tz == "Eastern Standard Time" else tz)
    expect = ZoneInfo(zone).utcoffset(dt.datetime.now(dt.timezone.utc))
    assert offset == expect.total_seconds() // 60
    body = generate_deploy_script(_lead_topology(tz, offset), registry, provider=provider)
    assert 'ZoneInfo("%s")' % zone in body
    # The message still names the zone the way the topology does.
    assert "%s, which is $RSP_STOP_LEAD minutes away" % tz in body
    _assert_lead_is_five_hours(_lead(body, zoneinfo=True))
    _assert_lead_is_five_hours(_lead(body, zoneinfo=False))


def test_utc_needs_no_tz_database():
    from redstackpro.deploy import _stop_zone
    assert _stop_zone("UTC") == ("UTC", 0)
    assert _stop_zone("Etc/UTC") == ("UTC", 0)


@pytest.mark.parametrize("tz", ["Mars/Olympus", "Mars Standard Time"])
def test_a_zone_the_export_cannot_resolve_says_the_check_did_not_run(registry, tz):
    """No offset to fall back on, so the guard takes its could-not-run branch,
    the same as a broken interpreter, rather than guessing the zone."""
    body = generate_deploy_script(_lead_topology(tz, 0), registry, provider="gcp")
    assert "OFFSET = None" in body
    for zoneinfo in (True, False):
        done = _lead(body, zoneinfo)
        assert done.returncode == 1 and done.stdout == "", (zoneinfo, done.stdout)


def test_the_guide_watches_provisioning_with_one_command(redstack):
    """The same one-line form the DONE box prints: ssh running rsp-watch, which
    returns when the run ends. tail -f never returned (Mike, 2026-11-06)."""
    for doc, user in ((redstack, "redop"), (_goad_light(), "blueop")):
        guide = _guide(doc)
        assert "\nssh -i keys/id_ed25519 %s@<jumpbox> rsp-watch\n" % user in guide
        assert "tail -f" not in guide


def test_the_run_step_says_the_powershell_scripts_are_unsigned(redstack):
    """One sentence where deploy.ps1 is run. It names the execution policy and
    stops there: no bypass or policy change is spelled out."""
    for doc in (redstack, _goad_light()):
        guide = _guide(doc)
        start = guide.index(".\\deploy.ps1\n```")
        run = guide[start:guide.index("**macOS and Linux**", start)]
        assert ("`deploy.ps1` and `manage.ps1` are unsigned, so PowerShell's "
                "execution policy has\nto allow them.") in run
        for word in ("Bypass", "Unblock-File", "Set-ExecutionPolicy"):
            assert word not in guide


def test_tzdata_is_a_dependency():
    """zoneinfo finds no zones on Windows or a slim image without it, and the
    export embeds a zone's offset only when the compiler can resolve the zone."""
    import tomllib
    pyproject = tomllib.loads(
        (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8"))
    assert any(d.startswith("tzdata") for d in pyproject["project"]["dependencies"])


def test_the_dns_action_shows_what_the_name_resolves_to_today(registry):
    """Every apply mints a new address while the canvas hands out a STATIC
    hostname, so a stale record is the default state rather than an accident.
    "Create an A record" reads as already-done to an operator whose record exists
    and merely points at the last deploy -- which cost a whole session of beacon
    callbacks on 2026-09-14. Print both halves so the delta is unmissable.
    """
    rd = {"id": "rd", "kind": "redirector",
          "overlay": {"hostname": "cdn.example.net",
                      "tls": {"cert_source": "letsencrypt"}}}
    jb = {"id": "jump", "kind": "jumpbox",
          "overlay": {"services": ["ssh", "guacamole"]}}
    body = generate_deploy_script(_topology("offense", [jb, rd]), registry, provider="gcp")
    assert "socket.gethostbyname" in body, "the live value must be looked up"
    assert "a stale record from an earlier deploy" in body
    # And it must stay quiet when there is genuinely nothing to do, or the notice
    # becomes noise the operator learns to scroll past.
    assert "nothing to do" in body


def test_no_kali_image_builder_is_shipped():
    # GCP boots debian-12 for a Kali operator and the operator role converts it,
    # so there is no image to build and no builder to ship.
    assert "build-kali-image.sh" not in static_files("gcp")
    assert "build-kali-image.sh" not in static_files("aws")


def test_static_files_ship_only_the_requested_provider():
    files = static_files("aws")
    assert any(p.startswith("terraform/modules/aws/") for p in files)
    # Shipping the other providers' modules would leave two thirds of the tree
    # unreferenced, and terraform init reads every directory it can reach.
    assert not any(p.startswith("terraform/modules/gcp/") for p in files)
    assert not any(p.startswith("terraform/modules/proxmox/") for p in files)


def test_static_files_include_the_role_library_and_the_inventory_tool():
    files = static_files("gcp")
    assert "ansible/requirements.yml" in files
    assert "tf_inventory.py" in files
    assert any(p.startswith("ansible/roles/") for p in files)


def test_static_files_ship_the_verify_checker():
    # The export carries its own redirector/stack checker so an operator with only
    # the download can run `python verify.py doors .`. See verify.py.
    files = static_files("gcp")
    assert "verify.py" in files
    assert "def check_doors" in files["verify.py"]


def test_static_files_ship_an_ansible_cfg_with_a_task_timeout_ceiling():
    # The export root is where the README runs ansible-playbook, so ansible.cfg
    # sits there. task_timeout caps any single task so a wedged installer fails
    # and can be recovered by a re-run instead of hanging the whole deploy.
    files = static_files("gcp")
    assert "ansible.cfg" in files
    assert "task_timeout" in files["ansible.cfg"]


def test_static_files_reject_an_unknown_provider():
    with pytest.raises(FileNotFoundError):
        static_files("digitalocean")


def test_compile_topology_produces_a_complete_working_directory(redstack, registry):
    files = compile_topology(redstack, registry=registry, provider="aws")
    assert "DEPLOYMENT-GUIDE.md" in files
    assert "terraform/main.tf" in files
    assert any(p.startswith("ansible/host_vars/") for p in files)
    # The static half is stitched in, not just the generated half.
    assert any(p.startswith("terraform/modules/aws/") for p in files)


def test_compiled_provider_reaches_both_the_modules_and_the_readme(redstack, registry):
    aws = compile_topology(redstack, registry=registry, provider="aws")
    assert any(p.startswith("terraform/modules/aws/") for p in aws)
    assert "aws" in aws["DEPLOYMENT-GUIDE.md"]


def test_readme_hints_are_provider_specific(redstack, registry):
    aws = compile_topology(redstack, registry=registry, provider="aws")["DEPLOYMENT-GUIDE.md"]
    gcp = compile_topology(redstack, registry=registry, provider="gcp")["DEPLOYMENT-GUIDE.md"]
    assert "region" in aws          # aws tfvars list
    assert "project" in gcp         # gcp tfvars list
    # The Kali Marketplace subscription is an aws-only precondition.
    assert "Marketplace" in aws
    assert "Marketplace" not in gcp


# The marker each provider's quota note carries. Proxmox and ESXi carry none.
QUOTA_MARKERS = {"gcp": "CPUS_ALL_REGIONS", "aws": "Elastic IPs",
                 "azure": "SkuNotAvailable"}


@pytest.mark.parametrize("provider", ["gcp", "aws", "azure", "proxmox", "esxi"])
def test_each_guide_carries_its_own_quota_note_and_no_other(redstack, registry, provider):
    """The GCP CPUS_ALL_REGIONS note used to ship in every offense guide, AWS's
    included, while the AWS deploy.sh points at the guide for Elastic IP and
    vCPU limits it never covered, and a defense guide had no quota note at all."""
    goad_light = json.loads(GOAD_LIGHT.read_text(encoding="utf-8"))
    guides = [compile_topology(goad_light, registry=registry,
                               provider=provider)["DEPLOYMENT-GUIDE.md"]]
    if provider in QUOTA_MARKERS:
        guides.append(compile_topology(redstack, registry=registry,
                                       provider=provider)["DEPLOYMENT-GUIDE.md"])
    for guide in guides:
        for other, marker in QUOTA_MARKERS.items():
            assert (marker in guide) == (other == provider), (provider, marker)
        assert ("## Quotas" in guide) == (provider in QUOTA_MARKERS)


def test_the_aws_quota_note_names_what_deploy_sh_points_at(redstack, registry):
    """deploy.sh tells an AWS user to see the guide for Elastic IP and vCPU
    headroom, so the guide has to answer with the numbers."""
    guide = compile_topology(redstack, registry=registry,
                             provider="aws")["DEPLOYMENT-GUIDE.md"]
    assert "DEPLOYMENT-GUIDE.md" in compile_topology(
        redstack, registry=registry, provider="aws")["deploy.sh"]
    assert "5 Elastic IPs per region" in guide
    assert "defense range takes 2" in guide and "offense stack 3" in guide
    assert "vCPU" in guide


# -- manage.sh / manage.ps1 (status, start, stop, teardown)

def test_manage_scripts_ship_alongside_the_deploy(redstack, registry):
    """Only meaningful once something has been deployed through a jumpbox,
    exactly like deploy.sh/deploy.ps1, and they ship or vanish together."""
    files = compile_topology(redstack, registry=registry, provider="gcp")
    assert "manage.sh" in files
    assert "manage.ps1" in files


def test_manage_script_is_provider_correct(redstack, registry):
    aws = compile_topology(redstack, registry=registry, provider="aws")["manage.sh"]
    gcp = compile_topology(redstack, registry=registry, provider="gcp")["manage.sh"]
    assert "aws ec2 start-instances" in aws and "gcloud" not in aws
    assert "gcloud compute instances" in gcp and "aws ec2" not in gcp


def test_compile_region_flows_into_the_tfvars(redstack, registry):
    """The compile --region override (and a document region) must reach the
    generated deploy.tfvars, not just the variables.tf default, or the user edits
    a region the deploy ignores."""
    files = compile_topology(
        redstack, registry=registry, provider="gcp", region="us-central1"
    )
    tfvars = files["deploy.tfvars"]
    assert '"us-central1"' in tfvars
    assert '"us-central1-a"' in tfvars


def test_deployment_guide_documents_managing_the_range(redstack, registry):
    guide = compile_topology(redstack, registry=registry, provider="gcp")["DEPLOYMENT-GUIDE.md"]
    assert "manage.ps1" in guide
    assert "manage.sh" in guide
    assert "teardown" in guide


@pytest.mark.parametrize("provider,sweep", [
    ("gcp", "It never touches another deployment in the same project."),
    ("aws", "It never touches another deployment in the same region."),
    ("azure", "It first deletes the deployment's resource group and everything in"),
])
def test_the_guide_says_teardown_asks_first_and_what_force_deletes(redstack, provider, sweep):
    guide = _guide(redstack, provider)
    assert "asks you to type the range name (or `yes`)" in guide
    assert "Add `--yes` to skip the question" in guide
    assert "Run it with no command for a help\nscreen" in guide
    assert sweep in guide
    assert "deletes this deployment's instances in the\ncloud first" not in guide
    assert "every redStackPRO instance" not in guide
    range_guide = _guide(_goad_light(), provider)
    assert "asks you to type the range name (or `yes`)" in range_guide


@pytest.mark.parametrize("provider", ["../../roles", "..", "gcp/../aws", "/etc",
                                      "C:\Windows", "GCP", "", "aws/"])
def test_static_files_refuses_a_provider_that_is_not_a_bare_name(provider):
    """provider names a directory under the modules tree. The API and CLI refuse
    an unknown one first; this keeps the file read itself from walking out of
    the asset tree (CodeQL py/path-injection) whatever the caller passes."""
    from redstackpro.export import static_files
    with pytest.raises(FileNotFoundError):
        static_files(provider)


# -- the deployment guide and deploy.tfvars

CHANGE_AUTO_STOP = ("in the canvas, open the Inspector tab and click\nempty space, "
                    "then Topology settings > Auto-stop")


def _guide(doc, provider="gcp"):
    return compile_topology(doc, Registry(), provider=provider)["DEPLOYMENT-GUIDE.md"]


def _goad_light():
    return json.loads(GOAD_LIGHT.read_text(encoding="utf-8"))


def test_the_guide_says_when_the_range_stops_itself():
    """Every shipped blueprint stops itself 8 hours after apply, and the guide
    never said so."""
    doc = _goad_light()
    guide = _guide(doc)
    assert ("This range stops itself 8 hours after the first apply, then daily "
            "at that time.") in guide
    assert ("Start it again with `bash manage.sh start` (`.\\manage.ps1 start` on "
            "Windows).") in guide
    assert CHANGE_AUTO_STOP in guide

    doc["auto_stop"] = {"enabled": True, "at": "21:30", "timezone": "Europe/London"}
    assert "This range stops itself daily at 21:30 Europe/London." in _guide(doc)

    doc["auto_stop"] = {"enabled": False}
    assert "## Auto-stop" not in _guide(doc)


@pytest.mark.parametrize("provider,expect,absent", [
    ("gcp", "`project`: your GCP project ID", "subscription_id"),
    ("aws", "Confirm `region` is the one you mean to deploy into.", "`project`"),
    ("azure", "`resource_group` is created by this deploy and deleted", "`project`"),
])
def test_the_guide_names_what_to_confirm_per_provider(provider, expect, absent):
    guide = _guide(_goad_light(), provider)
    assert expect in guide
    assert absent not in guide.split("## 3.")[0].split("## 2.")[1]
    assert "(and, on GCP, the project)" not in guide
    assert "Python 3.8+" in guide and "3.11" not in guide


def _section(guide, number):
    return guide.split("## %d." % number)[1].split("\n## ")[0]


@pytest.mark.parametrize("provider", ["gcp", "aws", "azure", "proxmox", "esxi"])
def test_the_guide_runs_everything_from_the_export_folder(provider):
    """keys/ in the keygen line is relative, so a key made from the home folder
    lands where the deploy never looks. Found using the export panel for real."""
    step = _section(_guide(_goad_light(), provider), 1)
    assert "`C:\\redstackpro\\my-range` on\nWindows or `~/redstackpro/my-range`" in step
    assert "goad-light" not in step, "the example folder is generic, not the topology name"
    assert "must not contain an apostrophe" in step
    assert "Every command in this guide runs from that folder" in step
    assert step.index("runs from that folder") < step.index("ssh-keygen")


@pytest.mark.parametrize("provider,name,winget,docs,login", [
    ("gcp", "Google Cloud CLI", "Google.CloudSDK",
     "https://cloud.google.com/sdk/docs/install", "gcloud auth login"),
    ("aws", "AWS CLI", "Amazon.AWSCLI",
     "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
     "aws configure"),
    ("azure", "Azure CLI", "Microsoft.AzureCLI",
     "https://learn.microsoft.com/cli/azure/install-azure-cli", "az login"),
])
def test_the_guide_installs_the_cloud_cli_before_the_login(
        redstack, provider, name, winget, docs, login):
    """The login step assumed the CLI was there, and nothing said to install it.
    manage.sh needs it for status, stop, start and teardown."""
    for doc in (_goad_light(), redstack):
        guide = _guide(doc, provider)
        auth = _section(guide, 3)
        assert auth.startswith(" Authenticate to your cloud\n\nInstall the %s first." % name)
        assert "winget install -e --id %s" % winget in auth
        assert "only updates PATH for new windows" in auth
        assert "**macOS and Linux**: follow %s." % docs in auth
        assert auth.index("winget install") < auth.index(login)
        needs = guide.split("## What you need")[1].split("\n## ")[0]
        assert "a Python 3.8+, and the %s |" % name in needs
        for other, (other_name, other_id, _) in CLI_INSTALL.items():
            if other != provider:
                assert other_id not in guide and other_name not in guide


@pytest.mark.parametrize("provider", ["proxmox", "esxi"])
def test_a_guide_without_a_cloud_cli_has_no_install_step(provider):
    guide = _guide(_goad_light(), provider)
    assert "winget" not in guide
    assert " CLI" not in guide
    assert "`terraform`, `ssh`, `tar`, and a Python 3.8+ |" in guide


def test_the_guide_and_the_export_panel_name_the_same_cli():
    """The panel and the guide each carry the install line; they must agree."""
    panel = (GOAD_LIGHT.parent.parent.parent / "src/deployTarget.js").read_text(
        encoding="utf-8")
    for provider, (name, winget, docs) in CLI_INSTALL.items():
        block = panel.split("\n  %s: {" % provider)[1].split("\n  },")[0]
        assert 'name: "%s"' % name in block, provider
        assert 'winget: "%s"' % winget in block, provider
        assert 'docs: "%s"' % docs in block, provider


def test_the_gcp_guide_enables_compute_and_points_at_the_quota_page():
    guide = _guide(_goad_light(), "gcp")
    assert "gcloud services enable compute.googleapis.com" in guide
    assert "https://console.cloud.google.com/iam-admin/quotas" in guide


@pytest.mark.parametrize("provider", ["gcp", "aws", "azure"])
def test_tfvars_explain_each_entry(provider):
    files = compile_topology(_goad_light(), Registry(), provider=provider)
    tfvars = files["deploy.tfvars"]
    assert "project conventions" not in tfvars
    assert "# REQUIRED: your public IP as /32. Find it: curl https://checkip.amazonaws.com" in tfvars
    assert "# Leave empty: deploy.sh fills it from keys/id_ed25519." in tfvars
    # lab_password is a real variable on every backend, so the hint is honest.
    assert "# lab_password = \"\"" in tfvars
    assert 'variable "lab_password"' in files["terraform/variables.tf"]
    assert ("# Values come from deploy.tfvars in the export root."
            in files["terraform/variables.tf"])
    hints = {
        "gcp": ["# GCP project ID (not its name or number). Find it: gcloud config get-value project",
                "gcloud compute zones list --filter=region:us-east4"],
        "aws": ["# Credentials come from your AWS CLI profile: set AWS_PROFILE=<name> "
                "or run aws configure (or aws sso login)."],
        "azure": ["# subscription_id: az account show --query id -o tsv",
                  "# location: az account list-locations -o table",
                  "# Created by this deploy and deleted by teardown. Must not already "
                  "exist; use one per range."],
    }[provider]
    for hint in hints:
        assert hint in tfvars, hint
