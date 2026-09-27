"""Export assembly is the artifact 0010 makes primary: the archive endpoint and
the CLI are both formatters over compile_topology, so the assembly is tested here
rather than through either one. It joins generated code to the static modules and
roles, and it ships one provider's modules, not all three. See 0010 and 0015.
"""

import pytest

from redstackpro.deploy import generate_deploy_script
from redstackpro.export import compile_topology, static_files


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
    rng = generate_deploy_script(_topology("haven", [jb]), registry)
    ops = generate_deploy_script(_topology("artie", [jb]), registry)
    # A range waits for an authenticated win_ping before promoting a fresh Windows
    # host and leaves the jumpbox out of the AD plays; an offense platform neither
    # gates on win_ping nor limits the jumpbox out.
    assert "win_ping" in rng and "!jumpboxes" in rng
    assert "win_ping" not in ops and "!jumpboxes" not in ops


def test_range_deploy_script_provisions_the_jumpbox_in_a_pass_of_its_own(registry):
    # A range limits the jumpbox out of the AD retry loop, so something else has
    # to run its play: for the first year nothing did, and every range came up
    # with no Guacamole portal and no assumed-breach foothold account while the
    # run still reported ok=1. The jumpbox pass must exist, and it must come
    # BEFORE the win_ping gate -- the portal is how the operator reaches the
    # range, so it cannot wait on a Windows box finishing its boot.
    jb = {"id": "jump", "kind": "jumpbox",
          "overlay": {"services": ["ssh", "guacamole"]}}
    rng = generate_deploy_script(_topology("haven", [jb]), registry)
    assert "--limit jumpboxes" in rng
    assert rng.index("--limit jumpboxes") < rng.index("win_ping")


def test_deploy_script_absent_without_a_jumpbox(registry):
    # Nothing to stage a provision through, so no deploy.sh is emitted.
    ts = {"id": "ts", "kind": "teamserver", "overlay": {}}
    assert generate_deploy_script(_topology("artie", [ts]), registry) is None


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
    doc = _topology("haven", registry_nodes or [jb])
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
    # just an obstacle. Recompiling is what actually resets the clock.
    assert "re-run the compile now" in body
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
    assert guard.index("exit 1") < guard.index("esac")


def test_no_ttl_means_no_stop_preflight(registry):
    """A topology that never asked for a TTL should not meet a check about one."""
    jb = {"id": "jump", "kind": "jumpbox",
          "overlay": {"services": ["ssh", "guacamole"]}}
    body = generate_deploy_script(_topology("haven", [jb]), registry, provider="gcp")
    assert "RSP_STOP_LEAD" not in body


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
    body = generate_deploy_script(_topology("artie", [jb, rd]), registry, provider="gcp")
    assert "socket.gethostbyname" in body, "the live value must be looked up"
    assert "STALE, from an earlier deploy" in body
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
