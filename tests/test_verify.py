"""tools/verify.py derives its checks from the export, never from a deploy.

The two scripts it replaces lived in a scratch directory and were written against
one range. They named that range's domains and carried both of its gating tokens
as literals, so they could only ever check that one deploy and they put
credentials in a file. And the stack script read its teamserver list out of the
jumpbox's /etc/hosts, the same file it was checking, so an empty block there
turned the listener checks into no checks at all.

Both are pinned here. They also assumed one deploy's shape in two ways that a
different shape makes wrong: that every door carries its own gating token, which
a rollover pool does not, and that every certificate is from Let's Encrypt, which
the demo's own AWS range is not.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import verify  # noqa: E402

from redstackpro import Registry  # noqa: E402
from redstackpro.authoring import set_redirector_hostname  # noqa: E402
from redstackpro.export import compile_topology  # noqa: E402

TEMPLATES = ROOT / "frontend/public"
HOSTNAME = "cdn.redops.design"


def _export(tmp_path, name, hostname=HOSTNAME, edit=None):
    """Compile a shipped template to disk and hand back a loaded Export."""
    document = json.loads((TEMPLATES / name).read_text(encoding="utf-8"))
    if edit:
        edit(document)
    set_redirector_hostname(document, hostname)
    files = compile_topology(document, Registry(), provider="gcp")
    out = tmp_path / name.replace(".json", "")
    for path, contents in files.items():
        target = out / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8", newline="\n")
    return verify.Export(out)


@pytest.fixture(scope="module")
def split_horizon(tmp_path_factory):
    return _export(tmp_path_factory.mktemp("sh"), "split-horizon.json",
                   {"apa-rd01": "static.redops.design",
                    "ngx-rd02": "status.redops.design"})


@pytest.fixture(scope="module")
def rollover(tmp_path_factory):
    return _export(tmp_path_factory.mktemp("ro"), "rollover.json")


def test_every_probe_comes_from_the_export(split_horizon):
    """The header name, the token and the path are all compiled values."""
    doors = {d["node"]: d for d in verify.door_plan(split_horizon)}
    apache = doors["red-apa-rd01"]
    nginx = doors["red-ngx-rd02"]

    assert apache["hostname"] == "static.redops.design"
    assert nginx["hostname"] == "status.redops.design"
    # Two doors, two gates. Reading one door's header off the other is the
    # mistake that makes a cross-door test pass for the wrong reason.
    assert apache["header_name"] != nginx["header_name"]
    assert apache["header_value"] and apache["header_value"] != nginx["header_value"]
    # Prefixes follow the fronts edges, so the probe reaches a real route.
    assert apache["prefixes"] == ["/cdn/assets"]
    assert sorted(nginx["prefixes"]) == ["/api/v1", "/system/check"]


def test_no_deploy_is_written_down_in_the_checker():
    """The reason for the rewrite, pinned.

    A gating token in a tracked file is a credential in a tracked file, and this
    repo is meant to go public. A hostname in a tracked file is a checker that
    verifies one range.
    """
    source = (ROOT / "tools/verify.py").read_text(encoding="utf-8")
    # The two tokens the replaced scripts carried in the clear.
    assert "t29quvzqywnthhnuaqccigyi" not in source
    assert "rkhydtb5qu6sa7h29hpo3ccn" not in source
    # And the operator's own domain, which is his registrar entry and not a
    # product default. See the cover-profile decision.
    assert "redops.design" not in source


def test_the_probe_goes_one_segment_under_the_prefix(split_horizon):
    """A redirector rewrites `^<prefix>/(.*)`, so the prefix itself does not
    match the route and probing it measures the decoy. Cost a false failure."""
    door = next(d for d in verify.door_plan(split_horizon)
                if d["node"] == "red-apa-rd01")
    prefix = door["prefixes"][0]
    path = "%s/%s" % (prefix.rstrip("/"), verify.PROBE_LEAF)
    assert path.startswith(prefix + "/")
    assert path != prefix


def test_doors_with_their_own_tokens_are_checked_in_both_directions(split_horizon, capsys):
    """Split horizon's whole claim is two front doors that do not share a fate,
    so each one's key must be tried against the other."""
    verify.check_doors(split_horizon, plan_only=True)
    printed = capsys.readouterr().out
    assert "with red-apa-rd01's header (must not open it)" in printed
    assert "with red-ngx-rd02's header (must not open it)" in printed


def test_a_shared_token_is_not_reported_as_a_broken_gate(rollover, capsys):
    """A rollover pool is several front doors for one teamserver and the compiler
    rolls one token for the whole pool. Holding that shape to the independence
    rule would report a deliberate property as a defect, which is what the
    replaced script would have done."""
    doors = verify.door_plan(rollover)
    assert len({d["header_value"] for d in doors}) == 1, "the pool shares a token"

    verify.check_doors(rollover, plan_only=True)
    printed = capsys.readouterr().out
    assert "must not open it" not in printed


def test_the_targets_do_not_come_from_the_thing_being_checked(split_horizon):
    """The negative control for the real bug this replaces.

    The old script read the teamserver list out of the jumpbox's /etc/hosts, the
    same file it checks two sections earlier. An empty block there, which has
    happened, made the loop run zero times: the listener check, the most valuable
    one in the script, tested nothing and the run reported one failure instead of
    four. Here the list is the export's, so it is complete before anything is
    contacted, and a missing hosts block can only ever add a failure, whatever
    the reason it came up empty.
    """
    found = split_horizon.group("teamservers")
    assert sorted(found) == ["red-adpx-ts03", "red-myth-ts02", "red-sliv-ts01"]
    # Not a naming guess either: every one of them is in the inventory group.
    assert all(split_horizon.hosts[n]["redstackpro_kind"] == "teamserver"
               for n in found)


def test_a_renamed_teamserver_is_still_found(tmp_path):
    """The slug is the operator's to change; the id scheme keeps the `ts` tag and
    the ordinal, which is why the old grep was safe against this. Group
    membership does not depend on either."""
    def rename(document):
        for node in document["nodes"]:
            if node["id"] == "myth-ts02":
                node["id"] = "haul-ts02"
        for edge in document["edges"]:
            for end in ("source", "target"):
                if edge[end] == "myth-ts02":
                    edge[end] = "haul-ts02"

    export = _export(tmp_path, "split-horizon.json",
                     {"apa-rd01": "static.redops.design",
                      "ngx-rd02": "status.redops.design"},
                     edit=rename)
    assert "red-haul-ts02" in export.group("teamservers")


def test_an_undeployed_export_refuses_instead_of_probing_a_placeholder(tmp_path):
    """Addresses are `<<tf:...>>` until tf_inventory.py fills them after apply.
    Handing one to ssh would produce a confusing connection error instead of the
    one fact that matters, which is that nothing has been deployed."""
    export = _export(tmp_path, "redstack.json")
    with pytest.raises(verify.Refuse, match="has not been deployed"):
        verify.stack_plan(export)


def test_a_range_export_refuses_the_door_checks(tmp_path):
    """`doors` is for an offense stack. A GOAD range has no redirector, and
    saying so is better than reporting that all zero doors passed."""
    document = json.loads(
        (TEMPLATES / "goad/goad-light.json").read_text(encoding="utf-8"))
    files = compile_topology(document, Registry(), provider="gcp")
    out = tmp_path / "goad-light"
    for path, contents in files.items():
        target = out / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8", newline="\n")
    with pytest.raises(verify.Refuse, match="no redirector"):
        verify.door_plan(verify.Export(out))


def test_could_not_check_never_reads_as_checked(tmp_path):
    """Exit 2, not 0 and not 1.

    A checker that cannot run must not be mistaken for one that found nothing
    wrong. An expired token once produced a clean billing audit over a running
    range, and the same shape has now been caught three times.
    """
    empty = tmp_path / "not-an-export"
    empty.mkdir()
    assert verify.main(["doors", str(empty)]) == 2


def test_a_door_that_is_down_says_so_once(split_horizon, monkeypatch, capsys):
    """One dead host answers nothing, so every check it has fails for the same
    reason. Printing that reason once per route buries it under itself. Here both
    doors are down, which is five routes between them."""
    monkeypatch.setattr(verify, "_chain_validates",
                        lambda hostname, timeout=15: (None, "refused"))
    assert verify.check_doors(split_horizon) == 1
    printed = capsys.readouterr().out
    assert printed.count("FAIL") == 2, "one failure per door, not per route"
    assert "still pointing at a destroyed redirector" in printed


def test_a_door_that_is_down_still_lends_its_key_to_the_other(split_horizon, monkeypatch):
    """A token comes from the export, not from the host, so "does this open the
    other door" stays answerable when its own door is unreachable. Dropping it
    from both sides would be the same silent loss of coverage this file is about.
    """
    # The apache door is down; the nginx one answers. Driven through check_doors
    # so that wiring the two lists together again is what fails this.
    monkeypatch.setattr(verify, "_chain_validates",
                        lambda hostname, timeout=15:
                        (None, "refused") if hostname.startswith("static")
                        else (True, "verified"))
    asked = []

    def record(host, path, header=None, timeout=15):
        asked.append((host, header[0] if header else None))
        return (404, 0) if header else (200, 1801)

    monkeypatch.setattr(verify, "_probe", record)
    verify.check_doors(split_horizon)
    assert ("status.redops.design", "X-Request-Id") in asked, (
        "the down door's key was never tried against the live one: %s" % asked)


def test_a_self_signed_door_passes_on_its_own_terms(monkeypatch):
    """The replaced script demanded Let's Encrypt on every door, so it could not
    verify a self_signed deploy at all. The demo's AWS range is self_signed on
    purpose, and a certificate is held to what the export declared."""
    report = verify.Report()
    monkeypatch.setattr(verify, "_chain_validates",
                        lambda hostname, timeout=15: (False, "self signed"))
    verify._check_certificate(
        {"hostname": "h", "node": "n", "cert_source": "self_signed"}, report)
    assert report.failed == 0


def test_a_letsencrypt_door_that_did_not_get_its_certificate_fails(monkeypatch, capsys):
    """Issuance waits 15 minutes for the A record and then carries on with the
    bootstrap certificate, so the deploy reports success while the door serves
    something no ordinary client trusts. That is the case worth catching, and
    the remedy needs no redeploy."""
    report = verify.Report()
    monkeypatch.setattr(verify, "_chain_validates",
                        lambda hostname, timeout=15: (False, "self signed"))
    verify._check_certificate(
        {"hostname": "h", "node": "n", "cert_source": "letsencrypt"}, report)
    assert report.failed == 1
    assert "rsp-issue-cert" in capsys.readouterr().out


# --------------------------------------------------------- an empty target list ---
#
# The rewrite fixed where the target list comes from. It did not fix what happens
# when the list is empty anyway, and three loops still ran zero times in silence:
# the gate check on a door with no uri prefix, and both stack loops. A check that
# runs zero times and says nothing is indistinguishable from a check that passed,
# which is the one thing this file exists to prevent.

def test_a_door_with_no_uri_prefix_says_so_instead_of_testing_nothing(capsys):
    """`uri_prefix` is optional on a fronts edge, so this is a valid topology.

    The gate check is the most valuable one in `doors`. Before this, a door in
    this shape went through it neither passed nor failed, and printed nothing.
    """
    report = verify.Report()
    verify._check_gate(
        {"hostname": "h", "node": "n", "header_name": "X-Request-Id",
         "header_value": "tok", "prefixes": []}, report)
    out = capsys.readouterr().out
    assert report.failed == 0
    assert "no gated route" in out, out


def test_a_range_has_no_teamserver_and_that_is_a_shape_not_a_failure(capsys):
    """`stack` is worth running on a range for the portal and the drop folder,
    so zero teamservers must not refuse the whole run. It must be said, though."""
    report = verify.Report()
    empty = verify._no_targets(report, [], [], "teamserver", "C2 listener")
    out = capsys.readouterr().out
    assert empty is True
    assert report.failed == 0
    assert "no teamserver" in out, out


def test_targets_lost_between_the_export_and_the_inventory_is_a_failure(capsys):
    """The original bug, in the only place it can still happen.

    The host_vars hold teamservers and the inventory group is empty, so the loop
    would run zero times over hosts that exist. That is not a shape, and the old
    script's exact defect: the run must not come back clean.
    """
    report = verify.Report()
    empty = verify._no_targets(report, [], ["red-myth-ts01", "red-sliv-ts02"],
                               "teamserver", "C2 listener")
    out = capsys.readouterr().out
    assert empty is True
    assert report.failed == 1
    assert "red-myth-ts01" in out and "zero times" in out, out


def test_a_full_target_list_is_left_alone(capsys):
    report = verify.Report()
    assert verify._no_targets(report, [("n", "10.0.0.1")], ["n"],
                              "teamserver", "C2 listener") is False
    assert report.failed == 0
    assert capsys.readouterr().out == ""


def test_the_stack_checks_speak_when_a_range_gives_them_nothing(tmp_path, capsys):
    """End to end on a real compiled range, not on a hand-made dict.

    goad-light has a jumpbox and no teamserver or redirector at all, which is the
    export `stack` is most likely to meet outside an offense deploy.
    """
    document = json.loads(
        (TEMPLATES / "goad/goad-light.json").read_text(encoding="utf-8"))
    files = compile_topology(document, Registry(), provider="gcp")
    out = tmp_path / "goad-light-stack"
    for path, contents in files.items():
        target = out / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8", newline="\n")
    export = verify.Export(out)
    assert export.of_kind("teamserver") == []
    assert export.of_kind("redirector") == []
    report = verify.Report()
    assert verify._no_targets(report, export.group("teamservers"),
                              export.of_kind("teamserver"),
                              "teamserver", "C2 listener") is True
    assert verify._no_targets(report, export.group("redirectors"),
                              export.of_kind("redirector"),
                              "redirector", "certificate command") is True
    assert report.failed == 0
    text = capsys.readouterr().out
    assert "no teamserver" in text and "no redirector" in text, text


def test_the_certificate_command_probe_does_not_fail_on_a_healthy_redirector():
    """rsp-issue-cert ships 0750 root:root, because it is run as
    `sudo rsp-issue-cert`. So `test -x` AS THE OPERATOR is false on a perfectly
    good redirector.

    The first live run of this tool duly reported the command missing on a host
    that had it, and told the reader their only option was to redeploy. That is
    worse than no check: a check that cannot fail gets ignored, but one that
    fails when nothing is wrong sends someone somewhere else entirely, and a
    demo day is exactly when that costs the most.

    The probe now separates three answers -- not installed, installed and root
    can run it, installed but this account cannot prove that -- and only the
    first is a failure.
    """
    source = (ROOT / "tools/verify.py").read_text(encoding="utf-8")
    probe = source[source.index("the certificate command"):]
    probe = probe[:probe.index("check(s) failed")]

    assert "sudo -n test -x" in probe, (
        "the probe still asks whether the OPERATOR can execute a root-only "
        "command, which is false on a healthy redirector")
    assert "test -e /usr/local/sbin/rsp-issue-cert" in probe, (
        "nothing distinguishes a missing command from an unreadable one")
    assert "unconfirmed" in probe, (
        "there is no third answer, so an account without sudo produces the same "
        "false failure in a new form")
