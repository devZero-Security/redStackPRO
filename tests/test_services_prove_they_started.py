"""A role that starts a daemon must prove the daemon works, not ask systemd.

This rule was paid for three times in one day (2026-09-13), each the same shape:
a service that reports healthy while doing nothing, behind a deploy that reports
success.

  * Adaptix exits 0 on a fatal error, so `Restart=on-failure` never fires,
    systemd says "Deactivated successfully", the ansible `service` task reports
    ok, and the range comes up with no C2 anywhere (150e87a).
  * Sliver had the same defect earlier; that role's comments say "the deploy
    still reported success, which is the worst".
  * Logstash exits FATAL on every start ("Could not connect to a compatible
    version of Elasticsearch" -- Elastic's output plugin refuses OpenSearch by
    design). `systemctl is-active` still answered `active`, 5044 was never bound,
    and the collector held zero indices on a range that had reported ok=1.

systemd's opinion is not evidence. A process that exits cleanly on a fatal error
is indistinguishable from one that worked, so the proof has to be something the
service can only produce by actually running: a bound port, an API that answers,
or a log line it writes when ready.

Checked per TASK FILE rather than per role, and that distinction was itself paid
for: redstackpro.siem has one file per SIEM product and only one runs on a given
range, so adding a port check to wazuh.yml made the whole role look proven while
elk.yml still started a container with three published ports and verified none of
them -- on a demo that runs both.

A file that genuinely needs no check says so in EXEMPT, with its reason. That is
a decision someone made rather than a gap nobody noticed.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLES = ROOT / "src/redstackpro/assets/ansible/roles"

# Starting a service.
STARTS = re.compile(
    r"ansible\.builtin\.(?:service|systemd)\s*:|community\.docker\.docker_container\s*:")

# Proving it works. Any of these is evidence the file looked at the service
# itself rather than at systemd: a port that must accept a connection, an
# endpoint that must answer, a command that must succeed against it.
PROVES = re.compile(
    r"ansible\.builtin\.wait_for\s*:"
    r"|ansible\.builtin\.uri\s*:"
    r"|ansible\.builtin\.wait_for_connection\s*:"
    r"|/dev/tcp/"
    r"|pg_isready"
    r"|curl -")

# Keyed "role/file". Keep this short: an entry is a claim that nothing downstream
# depends on the service actually working, or that something else already proves
# it more directly than a check here could.
EXEMPT = {
    "redstackpro.shipper/main.yml":
        "filebeat ships rather than listens, and retries its output forever. A "
        "broken shipper shows up as an empty index at the collector, which is "
        "where the check belongs and where it now is.",
    "redstackpro.jumpbox/service-ssh.yml":
        "ansible reaches this host over ssh. Every subsequent task is the check, "
        "and a dead sshd fails the run immediately and unmistakably.",
    "redstackpro.jumpbox/hardening.yml":
        "fail2ban listens on nothing. It reads a log and writes firewall rules, "
        "so there is no port to probe; its own jail check is a different test.",
    "redstackpro.jumpbox/service-openvpn.yml":
        "opt-in remote access, not part of the range's own function. It binds "
        "UDP, which wait_for cannot meaningfully probe.",
    "redstackpro.jumpbox/service-wireguard.yml":
        "same as openvpn: opt-in, and UDP.",
}


def _role_dirs():
    return sorted(p for p in ROLES.iterdir() if (p / "tasks").is_dir())


def _starting_files():
    for role in _role_dirs():
        for path in sorted((role / "tasks").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            if STARTS.search(text):
                yield "%s/%s" % (role.name, path.name), text


def test_every_file_that_starts_a_daemon_also_proves_it_works():
    missing = [name for name, text in _starting_files()
               if not PROVES.search(text) and name not in EXEMPT]
    assert not missing, (
        "these files start a daemon and never check it actually works: %s. "
        "systemd's opinion is not evidence -- a process that exits cleanly on a "
        "fatal error looks exactly like one that worked. Add a port check, an "
        "API call, or a log assertion, or add an EXEMPT entry with a reason."
        % ", ".join(missing))


def test_the_exemptions_all_name_a_file_that_exists():
    """An exemption for a file that is gone is a rule quietly weakened, and one
    for a file that no longer starts anything is dead weight."""
    starting = {name for name, _ in _starting_files()}
    stale = sorted(set(EXEMPT) - starting)
    assert not stale, (
        "EXEMPT names files that do not exist or no longer start a service: %s"
        % stale)


def test_the_collector_proves_its_receiver_is_listening():
    """The specific instance that started this rule. The collector's whole job is
    to receive, so the receiver port answering is the one fact worth asserting --
    and it is exactly the fact that was missing while Logstash exited on every
    start behind an `active` unit.
    """
    text = (ROLES / "redstackpro.collector/tasks/receiver.yml").read_text(encoding="utf-8")
    assert PROVES.search(text), (
        "the collector starts logstash without ever checking the ingest port is "
        "bound; that is how a range shipped with zero indices and reported ok=1")


def test_both_siem_products_are_proven_not_just_the_one_that_was_looked_at():
    """The hole a role-wide check left. Only one of these runs on a given range,
    and the demo range runs both, so each needs its own proof."""
    for product in ("wazuh", "elk"):
        path = ROLES / "redstackpro.siem/tasks" / ("%s.yml" % product)
        text = path.read_text(encoding="utf-8")
        assert PROVES.search(text), (
            "redstackpro.siem/%s.yml starts services and proves none of them"
            % product)
