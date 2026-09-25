#!/usr/bin/env python3
"""Check a deployed range against the export that built it.

    python -m redstackpro.tools.verify doors build/   probe the front doors from outside
    python -m redstackpro.tools.verify stack build/   check the stack from its jumpbox
    python -m redstackpro.tools.verify doors build/ --plan   print the checks, run none

Both subcommands read the compiled export and derive every input from it: which
hosts are redirectors, the domain each one answers on, its gating header and
token, the URI prefix of every teamserver it fronts, and which hosts are
teamservers at all. Nothing about a particular deploy is written down here.

That is the point. These replace two scripts written against one range, kept in a
scratch directory. They named that range's two domains and carried both of its
gating tokens as literals, so they verified that deploy and no other, and a token
in a file is a credential in a file.

The subtler one: the stack script found the teamservers by grepping the jumpbox's
/etc/hosts, which is the file it checks two sections earlier. When that block is
missing, and it has been missing once, the loop runs zero times. So the most
valuable check in the script, that every teamserver actually holds 443, tests
nothing at all, and the run ends reporting a single failure instead of four. A
check must not source its targets from the thing it is checking, whatever the
reason the target list comes up empty. The export already knows every one of
them, so ask the export.

Exit status is 0 when every check passed, 1 when one failed, and 2 when the
checks could not be run at all. The third is separate on purpose: a checker that
reports "could not ask" as "nothing found" is how an expired token once produced
a clean billing audit over a running range.
"""

import argparse
import http.client
import os
import re
import ssl
import subprocess
import sys
from pathlib import Path

import yaml

# redirect_rules bounces curl's default user agent on purpose, so a probe that
# sends it measures the bouncer rather than the route behind it. Cost a false
# failure once.
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# A redirector rewrites `^<prefix>/(.*)`, so the prefix itself does not match the
# route and probing it tests the decoy instead. Every probe goes one segment
# under. The leaf is arbitrary; a teamserver answers its own way to anything.
PROBE_LEAF = "healthz"

# Addresses do not exist until apply. tf_inventory.py fills these in place, so
# finding one means the export in hand has not been deployed.
PLACEHOLDER = re.compile(r"<<tf:[^>]+>>")

TIMEOUT = 15


class Refuse(Exception):
    """Cannot run the checks. Never reported as a passing result."""


class Unreachable(Exception):
    """One probe did not complete. Reported as a failed check, not a crash."""


# --------------------------------------------------------------------------
# the export


class Export:
    """The compiled artifact, read the way the deploy reads it."""

    def __init__(self, root):
        self.root = Path(root)
        ansible = self.root / "ansible"
        if not ansible.is_dir():
            raise Refuse("%s has no ansible/ directory, so it is not a "
                         "redStackPRO export." % self.root)
        self.settings = _yaml(ansible / "group_vars/all.yml")
        self.inventory = _yaml(ansible / "inventory.yml")
        self.hosts = {p.stem: _yaml(p)
                      for p in sorted((ansible / "host_vars").glob("*.yml"))}
        if not self.hosts:
            raise Refuse("%s carries no host_vars, so there is nothing to "
                         "check." % self.root)

    @property
    def account(self):
        """The operator account, which is redop on an ops stack and blueop on a
        range. Reading it is what keeps a wrong guess from spending the jumpbox's
        fail2ban budget: five failed logins cost an hour of access to the only
        public host."""
        account = self.settings.get("ansible_user")
        if not account:
            raise Refuse("the export does not say which account to use "
                         "(no ansible_user in group_vars/all.yml).")
        return account

    def group(self, name):
        """Host names in an inventory group, in the order the export lists them."""
        children = (self.inventory.get("all") or {}).get("children") or {}
        hosts = (children.get(name) or {}).get("hosts") or {}
        return [h for h in hosts if h in self.hosts]

    def of_kind(self, kind):
        return [n for n, v in self.hosts.items()
                if v.get("redstackpro_kind") == kind]

    def address(self, name, field="redstackpro_host_address"):
        value = self.hosts[name].get(field)
        if value is None:
            raise Refuse("%s has no %s in the export." % (name, field))
        if PLACEHOLDER.search(str(value)):
            raise Refuse(
                "%s still carries an address placeholder (%s), so this export "
                "has not been deployed yet. Addresses are filled by "
                "tf_inventory.py after terraform apply." % (name, value))
        return value


def _yaml(path):
    if not path.exists():
        raise Refuse("%s is missing from the export." % path)
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


# --------------------------------------------------------------------------
# reporting


class Report:
    def __init__(self):
        self.failed = 0

    def pass_(self, text):
        print("  PASS  %s" % text)

    def fail(self, text):
        print("  FAIL  %s" % text)
        self.failed += 1

    def note(self, text):
        print("  ..    %s" % text)

    def heading(self, text):
        print("\n== %s" % text)


# --------------------------------------------------------------------------
# doors: the view from outside, which is the only one that matters


def door_plan(export):
    """Every check the front doors earn, derived from what they were compiled to be."""
    doors = []
    for name in sorted(export.of_kind("redirector")):
        host = export.hosts[name]
        hostname = host.get("redstackpro_redirector_hostname")
        if not hostname:
            raise Refuse("%s is a redirector with no hostname, which RDR001 "
                         "should have refused at compile." % name)
        gating = host.get("redstackpro_redirector_gating") or {}
        doors.append({
            "node": name,
            "hostname": hostname,
            "header_name": gating.get("header_name"),
            "header_value": gating.get("header_value"),
            "decoy": gating.get("decoy"),
            "cert_source": (host.get("redstackpro_redirector_tls")
                            or {}).get("cert_source", "self_signed"),
            "prefixes": [u.get("uri_prefix") for u in host.get("upstreams") or []
                         if u.get("uri_prefix")],
            "upstreams": [u.get("name") for u in host.get("upstreams") or []],
        })
    if not doors:
        raise Refuse("this export has no redirector, so there is no front door "
                     "to check. `doors` is for an offense stack.")
    return doors


def check_doors(export, plan_only=False):
    doors = door_plan(export)
    report = Report()

    report.heading("front doors, from the export")
    for d in doors:
        report.note("%s  %s  %s  gate=%s  fronts=%s"
                    % (d["node"], d["hostname"], d["cert_source"],
                       d["header_name"] or "<none>",
                       ", ".join("%s%s" % (u, p) for u, p
                                 in zip(d["upstreams"], d["prefixes"])) or "<none>"))

    _note_shared_names(doors, report)

    if plan_only:
        _print_plan(doors, report)
        return 0

    report.heading("certificates")
    # A door that does not answer at all fails every check it has for one
    # reason, and printing that reason five times buries it. Say it once and
    # skip the rest of that door's checks; the other doors still get theirs.
    silent = set()
    for d in doors:
        if not _check_certificate(d, report):
            silent.add(d["node"])
    # A door that is down is still a source of a key: its token comes from the
    # export, not from the host, so "does this token open the other door" is
    # still a question worth asking. Only the checks that need it to ANSWER are
    # skipped. Dropping it from both sides would be the same silent loss of
    # coverage this file exists to avoid.
    reachable = [d for d in doors if d["node"] not in silent]
    if not reachable:
        print("\n%d check(s) failed" % report.failed)
        return 1

    report.heading("each door serves its own cover")
    covers = {}
    for d in reachable:
        try:
            status, size = _probe(d["hostname"], "/")
        except Unreachable as exc:
            report.fail("%s / did not answer: %s" % (d["hostname"], exc))
            continue
        covers[d["node"]] = (size, d["decoy"])
        report.note("%s / -> %s/%s" % (d["hostname"], status, size))
        if status == 200:
            report.pass_("%s serves a cover page" % d["hostname"])
        else:
            report.fail("%s / gave %s, not the 200 a decoy answers with"
                        % (d["hostname"], status))
    _check_covers_differ(reachable, covers, report)

    report.heading("the gate is load bearing")
    for d in reachable:
        _check_gate(d, report)

    report.heading("the doors do not share a key")
    _check_independence(doors, reachable, report)

    print("\n%d check(s) failed" % report.failed if report.failed
          else "\nevery check passed")
    return 1 if report.failed else 0


def _check_certificate(door, report):
    """What matters is whether the chain validates, not whose name is on it.

    Declared letsencrypt and not validating is the real and recoverable case:
    issuance waits 15 minutes for the A record and then carries on with the
    self-signed bootstrap certificate, so the deploy reports success and the
    door serves a certificate no ordinary client trusts.

    Returns False when the door did not answer at all, so the caller can stop
    asking it things.
    """
    valid, detail = _chain_validates(door["hostname"])
    if valid is None:
        report.fail("%s did not answer on 443 (%s), so none of its other checks "
                    "can run. A name that resolves with nothing behind it is "
                    "usually a record still pointing at a destroyed redirector."
                    % (door["hostname"], detail))
        return False
    if door["cert_source"] == "letsencrypt":
        if valid:
            report.pass_("%s serves a publicly trusted certificate"
                         % door["hostname"])
        else:
            report.fail("%s was compiled for letsencrypt but its chain does not "
                        "validate (%s). Issuance most likely missed its window; "
                        "`sudo rsp-issue-cert` on %s finishes it with no redeploy."
                        % (door["hostname"], detail, door["node"]))
    else:
        if valid:
            report.note("%s was compiled self_signed and yet validates, so "
                        "something already replaced the certificate"
                        % door["hostname"])
        else:
            report.pass_("%s serves its self-signed certificate, as declared"
                         % door["hostname"])
    return True


def _check_covers_differ(doors, covers, report):
    """Two doors with different decoy themes must serve different pages.

    Same theme twice is not a defect. A rollover pool is several front doors for
    one teamserver and they are meant to look alike, so only the doors that were
    compiled to differ are held to it.
    """
    for i, a in enumerate(doors):
        for b in doors[i + 1:]:
            if a["decoy"] == b["decoy"] or a["node"] not in covers or b["node"] not in covers:
                continue
            if covers[a["node"]][0] == covers[b["node"]][0]:
                report.fail("%s and %s were compiled with different decoys (%s "
                            "and %s) and served the same %s byte body, so one "
                            "decoy is being served by both"
                            % (a["hostname"], b["hostname"], a["decoy"],
                               b["decoy"], covers[a["node"]][0]))
            else:
                report.pass_("%s (%s) and %s (%s) serve different pages"
                             % (a["hostname"], a["decoy"], b["hostname"], b["decoy"]))


def _check_gate(door, report):
    """A route the gate does not change is a route open to anyone who finds it."""
    if not door["header_name"]:
        report.note("%s carries no gating header, so there is nothing to test"
                    % door["hostname"])
        return
    # `uri_prefix` is optional on a fronts edge (FRT002 skips an edge without
    # one), so this list can be empty on a valid topology. Left unsaid, the loop
    # below ran zero times and this door came out of the most valuable check in
    # `doors` having been neither passed nor failed, silently. The guard above
    # speaks; this one has to as well.
    if not door["prefixes"]:
        report.note("%s fronts no route under a uri prefix, so it has no gated "
                    "route to test" % door["hostname"])
        return
    header = (door["header_name"], door["header_value"])
    for prefix in door["prefixes"]:
        path = "%s/%s" % (prefix.rstrip("/"), PROBE_LEAF)
        try:
            ungated = _probe(door["hostname"], path)
            gated = _probe(door["hostname"], path, header=header)
        except Unreachable as exc:
            report.fail("%s %s did not answer: %s" % (door["hostname"], path, exc))
            continue
        report.note("%s %s  ungated=%s/%s  gated=%s/%s"
                    % (door["hostname"], path, ungated[0], ungated[1],
                       gated[0], gated[1]))
        if ungated == gated:
            report.fail("%s %s answers the same with and without %s, so the "
                        "gate is not load bearing on this route"
                        % (door["hostname"], path, door["header_name"]))
        else:
            report.pass_("%s %s: the gate is load bearing (%s/%s -> %s/%s)"
                         % (door["hostname"], path, ungated[0], ungated[1],
                            gated[0], gated[1]))


def _check_independence(doors, reachable, report):
    """One door's key must not open another.

    Only where the compiler gave them different tokens. A rollover pool shares
    one token across its doors by design, and holding that shape to this rule
    would report a deliberate property as a defect.
    """
    tested = 0
    for a in doors:
        for b in reachable:
            if a is b or not a["header_value"] or not b["header_value"]:
                continue
            if a["header_value"] == b["header_value"]:
                report.note("%s and %s share a gating token by compile, which "
                            "is the rollover shape, so there is no separation "
                            "to test between them" % (a["node"], b["node"]))
                continue
            if not b["prefixes"]:
                continue
            path = "%s/%s" % (b["prefixes"][0].rstrip("/"), PROBE_LEAF)
            try:
                stranger = _probe(b["hostname"], path,
                                  header=(a["header_name"], a["header_value"]))
                own = _probe(b["hostname"], path,
                             header=(b["header_name"], b["header_value"]))
            except Unreachable as exc:
                report.fail("%s %s did not answer: %s" % (b["hostname"], path, exc))
                continue
            tested += 1
            report.note("%s %s with %s's header -> %s/%s (its own: %s/%s)"
                        % (b["hostname"], path, a["node"], stranger[0],
                           stranger[1], own[0], own[1]))
            if stranger == own:
                report.fail("%s's key opened %s, so the two front doors are not "
                            "independent" % (a["node"], b["node"]))
            else:
                report.pass_("%s's key does not open %s" % (a["node"], b["node"]))
    if not tested:
        report.note("one front door, or one shared token, so there is no "
                    "cross-door separation to test")


def _note_shared_names(doors, report):
    """Doors behind one name cannot be told apart from outside.

    A pool answering a single record is a real shape, but every probe then
    reaches whichever host the resolver hands out, so a result describes the pool
    and not the door. Worth saying rather than reporting three checks that may
    all have landed on the same host.
    """
    names = {}
    for d in doors:
        names.setdefault(d["hostname"], []).append(d["node"])
    for hostname, nodes in names.items():
        if len(nodes) > 1:
            report.note("%s answers for %s, so a probe reaches whichever the "
                        "resolver returns and cannot single one out"
                        % (hostname, " and ".join(nodes)))


def _print_plan(doors, report):
    report.heading("probes this would make")
    for d in doors:
        print("  GET https://%s/                     (cover, expect 200)" % d["hostname"])
        for prefix in d["prefixes"]:
            path = "%s/%s" % (prefix.rstrip("/"), PROBE_LEAF)
            print("  GET https://%s%s   ungated and with %s"
                  % (d["hostname"], path, d["header_name"]))
    for a in doors:
        for b in doors:
            if a is b or not a["header_value"] or not b["header_value"]:
                continue
            if a["header_value"] == b["header_value"] or not b["prefixes"]:
                continue
            print("  GET https://%s%s/%s   with %s's header (must not open it)"
                  % (b["hostname"], b["prefixes"][0].rstrip("/"), PROBE_LEAF, a["node"]))


# --------------------------------------------------------------------------
# probing


def _probe(hostname, path, header=None, timeout=TIMEOUT):
    """Return (status, body length).

    Both halves are the tell. A decoy answers 200 with a themed body of real
    size; a teamserver behind the gate answers with its own status and usually no
    body at all, so the pair separates "routed" from "bounced" where the status
    alone does not.
    """
    context = ssl._create_unverified_context()
    headers = {"User-Agent": BROWSER_UA}
    if header:
        headers[header[0]] = header[1]
    connection = http.client.HTTPSConnection(hostname, 443, timeout=timeout,
                                             context=context)
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, len(response.read())
    except Exception as exc:
        raise Unreachable("%s: %s" % (type(exc).__name__, exc))
    finally:
        connection.close()


def _chain_validates(hostname, timeout=TIMEOUT):
    """(True|False|None, detail). None means the host did not answer at all."""
    try:
        connection = http.client.HTTPSConnection(
            hostname, 443, timeout=timeout, context=ssl.create_default_context())
        connection.connect()
        connection.close()
        return True, "verified"
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message or str(exc)
    except Exception as exc:
        return None, "%s: %s" % (type(exc).__name__, exc)


# --------------------------------------------------------------------------
# stack: the view from the jumpbox


def stack_plan(export):
    jumpboxes = export.of_kind("jumpbox")
    if not jumpboxes:
        raise Refuse("this export has no jumpbox, so there is no way in.")
    jumpbox = jumpboxes[0]
    return {
        "account": export.account,
        "jumpbox": jumpbox,
        "target": "%s@%s" % (export.account,
                             export.address(jumpbox, "ansible_host")),
        # From the inventory groups, and so from the export rather than from the
        # range. The id scheme does guarantee a teamserver ends in `ts` and an
        # ordinal, so grepping for that shape was not the fragile part; reading
        # the list off the jumpbox's /etc/hosts was, because an empty block there
        # turns the listener checks into no checks.
        "teamservers": [(n, export.address(n)) for n in export.group("teamservers")],
        "redirectors": [(n, export.address(n)) for n in export.group("redirectors")],
    }


def _no_targets(report, listed, present, what, checking):
    """Say why a loop is about to run zero times, and judge whether that is a
    shape or a defect.

    An empty target list is how a check becomes no check, which is the failure
    this whole file exists to avoid. It is not always wrong: a range carries no
    teamserver and no redirector, and `stack` is still worth running there for
    the portal, the drop folder and the hosts file. It is wrong when the export
    HOLDS those hosts and the list still came up empty, because then something
    between the two lost them, and that is the original bug wearing a new coat.

    `listed` comes from the inventory groups and `present` from the host_vars,
    so the two can disagree, and the disagreement is the whole signal.
    """
    if listed:
        return False
    if present:
        report.fail(
            "the export holds %d %s (%s) but the inventory group is empty, so "
            "the %s check would have run zero times and reported nothing"
            % (len(present), what, ", ".join(sorted(present)), checking))
    else:
        report.note("this export has no %s, so there is no %s to check"
                    % (what, checking))
    return True


def check_stack(export, key, plan_only=False):
    plan = stack_plan(export)
    report = Report()

    report.heading("stack, from the export")
    report.note("jumpbox     %s as %s" % (plan["target"], plan["account"]))
    report.note("teamservers %s" % ", ".join("%s (%s)" % t for t in plan["teamservers"]))
    report.note("redirectors %s" % ", ".join("%s (%s)" % r for r in plan["redirectors"]))

    if plan_only:
        report.heading("checks this would run over ssh")
        for line in ("the provisioning run reported a result",
                     "the portal answers on the jumpbox",
                     "the stock guacadmin account is gone",
                     "the hosts file names the stack",
                     "every teamserver holds 443",
                     "the drop folder exists",
                     "every redirector carries rsp-issue-cert"):
            print("  %s" % line)
        return 0

    ssh = _ssh_command(plan["target"], key)

    report.heading("the provisioning run")
    run = _ssh(ssh, 'grep -a "RUN EXITED" ~/provision/run.log | tail -1')
    if run:
        report.pass_(run)
    else:
        report.fail("no RUN EXITED line in ~/provision/run.log yet")
    recap = _ssh(ssh, 'grep -aoE "failed=[0-9]+|unreachable=[0-9]+" '
                      '~/provision/run.log | sort -u | tr "\\n" " "')
    report.note("recap: %s" % (recap or "<none>"))

    report.heading("the portal")
    code = _ssh(ssh, 'curl -sk -o /dev/null -w "%{http_code}" '
                     'https://127.0.0.1/guacamole/')
    if code == "200":
        report.pass_("portal answers %s" % code)
    else:
        report.fail("portal answered %s, not 200" % (code or "<nothing>"))

    # The database is `guacamole`, the column is `name`. Both cost a false
    # result once by being guessed as guacamole_db and entity_name.
    accounts = _ssh(ssh, "sudo docker exec redstackpro-guac-db psql -U guacamole "
                         "-d guacamole -tAc 'select name from guacamole_entity "
                         "order by name' 2>/dev/null | tr '\\n' ' '")
    report.note("accounts: %s" % (accounts or "<none>"))
    if "guacadmin" in (accounts or ""):
        report.fail("the stock guacadmin account is still present")
    else:
        report.pass_("no stock guacadmin")

    report.heading("names")
    # Case insensitive: the block is written with the product's own casing and a
    # case sensitive grep reported an empty hosts file once.
    named = _ssh(ssh, "grep -ic redstackpro /etc/hosts")
    if named and named.isdigit() and int(named) > 0:
        report.pass_("/etc/hosts names %s host(s)" % named)
    else:
        report.fail("/etc/hosts carries no redStackPRO block")

    report.heading("C2 listeners, by port and never by systemd's opinion")
    _no_targets(report, plan["teamservers"], export.of_kind("teamserver"),
                "teamserver", "C2 listener")
    for name, address in plan["teamservers"]:
        open_ports = [p for p in (443, 4321, 7443, 31337)
                      if _ssh(ssh, "timeout 5 bash -c '</dev/tcp/%s/%d' "
                                   "&& echo open" % (address, p)) == "open"]
        if 443 in open_ports:
            report.pass_("%s (%s) open: %s"
                         % (name, address, " ".join(str(p) for p in open_ports)))
        else:
            report.fail("%s (%s) has no 443 beacon listener, which is the port a "
                        "redirector proxies to. Open: %s"
                        % (name, address,
                           " ".join(str(p) for p in open_ports) or "none"))

    report.heading("the drop folder")
    if _ssh(ssh, "test -d /opt/redstackpro/drop && echo yes") == "yes":
        report.pass_("/opt/redstackpro/drop")
    else:
        report.fail("/opt/redstackpro/drop is missing, so the portal has no way "
                    "to hand a file to a range host")

    report.heading("the certificate command ships on every redirector")
    _no_targets(report, plan["redirectors"], export.of_kind("redirector"),
                "redirector", "certificate command")
    # The command ships 0750 root:root, because it is meant to be run as
    # `sudo rsp-issue-cert`. So `test -x` AS THE OPERATOR is false on a perfectly
    # good redirector, and the first live run of this tool duly reported a
    # missing command on a host that had it, with a message telling the reader
    # their only option was to redeploy. A check that fails when nothing is
    # wrong costs more than no check: the other kind gets ignored, this kind
    # sends someone somewhere else entirely, and on a demo day that is expensive.
    #
    # Ask the question that matters instead -- is it installed, and can root run
    # it -- and separate "not there" from "there but I could not confirm".
    for name, address in plan["redirectors"]:
        out = _ssh(ssh, "ssh -i ~/.ssh/deploy-key -o BatchMode=yes "
                        "-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "
                        "%s@%s 'if ! test -e /usr/local/sbin/rsp-issue-cert; "
                        "then echo missing; "
                        "elif sudo -n test -x /usr/local/sbin/rsp-issue-cert "
                        "2>/dev/null; then echo yes; "
                        "else echo unconfirmed; fi'" % (plan["account"], address))
        if out == "yes":
            report.pass_("%s carries rsp-issue-cert" % name)
        elif out == "unconfirmed":
            # Present, but this account cannot sudo to prove root can run it.
            # Not a failure: the file being there is most of the answer, and
            # calling it broken would be the false alarm above in a new coat.
            report.note("%s has rsp-issue-cert; could not confirm it is "
                        "executable by root from this account" % name)
        else:
            report.fail("%s has no rsp-issue-cert, so a missed certificate "
                        "window could only be fixed by redeploying" % name)

    print("\n%d check(s) failed" % report.failed if report.failed
          else "\nevery check passed")
    return 1 if report.failed else 0


def _ssh_command(target, key):
    command = ["ssh", "-o", "StrictHostKeyChecking=accept-new",
               "-o", "ConnectTimeout=20", "-o", "BatchMode=yes"]
    if key:
        command += ["-i", str(key)]
    return command + [target]


def _ssh(base, remote):
    try:
        out = subprocess.run(base + [remote], capture_output=True, text=True,
                             timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out.stdout.strip()


# --------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check a deployed range against the export that built it.")
    sub = parser.add_subparsers(dest="what", required=True)

    doors = sub.add_parser("doors", help="probe the front doors from outside")
    doors.add_argument("build", help="a compiled export directory")
    doors.add_argument("--plan", action="store_true",
                       help="print the probes and make none")

    stack = sub.add_parser("stack", help="check the stack from its jumpbox")
    stack.add_argument("build", help="a compiled export directory")
    stack.add_argument("--plan", action="store_true",
                       help="print the checks and run none")
    stack.add_argument("--key", default=os.environ.get("REDSTACKPRO_SSH_KEY"),
                       help="ssh private key; defaults to $REDSTACKPRO_SSH_KEY, "
                            "the same variable deploy.sh takes")

    args = parser.parse_args(argv)
    try:
        export = Export(args.build)
        if args.what == "doors":
            return check_doors(export, plan_only=args.plan)
        return check_stack(export, args.key, plan_only=args.plan)
    except Refuse as exc:
        sys.stderr.write("cannot check: %s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
