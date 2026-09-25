#!/usr/bin/env python3
"""Check the Ansible half of a compiled export more deeply than a syntax check.

    python -m redstackpro.tools.check_roles build/ansible

`ansible-playbook --syntax-check` parses site.yml and the static role entry
points. It never opens a file reached by `include_tasks` with a templated name,
which is every branch the jumpbox, collector, operator, and teamserver roles
have. A typo in `sink-splunk.yml` passes a syntax check and fails at run time on
somebody else's infrastructure.

So this walks every task and handler file, parses it, confirms every templated
include has a file for each legal value, and resolves every module name against
what `ansible-galaxy collection install -r requirements.yml` actually installed.
"""

import argparse
import subprocess
import sys
from pathlib import Path

import yaml

# Keys that sit beside a module in a task and are not the module. A task with two
# keys left over is reported as ambiguous, so anything missing here is a false
# positive rather than a missed bug: async/poll, ignore_unreachable and timeout were
# all in shipped roles and read as second modules, which failed this check for weeks.
# Add a keyword the moment a role uses one; it can only ever quieten a false alarm.
KEYWORDS = {
    "name", "when", "loop", "with_items", "with_dict", "with_fileglob",
    "with_first_found", "with_nested", "with_together", "with_sequence",
    "with_subelements",
    "notify", "tags", "register", "vars", "become", "become_user", "become_method",
    "delegate_to", "delegate_facts", "ignore_errors", "ignore_unreachable",
    "failed_when",
    "changed_when", "loop_control", "block", "rescue", "always", "until",
    "retries", "delay", "no_log", "run_once", "args", "environment",
    "check_mode", "any_errors_fatal", "listen", "throttle", "connection",
    "async", "poll", "timeout", "port", "remote_user", "module_defaults",
    "collections", "diff", "debugger",
}

# The legal values of every overlay field a role dispatches on. A branch with no
# file is a dead branch, and the topology can reach every one of these.
BRANCHES = {
    "service-": ["ssh", "guacamole", "wireguard", "openvpn"],
    "sink-": ["opensearch", "elasticsearch", "splunk"],
    "os-": ["kali", "debian", "windows"],
    "c2-": ["mythic", "sliver", "adaptix", "cobalt_strike", "none"],
}


def modules_in(tasks, found):
    if not isinstance(tasks, list):
        return
    for task in tasks:
        if not isinstance(task, dict):
            continue
        for key in ("block", "rescue", "always"):
            if key in task:
                modules_in(task[key], found)
        names = [k for k in task if k not in KEYWORDS]
        if len(names) == 1:
            found.add(names[0])
        elif len(names) > 1:
            found.add(("AMBIGUOUS", task.get("name"), tuple(sorted(names))))


def check(root):
    problems = []
    modules = set()
    parsed = 0

    for path in sorted(root.rglob("*.yml")):
        rel = path.relative_to(root).as_posix()
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            problems.append("%s does not parse: %s" % (rel, exc))
            continue
        if "/tasks/" in rel or "/handlers/" in rel:
            parsed += 1
            modules_in(document, modules)

    for path in sorted(root.rglob("tasks/*.yml")):
        rel = path.relative_to(root).as_posix()
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for task in document if isinstance(document, list) else []:
            if not isinstance(task, dict):
                continue
            target = task.get("ansible.builtin.include_tasks")
            if isinstance(target, dict):
                target = target.get("file")
            if not isinstance(target, str) or "{{" not in target:
                continue
            prefix, _, rest = target.partition("{{")
            suffix = rest.split("}}", 1)[1] if "}}" in rest else ""
            for value in BRANCHES.get(prefix, []):
                if not (path.parent / ("%s%s%s" % (prefix, value, suffix))).is_file():
                    problems.append(
                        "%s includes %s%s%s and there is no such file"
                        % (rel, prefix, value, suffix))

    ambiguous = [m for m in modules if isinstance(m, tuple)]
    for _, task_name, names in ambiguous:
        problems.append("task %r has two module keys: %s"
                        % (task_name, ", ".join(names)))

    unresolved = []
    for module in sorted(m for m in modules if isinstance(m, str)):
        result = subprocess.run(["ansible-doc", "-t", "module", module],
                                capture_output=True, text=True)
        # ansible-doc exits 0 whether or not it found anything and simply
        # prints nothing for a name it does not know, so the return code says
        # only that the command ran. Emptiness is the answer.
        if not result.stdout.strip():
            unresolved.append(module)
    if unresolved:
        problems.append(
            "modules that do not resolve against the installed collections: %s. "
            "Either the name is wrong or requirements.yml is missing one."
            % ", ".join(unresolved))

    return parsed, len(modules), problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default="build/ansible",
                    help="the ansible directory of a compiled export")
    args = ap.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        print("no such directory: %s" % root)
        return 2

    parsed, modules, problems = check(root)
    print("parsed %d task and handler files, %d modules referenced"
          % (parsed, modules))

    if problems:
        print("\nproblems")
        for problem in problems:
            print(" -", problem)
        return 1

    print("every task file parses, every branch has a file, "
          "every module resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
