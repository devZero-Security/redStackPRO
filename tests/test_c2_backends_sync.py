"""One C2 backend set, five places that must agree.

Adding a C2 product means touching all five: the schema enum (the legal values),
the id-slug table (idscheme.SUBTYPE), the check_roles c2 branch list, the
terraform control-port table (plan.C2_CONTROL_PORTS), and a role tasks file
c2-<value>.yml. A prior audit found this is a scavenger hunt, and that
cobalt_strike was already half-wired (enum plus role, no control port). This
guard fails with a clear list of what is missing the moment a new backend is
added to one place and not the rest, rather than letting the gap surface at
compile or apply time.

Two documented exception sets carry the values that legitimately differ: a value
with no dedicated id slug (it takes the bare `ts` slug), and a value with no
operator control port (nothing in-range to open a rule for). See P1/P2 and
plan.C2_CONTROL_PORTS.
"""

import json
from pathlib import Path

from redstackpro.idscheme import SUBTYPE
from redstackpro.terraform.plan import C2_CONTROL_PORTS
from redstackpro.tools.check_roles import BRANCHES

ROOT = Path(__file__).resolve().parent.parent

_SCHEMA = ROOT / "src/redstackpro/schema/topology/0.5.0.json"
_TEAMSERVER_TASKS = (ROOT / "src/redstackpro/assets/ansible/roles"
                     / "redstackpro.teamserver/tasks")

# `none` is the plain Debian catchall for custom C2 (OC2 and the like). It reads
# no product subtype, so it takes the bare `ts` slug and carries no id-slug entry.
NO_SLUG = {"none"}

# Values that legitimately open no operator control-plane firewall rule:
#   none          stands up no team server, so there is nothing to reach.
#   cobalt_strike is licensed and operator-supplied. The role prepares the host
#                 and stops (c2-cobalt_strike.yml); the operator runs the team
#                 server themselves and drives it with their own CS client, not an
#                 in-range operator box. redStackPRO stands up no CS service, so it
#                 opens no control port for one. See P2.
NO_CONTROL_PORT = {"none", "cobalt_strike"}


def _schema_enum():
    doc = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    return set(doc["$defs"]["overlay_teamserver"]["properties"]["c2"]["enum"])


def _role_files():
    return {p.name[len("c2-"):-len(".yml")]
            for p in _TEAMSERVER_TASKS.glob("c2-*.yml")}


def test_c2_backend_set_is_in_sync_across_all_five_sources():
    canonical = _schema_enum()
    assert canonical, "schema enum is empty; the JSON path drifted?"

    id_slugs = set(SUBTYPE["teamserver"][1])
    branches = set(BRANCHES["c2-"])
    control = set(C2_CONTROL_PORTS)
    roles = _role_files()

    # The role files and the check_roles branch list carry the full set: every
    # legal value dispatches to a task file, and check_roles asserts each exists.
    assert roles == canonical, (
        "role tasks files disagree with the schema enum: missing %s, extra %s"
        % (canonical - roles, roles - canonical))
    assert branches == canonical, (
        "check_roles c2 branch list disagrees with the schema enum: "
        "missing %s, extra %s" % (canonical - branches, branches - canonical))

    # The id-slug table carries every value that names itself, i.e. all but the
    # documented no-slug exceptions.
    expected_slugs = canonical - NO_SLUG
    assert id_slugs == expected_slugs, (
        "idscheme.SUBTYPE teamserver c2 table disagrees: missing %s, extra %s. "
        "A new backend needs an id slug (or a NO_SLUG entry saying why not)."
        % (expected_slugs - id_slugs, id_slugs - expected_slugs))

    # The control-port table carries every value an in-range operator drives,
    # i.e. all but the documented no-control-port exceptions.
    expected_control = canonical - NO_CONTROL_PORT
    assert control == expected_control, (
        "plan.C2_CONTROL_PORTS disagrees: missing %s, extra %s. A new backend "
        "needs a control port (or a NO_CONTROL_PORT entry saying why not)."
        % (expected_control - control, control - expected_control))

    # The exception sets name only real values, so a removed backend or a typo
    # cannot leave behind an exception that no longer applies.
    assert NO_SLUG <= canonical, "NO_SLUG names a value not in the schema enum"
    assert NO_CONTROL_PORT <= canonical, \
        "NO_CONTROL_PORT names a value not in the schema enum"
