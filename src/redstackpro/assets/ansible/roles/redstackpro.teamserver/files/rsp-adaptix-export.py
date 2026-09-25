#!/usr/bin/env python3
"""Export AdaptixC2 task history as JSON lines, for the log shipper to collect.

Adaptix is the one C2 here that writes no usable log. Its whole logger is
fmt.Printf to stdout, and that stream carries startup lines and errors: no
operator, no agent id, nothing that says who did what. The attribution exists
only in its SQLite database, in Tasks.Client (the operator) and Tasks.AgentId.
Its internal event bus would be the tidy way to get at that, but the bus has no
sink and the server-side scripting hooks are no-ops, so reading the database is
the only route that does not mean patching Go.

Run on a timer. Each pass reads rows newer than the last watermark, appends one
JSON object per task, and records where it got to, so a restart neither
duplicates nor skips.

The database is opened READ ONLY through a file: URI. Adaptix is writing to it
at the same time, and a reader that could take a write lock would be a tool that
can wedge the teamserver it is watching.
"""

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

# Columns worth carrying, and what they become. Anything else in the row is
# ignored rather than shipped: Tasks also holds Message and ClearText, which are
# full command OUTPUT, and putting that in a log index would balloon it and copy
# whatever the implant read back into a second place.
TASK_FIELDS = {
    "TaskId": "task_id",
    "AgentId": "agent_id",
    "TaskType": "task_type",
    "Client": "operator",
    "User": "agent_user",
    "Computer": "agent_computer",
    "CommandLine": "command",
    "Completed": "completed",
}
AGENT_FIELDS = {
    "Name": "agent_name",
    "Listener": "listener",
    "ExternalIP": "agent_external_ip",
    "InternalIP": "agent_internal_ip",
    "Domain": "agent_domain",
    "Username": "agent_username",
    "Computer": "agent_computer",
    "Process": "agent_process",
    "Elevated": "agent_elevated",
}


def epoch_to_iso(value):
    """Adaptix stores dates as BIGINT and does not say in what unit.

    Seconds and milliseconds are told apart by magnitude rather than by trusting
    either: a seconds value for any plausible date is ten digits, a milliseconds
    value is thirteen. Guessing wrong puts every event in 1970 or in the year
    50000+, and both are the kind of wrong that looks like a broken clock rather
    than a broken parser. Anything that is neither is left out entirely, because
    a made-up timestamp is worse than a missing one.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    if n > 10 ** 12:            # milliseconds
        seconds = n / 1000.0
    elif n > 10 ** 8:           # seconds
        seconds = float(n)
    else:
        return None
    try:
        return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def rows(conn, table):
    """Every row of a table as dicts, or [] if the table is not there.

    Adaptix's schema is not a published interface and has changed before, so
    columns are read by NAME from the cursor rather than by position, and a
    missing table is a reason to carry on with less rather than to crash the
    timer every thirty seconds.
    """
    try:
        cur = conn.execute("SELECT rowid, * FROM %s" % table)
    except sqlite3.Error:
        return []
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def read_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return int(json.load(fh).get("rowid", 0))
    except (OSError, ValueError, AttributeError):
        # No state, or state we cannot read, means start from the beginning.
        # Re-shipping is recoverable; silently skipping history is not.
        return 0


def write_state(path, rowid):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"rowid": rowid, "updated": time.time()}, fh)
    os.replace(tmp, path)       # atomic, so a kill mid-write cannot corrupt it


def export(db_path, out_path, state_path, node=""):
    if not os.path.exists(db_path):
        # The teamserver has not created it yet. Not an error: this runs on a
        # timer from boot, and the database appears when Adaptix first starts.
        return 0

    uri = "file:%s?mode=ro" % db_path.replace("?", "%3f").replace("#", "%23")
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        agents = {a.get("Id"): a for a in rows(conn, "Agents") if a.get("Id")}
        tasks = rows(conn, "Tasks")
    finally:
        conn.close()

    last = read_state(state_path)
    fresh = sorted((t for t in tasks if int(t.get("rowid", 0)) > last),
                   key=lambda t: int(t["rowid"]))
    if not fresh:
        return 0

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    written = 0
    with open(out_path, "a", encoding="utf-8") as fh:
        for task in fresh:
            event = {"event": "task", "node_id": node}
            for src, dst in TASK_FIELDS.items():
                if task.get(src) is not None:
                    event[dst] = task[src]
            for src, dst in (("StartDate", "started"), ("FinishDate", "finished")):
                iso = epoch_to_iso(task.get(src))
                if iso:
                    event[dst] = iso
            agent = agents.get(task.get("AgentId"))
            if agent:
                for src, dst in AGENT_FIELDS.items():
                    if agent.get(src) is not None and dst not in event:
                        event[dst] = agent[src]
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")
            written += 1
        fh.flush()
        os.fsync(fh.fileno())

    # Only after the rows are on disk. The other order loses every task in the
    # window if the process dies between the two, and loses them silently.
    write_state(state_path, int(fresh[-1]["rowid"]))
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", required=True, help="adaptixserver.db")
    ap.add_argument("--out", required=True, help="JSON lines the shipper reads")
    ap.add_argument("--state", required=True, help="where the watermark lives")
    ap.add_argument("--node", default="", help="topology node id, stamped on each event")
    args = ap.parse_args(argv)
    try:
        written = export(args.db, args.out, args.state, args.node)
    except sqlite3.Error as exc:
        # Loud, and non-zero, so a broken read shows up in the journal as a
        # failing timer rather than as an export that quietly stops producing.
        print("adaptix export failed: %s" % exc, file=sys.stderr)
        return 1
    if written:
        print("exported %d task(s)" % written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
