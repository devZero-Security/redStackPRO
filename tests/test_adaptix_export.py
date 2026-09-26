"""The Adaptix exporter, run against a synthetic adaptixserver.db.

Adaptix is the one C2 here whose attribution exists nowhere but its database:
its logger is fmt.Printf to stdout and that stream names no operator and no
agent. So this tool is the only thing standing between "somebody ran commands on
this range" and knowing who.

The schema mirrored here is Adaptix's own (AdaptixServer/core/database), and the
tests exercise the things that are easy to get wrong and silent when wrong:
the watermark, the epoch unit, and a schema that has moved.
"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.teamserver/files"
sys.path.insert(0, str(FILES))

import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "rsp_adaptix_export", FILES / "rsp-adaptix-export.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


def make_db(path, tasks=(), agents=()):
    """Adaptix's shape, as far as this tool reads it."""
    conn = sqlite3.connect(str(path))
    conn.execute("""CREATE TABLE Tasks (
        TaskId TEXT NOT NULL UNIQUE, AgentId TEXT NOT NULL, TaskType INTEGER,
        Client TEXT, User TEXT, Computer TEXT, StartDate BIGINT,
        FinishDate BIGINT, CommandLine TEXT NOT NULL, MessageType INTEGER,
        Message TEXT, ClearText TEXT, Completed INTEGER)""")
    conn.execute("""CREATE TABLE Agents (
        Id TEXT, Name TEXT, Listener TEXT, ExternalIP TEXT, InternalIP TEXT,
        Pid INTEGER, Arch TEXT, Elevated INTEGER, Process TEXT, OsDesc TEXT,
        Domain TEXT, Computer TEXT, Username TEXT, Impersonated TEXT,
        CreateTime BIGINT, LastTick BIGINT)""")
    for t in tasks:
        conn.execute(
            "INSERT INTO Tasks (TaskId, AgentId, TaskType, Client, User, "
            "Computer, StartDate, FinishDate, CommandLine, Message, "
            "ClearText, Completed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (t["TaskId"], t["AgentId"], t.get("TaskType", 1), t.get("Client"),
             t.get("User"), t.get("Computer"), t.get("StartDate"),
             t.get("FinishDate"), t["CommandLine"], t.get("Message"),
             t.get("ClearText"), t.get("Completed", 1)))
    for a in agents:
        conn.execute(
            "INSERT INTO Agents (Id, Name, Listener, ExternalIP, InternalIP, "
            "Domain, Computer, Username, Process, Elevated) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (a["Id"], a.get("Name"), a.get("Listener"), a.get("ExternalIP"),
             a.get("InternalIP"), a.get("Domain"), a.get("Computer"),
             a.get("Username"), a.get("Process"), a.get("Elevated", 0)))
    conn.commit()
    conn.close()


def run(tmp_path, node="art-adpx-ts01"):
    out, state = tmp_path / "out/adaptix.jsonl", tmp_path / "state.json"
    n = exporter.export(str(tmp_path / "adaptixserver.db"), str(out), str(state), node)
    lines = ([json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
             if out.exists() else [])
    return n, lines


def test_it_exports_the_operator_and_the_agent(tmp_path):
    """The whole point. Tasks.Client is the operator and Tasks.AgentId is the
    implant, and they exist in no log anywhere on the host."""
    make_db(tmp_path / "adaptixserver.db",
            tasks=[{"TaskId": "t1", "AgentId": "a77", "Client": "redop",
                    "CommandLine": "whoami", "StartDate": 1789000000,
                    "User": "NT AUTHORITY\\SYSTEM", "Computer": "BRAAVOS"}],
            agents=[{"Id": "a77", "Name": "beacon-1", "Listener": "http",
                     "ExternalIP": "34.1.2.3", "Domain": "ESSOS",
                     "Username": "khal.drogo", "Computer": "BRAAVOS"}])
    n, lines = run(tmp_path)
    assert n == 1
    ev = lines[0]
    assert ev["operator"] == "redop"
    assert ev["agent_id"] == "a77"
    assert ev["command"] == "whoami"
    assert ev["node_id"] == "art-adpx-ts01"
    # Joined from Agents, which is where the implant's context lives.
    assert ev["listener"] == "http"
    assert ev["agent_domain"] == "ESSOS"


def test_command_output_is_not_shipped(tmp_path):
    """Tasks.Message and Tasks.ClearText hold full command OUTPUT. Shipping that
    would balloon the index and copy whatever the implant read into a second
    place that outlives the engagement."""
    make_db(tmp_path / "adaptixserver.db",
            tasks=[{"TaskId": "t1", "AgentId": "a1", "Client": "redop",
                    "CommandLine": "cat /etc/shadow", "StartDate": 1789000000,
                    "Message": "root:$6$SECRET", "ClearText": "root:$6$SECRET"}])
    _, lines = run(tmp_path)
    blob = json.dumps(lines)
    assert "SECRET" not in blob, "command output is being shipped into the log index"


def test_the_watermark_neither_repeats_nor_skips(tmp_path):
    """It runs on a timer, so every pass sees rows it has already sent. Getting
    this wrong duplicates the whole table every thirty seconds, or loses the
    first task of every restart."""
    db = tmp_path / "adaptixserver.db"
    make_db(db, tasks=[{"TaskId": "t1", "AgentId": "a1", "Client": "redop",
                        "CommandLine": "one", "StartDate": 1789000000}])
    assert run(tmp_path)[0] == 1
    assert run(tmp_path)[0] == 0, "a second pass re-sent rows it had already sent"

    conn = sqlite3.connect(str(db))
    conn.execute("INSERT INTO Tasks (TaskId, AgentId, Client, CommandLine, "
                 "StartDate) VALUES ('t2','a1','redop','two',1789000100)")
    conn.commit()
    conn.close()

    n, lines = run(tmp_path)
    assert n == 1, "a new task was not picked up"
    assert [e["command"] for e in lines] == ["one", "two"]


def test_seconds_and_milliseconds_are_told_apart(tmp_path):
    """Adaptix stores BIGINT and does not say in what unit. Reading ms as s puts
    the event in the year 58000; reading s as ms puts it in 1970. Both look like
    a broken clock rather than a broken parser."""
    assert exporter.epoch_to_iso(1789000000).startswith("2026-")
    assert exporter.epoch_to_iso(1789000000000).startswith("2026-")
    # Neither shape: no timestamp at all rather than an invented one.
    assert exporter.epoch_to_iso(0) is None
    assert exporter.epoch_to_iso(None) is None
    assert exporter.epoch_to_iso("not a number") is None


def test_a_missing_database_is_not_an_error(tmp_path):
    """It runs on a timer from boot and the database appears when Adaptix first
    starts. Treating absence as failure would make the timer red until then."""
    assert run(tmp_path)[0] == 0


def test_a_schema_that_moved_costs_fields_not_the_export(tmp_path):
    """Adaptix's schema is not a published interface and has changed before.
    Columns are read by name, so an unexpected one is ignored and a missing one
    is simply absent -- losing a field beats losing the export."""
    db = tmp_path / "adaptixserver.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE Tasks (TaskId TEXT, AgentId TEXT, Client TEXT, "
                 "CommandLine TEXT, StartDate BIGINT, SomethingNew TEXT)")
    conn.execute("INSERT INTO Tasks VALUES ('t1','a1','redop','whoami',"
                 "1789000000,'ignored')")
    conn.commit()
    conn.close()
    # No Agents table at all.
    n, lines = run(tmp_path)
    assert n == 1
    assert lines[0]["operator"] == "redop"
    assert "listener" not in lines[0]


def test_the_database_is_opened_read_only(tmp_path):
    """Adaptix is writing to this file while we read it. A reader that can take
    a write lock is a tool that can wedge the teamserver it is watching."""
    source = (FILES / "rsp-adaptix-export.py").read_text(encoding="utf-8")
    assert "mode=ro" in source
    assert "uri=True" in source


def test_the_watermark_is_written_after_the_rows(tmp_path):
    """The other order loses every task in the window if the process dies
    between the two, and loses them without saying so."""
    source = (FILES / "rsp-adaptix-export.py").read_text(encoding="utf-8")
    body = source[source.index("def export("):source.index("def main(")]
    assert body.index("fh.write(") < body.index("write_state("), (
        "the watermark advances before the rows are on disk")
    assert "os.fsync" in body, "rows can sit in a buffer when the watermark moves"


def test_nothing_the_exporter_writes_is_silently_dropped(tmp_path):
    """The exporter picks key names and the logstash branch renames them, in two
    different files with nothing connecting them at runtime.

    The branch used to end on `remove_field => [rsp_adx]`, which threw away
    everything not explicitly renamed: task_id, the listener, the agent's domain
    and internal address, whether it was elevated, when the task finished. All
    real, all gone, and nothing anywhere reports a dropped field. What is not
    mapped is now kept under its own object instead.
    """
    import re
    pipeline = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.collector"
                "/templates/logstash-redstackpro.conf.j2").read_text(encoding="utf-8")
    branch = pipeline[pipeline.index("---- adaptix, the task export"):
                      pipeline.index("---- adaptix, the journal")]
    assert 'remove_field => ["[rsp_adx]"]' not in branch, (
        "the leftover fields are deleted rather than kept")
    assert '"[rsp_adx]" => "[redstackpro][c2][adaptix]"' in branch

    # And every key the pipeline renames must be one the exporter can emit.
    #
    # Against the exporter's declared field names, not against one sample row: a
    # sparse task legitimately carries no agent columns, so comparing to a single
    # event fails on fields that are merely absent that time rather than wrong.
    can_emit = (set(exporter.TASK_FIELDS.values())
                | set(exporter.AGENT_FIELDS.values())
                | {"event", "node_id", "started", "finished"})
    read = set(re.findall(r'"\[rsp_adx\]\[([^\]]+)\]"', branch))
    assert read <= can_emit, (
        "the pipeline renames %s, which the exporter never writes"
        % sorted(read - can_emit))


def test_a_corrupt_state_file_restarts_rather_than_stops(tmp_path):
    """Re-shipping is recoverable. Silently skipping the whole history is not."""
    state = tmp_path / "state.json"
    state.write_text("{ this is not json", encoding="utf-8")
    assert exporter.read_state(str(state)) == 0
