import assert from "node:assert/strict";
import { history, inspect, record, snapshot } from "./diagnostics.js";

// inspect is the invariant check the blank-canvas banner runs. A sound document
// has no problems.
{
  const doc = {
    nodes: [
      { id: "network-main", kind: "network", position: { x: 0, y: 0 }, width: 400, height: 300 },
      { id: "ts-01", kind: "teamserver", position: { x: 10, y: 20 } },
    ],
    edges: [{ id: "e1", role: "attached", source: "ts-01", target: "network-main" }],
  };
  assert.deepEqual(inspect(doc), []);
}

// A non-finite coordinate is the runtime shape of the blank-canvas bug and must
// be flagged.
{
  const doc = { nodes: [{ id: "a", kind: "host", position: { x: NaN, y: 0 } }], edges: [] };
  const problems = inspect(doc);
  assert.ok(problems.some((p) => p.includes("a.position.x")), problems.join("|"));
}

// A wildly out-of-range coordinate (the compounding-nest bug) is flagged before
// it blanks the canvas.
{
  const doc = { nodes: [{ id: "a", kind: "host", position: { x: 999999, y: 0 } }], edges: [] };
  assert.ok(inspect(doc).some((p) => p.includes("out of range")));
}

// A node with no position and an edge to a gone node are each caught.
{
  assert.ok(inspect({ nodes: [{ id: "a", kind: "host" }], edges: [] }).some((p) => p.includes("no position")));
  const orphan = {
    nodes: [{ id: "a", kind: "host", position: { x: 0, y: 0 } }],
    edges: [{ id: "e", role: "fronts", source: "a", target: "ghost" }],
  };
  assert.ok(inspect(orphan).some((p) => p.includes("ghost")));
}

// A duplicate node id is a rename typo, not corruption: it is REF002's finding
// to report, not the corruption banner's. inspect stays quiet about it (and
// still resolves edges against whichever node shares the id, rather than
// flagging a dangling edge on top of it).
{
  const dup = {
    nodes: [
      { id: "a", kind: "host", position: { x: 0, y: 0 } },
      { id: "a", kind: "host", position: { x: 1, y: 1 } },
    ],
    edges: [{ id: "e", role: "attached", source: "a", target: "a" }],
  };
  assert.deepEqual(inspect(dup), []);
}

// A document with no nodes array is not drawable and says so rather than throwing.
assert.deepEqual(inspect(null), ["document has no nodes array"]);
assert.deepEqual(inspect({}), ["document has no nodes array"]);

// record keeps a rolling history; a recorded event comes back with its type and
// a monotonic sequence.
{
  const before = history().length;
  const e = record("test-event", { a: 1 });
  assert.equal(e.type, "test-event");
  const after = history();
  assert.equal(after.length, before + 1);
  assert.equal(after.at(-1).type, "test-event");
  assert.ok(after.at(-1).seq > 0);
}

// The buffer is bounded: far more than the cap still leaves a capped history.
{
  for (let i = 0; i < 250; i += 1) record("spam", i);
  assert.ok(history().length <= 200, `history grew to ${history().length}`);
}

// snapshot bundles the problems, the events, and a trimmed document shape, and is
// plain JSON.
{
  const doc = { name: "g", prefix: "rt", nodes: [{ id: "a", kind: "host", position: { x: 0, y: 0 } }], edges: [] };
  const snap = snapshot(doc, { crash: "boom" });
  assert.deepEqual(snap.problems, []);
  assert.ok(Array.isArray(snap.events));
  assert.equal(snap.document.nodes[0].id, "a");
  assert.equal(snap.crash, "boom");
  JSON.stringify(snap); // must not throw
}

console.log("diagnostics.test.mjs: all passed");
