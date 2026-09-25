// Canvas telemetry, local only. The compiler-blank-canvas class of bug is hard
// to catch after the fact because it leaves no trace: a node's position goes bad
// and React Flow renders nothing. This keeps a rolling log of what the canvas
// just did and a cheap invariant check on the document, so when the canvas
// blanks there is a concrete record of the steps that led there, copyable in one
// keystroke. Nothing leaves the browser; the platform holds no telemetry service
// and this is not one. See architecture.md on the export-only boundary.

const MAX_EVENTS = 200;
const events = [];
let seq = 0;

// Record one thing the canvas did. Detail should be small: ids and counts, not a
// whole document. Mirrored to the console so it also shows in devtools and in a
// headless run.
export function record(type, detail) {
  const event = { seq: seq += 1, at: Date.now(), type, detail };
  events.push(event);
  if (events.length > MAX_EVENTS) events.shift();
  // Mirror to the console only in a dev build, so production and the test suite
  // stay quiet. The ring buffer above is what the Copy diagnostics path reads, so
  // nothing is lost when the console is silent.
  if (typeof import.meta !== "undefined" && import.meta.env?.DEV) {
    try {
      // eslint-disable-next-line no-console
      console.debug("[redstackpro]", type, detail === undefined ? "" : detail);
    } catch {
      // A console that throws is not worth crashing the recorder over.
    }
  }
  return event;
}

export function history() {
  return events.slice();
}

// The invariants a drawable document holds. Returns a list of human-readable
// problems, empty when the document is sound. The blank-canvas bugs all show up
// here first: a non-finite or wildly out-of-range coordinate, a node with no
// position, an edge naming a node that is gone, a duplicate id.
const RANGE = 100000;
export function inspect(document) {
  const problems = [];
  if (!document || !Array.isArray(document.nodes)) {
    return ["document has no nodes array"];
  }
  const ids = new Set();
  for (const node of document.nodes) {
    if (ids.has(node.id)) problems.push(`duplicate node id ${node.id}`);
    ids.add(node.id);
    const fields = [
      ["position.x", node.position?.x],
      ["position.y", node.position?.y],
      ["width", node.width],
      ["height", node.height],
    ];
    for (const [name, value] of fields) {
      if (value === undefined) continue;
      if (!Number.isFinite(value)) {
        problems.push(`${node.id}.${name} is ${value}`);
      } else if (Math.abs(value) > RANGE) {
        problems.push(`${node.id}.${name} is out of range (${Math.round(value)})`);
      }
    }
    if (!node.position) problems.push(`${node.id} has no position`);
  }
  for (const edge of document.edges || []) {
    if (!ids.has(edge.source)) problems.push(`edge ${edge.id} source ${edge.source} is gone`);
    if (!ids.has(edge.target)) problems.push(`edge ${edge.id} target ${edge.target} is gone`);
  }
  return problems;
}

// Everything worth handing over when something goes wrong: the recent events, a
// small shape of the current document, and the environment. Safe to copy to the
// clipboard and paste into a bug report.
export function snapshot(document, extra = {}) {
  const doc = document
    ? {
        name: document.name,
        prefix: document.prefix,
        schema_version: document.schema_version,
        nodes: (document.nodes || []).map((n) => ({
          id: n.id,
          kind: n.kind,
          position: n.position,
          width: n.width,
          height: n.height,
        })),
        edges: (document.edges || []).map((e) => ({
          id: e.id,
          role: e.role,
          source: e.source,
          target: e.target,
        })),
      }
    : null;
  return {
    when: new Date().toISOString(),
    url: typeof location !== "undefined" ? location.href : "",
    userAgent: typeof navigator !== "undefined" ? navigator.userAgent : "",
    problems: inspect(document),
    events: history(),
    document: doc,
    ...extra,
  };
}
