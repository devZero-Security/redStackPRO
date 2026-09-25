// Save and load. The URL is what says which topology is open, and the dirty
// comparison is what stands between a person and losing their work on refresh,
// so both are worth testing without a browser.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import {
  conflictProse,
  copyName,
  topologyIdFromUrl,
  sameDocument,
  saveBlockedReason,
  saveMode,
  urlForTopology,
} from "./session.js";
import { autoLayout, layoutIfNeeded } from "./layout.js";

const doc = JSON.parse(readFileSync("public/redstack.json", "utf8"));

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

test("the open topology round trips through the URL", () => {
  const url = urlForTopology("abc123");
  assert.equal(url, "/?topology=abc123");
  assert.equal(topologyIdFromUrl(url.slice(url.indexOf("?"))), "abc123");
});

test("no topology in the URL opens nothing", () => {
  assert.equal(topologyIdFromUrl(""), null);
  assert.equal(topologyIdFromUrl("?provider=aws"), null);
  assert.equal(urlForTopology(null), "/");
});

test("other query parameters survive opening a topology", () => {
  assert.equal(urlForTopology("abc", "?provider=aws"), "/?provider=aws&topology=abc");
  assert.equal(urlForTopology(null, "?provider=aws&topology=abc"), "/?provider=aws");
});

test("an untouched document is not unsaved", () => {
  assert.ok(sameDocument(doc, structuredClone(doc)));
});

test("key order is not a change", () => {
  // A document that made a round trip through the API comes back in whatever
  // order the serializer chose, and that must not read as unsaved work.
  const reordered = {
    ...structuredClone(doc),
    nodes: doc.nodes.map((n) => Object.fromEntries(Object.entries(n).reverse())),
  };
  assert.ok(sameDocument(doc, reordered));
});

test("a moved node is a change", () => {
  const moved = structuredClone(doc);
  moved.nodes[0].position = { x: 999, y: 999 };
  assert.ok(!sameDocument(doc, moved));
});

test("an edited overlay is a change", () => {
  const edited = structuredClone(doc);
  edited.nodes.find((n) => n.kind === "teamserver").overlay.c2 = "sliver";
  assert.ok(!sameDocument(doc, edited));
});

test("save creates without a topology and updates with one", () => {
  assert.equal(saveMode(null), "create");
  assert.equal(saveMode({ id: "g1", editable: true }), "update");
});

test("saving someone else's org topology forks rather than failing", () => {
  // Org visible topologies are read only to non owners and reuse is by copy. 0009.
  assert.equal(saveMode({ id: "g1", editable: false }), "fork");
});

test("save waits for a compile and skips a clean document", () => {
  assert.match(saveBlockedReason({ dirty: true, compiling: true }), /compile/);
  assert.match(saveBlockedReason({ dirty: false }), /No changes/);
  assert.match(saveBlockedReason({ dirty: true, conflict: {} }), /conflict/);
  assert.equal(saveBlockedReason({ dirty: true }), null);
});

test("a conflict names both versions and says nothing was lost", () => {
  const prose = conflictProse({ your_version: 3, current_version: 5 });
  assert.match(prose, /version 3/);
  assert.match(prose, /version 5/);
  assert.match(prose, /2 revisions ahead/);
  assert.match(prose, /Nothing has been discarded/);
  assert.match(
    conflictProse({ your_version: 3, current_version: 4 }),
    /1 revision ahead/
  );
});

test("a conflict without numbers still reads as prose", () => {
  const prose = conflictProse({});
  assert.match(prose, /moved since you opened it/);
  assert.ok(!prose.includes("undefined"));
});

test("a copy suffix does not stack", () => {
  assert.equal(copyName("Range"), "Range (copy)");
  assert.equal(copyName("Range (copy)"), "Range (copy)");
  assert.equal(copyName("Range", "conflict copy"), "Range (conflict copy)");
  assert.equal(copyName(""), "Untitled (copy)");
});

test("a saved topology is not laid out again", () => {
  // The layout a person arranged is in the document they saved. Running the
  // layout on load would move their canvas under them on every reload.
  const laid = autoLayout(doc);
  assert.strictEqual(layoutIfNeeded(laid), laid);
});

test("a document without positions is laid out on arrival", () => {
  assert.ok(layoutIfNeeded(doc).nodes.every((n) => n.position));
  assert.notStrictEqual(layoutIfNeeded(doc), doc);
});

console.log(`\n${passed} passed`);
