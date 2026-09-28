import assert from "node:assert";
import {
  hostSlug, containerSlug, abbrevOf, ordinalOf, slugOf, composeId, edgeId,
  proposeId, retitle,
} from "./idscheme.js";

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

// A small document: one network holding one subnet holding one host, wired by
// attachment, so families roll up the way retitle expects.
const build = (hostKind, overlay) => ({
  prefix: "off",
  nodes: [
    { id: "net01", kind: "network", overlay: {} },
    { id: "sub01", kind: "segment", overlay: {} },
    { id: "h01", kind: hostKind, overlay },
  ],
  edges: [
    { id: "e-sub01-net01-attached", role: "attached", source: "sub01", target: "net01" },
    { id: "e-h01-sub01-attached", role: "attached", source: "h01", target: "sub01" },
  ],
});

test("a host's slug reads its subtype", () => {
  assert.equal(hostSlug({ kind: "teamserver", overlay: { c2: "mythic" } }), "myth");
  assert.equal(hostSlug({ kind: "operator", overlay: { os: "windows" } }), "win");
  assert.equal(hostSlug({ kind: "redirector", overlay: { server: "apache" } }), "apache");
  assert.equal(hostSlug({ kind: "collector", overlay: { sink: "opensearch" } }), "open");
  assert.equal(hostSlug({ kind: "jumpbox", overlay: {} }), "jump");
  assert.equal(hostSlug({ kind: "teamserver", overlay: {} }), "");
});

test("a container's slug is its dominant family, mgmt outranking c2 outranking rdir", () => {
  assert.equal(containerSlug("network", new Set(["mgmt"])), "main");
  assert.equal(containerSlug("network", new Set(["c2"])), "c2");
  assert.equal(containerSlug("network", new Set(["rdir"])), "rdir");
  assert.equal(containerSlug("network", new Set(["c2", "mgmt"])), "main");
  assert.equal(containerSlug("segment", new Set(["mgmt"])), "mgmt");
  assert.equal(containerSlug("segment", new Set(["c2", "rdir"])), "c2");
  assert.equal(containerSlug("network", new Set()), "");
});

test("an id parses into slug, tag, and ordinal", () => {
  assert.equal(abbrevOf("myth-ts01"), "ts");
  assert.equal(ordinalOf("myth-ts01"), "01");
  assert.equal(slugOf("myth-ts01"), "myth");
  assert.equal(abbrevOf("c2-sub01"), "sub");
  assert.equal(slugOf("c2-sub01"), "c2");
  assert.equal(abbrevOf("ts01"), "ts");
  assert.equal(slugOf("ts01"), "");
  assert.equal(composeId("myth", "ts", 1), "myth-ts01");
  assert.equal(composeId("", "ts", 2), "ts02");
  assert.equal(edgeId("a", "b", "logs_to"), "e-a-b-logs-to");
});

test("proposeId reads the seed overlay and skips taken ids", () => {
  const doc = build("teamserver", { c2: "mythic" });
  assert.equal(proposeId(doc, { kind: "teamserver", overlay: { c2: "sliver" } }), "sliv-ts01");
  // h01 is a mythic teamserver but its id is a bare ordinal, so myth-ts01 is free.
  assert.equal(proposeId(doc, { kind: "teamserver", overlay: { c2: "mythic" } }), "myth-ts01");
});

test("retitle names the containers after what they hold and cascades edges", () => {
  const { document: out, renamed } = retitle(build("teamserver", { c2: "mythic" }));
  const ids = out.nodes.map((n) => n.id);
  assert.ok(ids.includes("c2-net01"), ids);   // network holds c2 only
  assert.ok(ids.includes("c2-sub01"), ids);
  assert.ok(ids.includes("myth-ts01"), ids);
  // the attachment edges were rewritten and re-keyed onto the new ids
  assert.ok(out.edges.some((e) => e.source === "myth-ts01" && e.target === "c2-sub01"));
  assert.equal(renamed.h01, "myth-ts01");
});

test("swapping a host's kind renames the host and its containers", () => {
  const first = retitle(build("teamserver", { c2: "mythic" })).document;
  // replace the teamserver with a jumpbox in the same slot
  const swapped = {
    ...first,
    nodes: first.nodes.map((n) =>
      n.kind === "teamserver" ? { id: n.id, kind: "jumpbox", overlay: { services: ["ssh"] } } : n
    ),
  };
  const ids = retitle(swapped).document.nodes.map((n) => n.id);
  assert.ok(ids.includes("main-net01"), ids);  // mgmt attached -> main
  assert.ok(ids.includes("mgmt-sub01"), ids);
  assert.ok(ids.includes("jump-bx01"), ids);
});

test("a pinned id is left alone", () => {
  const doc = build("teamserver", { c2: "mythic" });
  const { document: out } = retitle(doc, new Set(["sub01"]));
  assert.ok(out.nodes.some((n) => n.id === "sub01"), "the pinned subnet keeps its id");
  assert.ok(out.nodes.some((n) => n.id === "myth-ts01"), "unpinned nodes still move");
});

test("a node pinned on the document survives retitle across a reload", () => {
  // No session ref, only the persisted flag: a reload starts with an empty pin
  // set but the hand-picked name must still be left alone.
  const doc = build("teamserver", { c2: "mythic" });
  const withPin = {
    ...doc,
    nodes: doc.nodes.map((n) => (n.id === "sub01" ? { ...n, id: "c2-lab", pinned: true } : n)),
    edges: doc.edges.map((e) => ({
      ...e,
      source: e.source === "sub01" ? "c2-lab" : e.source,
      target: e.target === "sub01" ? "c2-lab" : e.target,
    })),
  };
  const { document: out } = retitle(withPin, new Set());
  assert.ok(out.nodes.some((n) => n.id === "c2-lab"), "the persisted pin keeps the id");
});

test("retitle is a no-op once the ids already agree", () => {
  const once = retitle(build("teamserver", { c2: "mythic" })).document;
  const { document: twice, renamed } = retitle(once);
  assert.equal(Object.keys(renamed).length, 0);
  assert.strictEqual(twice, once);
});

console.log(`\n${passed} passed`);
