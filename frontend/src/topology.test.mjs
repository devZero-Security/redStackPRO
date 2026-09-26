// Conversion is the only place that knows both the document and the canvas, so
// it is the piece worth testing without a browser.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import {
  addEdge, addHostPreset, addNode, applyPositions, inferRole, removeNode,
  setJoin, setParent, toFlow,
} from "./topology.js";
import { HOST_PRESETS } from "./presets.js";
import { proposeId } from "./idscheme.js";
import { autoLayout, needsLayout } from "./layout.js";

const doc = JSON.parse(readFileSync("public/redstack.json", "utf8"));
const palette = {
  topology: [{ kind: "network", abbrev: "net", category: "container", color: "#868e96" },
             { kind: "segment", abbrev: "sub", category: "container", color: "#868e96" }],
  operational: [{ kind: "redirector", abbrev: "rd", category: "host", color: "#f59f00" },
                { kind: "teamserver", abbrev: "ts", category: "host", color: "#e03131" },
                { kind: "collector", abbrev: "log", category: "host", color: "#9c36b5" }],
  access: [{ kind: "jumpbox", abbrev: "bx", category: "host", color: "#1c7ed6" },
           { kind: "operator", abbrev: "op", category: "host", color: "#1c7ed6" }],
};

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

test("attachment is nesting, not a drawn line", () => {
  const { nodes, edges } = toFlow(doc, palette);
  assert.equal(nodes.find((n) => n.id === "myth-ts01").parentId, "c2-sub01");
  assert.equal(nodes.find((n) => n.id === "c2-sub01").parentId, "main-net01");
  assert.ok(!edges.some((e) => e.data.edge.role === "attached"));
});

test("containers precede their children", () => {
  const { nodes } = toFlow(doc, palette);
  const index = Object.fromEntries(nodes.map((n, i) => [n.id, i]));
  for (const node of nodes) {
    if (node.parentId) assert.ok(index[node.parentId] < index[node.id], node.id);
  }
});

test("the drawn name is the prefix plus the id", () => {
  const { nodes } = toFlow(doc, palette);
  assert.equal(nodes.find((n) => n.id === "myth-ts01").data.name, "art-myth-ts01");
});

test("manages is an annotation on the node, not a drawn line", () => {
  const { nodes, edges } = toFlow(doc, palette);
  // jump-bx01 manages the network it sits in (main-net01) and the peered
  // network (rdir-net01). Neither is a line now: a line into a container box
  // reads as piercing territory. Both show as an annotation on the jumpbox,
  // including the home network the loop form had to hide.
  assert.ok(!edges.some((e) => e.data.edge.role === "manages"), "no manages line");
  const jump = nodes.find((n) => n.id === "jump-bx01");
  assert.deepEqual([...jump.data.manages].sort(), ["main-net01", "rdir-net01"]);
  // The chip reads as a count by kind, with the full names left to the tooltip.
  assert.equal(jump.data.managesLabel, "2 networks");
});

test("a peering between networks is drawn", () => {
  const { edges } = toFlow(doc, palette);
  // Two peered networks read as joined rather than as two loose boxes.
  assert.ok(edges.some((e) => e.id === "e-main-net01-rdir-net01-peers"), "the peers edge draws");
});

test("a host on an internet segment reads as publicly reachable", () => {
  const { nodes } = toFlow(doc, palette);
  // apache-rd01 sits in rdir-sub01, which is exposure internet, and a redirector
  // takes an address by default. A teamserver in a local segment does not.
  assert.equal(nodes.find((n) => n.id === "apache-rd01").data.public, true);
  assert.equal(nodes.find((n) => n.id === "myth-ts01").data.public, false);
  assert.equal(nodes.find((n) => n.id === "kali-op01").data.public, false);
});

test("role follows from what a line connects", () => {
  assert.equal(inferRole("redirector", "teamserver"), "fronts");
  assert.equal(inferRole("teamserver", "collector"), "logs_to");
  assert.equal(inferRole("jumpbox", "network"), "manages");
  assert.equal(inferRole("teamserver", "redirector"), null);
});

test("a new node takes the next free id for its slug", () => {
  // The document already holds a Mythic teamserver, so another is myth-ts02; a
  // fresh Nginx redirector takes the free nginx-rd01 (the shipped one is Apache).
  assert.equal(proposeId(doc, { kind: "teamserver", overlay: { c2: "mythic" } }), "myth-ts02");
  assert.equal(proposeId(doc, { kind: "redirector", overlay: { server: "nginx" } }), "nginx-rd01");
});

test("adding a node seeds a schema valid overlay and a scheme id", () => {
  const next = addNode(doc, { kind: "teamserver", abbrev: "ts", category: "host" }, { x: 0, y: 0 });
  const added = next.nodes.at(-1);
  assert.equal(added.id, "myth-ts02");
  assert.ok(added.overlay.c2);
});

test("adding a network allocates a fresh range", () => {
  // The example already uses 10.30 and 10.31, so the allocator skips to the next
  // free /16 rather than colliding.
  const next = addNode(doc, { kind: "network", abbrev: "net", category: "container" }, { x: 0, y: 0 });
  const added = next.nodes.at(-1);
  assert.match(added.overlay.cidr, /^10\.\d+\.0\.0\/16$/);
  assert.ok(!doc.nodes.some((n) => n.overlay?.cidr === added.overlay.cidr), "range is unused");
});

test("removing a node removes its edges", () => {
  const next = removeNode(doc, "myth-ts01");
  assert.ok(!next.edges.some((e) => e.source === "myth-ts01" || e.target === "myth-ts01"));
});

test("reparenting rewrites exactly one attachment", () => {
  const next = setParent(doc, "myth-ts01", "rdir-sub01");
  const attachments = next.edges.filter((e) => e.role === "attached" && e.source === "myth-ts01");
  assert.equal(attachments.length, 1);
  assert.equal(attachments[0].target, "rdir-sub01");
});

test("an edge is not added twice", () => {
  const once = addEdge(doc, "apache-rd01", "open-log01", "logs_to");
  const twice = addEdge(once, "apache-rd01", "open-log01", "logs_to");
  assert.equal(once.edges.length, twice.edges.length);
});

test("positions survive the round trip", () => {
  const { nodes } = toFlow(doc, palette);
  const moved = nodes.map((n) => ({ ...n, position: { x: 11, y: 22 } }));
  const next = applyPositions(doc, moved);
  assert.deepEqual(next.nodes[0].position, { x: 11, y: 22 });
  assert.equal(next.nodes.length, doc.nodes.length);
});

test("auto layout gives every node a position", () => {
  const laid = autoLayout(doc);
  assert.ok(laid.nodes.every((n) => n.position));
  assert.ok(!needsLayout(laid));
  assert.ok(needsLayout(doc), "the example ships without positions");
});

test("nothing overlaps inside a segment", () => {
  const laid = autoLayout(doc);
  const parent = Object.fromEntries(
    laid.edges.filter((e) => e.role === "attached").map((e) => [e.source, e.target])
  );
  const groups = {};
  for (const node of laid.nodes) {
    if (node.kind === "network" || node.kind === "segment") continue;
    (groups[parent[node.id]] ||= []).push(node);
  }
  for (const members of Object.values(groups)) {
    const seen = new Set();
    for (const m of members) {
      const key = `${m.position.x},${m.position.y}`;
      assert.ok(!seen.has(key), `two hosts at ${key}`);
      seen.add(key);
    }
  }
});

test("a container is sized to fit its members", () => {
  const laid = autoLayout(doc);
  const byId = Object.fromEntries(laid.nodes.map((n) => [n.id, n]));
  const parent = Object.fromEntries(
    laid.edges.filter((e) => e.role === "attached").map((e) => [e.source, e.target])
  );
  for (const node of laid.nodes) {
    const box = byId[parent[node.id]];
    if (!box?.width) continue;
    assert.ok(node.position.x >= 0 && node.position.y >= 0, node.id);
    assert.ok(node.position.x < box.width, `${node.id} sticks out of ${box.id}`);
    assert.ok(node.position.y < box.height, `${node.id} sticks out of ${box.id}`);
  }
});

test("segments in the main network read top to bottom, c2 above the jumpbox", () => {
  // The callback's path inward: the c2 near the top, and below it the one
  // internal segment that holds the jumpbox, the operator boxes and the
  // collector (redStack's shape). Positions are relative to the network, so the
  // segments of main-net01 compare directly.
  const laid = autoLayout(doc);
  const y = Object.fromEntries(
    laid.nodes.filter((n) => n.kind === "segment").map((n) => [n.id, n.position.y])
  );
  assert.ok(y["c2-sub01"] < y["mgmt-sub01"], "the c2 sits above the management tier");
});

test("the redirector network sits above the main range", () => {
  // The internet-facing redirector network is at the top of the hierarchy, with
  // the main range stacked below it.
  const laid = autoLayout(doc);
  const byId = Object.fromEntries(laid.nodes.map((n) => [n.id, n]));
  assert.ok(
    byId["rdir-net01"].position.y < byId["main-net01"].position.y,
    "the redirector network is on top"
  );
});

test("peer networks share a row instead of stacking", () => {
  // Split horizon's two front doors both rank at the redirector tier, so they
  // are alternatives to each other rather than one behind the other. Stacked,
  // the only way to see they were siblings was to compare their CIDRs.
  const split = JSON.parse(readFileSync("public/split-horizon.json", "utf8"));
  const laid = autoLayout(split);
  const byId = Object.fromEntries(laid.nodes.map((n) => [n.id, n]));
  const long = byId["long-net01"];
  const intr = byId["intr-net01"];
  assert.equal(long.position.y, intr.position.y, "the two doors sit on one row");
  assert.notEqual(long.position.x, intr.position.x, "and not on top of each other");
  assert.ok(
    long.position.x + long.width <= intr.position.x,
    "the row does not overlap"
  );
  // The rows themselves still read top to bottom by tier.
  assert.ok(
    long.position.y < byId["main-net01"].position.y,
    "the redirector row is above the main range"
  );
});

test("networks of different rank still stack", () => {
  // The rollover shape has one redirector network and one main network, which
  // do not tie, so nothing about the peer row applies to it.
  const roll = JSON.parse(readFileSync("public/rollover.json", "utf8"));
  const byId = Object.fromEntries(autoLayout(roll).nodes.map((n) => [n.id, n]));
  assert.equal(byId["rdir-net01"].position.x, byId["main-net01"].position.x);
  assert.ok(byId["rdir-net01"].position.y < byId["main-net01"].position.y);
});

test("layout is stable across runs", () => {
  assert.deepEqual(autoLayout(doc), autoLayout(doc));
});

test("a range jumpbox and SIEM nest in the subnet, not a domain", () => {
  const range = JSON.parse(readFileSync("public/goad/goad-wazuh.json", "utf8"));
  const { nodes } = toFlow(range, palette);
  assert.equal(nodes.find((n) => n.id === "jumpbox").parentId, "sub01");
  assert.equal(nodes.find((n) => n.id === "wazuh").parentId, "sub01");
  // A domain member still nests in its domain.
  assert.equal(nodes.find((n) => n.id === "kingslanding").parentId, "sevenkingdoms");
});

test("a host preset arrives with its role and services filled in", () => {
  const empty = { schema_version: "0.6.0", mode: "haven", prefix: "hvn", nodes: [], edges: [] };
  const sql = HOST_PRESETS.find((p) => p.key === "sql");
  const next = addHostPreset(empty, sql, { x: 0, y: 0 });
  assert.equal(next.nodes.length, 1);
  const node = next.nodes[0];
  assert.equal(node.kind, "srv");
  assert.equal(node.overlay.role, "sql");
  assert.deepEqual(node.overlay.services, ["mssql"]);
  // The id derives from the kind, not a bare ordinal.
  assert.ok(/srv0\d$/.test(node.id), node.id);
});

test("joining a host to a domain rewrites the joins edge, not a second one", () => {
  const range = JSON.parse(readFileSync("public/goad/goad-wazuh.json", "utf8"));
  // castelblack joins north in the template; move it to sevenkingdoms.
  const moved = setJoin(range, "castelblack", "sevenkingdoms");
  const joins = moved.edges.filter((e) => e.role === "joins" && e.source === "castelblack");
  assert.equal(joins.length, 1);
  assert.equal(joins[0].target, "sevenkingdoms");
  // An empty domain clears membership.
  const cleared = setJoin(moved, "castelblack", undefined);
  assert.ok(!cleared.edges.some((e) => e.role === "joins" && e.source === "castelblack"));
});

test("placing a host on a subnet re-nests it there", () => {
  const range = JSON.parse(readFileSync("public/goad/goad-wazuh.json", "utf8"));
  const placed = setParent(range, "wazuh", "sub01");
  const attached = placed.edges.filter((e) => e.role === "attached" && e.source === "wazuh");
  assert.equal(attached.length, 1);
  assert.equal(attached[0].target, "sub01");
});

console.log(`\n${passed} passed`);
