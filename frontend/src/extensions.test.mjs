import assert from "node:assert";
import {
  EXTENSIONS,
  activeExtensions,
  applyExtension,
  availableExtensions,
  canAdd,
  removeExtension,
  supportsExtension,
} from "./extensions.js";

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

// A minimal GOAD-like range: one subnet, one domain, one Windows DC joined. The
// name matters now: extensions offer by lab compatibility.
const base = (name = "GOAD-Mini") => ({
  name,
  mode: "defense",
  nodes: [
    { id: "net01", kind: "network", overlay: { cidr: "192.168.0.0/16" } },
    { id: "sub01", kind: "segment", overlay: { cidr: "192.168.56.0/24", egress: "allowed", exposure: "local" } },
    { id: "sevenkingdoms", kind: "domain", overlay: { fqdn: "sevenkingdoms.local", netbios: "SEVENKINGDOMS" } },
    { id: "kingslanding", kind: "dc", overlay: { os: "windows_server_2019", hostname: "kingslanding", edr: "defender" } },
  ],
  edges: [
    { id: "e-sub01-net01-attached", role: "attached", source: "sub01", target: "net01" },
    { id: "e-kingslanding-sub01-attached", role: "attached", source: "kingslanding", target: "sub01" },
    { id: "e-kingslanding-joins", role: "joins", source: "kingslanding", target: "sevenkingdoms" },
  ],
});

test("the five GOAD extensions are declared, guacamole omitted", () => {
  const keys = EXTENSIONS.map((e) => e.key).sort();
  assert.deepEqual(keys, ["elk", "exchange", "lx01", "wazuh", "ws01"]);
  // Guacamole runs on the jumpbox, so it is not offered as a separate box.
  assert.ok(!keys.includes("guacamole"));
});

test("adding wazuh adds a SIEM box and an agent on the Windows host", () => {
  const doc = applyExtension(base(), "wazuh");
  const siem = doc.nodes.find((n) => n.kind === "siem");
  assert.equal(siem.id, "wazuh");
  assert.equal(siem.overlay.product, "wazuh");
  // The SIEM attaches to the subnet, and it is not a domain member.
  assert.ok(doc.edges.some((e) => e.role === "attached" && e.source === "wazuh" && e.target === "sub01"));
  assert.ok(!doc.edges.some((e) => e.role === "joins" && e.source === "wazuh"));
  // Every Windows host now runs the wazuh agent.
  const dc = doc.nodes.find((n) => n.id === "kingslanding");
  assert.equal(dc.overlay.edr, "wazuh");
});

test("adding ws01 adds a hardened workstation joined to the root domain", () => {
  const doc = applyExtension(base(), "ws01");
  const ws = doc.nodes.find((n) => n.id === "ws01");
  assert.equal(ws.kind, "wks");
  assert.equal(ws.overlay.os, "windows_10");
  assert.ok(doc.edges.some((e) => e.role === "joins" && e.source === "ws01" && e.target === "sevenkingdoms"));
  assert.ok(doc.edges.some((e) => e.role === "attached" && e.source === "ws01" && e.target === "sub01"));
});

test("activeExtensions reports what is present", () => {
  const doc = applyExtension(applyExtension(base(), "wazuh"), "ws01");
  const active = activeExtensions(doc);
  assert.ok(active.has("wazuh"));
  assert.ok(active.has("ws01"));
  assert.ok(!active.has("elk"));
});

test("removing wazuh drops the box and reverts the agent to defender", () => {
  const withExt = applyExtension(base(), "wazuh");
  const doc = removeExtension(withExt, "wazuh");
  assert.ok(!doc.nodes.some((n) => n.id === "wazuh"));
  assert.ok(!doc.edges.some((e) => e.source === "wazuh" || e.target === "wazuh"));
  assert.equal(doc.nodes.find((n) => n.id === "kingslanding").overlay.edr, "defender");
});

test("applying twice is idempotent", () => {
  const once = applyExtension(base(), "wazuh");
  const twice = applyExtension(once, "wazuh");
  assert.equal(twice.nodes.filter((n) => n.id === "wazuh").length, 1);
});

test("a domain extension cannot be added to a range with no domain", () => {
  const noDomain = {
    name: "GOAD-Mini",
    mode: "defense",
    nodes: [
      { id: "net01", kind: "network", overlay: { cidr: "10.0.0.0/16" } },
      { id: "sub01", kind: "segment", overlay: { cidr: "10.0.10.0/24", egress: "allowed", exposure: "local" } },
    ],
    edges: [{ id: "e-sub01-net01-attached", role: "attached", source: "sub01", target: "net01" }],
  };
  assert.equal(canAdd(noDomain, "ws01"), false);
  // A standalone box has no such requirement.
  assert.equal(canAdd(noDomain, "wazuh"), true);
});

test("labs only offer the extensions GOAD says they support", () => {
  // ws01/exchange/lx01 are sevenkingdoms specific: the three main labs offer
  // them, the generated labs (NHA, SCCM, ...) do not. wazuh and elk are "*".
  for (const lab of ["GOAD", "GOAD-Light", "GOAD-Mini"]) {
    assert.ok(supportsExtension(base(lab), "ws01"), `${lab} should offer ws01`);
  }
  const nha = availableExtensions(base("NHA")).map((e) => e.key).sort();
  assert.deepEqual(nha, ["elk", "wazuh"]);
  assert.equal(supportsExtension(base("NHA"), "ws01"), false);
  assert.equal(canAdd(base("NHA"), "exchange"), false);
  // The full lab offers all five.
  assert.equal(availableExtensions(base("GOAD")).length, 5);
});

console.log(`\n${passed} passed`);
