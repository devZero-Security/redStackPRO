// The range starters: each must name a real host kind and a valid role, since a
// preset that seeds an invalid overlay would ship a node the validator rejects.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { HOST_PRESETS, OPS_PRESETS, presetsFor } from "./presets.js";

const schema = JSON.parse(readFileSync("../schema/topology/0.4.0.json", "utf8"));
const rangeHostRoles = schema.$defs.overlay_range_host.properties.role.enum;
const HOST_KINDS = new Set(["srv", "wks", "dc", "fw"]);
const OPS_KINDS = new Set(["redirector", "teamserver", "operator"]);
const enumOf = (def, field) => schema.$defs[def].properties[field].enum;

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

test("every preset names a range host kind", () => {
  for (const p of HOST_PRESETS) assert.ok(HOST_KINDS.has(p.kind), p.key);
});

test("every preset role is in the schema enum", () => {
  for (const p of HOST_PRESETS) {
    assert.ok(rangeHostRoles.includes(p.overlay.role), `${p.key}: ${p.overlay.role}`);
  }
});

test("preset keys are unique", () => {
  const keys = HOST_PRESETS.map((p) => p.key);
  assert.equal(new Set(keys).size, keys.length);
});

test("each canvas serves its own presets", () => {
  assert.equal(presetsFor("range").length, HOST_PRESETS.length);
  assert.equal(presetsFor("ops").length, OPS_PRESETS.length);
  assert.ok(OPS_PRESETS.length > 0);
});

test("attack presets name a redirector, teamserver, or operator subtype", () => {
  const c2 = enumOf("overlay_teamserver", "c2");
  const server = enumOf("overlay_redirector", "server");
  const os = enumOf("overlay_operator", "os");
  for (const p of OPS_PRESETS) {
    assert.ok(OPS_KINDS.has(p.kind), `${p.key}: kind ${p.kind}`);
    if (p.kind === "teamserver") assert.ok(c2.includes(p.overlay.c2), `${p.key}: c2 ${p.overlay.c2}`);
    if (p.kind === "redirector") assert.ok(server.includes(p.overlay.server), `${p.key}: server`);
    if (p.kind === "operator") assert.ok(os.includes(p.overlay.os), `${p.key}: os`);
  }
});

test("every preset carries a palette icon and a display abbrev", () => {
  // They render as their own first-class hosts now, so a blank icon or tag would
  // ship an unlabelled button.
  for (const p of [...HOST_PRESETS, ...OPS_PRESETS]) {
    assert.ok(p.icon, `${p.key}: icon`);
    assert.ok(p.abbrev, `${p.key}: abbrev`);
    assert.ok(p.color, `${p.key}: color`);
  }
});

test("preset keys are unique within a canvas", () => {
  for (const list of [HOST_PRESETS, OPS_PRESETS]) {
    const keys = list.map((p) => p.key);
    assert.equal(new Set(keys).size, keys.length);
  }
});

console.log(`\n${passed} passed`);
