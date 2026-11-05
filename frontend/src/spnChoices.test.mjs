import assert from "node:assert";
import { readFileSync } from "node:fs";
import {
  defaultDelegateTo, hostDomain, spnChoices, withDelegationDefault,
} from "./spnChoices.js";

const light = JSON.parse(readFileSync("public/goad/goad-light.json", "utf8"));

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

test("north offers the services its hosts really run, the DC first", () => {
  const groups = spnChoices(light, "north");
  assert.deepStrictEqual(groups.map((g) => g.host), ["winterfell", "castelblack"]);
  const spns = groups.flatMap((g) => g.spns.map((s) => s.spn));
  assert.ok(spns.includes("CIFS/winterfell.north.sevenkingdoms.local"));
  assert.ok(spns.includes("LDAP/winterfell.north.sevenkingdoms.local"));
  assert.ok(spns.includes("MSSQLSvc/castelblack.north.sevenkingdoms.local:1433"));
  assert.ok(spns.includes("HTTP/castelblack.north.sevenkingdoms.local"));
  // No SQL or IIS on the DC, so neither is offered there.
  assert.ok(!spns.includes("MSSQLSvc/winterfell.north.sevenkingdoms.local:1433"));
  assert.ok(!spns.includes("HTTP/winterfell.north.sevenkingdoms.local"));
});

test("a computer is never offered as its own delegation target", () => {
  const groups = spnChoices(light, "north", { exclude: "castelblack" });
  assert.deepStrictEqual(groups.map((g) => g.host), ["winterfell"]);
});

test("the default target is CIFS on the domain's DC", () => {
  assert.deepStrictEqual(defaultDelegateTo(light, "north"),
    ["CIFS/winterfell.north.sevenkingdoms.local"]);
  assert.strictEqual(hostDomain(light, "castelblack"), "north");
});

test("ticking constrained_delegation_kerberos fills delegate_to once", () => {
  // castelblack ships with delegation to HTTP/winterfell; start from a bare copy.
  const shipped = light.nodes.find((n) => n.id === "castelblack");
  const { vulns_vars: _vars, ...rest } = shipped.overlay;
  const node = { ...shipped, overlay: { ...rest, vulns: (rest.vulns || []).filter(
    (v) => v !== "constrained_delegation_kerberos") } };
  const ticked = withDelegationDefault(light, node, {
    ...node.overlay, vulns: [...(node.overlay.vulns || []), "constrained_delegation_kerberos"],
  });
  assert.deepStrictEqual(ticked.vulns_vars.delegate_to,
    ["CIFS/winterfell.north.sevenkingdoms.local"]);
  // A target the person already set is kept.
  const kept = withDelegationDefault(light, node, {
    ...node.overlay,
    vulns: ["constrained_delegation_kerberos"],
    vulns_vars: { delegate_to: ["HTTP/x.north.sevenkingdoms.local"] },
  });
  assert.deepStrictEqual(kept.vulns_vars.delegate_to, ["HTTP/x.north.sevenkingdoms.local"]);
  // Already ticked before: nothing is refilled after the person clears it.
  const already = { ...node, overlay: { ...node.overlay, vulns: ["constrained_delegation_kerberos"] } };
  const cleared = withDelegationDefault(light, already, { ...already.overlay, vulns_vars: {} });
  assert.strictEqual(cleared.vulns_vars.delegate_to, undefined);
});

test("a domain with no fqdn offers nothing rather than half names", () => {
  const doc = { nodes: [{ id: "d", kind: "domain", overlay: {} }, { id: "h", kind: "srv" }],
                edges: [{ role: "joins", source: "h", target: "d" }] };
  assert.deepStrictEqual(spnChoices(doc, "d"), []);
  assert.deepStrictEqual(defaultDelegateTo(doc, "d"), []);
});

console.log(`spnChoices: ${passed} passed`);
