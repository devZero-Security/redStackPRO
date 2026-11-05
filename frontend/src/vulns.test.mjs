// The vuln catalog is a product surface (the plant-a-vuln menu) and the source
// the shipped templates draw their vulns from. These guard that the curated set
// stays coherent: no template references a vuln the catalog dropped, ids are
// unique, and every entry declares its GOAD mapping so range compilation can
// wire it. See vulns.js and 0050.
import assert from "node:assert";
import { readFileSync, readdirSync } from "node:fs";
import { ACCOUNT_TECHNIQUE_IDS, VULN_CATALOG, VULN_GOAD, VULN_LABEL, VULN_PARAMS, VULN_PROVIDERS, vulnParamsExample } from "./vulns.js";

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

const items = VULN_CATALOG.flatMap((g) => g.items);
const ids = new Set(items.map((i) => i.id));
const RANGE_PROVIDERS = ["aws", "gcp", "azure", "proxmox", "esxi"];

test("the catalog is a scoped common set", () => {
  // The original cap (24) was this catalog's size at 0050; it has since grown
  // organically as range work added technique groups (ADCS, ACL abuse,
  // delegation, coercion & relay...). This guards against unbounded sprawl, not
  // against the catalog's documented, deliberate growth.
  assert.ok(items.length >= 10 && items.length <= 80, `${items.length} items`);
});

test("ids are unique", () => {
  assert.equal(ids.size, items.length);
});

test("every item has a label and a goad mapping key", () => {
  for (const i of items) {
    assert.ok(i.label, i.id);
    assert.ok("goad" in i, `${i.id} declares no goad mapping`);
    assert.equal(VULN_LABEL[i.id], i.label);
    assert.ok(i.id in VULN_GOAD, i.id);
  }
});

test("a provider-restricted vuln names a non-empty subset of real range providers", () => {
  for (const i of items) {
    if (!("providers" in i)) continue;
    assert.ok(Array.isArray(i.providers) && i.providers.length > 0, i.id);
    for (const p of i.providers) {
      assert.ok(RANGE_PROVIDERS.includes(p), `${i.id} names unknown provider ${p}`);
    }
    assert.deepEqual(VULN_PROVIDERS[i.id], i.providers, i.id);
  }
});

test("no shipped template references a vuln the catalog dropped", () => {
  // The GOAD templates that carry vulns live in the goad/ subdirectory.
  const dirs = ["public", "public/goad"];
  const used = new Set();
  for (const dir of dirs) {
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".json")) continue;
      let doc;
      try {
        doc = JSON.parse(readFileSync(`${dir}/${f}`, "utf8"));
      } catch {
        continue;
      }
      for (const n of doc.nodes || []) {
        for (const v of (n.overlay || {}).vulns || []) used.add(v);
      }
    }
  }
  const orphans = [...used].filter((v) => !ids.has(v));
  assert.deepEqual(orphans, [], `templates reference vulns not in the catalog: ${orphans}`);
});

test("the account techniques are exactly the user: mapped ids", () => {
  // kerberoasting, asreproasting, password_in_description, and weak_password
  // are account flaws, not host tasks (see the Kerberos and Credentials group
  // comments): the host VulnPicker plants them on a domain user instead of the
  // host's own overlay.vulns. See rangeUsers.js.
  const userMapped = items.filter((i) => typeof i.goad === "string" && i.goad.startsWith("user:"));
  assert.deepEqual(
    [...ACCOUNT_TECHNIQUE_IDS].sort(),
    userMapped.map((i) => i.id).sort()
  );
  assert.deepEqual(
    [...ACCOUNT_TECHNIQUE_IDS].sort(),
    ["asreproasting", "kerberoasting", "password_in_description", "weak_password"]
  );
});

test("every parameterized vuln is a catalog id with described keys", () => {
  for (const [id, params] of Object.entries(VULN_PARAMS)) {
    assert.ok(ids.has(id), `VULN_PARAMS names ${id}, which the catalog does not have`);
    assert.ok(params.length > 0, id);
    for (const p of params) {
      assert.match(p.key, /^[a-z0-9_]+(\.[a-z0-9_]+)?$/, `${id} ${p.key}`);
      assert.ok(p.about, `${id} ${p.key} has no about`);
      if (p.required) assert.ok("example" in p, `${id} ${p.key} is required but has no example`);
    }
  }
});

test("every setting has a plain label, one per key and unique across keys", () => {
  const byLabel = new Map();
  const byKey = new Map();
  for (const [id, params] of Object.entries(VULN_PARAMS)) {
    for (const p of params) {
      assert.ok(p.label && p.label !== p.key, `${id} ${p.key} has no plain label`);
      if (byKey.has(p.key)) assert.equal(p.label, byKey.get(p.key), `${p.key} is labelled two ways`);
      byKey.set(p.key, p.label);
      const other = byLabel.get(p.label.toLowerCase());
      assert.ok(!other || other === p.key, `${p.key} and ${other} share the label ${p.label}`);
      byLabel.set(p.label.toLowerCase(), p.key);
    }
  }
});

test("the example is one line of JSON carrying every required key", () => {
  for (const [id, params] of Object.entries(VULN_PARAMS)) {
    const line = vulnParamsExample(id);
    assert.ok(!line.includes("\n"), id);
    const parsed = JSON.parse(line);
    for (const p of params.filter((q) => q.required)) {
      const value = p.key.split(".").reduce((at, part) => (at || {})[part], parsed);
      assert.deepEqual(value, p.example, `${id} ${p.key}`);
    }
  }
  assert.equal(
    vulnParamsExample("constrained_delegation_kerberos"),
    '{"delegate_to":["CIFS/srv01.corp.local"]}'
  );
  assert.equal(vulnParamsExample("smbv1"), null);
});

console.log(`\n${passed} passed`);
