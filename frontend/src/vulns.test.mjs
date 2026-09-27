// The vuln catalog is a product surface (the plant-a-vuln menu) and the source
// the shipped templates draw their vulns from. These guard that the curated set
// stays coherent: no template references a vuln the catalog dropped, ids are
// unique, and every entry declares its GOAD mapping so range compilation can
// wire it. See vulns.js and 0050.
import assert from "node:assert";
import { readFileSync, readdirSync } from "node:fs";
import { ACCOUNT_TECHNIQUE_IDS, VULN_CATALOG, VULN_GOAD, VULN_LABEL, VULN_PROVIDERS } from "./vulns.js";

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

console.log(`\n${passed} passed`);
