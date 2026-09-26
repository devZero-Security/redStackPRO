// The hardening catalog is a second copy of a list whose source of truth is the
// schema enum. Two copies drift, so this reads the schema and holds the catalog
// to it: a control added to one and not the other fails here rather than
// showing up as a checkbox that no host can ever have, or a schema value with
// no way to tick it.
//
// Same reason tests/test_vuln_providers_sync.py exists for the vuln list.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { HARDENING_CATALOG, HARDENING_IDS } from "./hardening.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(
  readFileSync(join(HERE, "../../src/redstackpro/schema/topology/0.5.0.json"), "utf8")
);
const enumIds =
  schema.$defs.overlay_range_host.properties.hardening.items.enum;

// The schema is the source of truth, so compare as SETS and report both
// directions by name. An equality assert on sorted arrays says only that they
// differ, which is the least useful thing it could say.
const inCatalog = new Set(HARDENING_IDS);
const inSchema = new Set(enumIds);

const missing = enumIds.filter((id) => !inCatalog.has(id));
assert.deepEqual(missing, [], `in the schema but not the catalog: ${missing}`);

const extra = HARDENING_IDS.filter((id) => !inSchema.has(id));
assert.deepEqual(extra, [], `in the catalog but not the schema: ${extra}`);

// Every id appears once. A duplicate would render two checkboxes bound to the
// same value, which look independent and are not.
assert.equal(
  new Set(HARDENING_IDS).size,
  HARDENING_IDS.length,
  "duplicate id in the hardening catalog"
);

// Every group says what it is for. The summaries are the whole point of the
// grouping: without them this is the flat wall of checkboxes it replaced.
for (const group of HARDENING_CATALOG) {
  assert.ok(group.group, "a hardening group has no name");
  assert.ok(
    group.summary && group.summary.length > 10,
    `hardening group ${group.group} has no usable summary`
  );
  assert.ok(group.items.length > 0, `hardening group ${group.group} is empty`);
  for (const item of group.items) {
    assert.ok(item.label, `hardening item ${item.id} has no label`);
    assert.ok(
      item.blurb && item.blurb.length > 20,
      `hardening item ${item.id} has no usable blurb`
    );
  }
}

console.log(`hardening ok (${HARDENING_IDS.length} controls, ${HARDENING_CATALOG.length} groups)`);
