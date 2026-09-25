import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { FAMILIES, familyFor, familyTooltip } from "./findingFamilies.js";

// The canvas must have a word for every family the validator can emit. A rule
// added in Python with no entry here renders as a bare acronym again, which is
// the thing this module exists to stop, so read the real validator rather than
// trusting a hand-kept list.
{
  const source = readFileSync(
    new URL("../../src/redstackpro/validate.py", import.meta.url),
    "utf8"
  );
  const emitted = new Set(
    [...source.matchAll(/"([A-Z]{3})\d{3}"/g)].map((m) => m[1])
  );
  assert.ok(emitted.size > 0, "found no finding codes in validate.py");
  for (const prefix of emitted) {
    assert.ok(
      FAMILIES[prefix],
      `validate.py emits ${prefix}nnn but findingFamilies.js has no label for it`
    );
  }
  // And nothing here is dead: a family the validator cannot emit is a label
  // nobody will ever see, usually left behind by a renamed rule.
  for (const prefix of Object.keys(FAMILIES)) {
    assert.ok(
      emitted.has(prefix),
      `findingFamilies.js labels ${prefix} but validate.py never emits it`
    );
  }
}

// Every label is short enough to sit inline in the footer without pushing the
// message onto another line, and every blurb is a sentence rather than a
// fragment, because it is read on its own in a tooltip.
for (const [prefix, family] of Object.entries(FAMILIES)) {
  assert.ok(family.label.length <= 16, `${prefix} label too long for the footer`);
  assert.doesNotMatch(family.label, /[.]/, `${prefix} label is a sentence`);
  assert.match(family.blurb, /\.$/, `${prefix} blurb does not end in a period`);
}

// The happy path: a real code resolves to its family, and the tooltip carries
// the code so nothing is lost by hiding it from the surface.
{
  const family = familyFor("CAR006");
  assert.equal(family.label, "Cardinality");
  assert.equal(family.known, true);
  const tip = familyTooltip("CAR006");
  assert.match(tip, /CAR006/);
  assert.match(tip, /Cardinality/);
  assert.match(tip, /How many of an edge kind/);
}

// A code from a newer validator than this build. Showing a guessed family would
// be worse than showing the code, so it falls back to the code unchanged and
// says it did not recognise it.
{
  const family = familyFor("ZZZ001");
  assert.equal(family.known, false);
  assert.equal(family.label, "ZZZ001");
  assert.equal(familyTooltip("ZZZ001"), "ZZZ001");
}

// Malformed and missing codes must not throw: the footer renders whatever the
// API sent, and a crash there takes the whole canvas down with it.
for (const bad of [undefined, null, "", "CAR", "car006", "CAR0060", 42]) {
  const family = familyFor(bad);
  assert.equal(family.known, false);
  assert.equal(typeof family.label, "string");
  assert.equal(typeof familyTooltip(bad), "string");
}

console.log("findingFamilies ok");
