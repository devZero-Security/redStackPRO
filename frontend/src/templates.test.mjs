import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  GROUP_NOTES,
  TEMPLATES,
  groupedTemplates,
  templateFor,
  templatesFor,
} from "./templates.js";

const PUBLIC = new URL("../public/", import.meta.url);

function document(file) {
  return JSON.parse(readFileSync(new URL(file + ".json", PUBLIC), "utf8"));
}

const ranges = templatesFor("defense");

// Every entry points at a document that is actually bundled. A template whose
// file is missing is a button that fails when pressed.
for (const t of [...ranges, ...templatesFor("offense")]) {
  const doc = document(t.file);
  assert.ok(Array.isArray(doc.nodes) && doc.nodes.length,
            `${t.name} loads an empty document`);
}

// ------------------------------------------------ the blurbs against the labs ---
//
// Six times now a hand-written description of a lab has disagreed with the lab.
// These pin the two found here: goad-light was shipping "No essos, no ADCS"
// while declaring esc1, and goad-wazuh was described as GOAD when it carries
// GOAD-Light's two domains. A description is only useful while it is true.

function vulns(doc) {
  const set = new Set();
  for (const node of doc.nodes) {
    for (const v of (node.overlay || {}).vulns || []) set.add(v);
  }
  return set;
}

function domainCount(doc) {
  return doc.nodes.filter((n) => n.kind === "domain").length;
}

for (const t of ranges) {
  const doc = document(t.file);
  const blurb = t.blurb.toLowerCase();

  // A lab that plants a certificate-template attack cannot be described as
  // having none. This is the exact claim goad-light shipped.
  const hasAdcs = [...vulns(doc)].some((v) => v.startsWith("esc"));
  if (hasAdcs) {
    assert.ok(!/no adcs/.test(blurb),
              `${t.name} says "no ADCS" but declares ${
                [...vulns(doc)].filter((v) => v.startsWith("esc")).join(", ")}`);
  }

  // Where a blurb counts domains, the count has to be the lab's.
  const claimed = blurb.match(/\b(one|two|three|four|five)\s+domains?\b/);
  if (claimed) {
    const words = { one: 1, two: 2, three: 3, four: 4, five: 5 };
    assert.equal(
      words[claimed[1]], domainCount(doc),
      `${t.name} claims ${claimed[1]} domain(s) and the template has ${domainCount(doc)}`);
  }
}

// --------------------------------------------------------- what a range is for ---

// The summary card has nothing to say without this, and a range whose point is
// not written down is the problem the card exists to fix.
for (const t of ranges) {
  assert.ok(t.teaches && t.teaches.length > 40,
            `${t.name} has no "teaches" text, so its summary card would be bare`);
  assert.match(t.teaches, /\.$/, `${t.name} teaches text is not a sentence`);
}

// ------------------------------------------------------------------- grouping ---

{
  const groups = groupedTemplates("defense");
  const goad = groups.find((g) => g.group === "GOAD");
  assert.ok(goad, "the GOAD family is not grouped");
  assert.equal(goad.templates.length, 8);

  // Harbor is ours, not a GOAD lab, and the palette folds the family into one
  // row. If Harbor ever gains `group: "GOAD"` it disappears inside that fold
  // and the product reads as a GOAD launcher again.
  const loose = groups.filter((g) => !g.group).flatMap((g) => g.templates);
  assert.deepEqual(loose.map((t) => t.name), ["Harbor"]);

  // Every group a template names has a note explaining what the family is.
  for (const { group } of groups) {
    if (group) assert.ok(GROUP_NOTES[group], `no note for the ${group} family`);
  }
}

// --------------------------------------------------------------- templateFor ---

{
  assert.equal(templateFor("harbor").name, "Harbor");
  // The canvas calls it with the url it fetched, so both the leading slash and
  // the extension have to come off.
  assert.equal(templateFor("/goad/goad.json").name, "GOAD");
  assert.equal(templateFor("goad/goad-light").name, "GOAD-Light");
  // Both canvases, not just the range one.
  assert.equal(templateFor("redstack").name, "redStack");
  // A topology somebody built themselves has no template, and the card must not
  // claim one.
  assert.equal(templateFor("something-else"), undefined);
  for (const bad of [undefined, null, ""]) {
    assert.equal(templateFor(bad), undefined);
  }
}

// Names are what a person picks from, so two entries cannot share one.
{
  const names = Object.values(TEMPLATES).flat().map((t) => t.name);
  assert.equal(new Set(names).size, names.length, "two templates share a name");
}

console.log("templates ok");
