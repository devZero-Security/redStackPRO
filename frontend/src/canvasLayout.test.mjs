// Every shipped blueprint opens with no box drawn over another. NHA's one host
// ninja domain used to render 260 tall and cover academy below it.
import assert from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { toFlow, containerSize, EMPTY_CONTAINER } from "./topology.js";
import { layoutIfNeeded } from "./layout.js";

const palette = {};
const files = [
  ...readdirSync("public").filter((f) => f.endsWith(".json")).map((f) => `public/${f}`),
  ...readdirSync("public/goad").filter((f) => f.endsWith(".json")).map((f) => `public/goad/${f}`),
];

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

const rect = (n) => ({
  x: n.position.x, y: n.position.y, w: n.style.width, h: n.style.height,
});
const overlaps = (a, b) =>
  a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

for (const file of files) {
  const doc = JSON.parse(readFileSync(file, "utf8"));
  if (!Array.isArray(doc.nodes)) continue;
  test(`${file}: no box overlaps a sibling, and every child fits its box`, () => {
    const { nodes } = toFlow(layoutIfNeeded(doc), palette);
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const groups = {};
    for (const n of nodes) (groups[n.parentId || ""] ||= []).push(n);
    for (const siblings of Object.values(groups)) {
      for (let i = 0; i < siblings.length; i += 1) {
        for (let j = i + 1; j < siblings.length; j += 1) {
          const a = siblings[i];
          const b = siblings[j];
          assert.ok(!overlaps(rect(a), rect(b)),
            `${a.id} ${JSON.stringify(rect(a))} overlaps ${b.id} ${JSON.stringify(rect(b))}`);
        }
      }
    }
    for (const n of nodes) {
      if (!n.parentId) continue;
      const box = rect(byId[n.parentId]);
      const r = rect(n);
      assert.ok(r.x + r.w <= box.w && r.y + r.h <= box.h,
        `${n.id} ${JSON.stringify(r)} spills out of ${n.parentId} ${JSON.stringify(box)}`);
    }
  });
}

test("an empty container keeps a roomy drop target", () => {
  assert.deepStrictEqual(containerSize({}, { width: 220, height: 140 }, false), EMPTY_CONTAINER);
});

test("a filled container with no stored size takes its contents' height", () => {
  assert.deepStrictEqual(containerSize({}, { width: 300, height: 150 }, true),
    { width: 420, height: 150 });
  assert.deepStrictEqual(containerSize({}, { width: 900, height: 150 }, true),
    { width: 900, height: 150 });
});

test("a stored size wins when it is larger than the contents", () => {
  assert.deepStrictEqual(containerSize({ width: 900, height: 500 }, { width: 300, height: 150 }, true),
    { width: 900, height: 500 });
  assert.deepStrictEqual(containerSize({ width: 100, height: 50 }, { width: 300, height: 150 }, true),
    { width: 300, height: 150 });
});

console.log(`canvasLayout: ${passed} passed`);
