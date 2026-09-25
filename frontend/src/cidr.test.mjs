import assert from "node:assert";
import { allocNetworkCidr, allocSegmentCidr, cidrWithin } from "./cidr.js";

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

const doc = (cidrs) => ({
  nodes: cidrs.map(([id, kind, cidr]) => ({ id, kind, overlay: { cidr } })),
  edges: [],
});

test("the first network takes 10.10.0.0/16", () => {
  assert.equal(allocNetworkCidr(doc([])), "10.10.0.0/16");
});

test("a second network skips the first and any hand chosen range", () => {
  assert.equal(allocNetworkCidr(doc([["n1", "network", "10.10.0.0/16"]])), "10.20.0.0/16");
  // an existing 10.30 is stepped over, not collided with
  assert.equal(
    allocNetworkCidr(doc([["n1", "network", "10.30.0.0/16"]])),
    "10.10.0.0/16"
  );
  assert.equal(
    allocNetworkCidr(doc([
      ["n1", "network", "10.10.0.0/16"],
      ["n2", "network", "10.20.0.0/16"],
    ])),
    "10.30.0.0/16"
  );
});

test("a subnet carves a /24 inside its network", () => {
  const d = doc([["n1", "network", "10.20.0.0/16"]]);
  assert.equal(allocSegmentCidr(d, "n1"), "10.20.0.0/24");
});

test("a second subnet takes the next /24 in the same network", () => {
  const d = doc([
    ["n1", "network", "10.20.0.0/16"],
    ["s1", "segment", "10.20.0.0/24"],
  ]);
  assert.equal(allocSegmentCidr(d, "n1"), "10.20.1.0/24");
});

test("a custom base_cidr moves allocation into that block", () => {
  const d = { base_cidr: "172.16.0.0/12", nodes: [], edges: [] };
  const first = allocNetworkCidr(d);
  assert.match(first, /^172\.\d+\.0\.0\/16$/, first);
  // and it stays inside 172.16.0.0/12
  const second = allocNetworkCidr({ ...d, nodes: [{ id: "n", kind: "network", overlay: { cidr: first } }] });
  assert.notEqual(second, first);
  assert.match(second, /^172\.\d+\.0\.0\/16$/, second);
});

test("cidrWithin knows a subnet from a foreign range", () => {
  assert.ok(cidrWithin("10.20.5.0/24", "10.20.0.0/16"));
  assert.ok(!cidrWithin("10.30.5.0/24", "10.20.0.0/16"));
  assert.ok(!cidrWithin("nonsense", "10.20.0.0/16"));
});

console.log(`\n${passed} passed`);
