// The range user generator. Seeded, so a run is deterministic and the assertions
// below hold every time. See rangeUsers.js.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  USER_ARCHETYPES, addUser, buildArchetype, generateUsers, recommendedUserCount,
  removeUser, seededRng, setUsers, updateUser,
} from "./rangeUsers.js";

// The schema lives in the package since ADR 0062, resolved from this file so the
// test does not depend on the cwd it runs from.
const HERE = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(
  readFileSync(join(HERE, "../../src/redstackpro/schema/topology/0.5.0.json"), "utf8"));
const USER_SCHEMA = schema.$defs.overlay_domain.properties.users.items;
const PRIVILEGES = new Set(USER_SCHEMA.properties.privilege.enum);
const FLAWS = new Set(USER_SCHEMA.properties.flaws.items.enum);

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

test("generates the requested count", () => {
  const users = generateUsers(15, "sk.local", seededRng(1));
  assert.equal(users.length, 15);
});

test("usernames are unique and emails derive from the fqdn", () => {
  const users = generateUsers(40, "corp.local", seededRng(7));
  const names = users.map((u) => u.username);
  assert.equal(new Set(names).size, names.length);
  for (const u of users) assert.equal(u.email, `${u.username}@corp.local`);
});

test("a batch has exactly one domain admin, in Domain Admins", () => {
  const users = generateUsers(20, "sk.local", seededRng(3));
  const das = users.filter((u) => u.privilege === "domain_admin");
  assert.equal(das.length, 1);
  assert.ok(das[0].groups.includes("Domain Admins"));
});

test("every privilege and flaw is a schema enum value", () => {
  const users = generateUsers(50, "sk.local", seededRng(9));
  for (const u of users) {
    assert.ok(PRIVILEGES.has(u.privilege), u.privilege);
    for (const f of u.flaws || []) assert.ok(FLAWS.has(f), f);
  }
});

test("a second populate does not collide with existing usernames", () => {
  const first = generateUsers(20, "sk.local", seededRng(2));
  const more = generateUsers(20, "sk.local", seededRng(2), first);
  const all = [...first, ...more].map((u) => u.username);
  assert.equal(new Set(all).size, all.length);
});

test("the seed makes generation deterministic", () => {
  assert.deepEqual(
    generateUsers(12, "sk.local", seededRng(42)),
    generateUsers(12, "sk.local", seededRng(42))
  );
});

test("recommended count scales with range size", () => {
  const lo = seededRng(1);
  const small = recommendedUserCount(3, lo);
  assert.ok(small >= 10 && small <= 20, small);
  const big = recommendedUserCount(9, seededRng(1));
  assert.ok(big >= 30 && big <= 50, big);
});

test("add, update, and remove edit the overlay users purely", () => {
  const node = { overlay: { fqdn: "sk.local", users: [] } };
  const o1 = addUser(node, { username: "a.one", privilege: "user" });
  assert.equal(o1.users.length, 1);
  const n1 = { overlay: o1 };
  const o2 = updateUser(n1, 0, { privilege: "domain_admin" });
  assert.equal(o2.users[0].privilege, "domain_admin");
  assert.equal(o2.users[0].username, "a.one");        // patch, not replace
  const o3 = removeUser({ overlay: o2 }, 0);
  assert.equal(o3.users.length, 0);
  // The originals are untouched.
  assert.equal(node.overlay.users.length, 0);
  assert.equal(o1.users.length, 1);
});

test("setUsers replaces the whole list", () => {
  const node = { overlay: { fqdn: "sk.local", users: [{ username: "old" }] } };
  const o = setUsers(node, [{ username: "new" }]);
  assert.equal(o.users.length, 1);
  assert.equal(o.users[0].username, "new");
});

test("each archetype builds a schema-valid user", () => {
  const allowed = new Set(Object.keys(USER_SCHEMA.properties));
  for (const a of USER_ARCHETYPES) {
    const u = buildArchetype(a.id, "sk.local", [], seededRng(3));
    assert.ok(u && u.username, a.id);
    for (const k of Object.keys(u)) assert.ok(allowed.has(k), `${a.id} field ${k} not in schema`);
    if (u.privilege) assert.ok(PRIVILEGES.has(u.privilege), a.id);
    for (const f of (u.flaws || [])) assert.ok(FLAWS.has(f), `${a.id} flaw ${f}`);
  }
});

test("the archetypes carry their defining traits", () => {
  const at = (id) => buildArchetype(id, "sk.local", [], seededRng(4));
  assert.equal(at("admin").privilege, "domain_admin");
  assert.deepEqual(at("service").flaws, ["kerberoastable"]);
  assert.equal(at("breach").assumed_breach, true);
  assert.equal(at("lowpriv").privilege, "user");
});

test("archetype names are unique against existing users", () => {
  const first = buildArchetype("service", "sk.local", [], seededRng(5));
  const next = buildArchetype("service", "sk.local", [first], seededRng(5));
  assert.notEqual(next.username, first.username);
});

console.log(`\n${passed} passed`);
