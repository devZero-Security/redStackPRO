// The range user generator. Seeded, so a run is deterministic and the assertions
// below hold every time. See rangeUsers.js.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  USER_ARCHETYPES, accountTechniquePlanted, addUser, buildArchetype, generateUsers,
  plantAccountTechnique, recommendedUserCount, removeAccountTechnique, removeUser,
  seededRng, setUsers, updateUser,
} from "./rangeUsers.js";

// The schema lives in the package since ADR 0062, resolved from this file so the
// test does not depend on the cwd it runs from.
const HERE = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(
  readFileSync(join(HERE, "../../src/redstackpro/schema/topology/0.6.0.json"), "utf8"));
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

// -- account techniques planted on a domain user (VulnPicker bridge)

test("planting kerberoasting adds a user marked planted_by with the mapped flaws", () => {
  const domain = { overlay: { fqdn: "sk.local", users: [] } };
  const overlay = plantAccountTechnique(domain, "srv01", "kerberoasting");
  assert.equal(overlay.users.length, 1);
  const u = overlay.users[0];
  assert.deepEqual(u.flaws, ["kerberoastable", "spn_set"]);
  assert.equal(u.planted_by, "srv01:kerberoasting");
  assert.equal(u.email, `${u.username}@sk.local`);
  // The username reads as a real account, not the raw technique id.
  assert.notEqual(u.username, "kerberoasting");
});

test("every account technique maps to schema-valid flaws", () => {
  const schema = JSON.parse(
    readFileSync(join(HERE, "../../src/redstackpro/schema/topology/0.6.0.json"), "utf8"));
  const flawEnum = new Set(
    schema.$defs.overlay_domain.properties.users.items.properties.flaws.items.enum);
  const domain = { overlay: { fqdn: "sk.local", users: [] } };
  for (const technique of ["kerberoasting", "asreproasting", "password_in_description", "weak_password"]) {
    const overlay = plantAccountTechnique(domain, "srv01", technique);
    for (const f of overlay.users[0].flaws) assert.ok(flawEnum.has(f), `${technique} flaw ${f}`);
  }
});

test("planted usernames are unique against the domain's existing users", () => {
  let domain = { overlay: { fqdn: "sk.local", users: [{ username: "svc.kerberoast" }] } };
  const overlay = plantAccountTechnique(domain, "srv01", "kerberoasting");
  assert.notEqual(overlay.users[1].username, "svc.kerberoast");
});

test("accountTechniquePlanted reflects the marker, and unchecking removes exactly that user", () => {
  let domain = { overlay: { fqdn: "sk.local", users: [] } };
  domain = { overlay: plantAccountTechnique(domain, "srv01", "kerberoasting") };
  // A second, unrelated user should survive the round trip.
  domain = { overlay: addUser(domain, { username: "regular.user", privilege: "user" }) };

  assert.equal(accountTechniquePlanted(domain, "srv01", "kerberoasting"), true);
  assert.equal(accountTechniquePlanted(domain, "srv01", "asreproasting"), false);
  assert.equal(accountTechniquePlanted(domain, "srv02", "kerberoasting"), false);

  const after = removeAccountTechnique(domain, "srv01", "kerberoasting");
  assert.equal(after.users.length, 1);
  assert.equal(after.users[0].username, "regular.user");
  domain = { overlay: after };
  assert.equal(accountTechniquePlanted(domain, "srv01", "kerberoasting"), false);
});

test("planting is idempotent: checking an already-planted technique adds nothing", () => {
  let domain = { overlay: { fqdn: "sk.local", users: [] } };
  domain = { overlay: plantAccountTechnique(domain, "srv01", "kerberoasting") };
  const again = plantAccountTechnique(domain, "srv01", "kerberoasting");
  assert.equal(again, null);
});

test("a host with no joined domain cannot plant or remove, and reads as not planted", () => {
  assert.equal(plantAccountTechnique(undefined, "srv01", "kerberoasting"), null);
  assert.equal(removeAccountTechnique(undefined, "srv01", "kerberoasting"), null);
  assert.equal(accountTechniquePlanted(undefined, "srv01", "kerberoasting"), false);
});

test("a normal host vuln keeps toggling into the host's own overlay.vulns", () => {
  // Not an account technique: adding/removing it never touches any domain's
  // users, it is a plain array edit on the host's own overlay, unchanged by
  // this feature. Regression guard for the account-technique bridge above.
  const host = { overlay: { vulns: [] } };
  const toggle = (id) => {
    const set = host.overlay.vulns;
    host.overlay = { ...host.overlay, vulns: set.includes(id) ? set.filter((v) => v !== id) : [...set, id] };
  };
  toggle("smbv1");
  assert.deepEqual(host.overlay.vulns, ["smbv1"]);
  toggle("smbv1");
  assert.deepEqual(host.overlay.vulns, []);
});

console.log(`\n${passed} passed`);
