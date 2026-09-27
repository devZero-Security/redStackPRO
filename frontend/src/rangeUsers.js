// Domain user accounts for a Cyber Range. A user lives on a domain node's
// overlay (overlay_domain.users). A person can add one by hand, give it a
// privilege and misconfigurations, or ask the canvas to populate a realistic
// set so a lab has a believable population to hunt through, not just the two or
// three named accounts an attack path needs. See 0049.
//
// The generator takes an injectable rng so a seeded run is deterministic in
// tests, the same pattern the cover profiles use. In the app it is Math.random.

const FIRST_NAMES = [
  "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
  "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph",
  "Jessica", "Thomas", "Sarah", "Charles", "Karen", "Daniel", "Nancy", "Matthew",
  "Lisa", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley", "Steven",
  "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle", "Kenneth",
  "Carol", "Kevin", "Amanda", "Brian", "Dorothy", "George", "Melissa", "Edward",
  "Deborah", "Ronald", "Stephanie", "Timothy", "Rebecca", "Jason", "Sharon",
  "Jeffrey", "Laura", "Ryan", "Cynthia", "Jacob", "Kathleen",
];

const LAST_NAMES = [
  "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
  "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
  "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
  "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
  "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
  "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
  "Carter", "Roberts",
];

// Business units a member is assigned to. One department group each, so the
// membership reads like a real directory rather than everyone in one bucket.
export const DEPARTMENTS = [
  "IT", "Helpdesk", "Finance", "HR", "Sales", "Engineering",
  "Marketing", "Legal", "Operations", "Executives", "Support", "Facilities",
];

// The flaws the generator may sprinkle on ordinary users, a subset of the schema
// enum that reads as an account-level misconfiguration rather than a host one.
const SPRINKLE_FLAWS = [
  "kerberoastable", "asrep_roastable", "password_in_description",
  "password_never_expires", "weak_password",
];

// A tiny linear-congruential rng seeded from an integer, so a test can pass a
// seed and get the same population every run. Mirrors profiles.js.
export function seededRng(seed) {
  let state = (seed >>> 0) || 1;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

const pick = (rng, list) => list[Math.floor(rng() * list.length)];

function usernameFrom(first, last, taken) {
  const base = `${first}.${last}`.toLowerCase();
  let candidate = base;
  let n = 1;
  while (taken.has(candidate)) candidate = `${base}${(n += 1)}`;
  taken.add(candidate);
  return candidate;
}

// One generated user. Mostly plain members; the caller decides who is an admin
// and who carries a flaw so the mix across a batch is controlled.
function makeUser(rng, fqdn, taken, { privilege = "user", flaws = [] } = {}) {
  const first = pick(rng, FIRST_NAMES);
  const last = pick(rng, LAST_NAMES);
  const username = usernameFrom(first, last, taken);
  const groups = [pick(rng, DEPARTMENTS)];
  if (privilege === "domain_admin" || privilege === "enterprise_admin") {
    groups.push(privilege === "enterprise_admin" ? "Enterprise Admins" : "Domain Admins");
  }
  const user = {
    username,
    display_name: `${first} ${last}`,
    email: `${username}@${fqdn}`,
    groups,
    privilege,
  };
  if (flaws.length) user.flaws = flaws;
  return user;
}

// How many users a range of a given size wants. Small ranges (a handful of
// hosts) get 10 to 20, larger ones 30 to 50, the counts Michael asked for. The
// caller passes the host count; the rng decides where in the band it lands.
export function recommendedUserCount(hostCount, rng = Math.random) {
  const [lo, hi] = hostCount >= 5 ? [30, 50] : [10, 20];
  return lo + Math.floor(rng() * (hi - lo + 1));
}

// Generate a believable population for a domain: one domain admin, a couple of
// flawed accounts that seed an attack path, and the rest ordinary members. The
// usernames are unique within the batch. `existing` seeds the taken set so a
// second populate does not collide with users already on the domain.
export function generateUsers(count, fqdn, rng = Math.random, existing = []) {
  const taken = new Set(existing.map((u) => u.username));
  const users = [];
  const n = Math.max(1, count);
  // Roughly one flawed account per eight users, at least one, capped so a small
  // lab is not all misconfigured.
  const flawed = Math.min(Math.max(1, Math.round(n / 8)), 6);
  for (let i = 0; i < n; i += 1) {
    const privilege = i === 0 ? "domain_admin" : "user";
    const flaws = i > 0 && i <= flawed ? [pick(rng, SPRINKLE_FLAWS)] : [];
    users.push(makeUser(rng, fqdn, taken, { privilege, flaws }));
  }
  return users;
}

// -- user-class archetypes (P2.5)
//
// Ready-made user templates a person drops onto a domain with one click, so a
// custom range gets a low-priv member, an admin, a kerberoastable service
// account, or the assumed-breach foothold without hand-defining every field.
// Each builds on makeUser and pre-fills the same overlay.users fields a person
// could set by hand (privilege, groups, flaws, assumed_breach); the DC role
// derives a workable SPN for a kerberoastable account with no explicit spns.
// See the P2.5 item and rangeUsers above.

function svcUsername(rng, taken) {
  let candidate = `svc_${pick(rng, DEPARTMENTS).toLowerCase()}`;
  let base = candidate;
  let n = 1;
  while (taken.has(candidate)) candidate = `${base}${(n += 1)}`;
  taken.add(candidate);
  return candidate;
}

export const USER_ARCHETYPES = [
  {
    id: "lowpriv",
    label: "Low-priv user",
    blurb: "An ordinary domain member in one business unit. The bulk of a directory.",
    build: (rng, fqdn, taken) => makeUser(rng, fqdn, taken, { privilege: "user" }),
  },
  {
    id: "admin",
    label: "Admin",
    blurb: "A Domain Admins member: an escalation target.",
    build: (rng, fqdn, taken) => makeUser(rng, fqdn, taken, { privilege: "domain_admin" }),
  },
  {
    id: "service",
    label: "Service account",
    blurb: "An SPN-bearing service account, kerberoastable. The DC role derives a workable SPN if none is set.",
    build: (rng, fqdn, taken) => {
      const username = svcUsername(rng, taken);
      return {
        username,
        display_name: username,
        email: `${username}@${fqdn}`,
        groups: ["Service Accounts"],
        privilege: "user",
        flaws: ["kerberoastable"],
      };
    },
  },
  {
    id: "breach",
    label: "Assumed-breach foothold",
    blurb: "The low-priv patient-zero an operator starts from (like GOAD's hodor). Named in the range briefing.",
    build: (rng, fqdn, taken) => {
      const u = makeUser(rng, fqdn, taken, { privilege: "user" });
      u.assumed_breach = true;
      return u;
    },
  },
];

// Build one archetype user for a domain, unique against the users already there.
export function buildArchetype(id, fqdn, existing = [], rng = Math.random) {
  const arch = USER_ARCHETYPES.find((a) => a.id === id);
  if (!arch) return null;
  const taken = new Set(existing.map((u) => u.username));
  return arch.build(rng, fqdn, taken);
}

// -- pure edits on a domain node's overlay.users

const usersOf = (node) => (node.overlay && node.overlay.users) || [];

export function addUser(node, user) {
  return { ...node.overlay, users: [...usersOf(node), user] };
}

export function updateUser(node, index, patch) {
  const users = usersOf(node).map((u, i) => (i === index ? { ...u, ...patch } : u));
  return { ...node.overlay, users };
}

export function removeUser(node, index) {
  return { ...node.overlay, users: usersOf(node).filter((_, i) => i !== index) };
}

export function setUsers(node, users) {
  return { ...node.overlay, users };
}

// -- account techniques planted on a domain user (host VulnPicker bridge)
//
// kerberoasting, asreproasting, password_in_description, and weak_password
// (vulns.js ACCOUNT_TECHNIQUE_IDS) are account flaws, not host tasks: checking
// one on a host used to write into overlay.vulns and no-op there (RNG009).
// Instead the host's VulnPicker plants ONE domain user, on the host's joined
// domain, carrying the matching flaws, so the technique actually runs.
// Unchecking removes exactly that user. The marker lives in a `planted_by`
// field on the user ("<hostId>:<technique>"), so the same host+technique pair
// can be found and removed again without touching any other user on the
// domain. See vulns.js and Inspector.jsx VulnPicker.

const ACCOUNT_TECHNIQUE_FLAWS = {
  kerberoasting: ["kerberoastable", "spn_set"],
  asreproasting: ["asrep_roastable"],
  password_in_description: ["password_in_description"],
  weak_password: ["weak_password"],
};

// A readable base username per technique, so the planted account reads like a
// real one rather than a raw technique id.
const ACCOUNT_TECHNIQUE_USERNAME = {
  kerberoasting: "svc.kerberoast",
  asreproasting: "roastme",
  password_in_description: "svc.helpdesk",
  weak_password: "svc.backup",
};

const plantedByOf = (hostId, technique) => `${hostId}:${technique}`;

// Whether a user marked for this host+technique already exists on the domain.
// A missing domainNode (the host is not joined to any domain) is never
// planted.
export function accountTechniquePlanted(domainNode, hostId, technique) {
  if (!domainNode) return false;
  const marker = plantedByOf(hostId, technique);
  return usersOf(domainNode).some((u) => u.planted_by === marker);
}

// Add the one domain user this technique needs, unique against the domain's
// existing usernames. Returns the domain's updated overlay, or null when
// there is no domain to plant on, the technique is unknown, or it is already
// planted (idempotent: a caller does not need to check first).
export function plantAccountTechnique(domainNode, hostId, technique) {
  if (!domainNode) return null;
  const flaws = ACCOUNT_TECHNIQUE_FLAWS[technique];
  if (!flaws) return null;
  if (accountTechniquePlanted(domainNode, hostId, technique)) return null;

  const fqdn = (domainNode.overlay || {}).fqdn || "example.local";
  const taken = new Set(usersOf(domainNode).map((u) => u.username));
  const base = ACCOUNT_TECHNIQUE_USERNAME[technique] || technique;
  let username = base;
  let n = 1;
  while (taken.has(username)) username = `${base}${(n += 1)}`;

  return addUser(domainNode, {
    username,
    email: `${username}@${fqdn}`,
    privilege: "user",
    flaws,
    planted_by: plantedByOf(hostId, technique),
  });
}

// Remove the user marked for this host+technique, if any. Returns the
// domain's updated overlay, or null when there is no domain or no such user.
export function removeAccountTechnique(domainNode, hostId, technique) {
  if (!domainNode) return null;
  const marker = plantedByOf(hostId, technique);
  const index = usersOf(domainNode).findIndex((u) => u.planted_by === marker);
  if (index === -1) return null;
  return removeUser(domainNode, index);
}
