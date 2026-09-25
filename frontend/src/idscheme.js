// The default id scheme, mirrored from src/redstackpro/idscheme.py so the canvas
// proposes the same ids the backend and the fixtures use. A node's id is a
// purpose slug, the kind tag, and a two digit ordinal: myth-ts01, main-net01,
// c2-sub01. The slug is derived from what the node is and what it holds, so
// re-purposing a node renames it; the tag is fixed per kind and is what a rule
// keys on. See 0016.
//
// retitle() is the live half: it renames the nodes the person has not renamed
// by hand and cascades the change through edges. A node the person renamed is
// pinned and left alone. idscheme.test.mjs pins these maps to the Python copy in
// spirit; test_idscheme.py pins the Python copy to the registry.

export const KIND_TAG = {
  network: "net",
  segment: "sub",
  teamserver: "ts",
  operator: "op",
  jumpbox: "bx",
  redirector: "rd",
  collector: "log",
  // range mode (0047)
  domain: "dom",
  dc: "dc",
  srv: "srv",
  wks: "wks",
  fw: "fw",
  siem: "siem",
  appliance: "appl",
};

// host kind -> [overlay field the subtype reads, value -> slug]
export const SUBTYPE = {
  teamserver: ["c2", { mythic: "myth", sliver: "sliv", adaptix: "adpx", cobalt_strike: "cs" }],
  operator: ["os", { windows: "win", kali: "kali", debian: "deb" }],
  redirector: ["server", { nginx: "nginx", apache: "apache" }],
  collector: ["sink", { opensearch: "open", elasticsearch: "elk", splunk: "splk" }],
  // range mode: a member server reads its role and a SIEM its product, so a
  // dropped host names itself like a Red Infra box (sql-srv01, wazuh-siem01).
  srv: ["role", { sql: "sql", web: "web", fileshare: "file", adcs: "adcs" }],
  siem: ["product", { wazuh: "wazuh", elk: "elk", splunk: "splk" }],
};
export const JUMPBOX_SLUG = "jump";

// host kind -> the family that decides the purpose of the container holding it.
export const FAMILY = {
  redirector: "rdir",
  teamserver: "c2",
  jumpbox: "mgmt",
  operator: "mgmt",
  collector: "mgmt",
};
// When a container holds more than one family, the most sensitive wins.
export const FAMILY_ORDER = ["mgmt", "c2", "rdir"];

// family -> slug, per container kind. A network with any management is "main";
// the same family names a subnet "mgmt".
export const NETWORK_PURPOSE = { mgmt: "main", c2: "c2", rdir: "rdir" };
export const SEGMENT_PURPOSE = { mgmt: "mgmt", c2: "c2", rdir: "rdir" };

export function hostSlug(node) {
  if (node.kind === "jumpbox") return JUMPBOX_SLUG;
  const entry = SUBTYPE[node.kind];
  if (!entry) return "";
  const [field, table] = entry;
  return table[node.overlay?.[field]] || "";
}

function dominant(families) {
  for (const fam of FAMILY_ORDER) if (families.has(fam)) return fam;
  return null;
}

export function containerSlug(kind, families) {
  const fam = dominant(families);
  if (!fam) return "";
  return (kind === "network" ? NETWORK_PURPOSE : SEGMENT_PURPOSE)[fam];
}

// -- id parsing. An id is <slug>-<tag><ordinal>, the slug optional.

const TRAILING = /(\d+)$/;
const tail = (id) => id.split("-").pop();
export const abbrevOf = (id) => tail(id).replace(TRAILING, "");
export const ordinalOf = (id) => (TRAILING.exec(tail(id)) || ["", ""])[1];
export const slugOf = (id) => (id.includes("-") ? id.slice(0, id.lastIndexOf("-")) : "");

export function composeId(slug, tag, ordinal) {
  const core = `${tag}${String(ordinal).padStart(2, "0")}`;
  return slug ? `${slug}-${core}` : core;
}

export function edgeId(source, target, role) {
  return `e-${source}-${target}-${role}`.replace(/_/g, "-");
}

// Families rolled up to the segment that holds each host, then to the network
// that holds each segment.
function families(nodes, parent) {
  const seg = {};
  const net = {};
  for (const node of nodes) {
    const fam = FAMILY[node.kind];
    if (!fam) continue;
    const holder = parent[node.id];
    if (holder) (seg[holder] ||= new Set()).add(fam);
  }
  for (const [segId, fams] of Object.entries(seg)) {
    const holder = parent[segId];
    if (holder) {
      const set = (net[holder] ||= new Set());
      for (const f of fams) set.add(f);
    }
  }
  return { seg, net };
}

export function desiredSlug(node, segFam, netFam) {
  if (node.kind === "network") return containerSlug("network", netFam[node.id] || new Set());
  if (node.kind === "segment") return containerSlug("segment", segFam[node.id] || new Set());
  return hostSlug(node);
}

// The id the scheme would give a node placed in this document. Used when a node
// is added so the seed carries a meaningful id straight away.
export function proposeId(document, node) {
  const parent = {};
  for (const e of document.edges) if (e.role === "attached") parent[e.source] = e.target;
  const { seg, net } = families(document.nodes, parent);
  const tag = KIND_TAG[node.kind];
  const slug = desiredSlug(node, seg, net);
  const used = new Set(document.nodes.map((n) => n.id));
  let ord = 1;
  let candidate = composeId(slug, tag, ord);
  while (used.has(candidate)) candidate = composeId(slug, tag, (ord += 1));
  return candidate;
}

// Rename every node the person has not pinned onto the scheme, and cascade the
// rename through edge endpoints and ids. A node whose id already reads as its
// current slug and tag keeps its ordinal, so a stable node's number never shifts
// when a sibling is added or removed. Returns the possibly unchanged document
// and the map of ids that moved, so the caller can follow the selection.
export function retitle(document, pinned = new Set()) {
  const { nodes, edges } = document;
  const parent = {};
  for (const e of edges) if (e.role === "attached") parent[e.source] = e.target;
  const { seg, net } = families(nodes, parent);

  const used = new Set(nodes.map((n) => n.id));
  const renamed = {};

  for (const node of nodes) {
    // Pinned either in this session (the ref) or persisted on the node from a
    // prior one, so a hand-renamed id survives a reload. See 0043.
    if (pinned.has(node.id) || node.pinned) continue;
    const tag = KIND_TAG[node.kind];
    if (!tag) continue;
    const slug = desiredSlug(node, seg, net);
    if (slugOf(node.id) === slug && abbrevOf(node.id) === tag && ordinalOf(node.id).length === 2) {
      continue;
    }
    let ord = 1;
    let candidate = composeId(slug, tag, ord);
    while (used.has(candidate)) candidate = composeId(slug, tag, (ord += 1));
    used.delete(node.id);
    used.add(candidate);
    renamed[node.id] = candidate;
  }

  if (Object.keys(renamed).length === 0) return { document, renamed };

  const remap = (id) => renamed[id] || id;
  const next = {
    ...document,
    nodes: nodes.map((n) => (renamed[n.id] ? { ...n, id: renamed[n.id] } : n)),
    edges: edges.map((e) => {
      if (!renamed[e.source] && !renamed[e.target]) return e;
      const source = remap(e.source);
      const target = remap(e.target);
      return { ...e, source, target, id: edgeId(source, target, e.role) };
    }),
  };
  return { document: next, renamed };
}
