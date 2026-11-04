// What a drawn line can be between two node kinds, and how each role reads to
// a person. The endpoint table mirrors the drawn roles in the registry's
// roles.yaml; tests/test_canvas_widgets_sync.py fails when the two drift.
// `manages`, `attached` and `joins` are not drawn lines, so they are not
// offered here.

// Kinds with category host in the registry. A "host" endpoint matches any.
export const HOST_KINDS = ["appliance", "collector", "dc", "fw", "jumpbox", "operator", "redirector", "siem", "srv", "teamserver", "wks"];

// One [source, target] pair per line, the way roles.yaml lists endpoints.
export const ROLE_ENDPOINTS = {
  fronts: [["redirector", "teamserver"]],
  logs_to: [["host", "collector"]],
  peers: [["network", "network"]],
  trusts: [["domain", "domain"]],
};

// Peering and trusts are one edge either way round, so they are offered once
// per pair rather than once per direction.
const SYMMETRIC = new Set(["peers", "trusts"]);

export const ROLE_TEXT = {
  fronts: {
    title: "C2 route",
    to: "C2 route to",
    from: "C2 route from",
    verb: "routes C2 to",
    about: "The redirector forwards beacon traffic that matches the URI prefix to this teamserver.",
  },
  logs_to: {
    title: "Ships logs to",
    to: "Ships logs to",
    from: "Receives logs from",
    verb: "ships logs to",
    about: "The source ships its logs to this collector.",
  },
  peers: {
    title: "Peered with",
    to: "Peered with",
    from: "Peered with",
    verb: "is peered with",
    about: "The two networks are peered, so their hosts reach each other on private addresses.",
  },
  trusts: {
    title: "Trusts",
    to: "Trusts",
    from: "Trusted by",
    verb: "trusts",
    about: "An Active Directory trust between the two domains.",
  },
  attached: { title: "Attached to", to: "Attached to", from: "Holds", verb: "is attached to" },
  joins: { title: "Joins", to: "Joins", from: "Joined by", verb: "joins" },
  manages: { title: "Manages", to: "Manages", from: "Managed by", verb: "manages" },
};

export function roleTitle(role) {
  return ROLE_TEXT[role]?.title || role;
}

const matches = (want, kind) =>
  want === kind || (want === "host" && HOST_KINDS.includes(kind));

// The drawn roles a line from sourceKind to targetKind may carry.
export function rolesFor(sourceKind, targetKind) {
  return Object.keys(ROLE_ENDPOINTS).filter((role) =>
    ROLE_ENDPOINTS[role].some(([s, t]) => matches(s, sourceKind) && matches(t, targetKind))
  );
}

// The rendered name, prefix plus id, the same as the Inspector heading.
export function nodeName(document, id) {
  return document?.prefix ? `${document.prefix}-${id}` : id;
}

const fqdnOf = (document, id) =>
  (document.nodes.find((n) => n.id === id)?.overlay?.fqdn || "").toLowerCase();

// For two domains, which is the parent: the one the other's FQDN ends with
// after a dot (north.sevenkingdoms.local is a child of sevenkingdoms.local).
// Null when neither FQDN says so or one is missing.
export function parentChild(document, a, b) {
  const fa = fqdnOf(document, a);
  const fb = fqdnOf(document, b);
  if (!fa || !fb) return null;
  if (fa.endsWith(`.${fb}`)) return { parent: b, child: a };
  if (fb.endsWith(`.${fa}`)) return { parent: a, child: b };
  return null;
}

// The trust type a trusts edge gets when it has none: parent_child when one
// FQDN sits under the other, else forest. The compiler applies the same rule
// to an untyped edge. For parent_child the parent becomes the source, because
// the compiler reads the source as the parent. Null until both FQDNs are set,
// so a fresh pair of domains is not locked to forest before they are named.
export function defaultTrustPatch(document, edge) {
  if (fqdnOf(document, edge.source) === "" || fqdnOf(document, edge.target) === "") {
    return null;
  }
  const pc = parentChild(document, edge.source, edge.target);
  if (!pc) return { trust_type: "forest" };
  const patch = { trust_type: "parent_child" };
  if (pc.parent !== edge.source) {
    patch.source = pc.parent;
    patch.target = pc.child;
  }
  return patch;
}

function edgeExists(document, role, source, target) {
  return document.edges.some(
    (e) =>
      e.role === role &&
      ((e.source === source && e.target === target) ||
        (SYMMETRIC.has(role) && e.source === target && e.target === source))
  );
}

// The lines that could join `node` and `other`, in either direction, minus the
// ones already drawn. Each is { role, source, target }.
export function connectOptions(document, node, other) {
  const out = [];
  const seen = new Set();
  const consider = (source, target) => {
    for (const role of rolesFor(source.kind, target.kind)) {
      const key = SYMMETRIC.has(role) ? role : `${role}:${source.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      let s = source.id;
      let t = target.id;
      if (role === "trusts") {
        const pc = parentChild(document, s, t);
        if (pc) {
          s = pc.parent;
          t = pc.child;
        }
      }
      if (!edgeExists(document, role, s, t)) out.push({ role, source: s, target: t });
    }
  };
  consider(node, other);
  consider(other, node);
  return out;
}

export function optionSentence(document, option) {
  const verb = ROLE_TEXT[option.role]?.verb || option.role;
  return `${nodeName(document, option.source)} ${verb} ${nodeName(document, option.target)}`;
}
