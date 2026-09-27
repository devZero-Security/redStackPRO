// Conversion between a redStackPRO document and what React Flow draws.
//
// The topology is the product and the canvas is a view onto it, so this file is
// the only place that knows about both. Everything else works on one or the
// other. See architecture.md.
//
// Containment is drawn as nesting rather than as lines: a host inside a segment
// box is an `attached` edge, a segment inside a network box is another. That
// keeps the canvas readable, because attachment is most of the edges in any
// real topology and drawing them all would bury the relationships that matter.

import { HOST } from "./layout.js";
import { proposeId, edgeId } from "./idscheme.js";
import { allocNetworkCidr, allocSegmentCidr, cidrWithin } from "./cidr.js";

const CONTAINERS = ["network", "segment", "domain"];
// Domain-member hosts: they nest in a domain via a joins edge.
const RANGE_HOSTS = ["dc", "srv", "wks", "fw"];
// Boxes that live on a range but are not domain members: the operator jumpbox
// and the standalone Linux appliances (SIEM, Guacamole). They nest in the
// subnet they attach to rather than in a domain. See the GOAD extensions.
const RANGE_STANDALONE = ["siem", "appliance", "jumpbox"];
const RANGE_MACHINES = [...RANGE_HOSTS, ...RANGE_STANDALONE];

// The extra height a host gains for the manages annotation row.
const MANAGES_ROW = 22;
// The extra height a host gains for the badge row (EDR, vulns, hardening, public).
const BADGE_ROW = 20;

// The count form of a manages annotation: how many of each kind a node governs,
// so a jumpbox reads "manages 2 networks" rather than a truncated name list. The
// full names stay in the chip's tooltip. Subnets read as "subnet", the word the
// canvas uses for a segment.
const MANAGES_NOUN = { network: "network", segment: "subnet" };
function managesSummary(targetIds, byId) {
  const counts = {};
  for (const id of targetIds) {
    const kind = byId[id]?.kind || "node";
    counts[kind] = (counts[kind] || 0) + 1;
  }
  return Object.entries(counts)
    .map(([kind, n]) => `${n} ${MANAGES_NOUN[kind] || kind}${n === 1 ? "" : "s"}`)
    .join(", ");
}

export const isContainer = (kind) => CONTAINERS.includes(kind);

// A range host nests one level deeper than any other kind: it joins a domain
// (or stands alone in a subnet), where everything else attaches straight to
// its container. The canvas drag handler needs this to know a domain is a
// valid drop target for one of these and not for a jumpbox or a SIEM box.
export const isRangeHost = (kind) => RANGE_HOSTS.includes(kind);

// Roles that are drawn as lines. Attachment is nesting, so it is not here.
// Peering is drawn, network to network, so two peered networks read as joined
// rather than as two boxes that happen to sit near each other. `manages` is not
// a line: a line into a container box reads as piercing territory and forces the
// jumpbox line through other boxes. It shows instead as an annotation on the
// jumpbox that names what it governs. See managesFrom below.
export const DRAWN_ROLES = ["fronts", "logs_to", "peers", "trusts"];

const ROLE_COLOR = {
  fronts: "#f59f00",
  logs_to: "#9c36b5",
  manages: "#1c7ed6",
  peers: "#0ca678",
  joins: "#4dabf7",
  trusts: "#b197fc",
};

// A drawn line's role follows from what it connects, so the canvas never asks.
// The endpoint rules live in the registry; this mirrors the drawn subset.
export function inferRole(sourceKind, targetKind) {
  if (sourceKind === "redirector" && targetKind === "teamserver") return "fronts";
  if (targetKind === "collector") return "logs_to";
  if (sourceKind === "jumpbox" && isContainer(targetKind)) return "manages";
  if (sourceKind === "domain" && targetKind === "domain") return "trusts";
  if (RANGE_HOSTS.includes(sourceKind) && targetKind === "domain") return "joins";
  return null;
}

export function roleColor(role) {
  return ROLE_COLOR[role] || "#868e96";
}

// How a role reads to a person. The schema keeps `fronts`, but on the canvas
// that line is the one carrying URI prefixes, so it shows as "URIs".
const ROLE_DISPLAY = { fronts: "URIs" };
export function roleDisplay(role) {
  return ROLE_DISPLAY[role] || role;
}

// A trust reads differently by type: parent-child and tree-root stay inside a
// forest, external and forest cross between forests. The forest boundary is not
// drawn as a box; it reads off the trust lines, which are coloured and dashed by
// type. See 0047.
const TRUST_INTRA = ["parent_child", "tree_root"];
export const trustIsIntra = (trustType) => TRUST_INTRA.includes(trustType);
export const trustColor = (trustType) => (trustIsIntra(trustType) ? "#b197fc" : "#ff922b");

// The legend entries for a document: the drawn roles present, with trusts split
// into the intra-forest and cross-forest kinds actually in the topology.
export function legendItems(document) {
  const items = [];
  for (const role of DRAWN_ROLES) {
    if (role === "trusts") continue;
    if (document.edges.some((e) => e.role === role)) {
      items.push({ key: role, color: roleColor(role), label: roleDisplay(role) });
    }
  }
  const trusts = document.edges.filter((e) => e.role === "trusts");
  if (trusts.some((e) => trustIsIntra(e.trust_type))) {
    items.push({ key: "trust-intra", color: trustColor("parent_child"), label: "intra-forest trust" });
  }
  if (trusts.some((e) => !trustIsIntra(e.trust_type))) {
    items.push({ key: "trust-cross", color: trustColor("external"), label: "cross-forest trust" });
  }
  return items;
}

// The word a line would read as if labelled. A `fronts` edge carries the URI
// prefix it serves; every other role reads as its own name. The canvas draws no
// label at rest now, but the connection list in the inspector uses this.
export function edgeLabel(edge) {
  return edge.role === "fronts" ? edge.uri_prefix || "fronts" : edge.role;
}

// A canvas mirror of ADR 0021: a segment's exposure is a ceiling and each host
// says whether it takes a public address, defaulting to true for a jumpbox and a
// redirector and false for everything else. The compiler owns the authoritative
// version; this only lights the badge so a host reachable from the internet is
// visible without opening the inspector. Kept in step with the per kind defaults
// in the schema and PUBLIC_BY_DEFAULT in the backend.
const PUBLIC_BY_DEFAULT = new Set(["jumpbox", "redirector"]);

export function isPubliclyReachable(host, segment) {
  if (!host || isContainer(host.kind)) return false;
  if (segment?.overlay?.exposure !== "internet") return false;
  const want = host.overlay?.public_address;
  return want === undefined ? PUBLIC_BY_DEFAULT.has(host.kind) : Boolean(want);
}

// -- document to flow

export function toFlow(document, palette) {
  const byId = Object.fromEntries(document.nodes.map((n) => [n.id, n]));
  const kinds = Object.fromEntries(
    Object.values(palette || {})
      .flat()
      .map((entry) => [entry.kind, entry])
  );

  // A lone network is mostly chrome: the boundary only carries meaning once there
  // are two and a peering runs between them. With one, it is drawn quiet so the
  // subnets and hosts read first. See 0042.
  const soloNetwork = document.nodes.filter((n) => n.kind === "network").length === 1;

  // Containment is drawn as nesting. Ops is the attachment chain, host to subnet
  // to network. Range adds a domain layer inside it: network to subnet to domain
  // to machine. A machine nests in its domain (joins edge), a domain in the
  // subnet its machines sit in, and the subnet in its network. See 0047.
  const isRange = document.mode === "haven";
  const parentOf = {};
  if (isRange) {
    const attachOf = {};
    for (const edge of document.edges) {
      if (edge.role === "attached") attachOf[edge.source] = edge.target;
    }
    for (const edge of document.edges) {
      if (edge.role === "joins") parentOf[edge.source] = edge.target; // machine -> domain
    }
    for (const [id, target] of Object.entries(attachOf)) {
      if (byId[id]?.kind === "segment") parentOf[id] = target; // subnet -> network
    }
    for (const edge of document.edges) {
      if (edge.role !== "joins") continue;
      const subnet = attachOf[edge.source];
      if (subnet && byId[subnet]?.kind === "segment" && !parentOf[edge.target]) {
        parentOf[edge.target] = subnet; // domain -> the subnet holding its machines
      }
    }
    // A range box that is not a domain member, the operator jumpbox, a SIEM, an
    // appliance, or an unjoined server, nests in the subnet it attaches to
    // rather than floating loose on the canvas.
    for (const [id, target] of Object.entries(attachOf)) {
      if (!parentOf[id] && RANGE_MACHINES.includes(byId[id]?.kind)
          && byId[target]?.kind === "segment") {
        parentOf[id] = target;
      }
    }
  } else {
    for (const edge of document.edges) {
      if (edge.role === "attached") parentOf[edge.source] = edge.target;
    }
  }

  // What each node manages, listed as an annotation on the node rather than
  // drawn as a line. Includes the container the jumpbox sits in, which the line
  // form had to hide as a loop; as text it is useful, not noise.
  const managesFrom = {};
  for (const edge of document.edges) {
    if (edge.role !== "manages") continue;
    (managesFrom[edge.source] ||= []).push(edge.target);
  }

  // A host that carries a manages annotation or a badge row (EDR, planted vulns,
  // hardening, a public address) is taller so those rows sit inside the card
  // rather than spilling past its border. Kept in one place so the container fit
  // below reserves the same height and never crops it.
  const hostHasBadges = (node) =>
    isPubliclyReachable(node, byId[parentOf[node.id]])
    || (node.overlay?.edr && node.overlay.edr !== "none")
    || (node.overlay?.vulns || []).length > 0
    || (node.overlay?.hardening || []).length > 0;
  const hostHeight = (node) =>
    HOST.height
    + (managesFrom[node.id]?.length ? MANAGES_ROW : 0)
    + (hostHasBadges(node) ? BADGE_ROW : 0);

  // Whether one node encloses another, walking the attachment chain up.
  const encloses = (ancestorId, nodeId) => {
    let current = parentOf[nodeId];
    while (current) {
      if (current === ancestorId) return true;
      current = parentOf[current];
    }
    return false;
  };

  // Containers first: React Flow requires a parent to precede its children. In
  // range the domains are the containers and the network/subnet are not drawn;
  // in ops it is the network/subnet chain.
  const ordered = isRange
    ? [
        ...document.nodes.filter((n) => n.kind === "network"),
        ...document.nodes.filter((n) => n.kind === "segment"),
        ...document.nodes.filter((n) => n.kind === "domain"),
        ...document.nodes.filter((n) => RANGE_MACHINES.includes(n.kind)),
      ]
    : [
        ...document.nodes.filter((n) => n.kind === "network"),
        ...document.nodes.filter((n) => n.kind === "segment"),
        ...document.nodes.filter((n) => !isContainer(n.kind)),
      ];

  const Z = { network: 0, segment: 1 };

  // The smallest a container can be and still hold everything inside it: the far
  // corner of its lowest, rightmost child plus a margin. A resize is floored at
  // this and the drawn box never renders below it, so a subnet can be made
  // bigger by hand but a child is never cropped out the bottom the way a second
  // collector was. See issue: resize subnets and networks as needed.
  const FIT_MARGIN = 16;
  const fitFor = {};
  // Deepest containers first: a subnet is sized to hold its hosts before the
  // network that holds it is sized, so the network can grow to the subnet's
  // real rendered size rather than its stored width. Without this a wide subnet
  // (four hosts in a row) overflows the network's border.
  const containersByDepth = [
    ...ordered.filter((n) => n.kind === "domain"),
    ...ordered.filter((n) => n.kind === "segment"),
    ...ordered.filter((n) => n.kind === "network"),
  ];
  for (const node of containersByDepth) {
    let w = 0;
    let h = 0;
    for (const child of ordered) {
      if (parentOf[child.id] !== node.id) continue;
      const baseW = child.width || (isContainer(child.kind) ? 360 : HOST.width);
      const baseH = child.height || (isContainer(child.kind) ? 200 : hostHeight(child));
      // A child container renders at least as large as its own fit, so measure
      // that effective size, not the stored width the parent would undershoot.
      const cw = Math.max(baseW, fitFor[child.id]?.width || 0);
      const ch = Math.max(baseH, fitFor[child.id]?.height || 0);
      w = Math.max(w, (child.position?.x || 0) + cw);
      h = Math.max(h, (child.position?.y || 0) + ch);
    }
    fitFor[node.id] = w
      ? { width: Math.round(w + FIT_MARGIN), height: Math.round(h + FIT_MARGIN) }
      : { width: 220, height: 140 };
  }

  const nodes = ordered.map((node) => {
    // Fallback guards a container that slipped past the fit loop, so a missing
    // fit can never blank the canvas.
    const fit = fitFor[node.id] || { width: 220, height: 140 };
    return {
      id: node.id,
      type: isContainer(node.kind) ? "container" : "host",
      position: node.position || { x: 0, y: 0 },
      parentId: parentOf[node.id],
      extent: parentOf[node.id] ? "parent" : undefined,
      // A container is picked up by its header. Dragging from anywhere inside it
      // would mean a click meant for a host moves the box it sits in.
      dragHandle: isContainer(node.kind) ? ".rg-container-head" : undefined,
      zIndex: Z[node.kind] ?? 3,
      style: isContainer(node.kind)
        ? {
            width: Math.max(node.width || 420, fit.width),
            height: Math.max(node.height || 260, fit.height),
          }
        : { width: HOST.width, height: hostHeight(node) },
      data: {
        node,
        fit,
        display: kinds[node.kind] || { label: node.kind, color: "#868e96" },
        // Range templates keep their canonical GOAD names, so the prefix is not
        // composed onto them; ops names are prefix plus id. See 0047.
        name: document.mode === "haven" ? node.id : `${document.prefix}-${node.id}`,
        public: isPubliclyReachable(node, byId[parentOf[node.id]]),
        solo: node.kind === "network" && soloNetwork,
        manages: managesFrom[node.id] || [],
        managesLabel: managesFrom[node.id]
          ? managesSummary(managesFrom[node.id], byId)
          : "",
        // Range host config, badged on the card.
        edr: node.overlay?.edr && node.overlay.edr !== "none" ? node.overlay.edr : "",
        vulnCount: (node.overlay?.vulns || []).length,
        hardeningCount: (node.overlay?.hardening || []).length,
      },
    };
  });

  const edges = document.edges
    // A drawn edge to a container that already encloses the source is a loop
    // around the node, and it says nothing containment does not already show. A
    // jumpbox manages the network it sits in; drawing that is the blue loop
    // people ask about. An edge to a container the source is not inside, such as
    // a jumpbox managing a peered network, still draws.
    .filter(
      (edge) =>
        DRAWN_ROLES.includes(edge.role) &&
        !(isContainer(byId[edge.target]?.kind) && encloses(edge.target, edge.source))
    )
    .map((edge) => {
      // A trust draws between its two domain boxes with an arrow per direction;
      // an "arrowclosed" marker string avoids importing React Flow's enum, so
      // this module stays free of a browser-only dependency.
      const trust = edge.role === "trusts";
      const both = trust && (edge.direction || "bidirectional") === "bidirectional";
      const stroke = trust ? trustColor(edge.trust_type) : roleColor(edge.role);
      const arrow = { type: "arrowclosed", color: stroke, width: 15, height: 15 };
      return {
        id: edge.id,
        type: "floating",
        source: edge.source,
        target: edge.target,
        label: edgeLabel(edge),
        // A wide invisible hit band so clicking the thin line to select it, or
        // grabbing its end to reconnect it, does not demand pixel-precise aim.
        interactionWidth: 18,
        reconnectable: true,
        animated: edge.role === "fronts",
        data: { edge },
        markerEnd: trust ? arrow : undefined,
        markerStart: both ? arrow : undefined,
        // Above the host cards, so a line reads as a connector drawn over the
        // shapes it joins, the way Visio and Lucid draw them, and is selectable
        // anywhere along its length rather than tucking behind a box.
        zIndex: 6,
        style: {
          stroke,
          strokeWidth: 2,
          // Cross-forest trusts are dashed, intra-forest solid, so the forest
          // boundary reads off the line without a forest box.
          ...(trust && !trustIsIntra(edge.trust_type) ? { strokeDasharray: "6 4" } : {}),
        },
        labelStyle: { fill: "#e6e8ea", fontSize: 11 },
        labelBgStyle: { fill: "#25272b" },
      };
    });

  return { nodes, edges, byId };
}

// -- flow back to document

export function applyPositions(document, flowNodes) {
  const positions = Object.fromEntries(
    flowNodes.map((n) => [n.id, { x: Math.round(n.position.x), y: Math.round(n.position.y) }])
  );
  const sizes = Object.fromEntries(
    flowNodes
      .filter((n) => n.style?.width)
      .map((n) => [n.id, { width: Math.round(n.style.width), height: Math.round(n.style.height) }])
  );
  return {
    ...document,
    nodes: document.nodes.map((node) => ({
      ...node,
      position: positions[node.id] || node.position,
      ...(sizes[node.id] || {}),
    })),
  };
}

// -- editing

// Enough of an overlay to satisfy the schema's required fields. The inspector
// edits the rest; a node that will not validate is worse than one with
// placeholder values, because the finding says nothing useful. A network and a
// subnet get their address range from the allocator in addNode so two of them
// never seed the same range.
const SEED_OVERLAY = {
  network: {},
  segment: { egress: "allowed", exposure: "local" },
  // No hostname on purpose: RDR001 refuses to compile until the operator sets one,
  // which is the point. Seeding a plausible domain here is what let a placeholder
  // ride all the way to a deploy that then asked for an A record nobody could
  // create. letsencrypt is the default so the name they choose gets a real cert.
  redirector: { server: "nginx", tls: { cert_source: "letsencrypt" } },
  teamserver: { c2: "mythic" },
  collector: { sink: "opensearch" },
  jumpbox: { services: ["ssh"] },
  operator: { os: "kali" },
};

export function addNode(document, entry, position) {
  const overlay = structuredClone(SEED_OVERLAY[entry.kind] || {});
  if (entry.kind === "network") overlay.cidr = allocNetworkCidr(document);
  if (entry.kind === "segment") overlay.cidr = allocSegmentCidr(document);
  // The id is derived from the kind and the seed overlay, so a Mythic
  // teamserver arrives as myth-ts01 rather than a bare ordinal. It settles
  // further once the node is nested and retitle runs. See idscheme.js.
  const id = proposeId(document, { kind: entry.kind, overlay });
  return {
    ...document,
    nodes: [...document.nodes, { id, kind: entry.kind, position, overlay }],
  };
}

// A range starter: a host kind plus a filled-in overlay, dropped from the
// palette so a SQL server or an AD CS box arrives already carrying its role and
// services rather than as a blank srv the user has to configure. Mirrors
// addNode; the id derives from the kind and the preset overlay. See presets.js.
export function addHostPreset(document, preset, position) {
  const overlay = structuredClone(preset.overlay || {});
  const id = proposeId(document, { kind: preset.kind, overlay });
  return {
    ...document,
    nodes: [...document.nodes, { id, kind: preset.kind, position, overlay }],
  };
}

export function removeNode(document, id) {
  return {
    ...document,
    nodes: document.nodes.filter((n) => n.id !== id),
    edges: document.edges.filter((e) => e.source !== id && e.target !== id),
  };
}

export function addEdge(document, source, target, role, extra = {}) {
  const id = edgeId(source, target, role);
  if (document.edges.some((e) => e.id === id)) return document;
  return {
    ...document,
    edges: [...document.edges, { id, role, source, target, ...extra }],
  };
}

export function removeEdge(document, id) {
  return { ...document, edges: document.edges.filter((e) => e.id !== id) };
}

// Nesting is attachment, so a drop into a container rewrites that edge.
export function setParent(document, childId, parentId) {
  const edges = document.edges.filter(
    (e) => !(e.role === "attached" && e.source === childId)
  );
  if (parentId) {
    edges.push({
      id: edgeId(childId, parentId, "attached"),
      role: "attached",
      source: childId,
      target: parentId,
    });
  }

  // A subnet dropped into a network takes a range inside that network, unless
  // the one it already carries fits there, so a hand chosen range is kept.
  let nodes = document.nodes;
  const child = document.nodes.find((n) => n.id === childId);
  const parent = document.nodes.find((n) => n.id === parentId);
  if (
    child?.kind === "segment" &&
    parent?.kind === "network" &&
    !cidrWithin(child.overlay?.cidr, parent.overlay?.cidr)
  ) {
    const scan = { ...document, nodes: document.nodes.filter((n) => n.id !== childId) };
    const cidr = allocSegmentCidr(scan, parentId);
    nodes = nodes.map((n) =>
      n.id === childId ? { ...n, overlay: { ...n.overlay, cidr } } : n
    );
  }

  return { ...document, nodes, edges };
}

// Joining a range host to a domain is a `joins` edge. Picking a domain from the
// inspector rewrites it in one step, the way nesting rewrites an attachment, so
// a host can be moved between domains without drawing or deleting a line. An
// empty domain clears the membership. See 0047.
export function setJoin(document, hostId, domainId) {
  const edges = document.edges.filter(
    (e) => !(e.role === "joins" && e.source === hostId)
  );
  if (domainId) {
    edges.push({
      id: edgeId(hostId, domainId, "joins"),
      role: "joins",
      source: hostId,
      target: domainId,
    });
  }
  return { ...document, edges };
}

export function updateOverlay(document, id, overlay) {
  return {
    ...document,
    nodes: document.nodes.map((n) => (n.id === id ? { ...n, overlay } : n)),
  };
}

export function updateEdge(document, id, patch) {
  return {
    ...document,
    edges: document.edges.map((e) => (e.id === id ? { ...e, ...patch } : e)),
  };
}

// The default prefix per canvas: ARTIE names run art-, HAVEN ranges hvn-.
export const MODE_PREFIX = { artie: "art", haven: "hvn" };

export const emptyDocument = (mode = "artie") => ({
  schema_version: "0.6.0",
  mode,
  name: "Untitled",
  prefix: MODE_PREFIX[mode] || "art",
  nodes: [],
  edges: [],
});
