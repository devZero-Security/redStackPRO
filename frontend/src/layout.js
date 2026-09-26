// Layout.
//
// A document carries no positions until someone drags something, and most
// documents never will: a blueprint, an agent's output, and a freshly migrated
// topology all arrive with none. Falling back to the origin puts every node on top
// of every other one, so the canvas computes a layout instead.
//
// The arrangement is by tier, which is the advisory label segments already
// carry, and it reads top to bottom as the callback's path inward.
//
// The redirector a target actually talks to sits at the top, then the C2 it
// fronts, then the collector everything ships to, and at the bottom the
// management tier: the operator boxes and, lowest, the jumpbox the whole range
// is reached through. So the axis is redirector, C2, collector, operators,
// jumpbox, top to bottom.
//
// Operators and the jumpbox share the management tier, so the tier index alone
// ties them. A management segment holding a jumpbox is nudged just below one
// holding only operator boxes, which puts the door at the very bottom.
//
// The vertical axis is that path inward, and the horizontal one is choice:
// networks that rank the same are alternatives to each other, not steps in a
// sequence, so they sit side by side. Two redirector networks fronting the same
// range read as two doors rather than one behind the other.

export const HOST = { width: 190, height: 54, gap: 14 };
export const PAD = { top: 34, side: 16, bottom: 16 };
export const SEGMENT_GAP = 22;
export const NETWORK_GAP = 60;

// How wide a row of peer networks is allowed to get before it wraps. The same
// number rangeLayout uses for its own rows, so the two passes break at the same
// place rather than for different reasons.
const NETWORK_MAX_ROW = 1500;

// Top to bottom along the callback's path inward: the internet-facing redirector
// at the top, the management tier with the jumpbox at the bottom.
export const TIER_ORDER = ["redirector", "edge", "c2", "collector", "management"];

// An unlabelled segment sorts just above the c2, because something nobody
// labelled is more likely to be internal than target-facing. Derived from the
// list rather than written as an offset, so reordering the tiers does not
// silently move it somewhere else.
const UNLABELLED_RANK = TIER_ORDER.indexOf("c2") - 0.5;

function tierRank(segment) {
  const tier = segment?.overlay?.tier;
  const index = TIER_ORDER.indexOf(tier);
  return index === -1 ? UNLABELLED_RANK : index;
}

// Within the management tier, the jumpbox sits lowest, because it is the entry
// point the whole range is reached through, so a management segment holding a
// jumpbox sorts just below one that holds only operator boxes.
// Frontend only: it reads segment contents rather than adding a tier value.
function segmentRank(segment, kinds) {
  const base = tierRank(segment);
  if (segment?.overlay?.tier !== "management") return base;
  return kinds.has("jumpbox") ? base + 0.25 : base - 0.25;
}

// Hosts in a segment read as a single row, so a tier is one horizontal band:
// the three teamservers sit side by side rather than wrapping to a grid. Beyond
// six it wraps, so a large segment does not run off the canvas.
function columnsFor(count) {
  return Math.min(Math.max(count, 1), 6);
}

// A range nests differently from an offensive topology: a subnet holds domains and
// standalone boxes, a domain holds the hosts joined to it. autoLayout's tier
// model knows only networks, segments, and hosts, so a range gets its own pass:
// domains sit in a wrapped row inside the subnet, each domain's members in a
// wrapped row inside it, and the standalone boxes (jumpbox, SIEM, an unjoined
// host, a freshly added extension) sit in a row beneath the domains. Positions
// are parent-relative, the same as the tier layout produces.
const RANGE_HOST_H = 84; // a range host card: name, os, and a badge row.
const DOMAIN_COLS = 3; // members per row inside a domain box.
const DOMAIN_GAP = 24;
const RANGE_MAX_ROW = 1500;

export function rangeLayout(document) {
  const attachedTo = {};
  const joinsDomain = {};
  for (const edge of document.edges) {
    if (edge.role === "attached") attachedTo[edge.source] = edge.target;
    else if (edge.role === "joins") joinsDomain[edge.source] = edge.target;
  }

  const isContainer = (k) => k === "network" || k === "segment" || k === "domain";
  const networks = document.nodes.filter((n) => n.kind === "network");
  const subnets = document.nodes.filter((n) => n.kind === "segment");
  const domains = document.nodes.filter((n) => n.kind === "domain");
  const hosts = document.nodes.filter((n) => !isContainer(n.kind));

  // A domain carries no attached edge: it lives in the subnet its member hosts
  // attach to. Derive that so domains land in the right subnet rather than
  // orphaning at the origin.
  const domainSubnet = {};
  for (const domain of domains) {
    const member = hosts.find((h) => joinsDomain[h.id] === domain.id);
    if (member) domainSubnet[domain.id] = attachedTo[member.id];
  }

  const position = {};
  const size = {};

  // Each domain sized to its members, laid out in a wrapped row.
  const domainBox = {};
  for (const domain of domains) {
    const members = hosts.filter((h) => joinsDomain[h.id] === domain.id);
    const cols = Math.min(Math.max(members.length, 1), DOMAIN_COLS);
    const rows = Math.max(1, Math.ceil(members.length / cols));
    members.forEach((h, i) => {
      position[h.id] = {
        x: PAD.side + (i % cols) * (HOST.width + HOST.gap),
        y: PAD.top + Math.floor(i / cols) * (RANGE_HOST_H + HOST.gap),
      };
    });
    domainBox[domain.id] = {
      width: PAD.side * 2 + cols * HOST.width + (cols - 1) * HOST.gap,
      height: PAD.top + PAD.bottom + rows * RANGE_HOST_H + (rows - 1) * HOST.gap,
    };
    size[domain.id] = domainBox[domain.id];
  }

  // Each subnet: domains in a wrapped row, standalone boxes in a row beneath.
  const subnetBox = {};
  for (const subnet of subnets) {
    const own = domains.filter((d) => domainSubnet[d.id] === subnet.id);
    const standalones = hosts.filter(
      (h) => attachedTo[h.id] === subnet.id && !joinsDomain[h.id]
    );

    let x = PAD.side;
    let y = PAD.top;
    let rowH = 0;
    let right = PAD.side;
    for (const d of own) {
      const box = domainBox[d.id];
      if (x > PAD.side && x + box.width > RANGE_MAX_ROW) {
        x = PAD.side;
        y += rowH + DOMAIN_GAP;
        rowH = 0;
      }
      position[d.id] = { x, y };
      right = Math.max(right, x + box.width);
      x += box.width + DOMAIN_GAP;
      rowH = Math.max(rowH, box.height);
    }
    let bottom = own.length ? y + rowH : PAD.top;

    if (standalones.length) {
      const sy = bottom + (own.length ? DOMAIN_GAP : 0);
      let sx = PAD.side;
      standalones.forEach((h) => {
        position[h.id] = { x: sx, y: sy };
        right = Math.max(right, sx + HOST.width);
        sx += HOST.width + HOST.gap;
      });
      bottom = sy + RANGE_HOST_H;
    }

    subnetBox[subnet.id] = {
      width: Math.max(360, right + PAD.side),
      height: Math.max(140, bottom + PAD.bottom),
    };
    size[subnet.id] = subnetBox[subnet.id];
  }

  // Each network: its subnets stacked top to bottom.
  let networkY = 0;
  for (const network of networks) {
    const own = subnets.filter((s) => attachedTo[s.id] === network.id);
    let y = PAD.top;
    let right = PAD.side;
    for (const s of own) {
      position[s.id] = { x: PAD.side, y };
      right = Math.max(right, PAD.side + subnetBox[s.id].width);
      y += subnetBox[s.id].height + SEGMENT_GAP;
    }
    size[network.id] = {
      width: Math.max(400, right + PAD.side),
      height: Math.max(160, (own.length ? y - SEGMENT_GAP : PAD.top) + PAD.bottom),
    };
    position[network.id] = { x: 0, y: networkY };
    networkY += size[network.id].height + NETWORK_GAP;
  }

  // Anything left unplaced sits in a row below so it is visible, not stacked at
  // the origin.
  let orphanX = 0;
  for (const node of document.nodes) {
    if (position[node.id]) continue;
    position[node.id] = { x: orphanX, y: networkY };
    orphanX += HOST.width + HOST.gap;
  }

  return {
    ...document,
    nodes: document.nodes.map((node) => ({
      ...node,
      position: position[node.id],
      ...(size[node.id] || {}),
    })),
  };
}

export function autoLayout(document) {
  if (document.mode === "haven") return rangeLayout(document);
  const byId = Object.fromEntries(document.nodes.map((n) => [n.id, n]));

  const parentOf = {};
  for (const edge of document.edges) {
    if (edge.role === "attached") parentOf[edge.source] = edge.target;
  }

  const networks = document.nodes.filter((n) => n.kind === "network");
  const segments = document.nodes.filter((n) => n.kind === "segment");
  const hosts = document.nodes.filter(
    (n) => n.kind !== "network" && n.kind !== "segment"
  );

  const position = {};
  const size = {};

  // Hosts fill their segment in a grid, and the segment is sized to fit rather
  // than the other way round.
  const segmentBox = {};
  const segmentKinds = {};
  for (const segment of segments) {
    const members = hosts.filter((h) => parentOf[h.id] === segment.id);
    segmentKinds[segment.id] = new Set(members.map((h) => h.kind));
    const cols = columnsFor(members.length);
    const rows = Math.max(1, Math.ceil(members.length / cols));

    members.forEach((host, index) => {
      position[host.id] = {
        x: PAD.side + (index % cols) * (HOST.width + HOST.gap),
        y: PAD.top + Math.floor(index / cols) * (HOST.height + HOST.gap),
      };
    });

    segmentBox[segment.id] = {
      width: PAD.side * 2 + cols * HOST.width + (cols - 1) * HOST.gap,
      height:
        PAD.top + PAD.bottom + rows * HOST.height + (rows - 1) * HOST.gap,
    };
    size[segment.id] = segmentBox[segment.id];
  }

  // Networks are ranked by the most target-facing tier they hold, so the
  // isolated redirector network sits above the main range. Rank orders the
  // rows; networks sharing a rank share a row (see the placement pass below).
  // Inside each network the segments stack top to bottom by tier, redirector at
  // the top and the jumpbox at the bottom.
  const rank = (segment) =>
    segmentRank(segment, segmentKinds[segment.id] || new Set());
  const networkRank = (network) => {
    const members = segments.filter((s) => parentOf[s.id] === network.id);
    return members.length ? Math.min(...members.map(rank)) : Number.POSITIVE_INFINITY;
  };
  // Computed once per network rather than per comparison: the placement pass
  // below asks for the rank of every network again while grouping, and
  // networkRank walks the segment list each time it is called.
  const rankOf = new Map(networks.map((n) => [n.id, networkRank(n)]));
  const orderedNetworks = [...networks].sort(
    (a, b) => rankOf.get(a.id) - rankOf.get(b.id)
  );

  // Sizing comes first, as its own pass. A row of networks cannot be placed
  // until the height of its tallest member is known, and that is not known
  // until every network in the row has been sized.
  for (const network of orderedNetworks) {
    const members = segments
      .filter((s) => parentOf[s.id] === network.id)
      .sort((a, b) => rank(a) - rank(b));

    // The content column is as wide as the widest segment, and every segment is
    // centred in it, so the narrower tiers line up under the teamservers rather
    // than hanging off the left edge.
    const widest = members.reduce(
      (w, s) => Math.max(w, segmentBox[s.id].width),
      0
    );
    const content = Math.max(320, widest);

    let y = PAD.top;
    for (const segment of members) {
      const box = segmentBox[segment.id];
      position[segment.id] = {
        x: PAD.side + (content - box.width) / 2,
        y,
      };
      y += box.height + SEGMENT_GAP;
    }

    size[network.id] = {
      width: PAD.side * 2 + content,
      height: Math.max(140, y - SEGMENT_GAP + PAD.bottom),
    };
  }

  // Networks of EQUAL rank are peers, and a peer is not a tier below. Two
  // redirector networks fronting one range -- split horizon's long haul and
  // interactive doors -- both rank at the redirector tier, so stacking them put
  // one behind the other and made a reader compare CIDRs to see they were
  // siblings. They now share a row, and the rows stack by rank, so the vertical
  // axis still reads as the callback's path inward while the horizontal one
  // says "these are alternatives to each other".
  //
  // Ties are exact: a network's rank is the minimum tier of its segments, so
  // nothing lands in a row by rounding. Networks holding no segments all rank
  // at infinity, which ties them together too, and a row of empty boxes is the
  // right answer for those as well.
  let networkY = 0;
  for (let i = 0; i < orderedNetworks.length; ) {
    const peers = [];
    const peerRank = rankOf.get(orderedNetworks[i].id);
    while (
      i < orderedNetworks.length &&
      rankOf.get(orderedNetworks[i].id) === peerRank
    ) {
      peers.push(orderedNetworks[i]);
      i += 1;
    }

    // A row wraps rather than running off to the right forever. Four peer
    // networks at 600px each is 2500px of row, which is a pan rather than a
    // picture; past the limit the row breaks and continues underneath.
    let x = 0;
    let rowHeight = 0;
    for (const network of peers) {
      const box = size[network.id];
      if (x > 0 && x + box.width > NETWORK_MAX_ROW) {
        networkY += rowHeight + NETWORK_GAP;
        x = 0;
        rowHeight = 0;
      }
      position[network.id] = { x, y: networkY };
      x += box.width + NETWORK_GAP;
      rowHeight = Math.max(rowHeight, box.height);
    }
    networkY += rowHeight + NETWORK_GAP;
  }

  // Anything with no parent, which is a topology mid edit rather than a finished
  // one, goes in a row underneath so it is visible instead of stacked at zero.
  let orphanX = 0;
  for (const node of document.nodes) {
    if (position[node.id]) continue;
    position[node.id] = { x: orphanX, y: networkY };
    orphanX += HOST.width + HOST.gap;
  }

  return {
    ...document,
    nodes: document.nodes.map((node) => ({
      ...node,
      position: position[node.id],
      ...(size[node.id] || {}),
    })),
  };
}

export function needsLayout(document) {
  return document.nodes.length > 0 && document.nodes.some((n) => !n.position);
}

// A saved topology carries the positions and sizes the person left it with, so
// laying it out again would rearrange their canvas under them on every reload.
// A blueprint, an agent's output, and a freshly migrated topology carry none, and
// those are the ones that need arranging.
export function layoutIfNeeded(document) {
  return needsLayout(document) ? autoLayout(document) : document;
}
