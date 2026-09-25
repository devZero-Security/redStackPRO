// The GOAD extensions, mirrored from Orange-Cyberdefense/GOAD extensions/*/
// extension.json. Each adds one box to a range; wazuh and elk also install an
// agent on every Windows host. Toggling one on a range adds its box and wires
// the agents; toggling it off removes them again. Domain members join the
// range's first (root) domain; the standalone Linux boxes sit on the subnet.
//
// `compatibility` is GOAD's own: the labs an extension can be added to, matched
// against the document name, with "*" meaning any lab. ws01/exchange/lx01 are
// sevenkingdoms specific, so they only offer on GOAD, GOAD-Light and GOAD-Mini;
// wazuh and elk work on any lab. GOAD's guacamole extension is deliberately
// omitted: redStackPRO always runs Guacamole on the jumpbox, so a separate
// guacamole box is redundant. See guacamole-on-the-jumpbox.

export const EXTENSIONS = [
  {
    key: "ws01",
    title: "Hardened workstation",
    blurb: "A hardened Windows 10 workstation (casterlyrock) joined to the domain. RunAsPPL, Defender ASR, constrained PowerShell.",
    requiresDomain: true,
    compatibility: ["GOAD", "GOAD-Light", "GOAD-Mini"],
    boxes: [{
      id: "ws01", kind: "wks", member: true,
      overlay: {
        os: "windows_10", hostname: "ws01", role: "generic", edr: "defender",
        vulns: [],
        notes: "Hardened workstation (ws01 extension): RunAsPPL, Defender ASR rules, constrained PowerShell.",
      },
    }],
  },
  {
    key: "exchange",
    title: "Exchange server",
    blurb: "An Exchange server (the-eyrie) joined to the domain. Extends the AD schema. A heavy box.",
    requiresDomain: true,
    compatibility: ["GOAD", "GOAD-Light", "GOAD-Mini"],
    boxes: [{
      id: "srv01", kind: "srv", member: true,
      overlay: {
        os: "windows_server_2019", hostname: "the-eyrie", role: "generic",
        services: ["exchange"], edr: "defender",
      },
    }],
  },
  {
    key: "lx01",
    title: "Linux domain member",
    blurb: "A Linux computer (lx01) enrolled in the domain.",
    requiresDomain: true,
    compatibility: ["GOAD", "GOAD-Light", "GOAD-Mini"],
    boxes: [{
      id: "lx01", kind: "srv", member: true,
      overlay: { os: "debian_12", hostname: "lx01", role: "generic", edr: "none" },
    }],
  },
  {
    key: "wazuh",
    title: "Wazuh SIEM",
    blurb: "A Wazuh server and an agent on every Windows host. The GOAD detection lab.",
    requiresDomain: false,
    compatibility: ["*"],
    agent: "wazuh",
    boxes: [{
      id: "wazuh", kind: "siem", member: false,
      overlay: { product: "wazuh", os: "ubuntu_2204", hostname: "wazuh" },
    }],
  },
  {
    key: "elk",
    title: "ELK stack",
    blurb: "An ELK server and a logbeat agent on every Windows host.",
    requiresDomain: false,
    compatibility: ["*"],
    agent: "elastic",
    boxes: [{
      id: "elk", kind: "siem", member: false,
      overlay: { product: "elk", os: "ubuntu_2204", hostname: "elk" },
    }],
  },
];

const EXT_BY_KEY = Object.fromEntries(EXTENSIONS.map((e) => [e.key, e]));
const WINDOWS_HOST_KINDS = ["dc", "srv", "wks"];

function eid(source, target, role) {
  return `e-${source}-${target}-${role}`.replace(/_/g, "-");
}

function primarySubnet(doc) {
  return doc.nodes.find((n) => n.kind === "segment") || null;
}

// The forest root is the domain with the fewest labels in its fqdn; that is the
// one GOAD extensions attach their members to (sevenkingdoms, not north).
function primaryDomain(doc) {
  const domains = doc.nodes.filter((n) => n.kind === "domain");
  return domains
    .slice()
    .sort((a, b) =>
      (a.overlay?.fqdn || "").split(".").length -
      (b.overlay?.fqdn || "").split(".").length)[0] || null;
}

function isWindows(node) {
  return WINDOWS_HOST_KINDS.includes(node.kind)
    && (node.overlay?.os || "").startsWith("windows");
}

// Which extensions are present on the range now: all of an extension's boxes
// are on the canvas.
export function activeExtensions(doc) {
  const ids = new Set(doc.nodes.map((n) => n.id));
  const active = new Set();
  for (const ext of EXTENSIONS) {
    if (ext.boxes.every((b) => ids.has(b.id))) active.add(ext.key);
  }
  return active;
}

// GOAD lists which labs an extension supports, matched against the document
// name; "*" is any lab. A lab an extension does not list simply does not offer
// it: ws01/exchange/lx01 are sevenkingdoms specific, so NHA, SCCM and the rest
// see only wazuh and elk.
export function supportsExtension(doc, key) {
  const ext = EXT_BY_KEY[key];
  if (!ext) return false;
  const compat = ext.compatibility || [];
  return compat.includes("*") || compat.includes(doc.name);
}

// The extensions to show for a range: only the ones its lab supports.
export function availableExtensions(doc) {
  return EXTENSIONS.filter((ext) => supportsExtension(doc, ext.key));
}

// An extension can be added when its lab supports it, its boxes are not already
// present, and, if it adds a domain member, the range actually has a domain.
export function canAdd(doc, key) {
  const ext = EXT_BY_KEY[key];
  if (!ext) return false;
  if (!supportsExtension(doc, key)) return false;
  if (activeExtensions(doc).has(key)) return false;
  if (ext.requiresDomain && !primaryDomain(doc)) return false;
  return true;
}

export function applyExtension(doc, key) {
  const ext = EXT_BY_KEY[key];
  if (!ext || !canAdd(doc, key)) return doc;

  const subnet = primarySubnet(doc);
  const domain = primaryDomain(doc);
  const nodes = doc.nodes.slice();
  const edges = doc.edges.slice();

  const domainCount = doc.nodes.filter((n) => n.kind === "domain").length;
  let memberSlot = domain
    ? edges.filter((e) => e.role === "joins" && e.target === domain.id).length
    : 0;
  let standaloneSlot = doc.nodes.filter((n) =>
    ["siem", "appliance", "jumpbox"].includes(n.kind)).length;

  for (const box of ext.boxes) {
    const position = box.member
      ? { x: 16 + memberSlot * 252, y: 48 }
      : { x: 16 + standaloneSlot * 252, y: 48 + domainCount * 190 + 40 };
    if (box.member) memberSlot += 1; else standaloneSlot += 1;

    nodes.push({ id: box.id, kind: box.kind, position, overlay: { ...box.overlay } });
    if (subnet) edges.push(edge(box.id, subnet.id, "attached"));
    if (box.member && domain) edges.push(edge(box.id, domain.id, "joins"));
  }

  let nextNodes = nodes;
  if (ext.agent) {
    nextNodes = nodes.map((n) =>
      isWindows(n)
        ? { ...n, overlay: { ...n.overlay, edr: ext.agent } }
        : n);
  }
  return { ...doc, nodes: nextNodes, edges };
}

export function removeExtension(doc, key) {
  const ext = EXT_BY_KEY[key];
  if (!ext) return doc;
  const boxIds = new Set(ext.boxes.map((b) => b.id));

  const nodes = doc.nodes.filter((n) => !boxIds.has(n.id));
  const edges = doc.edges.filter(
    (e) => !boxIds.has(e.source) && !boxIds.has(e.target));

  let nextNodes = nodes;
  if (ext.agent) {
    // Revert the agent we set to the Windows default; we do not track the prior
    // value, and defender is what a fresh Windows box runs.
    nextNodes = nodes.map((n) =>
      isWindows(n) && n.overlay?.edr === ext.agent
        ? { ...n, overlay: { ...n.overlay, edr: "defender" } }
        : n);
  }
  return { ...doc, nodes: nextNodes, edges };
}

function edge(source, target, role) {
  return { id: eid(source, target, role), role, source, target };
}
