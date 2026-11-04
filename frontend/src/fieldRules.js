// The rules behind the Inspector's generated overlay forms: $ref resolution,
// labels for fields and options, the default an empty field compiles to, which
// fields mean nothing for a given node, and client-side value checks. Pure, so
// each rule is testable without rendering. Inspector.jsx Field consumes these.
//
// Defaults here mirror the compiler, not the schema alone: a dc with no os
// builds Windows Server 2022, a dc with no hostname is named after its id, and
// a domain with no netbios takes its first fqdn label uppercased.

import { PROFILES } from "./profiles.js";

const AD_KINDS = new Set(["dc", "srv", "wks"]);
// Plain Linux boxes on a range subnet. Nothing is installed on them yet.
const LINUX_ONLY_KINDS = new Set(["fw", "appliance"]);
const RANGE_HOST_KINDS = new Set([...AD_KINDS, ...LINUX_ONLY_KINDS]);

// The values a role installs from a range host's services list. Only the srv
// role reads it (redstackpro.srv tasks: mssql, iis, exchange).
export const RANGE_SERVICES = ["mssql", "iis", "exchange"];

// ----------------------------------------------------------------- $ref

// A property that is only a $ref takes its type, constraints and help from the
// def. The property's own keys (title, description, default) win over the def's.
export function resolveSpec(spec, defs) {
  if (!spec || typeof spec.$ref !== "string" || !defs) return spec;
  const m = /^#\/\$defs\/(.+)$/.exec(spec.$ref);
  const def = m ? defs[m[1]] : undefined;
  if (!def) return spec;
  const { $ref: _ref, ...own } = spec;
  return { "x-ui-def": m[1], ...resolveSpec(def, defs), ...own };
}

// The JSON shape a field must be edited as, or null for a plain control. An
// object or a list of objects has no plain control that can hold it.
export function jsonKindFor(spec, value) {
  if (!spec) return null;
  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  if (spec.type === "object" && !spec.properties) return "object";
  if (spec.type === "array") {
    const items = spec.items || {};
    if (items.type === "object" || items.properties || items.type === "array") return "array";
    if (Array.isArray(value) && value.some((v) => v !== null && typeof v === "object")) return "array";
    if (value != null && !Array.isArray(value)) return "array";
    return null;
  }
  if (spec.type === "object") return value != null && !isObj(value) ? "object" : null;
  if (value !== null && typeof value === "object") return Array.isArray(value) ? "array" : "object";
  return null;
}

// ----------------------------------------------------------------- labels

export function fieldLabel(name, spec) {
  return spec?.title ?? name;
}

const DECOY_LABELS = Object.fromEntries(PROFILES.map((p) => [p.key, p.label]));

// Per-field option labels, for values whose meaning depends on the field
// ("none" is a C2 choice in one place and a cover page in another).
const FIELD_OPTION_LABELS = {
  c2: { mythic: "Mythic", sliver: "Sliver", adaptix: "AdaptixC2", none: "None (plain Debian host)" },
  decoy: { ...DECOY_LABELS, none: "No cover page" },
  edr: {
    none: "None",
    defender: "Microsoft Defender",
    elastic: "Elastic",
    wazuh: "Wazuh",
    crowdstrike: "CrowdStrike",
    sentinelone: "SentinelOne",
  },
  egress: { allowed: "Allowed", none: "None" },
  exposure: { internet: "Internet", local: "Local only", none: "None (isolated)" },
  access_mode: { public: "Public portal", wireguard: "WireGuard", openvpn: "OpenVPN" },
  role: {
    generic: "Generic",
    sql: "SQL Server",
    web: "Web server",
    fileshare: "File server",
    adcs: "AD CS",
    mecm: "MECM",
  },
  tier: {
    edge: "Edge",
    redirector: "Redirector",
    c2: "C2",
    collector: "Collector",
    management: "Management",
  },
  os: { windows: "Windows", kali: "Kali", debian: "Debian" },
  direction: { inbound: "Inbound", outbound: "Outbound", bidirectional: "Both ways" },
};

const OPTION_LABELS = {
  windows_server_2016: "Windows Server 2016",
  windows_server_2019: "Windows Server 2019",
  windows_server_2022: "Windows Server 2022",
  windows_server_2025: "Windows Server 2025",
  windows_10: "Windows 10 (Server 2022 on GCP/AWS)",
  windows_11: "Windows 11 (Server 2022 on GCP/AWS)",
  linux: "Linux (Debian)",
  debian_13: "Debian 13",
  debian_12: "Debian 12",
  ubuntu_2404: "Ubuntu 24.04",
  ubuntu_2204: "Ubuntu 22.04",
  ubuntu_2004: "Ubuntu 20.04",
  letsencrypt: "Let's Encrypt",
  self_signed: "Self-signed",
  provided: "Your own certificate",
  parent_child: "Parent and child",
  tree_root: "Tree root",
  external: "External",
  forest: "Forest",
  apache: "Apache",
  nginx: "nginx",
  opensearch: "OpenSearch",
  elasticsearch: "Elasticsearch",
  splunk: "Splunk",
  filebeat: "Filebeat",
  wazuh: "Wazuh",
  elk: "ELK",
  gcp: "GCP",
  aws: "AWS",
  azure: "Azure",
  proxmox: "Proxmox",
  esxi: "ESXi",
  http: "HTTP",
  https: "HTTPS",
  dns: "DNS",
  tcp: "TCP",
  udp: "UDP",
  ssh: "SSH",
  guacamole: "Guacamole portal",
  wireguard: "WireGuard",
  openvpn: "OpenVPN",
  mssql: "SQL Server (mssql)",
  iis: "IIS",
  exchange: "Exchange",
  adcs: "AD CS",
  mecm: "MECM",
  smb: "SMB",
  user: "User",
  local_admin: "Local admin",
  domain_admin: "Domain admin",
  enterprise_admin: "Enterprise admin",
};

function humanize(value) {
  const text = String(value).replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

// The display label for an enum value. The stored value never changes.
export function optionLabel(field, value) {
  if (value == null || value === "") return "";
  const key = String(value);
  return FIELD_OPTION_LABELS[field]?.[key] ?? OPTION_LABELS[key] ?? humanize(key);
}

// One line per option, shown under the select for the chosen one.
const ROLE_HELP = {
  generic: "Installs nothing.",
  sql: "Installs SQL Server.",
  web: "Badge only. Tick IIS under Services to install IIS.",
  fileshare: "Badge only. Add the Open share vuln for a share.",
  adcs: "Installs an Enterprise CA. Works on a dc or a srv.",
  mecm: "Installs an MECM site.",
};

// ----------------------------------------------------------------- defaults

const leaf = (path) => path.split(".").pop();

function netbiosFrom(fqdn) {
  const first = String(fqdn || "").split(".")[0];
  return first ? first.toUpperCase() : undefined;
}

// What an empty field compiles to, when the schema carries no default.
function knownDefault(path, ctx = {}) {
  const ov = ctx.overlay || {};
  switch (path) {
    case "os":
      if (AD_KINDS.has(ctx.kind)) return "windows_server_2022";
      if (LINUX_ONLY_KINDS.has(ctx.kind)) return "linux";
      if (ctx.kind === "siem") return "debian_13";
      return undefined;
    case "tls.cert_source":
      return "letsencrypt";
    case "access_mode":
      return "public";
    case "gating.decoy":
      return "cdn";
    case "vpn_protocol":
      return "udp";
    case "vpn_port":
      return ov.access_mode === "openvpn" ? 1194 : 51820;
    case "edr":
      return "none";
    case "role":
      return RANGE_HOST_KINDS.has(ctx.kind) ? "generic" : undefined;
    case "shipper":
      return "filebeat";
    case "hostname":
      return ctx.kind === "dc" ? ctx.id : undefined;
    case "netbios":
      return ctx.kind === "domain" ? netbiosFrom(ov.fqdn) : undefined;
    default:
      return undefined;
  }
}

export function defaultFor(path, spec, ctx) {
  return spec?.default ?? knownDefault(path, ctx);
}

// The label of a select's empty option. Required fields get none.
export function emptyOptionLabel(path, spec, ctx) {
  const def = defaultFor(path, spec, ctx);
  return def == null ? "not set" : `default (${optionLabel(leaf(path), def)})`;
}

// ----------------------------------------------------------------- context

function isWindowsHost(ctx) {
  if (LINUX_ONLY_KINDS.has(ctx.kind)) return false;
  const os = ctx.overlay?.os;
  if (os) return String(os).startsWith("windows");
  return AD_KINDS.has(ctx.kind);
}

// A field that holds nothing worth showing: empty, or equal to its default.
export function isEmptyValue(value, def) {
  if (value == null || value === "" || value === false) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === "object") return Object.keys(value).length === 0;
  return def !== undefined && value === def;
}

const VPN_OFFENSE_ONLY = new Set(["access_mode", "vpn_port", "vpn_protocol", "operators"]);
const NOTHING_INSTALLED = new Set([
  "vulns", "vulns_vars", "hardening", "services", "role", "edr",
  "defender_enabled", "endpoint_telemetry", "sudo_groups", "ssh_groups",
]);

// Why a field means nothing on this node, or null when it does.
function unusedReason(path, ctx) {
  const { kind, mode } = ctx;
  const ov = ctx.overlay || {};
  const access = ov.access_mode || "public";
  if (kind === "jumpbox") {
    if (mode === "defense" && VPN_OFFENSE_ONLY.has(path)) {
      return "a defense range keeps the public portal. VPN access and the operator roster are offense features.";
    }
    if ((path === "vpn_port" || path === "vpn_protocol") && access === "public") {
      return "used only when Access mode is WireGuard or OpenVPN.";
    }
    if (path === "vpn_protocol" && access === "wireguard") return "WireGuard is UDP only.";
  }
  if (kind === "network" && path === "provider") return "nothing reads it yet.";
  if (kind === "collector" && path === "shipper") return "Filebeat is the only shipper.";
  if (kind === "teamserver" && path === "version") {
    if (ov.c2 === "sliver") return "Sliver always installs the current release.";
    if (ov.c2 === "none") return "no C2 is installed, so there is no version to pick.";
  }
  if (kind === "operator" && path === "desktop" && ov.os === "windows") {
    return "a Windows operator already has a desktop over RDP.";
  }
  if (RANGE_HOST_KINDS.has(kind)) {
    if (LINUX_ONLY_KINDS.has(kind) && NOTHING_INSTALLED.has(path)) {
      return "redStackPRO installs nothing on this host yet.";
    }
    if ((path === "sudo_groups" || path === "ssh_groups") && (kind !== "srv" || isWindowsHost(ctx))) {
      return "only a Linux member server reads this.";
    }
    if ((path === "defender_enabled" || path === "endpoint_telemetry") && !isWindowsHost(ctx)) {
      return "Windows hosts only.";
    }
    if (path === "services" && kind !== "srv") {
      return "only a member server (srv) installs services.";
    }
    if (path === "role" && kind === "wks") return "nothing reads the role on a workstation.";
  }
  return null;
}

// Offense hosts whose public address is fixed by kind: EXP001 and EXP002 accept
// exactly one value, so the box is shown locked unless it holds the wrong one.
const OFFENSE_PUBLIC = { jumpbox: true, redirector: true, teamserver: false, collector: false, operator: false };

function lockedPublicAddress(ctx, value) {
  if (ctx.kind === "jumpbox" && ctx.mode === "defense") {
    return { value: true, reason: "A range jumpbox always takes a public address: it is the only way in." };
  }
  if (ctx.mode !== "offense" || !(ctx.kind in OFFENSE_PUBLIC)) return null;
  const forced = OFFENSE_PUBLIC[ctx.kind];
  if (value !== undefined && value !== forced) return null;
  return forced
    ? { value: true, reason: `A ${ctx.kind} always takes a public address.` }
    : { value: false, reason: `A ${ctx.kind} never takes a public address. Reach it through the jumpbox.` };
}

function unknownServiceTitle(value) {
  const known = { adcs: "Set Role to AD CS instead.", mecm: "Set Role to MECM instead." }[value];
  return `${value} does nothing: no role installs it.${known ? " " + known : ""}`;
}

// The spec as it applies to this node, plus how to show it:
//   hide     render nothing
//   ignored  render, with a note saying why the value is not used here
//   locked   render read-only at a fixed value, with the reason as help
export function fieldRule(path, spec, ctx, value) {
  if (!spec || !ctx) return { spec };
  const def = defaultFor(path, spec, ctx);
  let out = spec;
  let locked = null;

  if (path === "public_address") locked = lockedPublicAddress(ctx, value);

  if (path === "offensive_toolkit" && ctx.kind === "jumpbox") {
    // The compiler turns it on for a range jumpbox unless the overlay says no.
    out = { ...out, default: ctx.mode === "defense" };
  }
  if (path === "vpn_port") out = { ...out, default: def };

  if (path === "os" && LINUX_ONLY_KINDS.has(ctx.kind) && out.enum) {
    out = { ...out, enum: out.enum.filter((v) => !String(v).startsWith("windows")) };
  }

  if (path === "role" && RANGE_HOST_KINDS.has(ctx.kind) && out.enum) {
    const enumFor = ctx.kind === "dc" ? out.enum.filter((v) => v === "generic" || v === "adcs") : out.enum;
    out = { ...out, enum: enumFor, "x-ui-option-help": ROLE_HELP };
  }

  if (path === "services" && ctx.kind === "jumpbox" && out.items?.enum) {
    // Access mode is hidden on a defense jumpbox, so the note there cannot
    // point at it.
    const vpn = ctx.mode === "defense"
      ? "A defense range runs no VPN server; operators use the public portal."
      : "The VPN server follows Access mode.";
    out = {
      ...out,
      items: { ...out.items, enum: out.items.enum.filter((v) => v !== "wireguard" && v !== "openvpn") },
      "x-ui-note": vpn,
      "x-ui-unknown-title": () => `Ignored. ${vpn}`,
    };
  }
  if (path === "services" && RANGE_HOST_KINDS.has(ctx.kind)) {
    out = {
      ...out,
      items: { ...(out.items || {}), enum: ctx.kind === "srv" ? RANGE_SERVICES : [] },
      "x-ui-unknown-title": unknownServiceTitle,
    };
  }

  const reason = unusedReason(path, ctx);
  if (reason) {
    if (isEmptyValue(value, def)) return { spec: out, hide: true };
    return { spec: out, ignored: reason };
  }
  return { spec: out, locked };
}

// ----------------------------------------------------------------- placeholders

const IPV4 = "^([0-9]{1,3}\\.){3}[0-9]{1,3}$";
const CIDR = "^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$";

// Plain reasons and examples for the schema's patterns, so a miss reads as a
// sentence rather than a regex.
const PATTERNS = {
  "^[a-z0-9][a-z0-9-]*$": {
    reason: "use lowercase letters, digits and hyphens, starting with a letter or digit",
    example: "main-net01",
  },
  [CIDR]: { reason: "use an address range in CIDR form", example: "10.30.0.0/16" },
  [IPV4]: { reason: "use an IPv4 address", example: "10.30.10.5" },
  "^[A-Za-z][A-Za-z0-9-]*$": {
    reason: "use letters, digits and hyphens, starting with a letter",
    example: "X-Request-Id",
  },
  "^[a-z][a-z0-9]{0,7}$": {
    reason: "use 1 to 8 lowercase letters or digits, starting with a letter",
    example: "off",
  },
  "^([01][0-9]|2[0-3]):[0-5][0-9]$": { reason: "use a 24 hour time, HH:MM", example: "18:00" },
  "^[a-z0-9][a-z0-9._-]*$": {
    reason: "use lowercase letters, digits, dot, underscore or hyphen, starting with a letter or digit",
    example: "j.smith",
  },
  "^[^\\r\\n|]+$": { reason: "use a single line with no pipe character", example: "lead" },
  "^/[a-z0-9][a-z0-9/_-]*$": {
    reason: "start with a slash, then lowercase letters, digits, slash, underscore or hyphen",
    example: "/cdn/assets",
  },
};

const DEF_EXAMPLES = { ipv4: "10.30.10.5", cidr: "10.30.0.0/16", identifier: "main-net01" };

export function exampleFor(spec) {
  if (!spec) return undefined;
  if (Array.isArray(spec.examples) && spec.examples.length) return spec.examples[0];
  return PATTERNS[spec.pattern]?.example ?? DEF_EXAMPLES[spec["x-ui-def"]];
}

// Grey hint text for a text box: the value the compiler fills in, else the
// schema's hint, else an example. Never the raw pattern.
export function placeholderFor(path, spec, ctx) {
  const def = defaultFor(path, spec, ctx);
  if (def != null && def !== "") return `${def} (default)`;
  if (spec?.["x-redstackpro-placeholder"]) return spec["x-redstackpro-placeholder"];
  const example = exampleFor(spec);
  return example != null ? `e.g. ${example}` : "";
}

// Help for a number field the schema gives none for.
export function numberHelp(spec, def) {
  const parts = [];
  const { minimum: min, maximum: max } = spec || {};
  if (min != null && max != null) parts.push(`A number from ${min} to ${max}.`);
  else if (min != null) parts.push(`A number, at least ${min}.`);
  else if (max != null) parts.push(`A number, at most ${max}.`);
  if (def != null) parts.push(`Empty uses ${def}.`);
  return parts.join(" ");
}

// ----------------------------------------------------------------- checks

function sentence(label, reason, example) {
  return `${label}: ${reason}.${example != null ? ` Example: ${example}.` : ""}`;
}

function testPattern(pattern, value) {
  try {
    return new RegExp(pattern, "u").test(value);
  } catch {
    return true;
  }
}

function addressReason(spec, value) {
  const isCidr = spec["x-ui-def"] === "cidr" || spec.pattern === CIDR;
  const isIp = spec["x-ui-def"] === "ipv4" || spec.pattern === IPV4;
  if (!isCidr && !isIp) return null;
  const [addr, prefix] = value.split("/");
  if (addr.split(".").some((o) => Number(o) > 255)) return "each of the four numbers must be 0 to 255";
  if (isCidr && Number(prefix) > 32) return "the number after the slash must be 0 to 32";
  return null;
}

// A plain message when a value misses the schema's pattern, bounds or choices,
// in the server's style: "{label}: {reason}. Example: {example}." Null if fine.
export function checkValue(label, spec, value, display = String) {
  if (!spec || value == null || value === "") return null;
  if (spec.enum) {
    return spec.enum.includes(value)
      ? null
      : `${label}: ${display(value)} is not one of the choices here. Pick one from the list.`;
  }
  const example = exampleFor(spec);
  if (spec.type === "integer" || spec.type === "number") {
    if (typeof value !== "number" || Number.isNaN(value)) return sentence(label, "use a number", spec.default ?? example);
    if (spec.type === "integer" && !Number.isInteger(value)) {
      return sentence(label, "use a whole number", spec.default ?? example);
    }
    const { minimum: min, maximum: max } = spec;
    if ((min != null && value < min) || (max != null && value > max)) {
      const range = min != null && max != null ? `from ${min} to ${max}` : min != null ? `of at least ${min}` : `of at most ${max}`;
      return sentence(label, `use a number ${range}`, spec.default ?? example);
    }
    return null;
  }
  if (spec.type === "array" && Array.isArray(value)) {
    if (spec.minItems && value.length < spec.minItems) {
      return sentence(label, `pick at least ${spec.minItems}`);
    }
    return null;
  }
  if (typeof value !== "string") return null;
  if (spec.minLength && value.length < spec.minLength) {
    return sentence(label, `use at least ${spec.minLength} characters`, example);
  }
  if (spec.maxLength && value.length > spec.maxLength) {
    return sentence(label, `use at most ${spec.maxLength} characters`, example);
  }
  if (spec.pattern && !testPattern(spec.pattern, value)) {
    return sentence(label, PATTERNS[spec.pattern]?.reason ?? "this is not in the expected format", example);
  }
  const address = addressReason(spec, value);
  if (address) return sentence(label, address, example);
  return null;
}

// Server findings that name a field on the node, as {field, message}. The path
// is relative to the overlay; a leading "overlay." is tolerated.
export function fieldFindings(findings) {
  return (findings || [])
    .filter((f) => typeof f?.field === "string" && f.field)
    .map((f) => ({ field: f.field.replace(/^overlay\./, ""), message: f.message, severity: f.severity }));
}

// The findings that belong to the field at `path`. A leaf also takes findings
// on anything under it (an array item), a fieldset only its own.
export function findingsAt(list, path, leafField = true) {
  return (list || []).filter(
    (f) => f.field === path || (leafField && f.field.startsWith(`${path}.`))
  );
}
