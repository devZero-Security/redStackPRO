// The rules behind the Inspector's generated overlay forms: $ref resolution,
// labels for fields and options, the default an empty field compiles to, which
// fields mean nothing for a given node, and client-side value checks. Pure, so
// each rule is testable without rendering. Inspector.jsx Field consumes these.
//
// Defaults here mirror the compiler, not the schema alone: a dc with no os
// builds Windows Server 2022 (a wks Windows 11), a dc with no hostname is named
// after its id, and a domain with no netbios takes its first fqdn label uppercased.

import { PROFILES } from "./profiles.js";
import { aKind } from "./edgeRoles.js";

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
  c2: { mythic: "Mythic", sliver: "Sliver", adaptix: "Adaptix", none: "None (plain Debian host)" },
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
  windows_10: "Windows 10 (past end of support)",
  windows_11: "Windows 11",
  linux: "Linux (Debian 13)",
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
  nginx: "Nginx",
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

const OS_HELP = {
  windows_10:
    "Microsoft ended Windows 10 support on 2025-10-14. Kept for labs that need it. " +
    "GCP and AWS boot Windows Server 2022 for it.",
  windows_11: "GCP and AWS have no Windows client image, so it boots Windows Server 2022 there.",
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
      // plan.DEFAULT_WINDOWS_OS
      if (ctx.kind === "wks") return "windows_11";
      if (AD_KINDS.has(ctx.kind)) return "windows_server_2022";
      if (LINUX_ONLY_KINDS.has(ctx.kind)) return "debian_13";
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
  "vulns", "vulns_vars", "hardening", "role", "edr",
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
    : { value: false, reason: `${aKind(ctx.kind).replace(/^a/, "A")} never takes a public address. Reach it through the jumpbox.` };
}

// The services values something installs on this host. Mirrors
// redstackpro.validate._services_acted_on, so a chip reads dead exactly when
// SVC001 warns on it: mssql, iis and exchange on a Windows srv, plus adcs and
// mecm when the Role field installs them.
export function servicesActedOn(ctx) {
  const windows = isWindowsHost(ctx);
  const acted = new Set(ctx.kind === "srv" && windows ? RANGE_SERVICES : []);
  const role = ctx.overlay?.role;
  if (role === "adcs" && (ctx.kind === "dc" || ctx.kind === "srv") && windows) acted.add("adcs");
  if (role === "mecm" && ctx.kind === "srv" && windows) acted.add("mecm");
  return acted;
}

// SVC001's remedy for a value nothing installs.
function serviceRemedy(value) {
  if (value === "adcs") return "Set Role to AD CS on a Windows dc or srv to stand up the CA.";
  if (value === "mecm") return "Set Role to MECM on a Windows member server.";
  if (RANGE_SERVICES.includes(value)) return "Put it on a Windows member server (srv).";
  return "Remove it. The services that install are mssql, iis and exchange on a Windows member server; for a file share add the Open share vuln.";
}

// How a stored services value outside the checklist shows: installed by the
// role, or dead with the reason. {text, title, dead}.
export function serviceChip(ctx, value) {
  if (servicesActedOn(ctx).has(value)) {
    const role = optionLabel("role", ctx.overlay?.role);
    return { text: `${value} (installed by Role: ${role})`, title: `Role ${role} installs this.`, dead: false };
  }
  return { text: value, title: `${value} installs nothing on this host. ${serviceRemedy(value)}`, dead: true };
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
  if (path === "os" && out.enum) out = { ...out, "x-ui-option-help": OS_HELP };

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
      "x-ui-chip": (v) => ({ text: optionLabel("services", v), title: `Ignored. ${vpn}`, dead: true }),
    };
  }
  if (path === "services" && RANGE_HOST_KINDS.has(ctx.kind)) {
    const checklist = ctx.kind === "srv" && isWindowsHost(ctx) ? RANGE_SERVICES : [];
    out = {
      ...out,
      items: { ...(out.items || {}), enum: checklist },
      "x-ui-chip": (v) => serviceChip(ctx, v),
      ...(checklist.length ? {} : { "x-ui-note": "Only a Windows member server (srv) installs from this list." }),
    };
    if (!checklist.length && isEmptyValue(value)) return { spec: out, hide: true };
  }

  const reason = unusedReason(path, ctx);
  if (reason) {
    if (isEmptyValue(value, def)) return { spec: out, hide: true };
    return { spec: out, ignored: reason };
  }
  return { spec: out, locked };
}

// ----------------------------------------------------------------- placeholders

const OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
// The address patterns, strict (0.7.0 now) and loose (older schemas).
const IPV4 = `^(${OCTET}\\.){3}${OCTET}$`;
const CIDR = `^(${OCTET}\\.){3}${OCTET}/(3[0-2]|[12]?[0-9])$`;
const IPV4_LOOSE = "^([0-9]{1,3}\\.){3}[0-9]{1,3}$";
const CIDR_LOOSE = "^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$";

const IP_REASON = { reason: "must be an IPv4 address", example: "10.30.10.5" };
const CIDR_REASON = { reason: "must be an IPv4 address range in CIDR form", example: "10.30.10.0/24" };

// Plain reasons and examples for the schema's patterns, so a miss reads as a
// sentence rather than a regex. Worded as the server's table
// (redstackpro.schemacheck.PATTERNS) so the inline message and the SCH001
// finding say the same thing; fields.test.jsx fails on a schema pattern
// missing here.
const PATTERNS = {
  "^[a-z0-9][a-z0-9-]*$": {
    reason: "must be lowercase letters, digits and hyphens, starting with a letter or digit",
    example: "myth-ts01",
  },
  [CIDR]: CIDR_REASON,
  [CIDR_LOOSE]: CIDR_REASON,
  [IPV4]: IP_REASON,
  [IPV4_LOOSE]: IP_REASON,
  "^[a-z][a-z0-9]{0,7}$": {
    reason: "must be 1 to 8 lowercase letters or digits, starting with a letter",
    example: "off",
  },
  "^[A-Za-z0-9][A-Za-z0-9-]{0,14}$": {
    reason: "must be 1 to 15 letters, digits or hyphens, starting with a letter or digit",
    example: "kingslanding",
  },
  "^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]$": {
    reason: "must be a domain name with no scheme, path or port",
    example: "cdn.example.net",
  },
  "^[A-Za-z][A-Za-z0-9-]*$": {
    reason: "must be letters, digits and hyphens, starting with a letter",
    example: "X-Request-Id",
  },
  "^([01][0-9]|2[0-3]):[0-5][0-9]$": { reason: "must be a 24 hour time, HH:MM", example: "20:00" },
  "^[a-z0-9][a-z0-9._-]*$": {
    reason: "must be lowercase letters, digits, dot, underscore or hyphen, starting with a letter or digit",
    example: "j.smith",
  },
  "^[^\\r\\n|]+$": { reason: "must be a single line with no pipe character", example: "lead" },
  "^/[a-z0-9][a-z0-9/_-]*$": {
    reason: "must start with a slash, then lowercase letters, digits, slash, underscore or hyphen",
    example: "/cdn/assets",
  },
};

export function patternInfo(pattern) {
  return PATTERNS[pattern];
}

const DEF_EXAMPLES = { ipv4: IP_REASON.example, cidr: CIDR_REASON.example, identifier: "myth-ts01" };

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

function addressKind(spec) {
  if (spec["x-ui-def"] === "cidr" || spec.pattern === CIDR || spec.pattern === CIDR_LOOSE) return "cidr";
  if (spec["x-ui-def"] === "ipv4" || spec.pattern === IPV4 || spec.pattern === IPV4_LOOSE) return "ipv4";
  return null;
}

// The most specific thing wrong with an address, as [reason, example], or null.
// A strict pattern alone would only say "must be an IPv4 address" for
// 10.30.10.300, which hides that one number is out of range.
function addressProblem(kind, value) {
  const base = kind === "cidr" ? CIDR_REASON : IP_REASON;
  const m = (kind === "cidr" ? /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/ : /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/).exec(value);
  if (!m) return [base.reason, base.example];
  const octets = m.slice(1, 5).map(Number);
  if (octets.some((o) => o > 255)) return ["each of the four numbers must be 0 to 255", base.example];
  if (m.slice(1, 5).some((o) => o.length > 1 && o.startsWith("0"))) {
    return ["a number must not start with 0", base.example];
  }
  if (kind !== "cidr") return null;
  const prefix = Number(m[5]);
  if (prefix > 32) return ["the number after the slash must be 0 to 32", base.example];
  // The clouds take a network address only (schemacheck does the same).
  const ip = octets.reduce((n, o) => n * 256 + o, 0);
  const size = 2 ** (32 - prefix);
  const network = ip - (ip % size);
  if (network !== ip) {
    const parts = [24, 16, 8, 0].map((shift) => Math.floor(network / 2 ** shift) % 256);
    return [`${value} has bits set past its mask, so it is not a network address`, `${parts.join(".")}/${prefix}`];
  }
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
    const sample = spec.default ?? example;
    if (typeof value !== "number" || Number.isNaN(value)) return sentence(label, "must be a number", sample);
    if (spec.type === "integer" && !Number.isInteger(value)) {
      return sentence(label, "must be a whole number", sample);
    }
    const { minimum: min, maximum: max } = spec;
    if ((min != null && value < min) || (max != null && value > max)) {
      const isPort = min === 1 && max === 65535;
      const range = isPort
        ? "must be a port from 1 to 65535"
        : min != null && max != null
          ? `must be from ${min} to ${max}`
          : min != null ? `must be at least ${min}` : `must be at most ${max}`;
      return sentence(label, range, sample ?? (isPort ? 443 : undefined));
    }
    return null;
  }
  if (spec.type === "array" && Array.isArray(value)) {
    if (spec.minItems && value.length < spec.minItems) {
      const n = spec.minItems;
      return sentence(label, `must list at least ${n === 1 ? "one entry" : `${n} entries`}`);
    }
    return null;
  }
  if (typeof value !== "string") return null;
  if (spec.minLength && value.length < spec.minLength) {
    return sentence(label, spec.minLength === 1 ? "must not be empty" : `must be at least ${spec.minLength} characters`, example);
  }
  if (spec.maxLength && value.length > spec.maxLength) {
    return sentence(label, `must be at most ${spec.maxLength} characters`, example);
  }
  const address = addressKind(spec);
  if (address) {
    const problem = addressProblem(address, value);
    if (problem) return sentence(label, problem[0], problem[1]);
  }
  if (spec.pattern && !testPattern(spec.pattern, value)) {
    return sentence(label, PATTERNS[spec.pattern]?.reason ?? "does not have the expected format", example);
  }
  return null;
}

// Server findings that name a field on the node, as {field, message}. The path
// is relative to the overlay; a leading "overlay." is tolerated.
export function fieldFindings(findings) {
  return (findings || [])
    .filter((f) => typeof f?.field === "string" && f.field)
    .map((f) => ({ field: f.field.replace(/^overlay\./, ""), message: f.message, severity: f.severity }));
}

// A warning or an info finding: shown at its field, but it does not mark the
// field invalid.
export const isNotice = (f) => f?.severity === "warning" || f?.severity === "info";

// The findings that belong to the field at `path`. A leaf also takes findings
// on anything under it (an array item), a fieldset only its own.
export function findingsAt(list, path, leafField = true) {
  return (list || []).filter(
    (f) => f.field === path || (leafField && f.field.startsWith(`${path}.`))
  );
}
