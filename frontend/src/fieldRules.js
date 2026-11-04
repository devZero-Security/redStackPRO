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
