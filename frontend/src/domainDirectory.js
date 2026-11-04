// The principals a domain will hold once it is built, read off the topology:
// its users, the groups they and the nesting name, the computers joined to it,
// its gMSAs and OUs. The Inspector's domain editors offer these as choices and
// flag a name that is not among them. Names compare without case, as AD does.

// Groups every domain has after promotion. Enterprise Admins and Schema Admins
// exist only in a forest root; they are offered everywhere for simplicity.
export const BUILTIN_GROUPS = [
  "Domain Admins",
  "Domain Users",
  "Domain Computers",
  "Domain Controllers",
  "Domain Guests",
  "Enterprise Admins",
  "Schema Admins",
  "Administrators",
  "Account Operators",
  "Backup Operators",
  "Server Operators",
  "Print Operators",
  "Remote Desktop Users",
  "Remote Management Users",
  "Group Policy Creator Owners",
  "DnsAdmins",
  "Protected Users",
  "Cert Publishers",
  "Key Admins",
];

const lower = (s) => (s || "").toLowerCase();
const isBuiltin = (g) => BUILTIN_GROUPS.some((b) => lower(b) === lower(g));

function uniqueSorted(list) {
  const out = new Map();
  for (const item of list) {
    if (item && !out.has(lower(item))) out.set(lower(item), item);
  }
  return [...out.values()].sort((a, b) => a.localeCompare(b));
}

// Hosts joined to this domain, with the Windows computer name the compiler
// uses (hostname, else the node id).
export function joinedHosts(document, domainId) {
  return (document?.edges || [])
    .filter((e) => e.role === "joins" && e.target === domainId)
    .map((e) => document.nodes.find((n) => n.id === e.source))
    .filter(Boolean)
    .map((n) => ({ id: n.id, kind: n.kind, name: n.overlay?.hostname || n.id }));
}

// Groups this domain defines itself: every group a user is in plus every
// group the nesting names. The dc role creates each one.
export function customGroups(overlay) {
  const ov = overlay || {};
  const names = [];
  for (const u of ov.users || []) names.push(...(u.groups || []));
  const nesting = ov.group_members && typeof ov.group_members === "object" ? ov.group_members : {};
  for (const [parent, members] of Object.entries(nesting)) {
    names.push(parent);
    if (Array.isArray(members)) names.push(...members);
  }
  return uniqueSorted(names.filter((g) => !isBuiltin(g)));
}

// Built-ins first, then the domain's own groups.
export function allGroups(overlay) {
  return [...BUILTIN_GROUPS, ...customGroups(overlay)];
}

export function domainDn(fqdn) {
  return (fqdn || "")
    .split(".")
    .filter(Boolean)
    .map((p) => `DC=${p}`)
    .join(",");
}

export function domainDirectory(document, domainNode) {
  const ov = domainNode?.overlay || {};
  const hosts = joinedHosts(document, domainNode?.id);
  return {
    fqdn: ov.fqdn || "",
    users: uniqueSorted((ov.users || []).map((u) => u.username)),
    builtins: BUILTIN_GROUPS,
    groups: customGroups(ov),
    hosts,
    computers: uniqueSorted(hosts.map((h) => `${h.name}$`)),
    gmsa: uniqueSorted((Array.isArray(ov.gmsa) ? ov.gmsa : []).map((g) => g?.name && `${g.name}$`)),
    ous: uniqueSorted(Array.isArray(ov.ous) ? ov.ous : []),
  };
}

// Every name an ACL principal can resolve to, with what it is.
export function principalChoices(dir) {
  return [
    ...dir.users.map((value) => ({ value, kind: "user" })),
    ...dir.builtins.map((value) => ({ value, kind: "built-in group" })),
    ...dir.groups.map((value) => ({ value, kind: "group" })),
    ...dir.computers.map((value) => ({ value, kind: "computer" })),
    ...dir.gmsa.map((value) => ({ value, kind: "gMSA" })),
  ];
}

// Targets add the OUs, as distinguished names, which apply_acls.ps1 resolves
// directly.
export function targetChoices(dir) {
  const base = domainDn(dir.fqdn);
  return [
    ...principalChoices(dir),
    ...dir.ous.map((ou) => ({ value: base ? `OU=${ou},${base}` : ou, kind: "OU" })),
  ];
}

const known = (choices, name) => choices.some((c) => lower(c.value) === lower(name));
const isDn = (name) => /^(CN|OU|DC)=/i.test(name || "");

// What apply_acls.ps1 does with a principal name: a DOMAIN\name form is
// resolved as an account, a name it cannot find is created as a new, empty
// group. "known" or "created".
export function principalStatus(dir, name) {
  if (!name) return "known";
  if (name.includes("\\")) return "known";
  return known(principalChoices(dir), name) ? "known" : "created";
}

// And with a target: a distinguished name is used as written, a computer
// name (ending in $) it cannot find is skipped, and any other unknown name is
// created as a new, empty group first. "known", "dn", "skipped" or "created".
export function targetStatus(dir, name) {
  if (!name) return "known";
  if (isDn(name)) return "dn";
  if (known(targetChoices(dir), name) || dir.ous.some((o) => lower(o) === lower(name))) {
    return "known";
  }
  if (name.endsWith("$") || name.includes("\\")) return "skipped";
  return "created";
}

export function groupKnown(overlay, name) {
  return allGroups(overlay).some((g) => lower(g) === lower(name));
}
