// The vulnerability settings form: what each VULN_PARAMS key offers, drawn from
// the topology, and the format it writes, which is the one the role reading
// the key uses (see PICKS). Choices are [{label, options: [{value, label?,
// about?}]}], one group per domain or list.
import { VULN_CATALOG, VULN_LABEL, VULN_PARAMS } from "./vulns.js";
import { BUILTIN_GROUPS, customGroups, domainDn, joinedHosts } from "./domainDirectory.js";
import {
  hostDomain, isWindowsHost, runsSql, spnChoices, spnOptionGroups, withDelegationDefault,
} from "./spnChoices.js";

const lower = (s) => String(s ?? "").toLowerCase();

function uniqueSorted(list) {
  const out = new Map();
  for (const item of list) if (item && !out.has(lower(item))) out.set(lower(item), item);
  return [...out.values()].sort((a, b) => a.localeCompare(b));
}

export const isPlainObject = (v) => !!v && typeof v === "object" && !Array.isArray(v);

// What each pick writes, in the words the form shows when a value is typed.
// The role that reads the key decides the format:
//   domain_user  DOMAIN\user. Register-ScheduledTask -User, cmdkey /user and
//                NTAccount all resolve it, and the compiler keys every
//                per-user password by it (ansible.py redstackpro_user_passwords).
//   bare_user    the sAMAccountName. Set-GPPermission -TargetName, the ESC14
//                sAMAccountName search and the KeePass entry take it bare.
//   principal    a user as DOMAIN\user, a group by name (ESC5 NTAccount).
//   group        the group name: plant_esc13.ps1 matches cn= and creates it.
//   sql_hosts    host.fqdn, the linked server name and its data source.
//   termsrv      TERMSRV/host, the cmdkey /add target.
//   ou           a distinguished name, the New-GPLink -Target.
export const PICKS = {
  spns: "SERVICE/host.fqdn, one SPN per entry",
  domain_user: "DOMAIN\\user",
  bare_user: "the user name alone, without a domain",
  principal: "DOMAIN\\user for a user, the name alone for a group",
  group: "the group name",
  ou: "a distinguished name, e.g. OU=Servers,DC=corp,DC=local",
  fs_rights: "an NTFS right, e.g. Modify",
  termsrv: "TERMSRV/host",
  sql_hosts: "host.fqdn",
  linked_logins: "rows of {target, remote_user, remote_password}",
  execas_logins: "rows of {login, target}",
  execas_users: "rows of {user, db, impersonate}",
};

// The rights win_acl takes, the FileSystemRights names (writable_share.yml).
export const FS_RIGHTS = [
  { value: "FullControl", about: "read, write, delete and change permissions" },
  { value: "Modify", about: "read, write and delete" },
  { value: "Write", about: "create and write files" },
  { value: "ReadAndExecute", about: "read and run" },
  { value: "Read", about: "read only" },
];

// The ESC parameters the compiler gathers to the CA from any host in the
// domain (ansible.py _adcs_forest_escs), so one set elsewhere counts here.
export const DOMAIN_WIDE_KEYS = new Set([
  "esc7_manager", "esc13_group", "esc5_principal", "esc14_target", "esc14_subject",
]);

const nodeById = (document, id) => (document?.nodes || []).find((n) => n.id === id);

// The Windows computer name the compiler uses: hostname, else the node id.
export const hostName = (node) => node?.overlay?.hostname || node?.id || "";

// The NetBIOS name the compiler gives a domain: its own, else the first fqdn
// label uppercased, 15 at most (ansible.py _netbios_default).
export function netbiosOf(domainNode) {
  const ov = domainNode?.overlay || {};
  if (ov.netbios) return ov.netbios;
  return ov.fqdn ? ov.fqdn.split(".")[0].toUpperCase().slice(0, 15) : "";
}

// Domains with a name to qualify by, the host's own first.
function rangeDomains(document, firstId) {
  const all = (document?.nodes || []).filter(
    (n) => n.kind === "domain" && (n.overlay?.fqdn || n.overlay?.netbios)
  );
  return [...all.filter((d) => d.id === firstId), ...all.filter((d) => d.id !== firstId)];
}

const domainTitle = (d) => d.overlay?.fqdn || netbiosOf(d);
const usernames = (d) => uniqueSorted((d.overlay?.users || []).map((u) => u?.username));
const ownDomain = (document, hostId) => nodeById(document, hostDomain(document, hostId));

// Every domain's users as DOMAIN\user, grouped by domain.
export function domainUserChoices(document, hostId) {
  return rangeDomains(document, hostDomain(document, hostId))
    .map((d) => {
      const nb = netbiosOf(d);
      return { label: domainTitle(d), options: usernames(d).map((u) => ({ value: `${nb}\\${u}` })) };
    })
    .filter((g) => g.options.length);
}

// The users of the host's own domain, by name alone: the role resolves a bare
// name in the domain it runs in.
export function bareUserChoices(document, hostId) {
  const d = ownDomain(document, hostId);
  if (!d) return [];
  const options = usernames(d).map((u) => ({ value: u }));
  return options.length ? [{ label: domainTitle(d), options }] : [];
}

// The host's domain groups, its own first, then the built-ins.
export function groupChoices(document, hostId) {
  const d = ownDomain(document, hostId);
  if (!d) return [];
  const own = customGroups(d.overlay).map((g) => ({ value: g }));
  return [
    ...(own.length ? [{ label: `Groups on ${domainTitle(d)}`, options: own }] : []),
    { label: "Built-in groups", options: BUILTIN_GROUPS.map((g) => ({ value: g })) },
  ];
}

// ESC5 takes a user or a group: users qualified, groups by name.
export function userOrGroupChoices(document, hostId) {
  const d = ownDomain(document, hostId);
  if (!d) return [];
  const nb = netbiosOf(d);
  const users = usernames(d).map((u) => ({ value: `${nb}\\${u}` }));
  return [
    ...(users.length ? [{ label: `Users on ${domainTitle(d)}`, options: users }] : []),
    ...groupChoices(document, hostId),
  ];
}

// The host's domain OUs as the distinguished names the dc role creates them
// at (OU=<name> under the domain root).
export function ouChoices(document, hostId) {
  const d = ownDomain(document, hostId);
  const fqdn = d?.overlay?.fqdn;
  if (!fqdn) return [];
  const base = domainDn(fqdn);
  const ous = uniqueSorted(Array.isArray(d.overlay.ous) ? d.overlay.ous : []);
  if (!ous.length) return [];
  return [{ label: `OUs on ${fqdn}`, options: ous.map((ou) => ({ value: `OU=${ou},${base}`, label: ou })) }];
}

// Every Windows host running SQL Server, in any domain, so a link can cross a
// forest trust: [{id, name, domainId, fqdn, fq}].
export function sqlHosts(document) {
  const out = [];
  for (const d of rangeDomains(document)) {
    const fqdn = d.overlay?.fqdn;
    if (!fqdn) continue;
    for (const h of joinedHosts(document, d.id)) {
      const node = nodeById(document, h.id);
      if (!isWindowsHost(node) || !runsSql(node)) continue;
      out.push({ id: h.id, name: h.name, domainId: d.id, fqdn, fq: `${h.name}.${fqdn}` });
    }
  }
  return out;
}

// SQL hosts to link to, grouped by domain, the host's own first. The host
// itself is offered last, as a loopback link (NHA links its SQL host to itself).
export function sqlHostChoices(document, hostId) {
  const hosts = sqlHosts(document);
  const own = hostDomain(document, hostId);
  return rangeDomains(document, own)
    .map((d) => {
      const here = hosts.filter((h) => h.domainId === d.id);
      const others = here.filter((h) => h.id !== hostId);
      const self = here.filter((h) => h.id === hostId);
      return {
        label: domainTitle(d),
        options: [
          ...others.map((h) => ({ value: h.fq, label: h.name, about: "SQL Server" })),
          ...self.map((h) => ({ value: h.fq, label: `${h.name} (this host)`, about: "a loopback link to this host" })),
        ],
      };
    })
    .filter((g) => g.options.length);
}

// The linked servers filled in when mssql_linked is ticked: every other SQL host.
export function defaultLinkedTargets(document, hostId) {
  return sqlHosts(document).filter((h) => h.id !== hostId).map((h) => h.fq);
}

// Hosts a TERMSRV credential can name: the host's own domain by computer
// name, as GOAD writes it, other domains by FQDN.
export function termsrvChoices(document, hostId) {
  const own = hostDomain(document, hostId);
  return rangeDomains(document, own)
    .map((d) => {
      const fqdn = d.overlay?.fqdn;
      const mine = d.id === own;
      const options = mine || fqdn
        ? joinedHosts(document, d.id)
            .filter((h) => isWindowsHost(nodeById(document, h.id)))
            .map((h) => ({
              value: mine ? h.name : `${h.name}.${fqdn}`,
              label: h.id === hostId ? `${h.name} (this host)` : undefined,
            }))
        : [];
      return { label: domainTitle(d), options };
    })
    .filter((g) => g.options.length);
}

// The rows a login list row picks from.
const SQL_LOGINS = { label: "SQL logins", options: [{ value: "sa", about: "the SQL sysadmin" }] };
const SYSTEM_DBS = { label: "System databases", options: [{ value: "master" }, { value: "msdb" }] };

// The columns of each row editor: {field, label, required, pick?, choices?,
// initial?, placeholder?, multiline?}. `describe` reads a row back in one line.
export function rowColumns(kind, document, hostId, vars) {
  if (kind === "linked_logins") {
    const targets = Array.isArray(vars?.mssql_linked_targets) ? vars.mssql_linked_targets : [];
    return [
      {
        field: "target", label: "linked server", required: true,
        choices: targets.length ? [{ label: "Linked servers", options: targets.map((t) => ({ value: t })) }] : [],
        placeholder: "host.fqdn of a linked server",
      },
      { field: "remote_user", label: "remote login", placeholder: "sa (default)" },
      { field: "remote_password", label: "remote password", placeholder: "the lab password (default)" },
    ];
  }
  if (kind === "execas_logins") {
    return [
      { field: "login", label: "login", required: true, choices: domainUserChoices(document, hostId), placeholder: "DOMAIN\\user" },
      {
        field: "target", label: "may impersonate", required: true, initial: "sa",
        choices: [SQL_LOGINS, ...domainUserChoices(document, hostId)], placeholder: "sa or DOMAIN\\user",
      },
    ];
  }
  if (kind === "execas_users") {
    return [
      { field: "user", label: "user", required: true, choices: domainUserChoices(document, hostId), placeholder: "DOMAIN\\user" },
      { field: "db", label: "database", required: true, choices: [SYSTEM_DBS], placeholder: "database name" },
      { field: "impersonate", label: "may impersonate", placeholder: "dbo (default)" },
    ];
  }
  if (kind === "files") {
    return [
      { field: "name", label: "file name", required: true, placeholder: "notes.txt" },
      { field: "content", label: "content", multiline: true, placeholder: "file text" },
    ];
  }
  return [];
}

export function describeRow(kind, row) {
  const r = isPlainObject(row) ? row : {};
  if (kind === "linked_logins") return `${r.target || "?"} as ${r.remote_user || "sa"}`;
  if (kind === "execas_logins") return `${r.login || "?"} may impersonate ${r.target || "?"}`;
  if (kind === "execas_users") return `${r.user || "?"} may impersonate ${r.impersonate || "dbo"} in ${r.db || "?"}`;
  if (kind === "files") return r.name || "?";
  return JSON.stringify(row);
}

export const ROW_KINDS = new Set(["linked_logins", "execas_logins", "execas_users", "files"]);
export const rowKind = (param) => (ROW_KINDS.has(param.pick) ? param.pick : ROW_KINDS.has(param.input) ? param.input : null);

// What a pick offers on this host.
export function choicesFor(pick, document, hostId) {
  switch (pick) {
    case "domain_user": return domainUserChoices(document, hostId);
    case "bare_user": return bareUserChoices(document, hostId);
    case "principal": return userOrGroupChoices(document, hostId);
    case "group": return groupChoices(document, hostId);
    case "ou": return ouChoices(document, hostId);
    case "fs_rights": return [{ label: "NTFS rights", options: FS_RIGHTS }];
    case "termsrv": return termsrvChoices(document, hostId);
    case "sql_hosts": return sqlHostChoices(document, hostId);
    case "spns":
      return spnOptionGroups(spnChoices(document, hostDomain(document, hostId), { exclude: hostId }));
    default: return [];
  }
}

// The option a value names, matched without case (a blueprint may write
// north\robb.stark where the picker offers NORTH\robb.stark).
export function matchOption(groups, value) {
  if (value == null || value === "") return null;
  for (const g of groups) for (const o of g.options) if (lower(o.value) === lower(value)) return o;
  return null;
}

// A nested key read and written on its dots. Writing an empty value removes
// the key, and a parent left empty goes with it; undefined when nothing is left.
export function getVar(vars, key) {
  let at = vars;
  for (const part of key.split(".")) {
    if (!isPlainObject(at)) return undefined;
    at = at[part];
  }
  return at;
}

const isEmpty = (v) => v == null || v === "" || (Array.isArray(v) && !v.length);

export function setVar(vars, key, value) {
  const [head, ...rest] = key.split(".");
  const base = isPlainObject(vars) ? { ...vars } : {};
  const next = rest.length ? setVar(base[head], rest.join("."), value) : value;
  if (isEmpty(next)) delete base[head];
  else base[head] = next;
  return Object.keys(base).length ? base : undefined;
}

// The ticked vulns that read settings, in catalog order, each with the keys it
// shows. A key two vulns read (bot_user) shows once, under the first; the other
// lists it in `shared` with the vuln it shows under. A vuln in `elsewhere` (the
// User activity ids) is marked so: its keys are edited there, not in the form,
// but still count as the form's for the JSON view.
export function formSections(vulns, elsewhere = null) {
  const ticked = new Set(vulns || []);
  const seen = new Map();
  const out = [];
  for (const id of VULN_CATALOG.flatMap((g) => g.items.map((i) => i.id))) {
    if (!ticked.has(id) || !VULN_PARAMS[id]) continue;
    const params = [];
    const shared = [];
    for (const p of VULN_PARAMS[id]) {
      if (seen.has(p.key)) {
        shared.push({ key: p.key, under: seen.get(p.key) });
        continue;
      }
      seen.set(p.key, VULN_LABEL[id]);
      params.push(p);
    }
    out.push({ vuln: id, label: VULN_LABEL[id], params, shared, elsewhere: !!elsewhere?.has(id) });
  }
  return out;
}

// The keys the form shows for these vulns, and the top-level keys of vars it
// does not, which stay in the JSON only.
export function formKeys(vulns) {
  return new Set(formSections(vulns).flatMap((s) => s.params.map((p) => p.key)));
}

export function keysOutsideForm(vulns, vars) {
  if (!isPlainObject(vars)) return [];
  const heads = new Set([...formKeys(vulns)].map((k) => k.split(".")[0]));
  return Object.keys(vars).filter((k) => !heads.has(k));
}

// A domain-wide ESC key set on another host in this host's domain:
// {host, value} for the first one found, else null.
export function setElsewhere(document, hostId, key) {
  if (!DOMAIN_WIDE_KEYS.has(key)) return null;
  const domainId = hostDomain(document, hostId);
  if (!domainId) return null;
  for (const h of joinedHosts(document, domainId)) {
    if (h.id === hostId) continue;
    const value = getVar(nodeById(document, h.id)?.overlay?.vulns_vars, key);
    if (!isEmpty(value)) return { host: h.name, value };
  }
  return null;
}

// A host's overlay with the obvious settings filled in for a vuln just ticked:
// delegate_to (withDelegationDefault), the other SQL hosts as linked servers,
// and TERMSRV/<this host> as the stored credential target. A key already set
// is kept, and nothing is refilled once the vuln was ticked before. Settings
// that are not an object are left for the person to fix.
export function withVulnDefaults(document, node, overlay) {
  if (overlay?.vulns_vars != null && !isPlainObject(overlay.vulns_vars)) return overlay;
  const next = withDelegationDefault(document, node, overlay);
  const was = node?.overlay?.vulns || [];
  const now = next?.vulns || [];
  const newly = (id) => now.includes(id) && !was.includes(id);
  let vars = next.vulns_vars;
  if (newly("mssql_linked") && isEmpty(getVar(vars, "mssql_linked_targets"))) {
    const targets = defaultLinkedTargets(document, node.id);
    if (targets.length) vars = setVar(vars, "mssql_linked_targets", targets);
  }
  if (newly("stored_credential") && isEmpty(getVar(vars, "stored_credential.target"))) {
    vars = setVar(vars, "stored_credential.target", `TERMSRV/${hostName(node)}`);
  }
  return vars === next.vulns_vars ? next : { ...next, vulns_vars: vars };
}
