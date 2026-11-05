// SPNs a delegation can point at: the services the compiler stands up on the
// Windows hosts of one domain. Used by the Delegate to picker on a user
// (constrained_delegation) and on a computer (constrained_delegation_kerberos).
import { joinedHosts } from "./domainDirectory.js";

const WINDOWS_KINDS = new Set(["dc", "srv", "wks"]);
const LINUX_OS = /^(debian|ubuntu|linux|kali)/;

export function isWindowsHost(node) {
  return WINDOWS_KINDS.has(node?.kind) && !LINUX_OS.test(node?.overlay?.os || "");
}

const servicesOf = (node) => (Array.isArray(node?.overlay?.services) ? node.overlay.services : []);

// The srv role installs SQL Server for role sql or an mssql service.
export function runsSql(node) {
  return node?.overlay?.role === "sql" || servicesOf(node).includes("mssql");
}

export function runsIis(node) {
  return servicesOf(node).includes("iis");
}

// The domain a host joins, or null.
export function hostDomain(document, hostId) {
  const edge = (document?.edges || []).find((e) => e.role === "joins" && e.source === hostId);
  return edge ? edge.target : null;
}

// [{host, kind, spns: [{spn, label, about}]}] for each Windows host joined to the
// domain, the DC first. `exclude` drops one host (a computer does not delegate
// to itself).
export function spnChoices(document, domainId, { exclude } = {}) {
  const domain = (document?.nodes || []).find((n) => n.id === domainId);
  const fqdn = domain?.overlay?.fqdn;
  if (!fqdn) return [];
  const groups = [];
  for (const h of joinedHosts(document, domainId)) {
    if (h.id === exclude) continue;
    const node = document.nodes.find((n) => n.id === h.id);
    if (!isWindowsHost(node)) continue;
    const fq = `${h.name}.${fqdn}`;
    const spns = [{ spn: `CIFS/${fq}`, label: "CIFS", about: "file and admin shares" }];
    if (node.kind === "dc") {
      spns.push({ spn: `LDAP/${fq}`, label: "LDAP", about: "directory access, DCSync" });
    }
    if (runsSql(node)) {
      spns.push({ spn: `MSSQLSvc/${fq}:1433`, label: "MSSQL", about: "SQL Server" });
    }
    // HTTP maps to the computer account by default, so it is a live target with
    // or without IIS (GOAD's castelblack delegates to HTTP/winterfell).
    spns.push({
      spn: `HTTP/${fq}`, label: "HTTP",
      about: runsIis(node) ? "IIS web and WinRM" : "WinRM",
    });
    spns.push({ spn: `HOST/${fq}`, label: "HOST", about: "services and scheduled tasks" });
    groups.push({ host: h.name, kind: node.kind, spns });
  }
  return groups.sort((a, b) => (a.kind === "dc" ? 0 : 1) - (b.kind === "dc" ? 0 : 1));
}

// spnChoices() in the [{label, options}] shape the pickers take.
export function spnOptionGroups(groups) {
  return groups.map((g) => ({
    label: g.host,
    options: g.spns.map((s) => ({ value: s.spn, label: s.label, about: s.about })),
  }));
}

// SPNs a service account (a Kerberoastable user) can carry: SQL Server and IIS
// on the domain's hosts. Never HOST, CIFS or LDAP: those sit on the computer
// account, so a user carrying one is a duplicate SPN.
export function userSpnChoices(document, domainId) {
  const domain = (document?.nodes || []).find((n) => n.id === domainId);
  const fqdn = domain?.overlay?.fqdn;
  if (!fqdn) return [];
  const out = [];
  for (const h of joinedHosts(document, domainId)) {
    const node = document.nodes.find((n) => n.id === h.id);
    if (!isWindowsHost(node)) continue;
    const fq = `${h.name}.${fqdn}`;
    if (runsSql(node)) out.push({ spn: `MSSQLSvc/${fq}:1433`, about: `SQL Server on ${h.name}` });
    if (runsIis(node)) out.push({ spn: `HTTP/${fq}`, about: `IIS on ${h.name}` });
  }
  return out;
}

// What a fresh delegation points at: CIFS on the domain controller, the classic
// target, else CIFS on the first other Windows host.
export function defaultDelegateTo(document, domainId, opts) {
  const first = spnChoices(document, domainId, opts)[0];
  return first ? [first.spns[0].spn] : [];
}

// A host's overlay with delegate_to filled in when constrained_delegation_kerberos
// has just been ticked and names no target yet. Anything already set is kept.
export function withDelegationDefault(document, node, overlay) {
  const was = node?.overlay?.vulns || [];
  const now = overlay?.vulns || [];
  const ticked = now.includes("constrained_delegation_kerberos")
    && !was.includes("constrained_delegation_kerberos");
  const vars = overlay?.vulns_vars && typeof overlay.vulns_vars === "object" ? overlay.vulns_vars : {};
  if (!ticked || (Array.isArray(vars.delegate_to) && vars.delegate_to.length)) return overlay;
  const spns = defaultDelegateTo(document, hostDomain(document, node.id), { exclude: node.id });
  if (!spns.length) return overlay;
  return { ...overlay, vulns_vars: { ...vars, delegate_to: spns } };
}
