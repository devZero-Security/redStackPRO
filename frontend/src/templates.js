// The template library, shared by both canvases. Each canvas has its own set of
// starting points; the picker shows only the current canvas's list. Red Infra
// templates open editable (starting points you customize); range templates open
// read-only (the GOAD family). See 0047. Each file is a document under public/.
export const TEMPLATES = {
  ops: [
    {
      file: "redstack",
      name: "redStack",
      blurb:
        "The recommended blueprint: three C2 backends behind an isolated Apache redirector, teamservers and operators behind a jumpbox.",
    },
    {
      file: "minimal-c2",
      name: "Minimal C2",
      blurb:
        "The smallest usable stack: one teamserver, one redirector, one jumpbox, one operator. A starting point to grow from.",
    },
    {
      file: "rollover",
      name: "Redirector rollover",
      blurb:
        "Three interchangeable front doors fronting one teamserver, for resilience when a redirector is burned or blocked.",
    },
    {
      file: "split-horizon",
      name: "Split horizon C2",
      blurb:
        "Two front doors that do not share a fate: Apache fronting Sliver for long haul, Nginx fronting Mythic for interactive, each redirector on its own peered network.",
    },
  ],
  range: [
    {
      file: "goad/goad",
      name: "GOAD",
      group: "GOAD",
      blurb: "Three domains across two forests, five machines. The full range.",
      teaches:
        "The reference range, and the one the written solution follows. The full " +
        "sevenkingdoms ACL killchain, a cross-forest trust to essos, ADCS from " +
        "ESC1 to ESC15, constrained and unconstrained delegation, MSSQL links " +
        "and impersonation, and the poisoning and relay path.",
    },
    {
      file: "goad/goad-light",
      name: "GOAD-Light",
      group: "GOAD",
      // "No ADCS" was wrong and shipped for a while: the lab declares esc1 on
      // the sevenkingdoms CA. Corrected against the template's own surface.
      blurb:
        "Two domains in one forest, three machines. No essos, and ADCS narrowed " +
        "to ESC1.",
      teaches:
        "GOAD with the essos forest removed. The same ACL chain, delegation, " +
        "MSSQL and relay path over a single forest, so the trust hop is the only " +
        "thing missing. Stands up in about half the time.",
    },
    {
      file: "goad/goad-mini",
      name: "GOAD-Mini",
      group: "GOAD",
      blurb: "One domain on a single DC. The smallest.",
      teaches:
        "Two techniques on one domain controller. For rehearsing a tool, a " +
        "beacon path or a deploy, rather than walking an attack chain.",
    },
    {
      file: "goad/nha",
      name: "NHA",
      group: "GOAD",
      blurb:
        "Ninja Hacker Academy: two domains, five machines. A themed challenge lab.",
      teaches:
        "Two separate forests, not a parent and a child. MSSQL links and " +
        "impersonation, CredSSP, a writable share, and a certificate template " +
        "ACL that has to be reached from the other forest.",
    },
    {
      file: "goad/sccm",
      name: "SCCM",
      group: "GOAD",
      blurb:
        "One domain, four machines, for practising Configuration Manager attack paths.",
      teaches:
        "The attack surface here is a real service rather than planted " +
        "vulnerabilities: a Configuration Manager site, its database, and a " +
        "client. Site takeover, credential recovery and PXE.",
    },
    {
      file: "goad/dracarys",
      name: "DRACARYS",
      group: "GOAD",
      blurb:
        "A training challenge: find your way to domain admin on dracarys.lab. One domain, three machines.",
      teaches:
        "A find-your-own-way challenge with no marked path. A KeePass vault, " +
        "Kerberos constrained delegation, LDAPS, and a Linux domain member " +
        "alongside the Windows hosts.",
    },
    {
      file: "goad/minilab",
      name: "MINILAB",
      group: "GOAD",
      blurb: "A minimal lab: one DC and one Windows 10 workstation.",
      teaches:
        "The smallest thing that still behaves like a domain. Stored " +
        "credentials, CredSSP and a weak password, with a real workstation to " +
        "land on.",
    },
    {
      file: "goad/goad-wazuh",
      name: "GOAD-Wazuh",
      group: "GOAD",
      // Not full GOAD: two domains, the same pair as GOAD-Light, plus a
      // workstation and the SIEM. The old blurb said "GOAD with a Wazuh
      // manager", which claimed the three-domain range.
      blurb:
        "Two domains and a workstation with a Wazuh manager watching, so the " +
        "attack path has something reporting on it.",
      teaches:
        "The detection axis. Every technique here is meant to be caught as well " +
        "as run, so it is the range to point a detection at: poisoning, " +
        "roasting, unconstrained delegation and GPP passwords, with a SIEM " +
        "already collecting.",
    },
    {
      file: "harbor",
      name: "Harbor",
      blurb:
        "A small corporate forest: a root domain and a child domain over the parent child trust, with the ordinary path from a phished workstation user to the forest.",
      teaches:
        "Ours, and deliberately not a puzzle. An ordinary corporate forest with " +
        "the mistakes ordinary forests have: poisoning, roastable service " +
        "accounts, unconstrained delegation, open shares and a stored " +
        "credential. The plain path from a phished workstation user to the " +
        "forest, with no theme in the way.",
    },
  ],
};

// What a family is, said once where the family is, rather than as a note over
// the whole list. The GOAD note used to sit above every range template and so
// described Harbor too, which is ours and not a GOAD lab.
// What the templates that belong to no family are called, where a family is
// also on screen. Harbor is ours rather than a GOAD lab, and saying so is the
// whole point of keeping it out of the GOAD group.
export const UNGROUPED_LABEL = "redStackPRO";

export const GROUP_NOTES = {
  GOAD:
    "Recreated natively on the Defense canvas as redStack nodes and edges, " +
    "deployed by redStackPRO's own pipeline, not imported or wrapped. A nod to " +
    "the GOAD project.",
};

// Templates grouped by their `group` for the picker, so a family like GOAD reads
// as a folder. Ungrouped templates fall under an empty-key section the picker
// renders without a header. Order follows the manifest.
export function groupedTemplates(mode) {
  const groups = new Map();
  for (const t of templatesFor(mode)) {
    const key = t.group || "";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(t);
  }
  return [...groups.entries()].map(([group, templates]) => ({ group, templates }));
}

// A template by the file it loads from, across both canvases, so whatever
// loaded a document can say what that document is. Returns undefined for a
// topology that did not come from a template, which is the ordinary case once
// somebody has started building their own.
export function templateFor(file) {
  const key = String(file || "").replace(/^\//, "").replace(/\.json$/, "");
  for (const list of Object.values(TEMPLATES)) {
    const hit = list.find((t) => t.file === key);
    if (hit) return hit;
  }
  return undefined;
}

// The templates for a canvas mode. Anything that is not the range canvas is
// treated as Red Infra, so an undefined mode falls back to the ops library.
export function templatesFor(mode) {
  return TEMPLATES[mode === "range" ? "range" : "ops"];
}
