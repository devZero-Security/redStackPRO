// Range starters: one-click hosts for the Cyber Ranges canvas, so building a
// custom lab does not begin with a blank srv the user has to fill in by hand.
// Each preset is a host kind plus a filled overlay (role, os, services). The
// role field already exists on overlay_range_host; these wire it to the palette.
// Dropping one derives its id from the kind and overlay, the same as any node.
// See presets.js consumers in App.jsx and addHostPreset in topology.js.

const WIN_SERVER = "windows_server_2019";
// The server family shares one colour; the icon is what tells them apart. The
// abbrev is a short display tag, not the schema role (fileshare stays the role,
// "file" is only what the palette prints).
const SERVER_COLOR = "#1098ad";

export const HOST_PRESETS = [
  {
    key: "sql",
    kind: "srv",
    label: "SQL Server",
    abbrev: "sql",
    icon: "tabler/outline/database",
    color: SERVER_COLOR,
    blurb: "MSSQL member server (linked servers, xp_cmdshell)",
    overlay: { role: "sql", os: WIN_SERVER, services: ["mssql"] },
  },
  {
    key: "web",
    kind: "srv",
    label: "Web Server",
    abbrev: "web",
    icon: "tabler/outline/world",
    color: SERVER_COLOR,
    blurb: "IIS member server",
    overlay: { role: "web", os: WIN_SERVER, services: ["iis"] },
  },
  {
    key: "fileshare",
    kind: "srv",
    label: "File Server",
    abbrev: "file",
    icon: "tabler/outline/folder",
    color: SERVER_COLOR,
    blurb: "SMB/NFS file share member server",
    overlay: { role: "fileshare", os: WIN_SERVER, services: ["smb"] },
  },
  {
    key: "adcs",
    kind: "srv",
    label: "AD CS Server",
    abbrev: "adcs",
    icon: "tabler/outline/certificate",
    color: SERVER_COLOR,
    blurb: "Certificate authority (ESC template practice)",
    overlay: { role: "adcs", os: WIN_SERVER, services: ["adcs"] },
  },
];

// The attack canvas presets: the redirector servers, the C2 frameworks a
// teamserver can run, and the operator OSes, each a first-class palette item
// folded under its kind so a Mythic teamserver or an Nginx redirector is one
// click. The plain kind (Teamserver, Redirector, Operator box) stays as the
// generic - a teamserver with no C2 is where you load your own. Each shares its
// kind's icon and colour; the label and abbrev tell them apart.
const REDIRECTOR = "#f59f00";
const TEAMSERVER = "#e03131";
const OPERATOR = "#1c7ed6";

export const OPS_PRESETS = [
  { key: "apache", kind: "redirector", label: "Apache", abbrev: "apache", icon: "tabler/outline/route", color: REDIRECTOR, blurb: "Apache redirector", overlay: { server: "apache" } },
  { key: "nginx", kind: "redirector", label: "Nginx", abbrev: "nginx", icon: "tabler/outline/route", color: REDIRECTOR, blurb: "Nginx redirector", overlay: { server: "nginx" } },
  { key: "mythic", kind: "teamserver", label: "Mythic", abbrev: "mythic", icon: "tabler/outline/server-2", color: TEAMSERVER, blurb: "Mythic C2 teamserver", overlay: { c2: "mythic" } },
  { key: "sliver", kind: "teamserver", label: "Sliver", abbrev: "sliver", icon: "tabler/outline/server-2", color: TEAMSERVER, blurb: "Sliver C2 teamserver", overlay: { c2: "sliver" } },
  { key: "adaptix", kind: "teamserver", label: "Adaptix", abbrev: "adaptix", icon: "tabler/outline/server-2", color: TEAMSERVER, blurb: "Adaptix C2 teamserver", overlay: { c2: "adaptix" } },
  { key: "op_kali", kind: "operator", label: "Kali", abbrev: "kali", icon: "tabler/outline/terminal-2", color: OPERATOR, blurb: "Kali operator box", overlay: { os: "kali" } },
  { key: "op_windows", kind: "operator", label: "Windows", abbrev: "win", icon: "tabler/outline/device-desktop", color: OPERATOR, blurb: "Windows operator box", overlay: { os: "windows" } },
  { key: "op_debian", kind: "operator", label: "Debian", abbrev: "debian", icon: "tabler/outline/terminal-2", color: OPERATOR, blurb: "Debian operator box", overlay: { os: "debian" } },
];

// Each canvas has its own presets: range starters on the defend canvas, the C2
// and redirector flavours on the attack canvas.
export function presetsFor(mode) {
  return mode === "haven" ? HOST_PRESETS : OPS_PRESETS;
}

// The presets that are flavours of one host kind, shown folded under it in the
// palette. A plain Workstation preset used to live here too; it only duplicated
// the Workstation host, so it was dropped.
export function presetsForKind(presets, kind) {
  return presets.filter((preset) => preset.kind === kind);
}
