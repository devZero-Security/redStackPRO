// User activity: the vulns that simulate a person on a range host (a logon
// bot, a scheduled task, the poisoning bots, a saved credential), shown as
// plain sentences. Each one ticks its vuln in overlay.vulns and edits the same
// vulns_vars keys its role reads (host_vulns/tasks/<id>.yml).
import { VULN_PROVIDERS } from "./vulns.js";
import { isPlainObject } from "./vulnForm.js";
import { isWindowsHost } from "./spnChoices.js";
import { labelFor } from "./providers.js";

// In display order. `keys` are the vulns_vars keys each one edits, so the
// settings form can leave them out and findings can show here instead.
export const ACTIVITIES = [
  {
    id: "rdp_scheduler",
    title: "Logon bot",
    idle: "A domain user logs on to this host every 3 minutes, so their credentials stay in memory.",
    keys: ["bot_user", "bot_interval_minutes"],
    task: "connect_bot",
  },
  {
    id: "schedule",
    title: "Scheduled task",
    idle: "A domain user, or SYSTEM, does something on this host every few minutes: stays logged on, runs a file, browses a share, fetches a web page, or runs your own PowerShell.",
    keys: ["schedule"],
  },
  {
    id: "responder",
    title: "Share-browsing bot",
    idle: "Every 2 minutes a domain user opens a share on a host that does not resolve, so a poisoner can answer and capture their hash.",
    keys: ["bot_user", "responder_target"],
    task: "responder_bot",
  },
  {
    id: "ntlm_relay",
    title: "Relay bot",
    idle: "Every 5 minutes a privileged domain user authenticates to a share on a host that does not resolve, so a poisoner can answer and relay it.",
    keys: ["ntlm_relay_user", "ntlm_relay_target"],
    task: "ntlm_bot",
  },
  {
    id: "stored_credential",
    title: "Saved credential",
    idle: "A domain user has a credential for an account saved in their Credential Manager.",
    keys: ["stored_credential"],
  },
];

export const ACTIVITY_IDS = new Set(ACTIVITIES.map((a) => a.id));

// host_vulns plants on Windows only, so a Linux host keeps the plain form.
export const showsActivity = (node) => isWindowsHost(node);

// Why this provider cannot plant the activity, or null when it can (or no
// provider is chosen yet).
export function providerBlock(id, provider) {
  const allowed = VULN_PROVIDERS[id];
  if (!allowed || !provider || allowed.includes(provider)) return null;
  return `Not planted on ${labelFor(provider)}: cloud networks drop the broadcast name lookups it relies on.`;
}

export function onlyOn(id) {
  const allowed = VULN_PROVIDERS[id];
  return allowed ? `${allowed.map(labelFor).join(" and ")} only` : null;
}

// ------------------------------------------------------- console sign-in

// The providers that boot a Windows 10 or 11 build as a client edition; GCP and
// AWS boot Server 2022 for it (CAP005). Same list as briefing.py.
export const CLIENT_IMAGE_PROVIDERS = ["azure", "proxmox", "esxi"];
const CLIENT_BUILDS = ["windows_10", "windows_11"];

const named = (value) => (typeof value === "string" && value.trim() ? value.trim() : null);

// The user console_signin.yml signs in at the console at boot, or null: Windows
// 10 and 11 run a user's scheduled tasks only after a console sign-in. Picked in
// the role's order; a host with the autologon vuln signs in that vuln's user.
export function consoleSigninUser(overlay, provider) {
  const ov = overlay || {};
  if (!CLIENT_IMAGE_PROVIDERS.includes(provider) || !CLIENT_BUILDS.includes(ov.os)) return null;
  const vulns = (Array.isArray(ov.vulns) ? ov.vulns : []).filter((v) => !providerBlock(v, provider));
  if (vulns.includes("autologon")) return null;
  const vv = isPlainObject(ov.vulns_vars) ? ov.vulns_vars : {};
  const sub = (key) => (isPlainObject(vv[key]) ? vv[key] : {});
  const order = [
    ["rdp_scheduler", vv.bot_user],
    ["stored_credential", sub("stored_credential").owner],
    ["schedule", sub("schedule").user],
    ["responder", vv.bot_user],
    ["ntlm_relay", vv.ntlm_relay_user || vv.bot_user],
  ];
  for (const [id, user] of order) {
    if (vulns.includes(id) && named(user)) return named(user);
  }
  return null;
}

// ---------------------------------------------------------------- quoting

// PowerShell ends a single-quoted string at any of these, and reads one
// written twice as itself.
const SINGLE = "'\u2018\u2019\u201a\u201b";
const QUOTE = new RegExp(`[${SINGLE}]`, "g");
const LITERAL = new RegExp(`^[${SINGLE}]((?:[^${SINGLE}]|[${SINGLE}]{2})*)[${SINGLE}]$`);
const PAIR = new RegExp(`([${SINGLE}])[${SINGLE}]`, "g");

export const psQuote = (text) => `'${String(text).replace(QUOTE, "$&$&")}'`;

// The text of one single-quoted PowerShell string, or null when it is not one.
export function psUnquote(text) {
  const m = LITERAL.exec(String(text ?? ""));
  return m ? m[1].replace(PAIR, "$1") : null;
}

// ------------------------------------------------------------ logon bot

export const DEFAULT_BOT_MINUTES = 3;
// Task Scheduler's longest repetition interval, 31 days.
export const MAX_BOT_MINUTES = 44640;

// The minutes the logon bot runs every, as rdp_scheduler.yml reads
// bot_interval_minutes: anything but a whole number from 1 up is the default.
export function botMinutes(value) {
  const text = typeof value === "number" || typeof value === "string" ? String(value).trim() : "";
  if (!/^[0-9]+$/.test(text) || Number(text) < 1) return DEFAULT_BOT_MINUTES;
  return Math.min(Number(text), MAX_BOT_MINUTES);
}

// ------------------------------------------------------------- schedule

// The role's default command (schedule.yml).
export const DEFAULT_COMMAND = "Start-Sleep -Seconds 5";
export const DEFAULT_TASK = "schedule_bot";
export const DEFAULT_SCRIPT_PATH = "C:\\schedule_bot.ps1";

const SLEEP = /^Start-Sleep -Seconds \d+$/;
const PS1 = /\.ps1$/i;
const FILE = "Start-Process ";
// Start-Process opens a .ps1 in Notepad, so a script is run by PowerShell.
const FILE_PS1 = "powershell.exe -ExecutionPolicy Bypass -File ";
const SHARE = "Get-ChildItem ";
const WEB = "Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials ";

export const SCHEDULE_ACTIONS = [
  { id: "logon", label: "stays logged on" },
  {
    id: "file", label: "runs a file", input: "File to run",
    placeholder: "C:\\tools\\app.exe or \\\\host\\share\\file",
    help: "Runs it as this user: an .exe, .ps1, .bat or a shortcut. No Office is installed, so documents do not open.",
  },
  { id: "share", label: "browses a share", input: "Share to browse", placeholder: "\\\\host\\share" },
  {
    id: "web", label: "fetches a web page", input: "Web page to fetch", placeholder: "http://host/page",
    help: "Sends this user's credentials to the site.",
  },
  { id: "custom", label: "runs my own PowerShell", input: "Scheduled task PowerShell", placeholder: DEFAULT_COMMAND },
  { id: "script", label: "runs my own script" },
];

// The command an action writes for a value, or undefined when there is
// nothing to run yet (the role then runs its default).
export function actionCommand(action, value) {
  const v = value == null ? "" : String(value);
  if (action === "custom") return v.trim() ? v : undefined;
  if (!v.trim()) return undefined;
  if (action === "file") return (PS1.test(v.trim()) ? FILE_PS1 : FILE) + psQuote(v);
  if (action === "share") return SHARE + psQuote(v);
  if (action === "web") return WEB + psQuote(v);
  if (action === "script") return `& ${psQuote(v)}`;
  return undefined;
}

// `& <path>` with the path quoted either way or bare, as the shipped
// blueprints write it.
function runsScript(command, path) {
  const m = /^&\s*(.+)$/.exec(command);
  if (!m) return false;
  const target = m[1].trim();
  const named = psUnquote(target) ?? /^"([^"]*)"$/.exec(target)?.[1] ?? target;
  return named.toLowerCase() === path.toLowerCase();
}

function templated(command) {
  for (const [action, prefix] of [["file", FILE_PS1], ["file", FILE], ["share", SHARE], ["web", WEB]]) {
    if (!command.startsWith(prefix)) continue;
    const value = psUnquote(command.slice(prefix.length));
    if (value == null || !value.trim()) continue;
    // Only the form actionCommand writes for that file reads back as one.
    if (action === "file" && (prefix === FILE_PS1) !== PS1.test(value.trim())) continue;
    return { action, value };
  }
  return null;
}

// What a stored schedule does, as {action, value}: a command in one of the
// forms above reads back as its action, and anything else is the person's own
// PowerShell. Script keys that the command does not run also read as their own
// PowerShell, so they stay on screen.
export function readSchedule(schedule) {
  const s = isPlainObject(schedule) ? schedule : {};
  const command = s.command == null ? "" : String(s.command).trim();
  if (s.script_path != null || s.script_content != null) {
    return typeof s.script_path === "string" && s.script_path && runsScript(command, s.script_path)
      ? { action: "script", value: s.script_path }
      : { action: "custom", value: command };
  }
  if (!command || SLEEP.test(command)) return { action: "logon", value: "" };
  return templated(command) || { action: "custom", value: command };
}

const clean = (obj) => {
  const out = Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v != null && v !== "")
  );
  return Object.keys(out).length ? out : undefined;
};

// The schedule with `action` doing `value`: a string, or {path, body} for a
// script. Who, how often and the task name are kept. Only the script action,
// and the person's own PowerShell, keep the script keys.
export function scheduleWith(schedule, action, value) {
  const s = isPlainObject(schedule) ? { ...schedule } : {};
  if (action === "script") {
    const path = value?.path ?? "";
    s.script_path = path;
    s.script_content = value?.body ?? "";
    s.command = actionCommand("script", path);
  } else {
    if (action !== "custom") {
      delete s.script_path;
      delete s.script_content;
    }
    s.command = actionCommand(action, value);
  }
  return clean(s);
}

// The double quotes the role wraps the command in (-Command "...") strip any
// inside it.
export const losesQuotes = (command) => typeof command === "string" && command.includes('"');

// The other ticked bot whose task this name would replace, or null.
export function taskClash(name, vulns) {
  const n = String(name || DEFAULT_TASK).toLowerCase();
  const ticked = new Set(vulns || []);
  return ACTIVITIES.find((a) => a.task && a.task === n && ticked.has(a.id)) || null;
}

// The vulns list with `id` ticked or not, in place.
export function toggled(vulns, id, on) {
  const list = Array.isArray(vulns) ? vulns : [];
  if (on) return list.includes(id) ? list : [...list, id];
  return list.filter((v) => v !== id);
}

// Each activity's findings at the keys it edits, one row each. A key two
// activities share (bot_user) goes to the one the message names (RNG011 starts
// "<vuln> on"), else the first ticked.
export function findingsByActivity(findings, vulns) {
  const ticked = new Set(vulns || []);
  const out = Object.fromEntries(ACTIVITIES.map((a) => [a.id, []]));
  for (const f of findings || []) {
    const field = String(f?.field || "");
    const rows = ACTIVITIES.filter((a) =>
      a.keys.some((k) => field === `vulns_vars.${k}` || field.startsWith(`vulns_vars.${k}.`))
    );
    if (!rows.length) continue;
    const home =
      rows.find((a) => String(f.message || "").startsWith(`${a.id} on `)) ||
      rows.find((a) => ticked.has(a.id)) ||
      rows[0];
    out[home.id].push(f);
  }
  return out;
}
