// User activity: the schedule command each action writes, read back, and
// quoted for PowerShell; plus which keys and findings the section owns.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { VULN_LABEL, VULN_PARAMS } from "./vulns.js";
import { formKeys, formSections } from "./vulnForm.js";
import {
  ACTIVITIES, ACTIVITY_IDS, DEFAULT_BOT_MINUTES, DEFAULT_SCRIPT_PATH, DEFAULT_TASK, MAX_BOT_MINUTES,
  CLIENT_IMAGE_PROVIDERS, SCHEDULE_ACTIONS, actionCommand, botMinutes, consoleSigninUser,
  findingsByActivity, losesQuotes, onlyOn, providerBlock, psQuote, psUnquote, readSchedule,
  scheduleWith, showsActivity, taskClash, toggled,
} from "./activity.js";

const load = (path) => JSON.parse(readFileSync(path, "utf8"));
const scheduleOf = (path, id) =>
  load(path).nodes.find((n) => n.id === id).overlay.vulns_vars.schedule;

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

const AWKWARD = [
  "C:\\tools\\app.exe",
  "C:\\Program Files\\It's Here\\run.bat",
  "\\\\fs01\\it's",
  "''",
  "'",
  "a''b",
  "end'",
  "$env:TEMP\\x `n $(whoami)",
  "curly \u2018left\u2019 and \u201alow\u201b",
  " spaced ",
];

test("a single quote is doubled, and $, backtick and double quotes are left alone", () => {
  assert.strictEqual(psQuote("C:\\a b\\c.exe"), "'C:\\a b\\c.exe'");
  assert.strictEqual(psQuote("it's"), "'it''s'");
  assert.strictEqual(psQuote("''"), "''''''");
  assert.strictEqual(psQuote("$x `y \"z\""), "'$x `y \"z\"'");
});

test("PowerShell's curly single quotes are doubled too, since they end the string", () => {
  assert.strictEqual(psQuote("a\u2019b"), "'a\u2019\u2019b'");
  assert.strictEqual(psQuote("\u2018x\u201b"), "'\u2018\u2018x\u201b\u201b'");
});

test("quoting reads back to the same text", () => {
  for (const text of AWKWARD) assert.strictEqual(psUnquote(psQuote(text)), text, text);
});

test("text that is not one whole single-quoted string does not unquote", () => {
  for (const text of ["", "plain", "'open", "'a'b'", "'a' 'b'", "\"double\"", "'it's'"]) {
    assert.strictEqual(psUnquote(text), null, text);
  }
  assert.strictEqual(psUnquote("''"), "");
});

test("each action writes its command", () => {
  assert.strictEqual(actionCommand("file", "C:\\tools\\app.exe"), "Start-Process 'C:\\tools\\app.exe'");
  assert.strictEqual(actionCommand("file", "\\\\fs01\\it\\setup.bat"), "Start-Process '\\\\fs01\\it\\setup.bat'");
  assert.strictEqual(actionCommand("share", "\\\\fs01\\it's"), "Get-ChildItem '\\\\fs01\\it''s'");
  assert.strictEqual(
    actionCommand("web", "http://intranet/"),
    "Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials 'http://intranet/'"
  );
  assert.strictEqual(actionCommand("custom", "whoami"), "whoami");
  assert.strictEqual(actionCommand("script", "C:\\bot.ps1"), "& 'C:\\bot.ps1'");
  assert.strictEqual(actionCommand("logon", "anything"), undefined);
});

test("a .ps1 file is run by PowerShell, since Start-Process opens it in Notepad", () => {
  assert.strictEqual(
    actionCommand("file", "\\\\fs01\\scripts\\Map.PS1"),
    "powershell.exe -ExecutionPolicy Bypass -File '\\\\fs01\\scripts\\Map.PS1'"
  );
});

test("an empty value writes no command, so the role runs its default", () => {
  for (const action of ["file", "share", "web", "custom", "script"]) {
    assert.strictEqual(actionCommand(action, ""), undefined, action);
    assert.strictEqual(actionCommand(action, "   "), undefined, action);
    assert.strictEqual(actionCommand(action, undefined), undefined, action);
  }
});

test("every templated command reads back as its action and value", () => {
  for (const action of ["file", "share", "web"]) {
    for (const value of [...AWKWARD.filter((v) => v.trim()), "C:\\x.ps1", "\\\\h\\s\\it's.ps1"]) {
      const command = actionCommand(action, value);
      assert.deepStrictEqual(readSchedule({ command }), { action, value }, command);
    }
  }
});

test("no command, or a sleep, reads as staying logged on", () => {
  assert.deepStrictEqual(readSchedule(undefined), { action: "logon", value: "" });
  assert.deepStrictEqual(readSchedule({ user: "NORTH\\arya.stark" }), { action: "logon", value: "" });
  assert.strictEqual(readSchedule({ command: "Start-Sleep -Seconds 5" }).action, "logon");
  assert.strictEqual(readSchedule({ command: " Start-Sleep -Seconds 30 " }).action, "logon");
});

test("anything else reads as the person's own PowerShell, kept as written", () => {
  for (const command of [
    "whoami",
    "Start-Process 'C:\\x.ps1'",
    "powershell.exe -ExecutionPolicy Bypass -File 'C:\\x.exe'",
    "Start-Process C:\\unquoted.exe",
    "Get-ChildItem 'a' 'b'",
    "Get-ChildItem ''",
    "start-process 'C:\\x.exe'",
    "Start-Sleep -Seconds 5; whoami",
  ]) {
    assert.deepStrictEqual(readSchedule({ command }), { action: "custom", value: command.trim() }, command);
  }
});

test("a script the command runs reads as the script action, as the blueprints write it", () => {
  for (const command of ["& C:\\bot.ps1", "& 'C:\\bot.ps1'", "& \"c:\\BOT.ps1\"", "&C:\\bot.ps1"]) {
    const s = { script_path: "C:\\bot.ps1", script_content: "whoami\n", command };
    assert.deepStrictEqual(readSchedule(s), { action: "script", value: "C:\\bot.ps1" }, command);
  }
  for (const [path, id] of [
    ["public/goad/minilab.json", "dc"], ["public/goad/nha.json", "share"],
    ["public/goad/dracarys.json", "balerion"], ["public/goad/dracarys.json", "vhagar"],
  ]) {
    assert.strictEqual(readSchedule(scheduleOf(path, id)).action, "script", `${path} ${id}`);
  }
});

test("script keys the command does not run read as own PowerShell, so they stay on screen", () => {
  assert.strictEqual(readSchedule({ script_path: "C:\\a.ps1", command: "& C:\\b.ps1" }).action, "custom");
  assert.strictEqual(readSchedule({ script_path: "C:\\a.ps1" }).action, "custom");
  assert.strictEqual(readSchedule({ script_content: "whoami", command: "Get-ChildItem '\\\\h\\s'" }).action, "custom");
});

test("switching action keeps who, how often and the task name", () => {
  const base = { user: "NORTH\\arya.stark", interval_minutes: 3, name: "web_bot", command: "whoami" };
  assert.deepStrictEqual(scheduleWith(base, "web", "http://intranet/"), {
    user: "NORTH\\arya.stark", interval_minutes: 3, name: "web_bot",
    command: "Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials 'http://intranet/'",
  });
  assert.deepStrictEqual(scheduleWith(base, "logon"), { user: "NORTH\\arya.stark", interval_minutes: 3, name: "web_bot" });
  assert.strictEqual(scheduleWith({ command: "whoami" }, "logon"), undefined);
});

test("the script action writes path, body and the command that runs it", () => {
  assert.deepStrictEqual(scheduleWith({ user: "A\\b" }, "script", { path: "C:\\it's.ps1", body: "whoami\n" }), {
    user: "A\\b", script_path: "C:\\it's.ps1", script_content: "whoami\n", command: "& 'C:\\it''s.ps1'",
  });
  const back = scheduleWith(undefined, "script", { path: DEFAULT_SCRIPT_PATH, body: "" });
  assert.deepStrictEqual(readSchedule(back), { action: "script", value: DEFAULT_SCRIPT_PATH });
  assert.deepStrictEqual(scheduleWith(undefined, "script", { path: "", body: "x" }), { script_content: "x" });
});

test("leaving the script drops its keys; own PowerShell keeps them", () => {
  const s = { script_path: "C:\\bot.ps1", script_content: "whoami", command: "& C:\\bot.ps1" };
  assert.deepStrictEqual(scheduleWith(s, "share", "\\\\fs\\it"), { command: "Get-ChildItem '\\\\fs\\it'" });
  assert.deepStrictEqual(scheduleWith(s, "custom", "& C:\\bot.ps1; whoami"), {
    script_path: "C:\\bot.ps1", script_content: "whoami", command: "& C:\\bot.ps1; whoami",
  });
});

test("every action has a label, and every typed one names its input", () => {
  const ids = SCHEDULE_ACTIONS.map((a) => a.id);
  assert.deepStrictEqual(ids, ["logon", "file", "share", "web", "custom", "script"]);
  for (const a of SCHEDULE_ACTIONS) {
    assert.ok(a.label, a.id);
    if (["file", "share", "web", "custom"].includes(a.id)) assert.ok(a.input && a.placeholder, a.id);
  }
});

test("a double quote in the command is flagged, since the task line strips it", () => {
  assert.strictEqual(losesQuotes('Write-Output "a b"'), true);
  assert.strictEqual(losesQuotes("Write-Output 'a b'"), false);
  assert.strictEqual(losesQuotes(undefined), false);
});

test("the task name defaults to schedule_bot and is flagged when it takes another bot's", () => {
  assert.strictEqual(DEFAULT_TASK, "schedule_bot");
  assert.strictEqual(VULN_PARAMS.schedule.find((p) => p.key === "schedule.name").example, DEFAULT_TASK);
  assert.strictEqual(taskClash(undefined, ["rdp_scheduler", "schedule"]), null);
  assert.strictEqual(taskClash("Connect_Bot", ["rdp_scheduler", "schedule"]).id, "rdp_scheduler");
  assert.strictEqual(taskClash("connect_bot", ["schedule"]), null);
  assert.strictEqual(taskClash("ntlm_bot", ["ntlm_relay"]).id, "ntlm_relay");
});

test("the logon bot interval reads as the role does: a whole number from 1 up, else 3", () => {
  assert.strictEqual(DEFAULT_BOT_MINUTES, 3);
  for (const unset of [undefined, null, ""]) assert.strictEqual(botMinutes(unset), 3);
  assert.strictEqual(botMinutes(1), 1);
  assert.strictEqual(botMinutes(15), 15);
  assert.strictEqual(botMinutes("05"), 5);
  for (const bad of [0, -2, 2.5, "abc", true, [5], { m: 5 }]) assert.strictEqual(botMinutes(bad), 3, String(bad));
  assert.strictEqual(botMinutes(MAX_BOT_MINUTES + 1), MAX_BOT_MINUTES);
  const role = readFileSync(
    new URL("../../src/redstackpro/assets/ansible/roles/redstackpro.host_vulns/tasks/rdp_scheduler.yml", import.meta.url),
    "utf8"
  );
  assert.ok(role.includes("bot_interval_minutes | default(3)"), "the role default moved");
  assert.ok(role.includes(`, ${MAX_BOT_MINUTES}] | min`), "the role cap moved");
  const param = VULN_PARAMS.rdp_scheduler.find((p) => p.key === "bot_interval_minutes");
  assert.strictEqual(param.example, DEFAULT_BOT_MINUTES);
  assert.match(param.about, /Default 3\./);
});

test("the poisoning bots are blocked on a cloud provider, with the reason", () => {
  assert.match(providerBlock("responder", "gcp"), /^Not planted on GCP: cloud networks drop/);
  assert.match(providerBlock("ntlm_relay", "aws"), /^Not planted on AWS/);
  assert.strictEqual(providerBlock("responder", "proxmox"), null);
  assert.strictEqual(providerBlock("responder", undefined), null);
  assert.strictEqual(providerBlock("rdp_scheduler", "gcp"), null);
  assert.strictEqual(onlyOn("responder"), "Proxmox and ESXi only");
  assert.strictEqual(onlyOn("schedule"), null);
});

test("every activity is a catalog vuln, and owns every key it reads", () => {
  for (const a of ACTIVITIES) {
    assert.ok(VULN_LABEL[a.id], a.id);
    for (const p of VULN_PARAMS[a.id]) {
      const head = p.key.split(".")[0];
      assert.ok(a.keys.includes(p.key) || a.keys.includes(head), `${a.id} ${p.key}`);
    }
  }
});

test("the settings form marks activity vulns, and still counts their keys for the JSON view", () => {
  const vulns = ["rdp_scheduler", "schedule", "sysvol_secret"];
  const sections = formSections(vulns, ACTIVITY_IDS);
  assert.deepStrictEqual(
    sections.map((s) => [s.vuln, s.elsewhere]),
    [["sysvol_secret", false], ["rdp_scheduler", true], ["schedule", true]]
  );
  assert.ok(formKeys(vulns).has("schedule.command"));
  assert.ok(formSections(vulns).every((s) => !s.elsewhere));
});

test("a finding shows under the activity its message names, else the first ticked", () => {
  const at = (field, message) => ({ field, message, severity: "warning" });
  const rows = findingsByActivity(
    [
      at("vulns_vars.bot_user", "responder on winterfell has no vulns_vars.bot_user, so no responder bot is created."),
      at("vulns_vars.bot_user", "rdp_scheduler on winterfell has no vulns_vars.bot_user, so no logon bot is created."),
      at("vulns_vars.schedule.interval_minutes", "must be an integer"),
      at("vulns_vars.bot_user", "some other check"),
      at("vulns_vars.gpo_abuse.principal", "not an activity"),
    ],
    ["responder", "rdp_scheduler", "schedule"]
  );
  assert.deepStrictEqual(rows.responder.map((f) => f.message.split(" ")[0]), ["responder"]);
  assert.deepStrictEqual(rows.rdp_scheduler.map((f) => f.message.split(" ")[0]), ["rdp_scheduler", "some"]);
  assert.strictEqual(rows.schedule.length, 1);
  assert.strictEqual(Object.values(rows).flat().length, 4);
});

test("only Windows range hosts show the section", () => {
  assert.strictEqual(showsActivity({ kind: "dc", overlay: {} }), true);
  assert.strictEqual(showsActivity({ kind: "wks", overlay: { os: "windows_10" } }), true);
  assert.strictEqual(showsActivity({ kind: "srv", overlay: { os: "debian_13" } }), false);
  assert.strictEqual(showsActivity({ kind: "jumpbox", overlay: {} }), false);
});

test("toggling adds once and removes", () => {
  assert.deepStrictEqual(toggled(undefined, "schedule", true), ["schedule"]);
  assert.deepStrictEqual(toggled(["schedule"], "schedule", true), ["schedule"]);
  assert.deepStrictEqual(toggled(["a", "schedule"], "schedule", false), ["a"]);
});

test("a Windows 10 or 11 host signs its bot user in where the provider boots a client", () => {
  const wks = (over = {}) => ({
    os: "windows_10",
    vulns: ["stored_credential"],
    vulns_vars: { stored_credential: { owner: "FREIGHT\dana.brooks" } },
    ...over,
  });
  assert.deepStrictEqual(CLIENT_IMAGE_PROVIDERS, ["azure", "proxmox", "esxi"]);
  for (const provider of CLIENT_IMAGE_PROVIDERS) {
    assert.strictEqual(consoleSigninUser(wks(), provider), "FREIGHT\dana.brooks", provider);
  }
  assert.strictEqual(consoleSigninUser(wks({ os: "windows_11" }), "azure"), "FREIGHT\dana.brooks");
  // GCP and AWS boot Server 2022, a server build is a server, and no provider is no answer.
  for (const provider of ["gcp", "aws", undefined]) {
    assert.strictEqual(consoleSigninUser(wks(), provider), null, provider);
  }
  assert.strictEqual(consoleSigninUser(wks({ os: "windows_server_2022" }), "azure"), null);
  // The autologon vuln signs its own user in.
  assert.strictEqual(consoleSigninUser(wks({ vulns: ["stored_credential", "autologon"] }), "azure"), null);
  assert.strictEqual(consoleSigninUser(wks({ vulns: ["smbv1"] }), "azure"), null);
});

test("the console user is picked in the role's order", () => {
  const user = (vulns, vulns_vars, provider = "proxmox") =>
    consoleSigninUser({ os: "windows_10", vulns, vulns_vars }, provider);
  const vv = {
    bot_user: "north\arya.stark",
    stored_credential: { owner: "north\robb.stark" },
    schedule: { user: "north\sansa.stark" },
    ntlm_relay_user: "north\eddard.stark",
  };
  assert.strictEqual(user(["stored_credential", "rdp_scheduler"], vv), "north\arya.stark");
  assert.strictEqual(user(["schedule", "stored_credential"], vv), "north\robb.stark");
  assert.strictEqual(user(["ntlm_relay", "schedule"], vv), "north\sansa.stark");
  assert.strictEqual(user(["ntlm_relay", "responder"], vv), "north\arya.stark");
  assert.strictEqual(user(["ntlm_relay"], vv), "north\eddard.stark");
  assert.strictEqual(user(["ntlm_relay"], { bot_user: "north\jon.snow" }), "north\jon.snow");
  // A SYSTEM task needs no sign-in, and a bot the provider drops is not planted.
  assert.strictEqual(user(["schedule"], { schedule: { name: "x" } }), null);
  assert.strictEqual(user(["responder"], vv, "azure"), null);
  assert.strictEqual(user(["rdp_scheduler"], { bot_user: "  " }), null);
  assert.strictEqual(user(["rdp_scheduler"], "not an object"), null);
});

console.log(`activity: ${passed} passed`);
