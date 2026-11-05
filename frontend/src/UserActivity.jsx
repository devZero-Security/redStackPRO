import React, { useState } from "react";
import "./widgets.css";
import { HostServiceInput, PickInput, emptyTextFor, userNote } from "./VulnSettings.jsx";
import { PICKS, choicesFor, getVar, isPlainObject, setVar, withVulnDefaults } from "./vulnForm.js";
import { hostDomain } from "./spnChoices.js";
import { isNotice } from "./fieldRules.js";
import {
  ACTIVITIES, DEFAULT_BOT_MINUTES, DEFAULT_COMMAND, DEFAULT_SCRIPT_PATH, DEFAULT_TASK,
  MAX_BOT_MINUTES, SCHEDULE_ACTIONS, botMinutes, consoleSigninUser, findingsByActivity, losesQuotes,
  onlyOn, providerBlock, readSchedule, scheduleWith, taskClash, toggled,
} from "./activity.js";

const Sentence = ({ children }) => <div className="rg-activity-sentence">{children}</div>;
const Words = ({ children }) => <span className="rg-activity-words">{children}</span>;
const Help = ({ children }) => <span className="rg-field-help">{children}</span>;
const Warn = ({ children }) => <span className="rg-widget-warn">{children}</span>;

// A domain user inside a sentence, written DOMAIN\user as every bot role takes it.
function UserPick({ name, value, document, hostId, emptyLabel, disabled, onChange }) {
  return (
    <span className="rg-activity-pick">
      <PickInput
        name={name}
        value={value}
        groups={choicesFor("domain_user", document, hostId)}
        emptyLabel={emptyLabel}
        typedHint={PICKS.domain_user}
        unknownNote={userNote}
        emptyText={emptyTextFor("domain_user", !!hostDomain(document, hostId))}
        placeholder="DOMAIN\user"
        disabled={disabled}
        onChange={onChange}
      />
    </span>
  );
}

function TextIn({ name, value, placeholder, disabled, onChange, className }) {
  return (
    <input
      aria-label={name}
      className={className}
      value={value == null ? "" : String(value)}
      placeholder={placeholder}
      spellCheck={false}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value || undefined)}
    />
  );
}

function ActivityRow({ activity, on, blocked, disabled, findings, onToggle, children }) {
  const only = onlyOn(activity.id);
  return (
    <div className={on ? "rg-activity is-on" : "rg-activity"}>
      <div className="rg-activity-head">
        <label className={blocked ? "rg-check is-provider-unsupported" : "rg-check"}>
          <input
            type="checkbox"
            checked={on}
            disabled={disabled || (!!blocked && !on)}
            onChange={(e) => onToggle(e.target.checked)}
          />
          {activity.title}
        </label>
        {only ? <span className="rg-vuln-provider-note">{only}</span> : null}
      </div>
      {on ? children : <Help>{activity.idle}</Help>}
      {blocked ? <span className="rg-field-ignored">{blocked}</span> : null}
      {findings.map((f, i) => (
        <span key={i} className={isNotice(f) ? `rg-field-finding is-${f.severity}` : "rg-field-error"}>
          {f.message}
        </span>
      ))}
    </div>
  );
}

// What the action, path and script are, so a local pick survives only until
// the stored schedule changes under it (an edit in the JSON view).
const whatOf = (s) => JSON.stringify([s?.command ?? null, s?.script_path ?? null, s?.script_content ?? null]);

const ACTION_HELP = {
  logon: "The task only waits a few seconds: its logon leaves the user's session and credentials on the host.",
  custom: "One line of PowerShell, run with powershell.exe -Command.",
  script: "The body is written to the script path at deploy, and the task runs it.",
};

function ScheduleActivity({ schedule, vulns, document, hostId, disabled, onChange }) {
  const s = isPlainObject(schedule) ? schedule : {};
  // The action picked here, for one with nothing to run yet (a file not typed),
  // and the values of actions left, so switching back restores them.
  const [picked, setPicked] = useState(null);
  const [drafts, setDrafts] = useState({});
  const read = readSchedule(s);
  const action = picked && picked.what === whatOf(s) ? picked.action : read.action;
  const meta = SCHEDULE_ACTIONS.find((a) => a.id === action);
  const value = action === read.action ? read.value : "";
  const scripted = s.script_path != null || s.script_content != null;
  const showScript = action === "script" || (action === "custom" && scripted);

  const write = (next, act) => {
    setPicked({ action: act, what: whatOf(next) });
    onChange(next);
  };
  const setKey = (key, v) => onChange(setVar(s, key, v));
  const choose = (next) => {
    const now =
      action === "custom" ? s.command ?? ""
        : action === "script" ? { path: s.script_path ?? "", body: s.script_content ?? "" }
          : value;
    const saved = { ...drafts, [action]: now };
    setDrafts(saved);
    let v = saved[next];
    if (next === "custom" && v == null) v = s.command ?? "";
    if (next === "script" && v == null) {
      v = { path: s.script_path || DEFAULT_SCRIPT_PATH, body: s.script_content ?? "" };
    }
    write(scheduleWith(s, next, v), next);
  };
  const setScript = (field, v) => {
    if (action === "script") {
      const cur = { path: s.script_path ?? "", body: s.script_content ?? "" };
      write(scheduleWith(s, "script", { ...cur, [field]: v ?? "" }), "script");
    } else {
      write(setVar(s, field === "path" ? "script_path" : "script_content", v), "custom");
    }
  };

  const mins = s.interval_minutes;
  const clash = taskClash(s.name, vulns);
  // As SYSTEM the logon leaves nothing, which the SYSTEM note below says.
  const help = meta.help || (action === "logon" && !s.user ? null : ACTION_HELP[action]);
  return (
    <>
      <Sentence>
        <UserPick
          name="Scheduled task runs as"
          value={s.user}
          emptyLabel="SYSTEM"
          document={document}
          hostId={hostId}
          disabled={disabled}
          onChange={(v) => setKey("user", v)}
        />
        <select aria-label="Scheduled task action" value={action} disabled={disabled} onChange={(e) => choose(e.target.value)}>
          {SCHEDULE_ACTIONS.map((a) => (
            <option key={a.id} value={a.id}>{a.label}</option>
          ))}
        </select>
        {meta.input ? (
          <TextIn
            name={meta.input}
            className="rg-activity-wide"
            value={action === "custom" ? s.command : value}
            placeholder={meta.placeholder}
            disabled={disabled}
            onChange={(v) => write(scheduleWith(s, action, v), action)}
          />
        ) : null}
        <Words>every</Words>
        <input
          type="number"
          className="rg-activity-num"
          aria-label="Scheduled task interval in minutes"
          min={1}
          step={1}
          value={mins ?? ""}
          placeholder="1"
          disabled={disabled}
          onChange={(e) => setKey("interval_minutes", e.target.value === "" ? undefined : Number(e.target.value))}
        />
        <Words>{Number(mins ?? 1) === 1 ? "minute." : "minutes."}</Words>
      </Sentence>
      {help ? <Help>{help}</Help> : null}
      {showScript ? (
        <div className="rg-activity-script">
          <label className="rg-activity-sub">
            <span>Script path</span>
            <TextIn
              name="Scheduled task script path"
              value={s.script_path}
              placeholder={DEFAULT_SCRIPT_PATH}
              disabled={disabled}
              onChange={(v) => setScript("path", v)}
            />
          </label>
          <textarea
            aria-label="Scheduled task script body"
            value={s.script_content == null ? "" : String(s.script_content)}
            rows={Math.min(10, Math.max(3, String(s.script_content ?? "").split("\n").length))}
            placeholder={`PowerShell the script runs. Left empty it is ${DEFAULT_COMMAND}.`}
            spellCheck={false}
            disabled={disabled}
            onChange={(e) => setScript("body", e.target.value || undefined)}
          />
          {!s.script_path ? <Warn>Set a script path, or the script is not written.</Warn> : null}
        </div>
      ) : null}
      {s.user ? null : <Help>As SYSTEM no user credential is left on the host to capture.</Help>}
      {losesQuotes(s.command) ? (
        <Warn>Double quotes are stripped on the task's command line. Use single quotes, or a script.</Warn>
      ) : null}
      <label className="rg-activity-sub">
        <span>Task name</span>
        <TextIn
          name="Scheduled task name"
          value={s.name}
          placeholder={DEFAULT_TASK}
          disabled={disabled}
          onChange={(v) => setKey("name", v)}
        />
      </label>
      <Help>One scheduled task per host.</Help>
      {clash ? (
        <Warn>
          {s.name || DEFAULT_TASK} is also the {clash.title.toLowerCase()}'s task, so one replaces
          the other. Pick another name.
        </Warn>
      ) : null}
    </>
  );
}

// The simulated people on a Windows range host, one sentence each. Ticking a
// line ticks its vuln (the same overlay.vulns the Vulnerabilities list edits,
// with the same defaults), and its pickers write the vulns_vars keys its role
// reads, so the settings form leaves those keys to this section.
export function UserActivity({ node, document, provider, findings, disabled, onChange }) {
  const overlay = node.overlay || {};
  const vulns = Array.isArray(overlay.vulns) ? overlay.vulns : [];
  const raw = overlay.vulns_vars;
  const malformed = raw != null && !isPlainObject(raw);
  const vars = malformed ? undefined : raw;
  const locked = disabled || malformed;
  const hostId = node.id;
  const byRow = findingsByActivity(findings, vulns);
  const on = (id) => vulns.includes(id);
  const v = (key) => getVar(vars, key);
  const set = (key, value) => onChange({ ...overlay, vulns_vars: setVar(vars, key, value) });
  const toggle = (id, next) =>
    onChange(withVulnDefaults(document, node, { ...overlay, vulns: toggled(overlay.vulns, id, next) }));
  const user = (name, key, emptyLabel) => (
    <UserPick
      name={name}
      value={v(key)}
      emptyLabel={emptyLabel}
      document={document}
      hostId={hostId}
      disabled={locked}
      onChange={(x) => set(key, x)}
    />
  );
  const botUser = typeof v("bot_user") === "string" ? v("bot_user") : "";
  const botMins = v("bot_interval_minutes");
  const botShown = botMins == null || botMins === "" ? DEFAULT_BOT_MINUTES : Number(botMins);
  const signin = malformed ? null : consoleSigninUser(overlay, provider);

  const sentences = {
    rdp_scheduler: (
      <>
        <Sentence>
          {user("Logon bot user", "bot_user", "pick a user")}
          <Words>logs on to this host every</Words>
          <input
            type="number"
            className="rg-activity-num"
            aria-label="Logon bot interval in minutes"
            min={1}
            max={MAX_BOT_MINUTES}
            step={1}
            value={botMins ?? ""}
            placeholder={String(DEFAULT_BOT_MINUTES)}
            disabled={locked}
            onChange={(e) => set("bot_interval_minutes", e.target.value === "" ? undefined : Number(e.target.value))}
          />
          <Words>{botShown === 1 ? "minute," : "minutes,"} so their credentials stay in memory.</Words>
        </Sentence>
        {botShown !== botMinutes(botMins) ? (
          <Warn>
            Not a whole number of minutes from 1 to {MAX_BOT_MINUTES} (31 days), so the bot
            runs every {botMinutes(botMins)} minutes.
          </Warn>
        ) : null}
      </>
    ),
    schedule: (
      <ScheduleActivity
        schedule={v("schedule")}
        vulns={vulns}
        document={document}
        hostId={hostId}
        disabled={locked}
        onChange={(next) => set("schedule", next)}
      />
    ),
    responder: (
      <>
        <Sentence>
          {user("Share-browsing bot user", "bot_user", "pick a user")}
          <Words>opens</Words>
          <TextIn
            name="Share the bot opens"
            className="rg-activity-wide"
            value={v("responder_target")}
            placeholder="\\Bravos\private"
            disabled={locked}
            onChange={(x) => set("responder_target", x)}
          />
          <Words>every 2 minutes.</Words>
        </Sentence>
        <Help>
          Name a host that does not resolve, so the lookup falls back to LLMNR and NBT-NS and a
          poisoner can answer and capture the hash.
        </Help>
        {on("rdp_scheduler") ? <Help>The same user as the logon bot: both read bot_user.</Help> : null}
      </>
    ),
    ntlm_relay: (
      <>
        <Sentence>
          {user(
            "Relay bot user",
            "ntlm_relay_user",
            botUser ? `same as the bot user, ${botUser}` : "pick a user"
          )}
          <Words>authenticates to</Words>
          <TextIn
            name="Share the relay bot authenticates to"
            className="rg-activity-wide"
            value={v("ntlm_relay_target")}
            placeholder="\\Meren\Private"
            disabled={locked}
            onChange={(x) => set("ntlm_relay_target", x)}
          />
          <Words>every 5 minutes.</Words>
        </Sentence>
        <Help>
          Pick a privileged user. Name a host that does not resolve, so a poisoner can answer and
          relay the authentication.
        </Help>
      </>
    ),
    stored_credential: (
      <>
        <Sentence>
          {user("Saved credential owner", "stored_credential.owner", "pick a user")}
          <Words>has a saved credential for</Words>
          {user("Saved credential account", "stored_credential.username", "pick an account")}
          <Words>to</Words>
          <span className="rg-activity-pick">
            <HostServiceInput
              name="Saved credential target"
              value={v("stored_credential.target")}
              groups={choicesFor("termsrv", document, hostId)}
              placeholder="TERMSRV/castelblack"
              disabled={locked}
              onChange={(x) => set("stored_credential.target", x)}
            />
          </span>
        </Sentence>
        <Help>
          Saved once at deploy in the owner's Credential Manager, with the account's own password.
          TERMSRV/host is an RDP credential.
        </Help>
      </>
    ),
  };

  return (
    <div className="rg-field rg-activities">
      <span className="rg-field-label">User activity</span>
      <Help>
        People simulated on this host. Each line ticks its vulnerability above and fills in what
        it reads.
      </Help>
      {malformed ? (
        <span className="rg-field-error">
          The vulnerability settings are not a JSON object, so these cannot be read. Fix them in
          Edit as JSON below.
        </span>
      ) : null}
      {ACTIVITIES.map((a) => (
        <ActivityRow
          key={a.id}
          activity={a}
          on={on(a.id)}
          blocked={providerBlock(a.id, provider)}
          disabled={disabled}
          findings={byRow[a.id]}
          onToggle={(next) => toggle(a.id, next)}
        >
          {sentences[a.id]}
        </ActivityRow>
      ))}
      {signin ? (
        <Help>
          On Windows 10 and 11, {signin} is signed in at the console at boot, because Windows runs a
          user's scheduled tasks only after someone signs in.
        </Help>
      ) : null}
    </div>
  );
}
