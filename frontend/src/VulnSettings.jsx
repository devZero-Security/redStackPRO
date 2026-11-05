import React, { useEffect, useState } from "react";
import "./widgets.css";
import { CheckListPicker, DelegateToPicker } from "./DelegateToPicker.jsx";
import { findingsAt, isNotice } from "./fieldRules.js";
import { hostDomain, spnChoices } from "./spnChoices.js";
import {
  PICKS, choicesFor, describeRow, formSections, getVar, isPlainObject, matchOption,
  rowColumns, rowKind, setElsewhere, setVar,
} from "./vulnForm.js";

const OTHER = "__other__";

// A select over grouped choices, with "Other, type it" for a value the list does
// not hold. A stored value it does not match shows in the typed box, never
// silently replaced. With no choices at all it is the typed box alone.
export function PickInput({
  name, value, groups, onChange, disabled, required, emptyLabel, allowOther = true,
  typedHint, unknownNote, emptyText, placeholder,
}) {
  const text = value == null ? "" : String(value);
  const match = matchOption(groups, text);
  const [typing, setTyping] = useState(false);
  const hasChoices = groups.some((g) => g.options.length);
  const typed = (
    <input
      aria-label={hasChoices ? `${name}, typed` : name}
      value={text}
      placeholder={placeholder}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value || undefined)}
    />
  );
  const hints = (
    <>
      {text && !match && unknownNote ? <span className="rg-widget-warn">{unknownNote}</span> : null}
      {typedHint && !disabled ? <span className="rg-field-help">Type it as {typedHint}.</span> : null}
    </>
  );
  if (!hasChoices) {
    return (
      <>
        {typed}
        {emptyText ? <span className="rg-field-help">{emptyText}</span> : null}
        {hints}
      </>
    );
  }
  const other = allowOther && (typing || (text !== "" && !match));
  const selected = match ? match.value : other ? OTHER : text;
  return (
    <>
      <select
        aria-label={name}
        value={selected}
        disabled={disabled}
        onChange={(e) => {
          const v = e.target.value;
          if (v === OTHER) {
            setTyping(true);
            return;
          }
          setTyping(false);
          onChange(v || undefined);
        }}
      >
        <option value="">{emptyLabel || (required ? "pick one" : "not set")}</option>
        {groups.map((g) =>
          g.options.length ? (
            <optgroup key={g.label} label={g.label}>
              {g.options.map((o) => (
                <option key={o.value} value={o.value} title={o.about}>
                  {o.label || o.value}
                </option>
              ))}
            </optgroup>
          ) : null
        )}
        {!allowOther && text && !match ? <option value={text}>{text} (not a choice here)</option> : null}
        {allowOther ? <option value={OTHER}>Other, type it</option> : null}
      </select>
      {other ? (
        <>
          {typed}
          {hints}
        </>
      ) : null}
    </>
  );
}

// TERMSRV/<host>: pick the host, then the whole target stays editable.
function HostServiceInput({ name, value, groups, onChange, disabled, placeholder }) {
  const text = value == null ? "" : String(value);
  const m = /^([^/]+)\/(.*)$/.exec(text);
  const service = m ? m[1] : "TERMSRV";
  const picked = matchOption(groups, m ? m[2] : "");
  return (
    <>
      {groups.length ? (
        <select
          aria-label={`${name} host`}
          value={picked ? picked.value : ""}
          disabled={disabled}
          onChange={(e) => e.target.value && onChange(`${service}/${e.target.value}`)}
        >
          <option value="">pick a host</option>
          {groups.map((g) => (
            <optgroup key={g.label} label={g.label}>
              {g.options.map((o) => (
                <option key={o.value} value={o.value}>{o.label || o.value}</option>
              ))}
            </optgroup>
          ))}
        </select>
      ) : null}
      <input
        aria-label={name}
        value={text}
        placeholder={placeholder}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value || undefined)}
      />
    </>
  );
}

const parseLines = (text) => text.split("\n").map((s) => s.trim()).filter(Boolean);

// One entry per line. The text stays local so a new empty line survives typing.
function LinesInput({ name, value, onChange, disabled, placeholder }) {
  const toText = (v) => (Array.isArray(v) ? v.join("\n") : "");
  const [text, setText] = useState(() => toText(value));
  const committed = JSON.stringify(value ?? []);
  useEffect(() => {
    if (JSON.stringify(parseLines(text)) !== committed) setText(toText(value));
  }, [committed]);
  return (
    <textarea
      aria-label={name}
      value={text}
      rows={Math.min(6, Math.max(2, text.split("\n").length))}
      placeholder={placeholder}
      disabled={disabled}
      onChange={(e) => {
        setText(e.target.value);
        const list = parseLines(e.target.value);
        onChange(list.length ? list : undefined);
      }}
    />
  );
}

// A list of objects, one row each. Rows are added whole from the bar below, so
// the document never holds a half-filled row the role would trip on.
function RowsInput({ name, kind, rows, columns, disabled, onChange }) {
  const initial = () =>
    Object.fromEntries(columns.filter((c) => c.initial).map((c) => [c.field, c.initial]));
  const [draft, setDraft] = useState(initial);
  const ready = columns.every((c) => !c.required || String(draft[c.field] ?? "").trim());
  const add = () => {
    const row = {};
    for (const c of columns) {
      const v = String(draft[c.field] ?? "");
      if (v.trim()) row[c.field] = c.multiline ? v : v.trim();
    }
    onChange([...rows, row]);
    setDraft(initial());
  };
  const setCell = (field, v) => setDraft((d) => ({ ...d, [field]: v }));
  return (
    <>
      {rows.length ? (
        <div className="rg-acls-list rg-vuln-rows">
          {rows.map((r, i) => (
            <div key={i} className="rg-acl-row">
              <span className="rg-acl-pair">
                <span className="rg-acl-p" title={describeRow(kind, r)}>{describeRow(kind, r)}</span>
              </span>
              {disabled ? null : (
                <button
                  type="button"
                  className="rg-user-del"
                  aria-label={`Remove ${name} row ${i + 1}`}
                  title="Remove row"
                  onClick={() => onChange(rows.filter((_, j) => j !== i))}
                >
                  &times;
                </button>
              )}
            </div>
          ))}
        </div>
      ) : (
        <span className="rg-field-help">None yet.</span>
      )}
      {disabled ? null : (
        <div className="rg-vuln-rows-add">
          {columns.map((c) => {
            const cell = `${name} new ${c.label}`;
            if (c.choices?.length) {
              return (
                <div key={c.field} className="rg-vuln-rows-cell">
                  <PickInput
                    name={cell}
                    value={draft[c.field]}
                    groups={c.choices}
                    required={c.required}
                    emptyLabel={c.label}
                    placeholder={c.placeholder}
                    onChange={(v) => setCell(c.field, v)}
                  />
                </div>
              );
            }
            const Tag = c.multiline ? "textarea" : "input";
            return (
              <Tag
                key={c.field}
                aria-label={cell}
                value={draft[c.field] ?? ""}
                placeholder={c.placeholder}
                rows={c.multiline ? 3 : undefined}
                onChange={(e) => setCell(c.field, e.target.value)}
              />
            );
          })}
          <button type="button" aria-label={`Add to ${name}`} disabled={!ready} onClick={add}>
            Add
          </button>
        </div>
      )}
    </>
  );
}

const ARRAY_SHAPED = new Set(["spns", "sql_hosts"]);
const wantsArray = (p) => ARRAY_SHAPED.has(p.pick) || p.input === "lines" || !!rowKind(p);

function shapeOk(param, value) {
  if (value == null) return true;
  if (wantsArray(param)) return Array.isArray(value);
  return typeof value === "string" || typeof value === "number";
}

const shown = (v) => (Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v));

const userNote = "Not a user in this range.";

function emptyTextFor(pick, joined) {
  if (pick === "domain_user") return "No users in this range yet. Add them on a domain, or type one.";
  if (!joined) return "Join this host to a domain to pick from it, or type a value.";
  if (pick === "bare_user") return "No users on this domain yet. Add them on the domain, or type one.";
  if (pick === "ou") return "No OUs on this domain yet. Add them on the domain, or type a distinguished name.";
  return null;
}

// One key of the settings: its name, required or not, the input its pick or
// shape calls for, what it does, and any finding the server raised on it.
function VulnKey({ param, vars, document, hostId, findings, disabled, onSet }) {
  const value = getVar(vars, param.key);
  const at = findingsAt(findings, `vulns_vars.${param.key}`);
  const errors = at.filter((f) => !isNotice(f));
  const elsewhere = setElsewhere(document, hostId, param.key);
  const orValue = param.or ? getVar(vars, param.or) : undefined;
  const fallback = elsewhere
    ? `set on ${elsewhere.host}: ${shown(elsewhere.value)}`
    : orValue
      ? `uses ${param.or}: ${shown(orValue)}`
      : null;
  const joined = !!hostDomain(document, hostId);
  const set = (v) => onSet(param.key, v);
  const placeholder =
    "example" in param && typeof param.example !== "object" ? String(param.example) : undefined;
  const kind = rowKind(param);

  let control;
  if (!shapeOk(param, value)) {
    control = (
      <span className="rg-field-error">
        The stored value is not {wantsArray(param) ? "a list" : "text"}. Fix it in Edit as JSON below.
      </span>
    );
  } else if (param.pick === "spns") {
    control = (
      <DelegateToPicker
        label={null}
        className="rg-delegate"
        value={value}
        groups={spnChoices(document, hostDomain(document, hostId), { exclude: hostId })}
        disabled={disabled}
        onChange={set}
      />
    );
  } else if (param.pick === "sql_hosts") {
    control = (
      <CheckListPicker
        className="rg-delegate"
        value={value}
        groups={choicesFor("sql_hosts", document, hostId)}
        disabled={disabled}
        onChange={set}
        checkLabel={(o) => `Link to ${o.value}`}
        emptyText="No SQL host in this range yet. Give a host the mssql service, or type an FQDN below."
        otherLabel={`${param.key}, other host`}
        otherPlaceholder="Other SQL host, e.g. sql02.corp.local"
        addLabel="Add SQL host"
        customTitle="Typed by hand, not a SQL host in this range"
        summary={(sel) => (sel.length ? `Links to: ${sel.join(", ")}.` : "Nothing picked yet.")}
      />
    );
  } else if (kind) {
    control = (
      <RowsInput
        name={param.key}
        kind={kind}
        rows={value || []}
        columns={rowColumns(kind, document, hostId, vars)}
        disabled={disabled}
        onChange={set}
      />
    );
  } else if (param.pick === "termsrv") {
    control = (
      <HostServiceInput
        name={param.key}
        value={value}
        groups={choicesFor("termsrv", document, hostId)}
        disabled={disabled}
        placeholder={placeholder}
        onChange={set}
      />
    );
  } else if (param.pick) {
    const users = param.pick === "domain_user" || param.pick === "bare_user";
    control = (
      <PickInput
        name={param.key}
        value={value}
        groups={choicesFor(param.pick, document, hostId)}
        required={param.required}
        emptyLabel={fallback}
        allowOther={param.pick !== "fs_rights"}
        typedHint={param.pick === "fs_rights" ? null : PICKS[param.pick]}
        unknownNote={
          users ? userNote
            : param.pick === "group" ? "Not a group on this domain yet. It is created as an empty group."
              : null
        }
        emptyText={emptyTextFor(param.pick, joined)}
        placeholder={placeholder}
        disabled={disabled}
        onChange={set}
      />
    );
  } else if (param.input === "number") {
    control = (
      <input
        type="number"
        aria-label={param.key}
        value={value ?? ""}
        min={1}
        step={1}
        placeholder={placeholder}
        disabled={disabled}
        onChange={(e) => set(e.target.value === "" ? undefined : Number(e.target.value))}
      />
    );
  } else if (param.input === "lines") {
    control = (
      <LinesInput
        name={param.key}
        value={value}
        placeholder={Array.isArray(param.example) ? param.example.join("\n") : undefined}
        disabled={disabled}
        onChange={set}
      />
    );
  } else if (param.input === "multiline") {
    control = (
      <textarea
        aria-label={param.key}
        value={value ?? ""}
        rows={Math.min(10, Math.max(3, String(value ?? "").split("\n").length))}
        spellCheck={false}
        disabled={disabled}
        onChange={(e) => set(e.target.value || undefined)}
      />
    );
  } else {
    control = (
      <input
        aria-label={param.key}
        value={value ?? ""}
        placeholder={fallback || placeholder}
        disabled={disabled}
        onChange={(e) => set(e.target.value || undefined)}
      />
    );
  }

  return (
    <div className={errors.length ? "rg-field rg-vuln-key-field is-invalid" : "rg-field rg-vuln-key-field"}>
      <span className="rg-vuln-key">
        <code>{param.key}</code>
        {param.required ? (
          <span className="rg-required">required{param.or ? ` (or ${param.or})` : ""}</span>
        ) : (
          <span className="rg-optional">optional</span>
        )}
      </span>
      {control}
      <span className="rg-field-help">{param.about}</span>
      {at.map((f, i) => (
        <span key={i} className={isNotice(f) ? `rg-field-finding is-${f.severity}` : "rg-field-error"}>
          {f.message}
        </span>
      ))}
    </div>
  );
}

// The vulnerability settings as a form: for each ticked vuln that reads
// settings, one input per key it reads, a picker where the value names
// something in the topology. It edits the same vulns_vars object as the JSON
// view below it, so either one can be used and both stay in step.
export function VulnSettings({ title, node, document, findings, disabled, onChange }) {
  const overlay = node.overlay || {};
  const vars = overlay.vulns_vars;
  const sections = formSections(overlay.vulns);
  if (!sections.length) return null;
  const malformed = vars != null && !isPlainObject(vars);
  return (
    <div className="rg-vuln-form">
      <span className="rg-field-label">{title}</span>
      <span className="rg-field-help">
        What the ticked vulnerabilities read. Where a setting names a user, group or
        host, pick it from this range.
      </span>
      {malformed ? (
        <span className="rg-field-error">
          These settings are not a JSON object, so the form cannot read them. Fix them in
          Edit as JSON below.
        </span>
      ) : (
        sections.map((s) => (
          <fieldset key={s.vuln} className="rg-fieldset rg-vuln-section">
            <legend>{s.label}</legend>
            {s.params.map((p) => (
              <VulnKey
                key={p.key}
                param={p}
                vars={vars}
                document={document}
                hostId={node.id}
                findings={findings}
                disabled={disabled}
                onSet={(key, value) => onChange(setVar(vars, key, value))}
              />
            ))}
            {s.shared.map((x) => (
              <span key={x.key} className="rg-field-help">
                Also reads <code>{x.key}</code>, set under {x.under} above.
              </span>
            ))}
          </fieldset>
        ))
      )}
    </div>
  );
}
