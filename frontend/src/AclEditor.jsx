import React, { useId, useState } from "react";
import "./widgets.css";
import {
  domainDirectory, principalChoices, principalStatus, targetChoices, targetStatus,
} from "./domainDirectory.js";

// The rights that compile: every name apply_acls.ps1 knows, plus the aliases
// the compiler maps onto them (ACL_ALIASES). tests/test_canvas_widgets_sync.py
// checks both against the script and the compiler. One entry per line.
export const ACL_RIGHTS = [
  { value: "GenericAll", label: "GenericAll", meaning: "Full control of the target." },
  { value: "GenericWrite", label: "GenericWrite", meaning: "Write the target's attributes, such as an SPN or a logon script." },
  { value: "WriteDacl", label: "WriteDacl", meaning: "Rewrite the target's permissions, then grant any right." },
  { value: "WriteOwner", label: "WriteOwner", meaning: "Take ownership of the target, then rewrite its permissions." },
  { value: "ForceChangePassword", label: "ForceChangePassword", meaning: "Reset the target user's password without knowing the old one." },
  { value: "AddMember", label: "AddMember", meaning: "Add any account to the target group." },
  { value: "WriteSPN", label: "WriteSPN", meaning: "Set an SPN on the target account, for a targeted Kerberoast." },
  { value: "Ext-Self-Self-Membership", label: "Add self to group", meaning: "Add yourself to the target group." },
  { value: "WriteProperty", label: "WriteProperty", meaning: "Write any property of the target." },
  { value: "ReadProperty", label: "ReadProperty", meaning: "Read the target's properties." },
  { value: "GenericExecute", label: "GenericExecute", meaning: "List and read the target." },
  { value: "Self", label: "Self", meaning: "Validated writes on the target, such as adding yourself to a group." },
  { value: "Ext-User-Force-Change-Password", label: "Force change password (AD name)", meaning: "Same as ForceChangePassword." },
  { value: "Ext-Write-SPN", label: "Write SPN (AD name)", meaning: "Same as WriteSPN." },
  { value: "Ext-Write-Self-Membership", label: "Write self membership (AD name)", meaning: "Same as Add self to group." },
];

// Canvas label to the apply_acls.ps1 name, as the compiler maps it.
export const ACL_ALIASES = {
  ForceChangePassword: "Ext-User-Force-Change-Password",
  AddMember: "Ext-Write-Member",
  WriteSPN: "Ext-Write-SPN",
};

const lower = (s) => String(s || "").toLowerCase();

// The dropdown entry for a saved right, matched without case the way the
// compiler and the script match it. An alias target with no entry of its own
// (Ext-Write-Member) reads as its alias.
function rightInfo(right) {
  const hit = ACL_RIGHTS.find((r) => lower(r.value) === lower(right));
  if (hit) return hit;
  const alias = Object.entries(ACL_ALIASES).find(([, v]) => lower(v) === lower(right));
  return alias ? { value: right, label: `${alias[0]} (AD name)`, meaning: `Same as ${alias[0]}.` } : null;
}

// A readable label for a right that is not in the list above, which may
// arrive as a raw AD string from an import. The stored value is kept.
function prettyRight(right) {
  return (right || "")
    .replace(/^Ext-/, "")
    .replace(/-/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2");
}

// What apply_acls.ps1 does with a name it cannot find (see domainDirectory.js).
function principalNote(dir, name) {
  return principalStatus(dir, name) === "created"
    ? `${name} is not found on this domain; it would be created as an empty group.`
    : null;
}

function targetNote(dir, name) {
  const status = targetStatus(dir, name);
  if (status === "created") {
    return `${name} is not found on this domain; it would be created as an empty group, so the right lands on nothing useful.`;
  }
  if (status === "skipped") return `${name} is not found on this domain; this right would be skipped.`;
  return null;
}

// The dangerous access rights on a domain: who can act on whom. This is the
// attack graph the users and groups sit inside, the same acls GOAD carries and
// BloodHound walks. See 0052.
export function AclEditor({ node, document, onChange, readOnly }) {
  const overlay = node.overlay || {};
  const acls = overlay.acls || [];
  const [principal, setPrincipal] = useState("");
  const [target, setTarget] = useState("");
  const [right, setRight] = useState("GenericAll");
  const principalList = useId();
  const targetList = useId();

  const dir = domainDirectory(document, node);
  const principals = principalChoices(dir);
  const targets = targetChoices(dir);

  const set = (next) => onChange({ ...overlay, acls: next.length ? next : undefined });
  // A name only an access right uses becomes one of the domain's own groups,
  // which the dc role creates on purpose rather than as a side effect.
  const addGroup = (name) => {
    const groups = Array.isArray(overlay.groups) ? overlay.groups : [];
    if (groups.some((g) => lower(g) === lower(name))) return;
    onChange({ ...overlay, groups: [...groups, name] });
  };
  // The unknown plain names in a principal and target pair, once each.
  const newGroups = (p, t) =>
    [...new Set([
      principalStatus(dir, p) === "created" ? p : null,
      targetStatus(dir, t) === "created" ? t : null,
    ].filter(Boolean))];
  const groupButtons = (names) =>
    readOnly
      ? null
      : names.map((name) => (
          <button
            key={name}
            type="button"
            className="rg-inline-btn rg-acl-group-btn"
            onClick={() => addGroup(name)}
          >
            Add {name} as a domain group
          </button>
        ));
  const add = () => {
    if (!principal.trim() || !target.trim() || !right.trim()) return;
    set([...acls, { principal: principal.trim(), target: target.trim(), right: right.trim() }]);
    setPrincipal("");
    setTarget("");
  };

  const pNote = principal.trim() ? principalNote(dir, principal.trim()) : null;
  const tNote = target.trim() ? targetNote(dir, target.trim()) : null;

  return (
    <div className="rg-acls">
      <h3>Access rights{acls.length ? ` (${acls.length})` : ""}</h3>
      <p className="rg-hint">
        Who can act on whom: the escalation edges that make the domain an attack
        graph. Pick the principal and target from this domain&apos;s users,
        groups, computers and OUs.
      </p>
      {acls.length ? (
        <div className="rg-acls-list">
          {acls.map((a, i) => {
            const known = rightInfo(a.right);
            const fresh = newGroups(a.principal, a.target);
            const notes = [
              principalNote(dir, a.principal),
              targetNote(dir, a.target),
              known ? null : `${a.right} is not a right redStackPRO applies; this entry is skipped.`,
            ].filter(Boolean);
            return (
              <div key={i} className="rg-acl-row">
                <span className="rg-acl-pair">
                  <span className="rg-acl-p" title={a.principal}>{a.principal}</span>
                  <span className="rg-acl-arrow" aria-hidden="true">&rarr;</span>
                  <span className="rg-acl-t" title={a.target}>{a.target}</span>
                </span>
                <span className="rg-acl-right" title={known ? known.meaning : a.right}>
                  {known ? known.label : prettyRight(a.right)}
                </span>
                {notes.length ? (
                  <span className="rg-acl-notes">
                    {notes.map((n) => (
                      <span key={n} className="rg-widget-warn">{n}</span>
                    ))}
                    {groupButtons(fresh)}
                  </span>
                ) : null}
                {readOnly ? null : (
                  <button
                    type="button"
                    className="rg-user-del"
                    title="Remove right"
                    aria-label="Remove right"
                    onClick={() => set(acls.filter((_, j) => j !== i))}
                  >
                    &times;
                  </button>
                )}
              </div>
            );
          })}
        </div>
      ) : null}
      {/* Reading order matches the sentence the row makes: principal, target,
          then the right that connects them, then Add. */}
      {readOnly ? null : (
        <>
          <div className="rg-acls-add">
            <input
              value={principal}
              placeholder="principal"
              aria-label="principal"
              list={principalList}
              onChange={(e) => setPrincipal(e.target.value)}
            />
            <input
              value={target}
              placeholder="target"
              aria-label="target"
              list={targetList}
              onChange={(e) => setTarget(e.target.value)}
            />
            <select aria-label="right" value={right} onChange={(e) => setRight(e.target.value)}>
              {ACL_RIGHTS.map((r) => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
            <button type="button" onClick={add} disabled={!principal.trim() || !target.trim()}>Add</button>
          </div>
          <datalist id={principalList}>
            {principals.map((c) => (
              <option key={`${c.kind}:${c.value}`} value={c.value} label={c.kind} />
            ))}
          </datalist>
          <datalist id={targetList}>
            {targets.map((c) => (
              <option key={`${c.kind}:${c.value}`} value={c.value} label={c.kind} />
            ))}
          </datalist>
          <span className="rg-field-help">{rightInfo(right)?.meaning}</span>
          {pNote ? <span className="rg-widget-warn">{pNote}</span> : null}
          {tNote ? <span className="rg-widget-warn">{tNote}</span> : null}
          {groupButtons(newGroups(principal.trim(), target.trim()))}
        </>
      )}
    </div>
  );
}
