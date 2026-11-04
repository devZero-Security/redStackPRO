import React, { useId, useState } from "react";
import "./widgets.css";
import {
  domainDirectory, principalChoices, principalStatus, targetChoices, targetStatus,
} from "./domainDirectory.js";

// The rights that compile: every name apply_acls.ps1 knows, plus the two
// aliases the compiler maps onto them. tests/test_canvas_widgets_sync.py
// checks this list against the script. One entry per line.
export const ACL_RIGHTS = [
  { value: "GenericAll", label: "GenericAll", meaning: "Full control of the target." },
  { value: "GenericWrite", label: "GenericWrite", meaning: "Write the target's attributes, such as an SPN or a logon script." },
  { value: "WriteDacl", label: "WriteDacl", meaning: "Rewrite the target's permissions, then grant any right." },
  { value: "WriteOwner", label: "WriteOwner", meaning: "Take ownership of the target, then rewrite its permissions." },
  { value: "ForceChangePassword", label: "ForceChangePassword", meaning: "Reset the target user's password without knowing the old one." },
  { value: "AddMember", label: "AddMember", meaning: "Add any account to the target group." },
  { value: "Ext-Self-Self-Membership", label: "Add self to group", meaning: "Add yourself to the target group." },
  { value: "Ext-Write-SPN", label: "Write SPN", meaning: "Set an SPN on the target account, for a targeted Kerberoast." },
  { value: "WriteProperty", label: "WriteProperty", meaning: "Write any property of the target." },
  { value: "ReadProperty", label: "ReadProperty", meaning: "Read the target's properties." },
  { value: "GenericExecute", label: "GenericExecute", meaning: "List and read the target." },
  { value: "Self", label: "Self", meaning: "Validated writes on the target, such as adding yourself to a group." },
  { value: "Ext-User-Force-Change-Password", label: "Force change password (AD name)", meaning: "Same as ForceChangePassword." },
  { value: "Ext-Write-Self-Membership", label: "Write self membership (AD name)", meaning: "Same as Add self to group." },
];

const RIGHT_BY_VALUE = Object.fromEntries(ACL_RIGHTS.map((r) => [r.value, r]));

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
  const acls = (node.overlay || {}).acls || [];
  const [principal, setPrincipal] = useState("");
  const [target, setTarget] = useState("");
  const [right, setRight] = useState("GenericAll");
  const principalList = useId();
  const targetList = useId();

  const dir = domainDirectory(document, node);
  const principals = principalChoices(dir);
  const targets = targetChoices(dir);

  const set = (next) => onChange({ ...(node.overlay || {}), acls: next.length ? next : undefined });
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
            const known = RIGHT_BY_VALUE[a.right];
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
          <span className="rg-field-help">{RIGHT_BY_VALUE[right]?.meaning}</span>
          {pNote ? <span className="rg-widget-warn">{pNote}</span> : null}
          {tNote ? <span className="rg-widget-warn">{tNote}</span> : null}
        </>
      )}
    </div>
  );
}
