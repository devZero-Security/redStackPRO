import React, { useId, useState } from "react";
import "./widgets.css";
import { allGroups, groupKnown } from "./domainDirectory.js";

// Group-in-group nesting on a domain: {parent group: [member groups]}, the
// chain GOAD builds as Dragons in QueenProtector in Domain Admins. The dc role
// creates every group named here and adds each member to its parent.
export function GroupNesting({ node, onChange, readOnly }) {
  const overlay = node.overlay || {};
  const raw = overlay.group_members;
  const nesting = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const [parent, setParent] = useState("");
  const [member, setMember] = useState("");
  const listId = useId();
  const groups = allGroups(overlay);

  const set = (next) =>
    onChange({ ...overlay, group_members: Object.keys(next).length ? next : undefined });

  const addPair = (p, m) => {
    const pk = Object.keys(nesting).find((k) => k.toLowerCase() === p.toLowerCase()) || p;
    const cur = Array.isArray(nesting[pk]) ? nesting[pk] : [];
    if (cur.some((x) => x.toLowerCase() === m.toLowerCase())) return;
    set({ ...nesting, [pk]: [...cur, m] });
  };
  const removePair = (p, m) => {
    const rest = (nesting[p] || []).filter((x) => x !== m);
    const next = { ...nesting };
    if (rest.length) next[p] = rest;
    else delete next[p];
    set(next);
  };
  const add = () => {
    const p = parent.trim();
    const m = member.trim();
    if (!p || !m || p.toLowerCase() === m.toLowerCase()) return;
    addPair(p, m);
    setMember("");
  };

  const fresh = [parent.trim(), member.trim()].filter((g) => g && !groupKnown(overlay, g));
  const pairs = Object.entries(nesting).flatMap(([p, ms]) =>
    (Array.isArray(ms) ? ms : []).map((m) => ({ parent: p, member: m }))
  );

  return (
    <div className="rg-acls rg-nesting">
      <h3>Group nesting{pairs.length ? ` (${pairs.length})` : ""}</h3>
      <p className="rg-hint">
        Groups that are members of other groups. Each member group gets every
        right its parent group has.
      </p>
      {pairs.length ? (
        <div className="rg-acls-list">
          {pairs.map(({ parent: p, member: m }) => (
            <div key={`${p}\u0000${m}`} className="rg-acl-row">
              <span className="rg-acl-pair">
                <span className="rg-acl-p" title={m}>{m}</span>
                <span className="rg-acl-arrow" aria-hidden="true">&rarr;</span>
                <span className="rg-acl-t" title={p}>{p}</span>
              </span>
              <span className="rg-acl-right">member of</span>
              {readOnly ? null : (
                <button
                  type="button"
                  className="rg-user-del"
                  title="Remove nesting"
                  aria-label="Remove nesting"
                  onClick={() => removePair(p, m)}
                >
                  &times;
                </button>
              )}
            </div>
          ))}
        </div>
      ) : null}
      {readOnly ? null : (
        <>
          <div className="rg-acls-add">
            <input
              value={member}
              placeholder="member group"
              aria-label="member group"
              list={listId}
              onChange={(e) => setMember(e.target.value)}
            />
            <input
              value={parent}
              placeholder="parent group"
              aria-label="parent group"
              list={listId}
              onChange={(e) => setParent(e.target.value)}
            />
            <button
              type="button"
              onClick={add}
              disabled={!parent.trim() || !member.trim() || parent.trim().toLowerCase() === member.trim().toLowerCase()}
            >
              Add
            </button>
          </div>
          <datalist id={listId}>
            {groups.map((g) => (
              <option key={g} value={g} />
            ))}
          </datalist>
          <span className="rg-field-help">The member group joins the parent group.</span>
          {fresh.map((g) => (
            <span key={g} className="rg-field-help">
              {g} is not on this domain yet; it will be created as a new group.
            </span>
          ))}
        </>
      )}
    </div>
  );
}
