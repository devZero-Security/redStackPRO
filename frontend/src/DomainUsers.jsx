import React, { useId, useState } from "react";
import "./widgets.css";
import {
  USER_ARCHETYPES, addUser, buildArchetype, generateUsers, recommendedUserCount,
  removeUser, setUsers, updateUser,
} from "./rangeUsers.js";
import { allGroups, groupKnown, joinedHosts } from "./domainDirectory.js";

const PRIVILEGES = ["user", "local_admin", "domain_admin", "enterprise_admin"];

// What each privilege does at deploy, from ansible.py domain_files and
// _local_admins_for.
export const PRIVILEGE_HELP = {
  user: "An ordinary domain member. No extra groups.",
  local_admin: "Added to local Administrators on every Windows member server and workstation in this domain.",
  domain_admin: "Added to Domain Admins.",
  enterprise_admin: "Added to Enterprise Admins and Domain Admins.",
};

export const BREACH_HELP =
  "The low-privilege user an operator starts as. Gets a portal tile on one workstation in this domain (a server if there is none) and is named in the range briefing.";

// The flaws offered, in this order, each with what the dc role does for it.
// `also` lists a schema id that does the same thing; it counts as this flaw
// and unticking removes both.
export const SHOWN_FLAWS = [
  { id: "kerberoastable", also: ["spn_set"], label: "Kerberoastable", help: "Sets an SPN on the account and pins it to RC4, so its service ticket can be requested and cracked." },
  { id: "asrep_roastable", also: ["no_preauth"], label: "AS-REP roastable", help: "Turns off Kerberos pre-authentication, so anyone can request a crackable AS-REP for it." },
  { id: "password_in_description", label: "Password in description", help: "Plants nothing by itself: write the password into the Description below." },
  { id: "weak_password", label: "Weak password", help: "Sets a sprayable password when the account has no password of its own." },
  { id: "constrained_delegation", label: "Constrained delegation", help: "Trusted to delegate with protocol transition (S4U) to the SPNs in Delegate to." },
  { id: "account_is_sensitive", label: "Sensitive, cannot be delegated", help: "Marks the account sensitive so it cannot be delegated. A defensive setting that shapes a delegation path." },
];

// Flaws that do nothing at deploy. Not offered; an existing one still shows,
// ticked, so it can be removed.
export const HIDDEN_FLAWS = {
  password_never_expires: "Password never expires (already on for every account)",
  reversible_encryption: "Reversible encryption (not applied)",
};

const ALIASES = Object.fromEntries(SHOWN_FLAWS.flatMap((f) => (f.also || []).map((a) => [a, f.id])));

// The distinct flaws a user carries, with the duplicate ids folded into the
// one they mean.
export function effectiveFlaws(flaws) {
  return [...new Set((flaws || []).map((f) => ALIASES[f] || f))];
}

const hasFlaw = (u, id) => effectiveFlaws(u.flaws).includes(id);

const splitList = (text) =>
  text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

function GroupChips({ user, overlay, disabled, onChange }) {
  const [draft, setDraft] = useState("");
  const listId = useId();
  const groups = user.groups || [];
  const add = () => {
    const g = draft.trim();
    if (!g) return;
    if (!groups.some((x) => x.toLowerCase() === g.toLowerCase())) onChange([...groups, g]);
    setDraft("");
  };
  const isNew = draft.trim() && !groupKnown(overlay, draft.trim());
  return (
    <div className="rg-field">
      <span className="rg-field-label">groups</span>
      <div className="rg-chips">
        {groups.map((g) => (
          <span key={g} className="rg-chip">
            {g}
            {disabled ? null : (
              <button
                type="button"
                className="rg-chip-del"
                title={`Remove ${g}`}
                aria-label={`Remove ${g}`}
                onClick={() => {
                  const next = groups.filter((x) => x !== g);
                  onChange(next.length ? next : undefined);
                }}
              >
                &times;
              </button>
            )}
          </span>
        ))}
        {groups.length ? null : <span className="rg-field-help">No groups yet.</span>}
      </div>
      {disabled ? null : (
        <div className="rg-users-add">
          <input
            value={draft}
            placeholder="add a group, e.g. IT"
            aria-label="add a group"
            list={listId}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                add();
              }
            }}
          />
          <button type="button" onClick={add} disabled={!draft.trim()}>Add</button>
          <datalist id={listId}>
            {allGroups(overlay).map((g) => (
              <option key={g} value={g} />
            ))}
          </datalist>
        </div>
      )}
      {isNew ? (
        <span className="rg-field-help">
          {draft.trim()} is not on this domain yet; it will be created as a new group.
        </span>
      ) : null}
    </div>
  );
}

function TextField({ label, value, placeholder, help, disabled, onChange }) {
  return (
    <label className="rg-field">
      <span className="rg-field-label">{label}</span>
      <input
        value={value ?? ""}
        placeholder={placeholder}
        aria-label={label}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value || undefined)}
      />
      {help ? <span className="rg-field-help">{help}</span> : null}
    </label>
  );
}

function ListField({ label, value, placeholder, help, disabled, onChange }) {
  // Local text so a trailing comma survives typing; the document gets the list.
  const [text, setText] = useState((value || []).join(", "));
  const committed = (value || []).join(", ");
  const shown = splitList(text).join(", ") === committed ? text : committed;
  return (
    <label className="rg-field">
      <span className="rg-field-label">{label}</span>
      <input
        value={shown}
        placeholder={placeholder}
        aria-label={label}
        disabled={disabled}
        onChange={(e) => {
          setText(e.target.value);
          const list = splitList(e.target.value);
          onChange(list.length ? list : undefined);
        }}
      />
      {help ? <span className="rg-field-help">{help}</span> : null}
    </label>
  );
}

// The user accounts on a domain. A person can add one by hand, change its
// privilege, expand it to edit its email, groups, and misconfigurations, or press
// Populate to fill the domain with a realistic population so a lab has bodies to
// hunt through, not just the accounts an attack path needs. The count Populate
// adds scales with the range's size. See rangeUsers.js and 0049.
export function DomainUsers({ node, document, rangeHostCount, flawOptions = [], onChange, readOnly }) {
  const overlay = node.overlay || {};
  const users = overlay.users || [];
  const fqdn = overlay.fqdn || "example.local";
  const [name, setName] = useState("");
  const [open, setOpen] = useState(-1);

  // Offered flaws: the shown set, limited to what the schema enum carries.
  const offered = SHOWN_FLAWS.filter((f) => !flawOptions.length || flawOptions.includes(f.id));
  const member = joinedHosts(document, node.id).find((h) => h.kind !== "dc");
  const delegateExample = `CIFS/${member ? member.name : "srv01"}.${fqdn}`;

  const patch = (i, p) => onChange(updateUser(node, i, p));

  const toggleFlaw = (i, flaw) => {
    const cur = users[i].flaws || [];
    const ids = [flaw.id, ...(flaw.also || [])];
    const next = hasFlaw(users[i], flaw.id)
      ? cur.filter((f) => !ids.includes(f))
      : [...cur, flaw.id];
    patch(i, { flaws: next.length ? next : undefined });
  };
  const removeFlaw = (i, id) => {
    const next = (users[i].flaws || []).filter((f) => f !== id);
    patch(i, { flaws: next.length ? next : undefined });
  };

  const add = () => {
    const username = name.trim();
    if (!username) return;
    onChange(addUser(node, { username, privilege: "user", email: `${username}@${fqdn}` }));
    setName("");
  };
  const populate = () => {
    const count = recommendedUserCount(rangeHostCount);
    onChange(setUsers(node, [...users, ...generateUsers(count, fqdn, Math.random, users)]));
  };
  const addArchetype = (id) => {
    const u = buildArchetype(id, fqdn, users);
    if (u) onChange(addUser(node, u));
  };

  return (
    <div className="rg-users">
      <h3>Users{users.length ? ` (${users.length})` : ""}</h3>
      <p className="rg-hint">
        Accounts on this domain. Populate fills it with a realistic set sized to
        the range; add your own for the accounts an attack path turns on.
      </p>
      {readOnly ? null : (
        <div className="rg-users-actions">
          <button type="button" onClick={populate}>Populate random</button>
          {users.length ? (
            <button type="button" className="rg-danger-text" onClick={() => onChange(setUsers(node, []))}>
              Clear
            </button>
          ) : null}
        </div>
      )}
      {readOnly ? null : (
        <div className="rg-users-archetypes">
          <span className="rg-field-label">add a class</span>
          {USER_ARCHETYPES.map((a) => (
            <button key={a.id} type="button" title={a.blurb} onClick={() => addArchetype(a.id)}>
              + {a.label}
            </button>
          ))}
        </div>
      )}
      {users.length ? (
        <div className="rg-users-list">
          {users.map((u, i) => {
            const flawCount = effectiveFlaws(u.flaws).length;
            const hidden = (u.flaws || []).filter((f) => HIDDEN_FLAWS[f]);
            const unknown = (u.flaws || []).filter(
              (f) => !HIDDEN_FLAWS[f] && !ALIASES[f] && !SHOWN_FLAWS.some((s) => s.id === f)
            );
            return (
              <div key={i} className={`rg-user ${open === i ? "is-open" : ""}`}>
                <div className="rg-user-row">
                  <button
                    type="button"
                    className="rg-user-name"
                    title="Edit this account"
                    onClick={() => setOpen(open === i ? -1 : i)}
                  >
                    {u.display_name || u.username}
                  </button>
                  <select
                    className={`rg-user-priv is-${u.privilege || "user"}`}
                    value={u.privilege || "user"}
                    title={PRIVILEGE_HELP[u.privilege || "user"]}
                    aria-label="privilege"
                    disabled={readOnly}
                    onChange={(e) => patch(i, { privilege: e.target.value })}
                  >
                    {PRIVILEGES.map((p) => (
                      <option key={p} value={p} title={PRIVILEGE_HELP[p]}>{p.replace("_", " ")}</option>
                    ))}
                  </select>
                  {flawCount ? (
                    <span className="rg-user-flaws" title={effectiveFlaws(u.flaws).join(", ")}>
                      {flawCount} flaw{flawCount === 1 ? "" : "s"}
                    </span>
                  ) : null}
                  {u.assumed_breach ? (
                    <span className="rg-user-breach" title={BREACH_HELP}>
                      breach
                    </span>
                  ) : null}
                  {readOnly ? null : (
                    <button
                      type="button"
                      className="rg-user-del"
                      title="Remove user"
                      onClick={() => onChange(removeUser(node, i))}
                    >
                      &times;
                    </button>
                  )}
                </div>
                {open === i ? (
                  <div className="rg-user-detail">
                    <span className="rg-field-help">{PRIVILEGE_HELP[u.privilege || "user"]}</span>
                    <TextField
                      label="email"
                      value={u.email}
                      disabled={readOnly}
                      onChange={(v) => patch(i, { email: v })}
                    />
                    <GroupChips
                      user={u}
                      overlay={overlay}
                      disabled={readOnly}
                      onChange={(groups) => patch(i, { groups })}
                    />
                    <div className="rg-field">
                      <span className="rg-field-label">misconfigurations</span>
                      <div className="rg-user-flaw-picks">
                        {offered.map((flaw) => (
                          <label key={flaw.id} className="rg-check" title={flaw.help}>
                            <input
                              type="checkbox"
                              checked={hasFlaw(u, flaw.id)}
                              disabled={readOnly}
                              onChange={() => toggleFlaw(i, flaw)}
                            />
                            {flaw.label}
                          </label>
                        ))}
                        {[...hidden, ...unknown].map((id) => (
                          <label key={id} className="rg-check is-noop" title="Does nothing at deploy. Untick to remove it.">
                            <input
                              type="checkbox"
                              checked
                              disabled={readOnly}
                              onChange={() => removeFlaw(i, id)}
                            />
                            {HIDDEN_FLAWS[id] || `${id} (not applied)`}
                          </label>
                        ))}
                      </div>
                    </div>
                    {hasFlaw(u, "password_in_description") || u.description ? (
                      <TextField
                        label="description"
                        value={u.description}
                        placeholder={`Password: ${u.password || "<the account's password>"}`}
                        help="Written to the account's AD description, where a description hunt finds it. Name a password the account really has: set Password below."
                        disabled={readOnly}
                        onChange={(v) => patch(i, { description: v })}
                      />
                    ) : null}
                    {hasFlaw(u, "password_in_description") || u.password ? (
                      <TextField
                        label="password"
                        value={u.password}
                        placeholder="shared lab password"
                        help="The account's own password. Empty uses the shared lab password, which is set at deploy."
                        disabled={readOnly}
                        onChange={(v) => patch(i, { password: v })}
                      />
                    ) : null}
                    {hasFlaw(u, "kerberoastable") || u.spns?.length ? (
                      <ListField
                        label="SPNs"
                        value={u.spns}
                        placeholder={`HTTP/${member ? member.name : "srv01"}.${fqdn}`}
                        help={`Comma separated. Empty sets MSSQLSvc/${u.username}.${fqdn}:1433.`}
                        disabled={readOnly}
                        onChange={(v) => patch(i, { spns: v })}
                      />
                    ) : null}
                    {hasFlaw(u, "constrained_delegation") || u.delegate_to?.length ? (
                      <ListField
                        label="delegate to"
                        value={u.delegate_to}
                        placeholder={delegateExample}
                        help="SPNs this account may delegate to, comma separated. Empty turns on protocol transition with no targets."
                        disabled={readOnly}
                        onChange={(v) => patch(i, { delegate_to: v })}
                      />
                    ) : null}
                    {hasFlaw(u, "weak_password") || u.weak_password ? (
                      <TextField
                        label="weak password"
                        value={u.weak_password}
                        placeholder="Summer2024!"
                        help={
                          u.password
                            ? "This account sets its own password, so that one is kept and this is not used."
                            : "Empty uses Summer2024!."
                        }
                        disabled={readOnly}
                        onChange={(v) => patch(i, { weak_password: v })}
                      />
                    ) : null}
                    <label className="rg-check" title={BREACH_HELP}>
                      <input
                        type="checkbox"
                        checked={!!u.assumed_breach}
                        disabled={readOnly}
                        onChange={(e) => patch(i, { assumed_breach: e.target.checked || undefined })}
                      />
                      Assumed-breach foothold
                    </label>
                    {u.assumed_breach ? <span className="rg-field-help">{BREACH_HELP}</span> : null}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      ) : null}
      {readOnly ? null : (
        <div className="rg-users-add">
          <input
            value={name}
            placeholder="username, e.g. j.smith"
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && add()}
          />
          <button type="button" onClick={add} disabled={!name.trim()}>Add</button>
        </div>
      )}
    </div>
  );
}
