import React, { useState } from "react";
import { FindingBadge } from "./FindingBadge.jsx";
import { DRAWN_ROLES, isContainer, roleColor, roleDisplay } from "./topology.js";
import { PROFILES } from "./profiles.js";
import { VULN_CATALOG, VULN_PROVIDERS } from "./vulns.js";
import { HARDENING_CATALOG } from "./hardening.js";
import {
  USER_ARCHETYPES, addUser, buildArchetype, generateUsers, recommendedUserCount,
  removeUser, setUsers, updateUser,
} from "./rangeUsers.js";

const PRIVILEGES = ["user", "local_admin", "domain_admin", "enterprise_admin"];

// Human labels for the account flaw enum, so the picker reads as techniques
// rather than snake_case. The ids are the schema enum (overlay_domain.users
// flaws); an unlabelled one falls back to its id.
const FLAW_LABELS = {
  kerberoastable: "Kerberoastable (SPN)",
  asrep_roastable: "AS-REP roastable (no preauth)",
  password_in_description: "Password in description",
  password_never_expires: "Password never expires",
  weak_password: "Weak password",
  reversible_encryption: "Reversible encryption",
  no_preauth: "No Kerberos preauth",
  spn_set: "SPN set",
};

// The user accounts on a domain. A person can add one by hand, change its
// privilege, expand it to edit its email, groups, and misconfigurations, or press
// Populate to fill the domain with a realistic population so a lab has bodies to
// hunt through, not just the accounts an attack path needs. The count Populate
// adds scales with the range's size. See rangeUsers.js and 0049.
function DomainUsers({ node, rangeHostCount, flawOptions = [], onChange }) {
  const users = (node.overlay || {}).users || [];
  const fqdn = (node.overlay || {}).fqdn || "example.local";
  const [name, setName] = useState("");
  const [open, setOpen] = useState(-1);

  const toggleFlaw = (i, flaw) => {
    const cur = users[i].flaws || [];
    const next = cur.includes(flaw) ? cur.filter((f) => f !== flaw) : [...cur, flaw];
    onChange(updateUser(node, i, { flaws: next.length ? next : undefined }));
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
      <div className="rg-users-actions">
        <button type="button" onClick={populate}>Populate random</button>
        {users.length ? (
          <button type="button" className="rg-danger-text" onClick={() => onChange(setUsers(node, []))}>
            Clear
          </button>
        ) : null}
      </div>
      <div className="rg-users-archetypes">
        <span className="rg-field-label">add a class</span>
        {USER_ARCHETYPES.map((a) => (
          <button key={a.id} type="button" title={a.blurb} onClick={() => addArchetype(a.id)}>
            + {a.label}
          </button>
        ))}
      </div>
      {users.length ? (
        <div className="rg-users-list">
          {users.map((u, i) => (
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
                  onChange={(e) => onChange(updateUser(node, i, { privilege: e.target.value }))}
                >
                  {PRIVILEGES.map((p) => (
                    <option key={p} value={p}>{p.replace("_", " ")}</option>
                  ))}
                </select>
                {u.flaws?.length ? (
                  <span className="rg-user-flaws" title={u.flaws.join(", ")}>
                    {u.flaws.length} flaw{u.flaws.length === 1 ? "" : "s"}
                  </span>
                ) : null}
                {u.assumed_breach ? (
                  <span className="rg-user-breach" title="Assumed-breach foothold (patient zero): also a local admin on the jumpbox">
                    breach
                  </span>
                ) : null}
                <button
                  type="button"
                  className="rg-user-del"
                  title="Remove user"
                  onClick={() => onChange(removeUser(node, i))}
                >
                  &times;
                </button>
              </div>
              {open === i ? (
                <div className="rg-user-detail">
                  <label className="rg-field">
                    <span className="rg-field-label">email</span>
                    <input
                      value={u.email || ""}
                      onChange={(e) => onChange(updateUser(node, i, { email: e.target.value || undefined }))}
                    />
                  </label>
                  <label className="rg-field">
                    <span className="rg-field-label">groups</span>
                    <input
                      value={(u.groups || []).join(", ")}
                      placeholder="IT, Domain Admins"
                      onChange={(e) =>
                        onChange(updateUser(node, i, {
                          groups: e.target.value.split(",").map((s) => s.trim()).filter(Boolean),
                        }))
                      }
                    />
                  </label>
                  <div className="rg-field">
                    <span className="rg-field-label">misconfigurations</span>
                    <div className="rg-user-flaw-picks">
                      {flawOptions.map((flaw) => (
                        <label key={flaw} className="rg-check" title={flaw}>
                          <input
                            type="checkbox"
                            checked={(u.flaws || []).includes(flaw)}
                            onChange={() => toggleFlaw(i, flaw)}
                          />
                          {FLAW_LABELS[flaw] || flaw}
                        </label>
                      ))}
                    </div>
                  </div>
                  <label
                    className="rg-check"
                    title="The low-priv patient-zero an operator starts from. Also created as a local admin on the jumpbox (SSH foothold); named in the range briefing."
                  >
                    <input
                      type="checkbox"
                      checked={!!u.assumed_breach}
                      onChange={(e) =>
                        onChange(updateUser(node, i, { assumed_breach: e.target.checked || undefined }))
                      }
                    />
                    Assumed-breach foothold
                  </label>
                </div>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
      <div className="rg-users-add">
        <input
          value={name}
          placeholder="username, e.g. j.smith"
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
        />
        <button type="button" onClick={add} disabled={!name.trim()}>Add</button>
      </div>
    </div>
  );
}

// A group starts expanded only when one of its items is already selected, so
// an applied category stays in view and an empty one stays out of the way.
// Computed once at mount from the value the picker opens with; toggling a
// group or an item afterward never fights the person by recomputing this.
function initialCollapsed(catalog, selected) {
  const collapsed = new Set();
  for (const group of catalog) {
    if (!group.items.some((item) => selected.includes(item.id))) {
      collapsed.add(group.group);
    }
  }
  return collapsed;
}

// The defensive-controls picker: the same grouped checklist as the vuln picker
// above, over hardening.js. Each group states what that family buys you, which
// is the job the schema description used to do in one run-on sentence.
function HardeningPicker({ value, onChange, disabled }) {
  const set = value || [];
  const [collapsed, setCollapsed] = useState(() => initialCollapsed(HARDENING_CATALOG, set));
  const toggle = (id) =>
    onChange(set.includes(id) ? set.filter((v) => v !== id) : [...set, id]);
  const toggleGroup = (key) =>
    setCollapsed((cur) => {
      const next = new Set(cur);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  return (
    <div className="rg-field">
      <span className="rg-field-label">
        hardening{set.length ? ` (${set.length})` : ""}
      </span>
      <div className="rg-vulns rg-hardening">
        {HARDENING_CATALOG.map((group) => {
          const selectedCount = group.items.filter((item) => set.includes(item.id)).length;
          const isCollapsed = collapsed.has(group.group);
          return (
            <div key={group.group} className="rg-vuln-group">
              <button
                type="button"
                className="rg-vuln-group-header"
                aria-expanded={!isCollapsed}
                onClick={() => toggleGroup(group.group)}
              >
                <span className="rg-vuln-group-caret" aria-hidden="true">
                  {isCollapsed ? "▸" : "▾"}
                </span>
                <span className="rg-vuln-group-label">
                  {group.group}
                  {selectedCount ? ` (${selectedCount})` : ""}
                </span>
              </button>
              <div className="rg-vuln-group-summary">{group.summary}</div>
              {isCollapsed
                ? null
                : group.items.map((item) => {
                    const isSelected = set.includes(item.id);
                    return (
                      <label
                        key={item.id}
                        className={`rg-check${isSelected ? " is-selected" : ""}`}
                        title={item.blurb}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          disabled={disabled}
                          onChange={() => toggle(item.id)}
                        />
                        {item.label}
                      </label>
                    );
                  })}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// The planted-vulnerability picker for a range host: a grouped checklist from
// the GOAD-derived catalog. See vulns.js.
//
// `provider` (the range's compile target, e.g. "gcp"/"proxmox") greys a vuln
// VULN_PROVIDERS restricts to other providers -- a template can still declare
// it (it may target more than one provider over its life), but the compiler
// silently drops it for this one, so the checkbox stays checkable, just
// visibly a no-op here. See redstackpro.ansible.VULN_PROVIDERS, kept in sync
// with vulns.js by tests/test_vuln_providers_sync.py.
function VulnPicker({ value, onChange, disabled, provider }) {
  const set = value || [];
  const [collapsed, setCollapsed] = useState(() => initialCollapsed(VULN_CATALOG, set));
  const toggle = (id) =>
    onChange(set.includes(id) ? set.filter((v) => v !== id) : [...set, id]);
  const toggleGroup = (key) =>
    setCollapsed((cur) => {
      const next = new Set(cur);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  return (
    <div className="rg-field">
      <span className="rg-field-label">
        vulnerabilities{set.length ? ` (${set.length})` : ""}
      </span>
      <div className="rg-vulns">
        {VULN_CATALOG.map((group) => {
          const selectedCount = group.items.filter((item) => set.includes(item.id)).length;
          const isCollapsed = collapsed.has(group.group);
          return (
            <div key={group.group} className="rg-vuln-group">
              <button
                type="button"
                className="rg-vuln-group-header"
                aria-expanded={!isCollapsed}
                onClick={() => toggleGroup(group.group)}
              >
                <span className="rg-vuln-group-caret" aria-hidden="true">
                  {isCollapsed ? "▸" : "▾"}
                </span>
                <span className="rg-vuln-group-label">
                  {group.group}
                  {selectedCount ? ` (${selectedCount})` : ""}
                </span>
              </button>
              {isCollapsed
                ? null
                : group.items.map((item) => {
                    const restricted = VULN_PROVIDERS[item.id];
                    const unsupported =
                      restricted && provider && !restricted.includes(provider);
                    const title = unsupported
                      ? `${item.blurb || ""}\n\nNo payoff on ${provider}: only planted on ${restricted.join("/")}. Still declarable for a template that also targets those.`
                      : item.blurb || "";
                    const isSelected = set.includes(item.id);
                    return (
                      <label
                        key={item.id}
                        className={`rg-check${isSelected ? " is-selected" : ""}${unsupported ? " is-provider-unsupported" : ""}`}
                        title={title}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          disabled={disabled}
                          onChange={() => toggle(item.id)}
                        />
                        {item.label}
                        {unsupported ? (
                          <span className="rg-vuln-provider-note">
                            {" "}({restricted.join("/")} only)
                          </span>
                        ) : null}
                      </label>
                    );
                  })}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// A redirector's cover: pick a vertical and apply it to fill the gating header,
// the decoy page, and a themed subdomain on one of your own domains, and re-roll
// the URI prefixes on the lines it fronts, all from the theme's pools. Applying
// again re-randomises, so the same theme gives a fresh disguise each press.
//
// The theme supplies the subdomain only; the root is always a domain you
// registered. With the field empty there is no honest name to offer, so Apply
// leaves the hostname alone and the compile stops at RDR001 rather than building
// a redirector that answers to a name nobody owns. See profiles.js.
// `none` serves no cover page at all. It is a real choice and the theme pools do
// not contain it, so it is offered here rather than in a second dropdown: this
// select IS the decoy field, which is why the decoy is hidden from the gating
// group below when this panel is on screen. Choosing a vertical used to mean
// picking "Healthcare portal" here and "healthcare" again ten fields down.
const NO_COVER = "none";

function CoverProfile({ node, onApply, domains = "", onDomainsChange, onDecoyChange }) {
  const [theme, setTheme] = useState(node.overlay?.gating?.decoy || PROFILES[0].key);
  const known = theme === NO_COVER || PROFILES.some((p) => p.key === theme);
  // Changing the vertical takes effect immediately, because it is just the cover
  // page. Apply is the re-roll: a new token, new URIs, a new suggested
  // subdomain. Separating them means changing your cover story does not silently
  // invalidate a gating token your implant profile already carries.
  const choose = (value) => {
    setTheme(value);
    onDecoyChange?.(value);
  };
  return (
    <div className="rg-cover">
      <h3>Cover profile</h3>
      <p className="rg-hint">
        The vertical this redirector pretends to be. Picking one sets the cover
        page straight away. Apply also re-rolls the gating header and token, the
        URIs it fronts, and suggests a themed subdomain on one of your domains;
        press it again for a fresh set. The subdomain is only a suggestion, and
        the hostname stays yours to edit.
      </p>
      <label className="rg-field">
        <span className="rg-field-label">your domains</span>
        <input
          value={domains}
          placeholder="my-domain.net, second-domain.com"
          onChange={(e) => onDomainsChange?.(e.target.value)}
        />
        <span className="rg-field-help">
          Domains you own from your registrar, and point at this redirector.
          Without one, Apply leaves the hostname empty: a cover on a name you do
          not own is a beacon that never comes back.
        </span>
      </label>
      <div className="rg-cover-row">
        <select value={known ? theme : ""} onChange={(e) => choose(e.target.value)}>
          {!known ? <option value="">custom</option> : null}
          {PROFILES.map((p) => (
            <option key={p.key} value={p.key}>
              {p.label}
            </option>
          ))}
          <option value={NO_COVER}>No cover page</option>
        </select>
        <button
          type="button"
          disabled={theme === NO_COVER}
          title={
            theme === NO_COVER
              ? "No cover page to apply. Pick a vertical to re-roll the header and URIs."
              : undefined
          }
          onClick={() => onApply(node.id, theme || PROFILES[0].key)}
        >
          Apply
        </button>
      </div>
    </div>
  );
}

// The gating group, minus the decoy: the Cover profile panel above owns it.
// Only used when that panel is on screen, so a read-only view still shows every
// field rather than a gap where one used to be.
function withoutDecoy(spec) {
  if (!spec?.properties?.decoy) return spec;
  const properties = { ...spec.properties };
  delete properties.decoy;
  return { ...spec, properties };
}

// A readable label for a GOAD access right, which may arrive as a raw AD string
// (Ext-User-Force-Change-Password) or a plain one (GenericAll). Prettify without
// losing the stored value.
function prettyRight(right) {
  return (right || "")
    .replace(/^Ext-/, "")
    .replace(/-/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2");
}

// The dangerous access rights on a domain: who can act on whom. This is the
// attack graph the users and groups sit inside, the same acls GOAD carries and
// BloodHound walks. Listed and editable here, since a right runs between two
// principals rather than being a property of one node. See 0052.
function DomainAcls({ node, onChange }) {
  const acls = (node.overlay || {}).acls || [];
  const [principal, setPrincipal] = useState("");
  const [target, setTarget] = useState("");
  const [right, setRight] = useState("GenericAll");

  const set = (next) => onChange({ ...(node.overlay || {}), acls: next.length ? next : undefined });
  const add = () => {
    if (!principal.trim() || !target.trim() || !right.trim()) return;
    set([...acls, { principal: principal.trim(), target: target.trim(), right: right.trim() }]);
    setPrincipal("");
    setTarget("");
  };

  return (
    <div className="rg-acls">
      <h3>Access rights{acls.length ? ` (${acls.length})` : ""}</h3>
      <p className="rg-hint">
        Who can act on whom: the escalation edges that make the domain an attack
        graph. Principal and target are usernames or groups.
      </p>
      {acls.length ? (
        <div className="rg-acls-list">
          {acls.map((a, i) => (
            <div key={i} className="rg-acl-row">
              <span className="rg-acl-pair">
                <span className="rg-acl-p" title={a.principal}>{a.principal}</span>
                <span className="rg-acl-arrow" aria-hidden="true">&rarr;</span>
                <span className="rg-acl-t" title={a.target}>{a.target}</span>
              </span>
              <span className="rg-acl-right" title={a.right}>{prettyRight(a.right)}</span>
              <button
                type="button"
                className="rg-user-del"
                title="Remove right"
                onClick={() => set(acls.filter((_, j) => j !== i))}
              >
                &times;
              </button>
            </div>
          ))}
        </div>
      ) : null}
      {/* Reading order matches the sentence the row makes: principal, target,
          then the right that connects them, then Add. */}
      <div className="rg-acls-add">
        <input value={principal} placeholder="principal" onChange={(e) => setPrincipal(e.target.value)} />
        <input value={target} placeholder="target" onChange={(e) => setTarget(e.target.value)} />
        <select value={right} onChange={(e) => setRight(e.target.value)}>
          {["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "ForceChangePassword", "AddMember"].map((r) => (
            <option key={r} value={r}>{r}</option>
          ))}
        </select>
        <button type="button" onClick={add} disabled={!principal.trim() || !target.trim()}>Add</button>
      </div>
    </div>
  );
}

// The operator roster on an artie jumpbox: the people who reach the range. Each
// becomes a portal account and, on a VPN access mode, gets a personal VPN
// credential generated on the jumpbox at apply. Reuses the acls row styling. See
// vpn-multiuser-spec.
//
// A handle is interpolated into shell, filenames and SQL on the jumpbox at apply,
// so it is held to a strict charset here (matches VPN005), and the free-form role
// to a single short line (VPN006), rather than letting a bad value through to fail
// only at compile.
const OPERATOR_HANDLE_RE = /^[a-z0-9][a-z0-9._-]*$/;
function Operators({ node, onChange }) {
  const operators = (node.overlay || {}).operators || [];
  const [handle, setHandle] = useState("");
  const [role, setRole] = useState("");
  const [err, setErr] = useState("");

  const set = (next) =>
    onChange({ ...(node.overlay || {}), operators: next.length ? next : undefined });
  const add = () => {
    const h = handle.trim().toLowerCase();
    const r = role.trim();
    if (!h) return;
    if (!OPERATOR_HANDLE_RE.test(h) || h.length > 32) {
      setErr("Handle: lowercase letters, digits, dot, underscore or hyphen, starting with a letter or digit, up to 32 characters.");
      return;
    }
    if (operators.some((o) => (o.handle || "").toLowerCase() === h)) {
      setErr(`${h} is already on the roster.`);
      return;
    }
    if (r && (/[|\r\n]/.test(r) || r.length > 64)) {
      setErr("Role: a single line with no pipe character, up to 64 characters.");
      return;
    }
    setErr("");
    set([...operators, r ? { handle: h, role: r } : { handle: h }]);
    setHandle("");
    setRole("");
  };

  return (
    <div className="rg-acls">
      <h3>Operators{operators.length ? ` (${operators.length})` : ""}</h3>
      <p className="rg-hint">
        The people who reach this range. Each gets a portal account and, on a VPN
        access mode, a personal VPN credential generated on the jumpbox. Handles are
        lowercase and unique.
      </p>
      {operators.length ? (
        <div className="rg-acls-list">
          {operators.map((o, i) => (
            <div key={i} className="rg-acl-row">
              <span className="rg-acl-pair">
                <span className="rg-acl-p" title={o.handle}>{o.handle}</span>
                {o.role ? (
                  <span className="rg-acl-right" title={o.role}>{o.role}</span>
                ) : null}
              </span>
              <button
                type="button"
                className="rg-user-del"
                title="Remove operator"
                onClick={() => set(operators.filter((_, j) => j !== i))}
              >
                &times;
              </button>
            </div>
          ))}
        </div>
      ) : null}
      <div className="rg-acls-add">
        <input value={handle} placeholder="handle" onChange={(e) => setHandle(e.target.value)} />
        <input value={role} placeholder="role (optional)" onChange={(e) => setRole(e.target.value)} />
        <button type="button" onClick={add} disabled={!handle.trim()}>Add</button>
      </div>
      {err ? <p className="rg-hint rg-danger-text">{err}</p> : null}
    </div>
  );
}

// The range host kinds that join a domain. Standalone range boxes (jumpbox,
// SIEM, appliance) sit on a subnet but do not join a domain, so they get the
// subnet control but not the domain one.
const DOMAIN_JOINERS = new Set(["dc", "srv", "wks", "fw"]);
const SUBNET_PLACEABLE = new Set(["dc", "srv", "wks", "fw", "jumpbox", "siem", "appliance"]);

// Placing a range host without drawing a line: pick its domain and its subnet
// from dropdowns and the joins and attached edges are rewritten in one step.
// This is the range analogue of nesting a box by dragging, for the times the
// canvas is crowded and a menu is quicker than aiming a drag. See setJoin and
// setParent in topology.js.
function RangePlacement({ node, document, onJoinDomain, onPlaceSubnet }) {
  const domains = document.nodes.filter((n) => n.kind === "domain");
  const subnets = document.nodes.filter((n) => n.kind === "segment");
  const joinsDomain =
    document.edges.find((e) => e.role === "joins" && e.source === node.id)?.target || "";
  const onSubnet =
    document.edges.find((e) => e.role === "attached" && e.source === node.id)?.target || "";
  const canJoin = DOMAIN_JOINERS.has(node.kind);
  if (!SUBNET_PLACEABLE.has(node.kind)) return null;
  return (
    <div className="rg-placement">
      <h3>Placement</h3>
      {canJoin ? (
        <label className="rg-field">
          <span className="rg-field-label">domain</span>
          <select
            value={joinsDomain}
            onChange={(e) => onJoinDomain?.(node.id, e.target.value || undefined)}
          >
            <option value="">none</option>
            {domains.map((d) => (
              <option key={d.id} value={d.id}>
                {d.overlay?.fqdn || d.id}
              </option>
            ))}
          </select>
          <span className="rg-field-help">The domain this host joins.</span>
        </label>
      ) : null}
      <label className="rg-field">
        <span className="rg-field-label">subnet</span>
        <select
          value={onSubnet}
          onChange={(e) => onPlaceSubnet?.(node.id, e.target.value || undefined)}
        >
          <option value="">none</option>
          {subnets.map((s) => (
            <option key={s.id} value={s.id}>
              {s.id}
              {s.overlay?.cidr ? ` (${s.overlay.cidr})` : ""}
            </option>
          ))}
        </select>
        <span className="rg-field-help">The subnet this host sits on.</span>
      </label>
    </div>
  );
}

// A node's drawn relationships, listed as rows you click to open and edit rather
// than hunting for a thin line to hit on the canvas. Each row names the role and
// the other end, coloured the same as the line so the two read as one thing.
// Below the list, a small form adds a new connection from this node without
// having to draw it: pick the other end and the role, or leave the role to be
// inferred from the two kinds.
function Connections({ node, document, onSelect, onAddEdge, readOnly }) {
  const [target, setTarget] = useState("");
  const [role, setRole] = useState("");
  const others = document.nodes.filter((n) => n.id !== node.id);
  const rows = document.edges
    .filter(
      (e) =>
        DRAWN_ROLES.includes(e.role) &&
        (e.source === node.id || e.target === node.id)
    )
    .map((e) => {
      const outgoing = e.source === node.id;
      const other = outgoing ? e.target : e.source;
      const detail = e.role === "fronts" ? e.uri_prefix || "" : "";
      return { id: e.id, role: e.role, outgoing, other, detail };
    });
  const add = () => {
    if (!target) return;
    onAddEdge?.(node.id, target, role || undefined);
    setTarget("");
    setRole("");
  };

  return (
    <div className="rg-connections">
      <h3>Connections</h3>
      {rows.length === 0 ? (
        <p className="rg-hint">No connections yet.</p>
      ) : (
        rows.map((r) => (
          <button
            key={r.id}
            type="button"
            className="rg-connection"
            onClick={() => onSelect?.(r.id)}
          >
            <span className="rg-connection-dot" style={{ background: roleColor(r.role) }} />
            <span className="rg-connection-role">{roleDisplay(r.role)}</span>
            <span className="rg-connection-dir">{r.outgoing ? "to" : "from"}</span>
            <span className="rg-connection-other">
              {document.prefix}-{r.other}
            </span>
            {r.detail ? <span className="rg-connection-detail">{r.detail}</span> : null}
          </button>
        ))
      )}
      {readOnly ? null : (
        <div className="rg-connection-add">
          <select value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">connect to...</option>
            {others.map((n) => (
              <option key={n.id} value={n.id}>
                {document.prefix}-{n.id}
              </option>
            ))}
          </select>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="">auto role</option>
            {DRAWN_ROLES.map((r) => (
              <option key={r} value={r}>
                {roleDisplay(r)}
              </option>
            ))}
          </select>
          <button type="button" onClick={add} disabled={!target}>
            Add
          </button>
        </div>
      )}
    </div>
  );
}

// The manages relationship is not a drawn line, so it does not appear in
// Connections. It is listed here instead: what this node governs, and, on a
// container, what governs it. Each row selects the other end so the two read as
// linked even without a line between them.
function Manages({ node, document, onSelectNode }) {
  const governs = document.edges
    .filter((e) => e.role === "manages" && e.source === node.id)
    .map((e) => e.target);
  const governedBy = document.edges
    .filter((e) => e.role === "manages" && e.target === node.id)
    .map((e) => e.source);
  if (!governs.length && !governedBy.length) return null;

  const rows = (ids) =>
    ids.map((id) => (
      <button
        key={id}
        type="button"
        className="rg-manages-row"
        onClick={() => onSelectNode?.(id)}
      >
        <span className="rg-manages-row-dot" />
        {document.prefix}-{id}
      </button>
    ));

  return (
    <div className="rg-manages-section">
      {governs.length ? (
        <>
          <h3>Manages</h3>
          {rows(governs)}
        </>
      ) : null}
      {governedBy.length ? (
        <>
          <h3>Managed by</h3>
          {rows(governedBy)}
        </>
      ) : null}
    </div>
  );
}

// Overlay forms are generated from the document schema rather than hardcoded,
// for the same reason the palette comes from the registry: a pro node kind
// should not need a change here. See 0013 and 0017.
//
// Fields marked derived never appear, because the compiler computes them and a
// person cannot supply them.

// The range host kinds (dc, srv, wks, fw) all share one overlay definition, so
// their forms resolve to it rather than a per-kind def that does not exist.
const RANGE_HOST_KINDS = new Set(["dc", "srv", "wks", "fw"]);

function overlaySchemaFor(schema, kind) {
  const defs = schema?.$defs || {};
  const name = RANGE_HOST_KINDS.has(kind) ? "range_host" : kind;
  return defs[`overlay_${name}`] || null;
}

function Field({ name, spec, value, required, onChange, disabled }) {
  const label = (
    <span className="rg-field-label">
      {spec.title || name}
      {required ? <span className="rg-required">required</span> : null}
    </span>
  );

  const help = spec.description ? (
    <span className="rg-field-help">{spec.description}</span>
  ) : null;

  // An enum is a choice, so it is a select rather than a free text box the
  // validator has to reject afterward.
  if (spec.enum) {
    return (
      <label className="rg-field">
        {label}
        <select
          value={value ?? ""}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value || undefined)}
        >
          <option value="">unset</option>
          {spec.enum.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
        {help}
      </label>
    );
  }

  if (spec.type === "boolean") {
    // The checkbox and its name sit on one row; the help text goes BELOW at
    // full width, the same as every other field type.
    //
    // It used to put all three in one flex row with align-items: center, so a
    // two-word label ended up vertically centred against a six-line paragraph
    // in a narrow right-hand column. Every boolean sat at a different height
    // from its neighbours and the rail read as ragged.
    return (
      <label className="rg-field">
        <span className="rg-check-row">
          <input
            type="checkbox"
            checked={value ?? spec.default ?? false}
            disabled={disabled}
            onChange={(e) => onChange(e.target.checked)}
          />
          {label}
        </span>
        {help}
      </label>
    );
  }

  if (spec.type === "integer" || spec.type === "number") {
    return (
      <label className="rg-field">
        {label}
        <input
          type="number"
          value={value ?? ""}
          placeholder={spec.default ?? ""}
          disabled={disabled}
          onChange={(e) =>
            onChange(e.target.value === "" ? undefined : Number(e.target.value))
          }
        />
        {help}
      </label>
    );
  }

  if (spec.type === "array") {
    const items = value || [];
    const options = spec.items?.enum;
    if (options) {
      return (
        <div className="rg-field">
          {label}
          <div className="rg-checks">
            {options.map((option) => (
              <label key={option} className="rg-check">
                <input
                  type="checkbox"
                  checked={items.includes(option)}
                  disabled={disabled}
                  onChange={(e) =>
                    onChange(
                      e.target.checked
                        ? [...items, option]
                        : items.filter((i) => i !== option)
                    )
                  }
                />
                {option}
              </label>
            ))}
          </div>
          {help}
        </div>
      );
    }
    return (
      <label className="rg-field">
        {label}
        <input
          value={items.join(", ")}
          disabled={disabled}
          onChange={(e) =>
            onChange(
              e.target.value
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean)
            )
          }
        />
        {help}
      </label>
    );
  }

  if (spec.type === "object" && spec.properties) {
    return (
      <fieldset className="rg-fieldset">
        <legend>{name}</legend>
        {spec.description ? <p className="rg-field-help">{spec.description}</p> : null}
        {Object.entries(spec.properties).map(([child, childSpec]) => (
          <Field
            key={child}
            name={child}
            spec={childSpec}
            value={(value || {})[child]}
            required={(spec.required || []).includes(child)}
            disabled={disabled}
            onChange={(next) => onChange({ ...(value || {}), [child]: next })}
          />
        ))}
      </fieldset>
    );
  }

  return (
    <label className="rg-field">
      {label}
      <input
        value={value ?? ""}
        // A field the schema gives hint text for shows the hint, so a value the
        // compiler will fill in for you says so in grey rather than sitting in the
        // document as a literal CHANGE-ME that someone has to notice and delete.
        // The raw pattern is the fallback for fields with no hint.
        placeholder={spec["x-redstackpro-placeholder"] ?? (spec.pattern || "")}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value || undefined)}
      />
      {help}
    </label>
  );
}

export function Inspector({
  schema,
  selection,
  document,
  findings,
  onOverlayChange,
  onEdgeChange,
  onSelectEdge,
  onSelectNode,
  onAddEdge,
  onRename,
  onDelete,
  onStraighten,
  canStraighten = false,
  onApplyCover,
  onRandomizeUri,
  onJoinDomain,
  onPlaceSubnet,
  rangeHostCount = 0,
  domains = "",
  onDomainsChange,
  readOnly = false,
  kindLabels = {},
  provider,
}) {
  if (!selection) {
    return (
      <aside className="rg-panel rg-inspector">
        <h2>Inspector</h2>
        <p className="rg-hint">Select a node or an edge.</p>
        <h3>Topology</h3>
        <p className="rg-kv">
          <span>prefix</span>
          <span>{document.prefix}</span>
        </p>
        <p className="rg-kv">
          <span>mode</span>
          <span>{document.mode}</span>
        </p>
        <p className="rg-kv">
          <span>nodes</span>
          <span>{document.nodes.length}</span>
        </p>
        <p className="rg-kv">
          <span>edges</span>
          <span>{document.edges.length}</span>
        </p>
      </aside>
    );
  }

  if (selection.type === "edge") {
    const edge = document.edges.find((e) => e.id === selection.id);
    if (!edge) return null;
    return (
      <aside className="rg-panel rg-inspector">
        <h2>{roleDisplay(edge.role)}</h2>
        <p className="rg-kv">
          <span>from</span>
          <span>{edge.source}</span>
        </p>
        <p className="rg-kv">
          <span>to</span>
          <span>{edge.target}</span>
        </p>
        <label className="rg-field">
          <span className="rg-field-label">role</span>
          <select
            value={edge.role}
            disabled={readOnly}
            onChange={(e) => {
              const role = e.target.value;
              if (!role || role === edge.role) return;
              // Switching to fronts seeds the fields it needs so it validates;
              // switching away drops them so a stale prefix does not linger.
              const patch =
                role === "fronts"
                  ? {
                      role,
                      protocol: edge.protocol || "https",
                      listen_port: edge.listen_port || 443,
                      upstream_port: edge.upstream_port || 443,
                      uri_prefix: edge.uri_prefix || "/cdn/assets",
                    }
                  : {
                      role,
                      protocol: undefined,
                      listen_port: undefined,
                      upstream_port: undefined,
                      uri_prefix: undefined,
                    };
              onEdgeChange(edge.id, patch);
            }}
          >
            {["fronts", "logs_to", "manages", "peers"].map((r) => (
              <option key={r} value={r}>
                {roleDisplay(r)}
              </option>
            ))}
          </select>
          <span className="rg-field-help">
            What this line is. The role also follows from what it connects; set it
            here when you want a different one.
          </span>
        </label>
        {edge.role === "fronts" ? (
          <>
            <Field
              name="uri_prefix"
              spec={{ type: "string", description: "Path the redirector routes to this teamserver. Randomise draws from the redirector's cover profile." }}
              value={edge.uri_prefix}
              disabled={readOnly}
              onChange={(v) => onEdgeChange(edge.id, { uri_prefix: v })}
            />
            {onRandomizeUri && !readOnly ? (
              <button type="button" className="rg-inline-btn" onClick={() => onRandomizeUri(edge.id)}>
                Randomize URI
              </button>
            ) : null}
            <Field
              name="protocol"
              spec={{ enum: ["http", "https", "dns", "tcp"] }}
              value={edge.protocol}
              required
              disabled={readOnly}
              onChange={(v) => onEdgeChange(edge.id, { protocol: v })}
            />
            <Field
              name="listen_port"
              spec={{ type: "integer" }}
              value={edge.listen_port}
              required
              disabled={readOnly}
              onChange={(v) => onEdgeChange(edge.id, { listen_port: v })}
            />
            <Field
              name="upstream_port"
              spec={{ type: "integer" }}
              value={edge.upstream_port}
              disabled={readOnly}
              onChange={(v) => onEdgeChange(edge.id, { upstream_port: v })}
            />
          </>
        ) : null}
        <FindingList findings={findings} />
        <p className="rg-field-help">
          Click the line and drag a dot to route it by hand. Double-click the
          line to straighten it. Its endpoints stay attached either way.
        </p>
        {canStraighten ? (
          <button type="button" onClick={onStraighten}>
            Straighten line
          </button>
        ) : null}
        {readOnly ? null : (
          <button className="rg-danger" onClick={() => onDelete(selection)}>
            Delete edge
          </button>
        )}
      </aside>
    );
  }

  const node = document.nodes.find((n) => n.id === selection.id);
  if (!node) return null;
  const overlaySchema = overlaySchemaFor(schema, node.kind);
  const required = overlaySchema?.required || [];
  // When the Cover profile panel is on screen it owns the decoy, so the gating
  // group below does not repeat it. Read-only views show the full group.
  const coverShown = node.kind === "redirector" && onApplyCover && !readOnly;

  return (
    <aside className="rg-panel rg-inspector">
      <h2>
        {document.prefix}-{node.id}
      </h2>
      <p className="rg-kv">
        <span>kind</span>
        <span>{kindLabels[node.kind] || node.kind}</span>
      </p>
      <label className="rg-field">
        <span className="rg-field-label">id</span>
        <input
          value={node.id}
          disabled={readOnly}
          onChange={(e) => onRename(node.id, e.target.value)}
        />
        <span className="rg-field-help">
          Purpose, then the kind tag and a two digit ordinal: myth-ts01. Left as
          is, it tracks what the node holds; rename it and it stays put.
        </span>
      </label>

      {coverShown ? (
        <CoverProfile
          node={node}
          onApply={onApplyCover}
          domains={domains}
          onDomainsChange={onDomainsChange}
          onDecoyChange={(decoy) =>
            onOverlayChange(node.id, {
              ...(node.overlay || {}),
              gating: { ...((node.overlay || {}).gating || {}), decoy },
            })
          }
        />
      ) : null}

      {document.mode === "haven" && !readOnly && (onJoinDomain || onPlaceSubnet) ? (
        <RangePlacement
          node={node}
          document={document}
          onJoinDomain={onJoinDomain}
          onPlaceSubnet={onPlaceSubnet}
        />
      ) : null}

      {node.kind === "jumpbox" && document?.mode === "artie" && !readOnly ? (
        <p className="rg-hint">
          This jumpbox can front a team. Set <code>access_mode</code> to
          wireguard or openvpn and add operators below: each gets a portal login
          and a personal VPN credential generated on the jumpbox at deploy.
        </p>
      ) : null}

      {overlaySchema
        ? Object.entries(overlaySchema.properties || {})
            .filter(([, spec]) => spec["x-redstackpro-source"] !== "derived")
            .map(([name, spec]) =>
              name === "vulns" ? (
                <VulnPicker
                  key={`${name}-${node.id}`}
                  value={(node.overlay || {}).vulns}
                  disabled={readOnly}
                  provider={provider}
                  onChange={(value) =>
                    onOverlayChange(node.id, { ...(node.overlay || {}), vulns: value })
                  }
                />
              ) : name === "hardening" ? (
                <HardeningPicker
                  key={`${name}-${node.id}`}
                  value={(node.overlay || {}).hardening}
                  disabled={readOnly}
                  onChange={(value) =>
                    onOverlayChange(node.id, {
                      ...(node.overlay || {}),
                      hardening: value && value.length ? value : undefined,
                    })
                  }
                />
              ) : name === "users" ? (
                readOnly ? null : (
                  <DomainUsers
                    key={name}
                    node={node}
                    rangeHostCount={rangeHostCount}
                    flawOptions={spec.items?.properties?.flaws?.items?.enum || []}
                    onChange={(overlay) => onOverlayChange(node.id, overlay)}
                  />
                )
              ) : name === "acls" ? (
                readOnly ? null : (
                  <DomainAcls
                    key={name}
                    node={node}
                    onChange={(overlay) => onOverlayChange(node.id, overlay)}
                  />
                )
              ) : name === "operators" ? (
                readOnly ? null : (
                  <Operators
                    key={name}
                    node={node}
                    onChange={(overlay) => onOverlayChange(node.id, overlay)}
                  />
                )
              ) : (
                <Field
                  key={name}
                  name={name}
                  spec={
                    name === "gating" && coverShown ? withoutDecoy(spec) : spec
                  }
                  required={required.includes(name)}
                  value={(node.overlay || {})[name]}
                  disabled={readOnly}
                  onChange={(value) =>
                    onOverlayChange(node.id, { ...(node.overlay || {}), [name]: value })
                  }
                />
              )
            )
        : null}

      <Manages node={node} document={document} onSelectNode={onSelectNode} />
      <Connections
        node={node}
        document={document}
        onSelect={onSelectEdge}
        onAddEdge={onAddEdge}
        readOnly={readOnly}
      />
      <FindingList findings={findings} />
      {readOnly ? null : (
        <button className="rg-danger" onClick={() => onDelete(selection)}>
          Delete node
        </button>
      )}
    </aside>
  );
}

function FindingList({ findings }) {
  if (!findings?.length) return null;
  return (
    <div className="rg-inline-findings">
      {findings.map((finding, index) => (
        <p key={index} className={`rg-finding is-${finding.severity}`}>
          <FindingBadge code={finding.code} /> {finding.message}
        </p>
      ))}
    </div>
  );
}
