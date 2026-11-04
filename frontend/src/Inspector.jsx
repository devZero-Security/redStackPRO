import React, { useEffect, useId, useState } from "react";
import { FindingBadge } from "./FindingBadge.jsx";
import { isContainer } from "./topology.js";
import { PROFILES } from "./profiles.js";
import {
  ACCOUNT_TECHNIQUE_IDS, VULN_CATALOG, VULN_LABEL, VULN_PARAMS, VULN_PROVIDERS,
  vulnParamsExample,
} from "./vulns.js";
import { HARDENING_CATALOG } from "./hardening.js";
import {
  checkValue, defaultFor, emptyOptionLabel, fieldFindings, fieldLabel, fieldRule, findingsAt,
  jsonKindFor, numberHelp, optionLabel, placeholderFor, resolveSpec,
} from "./fieldRules.js";
import {
  accountTechniquePlanted, plantAccountTechnique, removeAccountTechnique,
} from "./rangeUsers.js";
import { DomainUsers } from "./DomainUsers.jsx";
import { AclEditor } from "./AclEditor.jsx";
import { GmsaEditor } from "./GmsaEditor.jsx";
import { GroupNesting } from "./GroupNesting.jsx";
import { TrustEditor } from "./TrustEditor.jsx";
import { EdgeRole, FrontsPorts } from "./EdgeEditors.jsx";
import { Connections } from "./Connections.jsx";
import { TopologySettings } from "./TopologySettings.jsx";
import { nodeName, roleTitle } from "./edgeRoles.js";

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
//
// Read-only for now: no role reads overlay.hardening, so ticking a control would
// promise a locked-down host that deploys unhardened. Stored values stay visible.
function HardeningPicker({ value, title = "hardening", ignored }) {
  const set = value || [];
  const [collapsed, setCollapsed] = useState(() => initialCollapsed(HARDENING_CATALOG, set));
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
        {title}{set.length ? ` (${set.length})` : ""}
      </span>
      <span className="rg-field-ignored">
        Not applied yet: these controls are recorded but not deployed.
      </span>
      {ignored ? <span className="rg-field-ignored">Not used here: {ignored}</span> : null}
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
                        <input type="checkbox" checked={isSelected} disabled readOnly />
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

// The account techniques a host cannot carry itself (vulns.js
// ACCOUNT_TECHNIQUE_IDS), pulled out of the catalog once so the picker below
// renders them in their own group and skips them in every other one. Reuses
// each item's label/blurb from VULN_CATALOG rather than repeating them.
const ACCOUNT_TECHNIQUE_ITEMS = VULN_CATALOG.flatMap((g) => g.items).filter((item) =>
  ACCOUNT_TECHNIQUE_IDS.has(item.id)
);

// The planted-vulnerability picker for a range host: a grouped checklist from
// the GOAD-derived catalog. See vulns.js.
//
// `provider` (the range's compile target, e.g. "gcp"/"proxmox") greys a vuln
// VULN_PROVIDERS restricts to other providers -- a template can still declare
// it (it may target more than one provider over its life), but the compiler
// silently drops it for this one, so the checkbox stays checkable, just
// visibly a no-op here. See redstackpro.ansible.VULN_PROVIDERS, kept in sync
// with vulns.js by tests/test_vuln_providers_sync.py.
//
// Four ids (ACCOUNT_TECHNIQUE_ITEMS) are account flaws, not host tasks:
// checking one plants a matching flawed user on the host's joined domain
// instead of writing into the host's own overlay.vulns, so they get their own
// group below rather than a checkbox that would otherwise no-op (RNG009). See
// rangeUsers.js plantAccountTechnique.
function VulnPicker({
  value, onChange, disabled, provider, document, hostId, onOverlayChange, title = "vulnerabilities",
  ignored,
}) {
  const set = value || [];
  const [collapsed, setCollapsed] = useState(() => initialCollapsed(VULN_CATALOG, set));
  const [accountCollapsed, setAccountCollapsed] = useState(false);
  const toggle = (id) =>
    onChange(set.includes(id) ? set.filter((v) => v !== id) : [...set, id]);
  const toggleGroup = (key) =>
    setCollapsed((cur) => {
      const next = new Set(cur);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const domainId =
    document?.edges.find((e) => e.role === "joins" && e.source === hostId)?.target;
  const domainNode = domainId ? document?.nodes.find((n) => n.id === domainId) : undefined;

  const toggleAccountTechnique = (id) => {
    if (!domainNode) return;
    const overlay = accountTechniquePlanted(domainNode, hostId, id)
      ? removeAccountTechnique(domainNode, hostId, id)
      : plantAccountTechnique(domainNode, hostId, id);
    if (overlay) onOverlayChange?.(domainNode.id, overlay);
  };

  return (
    <div className="rg-field">
      <span className="rg-field-label">
        {title}{set.length ? ` (${set.length})` : ""}
      </span>
      {ignored ? <span className="rg-field-ignored">Not used here: {ignored}</span> : null}
      <div className="rg-vulns">
        {VULN_CATALOG.map((group) => {
          const items = group.items.filter((item) => !ACCOUNT_TECHNIQUE_IDS.has(item.id));
          if (!items.length) return null;
          const selectedCount = items.filter((item) => set.includes(item.id)).length;
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
                : items.map((item) => {
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
        <div className="rg-vuln-group rg-vuln-group-account">
          <button
            type="button"
            className="rg-vuln-group-header"
            aria-expanded={!accountCollapsed}
            onClick={() => setAccountCollapsed((cur) => !cur)}
          >
            <span className="rg-vuln-group-caret" aria-hidden="true">
              {accountCollapsed ? "▸" : "▾"}
            </span>
            <span className="rg-vuln-group-label">Account techniques (planted on a domain user)</span>
          </button>
          {accountCollapsed ? null : (
            <>
              {!domainNode ? (
                <p className="rg-hint">
                  Join this host to a domain to plant account techniques.
                </p>
              ) : null}
              {ACCOUNT_TECHNIQUE_ITEMS.map((item) => {
                const planted = accountTechniquePlanted(domainNode, hostId, item.id);
                return (
                  <label
                    key={item.id}
                    className={`rg-check${planted ? " is-selected" : ""}`}
                    title={item.blurb || ""}
                  >
                    <input
                      type="checkbox"
                      checked={planted}
                      disabled={disabled || !domainNode}
                      onChange={() => toggleAccountTechnique(item.id)}
                    />
                    {item.label}
                  </label>
                );
              })}
            </>
          )}
        </div>
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

// The operator roster on an offense jumpbox: the people who reach the range. Each
// becomes a portal account and, on a VPN access mode, gets a personal VPN
// credential generated on the jumpbox at apply. Reuses the acls row styling. See
// vpn-multiuser-spec.
//
// A handle is interpolated into shell, filenames and SQL on the jumpbox at apply,
// so it is held to a strict charset here (matches VPN005), and the free-form role
// to a single short line (VPN006), rather than letting a bad value through to fail
// only at compile.
const OPERATOR_HANDLE_RE = /^[a-z0-9][a-z0-9._-]*$/;
function Operators({ node, onChange, readOnly, ignored }) {
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
      {ignored ? <p className="rg-field-ignored">Not used here: {ignored}</p> : null}
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
              {readOnly ? null : (
                <button
                  type="button"
                  className="rg-user-del"
                  title="Remove operator"
                  onClick={() => set(operators.filter((_, j) => j !== i))}
                >
                  &times;
                </button>
              )}
            </div>
          ))}
        </div>
      ) : null}
      {readOnly ? null : (
        <div className="rg-acls-add">
          <input value={handle} placeholder="handle" onChange={(e) => setHandle(e.target.value)} />
          <input value={role} placeholder="label, e.g. lead (display only)" onChange={(e) => setRole(e.target.value)} />
          <button type="button" onClick={add} disabled={!handle.trim()}>Add</button>
        </div>
      )}
      {err ? <p className="rg-hint rg-danger-text">{err}</p> : null}
    </div>
  );
}

// The range host kinds that join a domain. Standalone range boxes (jumpbox,
// SIEM, firewall, appliance) sit on a subnet but do not join a domain, so they
// get the subnet control but not the domain one.
const DOMAIN_JOINERS = new Set(["dc", "srv", "wks"]);
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

// The range host kinds (dc, srv, wks, fw, appliance) all share one overlay
// definition, so their forms resolve to it rather than a per-kind def that does
// not exist. appliance used to miss here and showed no fields at all.
const RANGE_HOST_KINDS = new Set(["dc", "srv", "wks", "fw", "appliance"]);

function overlaySchemaFor(schema, kind) {
  const defs = schema?.$defs || {};
  const name = RANGE_HOST_KINDS.has(kind) ? "range_host" : kind;
  return defs[`overlay_${name}`] || null;
}

// An object with free keys (vulns_vars, group_members) is edited as JSON text.
// The text stays local until it parses to an object, so a half-typed brace never
// reaches the document. It used to fall through to the plain input, which showed
// "[object Object]" and saved whatever was typed as a string.
function showJson(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function sameJson(text, value) {
  try {
    const parsed = text.trim() ? JSON.parse(text) : null;
    return JSON.stringify(parsed) === JSON.stringify(value ?? null);
  } catch {
    return false;
  }
}

// `expect` is the shape the field holds: "object" ({...}) or "array" ([...]), so
// a list of objects (gmsa, say) gets the same editor instead of a text box.
function JsonObjectField({ label, help, value, disabled, onChange, expect = "object", className = "rg-field" }) {
  const id = useId();
  const [text, setText] = useState(() => showJson(value));
  const [error, setError] = useState(null);
  const wantArray = expect === "array";
  const fits = (v) => (wantArray ? Array.isArray(v) : !!v && typeof v === "object" && !Array.isArray(v));
  const shapeHint = wantArray ? "a JSON list, [...]" : "a JSON object, {...}";
  const committed = typeof value === "string" ? value : JSON.stringify(value ?? null);
  useEffect(() => {
    // An outside change (undo, a template load) replaces the text unless the
    // text already says the same thing.
    if (!sameJson(text, value)) {
      setText(showJson(value));
      setError(null);
    }
  }, [committed]);

  const edit = (next) => {
    setText(next);
    if (!next.trim()) {
      setError(null);
      onChange(undefined);
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(next);
    } catch {
      setError("Not valid JSON yet. The last valid value is kept.");
      return;
    }
    if (!fits(parsed)) {
      setError(`Must be ${shapeHint}. The last valid value is kept.`);
      return;
    }
    setError(null);
    onChange(parsed);
  };

  // A stored value of the wrong shape (a string where a list belongs) says so
  // up front rather than only once someone starts typing.
  const shown =
    error || (value != null && !fits(value) ? `The stored value is not ${shapeHint}. Replace it with one.` : null);

  // The help sits outside the label: a click inside a label moves focus to the
  // textarea, which would drop a selection made in the help's example.
  return (
    <div className={className}>
      <label htmlFor={id}>{label}</label>
      <textarea
        id={id}
        value={text}
        rows={Math.min(10, Math.max(2, text.split("\n").length))}
        spellCheck={false}
        disabled={disabled}
        onChange={(e) => edit(e.target.value)}
      />
      {shown ? <span className="rg-field-error">{shown}</span> : null}
      {help}
    </div>
  );
}

// A comma separated list of strings. The text stays local so a trailing comma
// survives while typing; a controlled input bound to the parsed list used to
// eat it, so a second entry could only be pasted in.
const parseList = (text) =>
  text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

function ListField({ label, help, value, disabled, onChange, placeholder, className = "rg-field" }) {
  const toText = (v) => (Array.isArray(v) ? v.join(", ") : "");
  const [text, setText] = useState(() => toText(value));
  const committed = JSON.stringify(value ?? []);
  useEffect(() => {
    if (JSON.stringify(parseList(text)) !== committed) setText(toText(value));
  }, [committed]);
  return (
    <label className={className}>
      {label}
      <input
        value={text}
        placeholder={placeholder}
        disabled={disabled}
        onChange={(e) => {
          setText(e.target.value);
          const list = parseList(e.target.value);
          onChange(list.length ? list : undefined);
        }}
      />
      {help}
    </label>
  );
}

// The help under vulns_vars: for each ticked vuln that reads parameters, its
// keys and a one-line example to copy, in catalog order. With none ticked, the
// field's plain description.
function VulnVarsHelp({ vulns, description }) {
  const ticked = new Set(vulns || []);
  const ids = VULN_CATALOG.flatMap((g) => g.items.map((i) => i.id)).filter(
    (id) => ticked.has(id) && VULN_PARAMS[id]
  );
  if (!ids.length) {
    return description ? <span className="rg-field-help">{description}</span> : null;
  }
  return (
    <div className="rg-field-help rg-vuln-params">
      <span>Keys the ticked vulns read. Merge the examples into one JSON object.</span>
      {ids.map((id) => (
        <div key={id} className="rg-vuln-params-item">
          <span className="rg-vuln-params-label">{VULN_LABEL[id]}</span>
          <ul>
            {VULN_PARAMS[id].map((p) => (
              <li key={p.key}>
                <code>{p.key}</code>
                {p.required ? (
                  <span className="rg-required">required{p.or ? ` (or ${p.or})` : ""}</span>
                ) : (
                  <span className="rg-optional">optional</span>
                )}{" "}
                {p.about}
              </li>
            ))}
          </ul>
          <code className="rg-vuln-params-example">{vulnParamsExample(id)}</code>
        </div>
      ))}
    </div>
  );
}

// `defs` is the schema's $defs, so a property that is only a $ref (public_address,
// a port) renders as the type it points at rather than as a bare text box.
// `path` is the dotted overlay path (tls.cert_source) and `ctx` the node it sits
// on ({id, kind, mode, overlay}); together they pick the default an empty field
// compiles to. Both are optional, so a bare spec (an edge field) still renders.
// `findings` are the server findings that name a field on this node
// ({field, message}); the ones at `path` mark this field red.
function Field({
  name, path = name, spec: rawSpec, value: rawValue, required, onChange, disabled,
  help: helpOverride, defs, ctx, findings,
}) {
  // The node's rules can hide the field, flag a stored value as unused here, or
  // lock it at the one value the compiler accepts. See fieldRules.js.
  const rule = fieldRule(path, resolveSpec(rawSpec, defs) || {}, ctx, rawValue);
  if (rule.hide) return null;
  const spec = rule.spec;
  const locked = rule.locked;
  const value = locked ? locked.value : rawValue;
  if (locked) disabled = true;
  const title = fieldLabel(name, spec);
  const def = defaultFor(path, spec, ctx);
  // A server finding on this field wins; the client check covers the gap until
  // the next validation lands, in the same words.
  const isFieldset = spec.type === "object" && !!spec.properties;
  const serverErrors = findingsAt(findings, path, !isFieldset).map((f) => f.message);
  const clientError =
    serverErrors.length || locked ? null : checkValue(title, spec, value, (v) => optionLabel(name, v));
  const errors = serverErrors.length ? serverErrors : clientError ? [clientError] : [];
  const cls = errors.length ? "rg-field is-invalid" : "rg-field";
  const errorList = errors.map((message, i) => (
    <span key={i} className="rg-field-error">{message}</span>
  ));
  const label = (
    <span className="rg-field-label">
      {title}
      {required ? <span className="rg-required">required</span> : null}
    </span>
  );

  const autoHelp = spec.type === "integer" || spec.type === "number" ? numberHelp(spec, def) : "";
  const helpText = locked ? locked.reason : spec.description || autoHelp;
  const help = (
    <>
      {locked ? null : helpOverride}
      {(locked || helpOverride == null) && helpText ? (
        <span className="rg-field-help">{helpText}</span>
      ) : null}
      {rule.ignored ? (
        <span className="rg-field-ignored">Not used here: {rule.ignored}</span>
      ) : null}
      {errorList}
    </>
  );

  // Never a text box for structured data: it showed "[object Object]" and any
  // keystroke replaced the structure with a string.
  const jsonKind = jsonKindFor(spec, value);
  if (jsonKind) {
    return (
      <JsonObjectField
        label={label}
        help={help}
        value={value}
        disabled={disabled}
        onChange={onChange}
        expect={jsonKind}
        className={cls}
      />
    );
  }

  // An enum is a choice, so it is a select rather than a free text box the
  // validator has to reject afterward. The empty option names what an empty
  // field compiles to; a required field has none. A stored value the list does
  // not offer stays selectable so the select never shows a choice it does not
  // hold.
  if (spec.enum) {
    const unset = value == null || value === "";
    const offered = unset || spec.enum.includes(value);
    const optionHelp = spec["x-ui-option-help"]?.[unset ? def : value];
    return (
      <label className={cls}>
        {label}
        <select
          value={value ?? ""}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value || undefined)}
        >
          {required ? (
            unset ? <option value="" disabled>pick one</option> : null
          ) : (
            <option value="">{emptyOptionLabel(path, spec, ctx)}</option>
          )}
          {offered ? null : (
            <option value={value}>{optionLabel(name, value)} (not a choice here)</option>
          )}
          {spec.enum.map((option) => (
            <option key={option} value={option}>
              {optionLabel(name, option)}
            </option>
          ))}
        </select>
        {optionHelp ? <span className="rg-field-help rg-option-help">{optionHelp}</span> : null}
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
      <label className={cls}>
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
      <label className={cls}>
        {label}
        <input
          type="number"
          value={value ?? ""}
          placeholder={def ?? ""}
          min={spec.minimum}
          max={spec.maximum}
          step={spec.type === "integer" ? 1 : undefined}
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
      const set = (next) => onChange(next.length ? next : undefined);
      // Stored values the checklist does not offer: shown as chips that say why
      // they do nothing, removable, never silently dropped.
      const unknown = items.filter((i) => !options.includes(i));
      const unknownTitle = spec["x-ui-unknown-title"];
      return (
        <div className={cls}>
          {label}
          {options.length ? (
            <div className="rg-checks">
              {options.map((option) => (
                <label key={option} className="rg-check">
                  <input
                    type="checkbox"
                    checked={items.includes(option)}
                    disabled={disabled}
                    onChange={(e) =>
                      set(e.target.checked ? [...items, option] : items.filter((i) => i !== option))
                    }
                  />
                  {optionLabel(name, option)}
                </label>
              ))}
            </div>
          ) : null}
          {unknown.length ? (
            <div className="rg-chips">
              {unknown.map((v) => (
                <span
                  key={v}
                  className="rg-chip"
                  title={unknownTitle ? unknownTitle(v) : `${v} is not one of the choices.`}
                >
                  {optionLabel(name, v)}
                  {disabled ? null : (
                    <button
                      type="button"
                      className="rg-chip-del"
                      aria-label={`Remove ${v}`}
                      onClick={() => set(items.filter((i) => i !== v))}
                    >
                      &times;
                    </button>
                  )}
                </span>
              ))}
            </div>
          ) : null}
          {spec["x-ui-note"] ? <span className="rg-field-help">{spec["x-ui-note"]}</span> : null}
          {help}
        </div>
      );
    }
    return (
      <ListField
        label={label}
        help={help}
        className={cls}
        value={items}
        placeholder={placeholderFor(path, spec, ctx)}
        disabled={disabled}
        onChange={onChange}
      />
    );
  }

  if (spec.type === "object" && spec.properties) {
    return (
      <fieldset className="rg-fieldset">
        <legend>{title}</legend>
        {spec.description ? <p className="rg-field-help">{spec.description}</p> : null}
        {rule.ignored ? <p className="rg-field-ignored">Not used here: {rule.ignored}</p> : null}
        {errorList}
        {Object.entries(spec.properties).map(([child, childSpec]) => (
          <Field
            key={child}
            name={child}
            path={`${path}.${child}`}
            spec={childSpec}
            value={(value || {})[child]}
            required={(spec.required || []).includes(child)}
            disabled={disabled}
            defs={defs}
            ctx={ctx}
            findings={findings}
            onChange={(next) => onChange({ ...(value || {}), [child]: next })}
          />
        ))}
      </fieldset>
    );
  }

  return (
    <label className={cls}>
      {label}
      <input
        value={value ?? ""}
        // A value the compiler fills in shows in grey, so a default does not sit
        // in the document as a literal someone has to notice and delete. Then
        // the schema's hint, then an example; never the raw pattern.
        placeholder={placeholderFor(path, spec, ctx)}
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
  deployTarget,
  onTopologyChange,
}) {
  if (!selection) {
    return (
      <TopologySettings
        document={document}
        deployTarget={deployTarget}
        readOnly={readOnly}
        onChange={onTopologyChange}
      />
    );
  }

  if (selection.type === "edge") {
    const edge = document.edges.find((e) => e.id === selection.id);
    if (!edge) return null;
    return (
      <aside className="rg-panel rg-inspector">
        <h2>{roleTitle(edge.role)}</h2>
        <p className="rg-kv">
          <span>from</span>
          <span>{nodeName(document, edge.source)}</span>
        </p>
        <p className="rg-kv">
          <span>to</span>
          <span>{nodeName(document, edge.target)}</span>
        </p>
        <EdgeRole
          edge={edge}
          document={document}
          readOnly={readOnly}
          onEdgeChange={onEdgeChange}
        />
        {edge.role === "trusts" ? (
          <TrustEditor
            edge={edge}
            document={document}
            readOnly={readOnly}
            onEdgeChange={onEdgeChange}
          />
        ) : null}
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
            <FrontsPorts edge={edge} readOnly={readOnly} onEdgeChange={onEdgeChange} />
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
  // What a field's rules read: the node it sits on and the canvas mode.
  const fieldCtx = { id: node.id, kind: node.kind, mode: document.mode, overlay: node.overlay || {} };
  const ruleOf = (name, spec) => fieldRule(name, spec, fieldCtx, fieldCtx.overlay[name]);
  // Findings that name a field (SCH001) show under that field as well.
  const onField = fieldFindings(findings);
  const idErrors = findingsAt(onField, "id");

  return (
    <aside className="rg-panel rg-inspector">
      <h2>
        {document.prefix}-{node.id}
      </h2>
      <p className="rg-kv">
        <span>kind</span>
        <span>{kindLabels[node.kind] || node.kind}</span>
      </p>
      <label className={idErrors.length ? "rg-field is-invalid" : "rg-field"}>
        <span className="rg-field-label">id</span>
        <input
          value={node.id}
          disabled={readOnly}
          onChange={(e) => onRename(node.id, e.target.value)}
        />
        {idErrors.map((f, i) => (
          <span key={i} className="rg-field-error">{f.message}</span>
        ))}
        <span className="rg-field-help">
          Lowercase kebab: a purpose slug, the kind tag, and a two digit
          ordinal, e.g. main-net01. Left as is, it tracks what the node
          holds; rename it and it stays put.
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

      {document.mode === "defense" && !readOnly && (onJoinDomain || onPlaceSubnet) ? (
        <RangePlacement
          node={node}
          document={document}
          onJoinDomain={onJoinDomain}
          onPlaceSubnet={onPlaceSubnet}
        />
      ) : null}

      {node.kind === "jumpbox" && document?.mode === "offense" && !readOnly ? (
        <p className="rg-hint">
          This jumpbox can front a team. Set <code>access_mode</code> to
          wireguard or openvpn and add operators below: each gets a portal login
          and a personal VPN credential generated on the jumpbox at deploy.
        </p>
      ) : null}

      {overlaySchema
        ? Object.entries(overlaySchema.properties || {})
            .map(([name, spec]) => [name, resolveSpec(spec, schema?.$defs)])
            .filter(([, spec]) => spec["x-redstackpro-source"] !== "derived")
            .filter(([name, spec]) => !ruleOf(name, spec).hide)
            .map(([name, spec]) =>
              name === "vulns" ? (
                <VulnPicker
                  key={`${name}-${node.id}`}
                  value={(node.overlay || {}).vulns}
                  title={spec.title}
                  ignored={ruleOf(name, spec).ignored}
                  disabled={readOnly}
                  provider={provider}
                  document={document}
                  hostId={node.id}
                  onOverlayChange={onOverlayChange}
                  onChange={(value) =>
                    onOverlayChange(node.id, { ...(node.overlay || {}), vulns: value })
                  }
                />
              ) : name === "hardening" ? (
                <HardeningPicker
                  key={`${name}-${node.id}`}
                  value={(node.overlay || {}).hardening}
                  title={spec.title}
                  ignored={ruleOf(name, spec).ignored}
                  disabled={readOnly}
                  onChange={(value) =>
                    onOverlayChange(node.id, {
                      ...(node.overlay || {}),
                      hardening: value && value.length ? value : undefined,
                    })
                  }
                />
              ) : name === "users" ? (
                <DomainUsers
                  key={`${name}-${node.id}`}
                  node={node}
                  document={document}
                  rangeHostCount={rangeHostCount}
                  flawOptions={spec.items?.properties?.flaws?.items?.enum || []}
                  readOnly={readOnly}
                  onChange={(overlay) => onOverlayChange(node.id, overlay)}
                />
              ) : name === "acls" ? (
                <AclEditor
                  key={`${name}-${node.id}`}
                  node={node}
                  document={document}
                  readOnly={readOnly}
                  onChange={(overlay) => onOverlayChange(node.id, overlay)}
                />
              ) : name === "gmsa" ? (
                <GmsaEditor
                  key={`${name}-${node.id}`}
                  node={node}
                  document={document}
                  readOnly={readOnly}
                  onChange={(overlay) => onOverlayChange(node.id, overlay)}
                />
              ) : name === "group_members" ? (
                <GroupNesting
                  key={`${name}-${node.id}`}
                  node={node}
                  readOnly={readOnly}
                  onChange={(overlay) => onOverlayChange(node.id, overlay)}
                />
              ) : name === "operators" ? (
                <Operators
                  key={name}
                  node={node}
                  ignored={ruleOf(name, spec).ignored}
                  readOnly={readOnly}
                  onChange={(overlay) => onOverlayChange(node.id, overlay)}
                />
              ) : (
                <Field
                  // Keyed by node too, so a JSON field's local text does not
                  // carry over to the next node selected.
                  key={`${name}-${node.id}`}
                  name={name}
                  spec={
                    name === "gating" && coverShown ? withoutDecoy(spec) : spec
                  }
                  required={required.includes(name)}
                  value={(node.overlay || {})[name]}
                  help={
                    name === "vulns_vars" ? (
                      <VulnVarsHelp
                        vulns={(node.overlay || {}).vulns}
                        description={spec.description}
                      />
                    ) : undefined
                  }
                  disabled={readOnly}
                  defs={schema?.$defs}
                  ctx={fieldCtx}
                  findings={onField}
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
        onEdgeChange={onEdgeChange}
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
