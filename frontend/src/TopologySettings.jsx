import React from "react";
import "./widgets.css";
import { AZURE_TIMEZONES } from "./azureTimezones.js";
import { FindingBadge } from "./FindingBadge.jsx";

// The region the export uses when the topology names none, per deploy target.
// Mirrors DEFAULT_REGION in src/redstackpro/terraform/plan.py.
const DEFAULT_REGION = { gcp: "us-east4", aws: "us-east-1", azure: "eastus2" };
const CIDR_RE = /^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/;

// Sets or, for undefined, removes top-level document fields.
export function applyTopologyPatch(document, patch) {
  const next = { ...document };
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined) delete next[key];
    else next[key] = value;
  }
  return next;
}

function allTimezones() {
  let zones = [];
  try {
    zones = Intl.supportedValuesOf("timeZone");
  } catch {
    zones = AZURE_TIMEZONES;
  }
  return ["UTC", ...zones.filter((z) => z !== "UTC")];
}

// The fields this panel edits. A document finding on one of them shows under
// it; any other (prefix, name) is listed at the top.
const PANEL_FIELDS = ["description", "region", "base_cidr", "auto_stop"];

const onField = (finding, path) =>
  finding.field === path || (finding.field || "").startsWith(`${path}.`);

function Findings({ findings }) {
  if (!findings?.length) return null;
  return (
    <div className="rg-inline-findings">
      {findings.map((f, i) => (
        <p key={i} className={`rg-finding is-${f.severity}`}>
          <FindingBadge code={f.code} /> {f.message}
        </p>
      ))}
    </div>
  );
}

// Drops empty keys so the document never carries auto_stop: {}.
function cleanStop(stop) {
  const out = {};
  for (const [k, v] of Object.entries(stop)) if (v !== undefined && v !== "") out[k] = v;
  return Object.keys(out).length ? out : undefined;
}

function AutoStop({ stop, deployTarget, disabled, onChange, findings }) {
  const enabled = !!stop.enabled;
  const hasAt = !!stop.at;
  const hasAfter = stop.after_hours != null;
  const mode = hasAt && hasAfter ? "both" : hasAt ? "at" : "after";
  const set = (patch) => onChange(cleanStop({ ...stop, ...patch }));

  const azure = deployTarget === "azure";
  const zone = stop.timezone || "UTC";
  const zones = azure ? AZURE_TIMEZONES : allTimezones();
  const zoneOk = zones.includes(zone);
  const showZone = mode !== "after" || (stop.timezone && stop.timezone !== "UTC");

  return (
    <div className="rg-settings-section">
      <h3>Auto-stop</h3>
      <p className="rg-hint">
        The range stops itself at this time each day (or N hours after the first
        apply). Start it again with manage.sh start.
      </p>
      <Findings findings={findings} />
      <label className="rg-field">
        <span className="rg-check-row">
          <input
            type="checkbox"
            checked={enabled}
            aria-label="Stop the range automatically"
            disabled={disabled}
            onChange={(e) =>
              set(
                e.target.checked
                  ? { enabled: true, ...(hasAt || hasAfter ? {} : { after_hours: 8 }) }
                  : { enabled: false }
              )
            }
          />
          <span>Stop the range automatically</span>
        </span>
        <span className="rg-field-help">
          Instances are stopped, not deleted. Disks and reserved addresses still bill.
        </span>
      </label>
      {enabled ? (
        <>
          <div className="rg-field" role="radiogroup" aria-label="when to stop">
            <label className="rg-check">
              <input
                type="radio"
                name="rg-auto-stop-mode"
                checked={mode === "at"}
                disabled={disabled}
                onChange={() => set({ at: stop.at || "20:00", after_hours: undefined })}
              />
              Stop at a time each day
            </label>
            <label className="rg-check">
              <input
                type="radio"
                name="rg-auto-stop-mode"
                checked={mode === "after"}
                disabled={disabled}
                onChange={() =>
                  set({ after_hours: stop.after_hours || 8, at: undefined, timezone: undefined })
                }
              />
              Stop a number of hours after the first apply
            </label>
            {mode === "both" ? (
              <span className="rg-field-help">Both are set. The earlier of the two wins each day.</span>
            ) : null}
          </div>
          {mode !== "after" ? (
            <label className="rg-field">
              <span className="rg-field-label">stop at</span>
              <input
                type="time"
                value={stop.at || ""}
                aria-label="stop at"
                disabled={disabled}
                onChange={(e) => set({ at: e.target.value || undefined })}
              />
              <span className="rg-field-help">24 hour HH:MM, every day.</span>
            </label>
          ) : null}
          {mode !== "at" ? (
            <label className="rg-field">
              <span className="rg-field-label">stop after (hours)</span>
              <input
                type="number"
                min={1}
                max={168}
                value={stop.after_hours ?? ""}
                aria-label="stop after hours"
                disabled={disabled}
                onChange={(e) =>
                  set({ after_hours: e.target.value === "" ? undefined : Number(e.target.value) })
                }
              />
              <span className="rg-field-help">
                1 to 168. Counted from the first apply; after that the range stops
                at the same time each day.
              </span>
              {hasAfter && (stop.after_hours < 1 || stop.after_hours > 168 || !Number.isInteger(stop.after_hours)) ? (
                <span className="rg-field-error">Use a whole number of hours from 1 to 168.</span>
              ) : null}
            </label>
          ) : null}
          {showZone ? (
            <label className="rg-field">
              <span className="rg-field-label">timezone</span>
              <select
                value={zone}
                aria-label="timezone"
                disabled={disabled}
                onChange={(e) => set({ timezone: e.target.value === "UTC" ? undefined : e.target.value })}
              >
                {zoneOk ? null : (
                  <option value={zone}>
                    {zone}
                    {azure ? " (Azure cannot use this zone)" : ""}
                  </option>
                )}
                {zones.map((z) => (
                  <option key={z} value={z}>{z}</option>
                ))}
              </select>
              <span className="rg-field-help">
                The stop time is read in this zone.
                {azure ? " Azure needs a zone it can map to a Windows time zone, so the list is shorter." : ""}
              </span>
              {azure && !zoneOk ? (
                <span className="rg-field-error">
                  Azure cannot map {zone}, so the export will fail. Pick a zone from the list.
                </span>
              ) : null}
            </label>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

// The settings that belong to the whole topology rather than to one node,
// shown when nothing is selected.
export function TopologySettings({ document, deployTarget, readOnly, onChange, findings = [] }) {
  const disabled = readOnly || !onChange;
  const set = (patch) => onChange?.(patch);
  const regionDefault = DEFAULT_REGION[deployTarget];
  const cidrBad = document.base_cidr && !CIDR_RE.test(document.base_cidr);
  const at = (path) => findings.filter((f) => onField(f, path));
  const elsewhere = findings.filter((f) => !PANEL_FIELDS.some((path) => onField(f, path)));

  return (
    <aside className="rg-panel rg-inspector">
      <h2>Topology settings</h2>
      <p className="rg-hint">
        These apply to the whole topology. Select a node or a line to edit it
        instead.
      </p>
      <Findings findings={elsewhere} />

      <label className="rg-field">
        <span className="rg-field-label">description</span>
        <textarea
          value={document.description || ""}
          rows={2}
          aria-label="description"
          disabled={disabled}
          onChange={(e) => set({ description: e.target.value || undefined })}
        />
        <span className="rg-field-help">A note for you and your team. Not deployed.</span>
      </label>
      <Findings findings={at("description")} />

      <label className="rg-field">
        <span className="rg-field-label">region</span>
        <input
          value={document.region || ""}
          placeholder={regionDefault || ""}
          aria-label="region"
          disabled={disabled}
          onChange={(e) => set({ region: e.target.value.trim() || undefined })}
        />
        <span className="rg-field-help">
          {regionDefault
            ? `Cloud region the export deploys to. Empty uses ${regionDefault} on ${deployTarget}.`
            : "Cloud region the export deploys to. Ignored by on-prem targets."}
        </span>
      </label>
      <Findings findings={at("region")} />

      <label className="rg-field">
        <span className="rg-field-label">address range</span>
        <input
          value={document.base_cidr || ""}
          placeholder="10.0.0.0/8"
          aria-label="address range"
          disabled={disabled}
          onChange={(e) => set({ base_cidr: e.target.value.trim() || undefined })}
        />
        <span className="rg-field-help">
          The block new networks and subnets are carved from. Empty uses
          10.0.0.0/8. Networks already placed keep their ranges.
        </span>
        {cidrBad ? (
          <span className="rg-field-error">Use an address and prefix length, e.g. 10.0.0.0/8.</span>
        ) : null}
      </label>
      <Findings findings={at("base_cidr")} />

      <AutoStop
        stop={document.auto_stop || {}}
        deployTarget={deployTarget}
        disabled={disabled}
        findings={at("auto_stop")}
        onChange={(auto_stop) => set({ auto_stop })}
      />

      <h3>Summary</h3>
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
