import React from "react";
import { Icon } from "./icons.jsx";
import { LabList } from "./LabList.jsx";
import { presetsForKind } from "./presets.js";

// Some kinds are fully covered by their presets: an operator always has an OS
// (Kali, Windows, Debian) and a redirector is Apache or Nginx, so their bare
// kind buttons are hidden while the presets still render in the category. A
// teamserver keeps its generic button (renamed to "Generic") because a
// teamserver with no preset C2 is a real choice: load your own.
const HIDE_GENERIC = new Set(["operator", "redirector"]);

// Read from the registry, never hardcoded. A pro node kind is a file dropped
// into schema/registry/kinds, with no change here. See 0013.
export function Palette({ groups, onAdd, presets = [], onAddPreset, labsMode, labsTitle = "Blueprints", onLoadLab }) {
  return (
    <aside className="rg-panel rg-palette">
      {labsMode ? (
        <section className="rg-palette-labs">
          <h3>{labsTitle}</h3>
          <LabList mode={labsMode} onLoad={onLoadLab} />
        </section>
      ) : null}
      {Object.entries(groups).map(([group, entries]) => (
        <section key={group}>
          <h3>{group}</h3>
          {entries.flatMap((entry) => {
            // A kind and its presets (Mythic, Sliver, an Nginx redirector) are
            // flavours of one thing, so they sit together in the category and
            // read in alphabetical order. A kind whose presets cover it (an
            // operator always has an OS, a redirector is apache or nginx) hides
            // its bare button.
            const items = [
              ...(HIDE_GENERIC.has(entry.kind)
                ? []
                : [{
                    key: `kind:${entry.kind}`,
                    label: entry.label,
                    icon: entry.icon,
                    color: entry.color,
                    abbrev: entry.abbrev,
                    blurb: entry.blurb,
                    onClick: () => onAdd(entry),
                    dragType: "application/redstackpro",
                    dragValue: entry.kind,
                  }]),
              ...presetsForKind(presets, entry.kind).map((preset) => ({
                key: `preset:${preset.key}`,
                label: preset.label,
                icon: preset.icon,
                color: preset.color,
                abbrev: preset.abbrev,
                blurb: preset.blurb,
                onClick: () => onAddPreset?.(preset),
                dragType: "application/redstackpro-preset",
                dragValue: preset.key,
              })),
            ];
            return items;
          }).sort((a, b) => a.label.localeCompare(b.label)).map((item) => (
            <button
              key={item.key}
              className="rg-palette-item"
              onClick={item.onClick}
              draggable
              onDragStart={(event) => {
                event.dataTransfer.setData(item.dragType, item.dragValue);
                event.dataTransfer.effectAllowed = "move";
              }}
              title={item.blurb}
            >
              <Icon icon={item.icon} color={item.color} />
              <span className="rg-palette-label">{item.label}</span>
              <span className="rg-palette-abbrev">{item.abbrev}</span>
            </button>
          ))}
        </section>
      ))}
      <p className="rg-hint">
        A network holds subnets, and a subnet holds hosts. Drop one inside another to
        attach it. Draw a line between two hosts and the role follows from what
        they are.
      </p>
    </aside>
  );
}
