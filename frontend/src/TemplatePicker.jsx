import React from "react";
import { UNGROUPED_LABEL, groupedTemplates } from "./templates.js";

// The template library, shared by both canvases. Every template loads as an
// editable baseline to customise; a family like GOAD is shown as its own folder
// so a person picks a lab and makes it theirs. The picker shows only the current
// canvas's set. See 0047 and 0051.
export function TemplatePicker({ mode, onPick, onDismiss }) {
  const isRange = mode === "defense";
  const groups = groupedTemplates(mode);
  // An ungrouped template rendered with no header sits directly under the
  // previous section's, so Harbor read as a ninth GOAD lab. It needs a label of
  // its own, but only when something else on this screen is labelled: the Red
  // Infra canvas has no groups at all, and a lone header over the whole list
  // would be noise there.
  const labelled = groups.some((g) => g.group);
  return (
    <div className="rg-modal-backdrop" onClick={onDismiss}>
      <div
        className={`rg-modal is-chooser rg-mode-${isRange ? "defense" : "offense"}`}
        role="dialog"
        aria-label="Load a template"
        onClick={(event) => event.stopPropagation()}
      >
        <h2>{isRange ? "Load a range template" : "Load a Red Infra template"}</h2>
        <p className="rg-muted">
          {isRange
            ? "Pick a range to start from and customise it for yourself."
            : "Editable starting points. Load one and make it yours."}
        </p>
        {groups.map(({ group, templates }) => (
          <section key={group || "_"} className="rg-template-group">
            {group || labelled ? (
              <h3 className="rg-template-group-name">{group || UNGROUPED_LABEL}</h3>
            ) : null}
            <div className="rg-chooser-grid rg-goad-grid">
              {templates.map((template) => (
                <button
                  key={template.file}
                  type="button"
                  className="rg-chooser-card"
                  onClick={() => onPick(template.file)}
                >
                  <span className="rg-chooser-name">{template.name}</span>
                  <span className="rg-chooser-blurb">{template.blurb}</span>
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
