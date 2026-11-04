// Findings by severity, and where clicking one should land.
//
// info is a notice: it never blocks a compile and is never counted as a
// warning or read as a failure. See findings.py.

export const SEVERITY_ORDER = ["error", "warning", "info"];

const rank = (severity) => {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index === -1 ? SEVERITY_ORDER.length : index;
};

// Worst first, stable within a severity, so a node's first finding is its worst.
export function sortFindings(findings) {
  return [...(findings || [])].sort((a, b) => rank(a.severity) - rank(b.severity));
}

export function countBySeverity(findings) {
  const count = { error: 0, warning: 0, info: 0 };
  for (const f of findings || []) {
    if (f.severity in count) count[f.severity] += 1;
  }
  return count;
}

// The target a document-level finding names (auto_stop.at, prefix). Mirrors
// TOPOLOGY_TARGET in schemacheck.py.
export const TOPOLOGY_TARGET = "topology";

// The selection a click on a finding makes. A document-level finding, or one
// whose target is gone, clears the selection so the Inspector shows Topology
// settings.
export function findingSelection(document, finding) {
  const id = finding?.target_ids?.[0];
  if (!id || id === TOPOLOGY_TARGET) return null;
  if (document.edges.some((e) => e.id === id)) return { type: "edge", id };
  if (document.nodes.some((n) => n.id === id)) return { type: "node", id };
  return null;
}
