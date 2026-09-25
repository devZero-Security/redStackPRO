// Which topology is open, and whether it has been saved.
//
// There is no active topology concept in the backend. Which topology is open is a
// client concern carried by the URL, because the platform never deploys and
// holds no reference to a running thing. See 0009.
//
// Everything here is pure, so it is testable without a browser. The parts that
// touch history, storage, or the network live in App.jsx.

export const TOPOLOGY_PARAM = "topology";

export function topologyIdFromUrl(search) {
  const id = new URLSearchParams(search || "").get(TOPOLOGY_PARAM);
  return id || null;
}

// Other query parameters survive, so a link with a filter or a debug flag on it
// still works once a topology is opened.
export function urlForTopology(id, search = "", pathname = "/") {
  const params = new URLSearchParams(search || "");
  if (id) params.set(TOPOLOGY_PARAM, id);
  else params.delete(TOPOLOGY_PARAM);
  const query = params.toString();
  return query ? `${pathname}?${query}` : pathname;
}

// Key order is not meaning. A document that made a round trip through the API
// comes back with whatever order the serializer chose, and showing that as an
// unsaved change would make the indicator useless.
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonical(value[key])])
    );
  }
  return value;
}

export function sameDocument(a, b) {
  if (a === b) return true;
  if (!a || !b) return false;
  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
}

// Where a save goes. A topology with no id is a create. A topology the principal owns
// is an update. An org visible topology owned by someone else is read only, and
// reuse is by copy, so saving it forks rather than failing. See 0009.
export function saveMode(topology) {
  if (!topology) return "create";
  return topology.editable ? "update" : "fork";
}

// Save is explicit, so the only thing that defers it is a compile holding the
// document. Everything else here is a reason it will not happen at all.
export function saveBlockedReason(state = {}) {
  const { conflict, compiling, saving, dirty } = state;
  if (conflict) return "Resolve the conflict before saving again.";
  if (compiling) return "A compile is in flight. Save once it finishes.";
  if (saving) return "Saving.";
  if (!dirty) return "No changes to save.";
  return null;
}

// A conflict is two people's work, not an error. The prose says what happened
// and states plainly that neither side has been thrown away, because the next
// thing the reader does is decide which one to keep.
export function conflictProse(details = {}) {
  const yours = details.your_version;
  const theirs = details.current_version;
  if (!Number.isInteger(yours) || !Number.isInteger(theirs)) {
    return "This topology moved since you opened it. Nothing has been discarded.";
  }
  const ahead = theirs - yours;
  return (
    `You opened version ${yours} and the saved topology is now version ${theirs}, ` +
    `${ahead} ${ahead === 1 ? "revision" : "revisions"} ahead. ` +
    "Nothing has been discarded."
  );
}

// A name for a fork. The picker lists topologies by name, so two rows reading the
// same thing is the one outcome to avoid. Forking a fork does not stack the
// suffix, because "x (copy) (copy) (copy)" tells a reader nothing.
export function copyName(name, suffix = "copy") {
  const base = (name || "Untitled").trim() || "Untitled";
  return base.endsWith(`(${suffix})`) ? base : `${base} (${suffix})`;
}
