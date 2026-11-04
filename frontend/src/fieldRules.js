// The rules behind the Inspector's generated overlay forms. Pure, so each rule
// is testable without rendering. Inspector.jsx Field consumes these.

// ----------------------------------------------------------------- $ref

// A property that is only a $ref takes its type, constraints and help from the
// def. The property's own keys (title, description, default) win over the def's.
export function resolveSpec(spec, defs) {
  if (!spec || typeof spec.$ref !== "string" || !defs) return spec;
  const m = /^#\/\$defs\/(.+)$/.exec(spec.$ref);
  const def = m ? defs[m[1]] : undefined;
  if (!def) return spec;
  const { $ref: _ref, ...own } = spec;
  return { "x-ui-def": m[1], ...resolveSpec(def, defs), ...own };
}

// The JSON shape a field must be edited as, or null for a plain control. An
// object or a list of objects has no plain control that can hold it.
export function jsonKindFor(spec, value) {
  if (!spec) return null;
  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  if (spec.type === "object" && !spec.properties) return "object";
  if (spec.type === "array") {
    const items = spec.items || {};
    if (items.type === "object" || items.properties || items.type === "array") return "array";
    if (Array.isArray(value) && value.some((v) => v !== null && typeof v === "object")) return "array";
    if (value != null && !Array.isArray(value)) return "array";
    return null;
  }
  if (spec.type === "object") return value != null && !isObj(value) ? "object" : null;
  if (value !== null && typeof value === "object") return Array.isArray(value) ? "array" : "object";
  return null;
}
