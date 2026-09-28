// The only way the canvas touches anything. Every action is an API call, or the
// agent harness eventually hits a wall. See architecture.md.

const BASE = "/api/v1";

async function request(path, options = {}) {
  const response = await fetch(BASE + path, {
    ...options,
    // Merged rather than replaced, so a caller adding one header does not drop
    // the content type.
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });

  if (response.headers.get("content-type")?.includes("application/zip")) {
    return response.blob();
  }

  const body = await response.json().catch(() => null);
  if (!response.ok) {
    // Errors carry a code, prose, and details. Surface the prose; the details
    // are what a caller acts on. See 0017.
    const error = new Error(body?.message || response.statusText);
    error.code = body?.code;
    error.details = body?.details || {};
    error.status = response.status;
    throw error;
  }
  return body;
}

export const api = {
  palette: (mode = "offense") => request(`/registry/palette?mode=${mode}`),
  schema: () => request("/registry/schema"),
  providers: () => request("/registry/providers"),

  // Paged, newest first. The default matches the API's own default, so a caller
  // that wants the first page keeps calling with no arguments. See 0026.
  listTopologies: (limit = 100, offset = 0) =>
    request(`/topologies?limit=${limit}&offset=${offset}`),
  // The create route reads an idempotency key, so a retry after a timeout
  // returns the topology the first attempt made rather than a second one. The
  // caller owns the key because only it knows which attempts are the same save.
  createTopology: (name, document, idempotencyKey) =>
    request("/topologies", {
      method: "POST",
      headers: idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {},
      body: JSON.stringify({ name, document }),
    }),
  getTopology: (id) => request(`/topologies/${id}`),
  saveTopology: (id, document, version, extra = {}) =>
    request(`/topologies/${id}`, {
      method: "PUT",
      body: JSON.stringify({ document, version, ...extra }),
    }),
  duplicateTopology: (id) =>
    request(`/topologies/${id}/duplicate`, { method: "POST" }),
  deleteTopology: (id) => request(`/topologies/${id}`, { method: "DELETE" }),

  // Blueprints are starter topologies. A clone is a private copy owned by the
  // caller; publish and unpublish flag one of the caller's own topologies so a team
  // can reuse it. See 0025.
  listBlueprints: () => request("/blueprints"),
  cloneBlueprint: (id) =>
    request(`/blueprints/${id}/clone`, { method: "POST" }),
  publishBlueprint: (id) =>
    request(`/topologies/${id}/publish`, { method: "POST" }),
  unpublishBlueprint: (id) =>
    request(`/topologies/${id}/unpublish`, { method: "POST" }),

  validate: (document, provider) =>
    request("/validate", {
      method: "POST",
      body: JSON.stringify({ document, provider: provider || "gcp" }),
    }),
  // Everything compiles natively to a redStackPRO terraform + ansible working
  // directory, offense and defense alike. A defense range currently targets aws;
  // the backend says so for the clouds without a native range backend yet.
  compile: (document, provider) =>
    request("/compile", {
      method: "POST",
      body: JSON.stringify({ document, provider: provider || "gcp" }),
    }),
  archiveUrl: (compileId) => `${BASE}/compile/${compileId}/archive`,
};
