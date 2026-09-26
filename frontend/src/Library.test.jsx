// The library, rendered.
//
// The backend runs ahead of the canvas here: blueprints, delete, and paging all
// have endpoints and api.js bindings, and none of them had a way in until the
// library. These tests drive the modal against a backend that actually mutates,
// so a delete that reloads a stale list, or a publish that does not move the
// topology, shows up as a failing assertion rather than a manual browser pass.

import React from "react";
import { describe, expect, test, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import App from "./App.jsx";

const PALETTE = {
  topology: [
    { kind: "network", abbrev: "network", category: "container", label: "Network", color: "#868e96" },
  ],
  operational: [
    { kind: "teamserver", abbrev: "ts", category: "host", label: "Teamserver", color: "#e03131" },
  ],
};

const DOC = {
  schema_version: "0.2.0",
  mode: "artie",
  name: "Cloned",
  prefix: "art",
  nodes: [{ id: "myth-ts01", kind: "teamserver", overlay: { c2: "mythic" },
    position: { x: 10, y: 10 } }],
  edges: [],
};

const summary = (over) => ({
  id: "g", name: "Topology", mode: "artie", visibility: "private",
  schema_version: "0.2.0", version: 1, owner_id: "u1",
  is_blueprint: false, editable: true, ...over,
});

function respond(status, body, contentType = "application/json") {
  return {
    ok: status < 400,
    status,
    headers: { get: () => (status === 204 ? null : contentType) },
    json: async () => body,
  };
}

// A backend with real state, so a delete or a publish changes what the next
// listing returns. `topologies` is newest first; blueprints carry a system starter
// that nobody owns plus whatever gets published.
function libraryBackend({ topologyCount = 3 } = {}) {
  const calls = [];
  let topologies = Array.from({ length: topologyCount }, (_, i) =>
    summary({ id: `g${i}`, name: `Topology ${i}` }));
  let blueprints = [
    summary({ id: "bp-sys", name: "redStack starter", owner_id: null,
      is_blueprint: true, editable: false }),
  ];
  let nextClone = 100;

  global.fetch = vi.fn(async (url, options = {}) => {
    const method = options.method || "GET";
    const body = options.body ? JSON.parse(options.body) : null;
    calls.push({ url, method, body });

    if (url.includes("/registry/palette")) return respond(200, { groups: PALETTE });
    if (url.includes("/registry/schema")) return respond(200, { $defs: {} });
    if (url.includes("/registry/providers")) {
      return respond(200, { providers: [{ name: "gcp" }, { name: "aws" }] });
    }
    if (url.endsWith("/validate")) {
      return respond(200, { valid: true, errors: 0, warnings: 0, findings: [] });
    }

    if (url.includes("/topologies?") && method === "GET") {
      const params = new URLSearchParams(url.split("?")[1]);
      const limit = Number(params.get("limit"));
      const offset = Number(params.get("offset"));
      return respond(200, topologies.slice(offset, offset + limit));
    }
    if (url.endsWith("/blueprints") && method === "GET") {
      return respond(200, blueprints);
    }

    let match = url.match(/\/blueprints\/([^/?]+)\/clone$/);
    if (match && method === "POST") {
      const clone = summary({ id: `c${nextClone++}`, name: "redStack starter (copy)" });
      topologies = [clone, ...topologies];
      return respond(201, clone);
    }

    match = url.match(/\/topologies\/([^/?]+)\/publish$/);
    if (match && method === "POST") {
      const g = topologies.find((x) => x.id === match[1]);
      topologies = topologies.filter((x) => x.id !== match[1]);
      const published = { ...g, is_blueprint: true };
      blueprints = [...blueprints, published];
      return respond(200, published);
    }
    match = url.match(/\/topologies\/([^/?]+)\/unpublish$/);
    if (match && method === "POST") {
      const bp = blueprints.find((x) => x.id === match[1]);
      blueprints = blueprints.filter((x) => x.id !== match[1]);
      const restored = { ...bp, is_blueprint: false };
      topologies = [restored, ...topologies];
      return respond(200, restored);
    }

    match = url.match(/\/topologies\/([^/?]+)$/);
    if (match && method === "DELETE") {
      topologies = topologies.filter((x) => x.id !== match[1]);
      return respond(204, null);
    }
    if (match && method === "GET") {
      return respond(200, { topology: summary({ id: match[1], name: "Cloned" }), document: DOC });
    }

    return respond(404, { code: "not_found", message: "no route: " + url });
  });

  return { calls, snapshot: () => ({ topologies, blueprints }) };
}

const openLibrary = async (user) => {
  await screen.findByRole("button", { name: "Library" });
  await user.click(screen.getByRole("button", { name: "Library" }));
  return screen.findByRole("dialog", { name: "Library" });
};

beforeEach(() => {
  window.history.replaceState({}, "", "/");
  window.confirm = () => true;
});


describe("browsing", () => {
  test("the library lists your topologies and the blueprint starters", async () => {
    libraryBackend();
    const user = userEvent.setup();
    render(<App />);

    const dialog = await openLibrary(user);
    expect(await within(dialog).findByText("Topology 0")).toBeTruthy();
    expect(within(dialog).getByText("redStack starter")).toBeTruthy();
    expect(within(dialog).getByText("system starter")).toBeTruthy();
  });

  test("cloning a blueprint opens the new private copy and closes the library",
    async () => {
      const backend = libraryBackend();
      const user = userEvent.setup();
      render(<App />);

      const dialog = await openLibrary(user);
      await within(dialog).findByText("redStack starter");
      await user.click(within(dialog).getByRole("button", { name: "Use this" }));

      // The clone POST happened, the canvas is on the cloned document, and the
      // URL names it so a reload comes back to it.
      await waitFor(() =>
        expect(backend.calls.some((c) => c.url.includes("/clone"))).toBe(true));
      expect(await screen.findByText("art-myth-ts01")).toBeTruthy();
      await waitFor(() => expect(window.location.search).toMatch(/topology=c\d+/));
      expect(screen.queryByRole("dialog", { name: "Library" })).toBeNull();
    });
});


describe("managing", () => {
  test("deleting a topology removes it from the list", async () => {
    libraryBackend();
    const user = userEvent.setup();
    render(<App />);

    const dialog = await openLibrary(user);
    await within(dialog).findByText("Topology 1");

    const row = within(dialog).getByText("Topology 1").closest("li");
    await user.click(within(row).getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(within(dialog).queryByText("Topology 1")).toBeNull());
    // The others are untouched.
    expect(within(dialog).getByText("Topology 0")).toBeTruthy();
  });

  test("a declined delete leaves the topology alone", async () => {
    window.confirm = () => false;
    const backend = libraryBackend();
    const user = userEvent.setup();
    render(<App />);

    const dialog = await openLibrary(user);
    const row = (await within(dialog).findByText("Topology 1")).closest("li");
    await user.click(within(row).getByRole("button", { name: "Delete" }));

    // No DELETE was sent and the row is still there.
    await waitFor(() => expect(within(dialog).getByText("Topology 1")).toBeTruthy());
    expect(backend.calls.some((c) => c.method === "DELETE")).toBe(false);
  });

  test("publishing moves a topology out of your list and into the blueprints",
    async () => {
      libraryBackend();
      const user = userEvent.setup();
      render(<App />);

      const dialog = await openLibrary(user);
      const yours = within(dialog)
        .getByRole("heading", { name: "Your topologies" }).closest("section");
      const prints = within(dialog)
        .getByRole("heading", { name: "Blueprints" }).closest("section");

      const row = (await within(yours).findByText("Topology 0")).closest("li");
      await user.click(within(row).getByRole("button", { name: "Publish" }));

      // Gone from your topologies, now a blueprint you own and can unpublish.
      await waitFor(() =>
        expect(within(yours).queryByText("Topology 0")).toBeNull());
      expect(within(prints).getByText("Topology 0")).toBeTruthy();
      expect(within(prints).getByRole("button", { name: "Unpublish" })).toBeTruthy();
    });
});


describe("paging", () => {
  test("load more fetches the next page and appends it", async () => {
    // Two full pages then a short one, so the button shows until the list is dry.
    libraryBackend({ topologyCount: 30 });
    const user = userEvent.setup();
    render(<App />);

    const dialog = await openLibrary(user);
    await within(dialog).findByText("Topology 0");
    // Page size is 25, so the 26th topology is not there yet.
    expect(within(dialog).queryByText("Topology 25")).toBeNull();

    await user.click(within(dialog).getByRole("button", { name: "Load more" }));

    expect(await within(dialog).findByText("Topology 25")).toBeTruthy();
    expect(within(dialog).getByText("Topology 29")).toBeTruthy();
    // The page came back short, so there is no more to load.
    await waitFor(() =>
      expect(within(dialog).queryByRole("button", { name: "Load more" })).toBeNull());
  });
});
