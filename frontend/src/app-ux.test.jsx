// The app shell's input and copy fixes, pure and rendered: what the palette
// seeds, what it offers, and what the header and export panel tell a person.

import React from "react";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, test, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";

import App from "./App.jsx";
import { addNode, emptyDocument, paletteGroups, PALETTE_HIDDEN } from "./topology.js";
import { HOST_PRESETS } from "./presets.js";
import { VULN_CATALOG } from "./vulns.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const PALETTES = {
  offense: {
    topology: [
      { kind: "network", abbrev: "network", category: "container", label: "Network", color: "#868e96" },
      { kind: "segment", abbrev: "subnet", category: "container", label: "Segment", color: "#868e96" },
    ],
    management: [
      { kind: "jumpbox", abbrev: "bx", category: "host", label: "Jumpbox", color: "#868e96" },
    ],
  },
  defense: {
    topology: [
      { kind: "network", abbrev: "network", category: "container", label: "Network", color: "#868e96" },
      { kind: "segment", abbrev: "subnet", category: "container", label: "Segment", color: "#868e96" },
    ],
    hosts: [
      { kind: "dc", abbrev: "dc", category: "host", label: "Domain controller", color: "#1971c2" },
      { kind: "appliance", abbrev: "appl", category: "host", label: "Appliance", color: "#868e96" },
    ],
    network: [
      { kind: "fw", abbrev: "fw", category: "host", label: "Firewall", color: "#3b5bdb" },
    ],
  },
};

function respond(status, body) {
  return {
    ok: status < 400,
    status,
    headers: { get: () => "application/json" },
    json: async () => body,
  };
}

const SUMMARY = {
  id: "g1", name: "Saved", mode: "offense", visibility: "private",
  schema_version: "0.7.0", version: 1, owner_id: "u1",
  is_blueprint: false, editable: true,
};

// A backend that serves the palettes, any saved documents, and the shipped
// blueprint files straight from public/.
function fakeBackend({ documents = {} } = {}) {
  const calls = [];
  global.fetch = vi.fn(async (url, options = {}) => {
    const method = options.method || "GET";
    calls.push({ url, method });
    if (url.includes("/registry/palette")) {
      const mode = /mode=(\w+)/.exec(url)?.[1] || "offense";
      return respond(200, { groups: PALETTES[mode] });
    }
    if (url.includes("/registry/schema")) return respond(200, { $defs: {} });
    if (url.includes("/registry/providers")) {
      return respond(200, { providers: [
        { name: "gcp", capabilities: ["windows_image"], maturity: "proven" },
      ] });
    }
    if (url.includes("/health")) return respond(200, { status: "ok", app_version: "9.9.9" });
    if (url.endsWith("/validate")) return respond(200, { findings: [] });
    if (url.includes("/topologies?") && method === "GET") return respond(200, []);
    const match = url.match(/\/topologies\/([^/?]+)$/);
    if (match && method === "GET" && documents[match[1]]) {
      return respond(200, {
        topology: { ...SUMMARY, id: match[1], mode: documents[match[1]].mode },
        document: documents[match[1]],
      });
    }
    if (url.endsWith(".json") && !url.includes("/api/")) {
      const file = join(HERE, "../public", url.replace(/^\//, ""));
      return respond(200, JSON.parse(readFileSync(file, "utf8")));
    }
    return respond(404, { code: "not_found", message: "no route: " + url });
  });
  return calls;
}

const openUrl = (search) => window.history.replaceState({}, "", "/" + (search || ""));

beforeEach(() => openUrl(""));


describe("palette seeds", () => {
  test("a dropped dc, srv or wks arrives as Windows Server 2022", () => {
    for (const kind of ["dc", "srv", "wks"]) {
      const doc = addNode(emptyDocument("defense"), { kind }, { x: 0, y: 0 });
      expect(doc.nodes[0].overlay.os, kind).toBe("windows_server_2022");
    }
  });

  test("a dropped jumpbox runs the Guacamole portal as well as ssh", () => {
    const doc = addNode(emptyDocument("offense"), { kind: "jumpbox" }, { x: 0, y: 0 });
    expect(doc.nodes[0].overlay.services).toEqual(["ssh", "guacamole"]);
  });

  test("the seed is a copy, so one node's edit never reaches the next", () => {
    const one = addNode(emptyDocument("defense"), { kind: "dc" }, { x: 0, y: 0 });
    one.nodes[0].overlay.os = "linux";
    const two = addNode(emptyDocument("defense"), { kind: "dc" }, { x: 0, y: 0 });
    expect(two.nodes[0].overlay.os).toBe("windows_server_2022");
  });
});


describe("palette offer", () => {
  test("Firewall and Appliance are not offered, and an emptied group goes", () => {
    const groups = paletteGroups(PALETTES.defense);
    const kinds = Object.values(groups).flat().map((e) => e.kind);
    expect(kinds).toContain("dc");
    for (const hidden of PALETTE_HIDDEN) expect(kinds).not.toContain(hidden);
    expect(groups.network).toBeUndefined();
  });

  test("a document that already has a fw and an appliance still opens and renders",
    async () => {
      const doc = {
        schema_version: "0.7.0", mode: "defense", name: "Old range", prefix: "def",
        nodes: [
          { id: "edge-fw01", kind: "fw", overlay: { os: "linux" }, position: { x: 0, y: 0 } },
          { id: "box-appl01", kind: "appliance", overlay: {}, position: { x: 300, y: 0 } },
        ],
        edges: [],
      };
      openUrl("?topology=g7");
      fakeBackend({ documents: { g7: doc } });
      render(<App />);

      expect(await screen.findByText("edge-fw01")).toBeTruthy();
      expect(screen.getByText("box-appl01")).toBeTruthy();
      const palette = window.document.querySelector(".rg-palette");
      await waitFor(() => expect(within(palette).getByText("Domain controller")).toBeTruthy());
      expect(within(palette).queryByText("Firewall")).toBeNull();
      expect(within(palette).queryByText("Appliance")).toBeNull();
    });
});


describe("presets", () => {
  test("the File Server preset plants a share through the Open share vuln", () => {
    const file = HOST_PRESETS.find((p) => p.key === "fileshare");
    expect(file.overlay.vulns).toContain("openshares");
    // smb in services installs nothing, so it is not seeded.
    expect(file.overlay.services || []).not.toContain("smb");
    const ids = VULN_CATALOG.flatMap((g) => g.items.map((i) => i.id));
    expect(ids).toContain("openshares");
    expect(file.blurb).not.toMatch(/NFS/);
  });

  test("the openshares role the preset relies on exists", () => {
    const task = join(HERE,
      "../../src/redstackpro/assets/ansible/roles/redstackpro.host_vulns/tasks/openshares.yml");
    expect(readFileSync(task, "utf8")).toMatch(/win_share/);
  });
});
