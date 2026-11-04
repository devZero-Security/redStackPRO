// The app shell's input and copy fixes, pure and rendered: what the palette
// seeds, what it offers, and what the header and export panel tell a person.

import React from "react";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, test, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import App from "./App.jsx";
import {
  addNode, cleanPrefix, emptyDocument, offSchemeIds, paletteGroups, PALETTE_HIDDEN,
} from "./topology.js";
import { HOST_PRESETS } from "./presets.js";
import { VULN_CATALOG } from "./vulns.js";
import { EXTENSIONS } from "./extensions.js";
import { TEMPLATES } from "./templates.js";
import { ExportPanel } from "./Export.jsx";
import { PLATFORMS, PROVIDER_SETUP } from "./deployTarget.js";

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


describe("extensions", () => {
  test("ws01 promises no hardening its seed does not set", () => {
    const ws01 = EXTENSIONS.find((e) => e.key === "ws01");
    const overlay = ws01.boxes[0].overlay;
    expect(overlay.hardening).toBeUndefined();
    const vulns = overlay.vulns || [];
    const words = `${ws01.title} ${ws01.blurb} ${overlay.notes || ""}`;
    if (!vulns.includes("run_as_ppl")) expect(words).not.toMatch(/RunAsPPL|PPL/i);
    expect(words).not.toMatch(/ASR|constrained PowerShell|hardened/i);
    // Defender is off on a range host unless defender_enabled is set, and the
    // blurb has to say which of the two this box gets.
    if (!overlay.defender_enabled) expect(ws01.blurb).toMatch(/Defender is turned off/);
  });
});


describe("blueprint picker text", () => {
  test("any blueprint that mentions poisoning says it plants on Proxmox and ESXi only", () => {
    for (const t of Object.values(TEMPLATES).flat()) {
      const words = `${t.blurb} ${t.teaches || ""}`;
      if (/poison/i.test(words)) {
        expect(words, t.name).toMatch(/Proxmox and ESXi/);
      }
    }
  });
});


describe("export panel", () => {
  const COMPILED = {
    compile_id: "c1",
    files: [
      { path: "terraform/firewall.tf", contents: "# firewall\n" },
      { path: "terraform/main.tf", contents: "# main\n" },
      { path: "deploy.tfvars", contents: 'project = ""\n' },
    ],
  };
  const DOC = { ...emptyDocument("offense"), nodes: [{ id: "net01", kind: "network", overlay: {} }] };

  function compileBackend() {
    global.fetch = vi.fn(async (url) =>
      url.endsWith("/compile") ? respond(200, COMPILED) : respond(404, {}));
  }

  test("deploy.tfvars opens first, not firewall.tf", async () => {
    compileBackend();
    render(<ExportPanel document={DOC} provider="gcp" />);
    const head = await waitFor(() => {
      const el = window.document.querySelector(".rg-code-head");
      expect(el?.textContent).toBe("deploy.tfvars");
      return el;
    });
    expect(head).toBeTruthy();
  });

  test.each([
    ["gcp", ["project", "region", "zone", "operator_source_ranges"],
      ["gcloud auth application-default login"]],
    ["aws", ["region", "operator_source_ranges"], ["aws configure", "aws sso login"]],
    ["azure", ["subscription_id", "location", "resource_group", "operator_source_ranges"],
      ["az login"]],
  ])("%s: step 2 names the tfvars fields and step 3 the login command",
    async (provider, fields, logins) => {
      compileBackend();
      render(<ExportPanel document={DOC} provider={provider} />);
      const steps = await waitFor(() => {
        const el = window.document.querySelector(".rg-export-steps");
        expect(el).toBeTruthy();
        return el;
      });
      const items = steps.querySelectorAll(":scope > li");
      const fieldStep = items[1];
      for (const field of fields) {
        expect(within(fieldStep).getByText(field).tagName).toBe("CODE");
      }
      expect(fieldStep.textContent).toMatch(
        /ssh_public_key can stay empty; deploy fills it from keys\/\./);
      const commands = [...items[2].querySelectorAll("code.rg-cmd")].map((c) => c.textContent);
      for (const login of logins) expect(commands).toContain(login);
    });

  test("the field lists match the variables each provider's Terraform declares", () => {
    const tf = (name) => readFileSync(
      join(HERE, `../../src/redstackpro/terraform/${name}.py`), "utf8");
    for (const [provider, setup] of Object.entries(PROVIDER_SETUP)) {
      const source = tf(provider);
      for (const field of setup.fields) {
        const declared = source.includes(`variable "${field}"`)
          || source.split(/\r?\n/).some((line) => line.startsWith(`${field} `));
        expect(declared, `${provider}: ${field}`).toBe(true);
      }
    }
  });

  test("Python 3.8 is the stated minimum on every platform", () => {
    for (const p of Object.values(PLATFORMS)) {
      expect(p.note).toMatch(/Python 3\.8 or newer/);
      expect(p.note).not.toMatch(/3\.11/);
    }
  });
});


describe("header inputs", () => {
  test("cleanPrefix keeps only what the schema pattern accepts", () => {
    expect(cleanPrefix("ACME")).toBe("acme");
    expect(cleanPrefix("R_T-9x")).toBe("rt9x");
    expect(cleanPrefix("1off")).toBe("off");
    expect(cleanPrefix("redteamops")).toBe("redteamo");
    expect(cleanPrefix("")).toBe("");
    for (const raw of ["Off", "a.b.c", "99zz", "x".repeat(20), "ok1"]) {
      const out = cleanPrefix(raw);
      if (out) expect(out).toMatch(/^[a-z][a-z0-9]{0,7}$/);
    }
  });

  test("the prefix field lowercases, strips and caps what is typed, and says why",
    async () => {
      fakeBackend();
      const user = userEvent.setup();
      render(<App />);
      const prefix = await screen.findByRole("textbox", { name: "Prefix" });
      expect(prefix.maxLength).toBe(8);
      expect(prefix.title).toMatch(
        /1 to 8 lowercase letters or digits, starting with a letter\. Prefix plus each host id must fit in 15 characters, so 3 to 4 letters is best \(off, acme\)\./);

      await user.clear(prefix);
      await user.type(prefix, "9R_t-Ops");
      expect(prefix.value).toBe("rtops");

      await user.clear(prefix);
      await user.type(prefix, "abcdefghijk");
      expect(prefix.value).toBe("abcdefgh");
    });

  test("an emptied prefix goes back to what it was on blur", async () => {
    fakeBackend();
    const user = userEvent.setup();
    render(<App />);
    const prefix = await screen.findByRole("textbox", { name: "Prefix" });
    await user.clear(prefix);
    expect(prefix.value).toBe("");
    await user.tab();
    await waitFor(() => expect(prefix.value).toBe("off"));
  });

  test("the name field explains itself and an emptied name reverts on blur", async () => {
    fakeBackend();
    const user = userEvent.setup();
    render(<App />);
    const name = await screen.findByLabelText("Topology name");
    expect(name.placeholder).toBe("Topology name");
    expect(name.title).toBe("Becomes the download file name and the guide title.");

    await user.clear(name);
    await user.type(name, "Range one");
    await user.tab();
    expect(name.value).toBe("Range one");

    await user.clear(name);
    await user.tab();
    await waitFor(() => expect(name.value).toBe("Range one"));
    // The revert folds into the typing step, so the canvas is back where it was.
    expect(screen.getByText("Unsaved changes")).toBeTruthy();
  });

  test("the inactive mode says switching starts an empty topology", async () => {
    fakeBackend();
    render(<App />);
    const defense = await screen.findByRole("tab", { name: "Defense" });
    expect(defense.title).toMatch(
      /Switching starts a new empty topology; saved work stays in the picker\./);
    const offense = screen.getByRole("tab", { name: "Offense" });
    expect(offense.title).not.toMatch(/Switching/);
  });

  test("the empty canvas points at the blueprints", async () => {
    fakeBackend();
    render(<App />);
    expect(await screen.findByText("Or pick a blueprint from the top of the palette.")).toBeTruthy();
  });
});


describe("loading a shipped blueprint", () => {
  const shipped = (file) =>
    JSON.parse(readFileSync(join(HERE, "../public", file), "utf8"));

  test("offSchemeIds names the ids retitle would have renamed", () => {
    expect(offSchemeIds(shipped("redstack.json"))).toEqual(["ops-sub01"]);
    expect(offSchemeIds(emptyDocument("offense"))).toEqual([]);
  });

  async function loadFromPicker(user, name) {
    await user.click(await screen.findByRole("button", { name: "Load blueprint" }));
    const dialog = await screen.findByRole("dialog", { name: "Load a blueprint" });
    await user.click(within(dialog).getByText(name).closest("button"));
  }

  test("redStack loads clean, with the ids its guide uses", async () => {
    fakeBackend();
    const user = userEvent.setup();
    render(<App />);
    await loadFromPicker(user, "redStack");

    expect(await screen.findByText("off-ops-sub01")).toBeTruthy();
    expect(screen.queryByText("off-mgmt-sub02")).toBeNull();
    expect(screen.getByText("Not saved")).toBeTruthy();
    expect(screen.queryByText("Unsaved changes")).toBeNull();
    expect(screen.getByRole("button", { name: "Undo" }).disabled).toBe(true);
  });

  test("an edit after the load still leaves the shipped ids alone", async () => {
    fakeBackend();
    const user = userEvent.setup();
    render(<App />);
    await loadFromPicker(user, "redStack");
    await screen.findByText("off-ops-sub01");

    await user.type(screen.getByLabelText("Topology name"), "!");
    expect(await screen.findByText("Unsaved changes")).toBeTruthy();
    expect(screen.getByText("off-ops-sub01")).toBeTruthy();
    expect(screen.queryByText("off-mgmt-sub02")).toBeNull();
  });

  test("every shipped offense blueprint loads without renaming a node", async () => {
    for (const file of ["minimalc2-cli", "minimalc2-gui", "rollover", "split-horizon"]) {
      const doc = shipped(`${file}.json`);
      expect(offSchemeIds(doc).length, file).toBeGreaterThan(0);
    }
    fakeBackend();
    const user = userEvent.setup();
    render(<App />);
    await loadFromPicker(user, "Split horizon C2");
    const doc = shipped("split-horizon.json");
    for (const id of offSchemeIds(doc)) {
      expect(await screen.findByText(`${doc.prefix}-${id}`), id).toBeTruthy();
    }
    expect(screen.getByText("Not saved")).toBeTruthy();
  });

  test("a saved topology carrying off-scheme ids opens clean", async () => {
    const doc = shipped("redstack.json");
    openUrl("?topology=g5");
    fakeBackend({ documents: { g5: doc } });
    render(<App />);
    expect(await screen.findByText("off-ops-sub01")).toBeTruthy();
    expect(screen.getByText(/Saved, version 1/)).toBeTruthy();
  });
});


describe("host card", () => {
  test("recorded hardening does not badge the host as hardened", async () => {
    const doc = {
      schema_version: "0.7.0", mode: "defense", name: "Range", prefix: "def",
      nodes: [{
        id: "ws01", kind: "wks", position: { x: 0, y: 0 },
        overlay: { os: "windows_10", hardening: ["asr", "runasppl"] },
      }],
      edges: [],
    };
    openUrl("?topology=g8");
    fakeBackend({ documents: { g8: doc } });
    render(<App />);
    expect(await screen.findByText("ws01")).toBeTruthy();
    const badge = screen.getByText("hardening off");
    expect(badge.title).toMatch(/does not apply them/);
    expect(screen.queryByText(/\d hardened/)).toBeNull();
  });
});
