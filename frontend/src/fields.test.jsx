// The Inspector's generic field layer: how a schema property turns into a
// control. Rendered against the real 0.7.0 schema where the behavior depends on
// it, and against small synthetic schemas where it should not.

import React, { useState } from "react";
import { describe, expect, test } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import SCHEMA from "../../src/redstackpro/schema/topology/0.7.0.json";
import { Inspector } from "./Inspector.jsx";
import { jsonKindFor, resolveSpec } from "./fieldRules.js";

// Renders one node in the Inspector over a local document, the way App wires
// onOverlayChange. `seen` collects every overlay the panel writes.
function Panel({ node, mode = "defense", schema = SCHEMA, findings = [], seen, extraNodes = [] }) {
  const [document, setDocument] = useState({
    schema_version: "0.7.0",
    mode,
    prefix: "t",
    nodes: [node, ...extraNodes],
    edges: [],
  });
  return (
    <Inspector
      schema={schema}
      selection={{ type: "node", id: node.id }}
      document={document}
      findings={findings}
      onOverlayChange={(id, overlay) => {
        seen?.push(overlay);
        setDocument((d) => ({
          ...d,
          nodes: d.nodes.map((n) => (n.id === id ? { ...n, overlay } : n)),
        }));
      }}
      onRename={() => {}}
      onDelete={() => {}}
      kindLabels={{}}
    />
  );
}

const fieldOf = (el) => el.closest(".rg-field");

describe("$ref resolution", () => {
  test("resolveSpec merges the property's own keys over the def", () => {
    const defs = { port: { type: "integer", minimum: 1, maximum: 65535, description: "def help" } };
    const out = resolveSpec({ $ref: "#/$defs/port", default: 5044, title: "Ingest port" }, defs);
    expect(out).toMatchObject({ type: "integer", minimum: 1, maximum: 65535, default: 5044, title: "Ingest port" });
    expect(out.$ref).toBeUndefined();
    expect(resolveSpec({ $ref: "#/$defs/port", description: "own help" }, defs).description).toBe("own help");
    // An unknown def leaves the spec alone.
    expect(resolveSpec({ $ref: "#/$defs/nope" }, defs)).toEqual({ $ref: "#/$defs/nope" });
  });

  test("public_address on a range host is a checkbox with the def's help", () => {
    render(<Panel node={{ id: "dc01", kind: "dc", overlay: { os: "windows_server_2022" } }} />);
    const box = screen.getByRole("checkbox", { name: /public_address|public address/i });
    expect(box.checked).toBe(false);
    expect(within(fieldOf(box)).getByText(/Whether this host holds a public address/)).toBeTruthy();
  });

  test("a port is a number input showing its default", () => {
    render(
      <Panel
        mode="offense"
        node={{ id: "log01", kind: "collector", overlay: { sink: "opensearch" } }}
      />
    );
    const input = screen.getByRole("spinbutton", { name: /ingest_port|ingest port/i });
    expect(input.getAttribute("placeholder")).toBe("5044");
  });
});

describe("structured values never render as a text box", () => {
  const OBJ_SCHEMA = {
    $defs: {
      overlay_range_host: {
        properties: {
          things: { type: "array", "x-redstackpro-source": "user", items: { type: "object", properties: { name: { type: "string" } } } },
          nesting: { type: "object", "x-redstackpro-source": "user", additionalProperties: { type: "array", items: { type: "string" } } },
          tags: { type: "array", "x-redstackpro-source": "user", items: { type: "string" } },
        },
      },
    },
  };

  test("jsonKindFor picks a JSON editor for objects and lists of objects", () => {
    expect(jsonKindFor({ type: "object", additionalProperties: true })).toBe("object");
    expect(jsonKindFor({ type: "array", items: { type: "object" } })).toBe("array");
    expect(jsonKindFor({ type: "array", items: { type: "string" } }, ["a"])).toBeNull();
    expect(jsonKindFor({ type: "array", items: { type: "string" } }, [{ a: 1 }])).toBe("array");
    expect(jsonKindFor({ type: "string" }, { a: 1 })).toBe("object");
    expect(jsonKindFor({ type: "string" }, "x")).toBeNull();
  });

  test("a list of objects shows as JSON and saves a list", () => {
    const seen = [];
    render(
      <Panel
        schema={OBJ_SCHEMA}
        seen={seen}
        node={{ id: "srv01", kind: "srv", overlay: { things: [{ name: "gmsa01" }] } }}
      />
    );
    const box = screen.getByRole("textbox", { name: "things" });
    expect(box.value).not.toContain("[object Object]");
    expect(JSON.parse(box.value)).toEqual([{ name: "gmsa01" }]);

    fireEvent.change(box, { target: { value: '{"name": "x"}' } });
    expect(seen).toHaveLength(0);
    expect(screen.getByText("Must be a JSON list, [...]. The last valid value is kept.")).toBeTruthy();

    fireEvent.change(box, { target: { value: '[{"name": "x"}]' } });
    expect(seen.at(-1).things).toEqual([{ name: "x" }]);
  });

  test("an object with free keys shows as JSON", () => {
    render(
      <Panel
        schema={OBJ_SCHEMA}
        node={{ id: "srv01", kind: "srv", overlay: { nesting: { "Domain Admins": ["QueenProtector"] } } }}
      />
    );
    const box = screen.getByRole("textbox", { name: "nesting" });
    expect(JSON.parse(box.value)).toEqual({ "Domain Admins": ["QueenProtector"] });
  });

  test("a string list keeps a typed comma, so a second entry can be typed", async () => {
    const user = userEvent.setup();
    const seen = [];
    render(<Panel schema={OBJ_SCHEMA} seen={seen} node={{ id: "srv01", kind: "srv", overlay: {} }} />);
    const input = screen.getByRole("textbox", { name: "tags" });
    await user.type(input, "LinuxAdmins, Ops");
    expect(input.value).toBe("LinuxAdmins, Ops");
    expect(seen.at(-1).tags).toEqual(["LinuxAdmins", "Ops"]);
  });
});

// The control under a field label. The label's first text node is the title,
// so a "required" badge does not get in the way.
function fieldNamed(title) {
  const label = screen.getAllByText(
    (_, el) => el?.classList?.contains("rg-field-label") && el.firstChild?.textContent === title
  )[0];
  return label.closest(".rg-field");
}
const selectNamed = (title) => fieldNamed(title).querySelector("select");
const inputNamed = (title) => fieldNamed(title).querySelector("input");
const optionTexts = (select) => [...select.options].map((o) => o.textContent);

// The real schema with titles added, to check a label follows spec.title.
function withTitles(titles) {
  const copy = structuredClone(SCHEMA);
  for (const [path, title] of Object.entries(titles)) {
    const [def, ...props] = path.split(".");
    let at = copy.$defs[def];
    for (const p of props) at = at.properties[p];
    at.title = title;
  }
  return copy;
}

describe("labels", () => {
  test("a field is labelled by spec.title, or its key without one", () => {
    const titled = withTitles({ "overlay_range_host.os": "Operating system" });
    const { unmount } = render(<Panel schema={titled} node={{ id: "dc01", kind: "dc", overlay: {} }} />);
    expect(selectNamed("Operating system")).toBeTruthy();
    unmount();
    render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
    expect(selectNamed("os")).toBeTruthy();
  });

  test("a fieldset legend uses spec.title", () => {
    const titled = withTitles({ "overlay_redirector.tls": "TLS certificate" });
    render(
      <Panel
        mode="offense"
        schema={titled}
        node={{ id: "cdn-rdr01", kind: "redirector", overlay: { server: "nginx", tls: {} } }}
      />
    );
    expect(screen.getByText("TLS certificate", { selector: "legend" })).toBeTruthy();
  });

  test("enum options read as words while the stored value stays the id", async () => {
    const user = userEvent.setup();
    const seen = [];
    render(<Panel seen={seen} node={{ id: "dc01", kind: "dc", overlay: {} }} />);
    const os = selectNamed("os");
    expect(optionTexts(os)).toContain("Windows Server 2019");
    expect(optionTexts(os)).toContain("Windows 10 (Server 2022 on GCP/AWS)");
    expect(optionTexts(os)).toContain("Windows 11 (Server 2022 on GCP/AWS)");
    expect(optionTexts(os)).not.toContain("windows_server_2019");
    await user.selectOptions(os, "Windows Server 2019");
    expect(seen.at(-1).os).toBe("windows_server_2019");
  });

  test("cert_source options are Let's Encrypt and Self-signed", () => {
    render(
      <Panel
        mode="offense"
        node={{ id: "cdn-rdr01", kind: "redirector", overlay: { server: "nginx", tls: {} } }}
      />
    );
    const texts = optionTexts(selectNamed("cert_source"));
    expect(texts).toContain("Let's Encrypt");
    expect(texts).toContain("Self-signed");
  });
});

describe("the empty option names the default", () => {
  test("a dc, srv or wks with no os says Windows Server 2022, never unset", () => {
    for (const kind of ["dc", "srv", "wks"]) {
      const { unmount } = render(<Panel node={{ id: `${kind}01`, kind, overlay: {} }} />);
      const os = selectNamed("os");
      expect(os.value).toBe("");
      expect(os.options[os.selectedIndex].textContent).toBe("default (Windows Server 2022)");
      expect(screen.queryByText("unset")).toBeNull();
      unmount();
    }
  });

  test("schema and known defaults label the empty option", () => {
    render(
      <Panel
        mode="offense"
        node={{ id: "cdn-rdr01", kind: "redirector", overlay: { server: "nginx", tls: {}, gating: {} } }}
      />
    );
    expect(optionTexts(selectNamed("cert_source"))[0]).toBe("default (Let's Encrypt)");
    expect(optionTexts(selectNamed("decoy"))[0]).toBe("default (CDN)");
  });

  test("a jumpbox's access mode and vpn protocol name theirs", () => {
    render(
      <Panel
        mode="offense"
        node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"], access_mode: "openvpn" } }}
      />
    );
    expect(optionTexts(selectNamed("access_mode"))[0]).toBe("default (Public portal)");
    expect(optionTexts(selectNamed("vpn_protocol"))[0]).toBe("default (UDP)");
    expect(inputNamed("vpn_port").getAttribute("placeholder")).toBe("1194");
  });

  test("a required enum offers no empty option", () => {
    render(<Panel mode="offense" node={{ id: "myth-ts01", kind: "teamserver", overlay: { c2: "mythic" } }} />);
    const c2 = selectNamed("c2");
    expect(optionTexts(c2)).toEqual(["Mythic", "Sliver", "AdaptixC2", "None (plain Debian host)"]);
  });

  test("a required enum with nothing stored asks for a pick rather than showing one", () => {
    render(<Panel mode="offense" node={{ id: "myth-ts01", kind: "teamserver", overlay: {} }} />);
    const c2 = selectNamed("c2");
    expect(c2.value).toBe("");
    expect(c2.options[c2.selectedIndex].textContent).toBe("pick one");
  });

  test("a stored value the list does not offer stays visible", () => {
    render(<Panel node={{ id: "wks01", kind: "wks", overlay: { os: "windows_7" } }} />);
    const os = selectNamed("os");
    expect(os.value).toBe("windows_7");
    expect(os.options[os.selectedIndex].textContent).toBe("Windows 7 (not a choice here)");
  });

  test("a dc hostname and a domain netbios show what the compiler fills in", () => {
    const { unmount } = render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
    expect(inputNamed("hostname").getAttribute("placeholder")).toBe("dc01 (default)");
    unmount();
    render(<Panel node={{ id: "sk-dom01", kind: "domain", overlay: { fqdn: "sevenkingdoms.local" } }} />);
    expect(inputNamed("netbios").getAttribute("placeholder")).toBe("SEVENKINGDOMS (default)");
  });

  test("a pattern field shows an example, never the raw pattern", () => {
    render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
    const ip = inputNamed("internal_ip");
    expect(ip.getAttribute("placeholder")).toBe("e.g. 10.30.10.5");
  });
});
