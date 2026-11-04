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
