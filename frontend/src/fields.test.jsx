// The Inspector's generic field layer: how a schema property turns into a
// control. Rendered against the real 0.7.0 schema where the behavior depends on
// it, and against small synthetic schemas where it should not.
//
// The real schema titles every property. Every rendered test runs twice: once
// with those titles, and once with every title stripped, where a label falls
// back to the property key.

import React, { useState } from "react";
import { beforeEach, describe, expect, test } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import SCHEMA from "../../src/redstackpro/schema/topology/0.7.0.json";
import GOAD from "../public/goad/goad.json";
import NHA from "../public/goad/nha.json";
import SCCM from "../public/goad/sccm.json";
import { Inspector } from "./Inspector.jsx";
import {
  RANGE_SERVICES, checkValue, fieldRule, jsonKindFor, patternInfo, resolveSpec, serviceChip,
  servicesActedOn,
} from "./fieldRules.js";

function stripTitles(node) {
  if (Array.isArray(node)) return node.map(stripTitles);
  if (!node || typeof node !== "object") return node;
  return Object.fromEntries(
    Object.entries(node).filter(([k]) => k !== "title").map(([k, v]) => [k, stripTitles(v)])
  );
}
const UNTITLED = stripTitles(SCHEMA);
const MODES = [["titled", SCHEMA], ["untitled", UNTITLED]];

// The schema the rendered tests in the current block use.
let ACTIVE = SCHEMA;

// The label a field shows under ACTIVE: its title (its own, else its $ref
// def's), or its key. `path` names the overlay def and the property, e.g.
// "redirector.tls.cert_source"; range hosts share "range_host".
function labelOf(path) {
  const [def, ...props] = path.split(".");
  let at = ACTIVE.$defs[`overlay_${def}`];
  let spec;
  for (const p of props) {
    spec = resolveSpec(at.properties[p], ACTIVE.$defs);
    at = spec;
  }
  return spec.title ?? props.at(-1);
}

// Renders one node in the Inspector over a local document, the way App wires
// onOverlayChange. `seen` collects every overlay the panel writes.
function Panel({ node, mode = "defense", schema = ACTIVE, findings = [], seen, extraNodes = [], placement = false }) {
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
      onJoinDomain={placement ? () => {} : undefined}
      onPlaceSubnet={placement ? () => {} : undefined}
    />
  );
}

const fieldOf = (el) => el.closest(".rg-field");

// A field by its label text. The label's first text node is the title, so a
// "required" badge does not get in the way.
const labelled = (text) =>
  screen.queryAllByText(
    (_, el) => el?.classList?.contains("rg-field-label") && el.firstChild?.textContent === text
  );
function fieldLabelled(text) {
  const found = labelled(text);
  if (!found.length) throw new Error(`no field labelled ${text}`);
  return found[0].closest(".rg-field");
}
const fieldNamed = (path) => fieldLabelled(labelOf(path));
const hasField = (path) => labelled(labelOf(path)).length > 0;
const selectNamed = (path) => fieldNamed(path).querySelector("select");
const inputNamed = (path) => fieldNamed(path).querySelector("input");
const checkboxNamed = (path) => fieldNamed(path).querySelector('input[type="checkbox"]');
const labelText = (field) => field.querySelector(".rg-field-label").firstChild.textContent;
const optionTexts = (select) => [...select.options].map((o) => o.textContent);
const errorsIn = (field) => [...field.querySelectorAll(".rg-field-error")].map((e) => e.textContent);

// ----------------------------------------------------------------- pure rules

describe("$ref resolution", () => {
  test("resolveSpec merges the property's own keys over the def", () => {
    const defs = { port: { type: "integer", minimum: 1, maximum: 65535, description: "def help", title: "Port" } };
    const out = resolveSpec({ $ref: "#/$defs/port", default: 5044, title: "Ingest port" }, defs);
    expect(out).toMatchObject({ type: "integer", minimum: 1, maximum: 65535, default: 5044, title: "Ingest port" });
    expect(out.$ref).toBeUndefined();
    expect(resolveSpec({ $ref: "#/$defs/port", description: "own help" }, defs)).toMatchObject({
      description: "own help",
      title: "Port",
    });
    // An unknown def leaves the spec alone.
    expect(resolveSpec({ $ref: "#/$defs/nope" }, defs)).toEqual({ $ref: "#/$defs/nope" });
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

describe("fieldRule", () => {
  test("hide only when empty or default; otherwise flag it ignored", () => {
    const ctx = { kind: "teamserver", mode: "offense", overlay: { c2: "sliver" } };
    expect(fieldRule("version", { type: "string" }, ctx, undefined).hide).toBe(true);
    expect(fieldRule("version", { type: "string" }, ctx, "v1.2").ignored).toMatch(/Sliver/);
    expect(fieldRule("version", { type: "string" }, { ...ctx, overlay: { c2: "mythic" } }, undefined).hide).toBeFalsy();
  });

  test("no context leaves the spec alone", () => {
    const spec = { enum: ["a"] };
    expect(fieldRule("os", spec, undefined, "a")).toEqual({ spec });
  });
});

// The same cases as validate._services_acted_on, so a chip reads dead exactly
// when SVC001 warns.
describe("services a host acts on", () => {
  const acted = (kind, overlay) => [...servicesActedOn({ kind, overlay })].sort();

  test("mirrors the validator", () => {
    expect(acted("srv", {})).toEqual(["exchange", "iis", "mssql"]);
    expect(acted("srv", { os: "debian_13" })).toEqual([]);
    expect(acted("srv", { role: "adcs" })).toEqual(["adcs", "exchange", "iis", "mssql"]);
    expect(acted("srv", { role: "mecm" })).toEqual(["exchange", "iis", "mecm", "mssql"]);
    expect(acted("dc", { role: "adcs" })).toEqual(["adcs"]);
    expect(acted("dc", { role: "adcs", os: "linux" })).toEqual([]);
    expect(acted("dc", { role: "mecm" })).toEqual([]);
    expect(acted("dc", {})).toEqual([]);
    expect(acted("wks", { role: "adcs" })).toEqual([]);
    expect(acted("fw", { role: "adcs" })).toEqual([]);
  });

  test("a chip is dead only when nothing installs the value, with SVC001's remedy", () => {
    expect(serviceChip({ kind: "dc", overlay: { role: "adcs" } }, "adcs")).toEqual({
      text: "adcs (installed by Role: AD CS)",
      title: "Role AD CS installs this.",
      dead: false,
    });
    expect(serviceChip({ kind: "srv", overlay: { role: "mecm" } }, "mecm").text).toBe(
      "mecm (installed by Role: MECM)"
    );
    const dead = serviceChip({ kind: "dc", overlay: {} }, "adcs");
    expect(dead.dead).toBe(true);
    expect(dead.title).toBe(
      "adcs installs nothing on this host. Set Role to AD CS on a Windows dc or srv to stand up the CA."
    );
    expect(serviceChip({ kind: "srv", overlay: { os: "linux" } }, "mssql").title).toMatch(
      /Put it on a Windows member server \(srv\)\.$/
    );
    expect(serviceChip({ kind: "srv", overlay: {} }, "smb").title).toMatch(/for a file share add the Open share vuln\.$/);
  });

  test("no services value in a shipped blueprint reads as dead", () => {
    for (const blueprint of [GOAD, NHA, SCCM]) {
      for (const node of blueprint.nodes) {
        if (!["dc", "srv", "wks", "fw", "appliance"].includes(node.kind)) continue;
        const ctx = { kind: node.kind, overlay: node.overlay || {} };
        for (const svc of node.overlay?.services || []) {
          const onChecklist = node.kind === "srv" && RANGE_SERVICES.includes(svc);
          expect([node.id, svc, onChecklist || !serviceChip(ctx, svc).dead]).toEqual([node.id, svc, true]);
        }
      }
    }
  });
});

describe("inline checks", () => {
  test("every pattern in the schema has a plain reason", () => {
    const patterns = new Set();
    const walk = (o) => {
      if (!o || typeof o !== "object") return;
      if (typeof o.pattern === "string") patterns.add(o.pattern);
      Object.values(o).forEach(walk);
    };
    walk(SCHEMA);
    expect(patterns.size).toBeGreaterThan(5);
    for (const p of patterns) expect([p, !!patternInfo(p)]).toEqual([p, true]);
  });

  test("checkValue reads plainly on the 0.7.0 address patterns", () => {
    const ip = resolveSpec({ $ref: "#/$defs/ipv4" }, SCHEMA.$defs);
    expect(checkValue("Internal IP", ip, "10.30.10.5")).toBeNull();
    expect(checkValue("Internal IP", ip, "10.30.10")).toBe(
      "Internal IP: must be an IPv4 address. Example: 10.30.10.5."
    );
    expect(checkValue("Internal IP", ip, "10.30.10.300")).toBe(
      "Internal IP: each of the four numbers must be 0 to 255. Example: 10.30.10.5."
    );
    expect(checkValue("Internal IP", ip, "10.30.010.5")).toBe(
      "Internal IP: a number must not start with 0. Example: 10.30.10.5."
    );
    const cidr = resolveSpec({ $ref: "#/$defs/cidr" }, SCHEMA.$defs);
    expect(checkValue("Address range", cidr, "10.30.0.0/16")).toBeNull();
    expect(checkValue("Address range", cidr, "10.30.0.0")).toBe(
      "Address range: must be an IPv4 address range in CIDR form. Example: 10.30.10.0/24."
    );
    expect(checkValue("Address range", cidr, "10.30.0.0/33")).toBe(
      "Address range: the number after the slash must be 0 to 32. Example: 10.30.10.0/24."
    );
    expect(checkValue("Address range", cidr, "10.30.10.5/24")).toBe(
      "Address range: 10.30.10.5/24 has bits set past its mask, so it is not a network address. Example: 10.30.10.0/24."
    );
    // The loose patterns of older schemas read the same.
    const loose = { type: "string", pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}$" };
    expect(checkValue("ip", loose, "10.30.10.300")).toBe(
      "ip: each of the four numbers must be 0 to 255. Example: 10.30.10.5."
    );
  });

  test("checkValue covers bounds, counts, lengths and choices", () => {
    const port = resolveSpec({ $ref: "#/$defs/port", default: 5044 }, SCHEMA.$defs);
    expect(checkValue("Ingest port", port, 70000)).toBe(
      "Ingest port: must be a port from 1 to 65535. Example: 5044."
    );
    expect(checkValue("Ingest port", port, 5044.5)).toBe("Ingest port: must be a whole number. Example: 5044.");
    expect(checkValue("Hours", { type: "integer", minimum: 1, maximum: 168 }, 200)).toBe(
      "Hours: must be from 1 to 168."
    );
    expect(checkValue("Services", { type: "array", minItems: 1 }, [])).toBe("Services: must list at least one entry.");
    expect(checkValue("Host name", { type: "string", maxLength: 15 }, "a".repeat(16))).toBe(
      "Host name: must be at most 15 characters."
    );
    expect(checkValue("Operating system", { enum: ["linux"] }, "windows_10", () => "Windows 10")).toBe(
      "Operating system: Windows 10 is not one of the choices here. Pick one from the list."
    );
    expect(checkValue("tag", { type: "string", pattern: "^x$" }, "y")).toBe("tag: does not have the expected format.");
    expect(checkValue("tag", { type: "string", pattern: "^x$" }, "")).toBeNull();
  });
});

// ----------------------------------------------------------------- rendered

describe.each(MODES)("with the %s schema", (mode, schema) => {
  const titled = mode === "titled";
  beforeEach(() => {
    ACTIVE = schema;
  });

  describe("$ref fields", () => {
    test("public_address on a range host is a checkbox with the def's help", () => {
      render(<Panel node={{ id: "dc01", kind: "dc", overlay: { os: "windows_server_2022" } }} />);
      const box = checkboxNamed("range_host.public_address");
      expect(box.checked).toBe(false);
      expect(within(fieldOf(box)).getByText(/Give this host a public IP/)).toBeTruthy();
    });

    test("a port is a number input showing its default", () => {
      render(<Panel mode="offense" node={{ id: "log01", kind: "collector", overlay: { sink: "opensearch" } }} />);
      const input = inputNamed("collector.ingest_port");
      expect(input.type).toBe("number");
      expect(input.getAttribute("placeholder")).toBe("5044");
    });
  });

  describe("labels", () => {
    test("a field is labelled by its title, or its key without one", () => {
      render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
      expect(labelText(fieldNamed("range_host.os"))).toBe(titled ? "Operating system" : "os");
      expect(labelText(fieldNamed("range_host.public_address"))).toBe(titled ? "Public address" : "public_address");
      expect(labelText(fieldNamed("range_host.internal_ip"))).toBe(titled ? "Internal IP" : "internal_ip");
    });

    test("a fieldset legend uses the title", () => {
      render(
        <Panel mode="offense" node={{ id: "cdn-rdr01", kind: "redirector", overlay: { server: "nginx", tls: {} } }} />
      );
      expect(screen.getByText(titled ? "TLS" : "tls", { selector: "legend" })).toBeTruthy();
    });

    test("enum options read as words while the stored value stays the id", async () => {
      const user = userEvent.setup();
      const seen = [];
      render(<Panel seen={seen} node={{ id: "dc01", kind: "dc", overlay: {} }} />);
      const os = selectNamed("range_host.os");
      expect(optionTexts(os)).toContain("Windows Server 2019");
      expect(optionTexts(os)).toContain("Windows 10 (past end of support)");
      expect(optionTexts(os)).toContain("Windows 11");
      expect(optionTexts(os)).toContain("Debian 13");
      expect(optionTexts(os)).not.toContain("windows_server_2019");
      await user.selectOptions(os, "Windows Server 2019");
      expect(seen.at(-1).os).toBe("windows_server_2019");
    });

    test("cert_source options are Let's Encrypt and Self-signed", () => {
      render(
        <Panel mode="offense" node={{ id: "cdn-rdr01", kind: "redirector", overlay: { server: "nginx", tls: {} } }} />
      );
      const texts = optionTexts(selectNamed("redirector.tls.cert_source"));
      expect(texts).toContain("Let's Encrypt");
      expect(texts).toContain("Self-signed");
    });
  });

  describe("the empty option names the default", () => {
    test("a dc or srv with no os says Windows Server 2022, a wks Windows 11, never unset", () => {
      const want = { dc: "Windows Server 2022", srv: "Windows Server 2022", wks: "Windows 11" };
      for (const [kind, label] of Object.entries(want)) {
        const { unmount } = render(<Panel node={{ id: `${kind}01`, kind, overlay: {} }} />);
        const os = selectNamed("range_host.os");
        expect(os.value).toBe("");
        expect(os.options[os.selectedIndex].textContent).toBe(`default (${label})`);
        expect(screen.queryByText("unset")).toBeNull();
        unmount();
      }
    });

    test("Windows 10 says it is past end of support, with the date", () => {
      render(<Panel node={{ id: "ws01", kind: "wks", overlay: { os: "windows_10" } }} />);
      const os = selectNamed("range_host.os");
      expect(os.options[os.selectedIndex].textContent).toBe("Windows 10 (past end of support)");
      expect(os.value).toBe("windows_10");
      const help = fieldOf(os).querySelector(".rg-option-help");
      expect(help.textContent).toMatch(/ended Windows 10 support on 2025-10-14/);
      expect(help.textContent).toMatch(/GCP and AWS boot Windows Server 2022/);
    });

    test("Windows 11 is plain, its help names the GCP and AWS substitution", () => {
      render(<Panel node={{ id: "ws01", kind: "wks", overlay: { os: "windows_11" } }} />);
      const os = selectNamed("range_host.os");
      expect(os.options[os.selectedIndex].textContent).toBe("Windows 11");
      const help = fieldOf(os).querySelector(".rg-option-help");
      expect(help.textContent).toMatch(/boots Windows Server 2022 there/);
      expect(help.textContent).not.toMatch(/end of support/);
    });

    test("schema and known defaults label the empty option", () => {
      render(
        <Panel
          mode="offense"
          node={{ id: "cdn-rdr01", kind: "redirector", overlay: { server: "nginx", tls: {}, gating: {} } }}
        />
      );
      expect(optionTexts(selectNamed("redirector.tls.cert_source"))[0]).toBe("default (Let's Encrypt)");
      expect(optionTexts(selectNamed("redirector.gating.decoy"))[0]).toBe("default (CDN)");
    });

    test("a jumpbox's access mode and vpn protocol name theirs", () => {
      render(
        <Panel
          mode="offense"
          node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"], access_mode: "openvpn" } }}
        />
      );
      expect(optionTexts(selectNamed("jumpbox.access_mode"))[0]).toBe("default (Public portal)");
      expect(optionTexts(selectNamed("jumpbox.vpn_protocol"))[0]).toBe("default (UDP)");
      expect(inputNamed("jumpbox.vpn_port").getAttribute("placeholder")).toBe("1194");
    });

    test("a required enum offers no empty option", () => {
      render(<Panel mode="offense" node={{ id: "myth-ts01", kind: "teamserver", overlay: { c2: "mythic" } }} />);
      expect(optionTexts(selectNamed("teamserver.c2"))).toEqual([
        "Mythic", "Sliver", "AdaptixC2", "None (plain Debian host)",
      ]);
    });

    test("a required enum with nothing stored asks for a pick rather than showing one", () => {
      render(<Panel mode="offense" node={{ id: "myth-ts01", kind: "teamserver", overlay: {} }} />);
      const c2 = selectNamed("teamserver.c2");
      expect(c2.value).toBe("");
      expect(c2.options[c2.selectedIndex].textContent).toBe("pick one");
    });

    test("a stored value the list does not offer stays visible", () => {
      render(<Panel node={{ id: "wks01", kind: "wks", overlay: { os: "windows_7" } }} />);
      const os = selectNamed("range_host.os");
      expect(os.value).toBe("windows_7");
      expect(os.options[os.selectedIndex].textContent).toBe("Windows 7 (not a choice here)");
    });

    test("a dc hostname and a domain netbios show what the compiler fills in", () => {
      const { unmount } = render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
      expect(inputNamed("range_host.hostname").getAttribute("placeholder")).toBe("dc01 (default)");
      unmount();
      render(<Panel node={{ id: "sk-dom01", kind: "domain", overlay: { fqdn: "sevenkingdoms.local" } }} />);
      expect(inputNamed("domain.netbios").getAttribute("placeholder")).toBe("SEVENKINGDOMS (default)");
    });

    test("a pattern field shows the schema's hint or an example, never the raw pattern", () => {
      const { unmount } = render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
      expect(inputNamed("range_host.internal_ip").getAttribute("placeholder")).toBe("e.g. 10.30.10.5");
      unmount();
      render(
        <Panel mode="offense" node={{ id: "cdn-rdr01", kind: "redirector", overlay: { server: "nginx", gating: {} } }} />
      );
      expect(inputNamed("redirector.gating.header_name").getAttribute("placeholder")).toBe("X-Request-Id");
    });
  });

  describe("fields that mean nothing on this node are hidden", () => {
    test("a defense jumpbox hides the VPN fields and the roster, and locks public_address", () => {
      render(<Panel node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"] } }} />);
      for (const name of ["access_mode", "vpn_port", "vpn_protocol"]) expect(hasField(`jumpbox.${name}`)).toBe(false);
      expect(screen.queryByText(/^Operators/)).toBeNull();
      const pub = checkboxNamed("jumpbox.public_address");
      expect(pub.checked).toBe(true);
      expect(pub.disabled).toBe(true);
      expect(within(fieldOf(pub)).getByText(/always takes a public address/)).toBeTruthy();
    });

    test("a stored value on a hidden field stays visible with the reason", () => {
      render(
        <Panel node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"], access_mode: "wireguard" } }} />
      );
      expect(
        within(fieldNamed("jumpbox.access_mode")).getByText(/Not used here: a defense range keeps the public portal/)
      ).toBeTruthy();
    });

    test("vpn fields follow the offense access mode", () => {
      const { unmount } = render(
        <Panel mode="offense" node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"] } }} />
      );
      expect(hasField("jumpbox.access_mode")).toBe(true);
      expect(hasField("jumpbox.vpn_port")).toBe(false);
      expect(hasField("jumpbox.vpn_protocol")).toBe(false);
      unmount();
      render(
        <Panel
          mode="offense"
          node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"], access_mode: "wireguard" } }}
        />
      );
      expect(inputNamed("jumpbox.vpn_port").getAttribute("placeholder")).toBe("51820");
      expect(hasField("jumpbox.vpn_protocol")).toBe(false);
    });

    test("offensive_toolkit shows the compiler's default for the mode", () => {
      const box = () => checkboxNamed("jumpbox.offensive_toolkit");
      const jump = (overlay) => ({ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"], ...overlay } });
      let r = render(<Panel node={jump({})} />);
      expect(box().checked).toBe(true);
      r.unmount();
      r = render(<Panel node={jump({ offensive_toolkit: false })} />);
      expect(box().checked).toBe(false);
      r.unmount();
      render(<Panel mode="offense" node={jump({})} />);
      expect(box().checked).toBe(false);
    });

    test("sudo_groups and ssh_groups show only on a Linux member server", () => {
      let r = render(<Panel node={{ id: "srv01", kind: "srv", overlay: {} }} />);
      expect(hasField("range_host.sudo_groups")).toBe(false);
      expect(hasField("range_host.ssh_groups")).toBe(false);
      r.unmount();
      r = render(<Panel node={{ id: "dc01", kind: "dc", overlay: { os: "linux" } }} />);
      expect(hasField("range_host.sudo_groups")).toBe(false);
      r.unmount();
      render(<Panel node={{ id: "lx-srv01", kind: "srv", overlay: { os: "debian_12" } }} />);
      expect(hasField("range_host.sudo_groups")).toBe(true);
      expect(hasField("range_host.ssh_groups")).toBe(true);
    });

    test("Defender and telemetry toggles are Windows only", () => {
      const r = render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
      expect(hasField("range_host.defender_enabled")).toBe(true);
      expect(hasField("range_host.endpoint_telemetry")).toBe(true);
      r.unmount();
      render(<Panel node={{ id: "lx-srv01", kind: "srv", overlay: { os: "linux" } }} />);
      expect(hasField("range_host.defender_enabled")).toBe(false);
      expect(hasField("range_host.endpoint_telemetry")).toBe(false);
    });

    test("desktop is hidden on a Windows operator", () => {
      const r = render(<Panel mode="offense" node={{ id: "win-op01", kind: "operator", overlay: { os: "windows" } }} />);
      expect(hasField("operator.desktop")).toBe(false);
      r.unmount();
      render(<Panel mode="offense" node={{ id: "kali-op01", kind: "operator", overlay: { os: "kali" } }} />);
      expect(hasField("operator.desktop")).toBe(true);
    });

    test("teamserver version shows only for Mythic and Adaptix", () => {
      for (const [c2, shown] of [["mythic", true], ["adaptix", true], ["sliver", false], ["none", false]]) {
        const r = render(<Panel mode="offense" node={{ id: "ts01", kind: "teamserver", overlay: { c2 } }} />);
        expect([c2, hasField("teamserver.version")]).toEqual([c2, shown]);
        r.unmount();
      }
    });

    test("a network's provider and a collector's shipper are hidden", () => {
      const r = render(
        <Panel mode="offense" node={{ id: "main-net01", kind: "network", overlay: { cidr: "10.30.0.0/16" } }} />
      );
      expect(hasField("network.provider")).toBe(false);
      expect(hasField("network.cidr")).toBe(true);
      r.unmount();
      render(
        <Panel
          mode="offense"
          node={{ id: "log01", kind: "collector", overlay: { sink: "opensearch", shipper: "filebeat" } }}
        />
      );
      expect(hasField("collector.shipper")).toBe(false);
    });

    test("an offense teamserver's public_address is locked off unless it holds the wrong value", () => {
      const r = render(<Panel mode="offense" node={{ id: "ts01", kind: "teamserver", overlay: { c2: "mythic" } }} />);
      let pub = checkboxNamed("teamserver.public_address");
      expect(pub.checked).toBe(false);
      expect(pub.disabled).toBe(true);
      r.unmount();
      render(
        <Panel mode="offense" node={{ id: "ts01", kind: "teamserver", overlay: { c2: "mythic", public_address: true } }} />
      );
      pub = checkboxNamed("teamserver.public_address");
      expect(pub.checked).toBe(true);
      expect(pub.disabled).toBe(false);
    });
  });

  describe("firewall and appliance hosts", () => {
    test("offer Linux os only, no vuln picker, and no domain picker", () => {
      for (const kind of ["fw", "appliance"]) {
        const r = render(<Panel placement node={{ id: `${kind}01`, kind, overlay: {} }} />);
        const os = selectNamed("range_host.os");
        expect(optionTexts(os).some((t) => /Windows/.test(t))).toBe(false);
        expect(optionTexts(os)[0]).toBe("default (Debian 13)");
        expect(screen.queryByText(new RegExp(`^${labelOf("range_host.vulns")}`))).toBeNull();
        expect(labelled("domain")).toHaveLength(0);
        expect(labelled("subnet")).toHaveLength(1);
        r.unmount();
      }
    });

    test("a srv keeps its domain picker", () => {
      render(<Panel placement node={{ id: "srv01", kind: "srv", overlay: {} }} />);
      expect(labelled("domain")).toHaveLength(1);
    });
  });

  describe("hardening is recorded, not deployed", () => {
    test("the picker is disabled, says so, and keeps stored values visible", async () => {
      const user = userEvent.setup();
      render(<Panel node={{ id: "ws01", kind: "wks", overlay: { hardening: ["runasppl", "asr"] } }} />);
      expect(screen.getByText("Not applied yet: these controls are recorded but not deployed.")).toBeTruthy();
      expect(screen.getByText(`${labelOf("range_host.hardening")} (2)`)).toBeTruthy();
      const ppl = screen.getByRole("checkbox", { name: "RunAsPPL (LSASS as a protected process)" });
      expect(ppl.checked).toBe(true);
      expect(ppl.disabled).toBe(true);
      await user.click(screen.getByRole("button", { name: /Network protocols/ }));
      expect(screen.getByRole("checkbox", { name: "SMB signing required" }).disabled).toBe(true);
    });
  });

  describe("services", () => {
    const chips = (field) =>
      [...field.querySelectorAll(".rg-chip")].map((c) => ({
        text: c.firstChild.textContent,
        dead: c.classList.contains("is-dead"),
        title: c.getAttribute("title"),
      }));

    test("a jumpbox offers ssh and guacamole; the VPN follows Access mode", async () => {
      const user = userEvent.setup();
      const seen = [];
      render(
        <Panel
          mode="offense"
          seen={seen}
          node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh", "wireguard"] } }}
        />
      );
      const field = fieldNamed("jumpbox.services");
      const boxes = within(field).getAllByRole("checkbox").map((b) => b.closest("label").textContent);
      expect(boxes).toEqual(["SSH", "Guacamole portal"]);
      expect(within(field).getByText("The VPN server follows Access mode.")).toBeTruthy();
      expect(chips(field)).toEqual([
        { text: "WireGuard", dead: true, title: "Ignored. The VPN server follows Access mode." },
      ]);
      await user.click(within(field).getByRole("button", { name: "Remove wireguard" }));
      expect(seen.at(-1).services).toEqual(["ssh"]);
    });

    test("on a defense jumpbox the note does not point at the hidden Access mode", () => {
      render(<Panel node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh", "wireguard"] } }} />);
      const field = fieldNamed("jumpbox.services");
      const note = "A defense range runs no VPN server; operators use the public portal.";
      expect(within(field).getByText(note)).toBeTruthy();
      expect(chips(field)[0].title).toBe(`Ignored. ${note}`);
    });

    test("a Windows member server gets a checklist; a value nothing installs is a dead chip", async () => {
      const user = userEvent.setup();
      const seen = [];
      render(<Panel seen={seen} node={{ id: "file-srv01", kind: "srv", overlay: { services: ["smb"] } }} />);
      const field = fieldNamed("range_host.services");
      const boxes = within(field).getAllByRole("checkbox").map((b) => b.closest("label").textContent);
      expect(boxes).toEqual(["SQL Server (mssql)", "IIS", "Exchange"]);
      const [chip] = chips(field);
      expect(chip.text).toBe("smb");
      expect(chip.dead).toBe(true);
      expect(chip.title).toMatch(/^smb installs nothing on this host\. Remove it\./);
      await user.click(within(field).getByRole("checkbox", { name: "IIS" }));
      expect(seen.at(-1).services).toEqual(["smb", "iis"]);
    });

    test("a value the Role field installs reads as installed, not dead (GOAD kingslanding, braavos)", () => {
      const kingslanding = GOAD.nodes.find((n) => n.id === "kingslanding");
      let r = render(<Panel node={kingslanding} />);
      let field = fieldNamed("range_host.services");
      expect(within(field).queryAllByRole("checkbox")).toHaveLength(0);
      expect(chips(field)).toEqual([
        { text: "adcs (installed by Role: AD CS)", dead: false, title: "Role AD CS installs this." },
      ]);
      expect(within(field).getByText("Only a Windows member server (srv) installs from this list.")).toBeTruthy();
      expect(within(field).queryByText(/Not used here/)).toBeNull();
      r.unmount();

      const braavos = GOAD.nodes.find((n) => n.id === "braavos");
      r = render(<Panel node={braavos} />);
      field = fieldNamed("range_host.services");
      expect(within(field).getByRole("checkbox", { name: "SQL Server (mssql)" }).checked).toBe(true);
      expect(chips(field).map((c) => [c.text, c.dead])).toEqual([["adcs (installed by Role: AD CS)", false]]);
      r.unmount();

      const mecm = SCCM.nodes.find((n) => n.id === "mecm");
      render(<Panel node={mecm} />);
      expect(chips(fieldNamed("range_host.services")).map((c) => [c.text, c.dead])).toEqual([
        ["mecm (installed by Role: MECM)", false],
      ]);
    });

    test("the same value without its role is dead", () => {
      render(<Panel node={{ id: "dc01", kind: "dc", overlay: { services: ["adcs"] } }} />);
      expect(chips(fieldNamed("range_host.services"))).toEqual([
        {
          text: "adcs",
          dead: true,
          title: "adcs installs nothing on this host. Set Role to AD CS on a Windows dc or srv to stand up the CA.",
        },
      ]);
    });

    test("services are hidden where nothing installs from them and nothing is stored", () => {
      for (const node of [
        { id: "dc01", kind: "dc", overlay: {} },
        { id: "wks01", kind: "wks", overlay: {} },
        { id: "lx-srv01", kind: "srv", overlay: { os: "linux" } },
      ]) {
        const r = render(<Panel node={node} />);
        expect([node.id, hasField("range_host.services")]).toEqual([node.id, false]);
        r.unmount();
      }
    });
  });

  describe("role", () => {
    test("the chosen role says what it installs", async () => {
      const user = userEvent.setup();
      render(<Panel node={{ id: "srv01", kind: "srv", overlay: {} }} />);
      const role = selectNamed("range_host.role");
      expect(role.options[role.selectedIndex].textContent).toBe("default (Generic)");
      expect(within(fieldNamed("range_host.role")).getByText("Installs nothing.")).toBeTruthy();
      await user.selectOptions(role, "SQL Server");
      expect(within(fieldNamed("range_host.role")).getByText("Installs SQL Server.")).toBeTruthy();
      await user.selectOptions(selectNamed("range_host.role"), "Web server");
      expect(
        within(fieldNamed("range_host.role")).getByText("Badge only. Tick IIS under Services to install IIS.")
      ).toBeTruthy();
    });

    test("a dc offers Generic and AD CS only; a workstation has no role", () => {
      const r = render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
      expect(optionTexts(selectNamed("range_host.role"))).toEqual(["default (Generic)", "Generic", "AD CS"]);
      r.unmount();
      render(<Panel node={{ id: "wks01", kind: "wks", overlay: { role: "generic" } }} />);
      expect(hasField("range_host.role")).toBe(false);
    });
  });

  describe("operator roster", () => {
    test("the role input says it is a display label", () => {
      render(<Panel mode="offense" node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"] } }} />);
      expect(screen.getByPlaceholderText("label, e.g. lead (display only)")).toBeTruthy();
    });
  });

  describe("inline validation", () => {
    test("a bad address turns the field red with the reason under it", () => {
      render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
      const ip = inputNamed("range_host.internal_ip");
      expect(fieldOf(ip).classList.contains("is-invalid")).toBe(false);
      fireEvent.change(ip, { target: { value: "10.30.10.300" } });
      expect(fieldOf(ip).classList.contains("is-invalid")).toBe(true);
      expect(errorsIn(fieldOf(ip))).toEqual([
        `${labelOf("range_host.internal_ip")}: each of the four numbers must be 0 to 255. Example: 10.30.10.5.`,
      ]);
      fireEvent.change(ip, { target: { value: "10.30.10" } });
      expect(errorsIn(fieldOf(ip))).toEqual([
        `${labelOf("range_host.internal_ip")}: must be an IPv4 address. Example: 10.30.10.5.`,
      ]);
      fireEvent.change(ip, { target: { value: "10.30.10.30" } });
      expect(fieldOf(ip).classList.contains("is-invalid")).toBe(false);
    });

    test("a subnet range with host bits set says which network address to use", () => {
      render(
        <Panel
          node={{ id: "lab-sub01", kind: "segment", overlay: { cidr: "10.30.10.5/24", egress: "allowed", exposure: "local" } }}
        />
      );
      expect(errorsIn(fieldNamed("segment.cidr"))).toEqual([
        `${labelOf("segment.cidr")}: 10.30.10.5/24 has bits set past its mask, so it is not a network address. Example: 10.30.10.0/24.`,
      ]);
    });

    test("a nested pattern field is checked", () => {
      render(
        <Panel
          mode="offense"
          node={{
            id: "cdn-rdr01",
            kind: "redirector",
            overlay: { server: "nginx", tls: {}, gating: { header_name: "X Request Id" } },
          }}
        />
      );
      expect(errorsIn(fieldNamed("redirector.gating.header_name"))).toEqual([
        `${labelOf("redirector.gating.header_name")}: must be letters, digits and hyphens, starting with a letter. Example: X-Request-Id.`,
      ]);
    });

    test("a port out of range is red", () => {
      render(
        <Panel mode="offense" node={{ id: "log01", kind: "collector", overlay: { sink: "opensearch", ingest_port: 70000 } }} />
      );
      expect(errorsIn(fieldNamed("collector.ingest_port"))).toEqual([
        `${labelOf("collector.ingest_port")}: must be a port from 1 to 65535. Example: 5044.`,
      ]);
    });

    test("a stored os a firewall cannot take is red", () => {
      render(<Panel node={{ id: "fw01", kind: "fw", overlay: { os: "windows_server_2019" } }} />);
      expect(errorsIn(fieldNamed("range_host.os"))).toEqual([
        `${labelOf("range_host.os")}: Windows Server 2019 is not one of the choices here. Pick one from the list.`,
      ]);
    });
  });

  describe("server findings that name a field", () => {
    const finding = (field, message, { id = "cdn-rdr01", severity = "error", code = "SCH001" } = {}) => ({
      code, severity, target_ids: [id], field, message, remedy: "",
    });
    const rdr = { id: "cdn-rdr01", kind: "redirector", overlay: { server: "nginx", tls: { cert_source: "letsencrypt" } } };

    test("an error marks the named field red with the message under it", () => {
      const message = "tls.cert_source on cdn-rdr01: must be one of letsencrypt, self_signed.";
      render(<Panel mode="offense" node={rdr} findings={[finding("tls.cert_source", message)]} />);
      const field = fieldNamed("redirector.tls.cert_source");
      expect(field.classList.contains("is-invalid")).toBe(true);
      expect(errorsIn(field)).toEqual([message]);
      // Only that field: its sibling select stays clean.
      expect(fieldNamed("redirector.server").classList.contains("is-invalid")).toBe(false);
      // Still in the node's finding list too.
      expect(screen.getAllByText(message)).toHaveLength(2);
    });

    test("an overlay. prefix and the node id are understood", () => {
      render(
        <Panel
          mode="offense"
          node={rdr}
          findings={[finding("overlay.server", "server: pick one."), finding("id", "id: use lowercase.")]}
        />
      );
      expect(errorsIn(fieldNamed("redirector.server"))).toEqual(["server: pick one."]);
      const id = fieldOf(screen.getByDisplayValue("cdn-rdr01"));
      expect(id.classList.contains("is-invalid")).toBe(true);
      expect(errorsIn(id)).toEqual(["id: use lowercase."]);
    });

    test("a server message replaces the client one on the same field", () => {
      render(
        <Panel
          node={{ id: "dc01", kind: "dc", overlay: { internal_ip: "10.30.10" } }}
          findings={[finding("internal_ip", "internal_ip on dc01: must be an IPv4 address.", { id: "dc01" })]}
        />
      );
      expect(errorsIn(fieldNamed("range_host.internal_ip"))).toEqual(["internal_ip on dc01: must be an IPv4 address."]);
    });

    test("a warning or info finding shows at its field without the red", () => {
      render(
        <Panel
          node={{ id: "file-srv01", kind: "srv", overlay: { os: "windows_10", services: ["smb"] } }}
          findings={[
            finding("services", "file-srv01 lists the service smb, which nothing installs on this host.", {
              id: "file-srv01", severity: "warning", code: "SVC001",
            }),
            finding("os", "file-srv01 asks for Windows 10; GCP has no client image.", {
              id: "file-srv01", severity: "info", code: "CAP005",
            }),
          ]}
        />
      );
      const services = fieldNamed("range_host.services");
      expect(services.classList.contains("is-invalid")).toBe(false);
      expect(errorsIn(services)).toEqual([]);
      expect(services.querySelector(".rg-field-finding.is-warning").textContent).toMatch(/lists the service smb/);
      const os = fieldNamed("range_host.os");
      expect(os.classList.contains("is-invalid")).toBe(false);
      expect(os.querySelector(".rg-field-finding.is-info").textContent).toMatch(/no client image/);
      // The node's list carries the severity class the stylesheet colours.
      expect(document.querySelector(".rg-finding.is-info")).toBeTruthy();
    });

    test("a finding with no field marks nothing", () => {
      const plain = { code: "RDR001", severity: "error", target_ids: ["cdn-rdr01"], message: "no hostname", remedy: "" };
      render(<Panel mode="offense" node={rdr} findings={[plain]} />);
      expect(document.querySelectorAll(".rg-field.is-invalid")).toHaveLength(0);
    });
  });
});
