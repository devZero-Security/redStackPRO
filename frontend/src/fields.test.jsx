// The Inspector's generic field layer: how a schema property turns into a
// control. Rendered against the real 0.7.0 schema where the behavior depends on
// it, and against small synthetic schemas where it should not.

import React, { useState } from "react";
import { describe, expect, test } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import SCHEMA from "../../src/redstackpro/schema/topology/0.7.0.json";
import { Inspector } from "./Inspector.jsx";
import { fieldRule, jsonKindFor, resolveSpec } from "./fieldRules.js";

// Renders one node in the Inspector over a local document, the way App wires
// onOverlayChange. `seen` collects every overlay the panel writes.
function Panel({ node, mode = "defense", schema = SCHEMA, findings = [], seen, extraNodes = [], placement = false }) {
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

// Whether a field label is on screen.
const hasField = (title) =>
  screen.queryAllByText(
    (_, el) => el?.classList?.contains("rg-field-label") && el.firstChild?.textContent === title
  ).length > 0;

describe("fields that mean nothing on this node are hidden", () => {
  test("a defense jumpbox hides the VPN fields and the roster, and locks public_address", () => {
    render(<Panel node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"] } }} />);
    for (const name of ["access_mode", "vpn_port", "vpn_protocol"]) expect(hasField(name)).toBe(false);
    expect(screen.queryByText(/^Operators/)).toBeNull();
    const pub = screen.getByRole("checkbox", { name: /public_address/ });
    expect(pub.checked).toBe(true);
    expect(pub.disabled).toBe(true);
    expect(within(fieldOf(pub)).getByText(/always takes a public address/)).toBeTruthy();
  });

  test("a stored value on a hidden field stays visible with the reason", () => {
    render(
      <Panel node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"], access_mode: "wireguard" } }} />
    );
    const field = fieldNamed("access_mode");
    expect(within(field).getByText(/Not used here: a defense range keeps the public portal/)).toBeTruthy();
  });

  test("vpn fields follow the offense access mode", () => {
    const { unmount } = render(
      <Panel mode="offense" node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"] } }} />
    );
    expect(hasField("access_mode")).toBe(true);
    expect(hasField("vpn_port")).toBe(false);
    expect(hasField("vpn_protocol")).toBe(false);
    unmount();
    render(
      <Panel
        mode="offense"
        node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"], access_mode: "wireguard" } }}
      />
    );
    expect(hasField("vpn_port")).toBe(true);
    expect(inputNamed("vpn_port").getAttribute("placeholder")).toBe("51820");
    expect(hasField("vpn_protocol")).toBe(false);
  });

  test("offensive_toolkit shows the compiler's default for the mode", () => {
    const box = () => screen.getByRole("checkbox", { name: /offensive_toolkit/ });
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
    expect(hasField("sudo_groups")).toBe(false);
    expect(hasField("ssh_groups")).toBe(false);
    r.unmount();
    r = render(<Panel node={{ id: "dc01", kind: "dc", overlay: { os: "linux" } }} />);
    expect(hasField("sudo_groups")).toBe(false);
    r.unmount();
    render(<Panel node={{ id: "lx-srv01", kind: "srv", overlay: { os: "linux" } }} />);
    expect(hasField("sudo_groups")).toBe(true);
    expect(hasField("ssh_groups")).toBe(true);
  });

  test("Defender and telemetry toggles are Windows only", () => {
    const r = render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
    expect(hasField("defender_enabled")).toBe(true);
    expect(hasField("endpoint_telemetry")).toBe(true);
    r.unmount();
    render(<Panel node={{ id: "lx-srv01", kind: "srv", overlay: { os: "linux" } }} />);
    expect(hasField("defender_enabled")).toBe(false);
    expect(hasField("endpoint_telemetry")).toBe(false);
  });

  test("desktop is hidden on a Windows operator", () => {
    const r = render(<Panel mode="offense" node={{ id: "win-op01", kind: "operator", overlay: { os: "windows" } }} />);
    expect(hasField("desktop")).toBe(false);
    r.unmount();
    render(<Panel mode="offense" node={{ id: "kali-op01", kind: "operator", overlay: { os: "kali" } }} />);
    expect(hasField("desktop")).toBe(true);
  });

  test("teamserver version shows only for Mythic and Adaptix", () => {
    for (const [c2, shown] of [["mythic", true], ["adaptix", true], ["sliver", false], ["none", false]]) {
      const r = render(<Panel mode="offense" node={{ id: "ts01", kind: "teamserver", overlay: { c2 } }} />);
      expect(hasField("version")).toBe(shown);
      r.unmount();
    }
  });

  test("a network's provider and a collector's shipper are hidden", () => {
    const r = render(
      <Panel mode="offense" node={{ id: "main-net01", kind: "network", overlay: { cidr: "10.30.0.0/16" } }} />
    );
    expect(hasField("provider")).toBe(false);
    expect(hasField("cidr")).toBe(true);
    r.unmount();
    render(
      <Panel
        mode="offense"
        node={{ id: "log01", kind: "collector", overlay: { sink: "opensearch", shipper: "filebeat" } }}
      />
    );
    expect(hasField("shipper")).toBe(false);
  });

  test("an offense teamserver's public_address is locked off unless it holds the wrong value", () => {
    const r = render(<Panel mode="offense" node={{ id: "ts01", kind: "teamserver", overlay: { c2: "mythic" } }} />);
    let pub = screen.getByRole("checkbox", { name: /public_address/ });
    expect(pub.checked).toBe(false);
    expect(pub.disabled).toBe(true);
    r.unmount();
    render(
      <Panel mode="offense" node={{ id: "ts01", kind: "teamserver", overlay: { c2: "mythic", public_address: true } }} />
    );
    pub = screen.getByRole("checkbox", { name: /public_address/ });
    expect(pub.checked).toBe(true);
    expect(pub.disabled).toBe(false);
  });
});

describe("firewall and appliance hosts", () => {
  test("offer Linux os only, no vuln picker, and no domain picker", () => {
    for (const kind of ["fw", "appliance"]) {
      const r = render(<Panel placement node={{ id: `${kind}01`, kind, overlay: {} }} />);
      const os = selectNamed("os");
      expect(optionTexts(os).some((t) => /Windows/.test(t))).toBe(false);
      expect(optionTexts(os)[0]).toBe("default (Linux (Debian))");
      expect(screen.queryByText(/^vulnerabilities/)).toBeNull();
      expect(hasField("domain")).toBe(false);
      expect(hasField("subnet")).toBe(true);
      r.unmount();
    }
  });

  test("a srv keeps its domain picker", () => {
    render(<Panel placement node={{ id: "srv01", kind: "srv", overlay: {} }} />);
    expect(hasField("domain")).toBe(true);
  });
});

describe("hardening is recorded, not deployed", () => {
  test("the picker is disabled, says so, and keeps stored values visible", async () => {
    const user = userEvent.setup();
    render(<Panel node={{ id: "ws01", kind: "wks", overlay: { hardening: ["runasppl", "asr"] } }} />);
    expect(screen.getByText("Not applied yet: these controls are recorded but not deployed.")).toBeTruthy();
    const ppl = screen.getByRole("checkbox", { name: "RunAsPPL (LSASS as a protected process)" });
    expect(ppl.checked).toBe(true);
    expect(ppl.disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: /Network protocols/ }));
    expect(screen.getByRole("checkbox", { name: "SMB signing required" }).disabled).toBe(true);
  });
});

describe("services", () => {
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
    const field = fieldNamed("services");
    const boxes = within(field).getAllByRole("checkbox").map((b) => b.closest("label").textContent);
    expect(boxes).toEqual(["SSH", "Guacamole portal"]);
    expect(within(field).getByText("The VPN server follows Access mode.")).toBeTruthy();
    const chip = within(field).getByText("WireGuard").closest(".rg-chip");
    expect(chip.getAttribute("title")).toBe("Ignored. The VPN server follows Access mode.");
    await user.click(within(chip).getByRole("button", { name: "Remove wireguard" }));
    expect(seen.at(-1).services).toEqual(["ssh"]);
  });

  test("on a defense jumpbox the note does not point at the hidden Access mode", () => {
    render(<Panel node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh", "wireguard"] } }} />);
    const field = fieldNamed("services");
    const note = "A defense range runs no VPN server; operators use the public portal.";
    expect(within(field).getByText(note)).toBeTruthy();
    expect(within(field).getByText("WireGuard").closest(".rg-chip").getAttribute("title")).toBe(`Ignored. ${note}`);
  });

  test("a member server gets a checklist of what a role installs; unknown values are chips", async () => {
    const user = userEvent.setup();
    const seen = [];
    render(<Panel seen={seen} node={{ id: "file-srv01", kind: "srv", overlay: { services: ["smb"] } }} />);
    const field = fieldNamed("services");
    const boxes = within(field).getAllByRole("checkbox").map((b) => b.closest("label").textContent);
    expect(boxes).toEqual(["SQL Server (mssql)", "IIS", "Exchange"]);
    const chip = within(field).getByText("SMB").closest(".rg-chip");
    expect(chip.getAttribute("title")).toBe("smb does nothing: no role installs it.");
    await user.click(within(field).getByRole("checkbox", { name: "IIS" }));
    expect(seen.at(-1).services).toEqual(["smb", "iis"]);
  });

  test("on a dc, services are hidden, or shown as unused chips when set", () => {
    const r = render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
    expect(hasField("services")).toBe(false);
    r.unmount();
    render(<Panel node={{ id: "dc01", kind: "dc", overlay: { role: "adcs", services: ["adcs"] } }} />);
    const field = fieldNamed("services");
    expect(within(field).queryAllByRole("checkbox")).toHaveLength(0);
    expect(within(field).getByText(/Not used here: only a member server/)).toBeTruthy();
    expect(within(field).getByText("AD CS").closest(".rg-chip").getAttribute("title")).toBe(
      "adcs does nothing: no role installs it. Set Role to AD CS instead."
    );
  });
});

describe("role", () => {
  test("the chosen role says what it installs", async () => {
    const user = userEvent.setup();
    render(<Panel node={{ id: "srv01", kind: "srv", overlay: {} }} />);
    const role = selectNamed("role");
    expect(role.options[role.selectedIndex].textContent).toBe("default (Generic)");
    expect(within(fieldNamed("role")).getByText("Installs nothing.")).toBeTruthy();
    await user.selectOptions(role, "SQL Server");
    expect(within(fieldNamed("role")).getByText("Installs SQL Server.")).toBeTruthy();
    await user.selectOptions(selectNamed("role"), "Web server");
    expect(
      within(fieldNamed("role")).getByText("Badge only. Tick IIS under Services to install IIS.")
    ).toBeTruthy();
  });

  test("a dc offers Generic and AD CS only; a workstation has no role", () => {
    const r = render(<Panel node={{ id: "dc01", kind: "dc", overlay: {} }} />);
    expect(optionTexts(selectNamed("role"))).toEqual(["default (Generic)", "Generic", "AD CS"]);
    r.unmount();
    render(<Panel node={{ id: "wks01", kind: "wks", overlay: { role: "generic" } }} />);
    expect(hasField("role")).toBe(false);
  });
});

describe("operator roster", () => {
  test("the role input says it is a display label", () => {
    render(<Panel mode="offense" node={{ id: "jump01", kind: "jumpbox", overlay: { services: ["ssh"] } }} />);
    expect(screen.getByPlaceholderText("label, e.g. lead (display only)")).toBeTruthy();
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
