// User activity in the real Inspector over the shipped blueprints: each line
// ticks its vuln, its pickers write the keys the role reads, and the
// Vulnerabilities list, the settings form and the JSON view stay in step.

import React, { useState } from "react";
import { describe, expect, test } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { computeAccessibleName } from "dom-accessibility-api";

import SCHEMA from "../../src/redstackpro/schema/topology/0.7.0.json";
import LIGHT from "../public/goad/goad-light.json";
import MINILAB from "../public/goad/minilab.json";
import { Inspector } from "./Inspector.jsx";

const clone = (v) => JSON.parse(JSON.stringify(v));

function Panel({ blueprint, id, edit, provider, findings = [], readOnly = false, seen }) {
  const [document, setDocument] = useState(() => {
    const doc = clone(blueprint);
    edit?.(doc);
    return doc;
  });
  return (
    <Inspector
      schema={SCHEMA}
      selection={{ type: "node", id }}
      document={document}
      findings={findings}
      readOnly={readOnly}
      provider={provider}
      onOverlayChange={(nodeId, overlay) => {
        if (nodeId === id) seen?.push(overlay);
        setDocument((d) => ({
          ...d,
          nodes: d.nodes.map((n) => (n.id === nodeId ? { ...n, overlay } : n)),
        }));
      }}
      onRename={() => {}}
      onDelete={() => {}}
      kindLabels={{}}
    />
  );
}

const overlayOf = (doc, id) => doc.nodes.find((n) => n.id === id).overlay;
const section = () => within(document.querySelector(".rg-activities"));
const box = (name) => screen.getByRole("checkbox", { name });
const row = (name) => within(box(name).closest(".rg-activity"));
const field = (role, name) => screen.getByRole(role, { name });
const json = () => screen.getByRole("textbox", { name: "Edit as JSON" });
const jsonValue = () => JSON.parse(json().value);
const last = (seen) => seen.at(-1);
const sched = (seen) => last(seen).vulns_vars?.schedule;
const action = () => field("combobox", "Scheduled task action");
const choose = (value) => fireEvent.change(action(), { target: { value } });
const type = (name, value) => fireEvent.change(field("textbox", name), { target: { value } });

// winterfell without its schedule, and minilab's dc with its script bot.
const winterfell = (props) => <Panel blueprint={LIGHT} id="winterfell" {...props} />;
const minilab = (props) => <Panel blueprint={MINILAB} id="dc" {...props} />;

describe("the section", () => {
  test("lists every activity, ticked ones as a sentence with pickers", () => {
    render(winterfell());
    for (const name of ["Logon bot", "Share-browsing bot", "Relay bot", "Saved credential"]) {
      expect(box(name).checked).toBe(true);
    }
    expect(box("Scheduled task").checked).toBe(false);
    expect(row("Logon bot").getByText(/logs on to this host every minute/)).toBeTruthy();
    expect(row("Scheduled task").getByText(/does something on this host every few minutes/)).toBeTruthy();
    expect(screen.queryByRole("combobox", { name: "Scheduled task action" })).toBeNull();
  });

  test("ticking an activity ticks its vuln, and the Vulnerabilities list follows", () => {
    const seen = [];
    render(winterfell({ seen }));
    fireEvent.click(box("Scheduled task"));
    expect(last(seen).vulns).toContain("schedule");
    fireEvent.click(screen.getByRole("button", { name: /Double-hop & bots/ }));
    expect(box("Scheduled login bot").checked).toBe(true);
    expect(action().value).toBe("logon");
  });

  test("unticking in the Vulnerabilities list unticks the activity", () => {
    const seen = [];
    render(winterfell({ seen }));
    // The group starts open: winterfell already has one of its vulns ticked.
    fireEvent.click(box("RDP scheduled logon"));
    expect(last(seen).vulns).not.toContain("rdp_scheduler");
    expect(box("Logon bot").checked).toBe(false);
    expect(screen.queryByRole("combobox", { name: "Logon bot user" })).toBeNull();
    // Unticking keeps the setting, as the list does, so ticking again restores it.
    fireEvent.click(box("Logon bot"));
    expect(field("combobox", "Logon bot user").value).toBe("NORTH\\robb.stark");
  });

  test("the settings form points to User activity instead of showing the keys again", () => {
    render(minilab());
    const form = within(document.querySelector(".rg-vuln-form"));
    for (const legend of ["Scheduled login bot", "Stored credential (CredMan)"]) {
      expect(within(form.getByText(legend).closest("fieldset")).getByText("Set under User activity above.")).toBeTruthy();
    }
    expect(screen.queryByRole("textbox", { name: "What it does" })).toBeNull();
    expect(screen.queryByRole("combobox", { name: "Runs as" })).toBeNull();
    // The JSON view does not call these keys its own.
    expect(screen.getByText("The same settings as one JSON object, for a key the form does not show.")).toBeTruthy();
  });

  test("a Linux host has no User activity, and keeps the plain form", () => {
    render(
      <Panel
        blueprint={LIGHT}
        id="castelblack"
        edit={(doc) => {
          const ov = overlayOf(doc, "castelblack");
          ov.os = "debian_13";
          ov.vulns = ["schedule"];
        }}
      />
    );
    expect(document.querySelector(".rg-activities")).toBeNull();
    expect(field("textbox", "What it does")).toBeTruthy();
  });
});

describe("the logon bot and the saved credential", () => {
  test("the logon bot user writes bot_user as DOMAIN\\user", () => {
    const seen = [];
    render(winterfell({ seen }));
    fireEvent.change(field("combobox", "Logon bot user"), { target: { value: "NORTH\\arya.stark" } });
    expect(last(seen).vulns_vars.bot_user).toBe("NORTH\\arya.stark");
    expect(jsonValue().bot_user).toBe("NORTH\\arya.stark");
  });

  test("the saved credential reads as owner, account and target", () => {
    const seen = [];
    render(winterfell({ seen }));
    expect(row("Saved credential").getByText("has a saved credential for")).toBeTruthy();
    fireEvent.change(field("combobox", "Saved credential account"), { target: { value: "NORTH\\eddard.stark" } });
    expect(last(seen).vulns_vars.stored_credential).toEqual({
      owner: "north\\robb.stark", username: "NORTH\\eddard.stark", target: "TERMSRV/castelblack",
    });
  });

  test("ticking the saved credential fills the target with this host", () => {
    const seen = [];
    render(<Panel blueprint={LIGHT} id="castelblack" seen={seen} />);
    fireEvent.click(box("Saved credential"));
    expect(last(seen).vulns).toContain("stored_credential");
    expect(last(seen).vulns_vars.stored_credential).toEqual({ target: "TERMSRV/castelblack" });
    expect(field("combobox", "Saved credential owner").value).toBe("");
  });
});

describe("the poisoning bots and the provider", () => {
  test("on a cloud provider an unticked bot is disabled, with the reason", () => {
    render(<Panel blueprint={LIGHT} id="castelblack" provider="gcp" />);
    for (const name of ["Share-browsing bot", "Relay bot"]) {
      expect(box(name).disabled).toBe(true);
      expect(row(name).getByText(/^Not planted on GCP: cloud networks drop/)).toBeTruthy();
      expect(row(name).getByText("Proxmox and ESXi only")).toBeTruthy();
    }
    expect(box("Logon bot").disabled).toBe(false);
  });

  test("on Proxmox they can be ticked", () => {
    render(<Panel blueprint={LIGHT} id="castelblack" provider="proxmox" />);
    expect(box("Share-browsing bot").disabled).toBe(false);
    expect(row("Share-browsing bot").queryByText(/Not planted/)).toBeNull();
  });

  test("one already ticked on a cloud provider says so and can still be unticked", () => {
    const seen = [];
    render(winterfell({ provider: "aws", seen }));
    expect(box("Share-browsing bot").disabled).toBe(false);
    expect(row("Share-browsing bot").getByText(/^Not planted on AWS/)).toBeTruthy();
    fireEvent.click(box("Share-browsing bot"));
    expect(last(seen).vulns).not.toContain("responder");
  });

  test("the targets write their keys, and the relay user falls back to the bot user", () => {
    const seen = [];
    render(winterfell({ seen }));
    type("Share the relay bot authenticates to", "\\\\Nowhere\\it's");
    expect(last(seen).vulns_vars.ntlm_relay_target).toBe("\\\\Nowhere\\it's");
    fireEvent.change(field("combobox", "Relay bot user"), { target: { value: "" } });
    expect(last(seen).vulns_vars.ntlm_relay_user).toBeUndefined();
    expect(within(field("combobox", "Relay bot user")).getByText("same as the bot user, north\\robb.stark")).toBeTruthy();
  });
});

describe("the scheduled task", () => {
  const ticked = (props) =>
    winterfell({ edit: (doc) => overlayOf(doc, "winterfell").vulns.push("schedule"), ...props });

  test("a new one is SYSTEM staying logged on every minute, task schedule_bot", () => {
    render(ticked());
    expect(field("combobox", "Scheduled task runs as").value).toBe("");
    expect(within(field("combobox", "Scheduled task runs as")).getByText("SYSTEM")).toBeTruthy();
    expect(action().value).toBe("logon");
    expect(row("Scheduled task").getByText("minute.")).toBeTruthy();
    expect(field("textbox", "Scheduled task name").placeholder).toBe("schedule_bot");
    expect(row("Scheduled task").getByText("One scheduled task per host.")).toBeTruthy();
    expect(row("Scheduled task").getByText(/As SYSTEM no user credential/)).toBeTruthy();
    expect(row("Scheduled task").queryByText(/its logon leaves/)).toBeNull();
  });

  test("who and how often write user and interval_minutes", () => {
    const seen = [];
    render(ticked({ seen }));
    fireEvent.change(field("combobox", "Scheduled task runs as"), { target: { value: "NORTH\\arya.stark" } });
    fireEvent.change(field("spinbutton", "Scheduled task interval in minutes"), { target: { value: "5" } });
    expect(sched(seen)).toEqual({ user: "NORTH\\arya.stark", interval_minutes: 5 });
    expect(row("Scheduled task").getByText("minutes.")).toBeTruthy();
    expect(row("Scheduled task").queryByText(/As SYSTEM/)).toBeNull();
    expect(row("Scheduled task").getByText(/its logon leaves the user's session and credentials/)).toBeTruthy();
  });

  test("runs a file: an .exe by Start-Process, a .ps1 by PowerShell, quotes doubled", () => {
    const seen = [];
    render(ticked({ seen }));
    choose("file");
    expect(sched(seen)).toBeUndefined();
    expect(action().value).toBe("file");
    expect(row("Scheduled task").getByText(/No Office is installed, so documents do not open/)).toBeTruthy();
    type("File to run", "\\\\fs01\\it's\\setup.exe");
    expect(sched(seen).command).toBe("Start-Process '\\\\fs01\\it''s\\setup.exe'");
    type("File to run", "C:\\tools\\map.ps1");
    expect(sched(seen).command).toBe("powershell.exe -ExecutionPolicy Bypass -File 'C:\\tools\\map.ps1'");
    expect(field("textbox", "File to run").value).toBe("C:\\tools\\map.ps1");
  });

  test("browses a share and fetches a web page", () => {
    const seen = [];
    render(ticked({ seen }));
    choose("share");
    type("Share to browse", "\\\\fs01\\public");
    expect(sched(seen).command).toBe("Get-ChildItem '\\\\fs01\\public'");
    choose("web");
    expect(row("Scheduled task").getByText("Sends this user's credentials to the site.")).toBeTruthy();
    type("Web page to fetch", "http://intranet/");
    expect(sched(seen).command).toBe("Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials 'http://intranet/'");
    // Back to the share restores what was typed there.
    choose("share");
    expect(field("textbox", "Share to browse").value).toBe("\\\\fs01\\public");
    expect(sched(seen).command).toBe("Get-ChildItem '\\\\fs01\\public'");
  });

  test("my own PowerShell starts from the current command and warns on a double quote", () => {
    const seen = [];
    render(ticked({ seen }));
    choose("share");
    type("Share to browse", "\\\\fs01\\public");
    choose("custom");
    expect(field("textbox", "Scheduled task PowerShell").value).toBe("Get-ChildItem '\\\\fs01\\public'");
    type("Scheduled task PowerShell", 'Write-Output "hi"');
    expect(sched(seen).command).toBe('Write-Output "hi"');
    expect(row("Scheduled task").getByText(/Double quotes are stripped/)).toBeTruthy();
  });

  test("an edit in the JSON shows as its action", () => {
    render(ticked());
    const next = { ...jsonValue(), schedule: { command: "Start-Process 'C:\\app.exe'" } };
    fireEvent.change(json(), { target: { value: JSON.stringify(next) } });
    expect(action().value).toBe("file");
    expect(field("textbox", "File to run").value).toBe("C:\\app.exe");
    fireEvent.change(json(), { target: { value: JSON.stringify({ ...next, schedule: { command: "whoami" } }) } });
    expect(action().value).toBe("custom");
    expect(field("textbox", "Scheduled task PowerShell").value).toBe("whoami");
  });

  test("a shipped script bot reads as my own script, with its path and body", () => {
    render(minilab());
    expect(action().value).toBe("script");
    expect(field("textbox", "Scheduled task script path").value).toBe("C:\\bot.ps1");
    expect(field("textbox", "Scheduled task script body").value).toMatch(/^New-PSDrive/);
    expect(field("combobox", "Scheduled task runs as").value).toBe("MINILAB\\alice");
    expect(field("textbox", "Scheduled task name").value).toBe("connect_bot");
  });

  test("leaving the script drops its keys, and coming back restores them", () => {
    const seen = [];
    render(minilab({ seen }));
    const body = field("textbox", "Scheduled task script body").value;
    choose("logon");
    expect(sched(seen)).toEqual({ name: "connect_bot", interval_minutes: 1, user: "MINILAB\\alice" });
    choose("script");
    expect(sched(seen)).toMatchObject({ script_path: "C:\\bot.ps1", script_content: body, command: "& 'C:\\bot.ps1'" });
  });

  test("a new script gets a default path and runs it", () => {
    const seen = [];
    render(ticked({ seen }));
    choose("script");
    expect(sched(seen)).toEqual({ script_path: "C:\\schedule_bot.ps1", command: "& 'C:\\schedule_bot.ps1'" });
    fireEvent.change(field("textbox", "Scheduled task script body"), { target: { value: "whoami\n" } });
    expect(sched(seen).script_content).toBe("whoami\n");
    type("Scheduled task script path", "");
    expect(sched(seen)).toEqual({ script_content: "whoami\n" });
    expect(action().value).toBe("script");
    expect(row("Scheduled task").getByText("Set a script path, or the script is not written.")).toBeTruthy();
  });

  test("a task name another ticked bot uses is flagged", () => {
    render(ticked());
    expect(row("Scheduled task").queryByText(/so one replaces the other/)).toBeNull();
    type("Scheduled task name", "connect_bot");
    expect(row("Scheduled task").getByText(/connect_bot is also the logon bot's task/)).toBeTruthy();
  });

  test("findings at a schedule key show under the scheduled task", () => {
    const finding = { field: "vulns_vars.schedule.interval_minutes", severity: "error", message: "must be a whole number" };
    render(ticked({ findings: [finding] }));
    expect(row("Scheduled task").getByText("must be a whole number")).toBeTruthy();
    expect(within(json().closest(".rg-field")).queryByText("must be a whole number")).toBeNull();
  });
});

describe("read-only blueprints and accessibility", () => {
  test("a locked blueprint shows every activity disabled", () => {
    render(minilab({ readOnly: true }));
    const controls = document.querySelectorAll(".rg-activities input, .rg-activities select, .rg-activities textarea");
    expect(controls.length).toBeGreaterThan(5);
    for (const el of controls) expect(el.disabled, el.outerHTML).toBe(true);
  });

  test("every control has a name unique on the page", () => {
    const panels = [
      () => winterfell({ edit: (doc) => overlayOf(doc, "winterfell").vulns.push("schedule") }),
      () => minilab(),
    ];
    for (const make of panels) {
      const { container, unmount } = render(make());
      const all = [...container.querySelectorAll("input, select, textarea")].map((el) => computeAccessibleName(el));
      for (const el of container.querySelectorAll(".rg-activities input, .rg-activities select, .rg-activities textarea")) {
        const name = computeAccessibleName(el);
        expect(name, el.outerHTML).toBeTruthy();
        expect(all.filter((n) => n === name), name).toHaveLength(1);
      }
      unmount();
    }
  });

  test("each action's input has its own name", () => {
    render(winterfell({ edit: (doc) => overlayOf(doc, "winterfell").vulns.push("schedule") }));
    const names = new Set();
    for (const value of ["file", "share", "web", "custom"]) {
      choose(value);
      const input = action().parentElement.querySelector("input:not([type=number])");
      names.add(computeAccessibleName(input));
    }
    expect(names.size).toBe(4);
  });
});
