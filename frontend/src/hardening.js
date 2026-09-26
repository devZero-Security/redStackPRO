// The catalog of defensive controls a range host can have applied (a host's
// overlay.hardening is a list of these ids).
//
// Same shape and same reason as vulns.js: the picker is data, so adding a
// control is a data change. Grouped, because nine checkboxes in one wrapped
// row is a wall with no order to it, and because the ids are opaque on their
// own -- `runasppl` and `asr` mean nothing to someone who has not met them.
//
// Each group carries a one-line `summary` saying what that family of controls
// buys you. That summary is what replaced a single run-on sentence in the
// schema description, which listed three of the nine ids and had to be read
// end to end to find any one of them.
//
// The ids here MUST match the schema enum at
// src/redstackpro/schema/topology/0.4.0.json -> $defs.overlay_range_host.properties.hardening;
// hardening.test.mjs reads the schema and holds this file to it, so a control
// added in one place cannot go missing from the other.

export const HARDENING_CATALOG = [
  {
    group: "Credential protection",
    summary: "Keep secrets in memory out of reach.",
    items: [
      {
        id: "runasppl",
        label: "runasppl",
        blurb: "Runs LSASS as a Protected Process Light, so an ordinary administrator cannot open it and read credentials out of memory.",
      },
      {
        id: "lsa_protection",
        label: "lsa_protection",
        blurb: "Turns on LSA protection, which blocks unsigned code from loading into the authentication subsystem.",
      },
      {
        id: "credential_guard",
        label: "credential_guard",
        blurb: "Isolates derived credentials in virtualisation-based security, so a pass-the-hash needs more than local admin.",
      },
    ],
  },
  {
    group: "Execution control",
    summary: "Limit what can run, and how.",
    items: [
      {
        id: "applocker",
        label: "applocker",
        blurb: "Allow-lists which executables and scripts may run, so dropping a binary is not enough to run it.",
      },
      {
        id: "constrained_powershell",
        label: "constrained_powershell",
        blurb: "Constrained Language Mode: PowerShell keeps working, but the .NET and COM calls most offensive tooling relies on stop being available.",
      },
      {
        id: "asr",
        label: "asr",
        blurb: "Defender Attack Surface Reduction rules, which block common execution routes such as Office spawning child processes.",
      },
    ],
  },
  {
    group: "Endpoint agent",
    summary: "Stop the agent being switched off.",
    items: [
      {
        id: "defender_tamper_protection",
        label: "defender_tamper_protection",
        blurb: "Stops Defender's own settings being disabled from the host, including by an administrator, so evasion has to work around it rather than turn it off.",
      },
    ],
  },
  {
    group: "Network protocols",
    summary: "Close the relay and poisoning routes.",
    items: [
      {
        id: "smb_signing",
        label: "smb_signing",
        blurb: "Requires SMB signing, which is what makes an SMB relay fail rather than land.",
      },
      {
        id: "llmnr_disabled",
        label: "llmnr_disabled",
        blurb: "Turns off LLMNR and NBT-NS name resolution, removing the broadcast fallback that responder-style poisoning answers.",
      },
    ],
  },
];

export const HARDENING_IDS = HARDENING_CATALOG.flatMap((g) => g.items.map((i) => i.id));
