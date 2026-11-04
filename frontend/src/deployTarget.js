// The machine an operator deploys FROM, and what a download should be called.
//
// Deploying from is not the same question as deploying to: the provider is a
// property of the topology, the machine is a property of the person's desk. Both
// deploy scripts ship in every export -- deploy.ps1 is a wrapper around the same
// deploy.sh, not a second implementation -- so this choice picks which
// instructions to show and what the file is named, and never changes what is
// inside it. An export that only ran on the machine its author happened to pick
// would be a worse product, not a better-tailored one.

import { providersFor, resolveProvider } from "./providers.js";

// The deploy target a document compiles for: the provider saved in it when this
// mode can build that one (or before the registry has answered), otherwise the
// session's choice. Either way resolved to one the mode offers.
export function targetFor(mode, providers, saved, chosen) {
  const usable = saved && (!providers.length || providersFor(mode, providers).includes(saved));
  return resolveProvider(mode, providers, usable ? saved : chosen);
}

export const PLATFORMS = {
  windows: {
    label: "Windows",
    file: "windows",
    run: ".\\deploy.ps1",
    shell: "PowerShell",
    // The one trap worth spending a line on. `bash` at a PowerShell prompt is
    // C:\Windows\System32\bash.exe, the WSL launcher, so the deploy runs in a
    // different filesystem with a different home and different cloud
    // credentials, and fails for reasons that look nothing like the cause.
    note: "Needs terraform, Git for Windows (for ssh, tar and Git Bash) and Python 3.8 or newer. Run it from PowerShell. Not `bash deploy.sh` there: that is WSL's bash, not Git Bash.",
    // PowerShell passes -N "" through as two literal quote characters, so the
    // key ends up with a passphrase of `""`. Nothing complains until the deploy
    // fails minutes later with Permission denied (publickey) from the jumpbox.
    keygen: "ssh-keygen -t ed25519 -f keys\\id_ed25519 -N ''",
  },
  unix: {
    label: "macOS / Linux",
    file: "macos-linux",
    run: "bash deploy.sh",
    shell: "a terminal",
    note: "Needs terraform, ssh, tar and Python 3.8 or newer.",
    keygen: 'ssh-keygen -t ed25519 -f keys/id_ed25519 -N ""',
  },
};

// What to set in deploy.tfvars and how to log in, per provider. Field names
// match terraform/<provider>.py. ssh_public_key is left out on purpose: deploy.sh
// fills it from keys/ when it is empty.
export const PROVIDER_SETUP = {
  gcp: {
    fields: ["project", "region", "zone", "operator_source_ranges"],
    login: ["gcloud auth login", "gcloud auth application-default login"],
    loginNote: "Run both: Terraform reads the application default login, manage.sh uses the other.",
  },
  aws: {
    fields: ["region", "operator_source_ranges"],
    login: ["aws configure"],
    altLogin: ["aws sso login"],
    loginNote: "Credentials come from your AWS CLI profile, not deploy.tfvars. Set AWS_PROFILE to pick a profile.",
  },
  azure: {
    fields: ["subscription_id", "location", "resource_group", "operator_source_ranges"],
    login: ["az login"],
  },
  proxmox: {
    fields: [
      "proxmox_endpoint", "proxmox_api_token", "proxmox_node", "proxmox_datastore",
      "proxmox_bridge", "operator_source_ranges",
    ],
    loginNote: "No login step: the API token in deploy.tfvars is the credential.",
  },
  esxi: {
    fields: [
      "vsphere_server", "vsphere_user", "vsphere_password", "datastore",
      "resource_pool", "esxi_host",
    ],
    loginNote: "No login step: the vSphere user and password in deploy.tfvars are the credential.",
  },
};

export function providerSetup(provider) {
  return PROVIDER_SETUP[provider] || { fields: [], login: [] };
}

export const PLATFORM_KEY = "redstackpro.deployPlatform";

export function defaultPlatform(platformString = "") {
  return platformString.startsWith("Win") ? "windows" : "unix";
}

// A file name that is still meaningful in a downloads folder a week later: what
// it is, where it goes, and what it will be run from. The name used to be the
// topology's title verbatim, so the shipped example arrived as
// "redStack default blueprint.zip" -- spaces and all, and byte-identical in name
// whichever provider it was built for.
export function slug(text) {
  return (
    (text || "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "redstackpro"
  );
}

export function archiveName(name, provider, platform) {
  const target = PLATFORMS[platform] || PLATFORMS.unix;
  return `${slug(name)}_${slug(provider)}_${target.file}.zip`;
}
