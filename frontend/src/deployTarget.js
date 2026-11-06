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
    // keys\ in the keygen line is relative, so every step runs from here.
    folder: "C:\\redstackpro\\my-range",
    // deploy.ps1 hands its own folder to Git Bash inside single quotes.
    pathNote: "The path must not contain an apostrophe: deploy.ps1 cannot run from one.",
    needs: ["terraform", "Git for Windows (for ssh, tar and Git Bash)", "Python 3.8 or newer"],
    // The one trap worth spending a line on. `bash` at a PowerShell prompt is
    // C:\Windows\System32\bash.exe, the WSL launcher, so the deploy runs in a
    // different filesystem with a different home and different cloud
    // credentials, and fails for reasons that look nothing like the cause.
    note: "Run it from PowerShell. Not bash deploy.sh there: that is WSL's bash, not Git Bash. " +
      "deploy.ps1 and manage.ps1 are unsigned, so PowerShell's execution policy has to allow them.",
    // Windows PowerShell 5.1 drops an empty argument, so -N '' leaves -N with no
    // value and ssh-keygen stops. No -N plus Enter twice works on 5.1 and 7. The
    // key must have no passphrase: deploy.sh uses BatchMode.
    keygen: "ssh-keygen -t ed25519 -f keys\\id_ed25519",
    keygenNote: "Press Enter twice when it asks for a passphrase: the deploy needs a key without one.",
  },
  unix: {
    label: "macOS / Linux",
    file: "macos-linux",
    run: "bash deploy.sh",
    shell: "a terminal",
    folder: "~/redstackpro/my-range",
    needs: ["terraform", "ssh", "tar", "Python 3.8 or newer"],
    note: "",
    keygen: 'ssh-keygen -t ed25519 -f keys/id_ed25519 -N ""',
  },
};

// "a, b and c"
function listed(items) {
  if (items.length < 2) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

// The cloud CLI is on the list because deploy.sh checks the login with it and
// manage.sh runs status, stop, start and teardown through it.
export function requirements(platform, provider) {
  const target = PLATFORMS[platform] || PLATFORMS.unix;
  const cli = providerSetup(provider).cli;
  const needs = [...target.needs];
  if (cli) needs.push(platform === "windows" ? `the ${cli.name} for Windows` : `the ${cli.name}`);
  return `Needs ${listed(needs)}.`;
}

// An example folder to extract into. Generic on purpose, not the topology's name.
export function extractFolder(platform) {
  return (PLATFORMS[platform] || PLATFORMS.unix).folder;
}

// What to set in deploy.tfvars and how to log in, per provider. Field names
// match terraform/<provider>.py. ssh_public_key is left out on purpose: deploy.sh
// fills it from keys/ when it is empty. cli.winget ids are checked with
// `winget show`; keep CLI_INSTALL in export.py in step.
export const PROVIDER_SETUP = {
  gcp: {
    fields: ["project", "region", "zone", "operator_source_ranges"],
    cli: {
      name: "Google Cloud CLI",
      bin: "gcloud",
      winget: "Google.CloudSDK",
      docs: "https://cloud.google.com/sdk/docs/install",
    },
    login: [
      "gcloud auth login",
      "gcloud auth application-default login",
      "gcloud services enable compute.googleapis.com --project <your-project-id>",
    ],
    loginNote: "Run all three: Terraform reads the application default login, manage.sh uses the other, and the last turns on the Compute Engine API, which a new project has off.",
  },
  aws: {
    fields: ["region", "operator_source_ranges"],
    cli: {
      name: "AWS CLI",
      bin: "aws",
      winget: "Amazon.AWSCLI",
      docs: "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
    },
    login: ["aws configure"],
    altLogin: ["aws sso login"],
    loginNote: "Credentials come from your AWS CLI profile, not deploy.tfvars. Set AWS_PROFILE to pick a profile.",
  },
  azure: {
    fields: ["subscription_id", "location", "operator_source_ranges"],
    fieldsNote: "resource_group is created by the deploy: keep the generated name, or pick one that does not exist yet.",
    cli: {
      name: "Azure CLI",
      bin: "az",
      winget: "Microsoft.AzureCLI",
      docs: "https://learn.microsoft.com/cli/azure/install-azure-cli",
    },
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
