// The machine an operator deploys FROM, and what a download should be called.
//
// Deploying from is not the same question as deploying to: the provider is a
// property of the topology, the machine is a property of the person's desk. Both
// deploy scripts ship in every export -- deploy.ps1 is a wrapper around the same
// deploy.sh, not a second implementation -- so this choice picks which
// instructions to show and what the file is named, and never changes what is
// inside it. An export that only ran on the machine its author happened to pick
// would be a worse product, not a better-tailored one.

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
    note: "Run it from PowerShell. Not `bash deploy.sh` there: that is WSL's bash, not Git Bash.",
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
    note: "Needs terraform, ssh, tar and a Python 3.8+, which you almost certainly have.",
    keygen: 'ssh-keygen -t ed25519 -f keys/id_ed25519 -N ""',
  },
};

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
