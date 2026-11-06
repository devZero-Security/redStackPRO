import assert from "node:assert/strict";
import {
  PLATFORMS, PROVIDER_SETUP, archiveName, defaultPlatform, extractFolder, requirements, slug,
} from "./deployTarget.js";

// What a download is called, and which machine it says to run it from.
//
// The name used to be the topology's title verbatim. The shipped example is called
// "redStack default blueprint", so it arrived as "redStack default
// blueprint.zip": spaces in a name that is about to be typed at a shell, and
// nothing in it to say which cloud it was built for, so two providers' exports
// of one topology were indistinguishable in a downloads folder.

// A name with spaces and capitals becomes one shell-safe word.
assert.equal(slug("redStack default blueprint"), "redstack-default-blueprint");
assert.equal(slug("Split  horizon -- C2!"), "split-horizon-c2");

// A name made entirely of punctuation still has to yield something usable:
// otherwise the download is called ".zip", which some browsers refuse outright.
assert.equal(slug("***"), "redstackpro");
assert.equal(slug(""), "redstackpro");
assert.equal(slug(undefined), "redstackpro");

// The three facts a person needs from the filename a week later.
assert.equal(
  archiveName("redStack default blueprint", "gcp", "windows"),
  "redstack-default-blueprint_gcp_windows.zip"
);
assert.equal(archiveName("GOAD-Light", "aws", "unix"), "goad-light_aws_macos-linux.zip");

// Two providers of one topology must not collide.
assert.notEqual(
  archiveName("Split horizon C2", "gcp", "unix"),
  archiveName("Split horizon C2", "aws", "unix")
);

// No name, for any platform or input, may contain whitespace.
for (const platform of Object.keys(PLATFORMS)) {
  for (const name of ["redStack default blueprint", "A B C", "  padded  "]) {
    assert.doesNotMatch(archiveName(name, "gcp", platform), /\s/,
      `${name} on ${platform}`);
  }
}

// An unknown platform falls back rather than naming the file "undefined".
assert.equal(archiveName("x", "gcp", "solaris"), "x_gcp_macos-linux.zip");

// Guessed from the browser, so the common case needs no choice at all.
assert.equal(defaultPlatform("Win32"), "windows");
assert.equal(defaultPlatform("MacIntel"), "unix");
assert.equal(defaultPlatform("Linux x86_64"), "unix");
assert.equal(defaultPlatform(""), "unix");

// Windows is pointed at the wrapper, never at bash. `bash deploy.sh` at a
// PowerShell prompt runs WSL's bash: a different filesystem, a different home,
// and usually different cloud credentials.
assert.equal(PLATFORMS.windows.run, ".\\deploy.ps1");
assert.match(PLATFORMS.windows.note, /WSL/);
assert.equal(PLATFORMS.unix.run, "bash deploy.sh");

// The scripts are unsigned. The note says so and stops there: no policy change
// or bypass is spelled out.
assert.match(PLATFORMS.windows.note, /unsigned, so PowerShell's execution policy has to allow them/);
assert.doesNotMatch(PLATFORMS.windows.note, /Bypass|Unblock-File|Set-ExecutionPolicy/);
assert.doesNotMatch(PLATFORMS.unix.note, /execution policy/);

// The keygen line is platform specific. Windows PowerShell 5.1 drops an empty
// argument to a native program, so -N '' or -N "" leaves -N with no value and
// ssh-keygen stops without writing a key. The Windows line leaves -N off and
// its note says to press Enter twice: the deploy needs a key with no passphrase.
assert.doesNotMatch(PLATFORMS.windows.keygen, /-N/,
  "Windows must not pass -N: PowerShell 5.1 drops the empty value");
assert.match(PLATFORMS.windows.keygenNote, /Enter twice/);
assert.match(PLATFORMS.unix.keygen, /-N ""/);
assert.notEqual(PLATFORMS.windows.keygen, PLATFORMS.unix.keygen);

// Everything the panel renders is present for every platform.
for (const [key, p] of Object.entries(PLATFORMS)) {
  for (const field of ["label", "file", "run", "shell", "folder", "needs", "keygen"]) {
    assert.ok(p[field], `${key}.${field} is missing`);
  }
}

// keys\ in the keygen line is relative, so the example folder is where every
// step runs. Named like the download, so it is shell safe.
// Generic on purpose: the example never carries the topology's name.
assert.equal(extractFolder("windows"), "C:\\redstackpro\\my-range");
assert.equal(extractFolder("unix"), "~/redstackpro/my-range");
assert.doesNotMatch(extractFolder("windows"), /'/);

// The cloud CLI is a requirement, and on Windows it is the Windows build.
assert.equal(
  requirements("windows", "azure"),
  "Needs terraform, Git for Windows (for ssh, tar and Git Bash), Python 3.8 or newer and the Azure CLI for Windows."
);
assert.equal(
  requirements("unix", "azure"),
  "Needs terraform, ssh, tar, Python 3.8 or newer and the Azure CLI."
);
assert.equal(requirements("unix", "proxmox"), "Needs terraform, ssh, tar and Python 3.8 or newer.");
assert.equal(requirements("unix", "esxi"), "Needs terraform, ssh, tar and Python 3.8 or newer.");
for (const [provider, setup] of Object.entries(PROVIDER_SETUP)) {
  if (!setup.cli) continue;
  for (const field of ["name", "bin", "winget", "docs"]) {
    assert.ok(setup.cli[field], `${provider}.cli.${field} is missing`);
  }
  assert.match(setup.cli.docs, /^https:\/\//);
  // The login commands run the binary the install step puts on PATH.
  for (const cmd of setup.login) assert.ok(cmd.startsWith(`${setup.cli.bin} `), cmd);
}
assert.equal(PROVIDER_SETUP.azure.cli.winget, "Microsoft.AzureCLI");
assert.equal(PROVIDER_SETUP.gcp.cli.winget, "Google.CloudSDK");
assert.equal(PROVIDER_SETUP.aws.cli.winget, "Amazon.AWSCLI");
assert.equal(PROVIDER_SETUP.proxmox.cli, undefined);
assert.equal(PROVIDER_SETUP.esxi.cli, undefined);

console.log("deployTarget.test.mjs: all passed");
