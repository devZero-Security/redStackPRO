import assert from "node:assert/strict";
import { PLATFORMS, archiveName, defaultPlatform, slug } from "./deployTarget.js";

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

// The keygen line is platform specific, and this is not cosmetic. PowerShell
// passes -N "" through as two literal quote characters, so the key is created
// with a passphrase of `""`. Nothing complains at the time; the deploy fails
// minutes later with Permission denied (publickey) from the jumpbox. Found by
// running the bash form at a PowerShell prompt on a live deploy.
assert.match(PLATFORMS.windows.keygen, /-N ''/,
  "Windows must use single quotes for an empty passphrase");
assert.doesNotMatch(PLATFORMS.windows.keygen, /-N ""/);
assert.match(PLATFORMS.unix.keygen, /-N ""/);
assert.notEqual(PLATFORMS.windows.keygen, PLATFORMS.unix.keygen);

// Everything the panel renders is present for every platform.
for (const [key, p] of Object.entries(PLATFORMS)) {
  for (const field of ["label", "file", "run", "shell", "note", "keygen"]) {
    assert.ok(p[field], `${key}.${field} is missing`);
  }
}

console.log("deployTarget.test.mjs: all passed");
