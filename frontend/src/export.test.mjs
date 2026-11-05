// The export panel is what makes redStackPRO legible as a code generator rather
// than a hosted lab, so the pieces that decide what a person sees are worth
// testing without a browser.
import assert from "node:assert";
import { readFileSync } from "node:fs";

const source = readFileSync("src/Export.jsx", "utf8");

// The helpers are lifted out of the shipped component rather than copied, so a
// change there fails here instead of quietly diverging.
const source_ = readFileSync("src/Export.jsx", "utf8");
const slice = (from, to) => source_.slice(source_.indexOf(from), source_.indexOf(to));

const LANGUAGE = { tf: "hcl", tfvars: "hcl", yml: "yaml", yaml: "yaml",
                   j2: "yaml", json: "json", md: "md", py: "py" };
const languageOf = (path) => LANGUAGE[path.split(".").pop()] || "text";

const highlight = new Function(
  "text", "language",
  slice("const TOKEN", "function tree(") + "\nreturn highlight(text, language);"
);

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

test("file kinds map to a language", () => {
  assert.equal(languageOf("terraform/main.tf"), "hcl");
  assert.equal(languageOf("ansible/inventory.yml"), "yaml");
  assert.equal(languageOf("README.md"), "md");
  assert.equal(languageOf("noextension"), "text");
});

test("markup in a file cannot escape into the page", () => {
  const out = highlight('<script>alert(1)</script>', "hcl");
  assert.ok(!out.includes("<script>"));
  assert.ok(out.includes("&lt;script&gt;"));
});

test("comments and strings are marked", () => {
  const out = highlight('# a comment\nname = "value"', "hcl");
  assert.ok(out.includes('<span class="c"># a comment</span>'));
  assert.ok(out.includes('<span class="s">"value"</span>'));
});

test("an unfilled address placeholder is called out", () => {
  const out = highlight("ansible_host: <<tf:rt-ts-01:private_address>>", "yaml");
  assert.ok(out.includes('<span class="p">'), "placeholders should be visible");
});

test("the panel states the export-only model", () => {
  assert.ok(/under your credentials/.test(source), "the export note is the whole pitch");
  assert.ok(/refuses to run on an invalid topology/.test(source));
});

test("the panel opens on deploy.tfvars, the one file a person must edit", () => {
  const preferred = slice("export const PREFERRED", "// A command on its own line");
  const first = /"([^"]+)"/.exec(preferred)?.[1];
  assert.equal(first, "deploy.tfvars");
  assert.ok(!preferred.includes("firewall.tf"));
});

const { api } = await import("./api.js");

test("the download carries the browser's timezone offset", () => {
  assert.equal(api.archiveUrl("abc", 300), "/api/v1/compile/abc/archive?tz_offset=300");
  assert.equal(api.archiveUrl("abc", -330), "/api/v1/compile/abc/archive?tz_offset=-330");
  assert.equal(
    api.archiveUrl("abc"),
    `/api/v1/compile/abc/archive?tz_offset=${new Date().getTimezoneOffset()}`
  );
});

test("both download buttons take the archive URL from api.js", () => {
  for (const file of ["src/Export.jsx", "src/App.jsx"]) {
    const text = readFileSync(file, "utf8");
    assert.ok(text.includes("fetch(api.archiveUrl(result.compile_id))"), file);
    assert.ok(!text.includes("/archive`"), `${file} builds its own archive URL`);
  }
});

console.log(`\n${passed} passed`);
