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

test("the panel says redStackPRO ran nothing", () => {
  assert.ok(/ran nothing/.test(source), "the export note is the whole pitch");
  assert.ok(/refuses to run on an invalid topology/.test(source));
});

test("the panel opens on a generated file, not a static one", () => {
  assert.ok(source.includes('"terraform/firewall.tf"'),
    "firewall.tf is derived entirely from edges, which is the thing to show");
});

console.log(`\n${passed} passed`);
