import React, { useEffect, useMemo, useState } from "react";
import { api } from "./api.js";
import { FindingBadge } from "./FindingBadge.jsx";
import {
  PLATFORMS,
  PLATFORM_KEY,
  archiveName,
  defaultPlatform,
  extractFolder,
  providerSetup,
  requirements,
} from "./deployTarget.js";
import { labelFor } from "./providers.js";

// The export is the product. redStackPRO does not run anything, so what a person
// should be looking at is the code they are about to run themselves. Showing
// the topology next to the HCL it produces is the whole pitch. See 0001 and 0010.

const LANGUAGE = {
  tf: "hcl",
  tfvars: "hcl",
  yml: "yaml",
  yaml: "yaml",
  j2: "yaml",
  json: "json",
  md: "md",
  py: "py",
};

function languageOf(path) {
  return LANGUAGE[path.split(".").pop()] || "text";
}

// A deliberately small highlighter. A syntax library would be a dependency and
// a bundle for something that only has to make comments recede.
//
// One pass, because running the rules in sequence means a later rule matches
// the markup an earlier one inserted: the string rule happily wraps the "c" in
// class="c" and the output falls apart.
const TOKEN = new RegExp(
  [
    "(^|\\n)(\\s*(?:#|//)[^\\n]*)",           // comment to end of line
    '("(?:[^"\\\\]|\\\\.)*")',                    // quoted string
    "(&lt;&lt;tf:[^&]*&gt;&gt;)",              // unfilled address placeholder
    "\\b(resource|module|variable|output|provider|terraform|locals|data|true|false|null)\\b",
  ].join("|"),
  "g"
);

function highlight(text, language) {
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  if (language === "md" || language === "text") return escaped;

  return escaped.replace(
    TOKEN,
    (match, lead, comment, string, placeholder, keyword) => {
      if (comment !== undefined) return `${lead}<span class="c">${comment}</span>`;
      if (string !== undefined) return `<span class="s">${string}</span>`;
      if (placeholder !== undefined) return `<span class="p">${placeholder}</span>`;
      return `<span class="k">${keyword}</span>`;
    }
  );
}

function tree(paths) {
  const grouped = {};
  for (const path of paths) {
    const cut = path.lastIndexOf("/");
    const dir = cut === -1 ? "." : path.slice(0, cut);
    (grouped[dir] ||= []).push(path);
  }
  return Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b));
}

// deploy.tfvars leads: it is the one file a person has to edit before running.
export const PREFERRED = [
  "deploy.tfvars",
  "DEPLOYMENT-GUIDE.md",
  "terraform/main.tf",
  "ansible/inventory.yml",
];

// A command on its own line. One click selects all of it, ready to copy.
function Cmd({ children }) {
  return (
    <code className="rg-cmd" style={{ userSelect: "all" }}>
      {children}
    </code>
  );
}

// Field names as inline code, read as "a, b and c".
function FieldList({ fields }) {
  return fields.map((field, index) => (
    <React.Fragment key={field}>
      {index === 0 ? "" : index === fields.length - 1 ? " and " : ", "}
      <code>{field}</code>
    </React.Fragment>
  ));
}


export function ExportPanel({ document, provider }) {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(null);
  const [collapsed, setCollapsed] = useState({});
  // Remembered per browser: the machine someone deploys from is a property of
  // their desk, not of the topology, so it does not belong in the document.
  const [platform, setPlatform] = useState(() => {
    try {
      const saved = window.localStorage.getItem(PLATFORM_KEY);
      if (saved && PLATFORMS[saved]) return saved;
    } catch (err) {
      // Private windows and blocked site data both throw. Not worth a failure.
    }
    return defaultPlatform(navigator.platform || "");
  });

  const choosePlatform = (key) => {
    setPlatform(key);
    try {
      window.localStorage.setItem(PLATFORM_KEY, key);
    } catch (err) {
      // See above: the choice still applies for this session.
    }
  };

  useEffect(() => {
    if (!document.nodes.length) {
      setResult(null);
      return;
    }
    let cancelled = false;
    setBusy(true);
    api
      .compile(document, provider)
      .then((body) => {
        if (cancelled) return;
        setResult(body);
        setError(null);
        setOpen((current) => {
          const paths = body.files.map((f) => f.path);
          if (current && paths.includes(current)) return current;
          return PREFERRED.find((p) => paths.includes(p)) || paths[0];
        });
      })
      .catch((err) => {
        if (cancelled) return;
        setResult(null);
        setError(err);
      })
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [document, provider]);

  const files = useMemo(
    () => Object.fromEntries((result?.files || []).map((f) => [f.path, f.contents])),
    [result]
  );

  const download = async () => {
    const blob = await fetch(api.archiveUrl(result.compile_id)).then((r) => r.blob());
    const url = URL.createObjectURL(blob);
    const link = window.document.createElement("a");
    link.href = url;
    link.download = archiveName(document.name, provider, platform);
    link.click();
    URL.revokeObjectURL(url);
  };

  if (error) {
    const findings = (error.details?.findings || []).filter(
      (f) => f.severity === "error"
    );
    return (
      <aside className="rg-panel rg-export">
        <h2>Export</h2>
        <p className="rg-export-blocked">
          {findings.length
            ? "The compiler refuses to run on an invalid topology."
            : error.message}
        </p>
        {findings.map((finding, index) => (
          <p key={index} className="rg-finding is-error">
            <FindingBadge code={finding.code} /> {finding.message}
          </p>
        ))}
      </aside>
    );
  }

  if (!result) {
    return (
      <aside className="rg-panel rg-export">
        <h2>Export</h2>
        <p className={busy ? "rg-hint rg-loading" : "rg-hint"}>
          {busy ? "Compiling" : "Add a node to see the working directory."}
        </p>
      </aside>
    );
  }

  const bytes = result.files.reduce((total, f) => total + f.contents.length, 0);
  const setup = providerSetup(provider);
  const cloud = labelFor(provider);
  const target = PLATFORMS[platform];
  const folder = extractFolder(platform, document.name);
  const cli = setup.cli;
  // The panel says Windows, so the CLI install has to be the Windows one.
  const install = !cli ? null : platform === "windows" ? (
    <>
      Install the {cli.name} for Windows:
      <Cmd>{`winget install -e --id ${cli.winget}`}</Cmd>
      The install only updates PATH for new windows, so open a new PowerShell
      window in the export folder, then log in to {cloud}:
    </>
  ) : (
    <>
      Install the {cli.name} (
      <a href={cli.docs} target="_blank" rel="noreferrer">install steps</a>
      ), then log in to {cloud}:
    </>
  );

  return (
    <aside className="rg-panel rg-export">
      <div className="rg-export-head">
        <h2>Working directory</h2>
        <span className="rg-export-meta">
          {result.files.length} files, {(bytes / 1024).toFixed(0)} kB, {cloud}
        </span>
        <label className="rg-export-platform">
          Deploy from
          <select
            value={platform}
            onChange={(e) => choosePlatform(e.target.value)}
          >
            {Object.entries(PLATFORMS).map(([key, p]) => (
              <option key={key} value={key}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <button className="rg-primary" onClick={download}>
          Download ({cloud})
        </button>
      </div>

      <p className="rg-export-note">
        You apply it, under your credentials, on your machine.
      </p>

      <ol className="rg-export-steps">
        <li>
          Extract the zip to its own folder, for example <code>{folder}</code>.
          {target.pathNote ? ` ${target.pathNote}` : ""} Open {target.shell} in
          that folder; every step below runs from there:
          <Cmd>{`cd ${folder}`}</Cmd>
          Make a key:
          <Cmd>{target.keygen}</Cmd>
          The key lands in the export's keys folder. Keep the folder: status,
          stop, start and teardown run from it too.
        </li>
        <li>
          Open <code>deploy.tfvars</code> (in the export root) and set{" "}
          {setup.fields.length ? (
            <FieldList fields={setup.fields} />
          ) : (
            "the values it lists"
          )}
          . <code>ssh_public_key</code> can stay empty; deploy fills it
          from <code>keys/</code>.
        </li>
        <li>
          {setup.login?.length ? (
            <>
              {install || <>Log in to {cloud}:</>}
              {setup.login.map((cmd) => <Cmd key={cmd}>{cmd}</Cmd>)}
              {setup.altLogin?.length ? (
                <>
                  or, with an SSO profile:
                  {setup.altLogin.map((cmd) => <Cmd key={cmd}>{cmd}</Cmd>)}
                </>
              ) : null}
              {setup.loginNote || null}
            </>
          ) : (
            setup.loginNote || `Log in to ${cloud} the way its Terraform provider expects.`
          )}
        </li>
        <li>
          Then in {target.shell}:
          <Cmd>{target.run}</Cmd>
        </li>
      </ol>
      <p className="rg-export-note">
        {[requirements(platform, provider), target.note].filter(Boolean).join(" ")} Both scripts are
        in every download, so the same export deploys from either machine. After
        it is up, manage.sh (manage.ps1 on Windows) does status, stop, start, and
        teardown. DEPLOYMENT-GUIDE.md has the long version.</p>

      <div className="rg-export-split">
        <div className="rg-tree">
          {tree(result.files.map((f) => f.path)).map(([dir, paths]) => (
            <div key={dir}>
              <button
                className="rg-tree-dir"
                onClick={() =>
                  setCollapsed((c) => ({ ...c, [dir]: !c[dir] }))
                }
              >
                {collapsed[dir] ? "\u25b8" : "\u25be"} {dir}
              </button>
              {collapsed[dir]
                ? null
                : paths.map((path) => (
                    <button
                      key={path}
                      className={`rg-tree-file ${path === open ? "is-open" : ""}`}
                      onClick={() => setOpen(path)}
                    >
                      {path.split("/").pop()}
                    </button>
                  ))}
            </div>
          ))}
        </div>

        <div className="rg-code">
          <div className="rg-code-head">{open}</div>
          <pre className={`rg-code-body lang-${languageOf(open || "")}`}>
            <code
              dangerouslySetInnerHTML={{
                __html: highlight(files[open] || "", languageOf(open || "")),
              }}
            />
          </pre>
        </div>
      </div>
    </aside>
  );
}
