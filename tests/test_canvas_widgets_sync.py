"""Two canvas tables mirror backend sources and must not drift from them.

- ROLE_ENDPOINTS and HOST_KINDS in frontend/src/edgeRoles.js decide which line
  roles the Inspector offers between two node kinds. They must match the drawn
  roles in the registry (roles.yaml, kinds/*.yaml).
- ACL_RIGHTS in frontend/src/AclEditor.jsx is the rights dropdown. Every right
  it offers must be one apply_acls.ps1 applies or an alias the compiler maps,
  and every right the script applies must be offered.
"""

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "src/redstackpro/schema/registry"
DRAWN = {"fronts", "logs_to", "peers", "trusts"}
ALIASES = {"ForceChangePassword", "AddMember"}


def _js_block(path, header, line_re):
    lines = path.read_text(encoding="utf-8").splitlines()
    start = lines.index(header)
    out = []
    for line in lines[start + 1:]:
        if line in ("};", "];"):
            break
        m = line_re.match(line)
        assert m, "unexpected line in %s: %r" % (header, line)
        out.append(m)
    return out


def test_edge_role_endpoints_match_the_registry():
    js_path = ROOT / "frontend/src/edgeRoles.js"
    rows = _js_block(js_path, "export const ROLE_ENDPOINTS = {",
                     re.compile(r"^  ([a-z_]+): (\[.*\]),$"))
    js = {m.group(1): sorted(map(tuple, json.loads(m.group(2)))) for m in rows}

    roles = yaml.safe_load((REGISTRY / "roles.yaml").read_text(encoding="utf-8"))["roles"]
    reg = {r["role"]: sorted((e["source"], e["target"]) for e in r["endpoints"])
           for r in roles if r["role"] in DRAWN}
    assert js == reg

    host_line = next(line for line in js_path.read_text(encoding="utf-8").splitlines()
                     if line.startswith("export const HOST_KINDS = "))
    js_hosts = set(json.loads(host_line.split("=", 1)[1].strip().rstrip(";")))
    reg_hosts = set()
    for f in (REGISTRY / "kinds").glob("*.yaml"):
        spec = yaml.safe_load(f.read_text(encoding="utf-8"))
        if spec.get("category") == "host":
            reg_hosts.add(spec["kind"])
    assert js_hosts == reg_hosts


def test_acl_rights_dropdown_matches_apply_acls():
    rows = _js_block(ROOT / "frontend/src/AclEditor.jsx", "export const ACL_RIGHTS = [",
                     re.compile(r'^  \{ value: "([A-Za-z-]+)", '))
    offered = {m.group(1) for m in rows}
    script = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.dc/files/"
              "apply_acls.ps1").read_text(encoding="utf-8")
    known = set(re.findall(r'^\s+"([A-Za-z-]+)"\s*=', script, re.MULTILINE))
    assert known, "found no rights in apply_acls.ps1; the tables drifted?"
    assert offered - ALIASES <= known, offered - ALIASES - known
    assert known <= offered, known - offered
