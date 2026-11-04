"""The required vulns_vars keys must agree on both sides: VULN_PARAMS in
frontend/src/vulns.js (the Inspector help that says what to set) and
redstackpro.validate.VULNS_VARS_REQUIRED (what RNG011 warns about). A one-sided
edit would have the canvas call a key optional that the validator says plants
nothing without it, or the reverse.
"""

import re
from pathlib import Path

from redstackpro.validate import VULNS_VARS_REQUIRED

ROOT = Path(__file__).resolve().parent.parent

_VULN = re.compile(r"^  ([a-z0-9_]+): \[$")
_KEY = re.compile(r'\bkey:\s*"([a-z0-9_.]+)"')
_REQUIRED = re.compile(r"\brequired:\s*true\b")
_OR = re.compile(r'\bor:\s*"([a-z0-9_.]+)"')


def _js_vuln_params():
    """{vuln: {key: (required, alternatives)}} read from the VULN_PARAMS block,
    one key per line, the way vulns.js writes it."""
    lines = (ROOT / "frontend/src/vulns.js").read_text(encoding="utf-8").splitlines()
    start = lines.index("export const VULN_PARAMS = {")
    out, vuln = {}, None
    for line in lines[start + 1:]:
        if line == "};":
            break
        m = _VULN.match(line)
        if m:
            vuln = m.group(1)
            out[vuln] = {}
            continue
        k = _KEY.search(line)
        if k:
            alt = _OR.search(line)
            out[vuln][k.group(1)] = (bool(_REQUIRED.search(line)),
                                     alt.group(1) if alt else None)
    return out


def test_required_keys_match_between_js_and_python():
    js = _js_vuln_params()
    assert js, "found no VULN_PARAMS entries in vulns.js; the block drifted?"
    js_required = {}
    for vuln, keys in js.items():
        reqs = {frozenset({k} | ({alt} if alt else set()))
                for k, (required, alt) in keys.items() if required}
        if reqs:
            js_required[vuln] = reqs
    py_required = {vuln: {frozenset(alts) for alts in spec["keys"]}
                   for vuln, spec in VULNS_VARS_REQUIRED.items()}
    assert js_required == py_required


def test_every_vuln_the_validator_checks_has_help():
    js = _js_vuln_params()
    for vuln, spec in VULNS_VARS_REQUIRED.items():
        for alts in spec["keys"]:
            assert alts[0] in js.get(vuln, {}), (vuln, alts[0])
