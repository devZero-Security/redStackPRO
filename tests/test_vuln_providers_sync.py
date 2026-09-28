"""The provider-applicability map for a gated vuln must agree on both sides: the
`providers` field in frontend/src/vulns.js (what greys the checkbox on the
canvas) and redstackpro.ansible.VULN_PROVIDERS (what the compiler actually
filters at generate time). A one-sided edit would silently desync what the
canvas promises from what a compile plants.
"""

import json
import re
from pathlib import Path

from redstackpro.ansible import VULN_PROVIDERS

ROOT = Path(__file__).resolve().parent.parent

# Every catalog entry is written on one line (id, label, blurb, goad[, providers]
# all on the same line), so a per-line regex scopes each match to its own entry
# without a JS parser.
_ENTRY = re.compile(r'id:\s*"([a-z0-9_]+)".*?providers:\s*(\[[^\]]*\])')


def _js_vuln_providers():
    src = (ROOT / "frontend/src/vulns.js").read_text(encoding="utf-8")
    out = {}
    for line in src.splitlines():
        m = _ENTRY.search(line)
        if m:
            out[m.group(1)] = tuple(json.loads(m.group(2)))
    return out


def test_provider_gating_matches_between_js_and_python():
    js = _js_vuln_providers()
    py = {k: tuple(v) for k, v in VULN_PROVIDERS.items()}
    assert js, "found no provider-restricted entries in vulns.js; regex drifted?"
    assert js == py
