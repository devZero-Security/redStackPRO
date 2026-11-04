"""The canvas offers only the IANA zones Azure's shutdown schedule can take.
AZURE_TIMEZONES in frontend/src/azureTimezones.js must list exactly the keys of
_WINDOWS_TZ in redstackpro.terraform.azure, or the Topology settings panel
offers a zone the Azure compile refuses, or hides one it accepts.
"""

import json
import re
from pathlib import Path

from redstackpro.terraform.azure import _WINDOWS_TZ

ROOT = Path(__file__).resolve().parent.parent

_ZONE = re.compile(r'^  ("[A-Za-z_/]+"),$')


def _js_zones():
    lines = (ROOT / "frontend/src/azureTimezones.js").read_text(encoding="utf-8").splitlines()
    start = lines.index("export const AZURE_TIMEZONES = [")
    out = []
    for line in lines[start + 1:]:
        if line == "];":
            break
        m = _ZONE.match(line)
        assert m, "unexpected line in AZURE_TIMEZONES: %r" % line
        out.append(json.loads(m.group(1)))
    return out


def test_canvas_azure_zones_match_the_compiler_mapping():
    js = _js_zones()
    assert js, "found no zones in azureTimezones.js; the block drifted?"
    assert len(js) == len(set(js)), "duplicate zone in azureTimezones.js"
    assert set(js) == set(_WINDOWS_TZ)
