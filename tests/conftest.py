import json
from pathlib import Path

import pytest

from shipped import EXAMPLES, example  # noqa: F401  (EXAMPLES is re-exported)

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def minimal():
    return example("minimal.json")


@pytest.fixture
def redstack():
    return example("redstack.json")


@pytest.fixture
def rollover(redstack):
    """redstack.json ships a single redirector, because that is the familiar
    redStack shape. The rollover pool of a second is reconstructed here to keep
    the multi-redirector codegen under test without shipping it as a worked
    example."""
    doc = json.loads(json.dumps(redstack))
    doc["nodes"].append({
        "id": "apache-rd02",
        "kind": "redirector",
        "overlay": {
            "server": "apache",
            # A rollover pool is several front doors for one teamserver, so this one
            # carries its own name. The gating value stays blank: FRT001 compares the
            # pool's values to each other and the compiler rolls one token for the
            # whole pool, so blank on both is the consistent state.
            "hostname": "assets.redops.design",
            "tls": {"cert_source": "letsencrypt"},
            "gating": {
                "header_name": "X-Request-Id",
                "header_value": "",
                "redirect_rules": True,
                "decoy": "cdn",
            },
        },
    })
    doc["edges"].extend([
        {"id": "e-apache-rd02-rdir-sub01-attached", "role": "attached",
         "source": "apache-rd02", "target": "rdir-sub01"},
        {"id": "e-apache-rd02-myth-ts01-fronts", "role": "fronts",
         "source": "apache-rd02", "target": "myth-ts01", "protocol": "https",
         "listen_port": 443, "upstream_port": 443, "uri_prefix": "/api/v1"},
        {"id": "e-apache-rd02-sliv-ts01-fronts", "role": "fronts",
         "source": "apache-rd02", "target": "sliv-ts01", "protocol": "https",
         "listen_port": 443, "upstream_port": 443, "uri_prefix": "/cdn/assets"},
        {"id": "e-apache-rd02-adpx-ts01-fronts", "role": "fronts",
         "source": "apache-rd02", "target": "adpx-ts01", "protocol": "https",
         "listen_port": 443, "upstream_port": 443, "uri_prefix": "/updates"},
        {"id": "e-apache-rd02-open-log01-logs-to", "role": "logs_to",
         "source": "apache-rd02", "target": "open-log01"},
    ])
    return doc


@pytest.fixture
def registry():
    from redstackpro import Registry
    return Registry(ROOT / "src/redstackpro/schema/registry")


@pytest.fixture
def parallel_chains():
    return example("parallel-chains.json")


@pytest.fixture
def peered():
    return example("peered.json")
