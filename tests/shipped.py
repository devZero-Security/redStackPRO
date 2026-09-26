"""The shipped topologies, made compilable for tests.

Every example carrying a redirector arrives one field short on purpose: RDR001
refuses to compile until the operator sets a hostname, because a domain has to be
registered and pointed at the box by a human and nothing can invent one. Shipping a
plausible one is what let a placeholder ride all the way to a deploy that then asked
for an A record nobody could create.

So the examples stay one field short and tests fill that field here, which keeps the
rest of the suite testing the pipeline instead of re-testing RDR001. The tests that
assert the examples really do demand it live in test_validate.
"""

import json
from pathlib import Path

from redstackpro.authoring import set_redirector_hostname

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "src/redstackpro/schema/topology/examples/0.5.0"
HOSTNAME = "cdn.redops.design"


def deployable(doc):
    """Fill in the operator's one required field. Mutates and returns.

    The same call the CLI and CI make, so the suite cannot drift from what a person
    at the canvas would produce. See redstackpro.authoring.
    """
    return set_redirector_hostname(doc, HOSTNAME)


def load(path):
    return deployable(json.loads(Path(path).read_text(encoding="utf-8")))


def example(name):
    return load(EXAMPLES / name)
