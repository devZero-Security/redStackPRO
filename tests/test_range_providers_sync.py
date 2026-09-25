"""Which providers can build a native defense range must have exactly one answer.

It had two, and they disagreed. `redstackpro.export.RANGE_PROVIDERS` has named
five since the native range landed, while the canvas toolbar carried a literal
["aws", "gcp", "azure", "proxmox"] -- so esxi was a target the compiler accepted
and the canvas would not offer, which is the same shape as the goad-wazuh
template that shipped without a line in the picker.

The canvas now derives the list from the registry: a provider hosts a range iff
it declares `windows_image`, which is the criterion export.py already states in
prose ("every native backend knows the Windows host kinds"). This pins that
derivation to the tuple, so adding a provider on one side and not the other
fails here rather than on someone's deploy.

Sibling of test_vuln_providers_sync, for the same reason.
"""

import re
from pathlib import Path

from redstackpro.export import RANGE_PROVIDERS
from redstackpro.registry import Registry

ROOT = Path(__file__).resolve().parent.parent

CAPABILITY = "windows_image"


def test_range_providers_are_exactly_those_with_a_windows_image():
    registry = Registry()
    derived = {name for name in registry.providers
               if CAPABILITY in registry.capabilities(name)}
    assert derived == set(RANGE_PROVIDERS)


def test_the_canvas_derives_the_list_rather_than_hardcoding_it():
    """The literal list is what drifted. If one comes back, say so here."""
    src = (ROOT / "frontend/src/providers.js").read_text(encoding="utf-8")
    assert CAPABILITY in src, "providers.js no longer derives from the capability"

    toolbar = (ROOT / "frontend/src/App.jsx").read_text(encoding="utf-8")
    hardcoded = re.search(
        r'\[\s*"(?:aws|gcp|azure|proxmox|esxi)"\s*,\s*"(?:aws|gcp|azure|proxmox|esxi)"',
        toolbar)
    assert not hardcoded, (
        "App.jsx carries a literal provider list again; derive it from the "
        "registry through providers.js instead")


def test_only_the_deployment_proven_backends_claim_to_be():
    """Michael 2026-09-13: "I only plan to demo on gcp and aws, the other
    providers are just placeholders for now." The canvas greys the rest, so this
    pins which two claim otherwise -- a backend quietly promoting itself would
    put an unproven target in front of a customer.
    """
    registry = Registry()
    proven = {n for n, s in registry.providers.items()
              if s.get("maturity") == "proven"}
    assert proven == {"aws", "gcp"}


def test_a_provider_that_declares_no_maturity_is_treated_as_preview():
    """Claiming proven by omission is the wrong way round: a backend added
    tomorrow should not present itself as deployment-proven because someone
    forgot a line. The endpoint defaults it, so assert the default's direction.
    """
    from redstackpro.api import routes
    import inspect as _inspect
    src = _inspect.getsource(routes.get_providers)
    assert '"maturity", "preview"' in src.replace("'", '"')
