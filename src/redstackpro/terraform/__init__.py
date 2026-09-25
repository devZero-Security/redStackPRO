"""Terraform generation.

Nodes become module blocks calling static modules. Edges become generated code,
because a firewall rule permitting 443 from one host to another exists only
because someone drew a line. See 0015.

One backend per provider. What they share is the plan and the outputs; what they
do not share is the firewall, which 0015 names as the place the provider
abstraction leaks.

The compiler never emits credentials or key material, only variables. See 0001.
"""

from ..validate import is_valid
from . import aws, azure, esxi, gcp, proxmox
from .plan import HOST_KINDS, GenerationError, TerraformPlan, outputs

BACKENDS = {
    "gcp": gcp,
    "aws": aws,
    "proxmox": proxmox,
    "azure": azure,
    "esxi": esxi,
}

__all__ = ["generate", "GenerationError", "TerraformPlan", "HOST_KINDS",
           "BACKENDS"]


def generate(topology, registry=None, provider="gcp", skip_validation=False,
             region=None):
    """Returns {path: contents} for the Terraform half of a compile file map."""
    backend = BACKENDS.get(provider)
    if backend is None:
        raise GenerationError(
            "no terraform backend for %r; have %s"
            % (provider, ", ".join(sorted(BACKENDS))))

    if not skip_validation and not is_valid(topology, provider=provider,
                                            registry=registry):
        raise GenerationError(
            "topology has validation errors; the compiler refuses to run")

    plan = TerraformPlan(topology, registry, provider, region)
    files = backend.files(plan)
    files["terraform/outputs.tf"] = outputs(plan)
    return files
