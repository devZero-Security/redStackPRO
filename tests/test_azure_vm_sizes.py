"""Azure VM sizes are a per-role default the operator can override per role.

Which sizes a subscription may allocate varies widely (one live subscription
could use no v5 size at all in eastus2), so a hardcoded size per host meant
hand-editing the generated main.tf mid-apply. The size now reads from a merged
map: the built-in defaults for the roles in the topology, overridden by
var.vm_sizes from deploy.tfvars.
"""

import json
import re
import shutil
import subprocess

import pytest

from redstackpro import Registry
from redstackpro.terraform import TerraformPlan, azure, generate

from shipped import ROOT, load

GOAD = ROOT / "frontend/public/goad/goad.json"


def _kinds(doc):
    return {n["kind"] for n in doc["nodes"] if n["kind"] in azure.DEFAULT_MACHINE}


def _defaults(doc):
    return azure.default_vm_sizes(TerraformPlan(doc, Registry(), "azure"))


def _host_modules(main):
    """{module label: {attribute: raw value}} for every host module, by regex so
    the check does not depend on how fmt aligned the block."""
    out = {}
    for label, body in re.findall(r'^module "(\w+)" \{\n(.*?)^\}', main, flags=re.M | re.S):
        attrs = dict(re.findall(r"^\s*(\w+)\s*=\s*(.+)$", body, flags=re.M))
        if attrs.get("source") == '"./modules/azure/host"':
            out[label] = attrs
    return out


def test_each_host_reads_its_size_from_the_merged_role_map(redstack):
    out = generate(redstack, provider="azure")
    main, variables = out["terraform/main.tf"], out["terraform/variables.tf"]
    assert "vm_sizes = merge(local.default_vm_sizes, var.vm_sizes)" in main
    hosts = _host_modules(main)
    assert hosts
    for attrs in hosts.values():
        assert attrs["size"] == 'local.vm_sizes[%s]' % attrs["kind"]
    assert re.search(r'variable "vm_sizes" \{\s*\n\s*description\s*=.*\n\s*type\s*=\s*map\(string\)'
                     r'\s*\n\s*default\s*=\s*\{\}', variables)


def test_the_defaults_cover_exactly_the_roles_in_the_topology(redstack):
    main = generate(redstack, provider="azure")["terraform/main.tf"]
    block = re.search(r"default_vm_sizes = \{\n(.*?)\n  \}", main, flags=re.S).group(1)
    defaults = dict(re.findall(r'(\w+)\s*=\s*"([^"]+)"', block))
    assert set(defaults) == _kinds(redstack)
    # The v5 defaults are kept; only the override is new.
    assert all(defaults[k] == azure.DEFAULT_MACHINE[k] for k in defaults)


def test_a_range_keeps_its_burstable_workstation_and_dc_defaults():
    doc = load(GOAD)
    sizes = _defaults(doc)
    assert set(sizes) == _kinds(doc)
    assert sizes["dc"] == "Standard_D2as_v5"
    if "wks" in sizes:
        assert sizes["wks"] == "Standard_B2as_v2"


def test_tfvars_ships_a_commented_example_of_every_role_with_its_default(redstack):
    tfvars = generate(redstack, provider="azure")["terraform/terraform.tfvars"]
    # Commented out: an unset map keeps every default.
    assert not re.search(r"^vm_sizes", tfvars, flags=re.M)
    block = re.search(r"^# vm_sizes = \{\n(.*?)^# \}", tfvars, flags=re.M | re.S)
    assert block, tfvars
    listed = dict(re.findall(r'^#\s+(\w+)\s+=\s+"([^"]+)"', block.group(1), flags=re.M))
    assert listed == _defaults(redstack)


def test_gcp_and_aws_are_untouched(redstack):
    for provider in ("gcp", "aws"):
        out = generate(redstack, provider=provider)
        assert "vm_sizes" not in out["terraform/main.tf"]
        assert "vm_sizes" not in out["terraform/variables.tf"]


@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not on PATH")
@pytest.mark.parametrize("override", [{}, {"jumpbox": "Standard_D2as_v7"}])
def test_a_partial_override_changes_only_the_roles_it_names(redstack, tmp_path, override):
    """Evaluated by terraform itself: the generated locals and variable, with a
    tfvars naming one role, resolve to the defaults with only that role changed."""
    out = generate(redstack, provider="azure")
    locals_block = re.search(r"^locals \{\n  default_vm_sizes = \{.*?^\}\n",
                             out["terraform/main.tf"], flags=re.M | re.S).group(0)
    variable = re.search(r'^variable "vm_sizes" \{.*?^\}\n',
                         out["terraform/variables.tf"], flags=re.M | re.S).group(0)
    (tmp_path / "main.tf").write_text(variable + locals_block, encoding="utf-8")
    body = "".join('  %s = "%s"\n' % kv for kv in override.items())
    (tmp_path / "terraform.tfvars").write_text("vm_sizes = {\n%s}\n" % body,
                                              encoding="utf-8")
    done = subprocess.run(["terraform", "console"], cwd=tmp_path,
                          input="jsonencode(local.vm_sizes)\n",
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    merged = json.loads(json.loads(done.stdout.strip().splitlines()[-1]))
    assert merged == dict(_defaults(redstack), **override)
