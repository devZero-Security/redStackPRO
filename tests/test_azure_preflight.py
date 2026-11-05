"""The Azure preflight deploy.sh runs between terraform init and apply.

Every check here runs against stubbed ARM responses shaped like the live ones
(Compute SKUs with restrictions, Compute and Network usages, provider state), on
a real compiled export, so the manifest and tfvars it reads are the shipped ones.
"""

import json
import re
import subprocess

import pytest

from redstackpro import Registry
from redstackpro.export import compile_topology
from redstackpro.tools import azure_preflight as ap

from shipped import ROOT, example, load

SUB = "11111111-2222-3333-4444-555555555555"
SECRET = "sp-secret-never-printed"
TOKEN = "arm-token-never-printed"
SP_ENV = {"ARM_CLIENT_ID": "cid", "ARM_CLIENT_SECRET": SECRET,
          "ARM_TENANT_ID": "tid", "ARM_SUBSCRIPTION_ID": SUB}
NOT_FOR_SUB = [{"type": "Location", "values": ["eastus2"],
                "restrictionInfo": {"locations": ["eastus2"]},
                "reasonCode": "NotAvailableForSubscription"}]


def sku(name, family, vcpus=2, memory=8, restrictions=(), gen="V1,V2"):
    return {"resourceType": "virtualMachines", "name": name, "family": family,
            "locations": ["eastus2"], "restrictions": list(restrictions),
            "capabilities": [{"name": "vCPUs", "value": str(vcpus)},
                             {"name": "MemoryGB", "value": str(memory)},
                             {"name": "HyperVGenerations", "value": gen}]}


def usage(value, current, limit, label=None):
    return {"name": {"value": value, "localizedValue": label or value},
            "currentValue": current, "limit": limit}


class FakeArm:
    """ARM and the token endpoint, keyed on the URL. Records every call."""

    def __init__(self, skus=None, compute=None, network=None, providers=None,
                 fail=(), groups=()):
        self.groups = {g.lower() for g in groups}
        self.skus = skus if skus is not None else [
            sku("Standard_D2as_v5", "standardDASv5Family"),
            sku("Standard_D4as_v5", "standardDASv5Family", 4, 16),
            sku("Standard_D2as_v7", "StandardDasv7Family"),
            sku("Standard_D2s_v7", "StandardDsv7Family"),
            sku("Standard_D2ps_v6", "standardDPSv6Family"),  # never suggested: arm64
        ]
        self.skus[-1]["capabilities"].append({"name": "CpuArchitectureType",
                                              "value": "Arm64"})
        self.compute = compute if compute is not None else [
            usage("cores", 0, 100, "Total Regional vCPUs"),
            usage("standardDASv5Family", 0, 100, "Standard DASv5 Family vCPUs"),
            usage("StandardDasv7Family", 0, 10, "Standard Dasv7 Family vCPUs"),
            usage("StandardDsv7Family", 0, 10, "Standard Dsv7 Family vCPUs"),
        ]
        self.network = network if network is not None else [
            usage("PublicIPAddresses", 0, 20, "Public IP Addresses")]
        self.providers = providers or {}
        self.fail = fail
        self.calls = []

    def __call__(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        for marker in self.fail:
            if marker in url:
                raise ap.ApiError("HTTP 403 AuthorizationFailed")
        if "login.microsoftonline.com" in url:
            return {"access_token": TOKEN}
        assert headers["Authorization"] == "Bearer " + TOKEN
        if "/Microsoft.Compute/skus" in url:
            assert "location+eq+%27eastus2%27" in url or "location%20eq" in url
            return {"value": self.skus}
        if "/Microsoft.Compute/locations/eastus2/usages" in url:
            return {"value": self.compute}
        if "/Microsoft.Network/locations/eastus2/usages" in url:
            return {"value": self.network}
        if "/resourcegroups/" in url:
            name = url.split("/resourcegroups/")[1].split("?")[0].lower()
            if name in self.groups:
                return {"name": name, "location": "eastus2"}
            raise ap.ApiError("HTTP 404 ResourceGroupNotFound", status=404)
        ns = url.split("/providers/")[1].split("?")[0]
        return {"namespace": ns,
                "registrationState": self.providers.get(ns, "Registered")}


def no_terraform(cmd, **kw):
    """terraform console unavailable: the preflight falls back to deploy.tfvars."""
    return subprocess.CompletedProcess(cmd, 1, "", "terraform not initialised")


@pytest.fixture
def export(tmp_path, redstack):
    files = compile_topology(redstack, Registry(), provider="azure")
    root = tmp_path / "export"
    for path, contents in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8", newline="\n")
    return root


def set_sizes(root, sizes):
    tfvars = root / "deploy.tfvars"
    body = "".join('  %s = "%s"\n' % kv for kv in sizes.items())
    tfvars.write_text(tfvars.read_text(encoding="utf-8")
                      + "vm_sizes = {\n%s}\n" % body, encoding="utf-8")


def run(root, arm, env=None, runner=no_terraform):
    lines = []
    rc = ap.main([str(root)], env=dict(SP_ENV, **(env or {})), http=arm,
                 run=runner, out=lines.append)
    text = "\n".join(lines)
    assert SECRET not in text and TOKEN not in text
    return rc, text


def proposed(text):
    """The vm_sizes block the preflight printed, as a dict."""
    block = text.split("vm_sizes = {")[1].split("}")[0]
    return dict(re.findall(r'(\w+)\s*=\s*"([^"]+)"', block))


def roles(root):
    return {h["role"] for h in json.loads(
        (root / "terraform/preflight.json").read_text(encoding="utf-8"))["hosts"]}


def test_passes_when_every_size_is_allowed_with_room(export):
    rc, text = run(export, FakeArm())
    assert rc == 0, text
    assert "azure preflight passed" in text
    assert "FAIL" not in text
    # The subscription id is masked; it lands in a log that may be shared.
    assert SUB not in text


def test_a_restricted_size_fails_and_names_sizes_that_fit(export):
    arm = FakeArm()
    arm.skus[0]["restrictions"] = NOT_FOR_SUB  # Standard_D2as_v5
    rc, text = run(export, arm)
    assert rc == 1, text
    assert ("Standard_D2as_v5 is not available to this subscription in eastus2 "
            "(NotAvailableForSubscription)") in text
    assert "2-vCPU sizes it can use here: Standard_D2as_v7, Standard_D2s_v7" in text
    assert "Standard_D2ps_v6" not in text.split("can use here:")[1].splitlines()[0]
    # The proposed vm_sizes clears the failure, family quota included.
    proposal = proposed(text)
    assert set(proposal) == roles(export)
    set_sizes(export, proposal)
    rc, text = run(export, arm)
    assert rc == 0, text


def test_a_size_not_offered_in_the_location_fails(export):
    set_sizes(export, {"jumpbox": "Standard_Typo2_v9"})
    rc, text = run(export, FakeArm())
    assert rc == 1
    assert "Standard_Typo2_v9 is not offered" in text


def test_family_quota_short_fails_and_proposes_a_split(export):
    """The live shape: only v7 allowed, each v7 family capped at 10 vCPUs, and the
    8-host offense stack needs 16."""
    arm = FakeArm()
    arm.skus[0]["restrictions"] = NOT_FOR_SUB
    set_sizes(export, {r: "Standard_D2as_v7" for r in roles(export)})
    rc, text = run(export, arm)
    assert rc == 1, text
    assert "Standard Dasv7 Family vCPUs quota is short: this apply needs 16 vCPUs" in text
    assert "short by 6" in text
    # Only the roles that must move are named, and they move to the other family.
    moved = proposed(text)
    assert moved and set(moved.values()) == {"Standard_D2s_v7"}
    # Splitting the roles across the two families passes.
    set_sizes(export, {"teamserver": "Standard_D2as_v7", "operator": "Standard_D2as_v7",
                       "collector": "Standard_D2s_v7", "jumpbox": "Standard_D2s_v7",
                       "redirector": "Standard_D2s_v7"})
    rc, text = run(export, arm)
    assert rc == 0, text


def test_regional_quota_short_fails(export):
    arm = FakeArm(compute=[usage("cores", 4, 10, "Total Regional vCPUs"),
                           usage("standardDASv5Family", 0, 100)])
    rc, text = run(export, arm)
    assert rc == 1
    assert "Total Regional vCPUs quota is short: this apply needs 16, 4 of 10" in text
    assert "quota increase" in text


def test_public_ip_quota_short_fails(export):
    arm = FakeArm(network=[usage("PublicIPAddresses", 2, 3, "Public IP Addresses")])
    rc, text = run(export, arm)
    assert rc == 1
    assert "Public IP Addresses quota is short: this export creates 3, 2 of 3" in text


def test_an_unregistered_provider_the_export_needs_fails_with_the_command(export):
    manifest = json.loads((export / "terraform/preflight.json").read_text(encoding="utf-8"))
    manifest["providers_required"] = {"Microsoft.DevTestLab": "the auto-stop schedule"}
    (export / "terraform/preflight.json").write_text(json.dumps(manifest), encoding="utf-8")
    rc, text = run(export, FakeArm(providers={"Microsoft.DevTestLab": "NotRegistered"}))
    assert rc == 1
    assert "az provider register --namespace Microsoft.DevTestLab --wait" in text
    # A raw ARM register POST with no body is answered 411.
    assert "curl -d ''" in text


def test_an_unregistered_core_provider_only_warns(export):
    """azurerm registers its core set itself when the identity may, so this is a
    warning with the command, not a stop."""
    rc, text = run(export, FakeArm(providers={"Microsoft.Storage": "NotRegistered"}))
    assert rc == 0, text
    assert "WARNING: Microsoft.Storage is NotRegistered" in text
    assert "az provider register --namespace Microsoft.Storage" in text


def test_an_api_failure_warns_and_continues(export):
    arm = FakeArm(fail=("management.azure.com",))
    rc, text = run(export, arm)
    assert rc == 0, text
    assert "WARNING: could not read VM sizes (HTTP 403 AuthorizationFailed)" in text
    # One warning for the providers, not one per namespace.
    assert text.count("resource provider state") == 1


def test_no_credentials_warns_and_continues(export, monkeypatch):
    monkeypatch.setattr(ap.shutil, "which", lambda name: None)
    lines = []
    rc = ap.main([str(export)], env={"ARM_SUBSCRIPTION_ID": SUB}, http=FakeArm(),
                 run=no_terraform, out=lines.append)
    assert rc == 0
    assert "azure preflight did not run: no Azure token" in "\n".join(lines)


def test_az_login_is_used_when_no_service_principal_is_set(export, monkeypatch):
    monkeypatch.setattr(ap.shutil, "which", lambda name: "/usr/bin/az" if name == "az" else None)

    def runner(cmd, **kw):
        if cmd[0] == "/usr/bin/az":
            assert cmd[1:3] == ["account", "get-access-token"]
            return subprocess.CompletedProcess(cmd, 0, TOKEN + "\n", "")
        return no_terraform(cmd)

    lines = []
    rc = ap.main([str(export)], env={"ARM_SUBSCRIPTION_ID": SUB}, http=FakeArm(),
                 run=runner, out=lines.append)
    assert rc == 0, "\n".join(lines)
    assert "asking as az login" in "\n".join(lines)


def test_the_skip_variable_skips_without_asking_azure(export):
    arm = FakeArm()
    rc, text = run(export, arm, env={"REDSTACKPRO_SKIP_PREFLIGHT": "1"})
    assert rc == 0
    assert "skipped (REDSTACKPRO_SKIP_PREFLIGHT=1)" in text
    assert arm.calls == []


def test_sizes_come_from_terraform_when_it_answers(export):
    """terraform's own merge wins over reading deploy.tfvars, so a vm_sizes set in
    an auto.tfvars or TF_VAR_ is seen too."""
    merged = {r: "Standard_D2s_v7" for r in roles(export)}
    merged["teamserver"] = "Standard_D2as_v7"

    def console(cmd, **kw):
        assert cmd[0] == "terraform" and cmd[-1] == "console"
        assert "local.vm_sizes" in kw["input"]
        value = json.dumps({"vm_sizes": merged, "location": "eastus2",
                            "subscription_id": ""})
        return subprocess.CompletedProcess(cmd, 0, json.dumps(value) + "\n", "")

    rc, text = run(export, FakeArm(), runner=console)
    assert rc == 0, text
    assert "sizes from terraform" in text
    assert "teamserver      3  Standard_D2as_v7" in text


def test_a_rerun_does_not_count_its_own_state_twice(export):
    """On a re-run the subscription's usage already includes this export's VMs."""
    arm = FakeArm(compute=[usage("cores", 16, 20, "Total Regional vCPUs"),
                           usage("standardDASv5Family", 16, 20)],
                  network=[usage("PublicIPAddresses", 3, 3, "Public IP Addresses")])
    rc, text = run(export, arm)
    assert rc == 1  # without state, it looks like a second copy
    state = {"resources": [
        {"mode": "managed", "type": "azurerm_linux_virtual_machine", "name": "this",
         "instances": [{"attributes": {"size": "Standard_D2as_v5"}}] * 8},
        {"mode": "managed", "type": "azurerm_public_ip", "name": "this",
         "instances": [{"attributes": {}}] * 3},
    ]}
    (export / "terraform/terraform.tfstate").write_text(json.dumps(state), encoding="utf-8")
    rc, text = run(export, arm)
    assert rc == 0, text


def test_a_zone_only_restriction_warns_but_passes(export):
    arm = FakeArm()
    arm.skus[0]["restrictions"] = [{
        "type": "Zone", "values": ["eastus2"], "reasonCode": "NotAvailableForSubscription",
        "restrictionInfo": {"locations": ["eastus2"], "zones": ["1", "2", "3"]}}]
    rc, text = run(export, arm)
    assert rc == 0, text
    assert "ok, regional only" in text
    assert "restricted for this subscription in zones 1,2,3" in text


def test_an_unknown_role_in_vm_sizes_warns(export):
    set_sizes(export, {"dcc": "Standard_D2as_v7"})
    rc, text = run(export, FakeArm())
    assert rc == 0
    assert "vm_sizes names 'dcc', which is no role in this topology" in text


def test_tfvars_parsing_ignores_comments_and_takes_hcl_forms(tmp_path):
    path = tmp_path / "deploy.tfvars"
    path.write_text(
        '# subscription_id = "commented"\n'
        'subscription_id = "abc" # trailing\n'
        'location = "westus3"\n'
        '/* vm_sizes = { dc = "nope" } */\n'
        '# vm_sizes = {\n#   dc = "Standard_X"\n# }\n'
        'vm_sizes = {\n'
        '  dc = "Standard_D2as_v7", "srv": "Standard_D2s_v7" // note\n'
        '  wks = "Standard_B2s_v2"\n'
        '}\n', encoding="utf-8")
    assert ap.read_tfvars(path) == {
        "subscription_id": "abc", "location": "westus3",
        "vm_sizes": {"dc": "Standard_D2as_v7", "srv": "Standard_D2s_v7",
                     "wks": "Standard_B2s_v2"}}


def test_deploy_runs_the_preflight_after_init_and_before_apply():
    from redstackpro.deploy import generate_deploy_script
    deploy = generate_deploy_script(example("redstack.json"), Registry(), provider="azure")
    init = deploy.index("terraform -chdir=terraform init")
    pre = deploy.index('"$PY" azure_preflight.py . --brief')
    apply_ = deploy.index("terraform -chdir=terraform apply")
    assert init < pre < apply_
    for provider in ("gcp", "aws"):
        other = generate_deploy_script(example("redstack.json"), Registry(), provider=provider)
        assert "azure_preflight" not in other


def test_the_guide_explains_vm_sizes_and_the_preflight_for_azure_only():
    goad = load(ROOT / "frontend/public/goad/goad-light.json")
    for doc in (example("redstack.json"), goad):
        guide = compile_topology(doc, Registry(), provider="azure")["DEPLOYMENT-GUIDE.md"]
        section = guide.split("## Azure: VM sizes and the preflight")[1].split("\n## ")[0]
        for needle in ("vm_sizes", "azure_preflight.py", "REDSTACKPRO_SKIP_PREFLIGHT=1"):
            assert needle in section
        assert guide.index("## Azure: VM sizes") < guide.index("## 4. Run the deploy")
        for provider in ("gcp", "aws"):
            other = compile_topology(doc, Registry(), provider=provider)["DEPLOYMENT-GUIDE.md"]
            assert "azure_preflight" not in other


LICENSING_URL = ("https://learn.microsoft.com/azure/virtual-machines/windows/"
                 "windows-desktop-multitenant-hosting-deployment")


def test_the_guide_has_the_client_licensing_note_on_azure_with_a_workstation():
    doc = load(ROOT / "frontend/public/goad/minilab.json")
    guide = compile_topology(doc, Registry(), provider="azure")["DEPLOYMENT-GUIDE.md"]
    section = guide.split("## Azure: Windows client licensing")[1].split("\n## ")[0]
    for needle in ("E3 or E5", "Microsoft 365", "`license_type`", LICENSING_URL):
        assert needle in section
    assert guide.index("## Azure: Windows client licensing") < guide.index("## 4. Run the deploy")
    # A workstation with no os is Windows 11, so it still gets the note.
    ws = next(n for n in doc["nodes"] if n["kind"] == "wks")
    ws["overlay"].pop("os")
    guide = compile_topology(doc, Registry(), provider="azure")["DEPLOYMENT-GUIDE.md"]
    assert "## Azure: Windows client licensing" in guide
    for provider in ("gcp", "aws"):
        other = compile_topology(doc, Registry(), provider=provider)["DEPLOYMENT-GUIDE.md"]
        assert "license_type" not in other


def test_the_guide_has_no_licensing_note_without_a_client_host():
    for doc in (example("redstack.json"),
                load(ROOT / "frontend/public/goad/goad-light.json")):
        assert not any(n["kind"] == "wks" for n in doc["nodes"])
        guide = compile_topology(doc, Registry(), provider="azure")["DEPLOYMENT-GUIDE.md"]
        assert "Windows client licensing" not in guide


def test_the_readme_carries_the_azure_licensing_note():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "`license_type`" in readme and LICENSING_URL in readme


def test_a_burstable_default_is_replaced_by_general_purpose_memory():
    """Live 2026-11-04: with B2as_v2 barred, the suggestion for a workstation was a
    4 GB compute-optimized F2as_v7 although 8 GB D sizes had quota. B maps to D, and
    a size with less memory than the default ranks last, whether or not the
    subscription's SKU list reports the default's memory."""
    listed = [sku("Standard_B2as_v2", "standardBasv2Family", restrictions=NOT_FOR_SUB),
              sku("Standard_F2as_v7", "StandardFasv7Family", memory=4),
              sku("Standard_D2ds_v7", "StandardDdsv7Family")]
    for values in (listed, listed[1:]):
        skus = ap.parse_skus(values, "eastus2")
        names = [c["name"] for c in ap.candidates(skus, 2, "Standard_B2as_v2")]
        assert names == ["Standard_D2ds_v7", "Standard_F2as_v7"]


def test_a_proposal_with_less_memory_says_so(export):
    """When the only size with quota room has less memory than the default, the
    proposal still clears the failure but names the shortfall."""
    arm = FakeArm(
        skus=[sku("Standard_D2as_v5", "standardDASv5Family", restrictions=NOT_FOR_SUB),
              sku("Standard_F2as_v7", "StandardFasv7Family", memory=4),
              sku("Standard_D2ps_v6", "standardDPSv6Family")],
        compute=[usage("cores", 0, 100, "Total Regional vCPUs"),
                 usage("StandardFasv7Family", 0, 100, "Standard Fasv7 Family vCPUs")])
    rc, text = run(export, arm)
    assert rc == 1, text
    assert set(proposed(text).values()) == {"Standard_F2as_v7"}
    assert "jumpbox gets Standard_F2as_v7 with 4 GB, less than the 8 GB" in text


# -- the resource group the deploy creates

def _rg(root):
    return ap.read_tfvars(root / "deploy.tfvars")["resource_group"]


def test_each_range_gets_its_own_resource_group_by_default(redstack):
    """Every export used to default to redstackpro-range, so a second range in
    the same subscription failed at apply, and teardown --force deleted the group
    the first range lived in."""
    files = compile_topology(redstack, Registry(), provider="azure")
    tfvars = files["deploy.tfvars"]
    m = re.search(r'(?m)^resource_group\s*=\s*"([^"]+)"', tfvars)
    assert m, tfvars
    rg = m.group(1)
    assert rg.startswith("off-") and rg.endswith("-rg")
    assert re.fullmatch(r"[a-z0-9-]{1,90}", rg)
    assert ("# Created by this deploy and deleted by teardown. Must not already "
            "exist; use one per range.") in tfvars
    assert 'default     = "%s"' % rg in files["terraform/variables.tf"]
    assert 'RG="${RG:-%s}"' % rg in files["manage.sh"]
    assert json.loads(files["terraform/preflight.json"])["default_resource_group"] == rg

    other = json.loads(json.dumps(redstack))
    other["name"] = "Another Range!"
    files = compile_topology(other, Registry(), provider="azure")
    assert 'resource_group  = "off-another-range-rg"' in files["deploy.tfvars"]

    long = json.loads(json.dumps(redstack))
    long["name"] = "x" * 200
    files = compile_topology(long, Registry(), provider="azure")
    rg = re.search(r'(?m)^resource_group\s*=\s*"([^"]+)"', files["deploy.tfvars"]).group(1)
    assert len(rg) == 90 and rg.endswith("-rg")


def test_an_existing_resource_group_outside_this_state_fails(export):
    rg = _rg(export)
    rc, text = run(export, FakeArm(groups=[rg.upper()]))
    assert rc == 1, text
    assert ("FAIL: resource group %s already exists. This deploy creates its own; "
            "set another resource_group in deploy.tfvars, or tear down the range "
            "that owns it." % rg) in text


def test_a_resource_group_this_state_owns_passes(export):
    rg = _rg(export)
    state = {"resources": [
        {"mode": "managed", "type": "azurerm_resource_group", "name": "this",
         "instances": [{"attributes": {"name": rg}}]}]}
    (export / "terraform/terraform.tfstate").write_text(json.dumps(state), encoding="utf-8")
    arm = FakeArm(groups=[rg])
    rc, text = run(export, arm)
    assert rc == 0, text
    # Owned by this state: the group is not even asked about.
    assert not any("/resourcegroups/" in url for _, url in arm.calls)


def test_a_resource_group_check_that_cannot_run_warns_and_passes(export):
    rc, text = run(export, FakeArm(fail=("/resourcegroups/",)))
    assert rc == 0, text
    assert "could not check whether resource group %s exists" % _rg(export) in text


def test_the_resource_group_check_is_a_read(export):
    arm = FakeArm()
    run(export, arm)
    assert all(method in ("GET", "POST") for method, _ in arm.calls)
    assert [m for m, u in arm.calls if "/resourcegroups/" in u] == ["GET"]


# -- --brief, what deploy.sh runs: a pass is one summary line, a failure the full table

def brief(root, arm, env=None, runner=no_terraform):
    lines = []
    rc = ap.main([str(root), "--brief"], env=dict(SP_ENV, **(env or {})), http=arm,
                 run=runner, out=lines.append)
    assert SECRET not in "\n".join(lines) and TOKEN not in "\n".join(lines)
    return rc, lines


def test_brief_pass_is_one_summary_line_naming_the_tightest_vcpu_quota(export):
    rc, lines = brief(export, FakeArm())
    assert rc == 0, lines
    assert [ln for ln in lines if not ln.startswith("WARNING")] == lines[-1:]
    summary = lines[-1]
    match = re.fullmatch(r"summary: (\d+) VMs on (.+), quota (\d+) of (\d+) vCPU", summary)
    assert match, summary
    assert int(match.group(1)) == len(json.loads(
        (export / "terraform/preflight.json").read_text(encoding="utf-8"))["hosts"])
    # The quota named is the vCPU row with the least room in the full table.
    rc, text = run(export, FakeArm())
    rows = re.findall(r"^   (.+?)\s+(\d+)\s+(\d+)\s+(\d+)  ok$", text, re.M)
    vcpu = [(int(n) + int(u), int(lim)) for label, n, u, lim in rows if "vCPU" in label]
    after, limit = max(vcpu, key=lambda r: r[0] / r[1])
    assert (int(match.group(3)), int(match.group(4))) == (after, limit)


def test_brief_failure_prints_the_full_table(export):
    set_sizes(export, {"jumpbox": "Standard_Typo2_v9"})
    rc, lines = brief(export, FakeArm())
    text = "\n".join(lines)
    assert rc == 1
    assert "FAIL: Standard_Typo2_v9 is not offered" in text
    assert re.search(r"^   role\s+hosts\s+size", text, re.M)
    assert not any(ln.startswith("summary:") for ln in lines)


def test_brief_skip_and_not_checked_still_end_on_a_summary(export, monkeypatch):
    rc, lines = brief(export, FakeArm(), env={"REDSTACKPRO_SKIP_PREFLIGHT": "1"})
    assert (rc, lines) == (0, ["summary: skipped (REDSTACKPRO_SKIP_PREFLIGHT=1)"])
    monkeypatch.setattr(ap.shutil, "which", lambda name: None)
    lines = []
    rc = ap.main([str(export), "--brief"], env={"ARM_SUBSCRIPTION_ID": SUB},
                 http=FakeArm(), run=no_terraform, out=lines.append)
    assert rc == 0
    assert lines[0].startswith("WARNING: azure preflight did not run: no Azure token")
    assert lines[-1] == "summary: not checked (see the warning)"
