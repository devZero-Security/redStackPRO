"""--provider is checked against the registry at the command line.

It took any string. "GCP", the way the docs and the canvas capitalize it, or a
typo, got past argparse and died as a KeyError traceback in the registry, which
names neither the mistake nor the fix. Now it is matched case insensitively and
anything else is refused with the list of valid providers.
"""

from pathlib import Path

import pytest

from redstackpro import Registry
from redstackpro import cli
from redstackpro.tools import compile as compile_tool
from redstackpro.tools import provider_arg

ROOT = Path(__file__).resolve().parent.parent
RANGE = str(ROOT / "frontend/public/goad/goad-light.json")
VALID = "valid providers: aws, azure, esxi, gcp, proxmox"


def test_every_registry_provider_is_accepted_in_any_case():
    for name in Registry().providers:
        assert provider_arg(name) == name
        assert provider_arg(name.upper()) == name


@pytest.mark.parametrize("argv", [
    ["compile", RANGE, "--provider", "gcpp", "--list"],
    ["validate", RANGE, "--provider", "nope"],
])
def test_an_unknown_provider_is_refused_with_the_valid_ones(argv, capsys):
    with pytest.raises(SystemExit) as exit_:
        cli.main(argv)
    assert exit_.value.code == 2
    err = capsys.readouterr().err
    assert "unknown provider" in err and VALID in err, err
    assert "Traceback" not in err and "KeyError" not in err


def test_the_standalone_compile_tool_refuses_it_too(capsys):
    with pytest.raises(SystemExit) as exit_:
        compile_tool.main([RANGE, "--provider", "Azur", "--list"])
    assert exit_.value.code == 2
    assert VALID in capsys.readouterr().err


@pytest.mark.parametrize("held", ["terraform/terraform.tfstate", "keys/id_ed25519"])
def test_compile_will_not_replace_a_deployed_export(tmp_path, capsys, held):
    """-o used to delete the folder first, so recompiling over a deployed export
    took its key and its Terraform state with it."""
    out = tmp_path / "export"
    (out / held).parent.mkdir(parents=True)
    (out / held).write_text("deployed")
    with pytest.raises(SystemExit) as exit_:
        cli.main(["compile", RANGE, "-o", str(out)])
    assert exit_.value.code == 1
    err = capsys.readouterr().err
    assert held in err and "Pick a new folder" in err and "--force" in err, err
    assert (out / held).read_text() == "deployed"
    assert not (out / "deploy.sh").exists()


def test_force_replaces_a_deployed_export(tmp_path, capsys):
    out = tmp_path / "export"
    (out / "terraform").mkdir(parents=True)
    (out / "terraform/terraform.tfstate").write_text("deployed")
    (out / "keys").mkdir()
    (out / "keys/id_ed25519").write_text("key")
    cli.main(["compile", RANGE, "-o", str(out), "--force"])
    assert "wrote" in capsys.readouterr().out
    assert not (out / "terraform/terraform.tfstate").exists()
    assert not (out / "keys/id_ed25519").exists()
    assert (out / "deploy.sh").is_file()


def test_a_stale_undeployed_export_is_still_replaced(tmp_path, capsys):
    """keys/.keep ships empty in every export, so it alone does not protect it."""
    out = tmp_path / "export"
    (out / "keys").mkdir(parents=True)
    (out / "keys/.keep").write_text("")
    (out / "stale.txt").write_text("old")
    cli.main(["compile", RANGE, "-o", str(out)])
    assert "wrote" in capsys.readouterr().out
    assert not (out / "stale.txt").exists()
    assert (out / "keys/.keep").is_file()
    assert (out / "deploy.sh").is_file()


def test_an_upper_case_provider_compiles_for_that_provider(capsys):
    cli.main(["compile", RANGE, "--provider", "AWS", "--list"])
    listed = capsys.readouterr().out
    assert "terraform/modules/aws/" in listed
    assert "terraform/modules/gcp/" not in listed
