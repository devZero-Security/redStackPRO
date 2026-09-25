"""The registry is the second artifact: kinds, providers, and roles as data, so
pro can extend the palette by dropping files in rather than by patching code. The
palette itself is exercised in test_naming; this covers capabilities, the
unsupported prose, and the requirement `when` clause. See 0013.
"""

import pytest


def test_loads_the_edge_roles(registry):
    assert set(registry.roles) == {
        "attached", "fronts", "logs_to", "manages", "peers", "joins", "trusts"}


def test_capabilities_is_a_set_and_excludes_peering_on_proxmox(registry):
    caps = registry.capabilities("proxmox")
    assert "subnet" in caps
    assert "network_peering" not in caps  # proxmox cannot peer, see 0029


def test_unsupported_reason_collapses_prose_to_one_line(registry):
    reason = registry.unsupported_reason("proxmox", "network_peering")
    assert reason
    assert "\n" not in reason
    assert "  " not in reason  # folded YAML whitespace is squeezed out


def test_unsupported_reason_is_none_for_a_supported_capability(registry):
    assert registry.unsupported_reason("proxmox", "subnet") is None


def test_unconditional_requirements_always_apply(registry):
    node = {"kind": "operator", "overlay": {"os": "debian"}}
    assert "compute" in registry.requirements_for(node)


def test_a_when_clause_gates_on_overlay_equality(registry):
    windows = {"kind": "operator", "overlay": {"os": "windows"}}
    debian = {"kind": "operator", "overlay": {"os": "debian"}}
    assert "windows_image" in registry.requirements_for(windows)
    assert "windows_image" not in registry.requirements_for(debian)
    assert "linux_image" in registry.requirements_for(debian)


def test_requirements_for_an_unknown_kind_raises(registry):
    with pytest.raises(KeyError):
        registry.requirements_for({"kind": "nonesuch"})


def test_a_when_clause_must_name_exactly_one_field(registry):
    # Deliberately not an expression language: more than one field is an error,
    # not an AND. The kind should split instead.
    registry.kinds["synthetic"] = {
        "kind": "synthetic",
        "requirements": [{"name": "x", "when": {"a": 1, "b": 2}}],
    }
    with pytest.raises(ValueError):
        registry.requirements_for(
            {"kind": "synthetic", "overlay": {"a": 1, "b": 2}})
