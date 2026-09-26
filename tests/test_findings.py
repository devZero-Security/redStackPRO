"""The finding is a wire contract: returned by the API, rendered by the canvas,
and iterated by the agent harness. Its shape and its guards are worth pinning so
a change to either is a change someone has to make on purpose. See 0014.
"""

from dataclasses import FrozenInstanceError

import pytest

from redstackpro.findings import finding


def test_message_renders_the_template():
    f = finding("CAR006", "warning", ["rdir-01"],
                "{name} fronts {count} teamservers.",
                name="rt-rdir-01", count=3)
    assert f.message == "rt-rdir-01 fronts 3 teamservers."


def test_to_dict_carries_the_rendeart_message_and_lists_targets():
    d = finding("X001", "error", ["a", "b"], "{n} bad", n="two").to_dict()
    # target_ids is a list, not a tuple, because the dict goes over the wire.
    assert d["target_ids"] == ["a", "b"]
    assert d["message"] == "two bad"
    assert set(d) == {"code", "severity", "target_ids", "template",
                      "values", "message", "remedy"}


def test_unknown_severity_is_rejected():
    with pytest.raises(ValueError):
        finding("X001", "critical", ["a"], "bad")


def test_a_finding_must_point_at_something():
    with pytest.raises(ValueError):
        finding("X001", "error", [], "points nowhere")


def test_the_helper_tuples_the_targets():
    assert finding("X001", "warning", ["a", "b"], "t").target_ids == ("a", "b")


def test_a_finding_is_frozen():
    f = finding("X001", "warning", ["a"], "t")
    with pytest.raises(FrozenInstanceError):
        f.code = "Y002"
