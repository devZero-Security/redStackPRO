"""The 0.10.0 UX pass on the validator: the schema check, the field path a
finding carries for the canvas, the info severity, and the rules that catch a
value which compiles but does nothing or breaks the deploy. Each rule has a case
that fires and one that does not.
"""

import pytest

from redstackpro.findings import finding


# -- the finding shape

def test_a_field_finding_serializes_its_path():
    d = finding("SCH001", "error", ["rd01"], "{path} bad", path="tls.cert_source",
                field="tls.cert_source").to_dict()
    assert d["field"] == "tls.cert_source"
    assert d["message"] == "tls.cert_source bad"


def test_a_finding_without_a_field_keeps_its_old_shape():
    d = finding("X001", "error", ["a"], "bad").to_dict()
    assert "field" not in d


def test_info_is_a_severity():
    assert finding("X001", "info", ["a"], "note").severity == "info"
    with pytest.raises(ValueError):
        finding("X001", "notice", ["a"], "note")
