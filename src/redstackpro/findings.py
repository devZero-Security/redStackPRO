"""The validation finding.

This object is returned by the API, rendered by the canvas, and iterated on by the
agent harness. It is a contract, so changing its shape is expensive. See 0014.
"""

from dataclasses import dataclass, field as dc_field


# info is a notice: it never blocks a compile and is not counted as a warning.
SEVERITIES = ("error", "warning", "info")


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    target_ids: tuple
    template: str
    values: dict = dc_field(default_factory=dict)
    remedy: str = ""
    # Dotted path of the offending field under its node or edge, e.g.
    # "tls.cert_source". Empty when the finding is not about one field.
    field: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError("severity must be one of %s" % (SEVERITIES,))
        if not self.target_ids:
            raise ValueError("%s: a finding must point at something" % self.code)

    @property
    def message(self):
        """Rendered prose. Shipped alongside the template so no consumer has to
        template client side."""
        return self.template.format(**self.values)

    def to_dict(self):
        out = {
            "code": self.code,
            "severity": self.severity,
            "target_ids": list(self.target_ids),
            "template": self.template,
            "values": self.values,
            "message": self.message,
            "remedy": self.remedy,
        }
        # Only when set, so every finding without one keeps the shape it had.
        if self.field:
            out["field"] = self.field
        return out


def finding(code, severity, targets, template, remedy="", field="", **values):
    return Finding(
        code=code,
        severity=severity,
        target_ids=tuple(targets),
        template=template,
        values=values,
        remedy=remedy,
        field=field,
    )
