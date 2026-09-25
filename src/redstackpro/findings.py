"""The validation finding.

This object is returned by the API, rendered by the canvas, and iterated on by the
agent harness. It is a contract, so changing its shape is expensive. See 0014.
"""

from dataclasses import dataclass, field


SEVERITIES = ("error", "warning")


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    target_ids: tuple
    template: str
    values: dict = field(default_factory=dict)
    remedy: str = ""

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
        return {
            "code": self.code,
            "severity": self.severity,
            "target_ids": list(self.target_ids),
            "template": self.template,
            "values": self.values,
            "message": self.message,
            "remedy": self.remedy,
        }


def finding(code, severity, targets, template, remedy="", **values):
    return Finding(
        code=code,
        severity=severity,
        target_ids=tuple(targets),
        template=template,
        values=values,
        remedy=remedy,
    )
