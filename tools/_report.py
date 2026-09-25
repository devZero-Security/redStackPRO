"""How a command line tool prints validation findings.

One renderer, shared, because the two tools that report findings are the two
tools a person meets first. `validate.py` reports them as its whole job;
`compile.py` reports them when the compiler refuses to run. Those two had
drifted to opposite extremes -- one printed the code, the message and the
remedy, the other let a GenerationError escape as a traceback naming no cause
at all -- and the difference was not a decision, it was an oversight.
"""


def render(findings, out=print):
    """Print findings the way the validator does. Returns the error count."""
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = len(findings) - errors
    for f in findings:
        out("    %-7s %-8s %s" % (f.severity, f.code, f.message))
        if f.remedy and f.severity == "error":
            out("            -> %s" % f.remedy)
    return errors, warnings


def summary(errors, warnings):
    """The one line header that precedes a rendered finding list."""
    if not errors and not warnings:
        return "clean"
    return "%d errors, %d warnings" % (errors, warnings)
