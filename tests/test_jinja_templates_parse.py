"""Every shipped .j2 template must be syntactically valid Jinja.

Templates render on the jumpbox at deploy, not at compile, so a syntax error in
one does not surface until a live run. This parses each one offline. It caught a
real regression: a bash length expansion (dollar-brace-hash) in rsp-operator.j2,
whose brace-hash reads as a Jinja comment-open, failed to render the deploy task.
Parse checks syntax only (tag/comment/block balance); unknown Ansible filters are
fine at parse time.
"""

import pathlib

import jinja2

import redstackpro

ASSETS = pathlib.Path(redstackpro.__file__).parent / "assets"


def test_all_shipped_jinja_templates_parse():
    env = jinja2.Environment()
    errors = []
    templates = sorted(ASSETS.rglob("*.j2"))
    assert templates, "no .j2 templates found under assets"
    for path in templates:
        try:
            env.parse(path.read_text(encoding="utf-8"))
        except jinja2.TemplateSyntaxError as exc:
            errors.append("%s: %s" % (path.relative_to(ASSETS), exc))
    assert not errors, "Jinja syntax errors in shipped templates:\n" + "\n".join(errors)
