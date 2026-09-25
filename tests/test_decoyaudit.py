"""The decoy imagery audit: the check that a test cannot be.

Every answer this tool gives depends on what a third party holds today, so it
cannot live in the suite. What the suite can hold is the part that decides what
counts as a problem, and the exit code, because the failure it exists to catch
is silent: a search term that stops returning anything does not error, the slot
falls back to drawn artwork, the page renders and the deploy succeeds. Nine of
eighty-one terms were dead the first time it ran and nothing had said so.
"""
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "redstackpro", "tools"))

import decoyaudit  # noqa: E402


class _Fetcher:
    """Stands in for the real fetcher, with a fixed answer per term."""

    def __init__(self, counts, default=9):
        self.counts = counts
        self.default = default

    def search(self, term, width):
        return [None] * self.counts.get(term, self.default)


def _run(monkeypatch, counts):
    monkeypatch.setattr(decoyaudit, "_fetcher", lambda: _Fetcher(counts))
    out = io.StringIO()
    code = decoyaudit.audit_terms(out=out)
    return code, out.getvalue()


def test_a_healthy_catalog_passes(monkeypatch):
    code, text = _run(monkeypatch, {})
    assert code == 0
    assert "dead terms (nothing usable): 0" in text


def test_a_dead_term_fails_and_is_named(monkeypatch):
    """The whole point. A term returning nothing is a real defect, so it has to
    reach a non-zero exit code rather than a line somebody might read."""
    term = next(iter(decoyaudit.decoyassets._catalog()["imagery"]["cdn"]["detail"]))
    code, text = _run(monkeypatch, {term: 0})
    assert code == 1
    assert term in text


def test_a_thin_term_warns_but_does_not_fail(monkeypatch):
    """Different severity on purpose: a small pool still produces a correct
    page, it just cannot vary between two redirectors. Worth saying, not worth
    failing a check over."""
    term = next(iter(decoyaudit.decoyassets._catalog()["imagery"]["cdn"]["detail"]))
    code, text = _run(monkeypatch, {term: decoyaudit.THIN - 1})
    assert code == 0
    assert term in text
    assert "thin terms" in text


def test_every_catalog_term_is_actually_visited(monkeypatch):
    """A checker that silently skips most of its input is the failure mode this
    repo keeps finding in its own checkers, so the count is asserted."""
    seen = []

    class Counting(_Fetcher):
        def search(self, term, width):
            seen.append(term)
            return [None] * 9

    monkeypatch.setattr(decoyaudit, "_fetcher", lambda: Counting({}))
    decoyaudit.audit_terms(out=io.StringIO())
    expected = sum(len(terms)
                   for pools in decoyaudit.decoyassets._catalog()["imagery"].values()
                   for terms in pools.values())
    assert len(seen) == expected


def test_a_source_that_raises_does_not_crash_the_audit(monkeypatch):
    """An audit that dies on the first unreachable term reports nothing about
    the other eighty."""
    class Angry(_Fetcher):
        def search(self, term, width):
            raise OSError("unreachable")

    monkeypatch.setattr(decoyaudit, "_fetcher", lambda: Angry({}))
    out = io.StringIO()
    decoyaudit.audit_terms(out=out)
    assert "ERROR" in out.getvalue()


def test_the_fetcher_the_tool_loads_is_the_one_the_role_ships():
    """If this drifts, the audit measures a script nothing deploys."""
    assert os.path.isfile(decoyaudit.FETCHER)
    assert decoyaudit.FETCHER.endswith(
        os.path.join("redstackpro.redirector", "files", "rsp-decoy-fetch.py"))
