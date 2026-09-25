"""Retention for stored compile results and idempotency keys.

A compile stores its whole file map so the archive endpoint can zip it without
recompiling, so a zip and a file map cannot disagree (0010). Nothing read that
map after the download, and nothing deleted it, so results accumulated without
bound; idempotency keys did the same. 0017 flagged both. This ages them out.

The rule is age alone: a compile is downloaded close to when it is made, and an
idempotency key matters only across a retry, so both have a natural expiry and
neither needs a per owner count. A heavier workload could outgrow a time window
inside it, and a count cap is a small addition to the same sweep if it ever does.
See 0024.

The sweep runs opportunistically: a compile prunes expired results, an idempotent
create prunes expired keys. No background job, which suits a synchronous API with
no task runner. Pruning only happens when there is activity, which is also the
only time growth happens, so the bound holds.

Both windows are env configurable. A window of zero or less turns that sweep off,
which is the escape hatch for an operator who wants to keep everything.
"""

import logging
import os
from datetime import timedelta

from sqlalchemy import delete

from . import db

COMPILE_RESULT_TTL_DAYS = "REDSTACKPRO_COMPILE_RESULT_TTL_DAYS"
IDEMPOTENCY_KEY_TTL_HOURS = "REDSTACKPRO_IDEMPOTENCY_KEY_TTL_HOURS"

DEFAULT_COMPILE_RESULT_TTL_DAYS = 7
DEFAULT_IDEMPOTENCY_KEY_TTL_HOURS = 24

logger = logging.getLogger("redstackpro.retention")


def _env_number(name, default):
    """A malformed or empty value falls back to the default rather than failing
    startup: a retention window is not worth a crash, and the default is safe."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("%s is not a number (%r); using %s", name, raw, default)
        return default


def prune_compile_results(sess, now=None):
    """Delete stored compile results past their window. Returns the count, and
    logs it when it is not zero, so a sweep is never silent."""
    days = _env_number(COMPILE_RESULT_TTL_DAYS, DEFAULT_COMPILE_RESULT_TTL_DAYS)
    if days <= 0:
        return 0
    cutoff = (now or db.now()) - timedelta(days=days)
    deleted = sess.execute(
        delete(db.CompileResult).where(db.CompileResult.created_at < cutoff)
    ).rowcount or 0
    if deleted:
        logger.info("pruned %d compile result(s) older than %s days",
                    deleted, days)
    return deleted


def prune_idempotency_keys(sess, now=None):
    """Delete idempotency keys past their window. A key past its window is
    pruned before the duplicate check reads it, so an expired key is treated as
    a new request rather than a stale hit."""
    hours = _env_number(IDEMPOTENCY_KEY_TTL_HOURS,
                        DEFAULT_IDEMPOTENCY_KEY_TTL_HOURS)
    if hours <= 0:
        return 0
    cutoff = (now or db.now()) - timedelta(hours=hours)
    deleted = sess.execute(
        delete(db.IdempotencyKey).where(db.IdempotencyKey.created_at < cutoff)
    ).rowcount or 0
    if deleted:
        logger.info("pruned %d idempotency key(s) older than %s hours",
                    deleted, hours)
    return deleted
