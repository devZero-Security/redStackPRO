"""Naming.

A node has one identifier. Everything else derives from it mechanically, so
nothing can drift. See 0016.

    prefix   off                     topology level, the instantiation parameter
    id       myth-ts01               node level, slug then kind tag then ordinal
    name     off-myth-ts01           composed, what a person and a host both see
    tf_ref   off_myth_ts01           Terraform labels take underscores
    tag      off-myth-ts01           GCP network tag

An id reads left to right as a purpose slug, the kind tag, and a two digit
ordinal: myth-ts01 is a teamserver running Mythic, main-net01 is the network
the management tier sits in. The slug is derived from what the node is and what
it holds, so re-purposing a node renames it; the kind tag is fixed per kind and
is what a rule keys on. The slug is optional, so a teamserver with no framework
is just ts01.
"""

import re

NETBIOS_LIMIT = 15


def platform_account(mode):
    """The single platform account every host in a canvas shares: the Linux
    admin + SSH identity + Guacamole login. One name per canvas, chosen by mode:
    ``blueop`` for a defensive range (mode == "defense"), ``redop`` for an
    offensive ops platform (every other mode). This collapses the former
    rtadmin (infra admin) / operator (Guac login) / mortiz (persona) split into
    one identity that reads sensibly on both canvases. Windows range hosts keep
    Administrator; this is the Linux/connection account. See ADR 0056 / P1.7."""
    return "blueop" if mode == "defense" else "redop"

_TRAILING_DIGITS = re.compile(r"(\d+)$")


def compose(prefix, node_id):
    return "%s-%s" % (prefix, node_id)


def tf_ref(prefix, node_id):
    return compose(prefix, node_id).replace("-", "_")


def _tail(node_id):
    """The final hyphen segment, which carries the kind tag and the ordinal.
    Everything before it is the slug, which may itself contain hyphens."""
    return node_id.rsplit("-", 1)[-1]


def abbrev_of(node_id):
    """The kind tag: the alphabetic head of the final segment. ts for ts01,
    net for main-net01, sub for c2-sub01."""
    return _TRAILING_DIGITS.sub("", _tail(node_id))


def ordinal_of(node_id):
    """The trailing ordinal as written, or the empty string when absent."""
    m = _TRAILING_DIGITS.search(_tail(node_id))
    return m.group(1) if m else ""


def slug_of(node_id):
    """The purpose slug, or the empty string when the id is just tag plus
    ordinal (ts01)."""
    return node_id.rsplit("-", 1)[0] if "-" in node_id else ""


def too_long(prefix, node_id):
    """Windows NetBIOS truncates at 15. Range mode will hit this before ops
    mode does, but the limit is the same either way."""
    return len(compose(prefix, node_id)) > NETBIOS_LIMIT
