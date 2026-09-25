"""Edits the canvas makes on a document, available to tooling.

A few fields on a topology are the operator's to supply and nothing can invent them.
The canvas collects them in the inspector before anyone presses Compile. Tools that
drive the pipeline without a human in front of them -- the CLI, CI, the test suite --
need to stand in for that person, and they should do it through one function rather
than each poking at the document in its own way.

Standing in for the operator is the only thing here. None of it relaxes a rule: a
document that has not had these fields filled still fails validation exactly as it
would on the canvas, which is the point. See rdr001 in validate.py.
"""


def set_redirector_hostname(document, hostname):
    """Give redirectors the name the operator would have typed.

    RDR001 refuses to compile a redirector that has no hostname, because a domain has
    to be registered and pointed at the box by a human. Shipping a plausible one is
    what let a placeholder ride all the way to a deploy that then asked for an A
    record nobody could create, so the examples stay one field short on purpose.

    Filling it here is the operator's keystroke, not a loophole: the name has to be
    one somebody actually owns, and the rule still rejects anything that reads like a
    placeholder. Mutates and returns the document.

    ``hostname`` is either a single name given to every redirector, or a mapping of
    node id to name for the split-horizon and rollover shapes, where two redirectors
    front the same C2 under different names and a single shared name would be a
    routing conflict, not a convenience. A mapping that misses a redirector on the
    document, or names one that is not there, raises rather than compiling a topology
    that still refuses on RDR001 or silently ignores a typo.
    """
    redirectors = [n for n in document.get("nodes", [])
                   if n.get("kind") == "redirector"]
    if isinstance(hostname, dict):
        unknown = set(hostname) - {n["id"] for n in redirectors}
        if unknown:
            raise ValueError("no redirector named %s on this topology"
                             % ", ".join(sorted(unknown)))
        for node in redirectors:
            if node["id"] in hostname:
                node.setdefault("overlay", {})["hostname"] = hostname[node["id"]]
        missing = [n["id"] for n in redirectors if n["id"] not in hostname]
        if missing:
            raise ValueError("no hostname given for redirector %s"
                             % ", ".join(missing))
    else:
        for node in redirectors:
            node.setdefault("overlay", {})["hostname"] = hostname
    return document
