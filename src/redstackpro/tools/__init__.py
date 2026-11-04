"""Command line tools that ship with the package.

Two are user facing through the `redstackpro` entry point (compile, validate);
the rest are dev tooling, run as `python -m redstackpro.tools.<name>`. See 0010.
"""

import argparse


def provider_arg(value):
    """argparse type for --provider: a registry provider, case insensitive.
    Unchecked, "GCP" or a typo died as a KeyError traceback in the registry."""
    from redstackpro.registry import Registry
    known = sorted(Registry().providers)
    name = value.strip().lower()
    if name not in known:
        raise argparse.ArgumentTypeError(
            "unknown provider %r; valid providers: %s" % (value, ", ".join(known)))
    return name
