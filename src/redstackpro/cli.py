"""Command line entry point.

`redstackpro serve` runs the API locally, the same thing tools/serve.py does, so an
installed package is launchable without the raw uvicorn incantation. redStackPRO
generates code: it never runs the IaC engine and never holds a cloud credential.
See 0001.
"""

import argparse


def _serve(args):
    try:
        import uvicorn
    except ModuleNotFoundError:
        raise SystemExit(
            "uvicorn is not installed. Install the dev extra: "
            "pip install -e '.[dev]'")
    from .api import create_app
    uvicorn.run(create_app(), host=args.host, port=args.port)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="redstackpro")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the API locally")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=_serve)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
