"""Command line entry point.

`redstackpro serve` runs the API locally, the same thing redstackpro.tools.serve
does, so an installed package is launchable without the raw uvicorn incantation.
`redstackpro compile` and `redstackpro validate` are the command line half of the
pipeline the canvas drives, sharing their code with redstackpro.tools so the CLI
and the download button cannot diverge. redStackPRO generates code: it never runs
the IaC engine and never holds a cloud credential. See 0001.
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

    from .tools import compile as compile_tool
    from .tools import validate as validate_tool

    comp = sub.add_parser("compile",
                          help="compile a topology into a working directory")
    compile_tool.configure(comp)
    comp.set_defaults(func=lambda a: compile_tool.run(a, comp.error))

    val = sub.add_parser("validate",
                         help="validate a topology, or the worked examples")
    validate_tool.configure(val)
    val.set_defaults(func=lambda a: validate_tool.run(a))

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
