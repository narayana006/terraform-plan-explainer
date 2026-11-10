"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .plan import PlanError, parse_plan
from .render import RENDERERS
from .risks import SEVERITIES, assess

EXIT_OK, EXIT_RISKY, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="terraform-plan-explainer",
        description="Summarise `terraform show -json` plan output in plain English, risky changes first.",
        epilog="Exit codes: 0 = nothing at or above --fail-on, 1 = risky findings, 2 = bad input.",
    )
    p.add_argument("plan", nargs="?", default="-",
                   help="path to plan JSON, or '-' / omitted to read stdin")
    p.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text")
    p.add_argument("--fail-on", choices=[*SEVERITIES, "never"], default="high",
                   help="exit 1 when a finding of this severity or worse exists (default: high)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.plan == "-":
            if sys.stdin.isatty():
                print("error: no plan given; pipe `terraform show -json plan.out` or pass a file",
                      file=sys.stderr)
                return EXIT_ERROR
            text = sys.stdin.read()
        else:
            with open(args.plan, encoding="utf-8") as fh:
                text = fh.read()
        changes = parse_plan(text)
    except (OSError, PlanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = assess(changes)
    sys.stdout.write(RENDERERS[args.format](changes, findings))

    if args.fail_on != "never":
        threshold = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f.severity) <= threshold for f in findings):
            return EXIT_RISKY
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
