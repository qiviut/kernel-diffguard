"""Command-line entry point for kernel-diffguard."""

from __future__ import annotations

import argparse

from .charter import summarize_goals


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kdiffguard",
        description="Analyze git repository changes for security and operational impact.",
    )
    parser.add_argument(
        "--charter",
        action="store_true",
        help="print the current project charter summary and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.charter:
        print(summarize_goals())
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
