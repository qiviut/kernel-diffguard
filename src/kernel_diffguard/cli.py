"""Command-line entry point for kernel-diffguard."""

from __future__ import annotations

import argparse

from .charter import summarize_goals
from .commit_review import render_json, render_text, review_commit


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
    subparsers = parser.add_subparsers(dest="command")
    review_commit_parser = subparsers.add_parser(
        "review-commit",
        help="review one local git commit and emit deterministic findings",
    )
    review_commit_parser.add_argument(
        "--repo", required=True, help="path to a local git repository"
    )
    review_commit_parser.add_argument(
        "--commit", required=True, help="commit SHA or revision to review"
    )
    review_commit_parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="output format",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.charter:
        print(summarize_goals())
        return 0
    if args.command == "review-commit":
        review = review_commit(args.repo, args.commit)
        if args.format == "json":
            print(render_json(review), end="")
        else:
            print(render_text(review))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
