"""Command-line entry point for kernel-diffguard."""

from __future__ import annotations

import argparse
import sys

from .charter import summarize_goals
from .commit_review import render_json as render_commit_json
from .commit_review import render_text as render_commit_text
from .commit_review import review_commit
from .range_review import (
    RangeReviewError,
    review_commits,
    review_range,
)
from .range_review import (
    render_json as render_range_json,
)
from .range_review import (
    render_text as render_range_text,
)


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
    review_range_parser = subparsers.add_parser(
        "review-range",
        help="review a local git commit range or explicit commit list",
    )
    review_range_parser.add_argument(
        "--repo", required=True, help="path to a local git repository"
    )
    review_range_parser.add_argument(
        "--base", help="base commit SHA or revision, excluded from review"
    )
    review_range_parser.add_argument(
        "--target", help="target commit SHA or revision, included in review"
    )
    review_range_parser.add_argument(
        "--commit",
        action="append",
        default=[],
        help="explicit commit SHA or revision to review; may be repeated",
    )
    review_range_parser.add_argument(
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
            print(render_commit_json(review), end="")
        else:
            print(render_commit_text(review))
        return 0
    if args.command == "review-range":
        try:
            if args.commit:
                if args.base or args.target:
                    parser.error(
                        "review-range accepts either --commit entries or --base/--target, not both"
                    )
                review = review_commits(args.repo, commits=args.commit)
            else:
                if not args.base or not args.target:
                    parser.error(
                        "review-range requires --base and --target unless --commit is used"
                    )
                review = review_range(args.repo, base=args.base, target=args.target)
        except RangeReviewError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(render_range_json(review), end="")
        else:
            print(render_range_text(review))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
