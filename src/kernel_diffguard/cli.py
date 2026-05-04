"""Command-line entry point for kernel-diffguard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .charter import summarize_goals
from .commit_review import render_json as render_commit_json
from .commit_review import render_text as render_commit_text
from .commit_review import review_commit
from .mailing_list import parse_mailing_list_message_file
from .mailing_list import render_json as render_message_json
from .range_review import (
    RangeReviewError,
    review_commits,
    review_merge_commit,
    review_range,
)
from .range_review import (
    render_json as render_range_json,
)
from .range_review import (
    render_text as render_range_text,
)
from .related_messages import find_related_message_candidates
from .scorecard import build_scorecard
from .scorecard import render_json as render_scorecard_json
from .scorecard import render_text as render_scorecard_text


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
    review_range_parser.add_argument("--repo", required=True, help="path to a local git repository")
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
        "--merge-commit",
        help="merge commit SHA or revision whose introduced commits should be reviewed",
    )
    review_range_parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="output format",
    )
    parse_message_parser = subparsers.add_parser(
        "parse-message",
        help="parse one RFC822 or mbox mailing-list message into normalized facts",
    )
    parse_message_parser.add_argument(
        "--file", required=True, help="path to a local RFC822/mbox message file"
    )
    parse_message_parser.add_argument(
        "--format",
        choices=("json",),
        default="json",
        help="output format",
    )
    related_messages_parser = subparsers.add_parser(
        "related-messages",
        help="score candidate links between normalized commit and message artifacts",
    )
    related_messages_parser.add_argument(
        "--commit-artifact",
        action="append",
        default=[],
        required=True,
        help="path to a normalized commit artifact JSON file; may be repeated",
    )
    related_messages_parser.add_argument(
        "--message-artifact",
        action="append",
        default=[],
        required=True,
        help="path to a normalized mailing-list message artifact JSON file; may be repeated",
    )
    related_messages_parser.add_argument(
        "--format",
        choices=("json",),
        default="json",
        help="output format",
    )
    scorecard_parser = subparsers.add_parser(
        "scorecard",
        help="emit deterministic review-signal value metrics",
    )
    scorecard_parser.add_argument(
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
                if args.base or args.target or args.merge_commit:
                    parser.error(
                        "review-range accepts either --commit entries, --merge-commit, "
                        "or --base/--target, not a mix"
                    )
                review = review_commits(args.repo, commits=args.commit)
            elif args.merge_commit:
                if args.base or args.target:
                    parser.error(
                        "review-range accepts either --merge-commit or --base/--target, not both"
                    )
                review = review_merge_commit(args.repo, merge_commit=args.merge_commit)
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
    if args.command == "parse-message":
        artifact = parse_mailing_list_message_file(args.file)
        print(render_message_json(artifact), end="")
        return 0
    if args.command == "related-messages":
        commit_artifacts = [_read_json_file(path) for path in args.commit_artifact]
        message_artifacts = [_read_json_file(path) for path in args.message_artifact]
        candidates = find_related_message_candidates(commit_artifacts, message_artifacts)
        result = {
            "artifact_type": "related_message_candidate_set",
            "schema_version": 1,
            "candidate_count": len(candidates),
            "candidates": candidates,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "scorecard":
        scorecard = build_scorecard(".")
        if args.format == "json":
            print(render_scorecard_json(scorecard), end="")
        else:
            print(render_scorecard_text(scorecard))
        return 0
    parser.print_help()
    return 0


def _read_json_file(path: str) -> dict[str, object]:
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object in {path}")
    return data


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
