"""Deterministic local commit-range review primitives."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .commit_review import review_commit

JsonObject = dict[str, Any]

MAX_COCHANGE_VALUES_PER_COMMIT = 64
MAX_EMITTED_COCHANGE_PAIRS_PER_KIND = 512


@dataclass(frozen=True)
class RangeReviewError(Exception):
    """A fail-closed range-review input error."""

    kind: str
    revision: str
    detail: str

    def __str__(self) -> str:
        return f"{self.kind}: {self.revision}: {self.detail}"


def review_range(repo: Path | str, *, base: str, target: str) -> JsonObject:
    """Review commits in ``base..target`` in deterministic topological order."""

    repo_path = Path(repo)
    base_sha = _rev_parse(repo_path, base)
    target_sha = _rev_parse(repo_path, target)
    commits = _range_commits(repo_path, base_sha, target_sha)
    return _review_commit_sequence(
        repo_path,
        commits,
        traversal="base-exclusive-target-inclusive",
        range_metadata={"base": base_sha, "target": target_sha},
    )


def review_commits(repo: Path | str, *, commits: list[str]) -> JsonObject:
    """Review an explicit ordered commit list without widening or deduplicating it."""

    repo_path = Path(repo)
    commit_shas = [_rev_parse(repo_path, commit) for commit in commits]
    return _review_commit_sequence(
        repo_path,
        commit_shas,
        traversal="explicit-commit-list",
        range_metadata={"base": None, "target": None},
    )


def render_json(review: JsonObject) -> str:
    """Render a stable JSON range review."""

    return json.dumps(review, indent=2, sort_keys=True) + "\n"


def render_text(review: JsonObject) -> str:
    """Render a compact human-readable range review."""

    range_info = review["range"]
    lines = [
        f"Range: {range_info['base']}..{range_info['target']}",
        f"Traversal: {range_info['traversal']}",
        f"Commits: {range_info['commit_count']}",
        "Findings:",
    ]
    any_findings = False
    for commit_review in review.get("commits", []):
        findings = commit_review.get("findings", [])
        if not findings:
            continue
        any_findings = True
        lines.append(f"- {commit_review['commit']} {commit_review['subject']}")
        for finding in findings:
            lines.append(f"  - {finding['id']} [{finding['severity']}]: {finding['summary']}")
    if not any_findings:
        lines.append("- none")
    return "\n".join(lines)


def _review_commit_sequence(
    repo: Path,
    commits: list[str],
    *,
    traversal: str,
    range_metadata: dict[str, str | None],
) -> JsonObject:
    commit_reviews = [review_commit(repo, commit) for commit in commits]
    return {
        "schema_version": 1,
        "review_posture": "review-assistant-not-verdict",
        "range": {
            **range_metadata,
            "traversal": traversal,
            "commit_count": len(commits),
            "errors": [],
        },
        "range_signals": _range_signals(repo, commit_reviews),
        "commits": commit_reviews,
        "findings_by_commit": {
            review["commit"]: review.get("findings", []) for review in commit_reviews
        },
    }


def _range_signals(repo: Path, commit_reviews: list[JsonObject]) -> JsonObject:
    co_changed_path_pairs: dict[tuple[str, str], int] = {}
    co_changed_path_prefix_pairs: dict[tuple[str, str], int] = {}
    co_change_limits = {
        "max_emitted_pairs_per_kind": MAX_EMITTED_COCHANGE_PAIRS_PER_KIND,
        "max_values_per_commit": MAX_COCHANGE_VALUES_PER_COMMIT,
        "omitted_path_pair_commits": 0,
        "omitted_path_pairs_after_limit": 0,
        "omitted_path_prefix_pair_commits": 0,
        "omitted_path_prefix_pairs_after_limit": 0,
    }
    finding_ids: dict[str, int] = {}
    kernel_impacts: dict[str, int] = {}
    path_prefixes: dict[str, int] = {}
    touched_paths: set[str] = set()
    authors_by_key: dict[tuple[str, str], JsonObject] = {}

    for commit_review in commit_reviews:
        commit = str(commit_review["commit"])
        author = _commit_author(repo, commit)
        author_key = (author["name"], author["email"])
        author_entry = authors_by_key.setdefault(
            author_key,
            {
                "name": author["name"],
                "email": author["email"],
                "commit_count": 0,
                "commits": [],
                "finding_ids": {},
                "path_prefixes": {},
            },
        )
        author_entry["commit_count"] += 1
        author_entry["commits"].append(commit)

        commit_paths = sorted({str(path) for path in commit_review.get("touched_paths", [])})
        path_omitted_commit, path_omitted_pairs = _increment_pair_counts(
            co_changed_path_pairs, commit_paths
        )
        prefix_omitted_commit, prefix_omitted_pairs = _increment_pair_counts(
            co_changed_path_prefix_pairs,
            sorted({_path_prefix(path) for path in commit_paths}),
        )
        if path_omitted_commit:
            co_change_limits["omitted_path_pair_commits"] += 1
        if prefix_omitted_commit:
            co_change_limits["omitted_path_prefix_pair_commits"] += 1
        co_change_limits["omitted_path_pairs_after_limit"] += path_omitted_pairs
        co_change_limits["omitted_path_prefix_pairs_after_limit"] += prefix_omitted_pairs

        for path_text in commit_paths:
            touched_paths.add(path_text)
            prefix = _path_prefix(path_text)
            path_prefixes[prefix] = path_prefixes.get(prefix, 0) + 1
            author_path_prefixes = author_entry["path_prefixes"]
            author_path_prefixes[prefix] = author_path_prefixes.get(prefix, 0) + 1
        for finding in commit_review.get("findings", []):
            finding_id = str(finding["id"])
            finding_ids[finding_id] = finding_ids.get(finding_id, 0) + 1
            author_finding_ids = author_entry["finding_ids"]
            author_finding_ids[finding_id] = author_finding_ids.get(finding_id, 0) + 1
        for impact in commit_review.get("kernel_impacts", []):
            impact_id = str(impact["id"])
            kernel_impacts[impact_id] = kernel_impacts.get(impact_id, 0) + 1

    return {
        "authors": [
            {
                **author,
                "finding_ids": dict(sorted(author["finding_ids"].items())),
                "path_prefixes": dict(sorted(author["path_prefixes"].items())),
            }
            for author in authors_by_key.values()
        ],
        "co_change_limits": co_change_limits,
        "co_changed_path_pairs": _pair_signal(co_changed_path_pairs, "paths"),
        "co_changed_path_prefix_pairs": _pair_signal(
            co_changed_path_prefix_pairs, "path_prefixes"
        ),
        "finding_ids": dict(sorted(finding_ids.items())),
        "kernel_impacts": dict(sorted(kernel_impacts.items())),
        "path_prefixes": dict(sorted(path_prefixes.items())),
        "touched_path_count": len(touched_paths),
        "touched_paths": sorted(touched_paths),
    }


def _path_prefix(path: str) -> str:
    return path.split("/", maxsplit=1)[0] if "/" in path else "."


def _increment_pair_counts(
    pair_counts: dict[tuple[str, str], int], values: list[str]
) -> tuple[bool, int]:
    if len(values) > MAX_COCHANGE_VALUES_PER_COMMIT:
        return True, 0

    omitted_after_limit = 0
    for left_index, left in enumerate(values):
        for right in values[left_index + 1 :]:
            pair = (left, right)
            if (
                pair not in pair_counts
                and len(pair_counts) >= MAX_EMITTED_COCHANGE_PAIRS_PER_KIND
            ):
                omitted_after_limit += 1
                continue
            pair_counts[pair] = pair_counts.get(pair, 0) + 1
    return False, omitted_after_limit


def _pair_signal(pair_counts: dict[tuple[str, str], int], pair_key: str) -> list[JsonObject]:
    return [
        {"commit_count": count, pair_key: [left, right]}
        for (left, right), count in sorted(pair_counts.items())
    ]


def _commit_author(repo: Path, commit: str) -> dict[str, str]:
    raw = _git(repo, "show", "-s", "--format=%an%x00%ae", commit).strip()
    name, email = raw.split("\x00", maxsplit=1)
    return {"name": name, "email": email}


def _rev_parse(repo: Path, revision: str) -> str:
    try:
        return _git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}").strip()
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or "not a commit revision"
        raise RangeReviewError("invalid-revision", revision, detail) from exc


def _range_commits(repo: Path, base_sha: str, target_sha: str) -> list[str]:
    raw = _git(repo, "rev-list", "--reverse", f"{base_sha}..{target_sha}")
    return [line for line in raw.splitlines() if line]


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout
