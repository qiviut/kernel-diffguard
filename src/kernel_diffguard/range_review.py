"""Deterministic local commit-range review primitives."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .commit_review import review_commit

JsonObject = dict[str, Any]


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
        "commits": commit_reviews,
        "findings_by_commit": {
            review["commit"]: review.get("findings", []) for review in commit_reviews
        },
    }


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
