"""Deterministic local commit-range review primitives."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .commit_review import CI_STATIC_ANALYSIS_MARKERS, review_commit
from .expert_checks import evaluate_range_checks, render_check_results_text
from .hostile_input import scan_hostile_instruction_texts
from .kernel_impact import kernel_impacts_for_paths
from .review_packet import build_review_packet, render_review_packet_text

JsonObject = dict[str, Any]

MAX_COCHANGE_VALUES_PER_COMMIT = 64
MAX_EMITTED_COCHANGE_PAIRS_PER_KIND = 512
MAX_DEFAULT_RANGE_COMMITS = 128
MAX_MERGE_TREE_DELTA_PATHS = 512
MAX_MERGE_TREE_DELTA_BYTES = 64_000


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


def review_merge_commit(
    repo: Path | str,
    *,
    merge_commit: str,
    max_commits: int = MAX_DEFAULT_RANGE_COMMITS,
) -> JsonObject:
    """Review commits introduced by a merge, excluding the merge commit itself."""

    repo_path = Path(repo)
    merge_sha = _rev_parse(repo_path, merge_commit)
    parents = _commit_parents(repo_path, merge_sha)
    if len(parents) < 2:
        raise RangeReviewError(
            "not-merge-commit",
            merge_commit,
            "expected a commit with at least two parents",
        )
    first_parent = parents[0]
    commits = _merge_introduced_commits(repo_path, merge_sha, first_parent, max_commits)
    merge_tree_delta = _review_merge_tree_delta(repo_path, merge_sha, first_parent)
    return _review_commit_sequence(
        repo_path,
        commits,
        traversal="merge-first-parent-exclusive",
        range_metadata={
            "base": first_parent,
            "target": merge_sha,
            "merge_commit": merge_sha,
            "parents": parents,
            "excluded_commits": [merge_sha],
            "id": "range:merge-first-parent-exclusive",
            "evidence_refs": [
                f"git:rev-list:{merge_sha} ^{first_parent}",
                f"git:diff-tree:{first_parent}..{merge_sha}",
            ],
        },
        supplemental_reviews=[merge_tree_delta],
        extra_fields={"merge_tree_delta": merge_tree_delta},
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
    merge_tree_delta = review.get("merge_tree_delta")
    if merge_tree_delta:
        lines.append("Merge tree delta:")
        merge_findings = merge_tree_delta.get("findings", [])
        if not merge_findings:
            lines.append("- none")
        else:
            lines.append(
                f"- {merge_tree_delta['commit']} first-parent tree delta"
            )
            for finding in merge_findings:
                lines.append(f"  - {finding['id']} [{finding['severity']}]: {finding['summary']}")
    lines.extend(render_check_results_text(review.get("expert_check_results", [])))
    lines.extend(render_review_packet_text(review["review_packet"]))
    return "\n".join(lines)


def _review_commit_sequence(
    repo: Path,
    commits: list[str],
    *,
    traversal: str,
    range_metadata: dict[str, Any],
    supplemental_reviews: list[JsonObject] | None = None,
    extra_fields: dict[str, Any] | None = None,
) -> JsonObject:
    commit_reviews = [review_commit(repo, commit) for commit in commits]
    signal_reviews = [*commit_reviews, *(supplemental_reviews or [])]
    range_manifest = _range_manifest(range_metadata, traversal, commit_reviews)
    review = {
        "schema_version": 1,
        "review_posture": "review-assistant-not-verdict",
        "range": range_manifest,
        "range_signals": _range_signals(repo, signal_reviews),
        "range_findings": _range_findings(commit_reviews),
        "commits": commit_reviews,
        "findings_by_commit": {
            review["commit"]: review.get("findings", []) for review in signal_reviews
        },
    }
    if extra_fields:
        review.update(extra_fields)
    review["expert_check_results"] = evaluate_range_checks(review)
    review["review_packet"] = build_review_packet(review)
    return review


def _range_manifest(
    range_metadata: dict[str, Any], traversal: str, commit_reviews: list[JsonObject]
) -> JsonObject:
    base = range_metadata.get("base")
    target = range_metadata.get("target")
    commits = [str(review["commit"]) for review in commit_reviews]
    manifest = {
        **range_metadata,
        "artifact_type": "commit_range_manifest",
        "id": range_metadata.get("id") or f"range:{traversal}",
        "schema_version": 1,
        "traversal": traversal,
        "commit_count": len(commits),
        "commits": commits,
        "commit_artifact_refs": [
            str(review["commit_artifact"]["id"]) for review in commit_reviews
        ],
        "commit_facts": [
            _range_commit_fact(review["commit_artifact"]) for review in commit_reviews
        ],
        "errors": [],
        "evidence_refs": range_metadata.get("evidence_refs")
        or [f"git:rev-list:{base}..{target}"],
        "trust_boundary": "derived_review_signal",
        "limits": {"truncated": False, "omitted_record_count": 0},
        "risk_hints": [],
    }
    return manifest


def _range_commit_fact(commit_artifact: JsonObject) -> JsonObject:
    return {
        "commit": commit_artifact["commit"],
        "author": commit_artifact["author"],
        "committer": commit_artifact["committer"],
        "touched_paths": commit_artifact["touched_paths"],
        "path_changes": commit_artifact["path_changes"],
        "diff_stats": commit_artifact["diff_stats"],
        "tags": commit_artifact["tags"],
        "signature": commit_artifact["signature"],
    }


def _range_findings(commit_reviews: list[JsonObject]) -> list[JsonObject]:
    setup_commits: list[JsonObject] = []
    use_commits: list[JsonObject] = []
    for review in commit_reviews:
        finding_ids = {finding["id"] for finding in review.get("findings", [])}
        paths = [str(path) for path in review.get("touched_paths", [])]
        setup_surface = bool(
            finding_ids & {"ci-static-analysis-weakened", "removed-test", "warning-policy-weakened"}
        ) or any(
            _is_ci_path(path) or _is_test_path(path) or _looks_like_script(path)
            for path in paths
        )
        if setup_surface:
            setup_commits.append(review)
        if "high-risk-path" in finding_ids or any(
            path.startswith(HIGH_RISK_PREFIXES) for path in paths
        ):
            use_commits.append(review)
    if not setup_commits or not use_commits:
        return []
    setup_commit = str(setup_commits[0]["commit"])
    use_commit = str(use_commits[-1]["commit"])
    if setup_commit == use_commit:
        return []
    return [
        _finding(
            "split-setup-use-pattern",
            "medium",
            "Range separates review-surface changes from high-risk code changes.",
            [
                f"setup-commit:{setup_commit}",
                f"use-commit:{use_commit}",
            ],
            (
                "Review the commits together for setup/use separation: a policy, test, CI, "
                "or script change may alter how the later high-risk change is evaluated."
            ),
        )
    ]


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
            if finding_id == "commit-integrity-cue":
                continue
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


def _review_merge_tree_delta(repo: Path, merge_sha: str, first_parent: str) -> JsonObject:
    raw_name_status, name_status_truncated = _git_bounded(
        repo,
        MAX_MERGE_TREE_DELTA_BYTES,
        "diff-tree",
        "--no-commit-id",
        "--name-status",
        "--find-renames",
        "-r",
        "-z",
        first_parent,
        merge_sha,
    )
    path_changes, omitted_path_records = _parse_name_status_z(
        raw_name_status, max_records=MAX_MERGE_TREE_DELTA_PATHS
    )
    touched_paths = sorted({path for change in path_changes for path in change["paths"]})
    patch_excerpt, patch_truncated = _git_bounded(
        repo,
        MAX_MERGE_TREE_DELTA_BYTES,
        "diff",
        "--no-ext-diff",
        "--find-renames",
        first_parent,
        merge_sha,
        "--",
    )
    findings = _findings_for_paths(path_changes, touched_paths, patch_excerpt)
    subject = _git(repo, "show", "-s", "--format=%s", merge_sha).strip()
    truncated = name_status_truncated or patch_truncated or omitted_path_records > 0
    return {
        "schema_version": 1,
        "review_posture": "review-assistant-not-verdict",
        "artifact_type": "merge_tree_delta_review",
        "commit": merge_sha,
        "base_parent": first_parent,
        "subject": subject,
        "touched_paths": touched_paths,
        "path_changes": path_changes,
        "kernel_impacts": kernel_impacts_for_paths(touched_paths),
        "findings": findings,
        "evidence_refs": [f"git:diff-tree:{first_parent}..{merge_sha}"],
        "trust_boundary": "local_git_diff_untrusted",
        "limits": {
            "truncated": truncated,
            "omitted_record_count": omitted_path_records,
            "name_status_truncated": name_status_truncated,
            "patch_truncated": patch_truncated,
            "max_path_records": MAX_MERGE_TREE_DELTA_PATHS,
            "max_bytes_per_git_command": MAX_MERGE_TREE_DELTA_BYTES,
        },
        "risk_hints": ["merge-tree-delta-reviewed-separately"]
        + (["merge-tree-delta-truncated"] if truncated else []),
    }


def _findings_for_paths(
    path_changes: list[JsonObject], touched_paths: list[str], patch_excerpt: str
) -> list[JsonObject]:
    findings: list[JsonObject] = []
    deleted_tests = [
        entry["paths"][-1]
        for entry in path_changes
        if entry["paths"] and entry["status"] == "D" and _is_test_path(entry["paths"][-1])
    ]
    if deleted_tests:
        findings.append(
            _finding(
                "removed-test",
                "high",
                "A test file was removed in the merge tree delta.",
                [f"path:{path}" for path in deleted_tests],
                "Check whether the merge resolution intentionally removed coverage.",
            )
        )
    ci_paths = [path for path in touched_paths if _is_ci_path(path)]
    if ci_paths and any(marker in patch_excerpt.lower() for marker in CI_STATIC_ANALYSIS_MARKERS):
        findings.append(
            _finding(
                "ci-static-analysis-weakened",
                "medium",
                "CI or static-analysis configuration changed around known analysis commands.",
                [f"path:{path}" for path in ci_paths],
                "Inspect whether merge-only CI changes removed or weakened checks.",
            )
        )
    added_scripts = [
        entry["paths"][-1]
        for entry in path_changes
        if entry["paths"] and entry["status"] == "A" and _looks_like_script(entry["paths"][-1])
    ]
    if added_scripts:
        findings.append(
            _finding(
                "suspicious-script-added",
                "medium",
                "A script-like file was added in the merge tree delta.",
                [f"path:{path}" for path in added_scripts],
                "Review whether the merge-only script runs in CI, build, install, "
                "or release paths.",
            )
        )
    hostile_hits = scan_hostile_instruction_texts(
        [
            ("merge-tree-delta", patch_excerpt),
            *[(f"path:{path}", path) for path in touched_paths],
        ]
    )
    if hostile_hits:
        evidence = sorted(
            {
                *[f"marker:{hit.marker}" for hit in hostile_hits],
                *[f"location:{hit.location}" for hit in hostile_hits],
            }
        )
        findings.append(
            _finding(
                "prompt-injection-text",
                "medium",
                "Prompt-injection or hostile-instruction language appears in the merge tree delta.",
                evidence,
                "Treat affected merge-only text as hostile data before model-assisted review.",
            )
        )
    high_risk_paths = [path for path in touched_paths if path.startswith(HIGH_RISK_PREFIXES)]
    if high_risk_paths:
        findings.append(
            _finding(
                "high-risk-path",
                "medium",
                "The merge tree delta touches paths that commonly need careful "
                "kernel or build-system review.",
                [f"path:{path}" for path in high_risk_paths],
                "Review merge conflict resolution/direct merge edits against the first parent.",
            )
        )
    return findings


def _parse_name_status_z(raw: str, *, max_records: int) -> tuple[list[JsonObject], int]:
    changes: list[JsonObject] = []
    omitted_records = 0
    tokens = [token for token in raw.split("\0") if token]
    index = 0
    while index < len(tokens):
        status_token = tokens[index]
        index += 1
        status = status_token[0]
        score = status_token[1:] or None
        path_count = 2 if status in {"R", "C"} else 1
        paths = tokens[index : index + path_count]
        index += path_count
        if len(paths) < path_count:
            omitted_records += 1
            continue
        if len(changes) >= max_records:
            omitted_records += 1
            continue
        changes.append({"status": status, "score": score, "paths": paths})
    return changes, omitted_records


def _git_bounded(repo: Path, max_stdout_bytes: int, *args: str) -> tuple[str, bool]:
    process = subprocess.Popen(
        ["git", *args],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None:
        raise RuntimeError("git stdout pipe was not created")
    kept = process.stdout.read(max_stdout_bytes + 1)
    truncated = len(kept) > max_stdout_bytes
    if truncated:
        process.kill()
        _stdout_remainder, _stderr = process.communicate()
        return kept[:max_stdout_bytes].decode(errors="ignore"), True
    stdout_remainder, stderr = process.communicate()
    output = kept + stdout_remainder
    if process.returncode != 0:
        raise subprocess.CalledProcessError(
            process.returncode,
            ["git", *args],
            output=output.decode(errors="ignore"),
            stderr=stderr.decode(errors="ignore"),
        )
    return output.decode(errors="ignore"), False


def _finding(
    finding_id: str,
    severity: str,
    summary: str,
    evidence: list[str],
    suggested_next_check: str,
) -> JsonObject:
    return {
        "id": finding_id,
        "severity": severity,
        "summary": summary,
        "evidence": evidence,
        "evidence_refs": evidence,
        "uncertainty": "heuristic",
        "false_positive_caveat": (
            "Heuristic cue only, not proof of a regression or malicious change."
        ),
        "suggested_next_check": suggested_next_check,
    }


def _is_test_path(path: str) -> bool:
    lowered = path.lower()
    return lowered.startswith("test/") or lowered.startswith("tests/") or "/test" in lowered


def _is_ci_path(path: str) -> bool:
    lowered = path.lower()
    return lowered.startswith(".github/workflows/") or lowered in {
        ".gitlab-ci.yml",
        "azure-pipelines.yml",
        "tox.ini",
        "pyproject.toml",
    }


def _looks_like_script(path: str) -> bool:
    lowered = path.lower()
    return lowered.startswith("scripts/") or lowered.endswith((".sh", ".bash", ".py", ".pl", ".rb"))


HIGH_RISK_PREFIXES = (
    "arch/",
    "drivers/",
    "fs/",
    "kernel/",
    "mm/",
    "net/",
    "security/",
    "scripts/",
)


def _rev_parse(repo: Path, revision: str) -> str:
    try:
        return _git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}").strip()
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or "not a commit revision"
        raise RangeReviewError("invalid-revision", revision, detail) from exc


def _range_commits(repo: Path, base_sha: str, target_sha: str) -> list[str]:
    raw = _git(repo, "rev-list", "--reverse", f"{base_sha}..{target_sha}")
    return [line for line in raw.splitlines() if line]


def _merge_introduced_commits(
    repo: Path, merge_sha: str, first_parent: str, max_commits: int
) -> list[str]:
    raw = _git(
        repo,
        "rev-list",
        "--reverse",
        "--max-count",
        str(max_commits + 2),
        merge_sha,
        f"^{first_parent}",
    )
    commits = [line for line in raw.splitlines() if line and line != merge_sha]
    if len(commits) > max_commits:
        raise RangeReviewError(
            "range-too-large",
            merge_sha,
            f"merge expansion exceeds max_commits={max_commits}",
        )
    return commits


def _commit_parents(repo: Path, commit_sha: str) -> list[str]:
    raw = _git(repo, "show", "-s", "--format=%P", commit_sha).strip()
    return raw.split() if raw else []


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout
