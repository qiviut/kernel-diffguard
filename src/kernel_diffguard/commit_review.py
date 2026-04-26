"""Deterministic single-commit review primitives."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

PROMPT_INJECTION_MARKERS = (
    "ignore previous instructions",
    "disregard previous instructions",
    "exfiltrate secrets",
    "reveal secrets",
    "system prompt",
)

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

CI_STATIC_ANALYSIS_MARKERS = ("ruff", "mypy", "flake8", "pylint", "shellcheck", "clang-tidy")


JsonObject = dict[str, Any]


def review_commit(repo: Path | str, commit: str) -> JsonObject:
    """Review one git commit and emit deterministic reviewer-assistance findings."""

    repo_path = Path(repo)
    commit_sha = _git(repo_path, "rev-parse", commit).strip()
    subject = _git(repo_path, "show", "-s", "--format=%s", commit_sha).strip()
    body = _git(repo_path, "show", "-s", "--format=%B", commit_sha)
    name_status = _parse_name_status(
        _git(repo_path, "diff-tree", "--no-commit-id", "--name-status", "-r", commit_sha)
    )
    patch = _git(repo_path, "show", "--format=", "--find-renames", commit_sha, "--")

    findings: list[JsonObject] = []
    touched_paths = sorted({path for entry in name_status for path in entry["paths"]})

    deleted_tests = [
        entry["paths"][-1]
        for entry in name_status
        if entry["status"] == "D" and _is_test_path(entry["paths"][-1])
    ]
    if deleted_tests:
        findings.append(
            _finding(
                "removed-test",
                "high",
                "A test file was removed.",
                [f"path:{path}" for path in deleted_tests],
                "Check whether coverage or regression protection was intentionally "
                "replaced elsewhere.",
            )
        )

    ci_paths = [path for path in touched_paths if _is_ci_path(path)]
    if ci_paths and any(marker in patch.lower() for marker in CI_STATIC_ANALYSIS_MARKERS):
        findings.append(
            _finding(
                "ci-static-analysis-weakened",
                "medium",
                "CI or static-analysis configuration changed around known analysis commands.",
                [f"path:{path}" for path in ci_paths],
                "Inspect whether checks were removed, weakened, or moved to another workflow.",
            )
        )

    added_scripts = [
        entry["paths"][-1]
        for entry in name_status
        if entry["status"] == "A" and _looks_like_script(entry["paths"][-1])
    ]
    if added_scripts:
        findings.append(
            _finding(
                "suspicious-script-added",
                "medium",
                "A script-like file was added.",
                [f"path:{path}" for path in added_scripts],
                "Review whether the script runs in CI, build, install, or release paths.",
            )
        )

    prompt_hits = [
        marker for marker in PROMPT_INJECTION_MARKERS if marker in f"{body}\n{patch}".lower()
    ]
    if prompt_hits:
        findings.append(
            _finding(
                "prompt-injection-text",
                "medium",
                "Prompt-injection or hostile-instruction language appears in commit text or diff.",
                [f"marker:{marker}" for marker in sorted(set(prompt_hits))],
                "Treat affected text as hostile data and avoid feeding it directly "
                "to privileged tools or prompts.",
            )
        )

    high_risk_paths = [path for path in touched_paths if path.startswith(HIGH_RISK_PREFIXES)]
    if high_risk_paths:
        findings.append(
            _finding(
                "high-risk-path",
                "medium",
                "The commit touches paths that commonly need careful kernel or "
                "build-system review.",
                [f"path:{path}" for path in high_risk_paths],
                "Map these paths to subsystem ownership and targeted retest areas.",
            )
        )

    return {
        "schema_version": 1,
        "review_posture": "review-assistant-not-verdict",
        "commit": commit_sha,
        "subject": subject,
        "touched_paths": touched_paths,
        "findings": findings,
    }


def render_text(review: JsonObject) -> str:
    """Render a compact human-readable review."""

    lines = [f"Commit: {review['commit']}", f"Subject: {review['subject']}", "Findings:"]
    findings = review.get("findings", [])
    if not findings:
        lines.append("- none")
        return "\n".join(lines)
    for finding in findings:
        lines.append(f"- {finding['id']} [{finding['severity']}]: {finding['summary']}")
        lines.append(f"  next: {finding['suggested_next_check']}")
    return "\n".join(lines)


def render_json(review: JsonObject) -> str:
    """Render a stable JSON review."""

    return json.dumps(review, indent=2, sort_keys=True) + "\n"


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout


def _parse_name_status(raw: str) -> list[JsonObject]:
    entries: list[JsonObject] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0][0]
        entries.append({"status": status, "paths": parts[1:]})
    return entries


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
        "uncertainty": "heuristic",
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
