"""Deterministic single-commit review primitives."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .commit_artifact import parse_commit_artifact
from .kernel_impact import kernel_impacts_for_paths

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
MAX_LINUX_SECURITY_CUE_INPUT_BYTES = 8_192
MAX_LINUX_SECURITY_CUES_PER_FAMILY = 8
LINUX_SECURITY_CUE_PATTERNS = (
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)),
    ("xsa", re.compile(r"\bXSA-\d+\b", re.IGNORECASE)),
    ("fixes", re.compile(r"^Fixes:\s+.+", re.IGNORECASE | re.MULTILINE)),
    ("reported-by", re.compile(r"^Reported-by:\s+.+", re.IGNORECASE | re.MULTILINE)),
    ("reviewed-by", re.compile(r"^Reviewed-by:\s+.+", re.IGNORECASE | re.MULTILINE)),
    ("tested-by", re.compile(r"^Tested-by:\s+.+", re.IGNORECASE | re.MULTILINE)),
    (
        "security-language",
        re.compile(
            r"\b(security[ -]?fix|double[ -]free|buffer[ -]overflow|"
            r"use-after-free|lifetime|VMA|mm)\b",
            re.IGNORECASE,
        ),
    ),
)
PATCH_SECURITY_LANGUAGE_PATTERN = re.compile(
    r"\b(security[ -]?fix|double[ -]free|buffer[ -]overflow|use-after-free|lifetime|VMA)\b",
    re.IGNORECASE,
)


JsonObject = dict[str, Any]


def review_commit(repo: Path | str, commit: str) -> JsonObject:
    """Review one git commit and emit deterministic reviewer-assistance findings."""

    repo_path = Path(repo)
    commit_artifact = parse_commit_artifact(repo_path, commit)
    commit_sha = commit_artifact["commit"]
    subject = commit_artifact["subject"]
    body = commit_artifact["body"]
    name_status = commit_artifact["path_changes"]
    patch = commit_artifact["diff_excerpt"]

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

    linux_security_cues = _linux_security_cues(
        f"{subject}\n{body}", patch, touched_paths
    )
    if linux_security_cues:
        findings.append(
            _finding(
                "linux-security-cue",
                "medium",
                "Commit text or patch contains Linux security/review cues.",
                linux_security_cues,
                (
                    "Use these cues to prioritize human review and targeted retest; "
                    "this is not a verdict."
                ),
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
        "kernel_impacts": kernel_impacts_for_paths(touched_paths),
        "commit_artifact": commit_artifact,
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
    impacts = review.get("kernel_impacts", [])
    if impacts:
        lines.append("Kernel impact hints:")
        for impact in impacts:
            lines.append(f"- {impact['id']}: {impact['summary']}")
            lines.append(f"  retest: {', '.join(impact['retest_hints'])}")
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
        "evidence_refs": evidence,
        "uncertainty": "heuristic",
        "false_positive_caveat": (
            "Heuristic cue only; benign maintenance commits can contain similar text."
        ),
        "suggested_next_check": suggested_next_check,
    }


def _linux_security_cues(
    metadata_text: str, patch_text: str, touched_paths: list[str]
) -> list[str]:
    metadata_excerpt, metadata_truncated = _bounded_text(
        metadata_text, MAX_LINUX_SECURITY_CUE_INPUT_BYTES
    )
    patch_excerpt, patch_truncated = _bounded_text(patch_text, MAX_LINUX_SECURITY_CUE_INPUT_BYTES)

    matches_by_id: dict[str, list[str]] = {}
    truncated_families: set[str] = set()
    for cue_id, pattern in LINUX_SECURITY_CUE_PATTERNS:
        _collect_limited_matches(
            cue_id,
            pattern,
            metadata_excerpt,
            matches_by_id,
            truncated_families,
        )
    _collect_limited_matches(
        "security-language",
        PATCH_SECURITY_LANGUAGE_PATTERN,
        patch_excerpt,
        matches_by_id,
        truncated_families,
    )

    has_linux_path = any(path.startswith(HIGH_RISK_PREFIXES) for path in touched_paths)
    strong_cues = matches_by_id.get("cve", []) + matches_by_id.get("xsa", [])
    metadata_cues = [
        cue
        for cue_id, cues in matches_by_id.items()
        if cue_id in {"fixes", "reported-by", "reviewed-by", "tested-by"}
        for cue in cues
    ]
    security_language = matches_by_id.get("security-language", [])
    meaningful_security_language = [
        cue for cue in security_language if cue.lower() != "security-language:mm"
    ]
    if not strong_cues and not (has_linux_path and (meaningful_security_language or metadata_cues)):
        return []

    evidence: list[str] = []
    seen: set[str] = set()
    for cue_id, _pattern in LINUX_SECURITY_CUE_PATTERNS:
        if cue_id not in {"cve", "xsa"} and not has_linux_path:
            continue
        for cue in matches_by_id.get(cue_id, []):
            if cue not in seen:
                seen.add(cue)
                evidence.append(cue)
    if metadata_truncated or patch_truncated or truncated_families:
        evidence.append("limit:linux-security-cue-scan-truncated")
    return evidence


def _collect_limited_matches(
    cue_id: str,
    pattern: re.Pattern[str],
    text: str,
    matches_by_id: dict[str, list[str]],
    truncated_families: set[str],
) -> None:
    for match in pattern.finditer(text):
        family_matches = matches_by_id.setdefault(cue_id, [])
        if len(family_matches) >= MAX_LINUX_SECURITY_CUES_PER_FAMILY:
            truncated_families.add(cue_id)
            return
        snippet = " ".join(match.group(0).split())
        evidence = f"{cue_id}:{snippet}"
        if evidence not in family_matches:
            family_matches.append(evidence)


def _bounded_text(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode()
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode(errors="ignore"), True


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
