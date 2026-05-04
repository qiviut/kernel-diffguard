"""Deterministic related-message candidate scoring for commit facts."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

JsonObject = dict[str, Any]

_MAX_CANDIDATES = 64
_MAX_MATCH_EVIDENCE_RECORDS = 8
_DEFAULT_TIME_WINDOW_DAYS = 21

_SUBJECT_TAG_RE = re.compile(r"\[(?:patch|rfc)[^\]]*\]", re.IGNORECASE)
_SUBJECT_PREFIX_RE = re.compile(r"^(?:re|fwd):\s*", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_NOISE_TOKENS = {
    "a",
    "an",
    "and",
    "for",
    "in",
    "of",
    "on",
    "patch",
    "re",
    "the",
    "to",
    "v2",
    "v3",
    "v4",
    "with",
}

_SUBSYSTEM_LIST_HINTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("net/", "drivers/net/"), ("netdev.vger.kernel.org", "linux-kernel.vger.kernel.org")),
    (("fs/",), ("linux-fsdevel.vger.kernel.org", "linux-kernel.vger.kernel.org")),
    (("mm/",), ("linux-mm.kvack.org", "linux-kernel.vger.kernel.org")),
    (("security/",), ("linux-security-module.vger.kernel.org", "linux-kernel.vger.kernel.org")),
    (("kernel/sched/",), ("linux-kernel.vger.kernel.org",)),
    (
        ("arch/arm", "arch/arm64"),
        ("linux-arm-kernel.lists.infradead.org", "linux-kernel.vger.kernel.org"),
    ),
    (("drivers/gpu/",), ("dri-devel.lists.freedesktop.org", "linux-kernel.vger.kernel.org")),
    (("drivers/",), ("linux-kernel.vger.kernel.org",)),
)


def find_related_message_candidates(
    commit_artifacts: list[JsonObject],
    message_artifacts: list[JsonObject],
    *,
    max_candidates: int = _MAX_CANDIDATES,
    time_window_days: int = _DEFAULT_TIME_WINDOW_DAYS,
) -> list[JsonObject]:
    """Find bounded, evidence-scored candidate links between commits and messages.

    Inputs are already-normalized artifacts, but their metadata still comes from hostile git
    and email sources. This function emits derived evidence only; it does not treat a match as
    proof that a discussion reviewed, approved, or correctly describes a commit.
    """

    candidates: list[JsonObject] = []
    window = timedelta(days=time_window_days)
    for commit in commit_artifacts:
        for message in message_artifacts:
            evidence = _match_evidence(commit, message, window)
            if not _has_non_time_evidence(evidence):
                continue
            candidates.append(
                _candidate(
                    commit, message, evidence, max_candidates=max_candidates, omitted_record_count=0
                )
            )

    candidates.sort(
        key=lambda candidate: (
            -int(candidate["total_evidence_score"]),
            str(candidate["commit_refs"][0]),
            str(candidate["message_refs"][0]),
        )
    )
    if len(candidates) <= max_candidates:
        return candidates

    omitted = len(candidates) - max_candidates
    emitted = candidates[:max_candidates]
    for candidate in emitted:
        candidate["limits"] = _limits(max_candidates, omitted)
        candidate["risk_hints"] = sorted(
            set([*candidate["risk_hints"], "candidate-records-truncated"])
        )
    return emitted


def _match_evidence(commit: JsonObject, message: JsonObject, window: timedelta) -> list[JsonObject]:
    evidence: list[JsonObject] = []
    timestamp_evidence = _timestamp_evidence(commit, message, window)
    if timestamp_evidence:
        evidence.append(timestamp_evidence)
    subject_evidence = _subject_evidence(commit, message)
    if subject_evidence:
        evidence.append(subject_evidence)
    path_evidence = _patch_path_evidence(commit, message)
    if path_evidence:
        evidence.append(path_evidence)
    list_evidence = _subsystem_list_evidence(commit, message)
    if list_evidence:
        evidence.append(list_evidence)
    return evidence[:_MAX_MATCH_EVIDENCE_RECORDS]


def _timestamp_evidence(
    commit: JsonObject, message: JsonObject, window: timedelta
) -> JsonObject | None:
    commit_time = _parse_datetime(str(commit.get("author", {}).get("timestamp", "")))
    message_time = _parse_datetime(str(message.get("date", "")))
    if not commit_time or not message_time:
        return None
    delta_seconds = int(abs((message_time - commit_time).total_seconds()))
    if timedelta(seconds=delta_seconds) > window:
        return None
    return {
        "kind": "timestamp-window",
        "score": 1,
        "commit_timestamp": commit_time.isoformat().replace("+00:00", "Z"),
        "message_timestamp": message_time.isoformat().replace("+00:00", "Z"),
        "delta_seconds": delta_seconds,
        "window_days": window.days,
    }


def _subject_evidence(commit: JsonObject, message: JsonObject) -> JsonObject | None:
    commit_subject = str(commit.get("subject", ""))
    message_subject = str(message.get("subject", ""))
    commit_tokens = _subject_tokens(commit_subject)
    message_tokens = _subject_tokens(message_subject)
    shared = sorted(commit_tokens & message_tokens)
    if len(shared) < 3:
        return None
    containment_bonus = commit_tokens <= message_tokens or message_tokens <= commit_tokens
    return {
        "kind": "subject-cue",
        "score": 3 if containment_bonus else 2,
        "shared_tokens": shared[:16],
    }


def _patch_path_evidence(commit: JsonObject, message: JsonObject) -> JsonObject | None:
    commit_paths = {str(path) for path in commit.get("touched_paths", [])}
    message_paths = {str(path) for path in message.get("patch", {}).get("touched_paths", [])}
    overlap = sorted(commit_paths & message_paths)
    if not overlap:
        return None
    return {
        "kind": "patch-path-overlap",
        "score": 4,
        "paths": overlap[:16],
        "omitted_path_count": max(0, len(overlap) - 16),
    }


def _subsystem_list_evidence(commit: JsonObject, message: JsonObject) -> JsonObject | None:
    expected_lists = _expected_lists_for_paths(
        [str(path) for path in commit.get("touched_paths", [])]
    )
    message_lists = {str(list_id).lower() for list_id in message.get("list_ids", [])}
    matched_lists = sorted(expected_lists & message_lists)
    if not matched_lists:
        return None
    return {"kind": "subsystem-list-id", "score": 2, "list_ids": matched_lists[:16]}


def _candidate(
    commit: JsonObject,
    message: JsonObject,
    evidence: list[JsonObject],
    *,
    max_candidates: int,
    omitted_record_count: int,
) -> JsonObject:
    commit_ref = str(commit.get("id") or f"commit:{commit.get('commit', '')}")
    message_ref = str(message.get("id") or f"message:{message.get('message_id', '')}")
    match_evidence = evidence[:_MAX_MATCH_EVIDENCE_RECORDS]
    return {
        "artifact_type": "related_message_candidate",
        "id": f"candidate:{_candidate_id_part(commit_ref)}:{_candidate_id_part(message_ref)}",
        "schema_version": 1,
        "commit_refs": [commit_ref],
        "message_refs": [message_ref],
        "match_evidence": match_evidence,
        "total_evidence_score": sum(int(item["score"]) for item in match_evidence),
        "evidence_refs": [
            str(commit.get("evidence_refs", [commit_ref])[0]),
            f"mail:message-id:{message.get('message_id', '')}",
        ],
        "trust_boundary": "derived_review_signal",
        "limits": _limits(max_candidates, omitted_record_count),
        "risk_hints": ["derived-from-hostile-git-and-email-input"],
    }


def _limits(max_candidates: int, omitted_record_count: int) -> JsonObject:
    return {
        "truncated": bool(omitted_record_count),
        "omitted_record_count": omitted_record_count,
        "max_candidates": max_candidates,
        "max_match_evidence_records": _MAX_MATCH_EVIDENCE_RECORDS,
    }


def _has_non_time_evidence(evidence: list[JsonObject]) -> bool:
    return any(item.get("kind") != "timestamp-window" for item in evidence)


def _subject_tokens(subject: str) -> set[str]:
    normalized = subject
    while True:
        stripped = _SUBJECT_PREFIX_RE.sub("", normalized).strip()
        if stripped == normalized:
            break
        normalized = stripped
    normalized = _SUBJECT_TAG_RE.sub(" ", normalized.lower())
    return {token for token in _TOKEN_RE.findall(normalized) if token not in _NOISE_TOKENS}


def _expected_lists_for_paths(paths: list[str]) -> set[str]:
    expected: set[str] = set()
    for path in paths:
        lower_path = path.lower()
        for prefixes, list_ids in _SUBSYSTEM_LIST_HINTS:
            if lower_path.startswith(prefixes):
                expected.update(list_id.lower() for list_id in list_ids)
    return expected


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _candidate_id_part(ref: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "-", ref).strip("-")[:96]
