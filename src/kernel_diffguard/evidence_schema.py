"""Normalized evidence schema catalog and lightweight fixture validation."""

from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]

TRUST_BOUNDARY_LABELS = (
    "local_git_metadata_untrusted",
    "local_git_diff_untrusted",
    "remote_archive_email_untrusted",
    "external_evidence_snapshot_untrusted",
    "derived_review_signal",
)

_COMMON_REQUIRED_FIELDS = (
    "artifact_type",
    "id",
    "evidence_refs",
    "trust_boundary",
    "limits",
    "risk_hints",
)

ARTIFACT_SCHEMAS: dict[str, JsonObject] = {
    "commit_artifact": {
        "summary": "Normalized facts for one local git commit and its bounded diff metadata.",
        "trust_boundaries": ["local_git_metadata_untrusted", "local_git_diff_untrusted"],
        "required_fields": [*_COMMON_REQUIRED_FIELDS, "commit", "parents", "touched_paths"],
        "hostile_fields": [
            "author",
            "committer",
            "subject",
            "body",
            "touched_paths",
            "diff_excerpts",
        ],
    },
    "commit_range_manifest": {
        "summary": "Deterministic manifest for an explicit commit list or X..Y traversal.",
        "trust_boundaries": ["derived_review_signal", "local_git_metadata_untrusted"],
        "required_fields": [*_COMMON_REQUIRED_FIELDS, "base", "target", "traversal", "commits"],
        "hostile_fields": ["base", "target", "commits", "errors"],
    },
    "mailing_list_message_artifact": {
        "summary": "Bounded RFC822/mbox message facts from local fixtures or archive snapshots.",
        "trust_boundaries": ["remote_archive_email_untrusted"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "message_id",
            "source_sha256",
            "subject",
            "from",
            "plain_text_excerpt",
        ],
        "hostile_fields": ["headers", "subject", "from", "to", "cc", "plain_text_excerpt"],
    },
    "related_message_candidate": {
        "summary": "Evidence-scored candidate link between commit/range facts and message facts.",
        "trust_boundaries": ["derived_review_signal"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "commit_refs",
            "message_refs",
            "match_evidence",
        ],
        "hostile_fields": ["subject_cues", "list_ids", "urls"],
    },
    "finding": {
        "summary": "Reviewer-assistance finding backed by deterministic evidence references.",
        "trust_boundaries": ["derived_review_signal"],
        "required_fields": [*_COMMON_REQUIRED_FIELDS, "severity", "summary", "uncertainty"],
        "hostile_fields": ["summary"],
    },
    "recommendation": {
        "summary": "Suggested next check or retest action tied to one or more findings/facts.",
        "trust_boundaries": ["derived_review_signal"],
        "required_fields": [*_COMMON_REQUIRED_FIELDS, "summary", "recommended_action"],
        "hostile_fields": ["summary", "recommended_action"],
    },
    "external_evidence_record": {
        "summary": "Provider-neutral OpenSSF-aligned snapshot record consumed offline.",
        "trust_boundaries": ["external_evidence_snapshot_untrusted"],
        "required_fields": [*_COMMON_REQUIRED_FIELDS, "provider", "subject", "source", "claims"],
        "hostile_fields": ["provider", "subject", "source", "claims"],
    },
}


def build_schema_catalog() -> JsonObject:
    """Return the deterministic normalized evidence schema catalog."""

    return {
        "schema_version": 1,
        "review_posture": "schemas-are-review-boundaries-not-verdicts",
        "trust_boundary_labels": list(TRUST_BOUNDARY_LABELS),
        "artifacts": ARTIFACT_SCHEMAS,
    }


def validate_schema_fixture(fixture: JsonObject) -> list[str]:
    """Validate representative schema fixtures without adding a heavy schema dependency."""

    errors: list[str] = []
    artifacts = fixture.get("artifacts")
    if not isinstance(artifacts, list):
        return ["artifacts must be a list"]

    for index, artifact in enumerate(artifacts):
        prefix = f"artifacts[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{prefix} must be an object")
            continue
        artifact_type = artifact.get("artifact_type")
        if artifact_type not in ARTIFACT_SCHEMAS:
            errors.append(f"{prefix}.artifact_type is unknown: {artifact_type}")
            continue
        _validate_required_fields(errors, prefix, artifact, ARTIFACT_SCHEMAS[str(artifact_type)])
        _validate_evidence_refs(errors, prefix, artifact)
        _validate_trust_boundary(errors, prefix, artifact)
        _validate_limits(errors, prefix, artifact)
        _validate_risk_hints(errors, prefix, artifact)
    return errors


def _validate_required_fields(
    errors: list[str], prefix: str, artifact: JsonObject, schema: JsonObject
) -> None:
    for field in schema["required_fields"]:
        if field not in artifact:
            errors.append(f"{prefix}.{field} is required")


def _validate_evidence_refs(errors: list[str], prefix: str, artifact: JsonObject) -> None:
    evidence_refs = artifact.get("evidence_refs")
    if not _is_non_empty_string_list(evidence_refs):
        errors.append(f"{prefix}.evidence_refs must be a non-empty list of strings")


def _validate_trust_boundary(errors: list[str], prefix: str, artifact: JsonObject) -> None:
    trust_boundary = artifact.get("trust_boundary")
    if trust_boundary not in TRUST_BOUNDARY_LABELS:
        errors.append(f"{prefix}.trust_boundary is unknown: {trust_boundary}")


def _validate_limits(errors: list[str], prefix: str, artifact: JsonObject) -> None:
    limits = artifact.get("limits")
    if not isinstance(limits, dict):
        errors.append(f"{prefix}.limits must be an object")
        return
    if not isinstance(limits.get("truncated"), bool):
        errors.append(f"{prefix}.limits.truncated must be a boolean")
    if not isinstance(limits.get("omitted_record_count"), int):
        errors.append(f"{prefix}.limits.omitted_record_count must be an integer")


def _validate_risk_hints(errors: list[str], prefix: str, artifact: JsonObject) -> None:
    risk_hints = artifact.get("risk_hints")
    if not isinstance(risk_hints, list) or any(not isinstance(hint, str) for hint in risk_hints):
        errors.append(f"{prefix}.risk_hints must be a list of strings")


def _is_non_empty_string_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) for item in value)
