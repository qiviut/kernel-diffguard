"""Normalized evidence schema catalog and lightweight fixture validation."""

from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]

CHECK_RESULT_STATUSES = (
    "satisfied",
    "violated",
    "missing_evidence",
    "not_applicable",
    "inconclusive",
)

NAMED_CHECK_CLASSIFICATIONS = (
    "generic",
    "candidate_kernel_specific",
    "requires_codebase_experience",
)

TRUST_BOUNDARY_LABELS = (
    "local_git_metadata_untrusted",
    "local_git_diff_untrusted",
    "remote_archive_email_untrusted",
    "remote_github_metadata_untrusted",
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
            "patch_series",
            "from",
            "plain_text_excerpt",
            "discussion_signals",
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
            "discussion_signals",
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
    "review_packet": {
        "summary": (
            "Human-oriented grouping of check results, required evidence, "
            "exceptions, and raw finding refs."
        ),
        "trust_boundaries": ["derived_review_signal"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "review_posture",
            "subject",
            "policy_result_groups",
            "expert_question_groups",
            "recommendations",
            "required_exceptions",
            "raw_finding_refs",
        ],
        "hostile_fields": ["subject", "recommendations", "required_exceptions"],
    },
    "external_evidence_record": {
        "summary": "Provider-neutral OpenSSF-aligned snapshot record consumed offline.",
        "trust_boundaries": ["external_evidence_snapshot_untrusted"],
        "required_fields": [*_COMMON_REQUIRED_FIELDS, "provider", "subject", "source", "claims"],
        "hostile_fields": ["provider", "subject", "source", "claims"],
    },
    "named_expert_check": {
        "summary": "Reviewed-code check contract promoted from an expert operating question.",
        "trust_boundaries": ["derived_review_signal"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "check_id",
            "expert_question",
            "classification",
            "applies_to",
            "evidence_consumed",
            "status_conditions",
            "required_next_action",
            "rationale",
            "limitations",
        ],
        "hostile_fields": ["rationale", "limitations"],
    },
    "expert_check_result": {
        "summary": "Deterministic result of applying one named expert check to bounded evidence.",
        "trust_boundaries": ["derived_review_signal"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "check_id",
            "expert_question",
            "status",
            "subject",
            "missing_evidence",
            "required_next_action",
            "rationale",
            "limitations",
        ],
        "hostile_fields": ["subject", "rationale", "limitations"],
    },
    "exception_record": {
        "summary": (
            "Explicit human/project exception for a violated or missing-evidence check result."
        ),
        "trust_boundaries": ["derived_review_signal"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "exception_id",
            "scope",
            "applies_to_check_ids",
            "rationale",
            "approver",
            "expires_or_review_by",
            "compensating_controls",
        ],
        "hostile_fields": ["rationale", "approver", "compensating_controls"],
    },
    "lore_search_result_set": {
        "summary": "Bounded lore.kernel.org Atom search result with normalized message artifacts.",
        "trust_boundaries": ["remote_archive_email_untrusted"],
        "required_fields": [*_COMMON_REQUIRED_FIELDS, "query", "source_url", "messages"],
        "hostile_fields": ["query", "source_url", "messages"],
    },
    "github_commit_source": {
        "summary": "Parsed immutable GitHub-hosted commit source before network fetch.",
        "trust_boundaries": ["remote_github_metadata_untrusted"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "owner",
            "repo",
            "commit",
            "source",
            "clone_url",
        ],
        "hostile_fields": ["owner", "repo", "commit", "source", "clone_url"],
    },
    "github_commit_materialization": {
        "summary": "Controlled bare-cache fetch of one immutable GitHub-hosted commit.",
        "trust_boundaries": ["remote_github_metadata_untrusted", "local_git_metadata_untrusted"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "repo_identity",
            "commit",
            "local_repo",
            "source",
            "provenance",
        ],
        "hostile_fields": ["repo_identity", "commit", "source", "provenance"],
    },
    "github_pull_request_source": {
        "summary": "Parsed GitHub pull-request source before API resolution.",
        "trust_boundaries": ["remote_github_metadata_untrusted"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "owner",
            "repo",
            "pull_request",
            "source",
            "api_url",
            "commits_api_url",
            "clone_url",
        ],
        "hostile_fields": [
            "owner",
            "repo",
            "pull_request",
            "source",
            "api_url",
            "commits_api_url",
            "clone_url",
        ],
    },
    "github_pull_request_materialization": {
        "summary": "Controlled API and bare-cache resolution of one GitHub pull request.",
        "trust_boundaries": ["remote_github_metadata_untrusted", "local_git_metadata_untrusted"],
        "required_fields": [
            *_COMMON_REQUIRED_FIELDS,
            "repo_identity",
            "pull_request",
            "local_repo",
            "source",
            "base",
            "head",
            "commits",
            "provenance",
        ],
        "hostile_fields": [
            "repo_identity",
            "pull_request",
            "source",
            "title",
            "body_excerpt",
            "author",
            "base",
            "head",
            "commits",
            "provenance",
        ],
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
        _validate_named_check_fields(errors, prefix, artifact)
        _validate_check_result_fields(errors, prefix, artifact)
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


def _validate_named_check_fields(errors: list[str], prefix: str, artifact: JsonObject) -> None:
    if artifact.get("artifact_type") != "named_expert_check":
        return
    classification = artifact.get("classification")
    if classification not in NAMED_CHECK_CLASSIFICATIONS:
        errors.append(f"{prefix}.classification is unknown: {classification}")
    status_conditions = artifact.get("status_conditions")
    if not isinstance(status_conditions, dict):
        errors.append(f"{prefix}.status_conditions must be an object")
        return
    for status in CHECK_RESULT_STATUSES:
        if status not in status_conditions:
            errors.append(f"{prefix}.status_conditions.{status} is required")


def _validate_check_result_fields(errors: list[str], prefix: str, artifact: JsonObject) -> None:
    if artifact.get("artifact_type") != "expert_check_result":
        return
    status = artifact.get("status")
    if status not in CHECK_RESULT_STATUSES:
        errors.append(f"{prefix}.status is unknown: {status}")
    if status != "not_applicable" and not _is_non_empty_string_list(artifact.get("evidence_refs")):
        errors.append(f"{prefix}.evidence_refs are required for applicable check results")
    if status in {"violated", "missing_evidence", "inconclusive"}:
        next_action = artifact.get("required_next_action")
        if not isinstance(next_action, str) or not next_action.strip():
            errors.append(f"{prefix}.required_next_action must describe the human next step")


def _is_non_empty_string_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) for item in value)
