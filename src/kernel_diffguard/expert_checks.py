"""Deterministic named expert checks over reduced review evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

JsonObject = dict[str, Any]


@dataclass(frozen=True)
class NamedExpertCheck:
    check_id: str
    expert_question: str
    rationale: str
    limitations: str
    required_next_action: str
    finding_ids: tuple[str, ...]
    missing_evidence: tuple[str, ...]


REMOVED_TEST_CHECK = NamedExpertCheck(
    check_id="KDG-CHECK-REMOVED-TEST",
    expert_question="UQ-004",
    rationale=(
        "Removed tests weaken feedback loops and must be paired with replacement "
        "coverage or an explicit exception."
    ),
    limitations=(
        "This check consumes existing removed-test signals only; it does not "
        "perform semantic coverage or rename analysis."
    ),
    required_next_action=(
        "Provide replacement test evidence, restore coverage, or record a scoped "
        "maintainer exception."
    ),
    finding_ids=("removed-test",),
    missing_evidence=("replacement coverage evidence", "accepted exception record"),
)

CI_STATIC_ANALYSIS_CHECK = NamedExpertCheck(
    check_id="KDG-CHECK-CI-STATIC-ANALYSIS-WEAKENED",
    expert_question="UQ-004",
    rationale=(
        "Weakened CI, static-analysis, warning, sanitizer, or fuzzing gates can "
        "let later unsafe changes pass undetected."
    ),
    limitations=(
        "This check is marker and path based; it cannot prove whether a changed "
        "gate was equivalently moved or replaced elsewhere."
    ),
    required_next_action=(
        "Cite the replacement gate, provide required-check context, restore the "
        "gate, or record an explicit exception."
    ),
    finding_ids=("ci-static-analysis-weakened", "warning-policy-weakened"),
    missing_evidence=(
        "required gate policy evidence",
        "equivalent replacement command evidence",
        "accepted exception record",
    ),
)

IMPLEMENTED_CHECKS = (REMOVED_TEST_CHECK, CI_STATIC_ANALYSIS_CHECK)


def evaluate_commit_checks(review: JsonObject) -> list[JsonObject]:
    """Evaluate initial named expert checks for one commit review."""

    subject = {"kind": "commit", "id": str(review["commit"])}
    evidence_subject_ref = f"commit:{review['commit']}"
    return [
        _evaluate_check(
            check, subject, evidence_subject_ref, _commit_findings(review), _commit_limits(review)
        )
        for check in IMPLEMENTED_CHECKS
    ]


def evaluate_range_checks(review: JsonObject) -> list[JsonObject]:
    """Evaluate initial named expert checks for one commit range review."""

    range_info = review["range"]
    subject = {
        "kind": "range",
        "id": str(range_info["id"]),
        "base": range_info.get("base"),
        "target": range_info.get("target"),
    }
    evidence_subject_ref = str(range_info["id"])
    findings: list[JsonObject] = []
    for commit_review in review.get("commits", []):
        findings.extend(
            _commit_findings(commit_review, subject_prefix=f"commit:{commit_review['commit']}")
        )
    if review.get("merge_tree_delta"):
        delta = review["merge_tree_delta"]
        findings.extend(
            _commit_findings(delta, subject_prefix=f"merge-tree-delta:{delta['commit']}")
        )
    return [
        _evaluate_check(
            check, subject, evidence_subject_ref, findings, range_info.get("limits", {})
        )
        for check in IMPLEMENTED_CHECKS
    ]


def render_check_results_text(check_results: list[JsonObject]) -> list[str]:
    """Render check results as compact text lines."""

    lines = ["Named expert check results:"]
    if not check_results:
        lines.append("- none")
        return lines
    for result in check_results:
        lines.append(
            f"- {result['check_id']} [{result['status']}]: {result['required_next_action']}"
        )
        evidence_refs = result.get("evidence_refs", [])
        if evidence_refs:
            lines.append(f"  evidence: {', '.join(str(ref) for ref in evidence_refs[:6])}")
        missing = result.get("missing_evidence", [])
        if missing:
            lines.append(f"  missing evidence: {', '.join(str(item) for item in missing[:6])}")
    return lines


def _commit_findings(review: JsonObject, *, subject_prefix: str | None = None) -> list[JsonObject]:
    findings: list[JsonObject] = []
    for finding in review.get("findings", []):
        copied = dict(finding)
        if subject_prefix:
            copied["evidence_refs"] = [
                f"{subject_prefix}:{ref}" for ref in _finding_refs(copied)
            ]
        findings.append(copied)
    return findings


def _commit_limits(review: JsonObject) -> JsonObject:
    artifact = review.get("commit_artifact", {})
    limits = artifact.get("limits", {})
    return _result_limits(limits)


def _finding_refs(finding: JsonObject) -> list[str]:
    refs = finding.get("evidence_refs")
    if not isinstance(refs, list):
        refs = finding.get("evidence", [])
    if not isinstance(refs, list):
        return []
    return [str(ref) for ref in refs]


def _evaluate_check(
    check: NamedExpertCheck,
    subject: JsonObject,
    evidence_subject_ref: str,
    findings: list[JsonObject],
    limits: JsonObject,
) -> JsonObject:
    matched = [finding for finding in findings if finding.get("id") in check.finding_ids]
    if matched:
        status = "missing_evidence"
        evidence_refs = _unique_refs(
            [
                f"finding:{finding['id']}"
                for finding in matched
                if isinstance(finding.get("id"), str)
            ]
            + [str(ref) for finding in matched for ref in _finding_refs(finding)]
        )
        missing_evidence = list(check.missing_evidence)
    else:
        status = "not_applicable"
        evidence_refs = [evidence_subject_ref]
        missing_evidence = []

    result_id_subject = str(subject.get("id", subject.get("kind", "subject")))
    return {
        "artifact_type": "expert_check_result",
        "id": f"check-result:{check.check_id}:{result_id_subject}",
        "check_id": check.check_id,
        "expert_question": check.expert_question,
        "status": status,
        "subject": subject,
        "missing_evidence": missing_evidence,
        "required_next_action": check.required_next_action
        if status != "not_applicable"
        else "No action required for this check on this subject.",
        "rationale": check.rationale,
        "limitations": check.limitations,
        "evidence_refs": evidence_refs,
        "trust_boundary": "derived_review_signal",
        "limits": _result_limits(limits),
        "risk_hints": ["human-review-required", "not-maliciousness-verdict"]
        if matched
        else ["not-applicable-not-verdict"],
    }


def _result_limits(limits: JsonObject) -> JsonObject:
    return {
        "truncated": bool(limits.get("truncated", False)),
        "omitted_record_count": int(limits.get("omitted_record_count", 0) or 0),
    }


def _unique_refs(refs: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for ref in refs:
        if ref in seen:
            continue
        seen.add(ref)
        unique.append(ref)
    return unique
