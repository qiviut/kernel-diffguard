"""Human-oriented review packets over deterministic findings and check results."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

JsonObject = dict[str, Any]
CHECK_STATUSES = (
    "satisfied",
    "violated",
    "missing_evidence",
    "inconclusive",
    "not_applicable",
    "no_check_coverage",
)
ACTIONABLE_STATUSES = {"violated", "missing_evidence", "inconclusive", "no_check_coverage"}


def build_review_packet(review: JsonObject) -> JsonObject:
    """Build a review packet that separates policy/check outcomes from raw findings."""

    check_results = list(review.get("expert_check_results", []))
    subject = _review_subject(review)
    evidence_refs = _packet_evidence_refs(review, check_results)
    return {
        "artifact_type": "review_packet",
        "schema_version": 1,
        "id": f"review-packet:{subject['kind']}:{subject['id']}",
        "evidence_refs": evidence_refs,
        "review_posture": review.get("review_posture", "review-assistant-not-verdict"),
        "subject": subject,
        "policy_result_groups": _group_check_results(check_results),
        "expert_question_groups": _expert_question_groups(review, check_results),
        "recommendations": [
            *_recommendations(check_results),
            *_coverage_gap_recommendations(review, check_results),
        ],
        "required_exceptions": _required_exceptions(check_results),
        "raw_finding_refs": _raw_finding_refs(review),
        "trust_boundary": "derived_review_signal",
        "limits": _packet_limits(review),
        "risk_hints": [
            "human-review-required",
            "raw-findings-are-evidence-not-verdicts",
            "not-maliciousness-verdict",
        ],
    }


def render_review_packet_text(packet: JsonObject) -> list[str]:
    """Render packet essentials as concise human-readable text lines."""

    lines = ["Review packet:"]
    lines.append(f"- posture: {packet['review_posture']}")
    subject = packet.get("subject", {})
    lines.append(f"- subject: {subject.get('kind', 'unknown')} {subject.get('id', '')}")

    lines.append("Policy/check result groups:")
    groups = packet.get("policy_result_groups", {})
    for status in CHECK_STATUSES:
        refs = groups.get(status, [])
        lines.append(f"- {status}: {_format_refs(refs)}")

    lines.append("Expert questions:")
    question_groups = packet.get("expert_question_groups", {})
    for question_id in sorted(str(key) for key in question_groups):
        question = question_groups[question_id]
        lines.append(f"- {question_id}:")
        for status in CHECK_STATUSES:
            refs = question.get(status, [])
            if refs:
                lines.append(f"  - {status}: {_format_refs(refs)}")

    recommendations = packet.get("recommendations", [])
    lines.append("Required next actions:")
    if not recommendations:
        lines.append("- none")
    for recommendation in recommendations:
        policy_ref = (
            recommendation.get("policy_id")
            or recommendation.get("check_id")
            or recommendation.get("finding_id")
            or recommendation.get("id")
        )
        lines.append(
            f"- {policy_ref} [{recommendation['status']}]: "
            f"{recommendation['required_next_action']}"
        )
        lines.append(f"  evidence: {_format_refs(recommendation.get('evidence_refs', []))}")
        missing = recommendation.get("missing_evidence", [])
        if missing:
            lines.append(f"  missing evidence: {_format_refs(missing)}")

    exceptions = packet.get("required_exceptions", [])
    lines.append("Required exceptions:")
    if not exceptions:
        lines.append("- none")
    for exception in exceptions:
        policy_ref = exception.get("policy_id") or exception.get("check_id")
        lines.append(f"- {policy_ref}: {exception['required_next_action']}")
        lines.append(f"  evidence: {_format_refs(exception.get('evidence_refs', []))}")

    raw_refs = packet.get("raw_finding_refs", [])
    lines.append("Raw deterministic findings remain evidence, not verdicts:")
    lines.append(f"- {_format_refs(raw_refs)}")
    return lines


def demo_status_mix_packet() -> JsonObject:
    """Return a deterministic packet fixture covering satisfied/violated/missing statuses."""

    review = {
        "schema_version": 1,
        "review_posture": "review-assistant-not-verdict",
        "commit": "demo-commit",
        "subject": "Demo packet status mix",
        "findings": [
            {"id": "removed-test", "evidence_refs": ["path:tests/test_guard.py"]},
            {
                "id": "ci-static-analysis-weakened",
                "evidence_refs": ["path:.github/workflows/ci.yml"],
            },
        ],
        "expert_check_results": [
            _demo_result(
                "KDG-CHECK-DEMO-SATISFIED",
                "satisfied",
                "No action required; replacement evidence is present.",
                ["finding:replacement-test-added", "path:tests/test_replacement.py"],
                [],
            ),
            _demo_result(
                "KDG-CHECK-DEMO-VIOLATED",
                "violated",
                "Restore the required gate or record an accepted exception.",
                ["finding:required-gate-removed", "path:.github/workflows/ci.yml"],
                [],
            ),
            _demo_result(
                "KDG-CHECK-DEMO-MISSING-EVIDENCE",
                "missing_evidence",
                "Provide replacement coverage or record a scoped maintainer exception.",
                ["finding:removed-test", "path:tests/test_guard.py"],
                ["replacement coverage evidence", "accepted exception record"],
            ),
        ],
    }
    return build_review_packet(review)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render deterministic review packet fixtures.")
    parser.add_argument(
        "--demo-status-mix",
        action="store_true",
        help="emit a synthetic review packet covering satisfied/violated/missing statuses",
    )
    args = parser.parse_args(argv)
    if args.demo_status_mix:
        print(json.dumps(demo_status_mix_packet(), indent=2, sort_keys=True))
        return 0
    parser.error("no review packet input provided")
    return 2


def _review_subject(review: JsonObject) -> JsonObject:
    if "range" in review:
        range_info = review["range"]
        return {
            "kind": "range",
            "id": str(range_info.get("id", "range")),
            "base": range_info.get("base"),
            "target": range_info.get("target"),
        }
    return {"kind": "commit", "id": str(review.get("commit", "unknown"))}


def _group_check_results(check_results: list[JsonObject]) -> JsonObject:
    groups: JsonObject = {status: [] for status in CHECK_STATUSES}
    for result in check_results:
        status = str(result.get("status", "inconclusive"))
        if status not in groups or status == "no_check_coverage":
            status = "inconclusive"
        groups[status].append(_result_ref(result))
    return groups


def _expert_question_groups(review: JsonObject, check_results: list[JsonObject]) -> JsonObject:
    groups: JsonObject = {}
    for result in check_results:
        question_id = str(result.get("expert_question", "unknown"))
        status = str(result.get("status", "inconclusive"))
        if status not in CHECK_STATUSES or status == "no_check_coverage":
            status = "inconclusive"
        question = groups.setdefault(question_id, {key: [] for key in CHECK_STATUSES})
        question[status].append(_result_ref(result))
    coverage_gaps = _coverage_gap_refs(review, check_results)
    if coverage_gaps:
        groups["no_check_coverage"] = {key: [] for key in CHECK_STATUSES}
        groups["no_check_coverage"]["no_check_coverage"] = coverage_gaps
    return groups


def _coverage_gap_refs(review: JsonObject, check_results: list[JsonObject]) -> list[JsonObject]:
    covered_findings = {
        ref
        for result in check_results
        for ref in (str(item) for item in result.get("evidence_refs", []))
        if ref.startswith("finding:") or ":finding:" in ref
    }
    gaps: list[JsonObject] = []
    for finding_ref in _all_finding_refs(review):
        finding = finding_ref["finding"]
        canonical_ref = str(finding_ref["ref"])
        finding_id = str(finding.get("id", "unknown"))
        if f"finding:{finding_id}" in covered_findings or canonical_ref in covered_findings:
            continue
        gaps.append(
            {
                "id": f"coverage-gap:{canonical_ref}",
                "status": "no_check_coverage",
                "finding_id": finding_id,
                "evidence_refs": _finding_evidence_refs(finding, canonical_ref),
            }
        )
    return gaps


def _coverage_gap_recommendations(
    review: JsonObject, check_results: list[JsonObject]
) -> list[JsonObject]:
    recommendations: list[JsonObject] = []
    for gap in _coverage_gap_refs(review, check_results):
        finding_id = gap["finding_id"]
        recommendations.append(
            {
                "id": f"recommendation:coverage-gap:{finding_id}",
                "status": "no_check_coverage",
                "required_next_action": (
                    "Decide whether this deterministic finding needs a named check, "
                    "accepted exception path, or should remain raw evidence only."
                ),
                "evidence_refs": gap["evidence_refs"],
                "missing_evidence": ["accepted named-check coverage decision"],
                "finding_id": finding_id,
            }
        )
    return recommendations


def _recommendations(check_results: list[JsonObject]) -> list[JsonObject]:
    recommendations: list[JsonObject] = []
    for result in check_results:
        status = str(result.get("status", "inconclusive"))
        if status not in ACTIONABLE_STATUSES:
            continue
        recommendation: JsonObject = {
            "id": f"recommendation:{_policy_or_check_id(result)}",
            "status": status,
            "required_next_action": str(result.get("required_next_action", "Review required.")),
            "evidence_refs": [str(ref) for ref in result.get("evidence_refs", [])],
            "missing_evidence": [str(item) for item in result.get("missing_evidence", [])],
        }
        _copy_policy_fields(result, recommendation)
        recommendations.append(recommendation)
    return recommendations


def _required_exceptions(check_results: list[JsonObject]) -> list[JsonObject]:
    exceptions: list[JsonObject] = []
    for result in check_results:
        missing_evidence = [str(item) for item in result.get("missing_evidence", [])]
        if not any("exception" in item.lower() for item in missing_evidence):
            continue
        exception: JsonObject = {
            "id": f"exception-required:{_policy_or_check_id(result)}",
            "status": result.get("status", "missing_evidence"),
            "required_next_action": str(result.get("required_next_action", "Record an exception.")),
            "missing_evidence": missing_evidence,
            "evidence_refs": [str(ref) for ref in result.get("evidence_refs", [])],
        }
        _copy_policy_fields(result, exception)
        exceptions.append(exception)
    return exceptions


def _raw_finding_refs(review: JsonObject) -> list[str]:
    return _unique([str(item["ref"]) for item in _all_finding_refs(review)])


def _all_findings(review: JsonObject) -> list[JsonObject]:
    return [item["finding"] for item in _all_finding_refs(review)]


def _all_finding_refs(review: JsonObject) -> list[JsonObject]:
    findings: list[JsonObject] = []
    for finding in review.get("findings", []):
        if isinstance(finding, dict) and isinstance(finding.get("id"), str):
            findings.append({"finding": finding, "ref": f"finding:{finding['id']}"})
    for commit_review in review.get("commits", []):
        commit = commit_review.get("commit", "unknown")
        for finding in commit_review.get("findings", []):
            if isinstance(finding, dict) and isinstance(finding.get("id"), str):
                findings.append(
                    {"finding": finding, "ref": f"commit:{commit}:finding:{finding['id']}"}
                )
    return findings


def _finding_evidence_refs(finding: JsonObject, canonical_ref: str) -> list[str]:
    refs = finding.get("evidence_refs")
    if not isinstance(refs, list):
        refs = finding.get("evidence", [])
    evidence_refs = [str(ref) for ref in refs] if isinstance(refs, list) else []
    return _unique([canonical_ref, *evidence_refs])


def _packet_evidence_refs(review: JsonObject, check_results: list[JsonObject]) -> list[str]:
    refs = [str(result["id"]) for result in check_results if isinstance(result.get("id"), str)]
    refs.extend(_raw_finding_refs(review))
    if not refs:
        refs.append(str(_review_subject(review)["id"]))
    return _unique(refs)


def _packet_limits(review: JsonObject) -> JsonObject:
    if "range" in review:
        limits = review["range"].get("limits", {})
    else:
        limits = review.get("commit_artifact", {}).get("limits", {})
    return {
        "truncated": bool(limits.get("truncated", False)),
        "omitted_record_count": int(limits.get("omitted_record_count", 0) or 0),
    }


def _demo_result(
    check_id: str,
    status: str,
    action: str,
    evidence_refs: list[str],
    missing_evidence: list[str],
) -> JsonObject:
    return {
        "artifact_type": "expert_check_result",
        "id": f"check-result:{check_id}:demo-commit",
        "check_id": check_id,
        "policy_id": check_id.replace("KDG-CHECK", "KDG-POLICY"),
        "expert_question": "UQ-DEMO",
        "status": status,
        "subject": {"kind": "commit", "id": "demo-commit"},
        "missing_evidence": missing_evidence,
        "required_next_action": action,
        "rationale": "Synthetic review-packet contract fixture.",
        "limitations": "Fixture only; not an analyzer verdict.",
        "evidence_refs": evidence_refs,
        "trust_boundary": "derived_review_signal",
        "limits": {"truncated": False, "omitted_record_count": 0},
        "risk_hints": ["human-review-required", "not-maliciousness-verdict"],
    }


def _result_ref(result: JsonObject) -> JsonObject:
    ref: JsonObject = {
        "id": str(result.get("id", _policy_or_check_id(result))),
        "status": str(result.get("status", "inconclusive")),
        "evidence_refs": [str(item) for item in result.get("evidence_refs", [])],
    }
    _copy_policy_fields(result, ref)
    return ref


def _copy_policy_fields(source: JsonObject, target: JsonObject) -> None:
    if source.get("policy_id"):
        target["policy_id"] = str(source["policy_id"])
    if source.get("check_id"):
        target["check_id"] = str(source["check_id"])


def _policy_or_check_id(result: JsonObject) -> str:
    return str(result.get("policy_id") or result.get("check_id") or result.get("id") or "unknown")


def _format_refs(refs: object) -> str:
    if not isinstance(refs, list) or not refs:
        return "none"
    return ", ".join(str(ref) for ref in refs[:6])


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
