"""Deterministic review-signal value scorecard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]

SUPPORTED_INPUT_SHAPES = (
    "local single commit",
    "local base-exclusive/target-inclusive range",
    "explicit ordered local commit list",
)

HEURISTIC_FINDINGS = (
    "ci-static-analysis-weakened",
    "high-risk-path",
    "prompt-injection-text",
    "removed-test",
    "suspicious-script-added",
)

SCHEMA_FIELDS_WITH_EVIDENCE_REFERENCES = (
    "finding.evidence",
    "finding.id",
    "finding.suggested_next_check",
    "finding.uncertainty",
    "kernel_impact.evidence",
    "kernel_impact.retest_hints",
    "kernel_impact.uncertainty",
)


def build_scorecard(project_root: Path | str) -> JsonObject:
    """Build a cheap deterministic scorecard for current reviewer value."""

    root = Path(project_root)
    golden_cases = _golden_case_names(root / "tests" / "golden" / "manifest.json")
    reviewer_examples = _end_to_end_reviewer_examples(root)
    return {
        "schema_version": 1,
        "review_posture": "metrics-are-steering-signals-not-product-claims",
        "counts": {
            "supported_input_shapes": len(SUPPORTED_INPUT_SHAPES),
            "heuristic_findings": len(HEURISTIC_FINDINGS),
            "golden_cases": len(golden_cases),
            "schema_fields_with_evidence_references": len(
                SCHEMA_FIELDS_WITH_EVIDENCE_REFERENCES
            ),
            "end_to_end_reviewer_examples": len(reviewer_examples),
        },
        "supported_input_shapes": list(SUPPORTED_INPUT_SHAPES),
        "heuristic_findings": list(HEURISTIC_FINDINGS),
        "golden_cases": golden_cases,
        "schema_fields_with_evidence_references": list(SCHEMA_FIELDS_WITH_EVIDENCE_REFERENCES),
        "end_to_end_reviewer_examples": reviewer_examples,
        "iteration_value_policy": {
            "feature_changes_require_scorecard_delta": True,
            "pure_maintenance_may_leave_counts_unchanged": True,
        },
    }


def render_json(scorecard: JsonObject) -> str:
    """Render stable scorecard JSON."""

    return json.dumps(scorecard, indent=2, sort_keys=True) + "\n"


def render_text(scorecard: JsonObject) -> str:
    """Render a compact human-readable scorecard."""

    counts = scorecard["counts"]
    return "\n".join(
        [
            "Review-signal scorecard",
            f"- supported input shapes: {counts['supported_input_shapes']}",
            f"- heuristic findings: {counts['heuristic_findings']}",
            f"- golden cases: {counts['golden_cases']}",
            "- schema fields with evidence references: "
            f"{counts['schema_fields_with_evidence_references']}",
            f"- end-to-end reviewer examples: {counts['end_to_end_reviewer_examples']}",
            "- feature changes require a scorecard delta unless they are pure maintenance",
        ]
    )


def _golden_case_names(manifest_path: Path) -> list[str]:
    if not manifest_path.exists():
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        return []
    return sorted(str(case["name"]) for case in cases if isinstance(case, dict) and "name" in case)


def _end_to_end_reviewer_examples(project_root: Path) -> list[str]:
    examples = []
    for case_name in _golden_case_names(project_root / "tests" / "golden" / "manifest.json"):
        examples.append(f"golden:{case_name}")
    return examples
