from __future__ import annotations

import json
from pathlib import Path

from kernel_diffguard.cli import main
from kernel_diffguard.scorecard import build_scorecard, render_json, render_text


def test_scorecard_counts_current_reviewer_value_dimensions():
    scorecard = build_scorecard(Path.cwd())

    assert scorecard["schema_version"] == 1
    assert scorecard["review_posture"] == "metrics-are-steering-signals-not-product-claims"
    assert scorecard["counts"] == {
        "supported_input_shapes": 3,
        "heuristic_findings": 5,
        "golden_cases": 2,
        "schema_fields_with_evidence_references": 7,
        "end_to_end_reviewer_examples": 2,
    }
    assert scorecard["iteration_value_policy"] == {
        "feature_changes_require_scorecard_delta": True,
        "pure_maintenance_may_leave_counts_unchanged": True,
    }

    assert scorecard["supported_input_shapes"] == [
        "local single commit",
        "local base-exclusive/target-inclusive range",
        "explicit ordered local commit list",
    ]
    assert scorecard["heuristic_findings"] == [
        "ci-static-analysis-weakened",
        "high-risk-path",
        "prompt-injection-text",
        "removed-test",
        "suspicious-script-added",
    ]
    assert scorecard["golden_cases"] == ["suspicious-range", "suspicious-single-commit"]


def test_scorecard_renderers_are_deterministic_and_human_readable():
    scorecard = build_scorecard(Path.cwd())

    rendered = render_json(scorecard)
    assert json.loads(rendered) == scorecard
    assert rendered.endswith("\n")

    text = render_text(scorecard)
    assert "Review-signal scorecard" in text
    assert "supported input shapes: 3" in text
    assert "heuristic findings: 5" in text
    assert "golden cases: 2" in text
    assert "feature changes require a scorecard delta" in text


def test_scorecard_cli_emits_json_and_text(capsys):
    assert main(["scorecard", "--format", "json"]) == 0
    json_output = capsys.readouterr().out
    assert json.loads(json_output)["counts"]["golden_cases"] == 2

    assert main(["scorecard", "--format", "text"]) == 0
    text_output = capsys.readouterr().out
    assert "Review-signal scorecard" in text_output
    assert "golden cases: 2" in text_output
