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
        "supported_input_shapes": 9,
        "heuristic_findings": 14,
        "golden_cases": 3,
        "schema_fields_with_evidence_references": 15,
        "normalized_evidence_artifact_schemas": 12,
        "trust_boundary_labels": 6,
        "end_to_end_reviewer_examples": 3,
    }
    assert scorecard["normalized_evidence_artifact_schemas"] == [
        "commit_artifact",
        "commit_range_manifest",
        "external_evidence_record",
        "finding",
        "github_commit_materialization",
        "github_commit_source",
        "github_pull_request_materialization",
        "github_pull_request_source",
        "lore_search_result_set",
        "mailing_list_message_artifact",
        "recommendation",
        "related_message_candidate",
    ]
    assert scorecard["trust_boundary_labels"] == [
        "derived_review_signal",
        "external_evidence_snapshot_untrusted",
        "local_git_diff_untrusted",
        "local_git_metadata_untrusted",
        "remote_archive_email_untrusted",
        "remote_github_metadata_untrusted",
    ]
    assert scorecard["iteration_value_policy"] == {
        "feature_changes_require_scorecard_delta": True,
        "pure_maintenance_may_leave_counts_unchanged": True,
    }

    assert scorecard["supported_input_shapes"] == [
        "local single commit",
        "local base-exclusive/target-inclusive range",
        "explicit ordered local commit list",
        "local merge commit expansion",
        "single RFC822/mbox mailing-list message",
        "normalized commit/message related-candidate scoring",
        "lore.kernel.org Atom search to normalized message artifacts",
        "GitHub-hosted immutable commit input",
        "GitHub pull request read-only review",
    ]
    assert scorecard["heuristic_findings"] == [
        "body-excerpt-truncated",
        "ci-static-analysis-weakened",
        "executable-looking-snippet",
        "generated-code-churn",
        "high-risk-path",
        "hostile-instruction-language",
        "linux-security-cue",
        "patch-content-present",
        "discussion-signal-records-truncated",
        "prompt-injection-text",
        "removed-test",
        "suspicious-script-added",
        "url-present",
        "warning-policy-weakened",
    ]
    assert scorecard["golden_cases"] == [
        "linux-security-commit",
        "suspicious-range",
        "suspicious-single-commit",
    ]


def test_scorecard_renderers_are_deterministic_and_human_readable():
    scorecard = build_scorecard(Path.cwd())

    rendered = render_json(scorecard)
    assert json.loads(rendered) == scorecard
    assert rendered.endswith("\n")

    text = render_text(scorecard)
    assert "Review-signal scorecard" in text
    assert "supported input shapes: 9" in text
    assert "heuristic findings: 14" in text
    assert "golden cases: 3" in text
    assert "schema fields with evidence references: 15" in text
    assert "normalized evidence artifact schemas: 12" in text
    assert "trust boundary labels: 6" in text
    assert "feature changes require a scorecard delta" in text


def test_scorecard_cli_emits_json_and_text(capsys):
    assert main(["scorecard", "--format", "json"]) == 0
    json_output = capsys.readouterr().out
    assert json.loads(json_output)["counts"]["golden_cases"] == 3

    assert main(["scorecard", "--format", "text"]) == 0
    text_output = capsys.readouterr().out
    assert "Review-signal scorecard" in text_output
    assert "golden cases: 3" in text_output
