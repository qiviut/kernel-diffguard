from __future__ import annotations

import json
from pathlib import Path

import pytest

from kernel_diffguard.golden import run_golden_manifest


def test_golden_runner_reports_matching_case(tmp_path: Path):
    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps({"schema_version": 1, "findings": []}, indent=2))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "empty-case",
                        "command": [
                            "python",
                            "-c",
                            "import json; print(json.dumps({'schema_version': 1, 'findings': []}))",
                        ],
                        "expected": str(expected),
                    }
                ]
            }
        )
    )

    result = run_golden_manifest(manifest)

    assert result.exit_code == 0
    assert result.case_count == 1
    assert result.changed_cases == []


def test_golden_runner_prepares_builtin_suspicious_commit_fixture(tmp_path: Path):
    expected = tmp_path / "expected.json"
    expected.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "review_posture": "review-assistant-not-verdict",
                "commit": "<commit>",
                "subject": "Maintenance update",
                "touched_paths": [
                    ".github/workflows/ci.yml",
                    "scripts/update.sh",
                    "security/backdoor.c",
                    "tests/test_guard.py",
                ],
                "findings": [
                    {"id": "removed-test"},
                    {"id": "ci-static-analysis-weakened"},
                    {"id": "suspicious-script-added"},
                    {"id": "prompt-injection-text"},
                    {"id": "high-risk-path"},
                ],
                "kernel_impacts": [{"id": "security-sensitive"}],
            },
            indent=2,
        )
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "builtin-suspicious-commit",
                        "fixture": "suspicious_single_commit",
                        "command": [
                            "kdiffguard",
                            "review-commit",
                            "--repo",
                            "{repo}",
                            "--commit",
                            "HEAD",
                            "--format",
                            "json",
                        ],
                        "expected": str(expected),
                        "ignore_fields": [
                            "commit_artifact",
                            "evidence",
                            "evidence_refs",
                            "false_positive_caveat",
                            "integrity_assessment",
                            "expert_check_results",
                            "optional_check_hooks",
                            "retest_hints",
                            "severity",
                            "summary",
                            "suggested_next_check",
                            "uncertainty",
                        ],
                        "normalize_fields": {"commit": "<commit>"},
                    }
                ]
            }
        )
    )

    result = run_golden_manifest(manifest)

    assert result.exit_code == 0
    assert result.case_count == 1


def test_golden_runner_normalizes_field_values_when_repeated_as_keys_or_list_items(
    tmp_path: Path,
):
    expected = tmp_path / "expected.json"
    expected.write_text(
        json.dumps(
            {
                "commit": "<commit>",
                "commits": ["<commit>"],
                "findings_by_commit": {"<commit>": [{"id": "signal"}]},
            },
            indent=2,
        )
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "normalized-nested-commit",
                        "command": [
                            "python",
                            "-c",
                            "import json; print(json.dumps({'commit': 'abc123', "
                            "'commits': ['abc123'], "
                            "'findings_by_commit': {'abc123': [{'id': 'signal'}]}}))",
                        ],
                        "expected": str(expected),
                        "normalize_fields": {"commit": "<commit>"},
                    }
                ]
            }
        )
    )

    result = run_golden_manifest(manifest)

    assert result.exit_code == 0
    assert result.changed_cases == []


def test_golden_runner_uses_manifest_order_for_repeated_value_collisions(
    tmp_path: Path,
):
    expected = tmp_path / "expected.json"
    expected.write_text(
        json.dumps(
            {
                "commit": "<commit>",
                "target": "<target>",
                "commits": ["<commit>"],
                "findings_by_commit": {"<commit>": [{"id": "signal"}]},
            },
            indent=2,
        )
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "normalized-collision",
                        "command": [
                            "python",
                            "-c",
                            "import json; print(json.dumps({'commit': 'abc123', "
                            "'target': 'abc123', 'commits': ['abc123'], "
                            "'findings_by_commit': {'abc123': [{'id': 'signal'}]}}))",
                        ],
                        "expected": str(expected),
                        "normalize_fields": {"commit": "<commit>", "target": "<target>"},
                    }
                ]
            }
        )
    )

    result = run_golden_manifest(manifest)

    assert result.exit_code == 0
    assert result.changed_cases == []


def test_golden_runner_rejects_normalized_key_collisions(tmp_path: Path):
    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps({"<commit>": {"id": "expected"}}, indent=2))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "normalized-key-collision",
                        "command": [
                            "python",
                            "-c",
                            "import json; print(json.dumps({'commit': 'abc123', "
                            "'abc123': {'id': 'actual'}, "
                            "'<commit>': {'id': 'preexisting'}}))",
                        ],
                        "expected": str(expected),
                        "normalize_fields": {"commit": "<commit>"},
                    }
                ]
            }
        )
    )

    with pytest.raises(ValueError, match="normalization collision"):
        run_golden_manifest(manifest)


def test_golden_runner_reports_finding_diff(tmp_path: Path):
    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps({"schema_version": 1, "findings": []}, indent=2))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "changed-case",
                        "command": [
                            "python",
                            "-c",
                            "import json; data={'schema_version': 1, "
                            "'findings': [{'id': 'new'}]}; print(json.dumps(data))",
                        ],
                        "expected": str(expected),
                    }
                ]
            }
        )
    )

    result = run_golden_manifest(manifest)

    assert result.exit_code == 1
    assert result.changed_cases == ["changed-case"]
    assert "changed-case" in result.report
    assert "Review sections:" in result.report
    assert "- Stable facts: none" in result.report
    assert "- Changed findings: $.findings[0]" in result.report
    assert "- Changed policy/check results: none" in result.report
    assert "- Changed missing-evidence obligations: none" in result.report
    assert "- Allowed metadata drift: ignored=none, normalized=none" in result.report
    assert "Full normalized JSON diff:" in result.report
    assert '"id": "new"' in result.report


def test_golden_runner_reports_policy_and_missing_evidence_diff(tmp_path: Path):
    expected = tmp_path / "expected.json"
    expected.write_text(
        json.dumps(
            {
                "expert_check_results": [
                    {
                        "check_id": "KDG-CHECK-REMOVED-TEST",
                        "status": "satisfied",
                        "missing_evidence": [],
                    }
                ]
            },
            indent=2,
        )
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "policy-change",
                        "command": [
                            "python",
                            "-c",
                            "import json; print(json.dumps({'expert_check_results': [{"
                            "'check_id': 'KDG-CHECK-REMOVED-TEST', "
                            "'status': 'missing_evidence', "
                            "'missing_evidence': ['replacement coverage evidence']}]}))",
                        ],
                        "expected": str(expected),
                        "ignore_fields": ["duration_ms"],
                        "normalize_fields": {"commit": "<commit>"},
                    }
                ]
            }
        )
    )

    result = run_golden_manifest(manifest)

    assert result.exit_code == 1
    assert "- Changed policy/check results: $.expert_check_results[0].status" in result.report
    assert (
        "- Changed missing-evidence obligations: $.expert_check_results[0].missing_evidence[0]"
        in result.report
    )
    assert "- Allowed metadata drift: ignored=duration_ms, normalized=commit" in result.report
