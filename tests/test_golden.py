from __future__ import annotations

import json
from pathlib import Path

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
                            "evidence",
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
    assert '"id": "new"' in result.report
