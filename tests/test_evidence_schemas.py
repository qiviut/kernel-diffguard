from __future__ import annotations

from kernel_diffguard.evidence_schema import build_schema_catalog, validate_schema_fixture


def test_schema_catalog_names_required_artifacts_and_trust_boundaries():
    catalog = build_schema_catalog()

    assert catalog["schema_version"] == 1
    assert catalog["review_posture"] == "schemas-are-review-boundaries-not-verdicts"
    assert set(catalog["artifacts"]) >= {
        "commit_artifact",
        "commit_range_manifest",
        "mailing_list_message_artifact",
        "related_message_candidate",
        "finding",
        "recommendation",
        "external_evidence_record",
        "lore_search_result_set",
        "github_commit_source",
        "github_commit_materialization",
        "github_pull_request_source",
        "github_pull_request_materialization",
    }
    assert set(catalog["trust_boundary_labels"]) >= {
        "local_git_metadata_untrusted",
        "local_git_diff_untrusted",
        "remote_archive_email_untrusted",
        "remote_github_metadata_untrusted",
        "external_evidence_snapshot_untrusted",
        "derived_review_signal",
    }

    for artifact in catalog["artifacts"].values():
        assert "evidence_refs" in artifact["required_fields"]
        assert "trust_boundary" in artifact["required_fields"]
        assert "limits" in artifact["required_fields"]


def test_schema_fixture_validation_accepts_representative_artifacts():
    fixture = {
        "schema_version": 1,
        "artifacts": [
            {
                "artifact_type": "commit_artifact",
                "id": "commit:abc123",
                "commit": "abc123",
                "parents": ["def456"],
                "touched_paths": ["tests/test_guard.py"],
                "evidence_refs": ["git:commit:abc123"],
                "trust_boundary": "local_git_metadata_untrusted",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": ["prompt-injection-text"],
            },
            {
                "artifact_type": "commit_range_manifest",
                "id": "range:base..target",
                "base": "def456",
                "target": "abc123",
                "traversal": "base-exclusive-target-inclusive",
                "commits": ["abc123"],
                "evidence_refs": ["git:rev-list:base..target"],
                "trust_boundary": "derived_review_signal",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": [],
            },
            {
                "artifact_type": "mailing_list_message_artifact",
                "id": "message:<id@example.test>",
                "message_id": "<id@example.test>",
                "source_sha256": "0" * 64,
                "subject": "[PATCH] guard fix",
                "patch_series": {
                    "is_patch": True,
                    "revision": 1,
                    "series_position": None,
                    "series_total": None,
                    "is_cover_letter": False,
                },
                "from": "Fixture Author <fixture@example.test>",
                "plain_text_excerpt": "bounded hostile email text",
                "discussion_signals": {
                    "review_tags": [],
                    "objections": [],
                    "open_questions": [],
                    "unresolved_markers": [],
                },
                "evidence_refs": ["mail:message-id:<id@example.test>"],
                "trust_boundary": "remote_archive_email_untrusted",
                "limits": {"truncated": True, "omitted_record_count": 3},
                "risk_hints": ["hostile-instruction-language"],
            },
            {
                "artifact_type": "related_message_candidate",
                "id": "candidate:1",
                "commit_refs": ["commit:abc123"],
                "message_refs": ["message:<id@example.test>"],
                "match_evidence": ["patch-id"],
                "discussion_signals": {
                    "review_tags": [],
                    "objections": [],
                    "open_questions": [],
                    "unresolved_markers": [],
                },
                "evidence_refs": ["mail:message-id:<id@example.test>", "git:commit:abc123"],
                "trust_boundary": "derived_review_signal",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": [],
            },
            {
                "artifact_type": "github_commit_source",
                "id": "github:source:example/linux:abc123",
                "owner": "example",
                "repo": "linux",
                "commit": "a" * 40,
                "source": "example/linux@" + "a" * 40,
                "clone_url": "https://github.com/example/linux.git",
                "evidence_refs": ["github:commit:example/linux@" + "a" * 40],
                "trust_boundary": "remote_github_metadata_untrusted",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": ["github-transport-is-not-a-trust-oracle"],
            },
            {
                "artifact_type": "github_commit_materialization",
                "id": "github:materialized:example/linux:abc123",
                "repo_identity": "github:example/linux",
                "commit": "a" * 40,
                "local_repo": "/tmp/cache/example/linux.git",
                "source": {"owner": "example", "repo": "linux"},
                "provenance": {"remote_commit_sha": "a" * 40},
                "evidence_refs": ["github:commit:example/linux@" + "a" * 40],
                "trust_boundary": "remote_github_metadata_untrusted",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": ["github-transport-is-not-a-trust-oracle"],
            },
            {
                "artifact_type": "github_pull_request_source",
                "id": "github:pull-request-source:example/linux:7",
                "owner": "example",
                "repo": "linux",
                "pull_request": 7,
                "source": "example/linux#7",
                "api_url": "https://api.github.com/repos/example/linux/pulls/7",
                "commits_api_url": "https://api.github.com/repos/example/linux/pulls/7/commits",
                "clone_url": "https://github.com/example/linux.git",
                "evidence_refs": ["github:pull-request:example/linux#7"],
                "trust_boundary": "remote_github_metadata_untrusted",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": ["github-transport-is-not-a-trust-oracle"],
            },
            {
                "artifact_type": "github_pull_request_materialization",
                "id": "github:pull-request-materialized:example/linux:7",
                "repo_identity": "github:example/linux",
                "pull_request": 7,
                "local_repo": "/tmp/cache/example/linux.git",
                "source": {"owner": "example", "repo": "linux"},
                "base": {"sha": "a" * 40, "ref": "main"},
                "head": {"sha": "b" * 40, "ref": "topic"},
                "commits": ["b" * 40],
                "provenance": {"commit_order_source": "github-pulls-commits-api"},
                "evidence_refs": ["github:pull-request:example/linux#7"],
                "trust_boundary": "remote_github_metadata_untrusted",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": ["github-pr-metadata-is-hostile"],
            },
            {
                "artifact_type": "finding",
                "id": "finding:removed-test",
                "severity": "high",
                "summary": "A test was removed.",
                "uncertainty": "heuristic",
                "evidence_refs": ["path:tests/test_guard.py"],
                "trust_boundary": "derived_review_signal",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": ["review-assistant-not-verdict"],
            },
            {
                "artifact_type": "recommendation",
                "id": "recommendation:retest",
                "summary": "Run replacement regression tests.",
                "recommended_action": "Check whether coverage moved elsewhere.",
                "evidence_refs": ["finding:removed-test"],
                "trust_boundary": "derived_review_signal",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": ["human-review-required"],
            },
            {
                "artifact_type": "external_evidence_record",
                "id": "external:openssf-scorecard:branch-protection",
                "provider": "openssf-scorecard",
                "subject": {"kind": "repository", "identifier": "github.com/example/project"},
                "source": {"uri": "https://example.invalid/snapshot.json"},
                "claims": [{"id": "scorecard.branch_protection", "value": "unknown"}],
                "evidence_refs": ["external:scorecard:branch_protection"],
                "trust_boundary": "external_evidence_snapshot_untrusted",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": ["not-verdict"],
            },
        ],
    }

    assert validate_schema_fixture(fixture) == []


def test_schema_fixture_validation_rejects_missing_evidence_and_unknown_boundaries():
    fixture = {
        "schema_version": 1,
        "artifacts": [
            {
                "artifact_type": "finding",
                "id": "finding:bad",
                "severity": "medium",
                "summary": "bad fixture",
                "uncertainty": "heuristic",
                "evidence_refs": [],
                "trust_boundary": "trusted-by-default",
                "limits": {"truncated": False, "omitted_record_count": 0},
                "risk_hints": [],
            }
        ],
    }

    assert validate_schema_fixture(fixture) == [
        "artifacts[0].evidence_refs must be a non-empty list of strings",
        "artifacts[0].trust_boundary is unknown: trusted-by-default",
    ]
