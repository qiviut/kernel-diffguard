from __future__ import annotations

from kernel_diffguard.commit_review import render_text, review_commit
from kernel_diffguard.review_packet import demo_status_mix_packet
from test_review_commit import make_repo_with_suspicious_commit


def test_review_commit_adds_packet_grouping_checks_and_recommendations(tmp_path):
    repo, commit = make_repo_with_suspicious_commit(tmp_path)

    result = review_commit(repo, commit)
    packet = result["review_packet"]

    assert packet["artifact_type"] == "review_packet"
    assert packet["subject"] == {"kind": "commit", "id": commit}
    assert packet["review_posture"] == "review-assistant-not-verdict"
    assert [
        item["check_id"] for item in packet["policy_result_groups"]["missing_evidence"]
    ] == ["KDG-CHECK-REMOVED-TEST", "KDG-CHECK-CI-STATIC-ANALYSIS-WEAKENED"]
    assert packet["policy_result_groups"]["satisfied"] == []
    assert packet["policy_result_groups"]["violated"] == []
    assert packet["policy_result_groups"]["not_applicable"] == []
    assert {item["check_id"] for item in packet["recommendations"]} == {
        "KDG-CHECK-REMOVED-TEST",
        "KDG-CHECK-CI-STATIC-ANALYSIS-WEAKENED",
    }
    assert all(item["evidence_refs"] for item in packet["recommendations"])
    assert all(item["check_id"] for item in packet["required_exceptions"])
    assert "finding:removed-test" in packet["raw_finding_refs"]


def test_review_packet_demo_locks_satisfied_violated_and_missing_evidence_groups():
    packet = demo_status_mix_packet()

    groups = packet["policy_result_groups"]
    assert [item["status"] for item in groups["satisfied"]] == ["satisfied"]
    assert [item["status"] for item in groups["violated"]] == ["violated"]
    assert [item["status"] for item in groups["missing_evidence"]] == ["missing_evidence"]
    assert {item["policy_id"] for item in packet["recommendations"]} == {
        "KDG-POLICY-DEMO-VIOLATED",
        "KDG-POLICY-DEMO-MISSING-EVIDENCE",
    }
    assert packet["required_exceptions"] == [
        {
            "id": "exception-required:KDG-POLICY-DEMO-MISSING-EVIDENCE",
            "status": "missing_evidence",
            "required_next_action": (
                "Provide replacement coverage or record a scoped maintainer exception."
            ),
            "missing_evidence": [
                "replacement coverage evidence",
                "accepted exception record",
            ],
            "evidence_refs": ["finding:removed-test", "path:tests/test_guard.py"],
            "policy_id": "KDG-POLICY-DEMO-MISSING-EVIDENCE",
            "check_id": "KDG-CHECK-DEMO-MISSING-EVIDENCE",
        }
    ]


def test_commit_text_output_makes_packet_next_actions_obvious(tmp_path):
    repo, commit = make_repo_with_suspicious_commit(tmp_path)

    text = render_text(review_commit(repo, commit))

    assert "Review packet:" in text
    assert f"- subject: commit {commit}" in text
    assert "Policy/check result groups:" in text
    assert "- missing_evidence:" in text
    assert "Required next actions:" in text
    assert "Required exceptions:" in text
    assert "Raw deterministic findings remain evidence, not verdicts:" in text
