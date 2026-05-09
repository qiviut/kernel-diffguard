from __future__ import annotations

from pathlib import Path

from kernel_diffguard.commit_review import review_commit
from kernel_diffguard.evidence_schema import validate_schema_fixture
from kernel_diffguard.range_review import review_range
from test_review_commit import commit_all, make_repo_with_suspicious_commit, run_git


def test_review_commit_emits_named_expert_check_results_for_removed_test_and_ci(tmp_path: Path):
    repo, commit = make_repo_with_suspicious_commit(tmp_path)

    result = review_commit(repo, commit)

    check_results = {check["check_id"]: check for check in result["expert_check_results"]}
    removed_test = check_results["KDG-CHECK-REMOVED-TEST"]
    ci_gate = check_results["KDG-CHECK-CI-STATIC-ANALYSIS-WEAKENED"]

    assert removed_test["artifact_type"] == "expert_check_result"
    assert removed_test["status"] == "missing_evidence"
    assert removed_test["subject"] == {"kind": "commit", "id": commit}
    assert "finding:removed-test" in removed_test["evidence_refs"]
    assert "path:tests/test_guard.py" in removed_test["evidence_refs"]
    assert removed_test["missing_evidence"] == [
        "replacement coverage evidence",
        "accepted exception record",
    ]
    assert "not-maliciousness-verdict" in removed_test["risk_hints"]

    assert ci_gate["status"] == "missing_evidence"
    assert "finding:ci-static-analysis-weakened" in ci_gate["evidence_refs"]
    assert "path:.github/workflows/ci.yml" in ci_gate["evidence_refs"]

    assert validate_schema_fixture({"artifacts": result["expert_check_results"]}) == []


def test_review_commit_marks_named_checks_not_applicable_when_no_signal_applies(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init", "--initial-branch", "main")
    run_git(repo, "config", "user.name", "Fixture Author")
    run_git(repo, "config", "user.email", "fixture@example.test")
    (repo / "README.md").write_text("baseline\n")
    commit_all(repo, "Initial baseline")
    (repo / "docs").mkdir()
    (repo / "docs" / "notes.txt").write_text("plain maintenance\n")
    commit = commit_all(repo, "docs: update notes")

    result = review_commit(repo, commit)

    assert [check["status"] for check in result["expert_check_results"]] == [
        "not_applicable",
        "not_applicable",
    ]
    assert all(
        check["evidence_refs"] == [f"commit:{commit}"] for check in result["expert_check_results"]
    )
    assert validate_schema_fixture({"artifacts": result["expert_check_results"]}) == []


def test_review_range_aggregates_named_check_results_over_commits(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init", "--initial-branch", "main")
    run_git(repo, "config", "user.name", "Fixture Author")
    run_git(repo, "config", "user.email", "fixture@example.test")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_guard.py").write_text("def test_guard():\n    assert True\n")
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\nsteps:\n  - run: pytest\n  - run: ruff check .\n"
    )
    base = commit_all(repo, "Initial guarded project")

    (repo / "tests" / "test_guard.py").unlink()
    removed_test_commit = commit_all(repo, "tests: remove obsolete guard")
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: CI\nsteps:\n  - run: pytest\n")
    ci_commit = commit_all(repo, "ci: simplify checks")

    result = review_range(repo, base=base, target=ci_commit)

    assert result["range"]["commits"] == [removed_test_commit, ci_commit]
    check_results = {check["check_id"]: check for check in result["expert_check_results"]}
    assert check_results["KDG-CHECK-REMOVED-TEST"]["status"] == "missing_evidence"
    assert (
        f"commit:{removed_test_commit}:path:tests/test_guard.py"
        in check_results["KDG-CHECK-REMOVED-TEST"]["evidence_refs"]
    )
    assert check_results["KDG-CHECK-CI-STATIC-ANALYSIS-WEAKENED"]["status"] == "missing_evidence"
    assert (
        f"commit:{ci_commit}:path:.github/workflows/ci.yml"
        in check_results["KDG-CHECK-CI-STATIC-ANALYSIS-WEAKENED"]["evidence_refs"]
    )
    assert validate_schema_fixture({"artifacts": result["expert_check_results"]}) == []
