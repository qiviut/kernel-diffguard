from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from kernel_diffguard.cli import main
from kernel_diffguard.range_review import RangeReviewError, review_commits, review_range


def run_git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def commit_all(
    repo: Path,
    message: str,
    *,
    author_name: str = "Fixture Author",
    author_email: str = "fixture@example.test",
) -> str:
    env = os.environ | {
        "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+00:00",
        "GIT_AUTHOR_NAME": author_name,
        "GIT_AUTHOR_EMAIL": author_email,
    }
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-m", message], cwd=repo, check=True, env=env)
    return run_git(repo, "rev-parse", "HEAD")


def make_linear_repo(tmp_path: Path) -> tuple[Path, str, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init", "--initial-branch", "main")
    run_git(repo, "config", "user.name", "Fixture Author")
    run_git(repo, "config", "user.email", "fixture@example.test")

    (repo / "README.md").write_text("initial\n")
    base = commit_all(repo, "Initial commit")

    (repo / "drivers").mkdir()
    (repo / "drivers" / "net.c").write_text("int net_driver(void) { return 1; }\n")
    first = commit_all(repo, "Add driver change")

    (repo / "docs").mkdir()
    (repo / "docs" / "notes.txt").write_text("release notes\n")
    second = commit_all(repo, "Add docs")

    return repo, base, first, second


def test_review_range_orders_base_exclusive_target_inclusive_commits(tmp_path: Path):
    repo, base, first, second = make_linear_repo(tmp_path)

    result = review_range(repo, base=base, target=second)

    assert result["schema_version"] == 1
    assert result["review_posture"] == "review-assistant-not-verdict"
    assert result["range"]["base"] == base
    assert result["range"]["target"] == second
    assert result["range"]["traversal"] == "base-exclusive-target-inclusive"
    assert result["range"]["commit_count"] == 2
    assert [commit["commit"] for commit in result["commits"]] == [first, second]
    assert result["findings_by_commit"][first][0]["id"] == "high-risk-path"
    assert result["findings_by_commit"][second] == []


def test_review_range_empty_range_is_explicit(tmp_path: Path):
    repo, _base, _first, second = make_linear_repo(tmp_path)

    result = review_range(repo, base=second, target=second)

    assert result["range"]["commit_count"] == 0
    assert result["commits"] == []
    assert result["findings_by_commit"] == {}
    assert result["range"]["errors"] == []
    assert result["range_signals"] == {
        "authors": [],
        "finding_ids": {},
        "path_prefixes": {},
        "touched_path_count": 0,
        "touched_paths": [],
    }


def test_review_range_emits_cumulative_author_and_diff_signals(tmp_path: Path):
    repo, base, first, _second = make_linear_repo(tmp_path)

    (repo / "kernel").mkdir()
    (repo / "kernel" / "scheduler.c").write_text("int scheduler_change(void) { return 1; }\n")
    third = commit_all(
        repo,
        "Adjust scheduler",
        author_name="Second Author",
        author_email="second@example.test",
    )

    result = review_range(repo, base=base, target=third)

    assert result["range_signals"] == {
        "authors": [
            {
                "name": "Fixture Author",
                "email": "fixture@example.test",
                "commit_count": 2,
                "commits": [first, result["commits"][1]["commit"]],
                "finding_ids": {"high-risk-path": 1},
                "path_prefixes": {"docs": 1, "drivers": 1},
            },
            {
                "name": "Second Author",
                "email": "second@example.test",
                "commit_count": 1,
                "commits": [third],
                "finding_ids": {"high-risk-path": 1},
                "path_prefixes": {"kernel": 1},
            },
        ],
        "finding_ids": {"high-risk-path": 2},
        "path_prefixes": {"docs": 1, "drivers": 1, "kernel": 1},
        "touched_path_count": 3,
        "touched_paths": ["docs/notes.txt", "drivers/net.c", "kernel/scheduler.c"],
    }


def test_review_commit_list_preserves_explicit_order_and_duplicates(tmp_path: Path):
    repo, _base, first, second = make_linear_repo(tmp_path)

    result = review_commits(repo, commits=[second, first, second])

    assert result["range"]["traversal"] == "explicit-commit-list"
    assert result["range"]["commit_count"] == 3
    assert [commit["commit"] for commit in result["commits"]] == [second, first, second]
    assert set(result["findings_by_commit"]) == {first, second}


def test_review_range_invalid_revision_fails_closed(tmp_path: Path):
    repo, base, _first, _second = make_linear_repo(tmp_path)

    with pytest.raises(RangeReviewError) as exc_info:
        review_range(repo, base=base, target="does-not-exist")

    assert exc_info.value.kind == "invalid-revision"
    assert "does-not-exist" in exc_info.value.revision
    assert "does-not-exist" in str(exc_info.value)


def test_review_range_cli_reports_invalid_revision_without_traceback(tmp_path: Path, capsys):
    repo, base, _first, _second = make_linear_repo(tmp_path)

    exit_code = main(
        [
            "review-range",
            "--repo",
            str(repo),
            "--base",
            base,
            "--target",
            "does-not-exist",
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "invalid-revision" in captured.err
    assert "Traceback" not in captured.err


def test_review_range_cli_accepts_explicit_commit_list(tmp_path: Path, capsys):
    repo, _base, first, second = make_linear_repo(tmp_path)

    exit_code = main(
        [
            "review-range",
            "--repo",
            str(repo),
            "--commit",
            second,
            "--commit",
            first,
            "--format",
            "json",
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["range"]["traversal"] == "explicit-commit-list"
    assert [commit["commit"] for commit in output["commits"]] == [second, first]


def test_review_range_cli_emits_json(tmp_path: Path, capsys):
    repo, base, first, second = make_linear_repo(tmp_path)

    exit_code = main(
        [
            "review-range",
            "--repo",
            str(repo),
            "--base",
            base,
            "--target",
            second,
            "--format",
            "json",
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["range"]["commit_count"] == 2
    assert [commit["commit"] for commit in output["commits"]] == [first, second]
