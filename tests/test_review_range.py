from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from kernel_diffguard.cli import main
from kernel_diffguard.range_review import review_range


def run_git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def commit_all(repo: Path, message: str) -> str:
    env = os.environ | {
        "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+00:00",
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
