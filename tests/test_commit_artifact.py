from __future__ import annotations

import os
import subprocess
from pathlib import Path

from kernel_diffguard.commit_artifact import parse_commit_artifact
from kernel_diffguard.commit_review import review_commit
from kernel_diffguard.evidence_schema import validate_schema_fixture


def run_git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def commit_all(repo: Path, message: str, *, env_extra: dict[str, str] | None = None) -> str:
    env = os.environ | {
        "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+00:00",
        "GIT_AUTHOR_NAME": "Fixture Author",
        "GIT_AUTHOR_EMAIL": "fixture@example.test",
        "GIT_COMMITTER_NAME": "Fixture Committer",
        "GIT_COMMITTER_EMAIL": "committer@example.test",
    }
    if env_extra:
        env.update(env_extra)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-m", message], cwd=repo, check=True, env=env)
    return run_git(repo, "rev-parse", "HEAD")


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init", "--initial-branch", "main")
    run_git(repo, "config", "user.name", "Fixture User")
    run_git(repo, "config", "user.email", "user@example.test")
    return repo


def test_parse_commit_artifact_emits_normalized_hostile_git_facts(tmp_path: Path):
    repo = make_repo(tmp_path)
    (repo / "README.md").write_text("baseline\n")
    base = commit_all(repo, "Initial baseline")

    (repo / "README.md").rename(repo / "README-renamed.md")
    (repo / "src").mkdir()
    (repo / "src" / "module.c").write_text("int module(void) { return 1; }\n")
    commit = commit_all(repo, "Subject with separator\n\nBody line 1\nBody line 2")

    artifact = parse_commit_artifact(repo, commit, max_diff_excerpt_bytes=2000)

    assert artifact["artifact_type"] == "commit_artifact"
    assert artifact["id"] == f"commit:{commit}"
    assert artifact["commit"] == commit
    assert artifact["parents"] == [base]
    assert len(artifact["tree"]) == 40
    assert artifact["author"] == {
        "name": "Fixture Author",
        "email": "fixture@example.test",
        "timestamp": "2024-01-01T00:00:00Z",
    }
    assert artifact["committer"] == {
        "name": "Fixture Committer",
        "email": "committer@example.test",
        "timestamp": "2024-01-01T00:00:00Z",
    }
    assert artifact["subject"] == "Subject with separator"
    assert artifact["body"] == "Subject with separator\n\nBody line 1\nBody line 2\n"
    assert artifact["touched_paths"] == ["README-renamed.md", "README.md", "src/module.c"]
    assert artifact["path_changes"] == [
        {"status": "R", "score": "100", "paths": ["README.md", "README-renamed.md"]},
        {"status": "A", "score": None, "paths": ["src/module.c"]},
    ]
    assert artifact["diff_stats"] == [
        {"additions": 0, "deletions": 0, "path": "README-renamed.md"},
        {"additions": 1, "deletions": 0, "path": "src/module.c"},
    ]
    assert artifact["trust_boundary"] == "local_git_metadata_untrusted"
    assert artifact["secondary_trust_boundaries"] == ["local_git_diff_untrusted"]
    assert artifact["evidence_refs"] == [f"git:commit:{commit}"]
    assert artifact["risk_hints"] == []
    assert artifact["limits"] == {
        "truncated": False,
        "omitted_record_count": 0,
        "max_diff_excerpt_bytes": 2000,
        "diff_excerpt_bytes": len(artifact["diff_excerpt"].encode()),
        "max_tag_records": 32,
        "max_tag_name_bytes": 256,
        "omitted_tag_record_count": 0,
    }
    assert "src/module.c" in artifact["diff_excerpt"]
    assert validate_schema_fixture({"artifacts": [artifact]}) == []


def test_parse_commit_artifact_handles_weird_paths_and_empty_commits(tmp_path: Path):
    repo = make_repo(tmp_path)
    weird_path = repo / "dir with spaces"
    weird_path.mkdir()
    original = weird_path / "old\tname.txt"
    original.write_text("baseline\n")
    base = commit_all(repo, "Initial weird path")

    renamed = weird_path / "new\nname.txt"
    original.rename(renamed)
    commit = commit_all(repo, "Rename weird path")

    rename_artifact = parse_commit_artifact(repo, commit)

    assert rename_artifact["parents"] == [base]
    assert rename_artifact["path_changes"] == [
        {
            "status": "R",
            "score": "100",
            "paths": ["dir with spaces/old\tname.txt", "dir with spaces/new\nname.txt"],
        }
    ]
    assert rename_artifact["touched_paths"] == [
        "dir with spaces/new\nname.txt",
        "dir with spaces/old\tname.txt",
    ]
    assert rename_artifact["diff_stats"] == [
        {"additions": 0, "deletions": 0, "path": "dir with spaces/new\nname.txt"}
    ]

    env = os.environ | {
        "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+00:00",
        "GIT_AUTHOR_NAME": "Fixture Author",
        "GIT_AUTHOR_EMAIL": "fixture@example.test",
        "GIT_COMMITTER_NAME": "Fixture Committer",
        "GIT_COMMITTER_EMAIL": "committer@example.test",
    }
    subprocess.run(
        ["git", "commit", "--allow-empty", "-m", "Empty review marker"],
        cwd=repo,
        check=True,
        env=env,
    )
    empty_commit = run_git(repo, "rev-parse", "HEAD")

    empty_artifact = parse_commit_artifact(repo, empty_commit)

    assert empty_artifact["parents"] == [commit]
    assert empty_artifact["touched_paths"] == []
    assert empty_artifact["path_changes"] == []
    assert empty_artifact["diff_stats"] == []
    assert empty_artifact["diff_excerpt"] == ""
    assert empty_artifact["limits"]["truncated"] is False


def test_parse_commit_artifact_caps_tag_facts_from_hostile_repos(tmp_path: Path):
    repo = make_repo(tmp_path)
    (repo / "README.md").write_text("baseline\n")
    commit = commit_all(repo, "Initial baseline")
    for index in range(40):
        run_git(repo, "tag", f"review-tag-{index:02d}", commit)

    artifact = parse_commit_artifact(repo, commit)

    assert len(artifact["tags"]) == 32
    assert artifact["tags"][0] == {"name": "review-tag-00", "kind": "tag"}
    assert artifact["tags"][-1] == {"name": "review-tag-31", "kind": "tag"}
    assert artifact["limits"]["max_tag_records"] == 32
    assert artifact["limits"]["omitted_tag_record_count"] == 1
    assert "tag-facts-truncated" in artifact["risk_hints"]


def test_parse_commit_artifact_bounds_large_diff_excerpts_and_preserves_metadata(tmp_path: Path):
    repo = make_repo(tmp_path)
    (repo / "README.md").write_text("baseline\n")
    commit_all(repo, "Initial baseline")

    (repo / "large.txt").write_text("\n".join(f"line {index}" for index in range(200)) + "\n")
    commit = commit_all(repo, "Large diff")

    artifact = parse_commit_artifact(repo, commit, max_diff_excerpt_bytes=120)

    assert artifact["limits"]["truncated"] is True
    assert artifact["limits"]["omitted_record_count"] == 1
    assert artifact["limits"]["max_diff_excerpt_bytes"] == 120
    assert len(artifact["diff_excerpt"].encode()) <= 120
    assert artifact["risk_hints"] == ["diff-excerpt-truncated"]


def test_review_commit_includes_normalized_commit_artifact(tmp_path: Path):
    repo = make_repo(tmp_path)
    (repo / "README.md").write_text("baseline\n")
    commit_all(repo, "Initial baseline")

    (repo / "tests").mkdir()
    (repo / "tests" / "test_guard.py").write_text("def test_guard():\n    assert True\n")
    commit = commit_all(repo, "Add regression test")

    review = review_commit(repo, commit)

    assert review["commit_artifact"]["artifact_type"] == "commit_artifact"
    assert review["commit_artifact"]["commit"] == commit
    assert review["commit_artifact"]["touched_paths"] == ["tests/test_guard.py"]
    assert review["touched_paths"] == review["commit_artifact"]["touched_paths"]
