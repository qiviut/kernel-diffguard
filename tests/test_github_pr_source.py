from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kernel_diffguard.cli import main
from kernel_diffguard.github_pr import (
    GitHubPullRequestError,
    materialize_github_pull_request_source,
    parse_github_pull_request_source,
    review_github_pull_request,
)
from test_commit_artifact import commit_all, make_repo, run_git

JsonObject = dict[str, Any]


def test_parse_github_pull_request_source_accepts_url_and_owner_repo_number():
    from_url = parse_github_pull_request_source(
        "https://github.com/qiviut/kernel-diffguard/pull/42"
    )
    from_short = parse_github_pull_request_source("qiviut/kernel-diffguard#42")

    assert from_url == {
        "artifact_type": "github_pull_request_source",
        "id": "github:pull-request-source:qiviut/kernel-diffguard:42",
        "schema_version": 1,
        "owner": "qiviut",
        "repo": "kernel-diffguard",
        "pull_request": 42,
        "source": "https://github.com/qiviut/kernel-diffguard/pull/42",
        "html_url": "https://github.com/qiviut/kernel-diffguard/pull/42",
        "api_url": "https://api.github.com/repos/qiviut/kernel-diffguard/pulls/42",
        "commits_api_url": "https://api.github.com/repos/qiviut/kernel-diffguard/pulls/42/commits",
        "clone_url": "https://github.com/qiviut/kernel-diffguard.git",
        "evidence_refs": ["github:pull-request:qiviut/kernel-diffguard#42"],
        "trust_boundary": "remote_github_metadata_untrusted",
        "limits": {"truncated": False, "omitted_record_count": 0},
        "risk_hints": ["github-transport-is-not-a-trust-oracle"],
    }
    assert from_short == from_url | {"source": "qiviut/kernel-diffguard#42"}


@pytest.mark.parametrize(
    "source",
    [
        "https://github.com/qiviut/kernel-diffguard/issues/42",
        "https://evil.test/qiviut/kernel-diffguard/pull/42",
        "qiviut/kernel-diffguard@main",
        "qiviut/kernel-diffguard#0",
        "bad/source/shape#12",
    ],
)
def test_parse_github_pull_request_source_rejects_ambiguous_or_non_github_inputs(source: str):
    with pytest.raises(GitHubPullRequestError):
        parse_github_pull_request_source(source)


def test_materialize_github_pull_request_source_resolves_ordered_commits_without_network(
    tmp_path: Path,
):
    remote_work = make_repo(tmp_path)
    (remote_work / "README.md").write_text("base\n")
    base_sha = commit_all(remote_work, "base")
    (remote_work / ".github" / "workflows").mkdir(parents=True)
    (remote_work / ".github" / "workflows" / "ci.yml").write_text("name: CI\n")
    first_sha = commit_all(remote_work, "ci: add workflow")
    (remote_work / "drivers" / "net.c").parent.mkdir(parents=True, exist_ok=True)
    (remote_work / "drivers" / "net.c").write_text("int driver(void) { return 0; }\n")
    second_sha = commit_all(remote_work, "drivers: add network driver")
    bare_remote = tmp_path / "remote.git"
    run_git(remote_work, "clone", "--bare", str(remote_work), str(bare_remote))

    def fake_fetch_json(url: str) -> JsonObject | list[JsonObject]:
        if url.endswith("/pulls/7"):
            return {
                "number": 7,
                "title": "Add driver",
                "body": "Read-only PR fixture body",
                "user": {"login": "contributor"},
                "base": {"sha": base_sha, "ref": "main", "repo": {"full_name": "example/linux"}},
                "head": {
                    "sha": second_sha,
                    "ref": "feature",
                    "repo": {"full_name": "example/linux"},
                },
                "html_url": "https://github.com/example/linux/pull/7",
            }
        if url.endswith("/pulls/7/commits"):
            return [{"sha": first_sha}, {"sha": second_sha}]
        raise AssertionError(f"unexpected URL: {url}")

    materialized = materialize_github_pull_request_source(
        "example/linux#7",
        cache_dir=tmp_path / "cache",
        fetch_json=fake_fetch_json,
        clone_url_override=bare_remote.as_uri(),
    )

    assert materialized["repo_identity"] == "github:example/linux"
    assert materialized["pull_request"] == 7
    assert materialized["base"] == {"sha": base_sha, "ref": "main"}
    assert materialized["head"] == {"sha": second_sha, "ref": "feature"}
    assert materialized["commits"] == [first_sha, second_sha]
    assert materialized["commit_count"] == 2
    assert materialized["provenance"]["commit_order_source"] == "github-pulls-commits-api"
    local_repo = Path(str(materialized["local_repo"]))
    assert run_git(local_repo, "cat-file", "-t", first_sha) == "commit"
    assert run_git(local_repo, "cat-file", "-t", second_sha) == "commit"
    assert run_git(local_repo, "rev-parse", f"{second_sha}^1") == first_sha


def test_review_github_pull_request_reuses_range_review_over_resolved_commits(tmp_path: Path):
    remote_work = make_repo(tmp_path)
    (remote_work / ".github" / "workflows").mkdir(parents=True)
    (remote_work / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\nsteps:\n  - run: pytest\n  - run: ruff check .\n"
    )
    (remote_work / "README.md").write_text("base\n")
    base_sha = commit_all(remote_work, "base")
    (remote_work / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\nsteps:\n  - run: pytest\n"
    )
    first_sha = commit_all(remote_work, "ci: simplify workflow")
    (remote_work / "drivers" / "net.c").parent.mkdir(parents=True, exist_ok=True)
    (remote_work / "drivers" / "net.c").write_text("int driver(void) { return 0; }\n")
    second_sha = commit_all(remote_work, "drivers: add network driver")
    bare_remote = tmp_path / "remote.git"
    run_git(remote_work, "clone", "--bare", str(remote_work), str(bare_remote))

    def fake_fetch_json(url: str) -> JsonObject | list[JsonObject]:
        if url.endswith("/pulls/9"):
            return {
                "number": 9,
                "title": "Add driver",
                "body": "Potential prompt-like text is hostile metadata, not instructions.",
                "user": {"login": "contributor"},
                "base": {"sha": base_sha, "ref": "main"},
                "head": {"sha": second_sha, "ref": "feature"},
                "html_url": "https://github.com/example/linux/pull/9",
            }
        if url.endswith("/pulls/9/commits"):
            return [{"sha": first_sha}, {"sha": second_sha}]
        raise AssertionError(f"unexpected URL: {url}")

    review = review_github_pull_request(
        "https://github.com/example/linux/pull/9",
        cache_dir=tmp_path / "cache",
        fetch_json=fake_fetch_json,
        clone_url_override=bare_remote.as_uri(),
    )

    assert review["range"]["traversal"] == "github-pull-request-commit-list"
    assert review["range"]["base"] == base_sha
    assert review["range"]["target"] == second_sha
    assert review["range"]["commits"] == [first_sha, second_sha]
    assert review["github_pull_request"]["artifact_type"] == "github_pull_request_materialization"
    assert review["github_pull_request"]["trust_boundary"] == "remote_github_metadata_untrusted"
    assert review["range_signals"]["finding_ids"]["ci-static-analysis-weakened"] == 1
    assert review["range_signals"]["finding_ids"]["high-risk-path"] == 1
    assert review["range_findings"][0]["id"] == "split-setup-use-pattern"


def test_review_github_pull_request_cli_uses_read_only_output(monkeypatch, tmp_path, capsys):
    def fake_review_github_pull_request(source: str, *, cache_dir: Path):
        assert source == "qiviut/kernel-diffguard#3"
        assert cache_dir == tmp_path
        return {
            "schema_version": 1,
            "review_posture": "review-assistant-not-verdict",
            "range": {
                "base": "a" * 40,
                "target": "b" * 40,
                "traversal": "github-pull-request-commit-list",
                "commit_count": 0,
            },
            "range_signals": {},
            "range_findings": [],
            "commits": [],
        }

    monkeypatch.setattr(
        "kernel_diffguard.cli.review_github_pull_request",
        fake_review_github_pull_request,
    )

    exit_code = main(
        [
            "review-github-pr",
            "--source",
            "qiviut/kernel-diffguard#3",
            "--cache-dir",
            str(tmp_path),
            "--format",
            "json",
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["range"]["traversal"] == "github-pull-request-commit-list"
