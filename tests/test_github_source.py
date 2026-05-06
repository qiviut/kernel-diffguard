from __future__ import annotations

import json
from pathlib import Path

import pytest

from kernel_diffguard.cli import main
from kernel_diffguard.github_source import (
    GitHubSourceError,
    materialize_github_commit_source,
    parse_github_commit_source,
)
from test_commit_artifact import commit_all, make_repo, run_git


def test_parse_github_commit_source_accepts_url_and_owner_repo_sha():
    sha = "a" * 40

    from_url = parse_github_commit_source(f"https://github.com/torvalds/linux/commit/{sha}")
    from_short = parse_github_commit_source(f"torvalds/linux@{sha}")

    assert from_url == {
        "artifact_type": "github_commit_source",
        "id": f"github:source:torvalds/linux:{sha}",
        "schema_version": 1,
        "owner": "torvalds",
        "repo": "linux",
        "commit": sha,
        "source": f"https://github.com/torvalds/linux/commit/{sha}",
        "clone_url": "https://github.com/torvalds/linux.git",
        "evidence_refs": [f"github:commit:torvalds/linux@{sha}"],
        "trust_boundary": "remote_github_metadata_untrusted",
        "limits": {"truncated": False, "omitted_record_count": 0},
        "risk_hints": ["github-transport-is-not-a-trust-oracle"],
    }
    assert from_short == from_url | {"source": f"torvalds/linux@{sha}"}


@pytest.mark.parametrize(
    "source",
    [
        "https://github.com/torvalds/linux/tree/master",
        "https://evil.test/torvalds/linux/commit/" + "a" * 40,
        "torvalds/linux@main",
        "torvalds/linux@" + "b" * 8,
        "bad/source/shape@" + "c" * 40,
    ],
)
def test_parse_github_commit_source_rejects_ambiguous_or_non_github_inputs(source: str):
    with pytest.raises(GitHubSourceError):
        parse_github_commit_source(source)


def test_materialize_github_commit_source_fetches_specific_sha_into_controlled_bare_cache(
    tmp_path: Path,
):
    remote_work = make_repo(tmp_path)
    (remote_work / "kernel.c").write_text("int old(void) { return 0; }\n")
    parent_sha = commit_all(remote_work, "initial")
    (remote_work / "kernel.c").write_text("int old(void) { return 1; }\n")
    sha = commit_all(remote_work, "kernel: remote fix")
    bare_remote = tmp_path / "remote.git"
    run_git(remote_work, "clone", "--bare", str(remote_work), str(bare_remote))

    materialized = materialize_github_commit_source(
        f"example/linux@{sha}",
        cache_dir=tmp_path / "cache",
        clone_url_override=bare_remote.as_uri(),
    )

    assert materialized["commit"] == sha
    assert materialized["repo_identity"] == "github:example/linux"
    assert materialized["local_repo"].endswith("example/linux.git")
    assert materialized["provenance"]["resolved_from"] == f"example/linux@{sha}"
    assert materialized["provenance"]["remote_commit_sha"] == sha
    assert run_git(Path(materialized["local_repo"]), "cat-file", "-t", sha) == "commit"
    assert (
        run_git(Path(materialized["local_repo"]), "rev-parse", f"{sha}^1")
        == parent_sha
    )


def test_review_github_commit_cli_uses_resolved_local_repo_without_network(
    monkeypatch,
    tmp_path,
    capsys,
):
    sha = "d" * 40

    def fake_review_github_commit(source: str, *, cache_dir: Path):
        assert source == f"qiviut/kernel-diffguard@{sha}"
        assert cache_dir == tmp_path
        return {
            "schema_version": 1,
            "review_posture": "review-assistant-not-verdict",
            "commit": sha,
            "source": {"owner": "qiviut", "repo": "kernel-diffguard"},
            "findings": [],
        }

    monkeypatch.setattr("kernel_diffguard.cli.review_github_commit", fake_review_github_commit)

    exit_code = main(
        [
            "review-github-commit",
            "--source",
            f"qiviut/kernel-diffguard@{sha}",
            "--cache-dir",
            str(tmp_path),
            "--format",
            "json",
        ]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["commit"] == sha
