"""Controlled GitHub-hosted commit input resolution.

GitHub is treated as a transport/provenance source, not a trust oracle. This module
only resolves immutable full-SHA commit inputs and fetches them into a caller-owned
bare cache before delegating to the same local git analyzers used elsewhere.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .commit_review import review_commit

JsonObject = dict[str, Any]

_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_OWNER_REPO_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)@(?P<commit>[0-9A-Fa-f]{40})$"
)
_SAFE_PATH_PART_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_FETCH_TIMEOUT_SECONDS = 120
_FETCH_DEPTH_WITH_PARENTS = "2"


class GitHubSourceError(ValueError):
    """Raised when a GitHub-hosted commit source is ambiguous or unavailable."""

    def __init__(self, kind: str, source: str, detail: str):
        super().__init__(f"{kind}: {source}: {detail}")
        self.kind = kind
        self.source = source
        self.detail = detail


def parse_github_commit_source(source: str) -> JsonObject:
    """Parse a GitHub commit URL or owner/repo@full_sha into bounded provenance facts."""

    parsed_short = _parse_owner_repo_at_sha(source)
    if parsed_short:
        owner, repo, commit = parsed_short
        clone_url = f"https://github.com/{owner}/{repo}.git"
        return _source_artifact(source, owner, repo, commit, clone_url)

    parsed_url = urlparse(source)
    if parsed_url.scheme != "https" or parsed_url.netloc.lower() != "github.com":
        raise GitHubSourceError(
            "unsupported-github-source",
            source,
            "expected https://github.com/OWNER/REPO/commit/FULL_SHA or OWNER/REPO@FULL_SHA",
        )
    path_parts = [part for part in parsed_url.path.split("/") if part]
    if len(path_parts) != 4 or path_parts[2] != "commit":
        raise GitHubSourceError(
            "unsupported-github-source",
            source,
            "only immutable GitHub commit URLs are accepted",
        )
    owner, repo, commit = path_parts[0], path_parts[1], path_parts[3]
    _validate_owner_repo_commit(source, owner, repo, commit)
    clone_url = f"https://github.com/{owner}/{repo}.git"
    return _source_artifact(source, owner, repo, commit.lower(), clone_url)


def materialize_github_commit_source(
    source: str,
    *,
    cache_dir: Path | str,
    clone_url_override: str | None = None,
) -> JsonObject:
    """Fetch one immutable GitHub commit into a controlled bare repository cache."""

    source_artifact = parse_github_commit_source(source)
    owner = str(source_artifact["owner"])
    repo = str(source_artifact["repo"])
    commit = str(source_artifact["commit"])
    clone_url = clone_url_override or str(source_artifact["clone_url"])
    repo_cache = Path(cache_dir) / _safe_path_part(owner) / f"{_safe_path_part(repo)}.git"
    repo_cache.parent.mkdir(parents=True, exist_ok=True)
    if not (repo_cache / "HEAD").exists():
        _git(None, "init", "--bare", str(repo_cache))
        _git(repo_cache, "remote", "add", "origin", clone_url)
    else:
        _git(repo_cache, "remote", "set-url", "origin", clone_url)
    _fetch_commit(repo_cache, commit)
    resolved = _git(repo_cache, "rev-parse", "--verify", f"{commit}^{{commit}}").strip()
    if resolved.lower() != commit.lower():
        raise GitHubSourceError(
            "resolved-commit-mismatch",
            source,
            f"expected {commit}, got {resolved}",
        )
    return {
        "artifact_type": "github_commit_materialization",
        "id": f"github:materialized:{owner}/{repo}:{resolved}",
        "schema_version": 1,
        "repo_identity": f"github:{owner}/{repo}",
        "commit": resolved,
        "local_repo": str(repo_cache),
        "source": source_artifact,
        "provenance": {
            "resolved_from": source,
            "remote_commit_sha": resolved,
            "clone_url": clone_url,
            "cache_policy": "bare-controlled-cache-fetch-specific-sha-with-parents",
        },
        "evidence_refs": [f"github:commit:{owner}/{repo}@{resolved}"],
        "trust_boundary": "remote_github_metadata_untrusted",
        "limits": {"truncated": False, "omitted_record_count": 0},
        "risk_hints": ["github-transport-is-not-a-trust-oracle"],
    }


def review_github_commit(source: str, *, cache_dir: Path | str) -> JsonObject:
    """Resolve a GitHub-hosted commit and review it via the local single-commit path."""

    materialized = materialize_github_commit_source(source, cache_dir=cache_dir)
    review = review_commit(Path(str(materialized["local_repo"])), str(materialized["commit"]))
    review["github_source"] = materialized
    return review


def render_json(artifact: JsonObject) -> str:
    """Render stable JSON for GitHub source artifacts."""

    return json.dumps(artifact, indent=2, sort_keys=True) + "\n"


def _parse_owner_repo_at_sha(source: str) -> tuple[str, str, str] | None:
    match = _OWNER_REPO_RE.match(source)
    if not match:
        return None
    owner, repo, commit = match.group("owner"), match.group("repo"), match.group("commit")
    _validate_owner_repo_commit(source, owner, repo, commit)
    return owner, repo, commit.lower()


def _validate_owner_repo_commit(source: str, owner: str, repo: str, commit: str) -> None:
    if not _SAFE_PATH_PART_RE.match(owner) or not _SAFE_PATH_PART_RE.match(repo):
        raise GitHubSourceError(
            "invalid-github-repository", source, "owner/repo has unsafe characters"
        )
    if not _FULL_SHA_RE.match(commit):
        raise GitHubSourceError(
            "ambiguous-github-revision",
            source,
            "commit must be a full 40-hex immutable SHA, not a branch or abbreviation",
        )


def _source_artifact(source: str, owner: str, repo: str, commit: str, clone_url: str) -> JsonObject:
    return {
        "artifact_type": "github_commit_source",
        "id": f"github:source:{owner}/{repo}:{commit.lower()}",
        "schema_version": 1,
        "owner": owner,
        "repo": repo,
        "commit": commit.lower(),
        "source": source,
        "clone_url": clone_url,
        "evidence_refs": [f"github:commit:{owner}/{repo}@{commit.lower()}"],
        "trust_boundary": "remote_github_metadata_untrusted",
        "limits": {"truncated": False, "omitted_record_count": 0},
        "risk_hints": ["github-transport-is-not-a-trust-oracle"],
    }


def _safe_path_part(value: str) -> str:
    if not _SAFE_PATH_PART_RE.match(value):
        raise GitHubSourceError("invalid-cache-path", value, "unsafe cache path component")
    return value


def _fetch_commit(repo: Path, commit: str) -> None:
    depth_arg = f"--depth={_FETCH_DEPTH_WITH_PARENTS}"
    try:
        _git(repo, "fetch", "--filter=blob:none", depth_arg, "origin", commit)
    except GitHubSourceError:
        _git(repo, "fetch", depth_arg, "origin", commit)


def _git(repo: Path | None, *args: str) -> str:
    command = ["git"]
    if repo is not None:
        command.extend(["-C", str(repo)])
    command.extend(["-c", "core.hooksPath=/dev/null"])
    command.extend(args)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=_FETCH_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitHubSourceError("git-timeout", " ".join(args), "git command timed out") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "git command failed"
        raise GitHubSourceError("git-command-failed", " ".join(args), detail)
    return completed.stdout
