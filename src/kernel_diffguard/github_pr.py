"""Controlled GitHub pull-request input resolution and read-only review."""

from __future__ import annotations

import json
import re
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .github_source import GitHubSourceError, materialize_github_commit_source
from .range_review import _review_commit_sequence

JsonObject = dict[str, Any]
JsonFetcher = Callable[[str], Any]

_PR_SHORT_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)#(?P<number>[0-9]+)$"
)
_SAFE_PATH_PART_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_MAX_PR_COMMITS = 128
_MAX_PR_TITLE_BYTES = 512
_MAX_PR_BODY_BYTES = 4096
_FETCH_TIMEOUT_SECONDS = 30


class GitHubPullRequestError(ValueError):
    """Raised when GitHub pull-request input is ambiguous or unavailable."""

    def __init__(self, kind: str, source: str, detail: str):
        super().__init__(f"{kind}: {source}: {detail}")
        self.kind = kind
        self.source = source
        self.detail = detail


def parse_github_pull_request_source(source: str) -> JsonObject:
    """Parse a GitHub PR URL or OWNER/REPO#NUMBER into bounded provenance facts."""

    parsed_short = _parse_owner_repo_pr_number(source)
    if parsed_short:
        owner, repo, number = parsed_short
        return _source_artifact(source, owner, repo, number)

    parsed_url = urlparse(source)
    if parsed_url.scheme != "https" or parsed_url.netloc.lower() != "github.com":
        raise GitHubPullRequestError(
            "unsupported-github-pr-source",
            source,
            "expected https://github.com/OWNER/REPO/pull/NUMBER or OWNER/REPO#NUMBER",
        )
    path_parts = [part for part in parsed_url.path.split("/") if part]
    if len(path_parts) != 4 or path_parts[2] != "pull":
        raise GitHubPullRequestError(
            "unsupported-github-pr-source",
            source,
            "only GitHub pull request URLs are accepted",
        )
    owner, repo, number_text = path_parts[0], path_parts[1], path_parts[3]
    number = _validate_owner_repo_pr_number(source, owner, repo, number_text)
    return _source_artifact(source, owner, repo, number)


def materialize_github_pull_request_source(
    source: str,
    *,
    cache_dir: Path | str,
    fetch_json: JsonFetcher | None = None,
    clone_url_override: str | None = None,
) -> JsonObject:
    """Resolve a GitHub PR to ordered commits in a controlled bare repository cache."""

    json_fetcher = fetch_json or _fetch_json
    source_artifact = parse_github_pull_request_source(source)
    owner = str(source_artifact["owner"])
    repo = str(source_artifact["repo"])
    pr_number = int(source_artifact["pull_request"])
    clone_url = clone_url_override or str(source_artifact["clone_url"])

    pr_payload = _fetch_object(json_fetcher, str(source_artifact["api_url"]), source)
    commits_payload = _fetch_list(json_fetcher, str(source_artifact["commits_api_url"]), source)
    commit_shas, omitted_commit_count = _commit_shas_from_payload(source, commits_payload)
    if not commit_shas:
        raise GitHubPullRequestError(
            "github-pr-has-no-commits", source, "pull request has no commits"
        )

    try:
        materialized_commits = [
            materialize_github_commit_source(
                f"{owner}/{repo}@{commit}",
                cache_dir=cache_dir,
                clone_url_override=clone_url,
            )
            for commit in commit_shas
        ]
    except GitHubSourceError as exc:
        raise GitHubPullRequestError(exc.kind, source, exc.detail) from exc
    local_repo = str(materialized_commits[-1]["local_repo"])
    base = _ref_summary(source, pr_payload, "base")
    head = _ref_summary(source, pr_payload, "head")
    if not _is_full_sha(str(base.get("sha", ""))):
        base["sha"] = None
    if not _is_full_sha(str(head.get("sha", ""))):
        head["sha"] = commit_shas[-1]
    elif str(head["sha"]).lower() != commit_shas[-1]:
        raise GitHubPullRequestError(
            "github-pr-head-mismatch",
            source,
            "PR head SHA does not match the last ordered commit entry",
        )

    title, title_truncated = _bounded_text(pr_payload.get("title"), _MAX_PR_TITLE_BYTES)
    body, body_truncated = _bounded_text(pr_payload.get("body"), _MAX_PR_BODY_BYTES)
    omitted_record_count = omitted_commit_count + int(title_truncated) + int(body_truncated)
    risk_hints = ["github-transport-is-not-a-trust-oracle", "github-pr-metadata-is-hostile"]
    if omitted_commit_count:
        risk_hints.append("github-pr-commit-records-truncated")
    if title_truncated or body_truncated:
        risk_hints.append("github-pr-text-truncated")

    return {
        "artifact_type": "github_pull_request_materialization",
        "id": f"github:pull-request-materialized:{owner}/{repo}:{pr_number}",
        "schema_version": 1,
        "repo_identity": f"github:{owner}/{repo}",
        "pull_request": pr_number,
        "local_repo": local_repo,
        "source": source_artifact,
        "title": title,
        "body_excerpt": body,
        "author": _user_login(pr_payload.get("user")),
        "base": base,
        "head": head,
        "commits": commit_shas,
        "commit_count": len(commit_shas),
        "commit_materializations": materialized_commits,
        "provenance": {
            "resolved_from": source,
            "api_url": source_artifact["api_url"],
            "commits_api_url": source_artifact["commits_api_url"],
            "html_url": pr_payload.get("html_url") or source_artifact["html_url"],
            "clone_url": clone_url,
            "commit_order_source": "github-pulls-commits-api",
            "cache_policy": "bare-controlled-cache-fetch-ordered-pr-commits",
        },
        "evidence_refs": [
            f"github:pull-request:{owner}/{repo}#{pr_number}",
            *[f"github:commit:{owner}/{repo}@{commit}" for commit in commit_shas],
        ],
        "trust_boundary": "remote_github_metadata_untrusted",
        "limits": {
            "truncated": bool(omitted_record_count),
            "omitted_record_count": omitted_record_count,
        },
        "risk_hints": risk_hints,
    }


def review_github_pull_request(
    source: str,
    *,
    cache_dir: Path | str,
    fetch_json: JsonFetcher | None = None,
    clone_url_override: str | None = None,
) -> JsonObject:
    """Resolve a GitHub PR and review its ordered commits without posting comments."""

    materialized = materialize_github_pull_request_source(
        source,
        cache_dir=cache_dir,
        fetch_json=fetch_json,
        clone_url_override=clone_url_override,
    )
    commits = [str(commit) for commit in materialized["commits"]]
    review = _review_commit_sequence(
        Path(str(materialized["local_repo"])),
        commits,
        traversal="github-pull-request-commit-list",
        range_metadata={
            "base": materialized["base"].get("sha"),
            "target": materialized["head"].get("sha") or commits[-1],
            "pull_request": materialized["pull_request"],
            "id": "range:github-pull-request-commit-list",
            "evidence_refs": materialized["evidence_refs"],
        },
    )
    review["github_pull_request"] = materialized
    return review


def render_json(artifact: JsonObject) -> str:
    """Render stable JSON for GitHub PR artifacts."""

    return json.dumps(artifact, indent=2, sort_keys=True) + "\n"


def _parse_owner_repo_pr_number(source: str) -> tuple[str, str, int] | None:
    match = _PR_SHORT_RE.match(source)
    if not match:
        return None
    owner, repo = match.group("owner"), match.group("repo")
    number = _validate_owner_repo_pr_number(source, owner, repo, match.group("number"))
    return owner, repo, number


def _validate_owner_repo_pr_number(source: str, owner: str, repo: str, number_text: str) -> int:
    if not _SAFE_PATH_PART_RE.match(owner) or not _SAFE_PATH_PART_RE.match(repo):
        raise GitHubPullRequestError(
            "invalid-github-repository", source, "owner/repo has unsafe characters"
        )
    try:
        number = int(number_text)
    except ValueError as exc:
        raise GitHubPullRequestError(
            "invalid-github-pr-number", source, "pull request number must be numeric"
        ) from exc
    if number < 1:
        raise GitHubPullRequestError(
            "invalid-github-pr-number", source, "pull request number must be positive"
        )
    return number


def _source_artifact(source: str, owner: str, repo: str, number: int) -> JsonObject:
    html_url = f"https://github.com/{owner}/{repo}/pull/{number}"
    api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}"
    return {
        "artifact_type": "github_pull_request_source",
        "id": f"github:pull-request-source:{owner}/{repo}:{number}",
        "schema_version": 1,
        "owner": owner,
        "repo": repo,
        "pull_request": number,
        "source": source,
        "html_url": html_url,
        "api_url": api_url,
        "commits_api_url": f"{api_url}/commits",
        "clone_url": f"https://github.com/{owner}/{repo}.git",
        "evidence_refs": [f"github:pull-request:{owner}/{repo}#{number}"],
        "trust_boundary": "remote_github_metadata_untrusted",
        "limits": {"truncated": False, "omitted_record_count": 0},
        "risk_hints": ["github-transport-is-not-a-trust-oracle"],
    }


def _fetch_object(fetch_json: JsonFetcher, url: str, source: str) -> JsonObject:
    payload = fetch_json(url)
    if not isinstance(payload, dict):
        raise GitHubPullRequestError(
            "github-api-shape-error", source, f"expected object from {url}"
        )
    return payload


def _fetch_list(fetch_json: JsonFetcher, url: str, source: str) -> list[JsonObject]:
    payload = fetch_json(url)
    if not isinstance(payload, list):
        raise GitHubPullRequestError("github-api-shape-error", source, f"expected list from {url}")
    objects: list[JsonObject] = []
    for item in payload:
        if not isinstance(item, dict):
            raise GitHubPullRequestError(
                "github-api-shape-error", source, f"expected list of objects from {url}"
            )
        objects.append(item)
    return objects


def _commit_shas_from_payload(source: str, payload: list[JsonObject]) -> tuple[list[str], int]:
    commits: list[str] = []
    omitted = max(0, len(payload) - _MAX_PR_COMMITS)
    for item in payload[:_MAX_PR_COMMITS]:
        sha = str(item.get("sha", "")).lower()
        if not _is_full_sha(sha):
            raise GitHubPullRequestError(
                "ambiguous-github-pr-commit",
                source,
                "PR commit entries must contain full immutable 40-hex SHAs",
            )
        commits.append(sha)
    return commits, omitted


def _ref_summary(source: str, payload: JsonObject, side: str) -> JsonObject:
    value = payload.get(side)
    if not isinstance(value, dict):
        raise GitHubPullRequestError("github-api-shape-error", source, f"missing PR {side} object")
    return {"sha": value.get("sha"), "ref": value.get("ref")}


def _bounded_text(value: object, max_bytes: int) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    text = str(value)
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    return raw[:max_bytes].decode("utf-8", errors="ignore"), True


def _user_login(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    login = value.get("login")
    if login is None:
        return None
    return str(login)


def _is_full_sha(value: str) -> bool:
    return bool(_FULL_SHA_RE.match(value))


def _fetch_json(url: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "kernel-diffguard",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT_SECONDS) as response:
            return json.load(response)
    except OSError as exc:
        raise GitHubPullRequestError("github-api-unavailable", url, str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise GitHubPullRequestError("github-api-invalid-json", url, str(exc)) from exc
