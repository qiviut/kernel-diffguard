"""Normalized single-commit source fact parsing."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]

_FORMAT_SEPARATOR = "%x1f"
_MAX_DEFAULT_DIFF_EXCERPT_BYTES = 16_384


def parse_commit_artifact(
    repo: Path | str,
    commit: str,
    *,
    max_diff_excerpt_bytes: int = _MAX_DEFAULT_DIFF_EXCERPT_BYTES,
) -> JsonObject:
    """Parse one local git commit into bounded normalized source facts."""

    repo_path = Path(repo)
    commit_sha = _git(repo_path, "rev-parse", "--verify", f"{commit}^{{commit}}").strip()
    metadata = _commit_metadata(repo_path, commit_sha)
    path_changes = _parse_name_status(
        _git(
            repo_path,
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-status",
            "--find-renames",
            "-r",
            "-z",
            commit_sha,
        )
    )
    diff_stats = _parse_numstat(
        _git(
            repo_path,
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--numstat",
            "--find-renames",
            "-r",
            "-z",
            commit_sha,
        )
    )
    diff_excerpt, truncated = _git_bounded(
        repo_path,
        max_diff_excerpt_bytes,
        "show",
        "--no-ext-diff",
        "--format=",
        "--find-renames",
        commit_sha,
        "--",
    )
    touched_paths = sorted({path for change in path_changes for path in change["paths"]})
    risk_hints = ["diff-excerpt-truncated"] if truncated else []

    return {
        "artifact_type": "commit_artifact",
        "id": f"commit:{commit_sha}",
        "schema_version": 1,
        "commit": commit_sha,
        "parents": metadata["parents"],
        "tree": metadata["tree"],
        "author": metadata["author"],
        "committer": metadata["committer"],
        "subject": metadata["subject"],
        "body": metadata["body"],
        "touched_paths": touched_paths,
        "path_changes": path_changes,
        "diff_stats": diff_stats,
        "diff_excerpt": diff_excerpt,
        "evidence_refs": [f"git:commit:{commit_sha}"],
        "trust_boundary": "local_git_metadata_untrusted",
        "secondary_trust_boundaries": ["local_git_diff_untrusted"],
        "limits": {
            "truncated": truncated,
            "omitted_record_count": 1 if truncated else 0,
            "max_diff_excerpt_bytes": max_diff_excerpt_bytes,
            "diff_excerpt_bytes": len(diff_excerpt.encode()),
        },
        "risk_hints": risk_hints,
    }


def _commit_metadata(repo: Path, commit_sha: str) -> JsonObject:
    raw = _git(
        repo,
        "show",
        "-s",
        f"--format=%H{_FORMAT_SEPARATOR}%P{_FORMAT_SEPARATOR}%T{_FORMAT_SEPARATOR}"
        f"%an{_FORMAT_SEPARATOR}%ae{_FORMAT_SEPARATOR}%aI{_FORMAT_SEPARATOR}"
        f"%cn{_FORMAT_SEPARATOR}%ce{_FORMAT_SEPARATOR}%cI{_FORMAT_SEPARATOR}"
        f"%s{_FORMAT_SEPARATOR}%B",
        commit_sha,
    )
    parts = raw.split("\x1f", maxsplit=10)
    if len(parts) != 11:
        raise ValueError("git commit metadata output did not contain expected separators")
    (
        _commit,
        parents,
        tree,
        author_name,
        author_email,
        author_timestamp,
        committer_name,
        committer_email,
        committer_timestamp,
        subject,
        body,
    ) = parts
    return {
        "parents": parents.split() if parents else [],
        "tree": tree,
        "author": {
            "name": author_name,
            "email": author_email,
            "timestamp": author_timestamp,
        },
        "committer": {
            "name": committer_name,
            "email": committer_email,
            "timestamp": committer_timestamp,
        },
        "subject": subject,
        "body": _normalize_commit_body(body),
    }


def _normalize_commit_body(body: str) -> str:
    stripped = body.rstrip("\n")
    return f"{stripped}\n" if stripped else ""


def _parse_name_status(raw: str) -> list[JsonObject]:
    changes: list[JsonObject] = []
    tokens = _split_nul(raw)
    index = 0
    while index < len(tokens):
        status_token = tokens[index]
        index += 1
        status = status_token[0]
        score = status_token[1:] or None
        path_count = 2 if status in {"R", "C"} else 1
        paths = tokens[index : index + path_count]
        index += path_count
        changes.append({"status": status, "score": score, "paths": paths})
    return changes


def _parse_numstat(raw: str) -> list[JsonObject]:
    stats: list[JsonObject] = []
    tokens = _split_nul(raw)
    index = 0
    while index < len(tokens):
        header = tokens[index]
        index += 1
        additions, deletions, path = header.split("\t", maxsplit=2)
        if path:
            normalized_path = path
        else:
            if index + 1 >= len(tokens):
                break
            _old_path = tokens[index]
            normalized_path = tokens[index + 1]
            index += 2
        stats.append(
            {
                "additions": _parse_count(additions),
                "deletions": _parse_count(deletions),
                "path": normalized_path,
            }
        )
    return stats


def _split_nul(raw: str) -> list[str]:
    return [token for token in raw.split("\0") if token]


def _parse_count(value: str) -> int | None:
    return None if value == "-" else int(value)


def _bounded_text(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode()
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode(errors="ignore"), True


def _git_bounded(repo: Path, max_stdout_bytes: int, *args: str) -> tuple[str, bool]:
    process = subprocess.Popen(
        ["git", *args],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None:
        raise RuntimeError("git stdout pipe was not created")
    kept = process.stdout.read(max_stdout_bytes + 1)
    truncated = len(kept) > max_stdout_bytes
    if truncated:
        process.kill()
        _stdout_remainder, _stderr = process.communicate()
        return kept[:max_stdout_bytes].decode(errors="ignore"), True

    stdout_remainder, stderr = process.communicate()
    output = kept + stdout_remainder
    if process.returncode != 0:
        raise subprocess.CalledProcessError(
            process.returncode,
            ["git", *args],
            output=output.decode(errors="ignore"),
            stderr=stderr.decode(errors="ignore"),
        )
    return output.decode(errors="ignore"), False


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout
