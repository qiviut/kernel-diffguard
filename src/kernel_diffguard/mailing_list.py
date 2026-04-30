"""Normalized mailing-list message parsing for hostile RFC822/mbox input."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

JsonObject = dict[str, Any]

_MAX_BODY_EXCERPT_BYTES = 16_384
_MAX_HEADER_BYTES = 512
_MAX_DERIVED_RECORDS = 32
_MAX_ATTACHMENT_SCAN_BYTES = 16_384
_URL_RE = re.compile(r"https?://[^\s<>()\[\]{}\"']+")
_DIFF_PATH_RE = re.compile(r"^diff --git a/(.*?) b/(.*?)$", re.MULTILINE)
_PROMPT_INJECTION_RE = re.compile(
    r"\b(ignore (all )?(previous|prior) instructions|exfiltrate|system prompt|developer message)\b",
    re.IGNORECASE,
)
_EXECUTABLE_SNIPPET_RE = re.compile(
    r"(^#!\s*/|\b(?:curl|wget)\b[^\n|]*(?:\|\s*(?:sh|bash))|\brm\s+-rf\b|\bsudo\b)",
    re.IGNORECASE | re.MULTILINE,
)


def parse_mailing_list_message(
    raw: str | bytes,
    *,
    source_ref: str = "stdin",
    max_body_excerpt_bytes: int = _MAX_BODY_EXCERPT_BYTES,
) -> JsonObject:
    """Parse one RFC822 or single-entry mbox message into bounded normalized facts."""

    raw_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    plain_text_excerpt, body_truncated = _plain_text_excerpt(message, max_body_excerpt_bytes)
    patch_text = _patch_text(message, plain_text_excerpt)
    message_id, message_id_truncated = _bounded_header(_raw_header(message, "message-id"))
    if not message_id:
        message_id = _synthetic_message_id(raw_bytes)
    from_header, from_truncated = _bounded_header(_raw_header(message, "from"))
    subject, subject_truncated = _bounded_header(_raw_header(message, "subject"))
    in_reply_to, in_reply_to_truncated = _bounded_header(_raw_header(message, "in-reply-to"))
    to_addrs, omitted_to_records = _addresses(message, "to")
    cc_addrs, omitted_cc_records = _addresses(message, "cc")
    list_ids, omitted_list_id_records = _list_ids(message)
    references, omitted_reference_records = _message_id_list(_raw_header(message, "references"))
    urls, omitted_url_records = _urls(plain_text_excerpt)
    attachments, omitted_attachment_records = _attachments(message)
    risk_hints = _risk_hints(message, plain_text_excerpt, body_truncated)
    patch, omitted_patch_paths = _patch_facts(patch_text)
    if patch["has_patch"]:
        risk_hints.append("patch-content-present")
    if omitted_url_records:
        risk_hints.append("url-records-truncated")
    if omitted_attachment_records:
        risk_hints.append("attachment-records-truncated")
    if omitted_patch_paths:
        risk_hints.append("patch-path-records-truncated")
    header_truncated_count = sum(
        [
            message_id_truncated,
            from_truncated,
            subject_truncated,
            in_reply_to_truncated,
        ]
    )
    omitted_header_records = (
        omitted_to_records
        + omitted_cc_records
        + omitted_list_id_records
        + omitted_reference_records
        + header_truncated_count
    )
    if omitted_header_records:
        risk_hints.append("header-field-truncated")

    omitted_record_count = (
        (1 if body_truncated else 0)
        + omitted_url_records
        + omitted_attachment_records
        + omitted_patch_paths
        + omitted_header_records
    )
    truncated = bool(omitted_record_count)
    return {
        "artifact_type": "mailing_list_message_artifact",
        "id": f"message:{message_id}",
        "schema_version": 1,
        "source_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "message_id": message_id,
        "unix_from": _unix_from(message),
        "date": _normalized_date(message.get("date")),
        "from": from_header,
        "to": to_addrs,
        "cc": cc_addrs,
        "list_ids": list_ids,
        "subject": subject,
        "in_reply_to": in_reply_to,
        "references": references,
        "plain_text_excerpt": plain_text_excerpt,
        "patch": patch,
        "attachments": attachments,
        "urls": urls,
        "domains": _domains(urls),
        "evidence_refs": [f"mail:source:{source_ref}", f"mail:message-id:{message_id}"],
        "trust_boundary": "remote_archive_email_untrusted",
        "limits": {
            "truncated": truncated,
            "omitted_record_count": omitted_record_count,
            "max_body_excerpt_bytes": max_body_excerpt_bytes,
            "body_excerpt_bytes": len(plain_text_excerpt.encode()),
            "raw_message_bytes": len(raw_bytes),
            "max_derived_records": _MAX_DERIVED_RECORDS,
            "omitted_url_record_count": omitted_url_records,
            "omitted_attachment_record_count": omitted_attachment_records,
            "omitted_patch_path_count": omitted_patch_paths,
            "omitted_header_record_count": omitted_header_records,
        },
        "risk_hints": sorted(set(risk_hints)),
    }


def parse_mailing_list_message_file(
    path: Path | str,
    *,
    max_body_excerpt_bytes: int = _MAX_BODY_EXCERPT_BYTES,
) -> JsonObject:
    """Parse one local message file using its path as the source reference."""

    message_path = Path(path)
    return parse_mailing_list_message(
        message_path.read_bytes(),
        source_ref=str(message_path),
        max_body_excerpt_bytes=max_body_excerpt_bytes,
    )


def render_json(artifact: JsonObject) -> str:
    """Render stable message artifact JSON."""

    return json.dumps(artifact, indent=2, sort_keys=True) + "\n"


def _plain_text_excerpt(message: Message, max_bytes: int) -> tuple[str, bool]:
    parts: list[str] = []
    used_bytes = 0
    truncated = False
    candidate_parts = list(message.walk()) if message.is_multipart() else [message]
    for part in candidate_parts:
        if part.is_multipart():
            continue
        if (
            part.get_content_disposition() == "attachment"
            or part.get_content_type() != "text/plain"
        ):
            continue
        remaining = max_bytes - used_bytes
        if remaining <= 0:
            truncated = True
            break
        excerpt = _part_text_bounded(part, remaining)
        parts.append(excerpt.rstrip("\n"))
        used_bytes += len(excerpt.encode())
        if _payload_size_bytes(part) > len(excerpt.encode()):
            truncated = True
            break
    joined = "\n".join(part for part in parts if part).rstrip("\n")
    final_excerpt, final_truncated = _bounded_text(
        joined + ("\n" if parts else ""),
        max_bytes,
    )
    return final_excerpt, truncated or final_truncated


def _attachments(message: Message) -> tuple[list[JsonObject], int]:
    attachments: list[JsonObject] = []
    omitted_records = 0
    for part in message.walk() if message.is_multipart() else []:
        if part.is_multipart() or part.get_content_disposition() != "attachment":
            continue
        if len(attachments) >= _MAX_DERIVED_RECORDS:
            omitted_records += 1
            continue
        attachments.append(
            {
                "content_type": part.get_content_type(),
                "filename": _bounded_header(part.get_filename() or "")[0],
                "size_bytes": _payload_size_bytes(part),
            }
        )
    return attachments, omitted_records


def _payload_size_bytes(part: Message) -> int:
    payload = part.get_payload(decode=False)
    if isinstance(payload, str):
        return len(payload.encode(errors="replace"))
    if isinstance(payload, bytes):
        return len(payload)
    return 0


def _part_text_bounded(part: Message, max_bytes: int) -> str:
    payload = part.get_payload(decode=False)
    if payload is None:
        return ""
    text = payload.decode(errors="replace") if isinstance(payload, bytes) else str(payload)
    excerpt, _truncated = _bounded_text(text, max_bytes)
    return excerpt


def _synthetic_message_id(raw_bytes: bytes) -> str:
    digest = hashlib.sha256(raw_bytes).hexdigest()[:16]
    return f"<synthetic-{digest}@kernel-diffguard.local>"


def _unix_from(message: Message) -> str:
    unix_from = message.get_unixfrom()
    if not unix_from:
        return ""
    return unix_from.removeprefix("From ")


def _raw_header(message: Message, name: str) -> str:
    value = message.get(name)
    return str(value).strip() if value is not None else ""


def _bounded_header(value: str) -> tuple[str, bool]:
    return _bounded_text(value, _MAX_HEADER_BYTES)


def _header(message: Message, name: str) -> str:
    return _bounded_header(_raw_header(message, name))[0]


def _addresses(message: Message, name: str) -> tuple[list[str], int]:
    values = message.get_all(name, [])
    addresses = [addr for _display, addr in getaddresses([str(value) for value in values]) if addr]
    return _cap_list(addresses)


def _cap_list(values: list[str]) -> tuple[list[str], int]:
    bounded_values: list[str] = []
    truncated_values = 0
    for value in values[:_MAX_DERIVED_RECORDS]:
        bounded, truncated = _bounded_header(value)
        bounded_values.append(bounded)
        if truncated:
            truncated_values += 1
    omitted_values = max(0, len(values) - _MAX_DERIVED_RECORDS)
    return bounded_values, omitted_values + truncated_values


def _list_ids(message: Message) -> tuple[list[str], int]:
    ids: list[str] = []
    for value in message.get_all("list-id", []):
        ids.extend(match.group(1) for match in re.finditer(r"<([^>]+)>", str(value)))
    return _cap_list(ids)


def _message_id_list(value: str) -> tuple[list[str], int]:
    return _cap_list(re.findall(r"<[^>]+>", value))


def _normalized_date(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _bounded_text(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode()
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode(errors="ignore"), True


def _urls(text: str) -> tuple[list[str], int]:
    all_urls = sorted(set(match.rstrip(".,;") for match in _URL_RE.findall(text)))
    return all_urls[:_MAX_DERIVED_RECORDS], max(0, len(all_urls) - _MAX_DERIVED_RECORDS)


def _domains(urls: list[str]) -> list[str]:
    domains = {urlparse(url).hostname for url in urls}
    return sorted(domain for domain in domains if domain)


def _patch_text(message: Message, plain_text: str) -> str:
    parts = [plain_text]
    scan_bytes = 0
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart() or part.get_content_disposition() != "attachment":
                continue
            filename = part.get_filename() or ""
            if part.get_content_type() in {"text/x-patch", "text/x-diff"} or filename.endswith(
                (".patch", ".diff")
            ):
                remaining = _MAX_ATTACHMENT_SCAN_BYTES - scan_bytes
                if remaining <= 0:
                    break
                excerpt = _part_text_bounded(part, remaining)
                parts.append(excerpt)
                scan_bytes += len(excerpt.encode())
    return "\n".join(parts)


def _patch_facts(text: str) -> tuple[JsonObject, int]:
    all_touched_paths = sorted({match.group(2) for match in _DIFF_PATH_RE.finditer(text)})
    touched_paths = all_touched_paths[:_MAX_DERIVED_RECORDS]
    omitted_paths = max(0, len(all_touched_paths) - _MAX_DERIVED_RECORDS)
    has_diff = bool(all_touched_paths)
    return {
        "has_patch": has_diff or bool(re.search(r"^---\s+\S", text, re.MULTILINE)),
        "has_diff": has_diff,
        "touched_paths": touched_paths,
    }, omitted_paths


def _risk_hints(message: Message, plain_text: str, body_truncated: bool) -> list[str]:
    risk_hints = ["email-content-is-hostile"]
    combined = "\n".join([_header(message, "subject"), plain_text])
    if body_truncated:
        risk_hints.append("body-excerpt-truncated")
    if _PROMPT_INJECTION_RE.search(combined):
        risk_hints.append("hostile-instruction-language")
    attachment_text_parts: list[str] = []
    attachment_text_bytes = 0
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart() or part.get_content_disposition() != "attachment":
                continue
            remaining = _MAX_ATTACHMENT_SCAN_BYTES - attachment_text_bytes
            if remaining <= 0:
                break
            excerpt = _part_text_bounded(part, remaining)
            attachment_text_parts.append(excerpt)
            attachment_text_bytes += len(excerpt.encode())
    attachment_text = "\n".join(attachment_text_parts)
    if _EXECUTABLE_SNIPPET_RE.search(combined) or _EXECUTABLE_SNIPPET_RE.search(attachment_text):
        risk_hints.append("executable-looking-snippet")
    urls, _omitted_urls = _urls(combined)
    if urls:
        risk_hints.append("url-present")
    return risk_hints
