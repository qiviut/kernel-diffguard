"""Deterministic hostile-instruction and prompt-injection cue scanning."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class HostileInstructionHit:
    """One bounded hostile-instruction cue found in untrusted text."""

    marker: str
    risk_hint: str
    location: str
    snippet: str


_HOSTILE_INSTRUCTION_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "ignore-previous-instructions",
        "hostile-instruction-language",
        re.compile(
            r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+instructions\b",
            re.I,
        ),
    ),
    (
        "policy-override-language",
        "policy-override-language",
        re.compile(
            r"\b(?:override|bypass|disable)\s+"
            r"(?:all\s+)?(?:the\s+)?(?:safety\s+)?policy\b",
            re.I,
        ),
    ),
    (
        "credential-or-secret-request",
        "credential-or-secret-request",
        re.compile(
            r"\b(?:exfiltrate|reveal|leak|print|dump|send)\s+(?:api\s+)?(?:tokens?|credentials?|secrets?)\b",
            re.I,
        ),
    ),
    (
        "tool-execution-request",
        "tool-execution-request",
        re.compile(
            r"\b(?:run|execute|call|use)\s+(?:this\s+)?(?:the\s+)?(?:shell\s+)?(?:command|tool|script)\b|"
            r"\b(?:curl|wget)\b[^\n|]*(?:\|\s*(?:sh|bash))|\brm\s+-rf\b|\bsudo\b",
            re.I,
        ),
    ),
    (
        "hidden-instruction-marker",
        "hidden-instruction-marker",
        re.compile(
            r"(?:<!--\s*hidden\s+instruction|begin\s+system\s+prompt|<\|im_start\|>|"
            r"\b(?:system|developer)\s+message\s*:|\bsystem\s+prompt\b)",
            re.I,
        ),
    ),
)


def scan_hostile_instruction_texts(fields: list[tuple[str, str]]) -> list[HostileInstructionHit]:
    """Scan named untrusted text fields for hostile-instruction cues.

    The scanner returns compact marker/location evidence, not raw authority. Callers decide how
    to surface the cues in findings or risk hints.
    """

    hits: list[HostileInstructionHit] = []
    seen: set[tuple[str, str]] = set()
    for location, text in fields:
        for marker, risk_hint, pattern in _HOSTILE_INSTRUCTION_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            key = (marker, location)
            if key in seen:
                continue
            seen.add(key)
            snippet = " ".join(match.group(0).split())
            hits.append(
                HostileInstructionHit(
                    marker=marker,
                    risk_hint=risk_hint,
                    location=location,
                    snippet=snippet,
                )
            )
    return hits


def hostile_risk_hints(fields: list[tuple[str, str]]) -> list[str]:
    """Return sorted risk hint IDs for hostile-instruction cues in untrusted text."""

    return sorted({hit.risk_hint for hit in scan_hostile_instruction_texts(fields)})
