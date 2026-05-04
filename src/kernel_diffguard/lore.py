"""Bounded lore.kernel.org search helpers for hostile mailing-list input."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import quote_plus, urljoin
from urllib.request import Request, urlopen
from xml.etree import ElementTree

from .mailing_list import parse_mailing_list_message

JsonObject = dict[str, Any]
FetchText = Callable[[str], str]

_LORE_SEARCH_BASE = "https://lore.kernel.org/all/"
_DEFAULT_MAX_RESULTS = 16
_FETCH_TIMEOUT_SECONDS = 10
_USER_AGENT = "kernel-diffguard/0.1"
_ATOM_NS = {"atom": "http://www.w3.org/2005/Atom"}


def search_lore_messages(
    query: str,
    *,
    fetch_text: FetchText | None = None,
    max_results: int = _DEFAULT_MAX_RESULTS,
) -> JsonObject:
    """Search lore.kernel.org Atom results and fetch bounded raw message artifacts."""

    fetch = fetch_text or _fetch_text
    search_url = _lore_search_url(query)
    atom_text = fetch(search_url)
    raw_urls = _raw_message_urls_from_atom(atom_text)
    emitted_urls = raw_urls[:max_results]
    omitted_record_count = max(0, len(raw_urls) - max_results)
    messages = []
    for raw_url in emitted_urls:
        message = parse_mailing_list_message(fetch(raw_url), source_ref=raw_url)
        message["source_url"] = raw_url
        messages.append(message)
    return {
        "artifact_type": "lore_search_result_set",
        "schema_version": 1,
        "query": query,
        "source_url": search_url,
        "message_count": len(messages),
        "messages": messages,
        "evidence_refs": [f"lore:search:{search_url}"],
        "trust_boundary": "remote_archive_email_untrusted",
        "limits": {
            "truncated": bool(omitted_record_count),
            "omitted_record_count": omitted_record_count,
            "max_results": max_results,
        },
        "risk_hints": _risk_hints(omitted_record_count),
    }


def render_json(result: JsonObject) -> str:
    """Render stable lore search JSON."""

    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def _lore_search_url(query: str) -> str:
    return f"{_LORE_SEARCH_BASE}?q={quote_plus(query)}&x=A"


def _raw_message_urls_from_atom(atom_text: str) -> list[str]:
    try:
        root = ElementTree.fromstring(atom_text)
    except ElementTree.ParseError:
        return []
    raw_urls: list[str] = []
    for entry in root.findall("atom:entry", _ATOM_NS):
        alternate = _entry_alternate_href(entry)
        if not alternate:
            continue
        raw_urls.append(_raw_url_for_alternate(alternate))
    return raw_urls


def _entry_alternate_href(entry: ElementTree.Element) -> str:
    for link in entry.findall("atom:link", _ATOM_NS):
        if link.attrib.get("rel", "alternate") == "alternate" and link.attrib.get("href"):
            return str(link.attrib["href"])
    return ""


def _raw_url_for_alternate(href: str) -> str:
    absolute = urljoin(_LORE_SEARCH_BASE, href)
    return f"{absolute.rstrip('/')}/raw"


def _fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": _USER_AGENT})
    with urlopen(request, timeout=_FETCH_TIMEOUT_SECONDS) as response:
        raw = cast(bytes, response.read())
    return raw.decode("utf-8", errors="replace")


def _risk_hints(omitted_record_count: int) -> list[str]:
    hints = ["network-fetched-email-is-hostile"]
    if omitted_record_count:
        hints.append("lore-result-records-truncated")
    return hints
