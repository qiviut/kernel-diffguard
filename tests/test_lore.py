from __future__ import annotations

from kernel_diffguard.cli import main
from kernel_diffguard.lore import search_lore_messages


def test_lore_search_cli_emits_json(monkeypatch, capsys):
    def fake_search(query: str, *, max_results: int):
        return {
            "artifact_type": "lore_search_result_set",
            "schema_version": 1,
            "query": query,
            "message_count": max_results,
            "messages": [],
            "evidence_refs": ["lore:search:fixture"],
            "trust_boundary": "remote_archive_email_untrusted",
            "limits": {"truncated": False, "omitted_record_count": 0, "max_results": max_results},
            "risk_hints": ["network-fetched-email-is-hostile"],
        }

    monkeypatch.setattr("kernel_diffguard.cli.search_lore_messages", fake_search)

    assert main(["lore-search", "--query", "net: fix guard", "--max-results", "2"]) == 0

    output = capsys.readouterr().out
    assert '"query": "net: fix guard"' in output
    assert '"message_count": 2' in output


def test_search_lore_messages_fetches_atom_raw_messages_and_parses_hostile_artifacts():
    fetched_urls: list[str] = []
    atom = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>[PATCH] net: fix guard</title>
    <link rel="alternate" href="https://lore.kernel.org/all/patch-1@example.test/" />
    <updated>2024-01-02T13:00:00Z</updated>
  </entry>
</feed>
"""
    raw_message = """Message-ID: <patch-1@example.test>
Date: Tue, 2 Jan 2024 13:00:00 +0000
From: Author <author@example.test>
To: netdev@vger.kernel.org
List-Id: <netdev.vger.kernel.org>
Subject: [PATCH] net: fix guard
Content-Type: text/plain; charset=utf-8

diff --git a/net/core/dev.c b/net/core/dev.c
+changed
"""

    def fake_fetch(url: str) -> str:
        fetched_urls.append(url)
        if url.endswith("&x=A"):
            return atom
        if url == "https://lore.kernel.org/all/patch-1@example.test/raw":
            return raw_message
        raise AssertionError(f"unexpected URL: {url}")

    result = search_lore_messages("net: fix guard", fetch_text=fake_fetch, max_results=8)

    assert fetched_urls == [
        "https://lore.kernel.org/all/?q=net%3A+fix+guard&x=A",
        "https://lore.kernel.org/all/patch-1@example.test/raw",
    ]
    assert result["artifact_type"] == "lore_search_result_set"
    assert result["query"] == "net: fix guard"
    assert result["message_count"] == 1
    message = result["messages"][0]
    assert message["message_id"] == "<patch-1@example.test>"
    assert message["source_url"] == "https://lore.kernel.org/all/patch-1@example.test/raw"
    assert message["trust_boundary"] == "remote_archive_email_untrusted"
    assert message["patch"]["touched_paths"] == ["net/core/dev.c"]


def test_search_lore_messages_bounds_feed_entries_without_fetching_excess_raw_messages():
    atom_entries = "\n".join(
        (
            '<entry><link rel="alternate" '
            f'href="https://lore.kernel.org/all/msg-{index}@example.test/" /></entry>'
        )
        for index in range(20)
    )
    atom = f'<feed xmlns="http://www.w3.org/2005/Atom">{atom_entries}</feed>'
    fetched_urls: list[str] = []

    def fake_fetch(url: str) -> str:
        fetched_urls.append(url)
        if url.endswith("&x=A"):
            return atom
        return f"""Message-ID: <{url.rsplit("/", 2)[-2]}>
Subject: bounded
Content-Type: text/plain; charset=utf-8

body
"""

    result = search_lore_messages("bounded", fetch_text=fake_fetch, max_results=3)

    assert result["message_count"] == 3
    assert len(fetched_urls) == 4
    assert result["limits"] == {
        "truncated": True,
        "omitted_record_count": 17,
        "max_results": 3,
    }
    assert "lore-result-records-truncated" in result["risk_hints"]
