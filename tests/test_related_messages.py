from __future__ import annotations

import json

from kernel_diffguard.cli import main
from kernel_diffguard.mailing_list import parse_mailing_list_message
from kernel_diffguard.related_messages import find_related_message_candidates


def test_find_related_messages_scores_subject_time_path_and_list_evidence():
    commit = {
        "artifact_type": "commit_artifact",
        "id": "commit:abc123def456",
        "commit": "abc123def456",
        "author": {"timestamp": "2024-01-02T12:00:00Z"},
        "subject": "net: fix guard packet accounting",
        "touched_paths": ["net/core/dev.c", "drivers/net/ethernet/example.c"],
        "evidence_refs": ["git:commit:abc123def456"],
    }
    related_message = parse_mailing_list_message(
        """Message-ID: <net-fix@example.test>
Date: Tue, 2 Jan 2024 13:00:00 +0000
From: Reviewer <reviewer@example.test>
To: netdev@vger.kernel.org
List-Id: <netdev.vger.kernel.org>
Subject: Re: [PATCH v2] net: fix guard packet accounting
Content-Type: text/plain; charset=utf-8

Looks related to the packet accounting fix.

diff --git a/net/core/dev.c b/net/core/dev.c
+changed
""",
        source_ref="fixture:net-fix",
    )
    unrelated_message = parse_mailing_list_message(
        """Message-ID: <fs-fix@example.test>
Date: Tue, 2 Jan 2024 13:00:00 +0000
From: Reviewer <reviewer@example.test>
To: linux-fsdevel@vger.kernel.org
List-Id: <linux-fsdevel.vger.kernel.org>
Subject: [PATCH] fs: unrelated inode cleanup
Content-Type: text/plain; charset=utf-8

No shared path or subject.
""",
        source_ref="fixture:fs-fix",
    )

    candidates = find_related_message_candidates([commit], [related_message, unrelated_message])

    assert [candidate["message_refs"] for candidate in candidates] == [
        ["message:<net-fix@example.test>"]
    ]
    candidate = candidates[0]
    evidence_kinds = {evidence["kind"] for evidence in candidate["match_evidence"]}
    assert evidence_kinds >= {
        "timestamp-window",
        "subject-cue",
        "patch-path-overlap",
        "subsystem-list-id",
    }
    assert candidate["commit_refs"] == ["commit:abc123def456"]
    assert candidate["total_evidence_score"] > 1
    assert candidate["trust_boundary"] == "derived_review_signal"
    assert candidate["evidence_refs"] == [
        "git:commit:abc123def456",
        "mail:message-id:<net-fix@example.test>",
    ]


def test_related_message_search_bounds_hostile_candidate_fanout():
    commit = {
        "artifact_type": "commit_artifact",
        "id": "commit:abc123def456",
        "commit": "abc123def456",
        "author": {"timestamp": "2024-01-02T12:00:00Z"},
        "subject": "net: fix guard packet accounting",
        "touched_paths": ["net/core/dev.c"],
        "evidence_refs": ["git:commit:abc123def456"],
    }
    messages = [
        parse_mailing_list_message(
            f"""Message-ID: <net-fix-{index}@example.test>
Date: Tue, 2 Jan 2024 13:00:00 +0000
From: Reviewer <reviewer@example.test>
To: netdev@vger.kernel.org
List-Id: <netdev.vger.kernel.org>
Subject: [PATCH] net: fix guard packet accounting
Content-Type: text/plain; charset=utf-8

Diff below.
diff --git a/net/core/dev.c b/net/core/dev.c
+changed {index}
""",
            source_ref=f"fixture:net-fix-{index}",
        )
        for index in range(80)
    ]

    candidates = find_related_message_candidates([commit], messages, max_candidates=32)

    assert len(candidates) == 32
    assert candidates[-1]["limits"] == {
        "truncated": True,
        "omitted_record_count": 48,
        "max_candidates": 32,
        "max_match_evidence_records": 8,
    }
    assert "candidate-records-truncated" in candidates[-1]["risk_hints"]


def test_related_messages_cli_reads_normalized_artifact_files(tmp_path, capsys):
    commit = {
        "artifact_type": "commit_artifact",
        "id": "commit:abc123def456",
        "commit": "abc123def456",
        "author": {"timestamp": "2024-01-02T12:00:00Z"},
        "subject": "net: fix guard packet accounting",
        "touched_paths": ["net/core/dev.c"],
        "evidence_refs": ["git:commit:abc123def456"],
    }
    message = parse_mailing_list_message(
        """Message-ID: <net-fix@example.test>
Date: Tue, 2 Jan 2024 13:00:00 +0000
From: Reviewer <reviewer@example.test>
To: netdev@vger.kernel.org
List-Id: <netdev.vger.kernel.org>
Subject: [PATCH] net: fix guard packet accounting
Content-Type: text/plain; charset=utf-8

diff --git a/net/core/dev.c b/net/core/dev.c
+changed
""",
        source_ref="fixture:net-fix",
    )
    commit_file = tmp_path / "commit.json"
    message_file = tmp_path / "message.json"
    commit_file.write_text(json.dumps(commit), encoding="utf-8")
    message_file.write_text(json.dumps(message), encoding="utf-8")

    exit_code = main(
        [
            "related-messages",
            "--commit-artifact",
            str(commit_file),
            "--message-artifact",
            str(message_file),
            "--format",
            "json",
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["artifact_type"] == "related_message_candidate_set"
    assert output["candidate_count"] == 1
    assert output["candidates"][0]["message_refs"] == ["message:<net-fix@example.test>"]
