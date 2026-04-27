from pathlib import Path

from kernel_diffguard.charter import AnalysisGoal, default_goals, summarize_goals


def test_default_goals_cover_malicious_change_impact_and_provenance():
    goals = default_goals()

    assert AnalysisGoal.MALICIOUS_CHANGE_DETECTION in goals
    assert AnalysisGoal.UPDATE_IMPACT_ANALYSIS in goals
    assert AnalysisGoal.PROVENANCE_AND_TREE_INTEGRITY in goals
    assert AnalysisGoal.MAILING_LIST_CONTEXT in goals


def test_goal_summary_mentions_kernel_as_initial_exemplar_not_only_target():
    summary = summarize_goals()

    assert "Linux kernel" in summary
    assert "git repositories" in summary
    assert "commit X to commit Y" in summary


def test_testing_strategy_covers_fixture_pyramid_and_iteration_value():
    strategy = Path("docs/testing-strategy.md").read_text(encoding="utf-8")

    required_sections = [
        "## Source-review fixture pyramid",
        "## Unit test coverage matrix",
        "## Integration fixture rules",
        "## Golden review-packet fixtures",
        "## Optional public-data smoke tests",
        "## Per-iteration value checks",
    ]
    for section in required_sections:
        assert section in strategy

    required_signals = [
        "removed tests",
        "CI/static-analysis weakening",
        "suspicious executable additions",
        "prompt-injection text",
        "high-risk kernel paths",
        "oversized diffs",
    ]
    for signal in required_signals:
        assert signal in strategy

    assert "default CI" in strategy
    assert "no network" in strategy
    assert "Raspberry Pi kernel" in strategy
    assert "lore.kernel.org" in strategy
    assert "observable reviewer signal" in strategy
    assert "parser capability" in strategy
    assert "evidence traceability" in strategy
