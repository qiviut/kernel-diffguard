import re
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


def test_ci_workflow_pins_github_actions_by_full_sha_with_update_intent():
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    strategy = Path("docs/testing-strategy.md").read_text(encoding="utf-8")

    uses_refs = re.findall(r"uses:\s+([^\s#]+)", workflow)
    assert uses_refs
    for action_ref in uses_refs:
        owner_repo, ref = action_ref.rsplit("@", 1)
        assert owner_repo.startswith("actions/")
        assert re.fullmatch(r"[0-9a-f]{40}", ref), action_ref

    assert "upstream tag intent: v6" in workflow
    assert "git ls-remote https://github.com/actions/checkout.git refs/tags/v6" in strategy
    assert "git ls-remote https://github.com/actions/setup-python.git refs/tags/v6" in strategy
    assert "review upstream release notes" in strategy


def test_external_evidence_design_covers_openssf_snapshot_boundaries():
    design = Path("docs/external-evidence.md").read_text(encoding="utf-8")

    required_sections = [
        "## Goal / problem framing",
        "## Snapshot-first architecture",
        "## Normalized external evidence record",
        "## OpenSSF component mapping",
        "## Trust boundaries and determinism",
        "## Integration order",
    ]
    for section in required_sections:
        assert section in design

    required_terms = [
        "OpenSSF Scorecard",
        "SLSA",
        "Sigstore",
        "OSV",
        "OpenVEX",
        "GUAC",
        "Security Insights",
        "Criticality Score",
        "Package Analysis",
        "snapshot",
        "offline by default",
        "reviewer-assistance signals",
    ]
    for term in required_terms:
        assert term in design

    assert "not verdicts" in design
    assert "no live network" in design


def test_official_interface_research_covers_version_sensitive_sources():
    research = Path("docs/official-interface-research.md").read_text(encoding="utf-8")

    required_sections = [
        "## Goal / problem framing",
        "## Official references",
        "## Interface decisions",
        "## Version-sensitive behavior",
        "## Alternatives and deferrals",
        "## Downstream beads",
    ]
    for section in required_sections:
        assert section in research

    required_terms = [
        "git-scm.com/docs",
        "git rev-list",
        "git diff-tree",
        "git cat-file",
        "git rev-parse",
        "pyproject.toml",
        "typing.python.org",
        "public-inbox",
        "lore.kernel.org",
        "docs.kernel.org/process",
        "Signed-off-by",
        "Fixes:",
        "offline by default",
        "hostile input",
    ]
    for term in required_terms:
        assert term in research

    assert "Git 2.51.0" in research
    assert "Python 3.13.7" in research


def test_normalized_evidence_schema_doc_covers_artifacts_and_boundaries():
    schema_doc = Path("docs/normalized-evidence-schemas.md").read_text(encoding="utf-8")

    required_sections = [
        "## Goal / problem framing",
        "## Trust-boundary labels",
        "## Artifact schemas",
        "## Validation fixtures",
        "## Downstream implementation rules",
    ]
    for section in required_sections:
        assert section in schema_doc

    required_terms = [
        "commit_artifact",
        "commit_range_manifest",
        "mailing_list_message_artifact",
        "related_message_candidate",
        "finding",
        "recommendation",
        "external_evidence_record",
        "evidence_refs",
        "trust_boundary",
        "limits",
        "risk_hints",
        "hostile input",
        "not verdicts",
    ]
    for term in required_terms:
        assert term in schema_doc


def test_expert_operating_questions_catalog_covers_onboarding_review_questions():
    catalog = Path("docs/expert-operating-questions.md").read_text(encoding="utf-8")

    required_sections = [
        "## Goal / problem framing",
        "## Classification",
        "## Universal repository-security questions",
        "## Candidate Linux-kernel questions",
        "## Questions that require more codebase experience",
        "## Relationship to downstream Beads",
        "## Non-goals",
    ]
    for section in required_sections:
        assert section in catalog

    required_questions = [
        "UQ-001: What authority boundary did this change touch?",
        "UQ-002: Which invariant does this subsystem or process appear to rely on?",
        "UQ-003: Is this change modifying policy, enforcement, setup, use, or",
        "UQ-004: Are tests, CI, static analysis, warnings, fuzzing, or sanitizers",
        "UQ-005: Are generated artifacts changing with corresponding source,",
        "UQ-006: Did this change add or modify high-authority executable code?",
        "UQ-007: Is risky behavior split across commits, files, or review surfaces?",
        "UQ-008: Does the change match its stated purpose without hiding semantic",
        "UQ-009: What evidence would make this change acceptable?",
        "UQ-010: What exception would a responsible maintainer have to write down?",
        "KQ-001: Does this touch a kernel authority or isolation boundary?",
        "CQ-001: What subsystem-specific invariants are maintainers relying on here?",
    ]
    for question in required_questions:
        assert question in catalog

    required_terms = [
        "generic",
        "candidate kernel-specific",
        "requires more codebase experience",
        "not a policy DSL",
        "Do not invent a broad policy DSL",
        "Do not produce anomaly scores",
        "hostile commit messages",
        "kernel-diffguard-2td",
        "kernel-diffguard-ngj",
        "kernel-diffguard-ehv",
    ]
    for term in required_terms:
        assert term in catalog
