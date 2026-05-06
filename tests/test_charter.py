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
    assert "scripts/check.sh" in workflow
    assert "scripts/check.sh" in strategy
    assert "python -m pytest -q" in strategy
    assert "python -m ruff check ." in strategy
    assert "python -m mypy src" in strategy
    assert "git diff --check" in strategy


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


def test_named_expert_checks_define_contracts_without_dsl_or_scoring():
    checks = Path("docs/named-expert-checks.md").read_text(encoding="utf-8")

    required_sections = [
        "## Goal / problem framing",
        "## Design posture",
        "## Named-check contract",
        "## Result vocabulary",
        "## First implementation-ready checks",
        "## Deferred checks requiring codebase experience",
        "## Review, testing, and promotion rules",
        "## Refactoring posture",
        "## Downstream Beads",
    ]
    for section in required_sections:
        assert section in checks

    required_contract_fields = [
        "check_id",
        "expert_question",
        "applies_to",
        "evidence_consumed",
        "satisfied_when",
        "violated_when",
        "missing_evidence_when",
        "inconclusive_when",
        "not_applicable_when",
        "required_next_action",
        "rationale",
        "limitations",
    ]
    for field in required_contract_fields:
        assert field in checks

    required_check_ids = [
        "KDG-CHECK-REMOVED-TEST",
        "KDG-CHECK-CI-STATIC-ANALYSIS-WEAKENED",
        "KDG-CHECK-HIGH-AUTHORITY-EXECUTABLE",
        "KDG-CHECK-GENERATED-CORRESPONDENCE",
        "KDG-CHECK-KERNEL-RETEST-OBLIGATION",
    ]
    for check_id in required_check_ids:
        assert check_id in checks

    required_statuses = [
        "satisfied",
        "violated",
        "missing_evidence",
        "inconclusive",
        "not_applicable",
    ]
    for status in required_statuses:
        assert status in checks

    required_terms = [
        "reviewed Python code",
        "not a user-authored DSL",
        "not an anomaly detector",
        "not a maliciousness verdict",
        "requires_codebase_experience",
        "accepted_invariant_missing",
        "target_profile_missing",
        "no_check_coverage",
        "observation -> candidate expert question -> evidence map -> named-check contract",
        "Do not invent a broad policy DSL now",
        "kernel-diffguard-ehv",
        "kernel-diffguard-krn",
    ]
    for term in required_terms:
        assert term in checks


def test_expert_question_evidence_map_covers_evidence_classes_and_gaps():
    evidence_map = Path("docs/expert-question-evidence-map.md").read_text(encoding="utf-8")

    required_sections = [
        "## Goal / problem framing",
        "## Evidence source classes",
        "## Current evidence inventory",
        "## Status vocabulary for evidence mapping",
        "## Mapping: universal repository-security questions",
        "## Mapping: candidate Linux-kernel questions",
        "## Mapping: codebase-experience-dependent questions",
        "## Evidence inputs that can feed first named checks",
        "## Required output behavior",
        "## Downstream Beads",
    ]
    for section in required_sections:
        assert section in evidence_map

    required_questions = [
        "UQ-001: What authority boundary did this change touch?",
        "UQ-002: Which invariant does this subsystem or process appear to rely on?",
        "UQ-003: Is this change modifying policy, enforcement, setup, use, or observation?",
        "UQ-004: Are tests, CI, static analysis, warnings, fuzzing, or sanitizers being weakened?",
        "UQ-005: Are generated artifacts changing with corresponding source,",
        "UQ-006: Did this change add or modify high-authority executable code?",
        "UQ-007: Is risky behavior split across commits, files, or review surfaces?",
        "UQ-008: Does the change match its stated purpose without hiding semantic drift?",
        "UQ-009: What evidence would make this change acceptable?",
        "UQ-010: What exception would a responsible maintainer have to write down?",
        "KQ-001: Does this touch a kernel authority or isolation boundary?",
        "KQ-002: Does this alter Kconfig, build options, defaults, or feature gates?",
        "KQ-003: Does this change a user-visible ABI, syscall, ioctl, netlink,",
        "KQ-004: Does this change scheduler, memory-management, locking, lifetime,",
        "KQ-005: Are source changes separated from required kernel tests, configs,",
        "CQ-001: What subsystem-specific invariants are maintainers relying on here?",
        "CQ-002: Which files or path prefixes normally change together for a reason",
        "CQ-003: Which target profiles make this change operationally relevant?",
        "CQ-004: Which repeated review objections should become durable questions or checks?",
    ]
    for question in required_questions:
        assert question in evidence_map

    required_terms = [
        "local git",
        "GitHub hostile metadata",
        "mailing-list/archive",
        "external snapshot",
        "generated artifact",
        "build/CI",
        "target profile",
        "answered_by_current_evidence",
        "partially_answered",
        "missing_evidence",
        "not_collected_by_default",
        "requires_codebase_experience",
        "no_check_coverage",
        "authority_boundary_map_missing",
        "replacement_or_exception_evidence_missing",
        "generated_source_correspondence_missing",
        "target_profile_missing",
        "not a policy DSL",
        "not a verdict table",
        "not an anomaly model",
    ]
    for term in required_terms:
        assert term in evidence_map
