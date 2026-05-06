# kernel-diffguard

kernel-diffguard is a new public project for analyzing git repositories for security and operational risk, using the Linux kernel as the prime initial example. Its long-term model is not probabilistic anomaly detection; it is deterministic evidence reduction followed by explicit operating-envelope checks that say which changes are permitted, which required evidence is missing, and which violations require human-approved exceptions.

The project is intentionally broader than the kernel: the kernel gives us a large, high-stakes, public, mailing-list-driven repository where we can build and validate reusable workflows for other git histories.

## Core questions

1. Was a malicious change added to the code, possibly over multiple commits, by:
   - an untrusted developer,
   - a trusted but compromised developer, or
   - injection into the git tree or generated binaries outside ordinary commits?
2. If a system updates from commit X to commit Y, where Y = X + n and n >= 1:
   - what changed that can affect our system,
   - what needs to be re-tested,
   - which commits are obviously correct versus too complex to trust casually, and
   - can mailing-list discussion or review context help us reason about the patch?

## Initial direction

The first milestone is not an all-knowing AI reviewer. It is a reproducible analysis workbench that gathers evidence, reduces it deterministically, and makes human review sharper. The project should move from raw review-signal findings toward allow-list-style operating envelopes: versioned rules for repository, subsystem, process, patch-shape, and target-system constraints. A useful result should say "policy X applies, evidence Y shows it is satisfied/violated/missing, and the required next action is Z" rather than "this looks statistically unusual."

Near-term work should therefore:

- ingest commit ranges and associated metadata,
- classify touched subsystems and likely runtime impact,
- surface evidence that can satisfy or violate explicit policy envelopes,
- correlate patches with public discussion, especially Linux kernel mailing lists,
- compare source trees and generated artifacts where possible, and
- emit review packets that separate facts, policy check results, missing evidence, uncertainty, and recommendations.

## Trust posture

Repository contents, commit metadata, mailing-list text, build logs, generated artifacts, and binaries are all treated as hostile input. The project should prefer deterministic parsing and reduction first, then logical policy checks over selected artifacts. Historical baselines may suggest candidate policies, but accepted policies must be explicit and inspectable; history should not silently become an anomaly score or trust oracle. Carefully bounded model-assisted analysis, if added later, must operate downstream of reduced evidence and policy results.

## Status

Early CLI and regression skeleton are in place. The current deterministic reviewer can:

- review one local commit with `kdiffguard review-commit --repo PATH --commit SHA --format json|text`,
- review one immutable GitHub-hosted commit with `kdiffguard review-github-commit --source OWNER/REPO@FULL_SHA --format json|text`,
- review a GitHub pull request read-only with `kdiffguard review-github-pr --source OWNER/REPO#NUMBER --format json|text`,
- review a local base-exclusive/target-inclusive range with `kdiffguard review-range --repo PATH --base X --target Y --format json|text`,
- review an explicit ordered commit list with `kdiffguard review-range --repo PATH --commit SHA --commit SHA --format json|text`,
- run golden analysis regression cases with `scripts/run-golden-analysis.sh`, and
- emit a deterministic review-signal scorecard with `kdiffguard scorecard --format json|text` or `scripts/run-scorecard.sh`.

Range JSON includes cumulative `range_signals`: stable author buckets, finding-id counts, top-level path-prefix counts, bounded same-commit co-changed path/prefix pairs, and touched-path summaries across the reviewed span. Co-change pairs are range-local evidence, not longitudinal baselines yet; they are capped and include omission counters under `co_change_limits` so hostile or mechanical fanout commits cannot produce unbounded output. This is intentionally first-class evidence for X→Y review rather than just a pile of individual commit reports.

Current findings are intentionally simple reviewer-assistance signals, not verdicts: removed tests, CI/static-analysis changes, warning-policy weakening, generated-code churn, suspicious script additions, Linux security cues, prompt-injection-like text, and high-risk kernel/build paths. Commit JSON also includes `optional_check_hooks` for environment-dependent compiler-warning and static-analyzer delta checks, plus `kernel_impacts`: path-heuristic hints for broad Linux areas such as Kconfig, drivers, architecture-specific code, syscall/ABI surfaces, filesystems, networking, scheduler, memory management, and security-sensitive paths. Range JSON aggregates these impact IDs under `range_signals.kernel_impacts` so an X→Y review can show which kernel areas changed across the span.

## Local verification

Run the same verification suite that GitHub Actions uses:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
PYTHON=.venv/bin/python scripts/check.sh
```

The script runs tests, golden review-packet regression cases, the review-signal
scorecard, ruff, mypy, and `git diff --check`. Keep `.github/workflows/ci.yml`
calling this script instead of duplicating individual verification commands.

OpenSSF-aligned work is treated as external evidence, not as a replacement for local source review. See `docs/expert-operating-questions.md` for the onboarding-stage catalog of security-review questions that should guide named expert checks without becoming a premature DSL. See `docs/expert-question-evidence-map.md` for how those questions map to current evidence, missing evidence, and coverage-gap results. See `docs/named-expert-checks.md` for the first inspectable named-check contracts that turn expert questions into reviewed code rather than a broad DSL. See `docs/operating-envelopes.md` for the allow-list/logical-policy direction, check-result shape, and exception model that should guide future review work. See `docs/external-evidence.md` for the snapshot-first integration model covering OpenSSF Scorecard, SLSA, Sigstore, OSV, OpenVEX, GUAC/Trustify, Security Insights, Criticality Score, and Package Analysis-style baselines. See `docs/official-interface-research.md` for current official Git, Python packaging/typing, public-inbox/lore, and Linux kernel process references that should guide parser and resolver interfaces. See `docs/normalized-evidence-schemas.md` for the first compatibility schema catalog covering commit artifacts, range manifests, mailing-list messages, related-message candidates, findings, recommendations, external evidence records, named expert checks, expert check results, exception records, evidence references, bounds, and trust-boundary labels. See `docs/architecture.md`, `docs/roadmap.md`, and `docs/testing-strategy.md` for the starting design and test/fixture strategy.
