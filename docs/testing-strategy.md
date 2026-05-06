# Testing strategy

kernel-diffguard should test for reviewer value, not just line coverage. The suite should prove that hostile git, GitHub, and mailing-list inputs are reduced into bounded, evidence-linked reviewer artifacts and, as the project matures, checked against explicit operating-envelope policies without pretending to prove that a change is safe or malicious.

The default path is deterministic and local-first: fast unit tests, synthetic integration tests, golden review-packet fixtures, and optional public-data smoke tests that never block ordinary pull-request CI. In this document, default CI means the normal pull-request and push gate.

## Default CI gates

Default GitHub Actions CI should remain deterministic, cheap, and safe for pull requests. The required gate is:

```bash
scripts/check.sh
```

That script is the single source of truth for both local verification and GitHub Actions. It currently runs:

1. `python -m pytest -q`
2. `scripts/run-golden-analysis.sh`
3. `scripts/run-scorecard.sh`
4. `python -m ruff check .`
5. `python -m mypy src`
6. `git diff --check`

Default CI must use no network, no real Linux kernel checkout, no live GitHub API calls, and no lore.kernel.org requests. Network-backed smoke checks belong in separate manual or scheduled workflows.

### GitHub Actions pin refresh procedure

Workflow action refs are supply-chain inputs. Trusted workflows pin official actions to full commit SHAs while keeping a nearby comment with the upstream tag intent. Refresh those pins deliberately instead of returning to floating tags:

1. Before changing a pin, review upstream release notes and changelogs for the intended tag.
2. Resolve the intended upstream tag to a full commit SHA:
   - `git ls-remote https://github.com/actions/checkout.git refs/tags/v6`
   - `git ls-remote https://github.com/actions/setup-python.git refs/tags/v6`
3. Replace only the SHA portion of the corresponding `uses:` line in `.github/workflows/ci.yml`; keep the `upstream tag intent: v6` comment accurate if the intended major tag changes.
4. Validate that every `uses:` ref in trusted workflows is still a 40-character lowercase hex SHA, then run the CI-equivalent gate: `scripts/check.sh`.
5. If `actionlint` is available locally, run it before committing the workflow change.

## Source-review fixture pyramid

The fixture pyramid is ordered from cheapest and most stable to broadest and most environment-sensitive:

1. Unit tests over small pure functions and schema-like shape contracts.
2. Synthetic git integration tests that create tiny local repositories during the test run.
3. Local bare-remotes and checked-in JSON/RFC822 fixtures for remote-shaped behavior.
4. Golden review-packet fixtures that run the CLI against pinned synthetic scenarios and compare normalized JSON.
5. Optional public-data smoke tests against public repositories or archives.

Each layer should add confidence that a reviewer-facing signal survives real orchestration. Higher layers should not duplicate every unit edge case.

## Unit test coverage matrix

Unit tests should cover these source-review components as they appear:

| Area | What to test | Fixture shape |
| --- | --- | --- |
| Schema and artifact shape | required keys, evidence references, uncertainty fields, truncation metadata, trust-boundary labels | small literal dictionaries and JSON snapshots |
| Git commit parsing | multiline subjects/bodies, unusual authors, weird paths, renames, empty commits, bounded diff excerpts | synthetic local commits |
| Commit-range parsing | deterministic order, empty ranges, merge handling, explicit commit lists, invalid revisions | synthetic local histories |
| GitHub input parsing | commit URLs, owner/repo@sha, PR URLs, owner/repo#number, malformed and mutable refs | pure parser tests plus checked-in API fixtures |
| Email parsing | RFC822 headers, multipart bodies, patch presence, huge bodies, malformed headers | local `.eml`/mbox fixtures |
| Prompt-injection hints | hostile instructions in commit messages, diffs, path names, PR text, and email bodies | bounded text literals and fixture commits |
| Static review rules | removed tests, CI/static-analysis weakening, suspicious executable additions, warning-policy changes, high-risk kernel paths, oversized diffs | fixture commits with positive and non-triggering variants |
| Expert operating questions | question IDs, classifications, downstream bead links, non-goals, and no-DSL/no-anomaly guardrails | documentation guard tests and future schema fixtures |
| Operating-envelope policies | policy applicability, satisfied/violated/missing-evidence/not-applicable/inconclusive statuses, exception handling, evidence refs | small policy files plus synthetic commits/ranges/PRs |
| Kernel impact hints | Kconfig, drivers, arch, syscall/ABI, filesystem, networking, scheduler, memory-management, security-sensitive surfaces | path lists plus synthetic commits |
| Review packet rendering | JSON/text stability, deterministic sorting, evidence links, retest hints | CLI output fixtures |

Unit tests should prefer real code over mocks. Use mocks only around unavoidable transport boundaries.

## Integration fixture rules

Synthetic integration tests should create local repositories in temporary directories and commit tiny files that demonstrate one behavior at a time. They should:

- configure local git identity explicitly inside the fixture repository;
- never execute repo-provided hooks, generated scripts, or build commands;
- avoid depending on wall-clock timestamps except where the timestamp behavior is under test;
- use local bare remotes when remote-like fetch/resolve behavior is needed;
- use checked-in GitHub API, PR, RFC822, and mbox fixtures instead of live network calls;
- include negative fixtures for noisy rules, not just positive suspicious cases;
- keep all untrusted path names, commit messages, diffs, PR text, and email text bounded before assertions.

Default CI should be able to run these tests offline from a clean checkout.

## Golden review-packet fixtures

A golden case captures a specific analysis result that has become valuable enough to preserve. It should include:

- a stable input identity:
  - synthetic fixture name, or
  - GitHub owner/repo plus immutable commit SHA, or
  - GitHub owner/repo PR number plus pinned base/head SHAs;
- command used to generate the result;
- expected normalized JSON output;
- expected policy check results once an operating-envelope policy applies;
- allowed volatile fields to ignore or normalize;
- rationale explaining why the expected result is useful.

Golden fixtures should cover easy-win reviewer signals, including:

- removed tests;
- CI/static-analysis weakening;
- suspicious executable additions;
- prompt-injection text;
- high-risk kernel paths;
- oversized diffs;
- Linux kernel impact hints and retest guidance;
- range-local author, path-prefix, and co-change summaries;
- first operating-envelope checks, especially removed-test, CI/static-analysis gate, high-authority executable, generated/source correspondence, and simple kernel retest-obligation policies.

The comparison should be strict for reviewer-facing facts and findings, but tolerant of deliberately volatile metadata such as runtime duration, cache path, tool version banner, and fetch timestamp.

Policy-result comparison should be stricter than heuristic-signal comparison: policy ID, applicability, status, evidence references, missing evidence, and required next action are reviewer-facing contract output. If a policy changes, update the golden result with an explicit rationale rather than letting output drift silently.

When a golden output changes, CI should make the change easy to review. The diff should separate:

- stable input/provenance changes;
- added findings;
- removed findings;
- changed severity/uncertainty;
- changed evidence references;
- changed policy results and missing-evidence obligations;
- allowed metadata drift.

A changed golden result is not automatically bad. It means one of two things happened:

1. Regression: the tool lost or corrupted a useful signal. Fix the code.
2. Intended improvement: the analysis became better or the output contract changed intentionally. Update the expected result and include the rationale in the commit or PR.

## Optional public-data smoke tests

Live public data is useful, but should not make normal PR CI flaky, slow, or network-dependent. Use this promotion path:

1. Synthetic fixture commits checked into the test suite.
2. Local bare remotes that mimic GitHub-hosted commit and PR resolution behavior.
3. Mocked GitHub API response fixtures for PR metadata.
4. Optional scheduled/manual workflow for real public GitHub commits or PRs.
5. Optional scheduled/manual workflow for lore.kernel.org or public-inbox behavior.

The first public kernel exemplar should be the Raspberry Pi kernel, tracked separately from generic git and upstream-Linux assumptions. Smoke tests may validate clone/fetch assumptions, branch naming, representative kernel path mappings, and public archive availability, but they must not be the only test for core analysis behavior.

## Per-iteration value checks

Each implementation iteration should improve at least one observable dimension unless it is pure maintenance:

- supported input shapes;
- parser capability;
- deterministic heuristic findings;
- explicit operating-envelope policy coverage;
- policy check result evidence traceability;
- prompt-injection/hostile-input coverage;
- golden case count;
- evidence traceability;
- retest guidance quality;
- end-to-end reviewer examples.

The future review-signal scorecard should report these counts deterministically in CI. Until then, commits and Beads notes should say which observable reviewer signal, parser capability, or evidence traceability improvement was added.

The initial scorecard is available with `kdiffguard scorecard --format json|text` and is run in CI by `scripts/run-scorecard.sh`. Metrics are steering signals, not product success claims.

This prevents infrastructure-only drift and keeps the project focused on sharper human review rather than coverage theater.
