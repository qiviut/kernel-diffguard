# Testing strategy

kernel-diffguard should test for reviewer value, not just line coverage. The test suite is expected to grow as a fixture pyramid: fast unit tests, synthetic integration tests, golden analysis regression cases, and optional public-data smoke tests.

## Default CI gates

Default GitHub Actions CI should remain deterministic, cheap, and safe for pull requests:

1. Unit tests
   - schema validation
   - git commit parsing
   - GitHub input parsing
   - prompt-injection hints
   - static review rules
   - JSON/text rendering

2. Synthetic integration tests
   - create tiny git repositories during tests
   - create local bare remotes when remote-like behavior is needed
   - use checked-in API/PR/email fixtures instead of live network calls
   - never require a Linux kernel checkout in normal PR CI

3. Golden analysis regression tests
   - run the CLI against pinned fixture commits or PR-like fixtures
   - normalize output before comparison
   - compare against checked-in expected results
   - fail with a useful diff when findings change

## Golden analysis regression cases

A golden case captures a specific analysis result that has become valuable enough to preserve. It should include:

- stable input identity:
  - synthetic fixture name, or
  - GitHub owner/repo plus immutable commit SHA, or
  - GitHub owner/repo PR number plus pinned base/head SHAs
- command used to generate the result
- expected normalized JSON output
- allowed volatile fields to ignore or normalize
- rationale explaining why the expected result is useful

The comparison should be strict for reviewer-facing facts and findings, but tolerant of deliberately volatile metadata such as runtime duration, cache path, tool version banner, and fetch timestamp.

When a golden output changes, CI should make the change easy to review. The diff should separate:

- stable input/provenance changes
- added findings
- removed findings
- changed severity/uncertainty
- changed evidence references
- allowed metadata drift

A changed golden result is not automatically bad. It means one of two things happened:

1. Regression: the tool lost or corrupted a useful signal. Fix the code.
2. Intended improvement: the analysis became better or the output contract changed intentionally. Update the expected result and include the rationale in the commit or PR.

## Public GitHub cases

Live public GitHub cases are useful, but should not make normal PR CI flaky or expensive. Prefer this order:

1. Synthetic fixture commits checked into the test suite.
2. Local bare remotes that mimic GitHub-hosted commit and PR resolution behavior.
3. Mocked GitHub API response fixtures for PR metadata.
4. Optional scheduled/manual workflow for real public GitHub commits or PRs.

The optional public-data workflow can validate that resolver assumptions still match github.com behavior, but it should not be the only place core analysis behavior is tested.

## Value scorecard

Each implementation iteration should improve at least one observable dimension unless it is pure maintenance:

- supported input shapes
- parser capabilities
- deterministic heuristic findings
- prompt-injection/hostile-input coverage
- golden case count
- evidence-reference quality
- end-to-end reviewer examples

This prevents infrastructure-only drift and makes review improvements visible over time.
