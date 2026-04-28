# Roadmap

## Milestone 0: project skeleton

- Public GitHub repository.
- README with purpose and trust posture.
- Initial architecture and roadmap docs.
- Minimal tested Python package and CLI placeholder.

## Milestone 1: single-commit reviewer for local and GitHub-hosted commits

- Accept a local repo path plus commit SHA, and later GitHub commit URLs or owner/repo@sha inputs.
- Resolve every input to a specific commit and repository identity before analysis.
- Emit commit metadata, parent/tree IDs, touched paths, diff stats, renames, bounded diff excerpts, and trust-boundary labels as stable JSON.
- Run first deterministic review signals: removed tests, weakened CI/static analysis, suspicious executable/script additions, prompt-injection text, and high-risk paths.
- Include synthetic git fixtures and mocked GitHub fixtures; default CI must not require network access.
- Start golden analysis regression cases once the reviewer output for specific fixture commits becomes useful.

## Milestone 2: GitHub PR review input

- Accept GitHub PR URLs or owner/repo#number inputs in read-only mode.
- Resolve base/head SHAs and ordered commits, then compose the single-commit reviewer output.
- Emit a PR-level summary with changed-risk areas, easy-win findings, evidence references, and suggested next checks.
- Treat PR titles, bodies, comments, labels, branch names, patches, and GitHub API metadata as hostile input.
- Add PR-shaped golden cases so CI catches changes in summarized findings and evidence references.

## Milestone 2.5: golden analysis regression in CI

- Maintain a versioned manifest of selected commits/PRs, expected normalized analysis results, and allowed volatile fields.
- Run the reviewer against those cases in GitHub Actions after unit/lint/type checks.
- Fail with a human-readable diff when stable findings change.
- Treat changed output as either a regression to fix or an intentional analysis improvement that requires updating the golden result with rationale.

## Milestone 2.7: external evidence snapshot model

- Define a local snapshot schema for OpenSSF-aligned external evidence before live integrations become sticky.
- Treat OpenSSF Scorecard, SLSA, Sigstore, OSV, OpenVEX, GUAC/Trustify, Security Insights, Criticality Score, and Package Analysis-style baselines as evidence providers, not verdict engines.
- Keep `review-commit` and `review-range` offline by default; live provider collection belongs in explicit collector commands or external tooling.
- Add synthetic golden fixtures proving external claims can be loaded, bounded, cited, and rendered deterministically.

## Milestone 3: Linux-kernel impact hints

- Map touched paths to kernel subsystems and maintainers where practical.
- Identify Kconfig, driver, arch, syscall, filesystem, networking, scheduler, memory-management, and security-sensitive surfaces.
- Generate initial retest hints.

## Milestone 4: discussion correlation

- Link commits/patch IDs/subjects to lore.kernel.org or other mailing-list archives.
- Track patch series revisions and review tags.
- Extract objections, acks, tested-by tags, and unresolved questions as evidence.

## Milestone 5: malicious-change and integrity heuristics

- Provenance anomaly checks: author/committer changes, signing gaps, suspicious timestamps, unusual review paths.
- Multi-commit behavior checks: suspicious split changes, setup/use separation, semantic drift across refactors.
- Tree/artifact checks: object reachability, clean checkout verification, generated artifact comparison, reproducibility hooks.

## Milestone 6: review packets

- Combine facts, context, risk hints, retest guidance, and uncertainty into a compact artifact suitable for release review.
