# Roadmap

## Milestone 0: project skeleton

- Public GitHub repository.
- README with purpose and trust posture.
- Initial architecture and roadmap docs.
- Minimal tested Python package and CLI placeholder.

## Milestone 0.5: official interface research

- Capture current official Git, Python packaging/typing, public-inbox/lore, and Linux kernel process references before parser and resolver interfaces harden.
- Prefer Git plumbing commands, explicit separators, immutable revisions, and bounded local snapshots over human output or hidden live network access.
- Keep version-sensitive behavior visible for Git, Python, lore/public-inbox, and kernel process assumptions.

## Milestone 1: deterministic evidence reducer for local and GitHub-hosted commits

- Define normalized evidence schemas and trust-boundary labels for commit artifacts, commit ranges, mailing-list messages, related-message candidates, findings, recommendations, and external evidence records.
- Accept a local repo path plus commit SHA, and later GitHub commit URLs or owner/repo@sha inputs.
- Resolve every input to a specific commit and repository identity before analysis.
- Emit commit metadata, parent/tree IDs, touched paths, diff stats, renames, bounded diff excerpts, and trust-boundary labels as stable JSON.
- Run first deterministic review signals: removed tests, weakened CI/static analysis, suspicious executable/script additions, prompt-injection text, and high-risk paths.
- Treat these signals as evidence for future policy checks, not as probabilistic maliciousness scores.
- Include synthetic git fixtures and mocked GitHub fixtures; default CI must not require network access.
- Start golden analysis regression cases once the reducer output for specific fixture commits becomes useful.

## Milestone 2: GitHub PR evidence input

- Accept GitHub PR URLs or owner/repo#number inputs in read-only mode.
- Resolve base/head SHAs and ordered commits, then compose the single-commit reviewer output.
- Emit a PR-level summary with changed-risk areas, easy-win findings, evidence references, and suggested next checks.
- Treat PR titles, bodies, comments, labels, branch names, patches, and GitHub API metadata as hostile input.
- Add PR-shaped golden cases so CI catches changes in summarized findings and evidence references.

## Milestone 2.3: operating-envelope policy model

- Define explicit allow-list-style policy artifacts for repository, subsystem, process, patch-shape, release, and target-profile envelopes.
- Define policy check result artifacts with statuses such as satisfied, violated, missing evidence, not applicable, and inconclusive.
- Make policies inspectable and versioned; every violation must cite evidence and a required next action.
- Treat historical baselines as candidate-policy material only. They may suggest envelopes, but they must not silently produce anomaly scores or implied suspicion.
- Implement first synthetic policies for removed tests, CI/static-analysis weakening, high-authority executable additions, generated/source correspondence, and simple kernel retest obligations.

## Milestone 2.5: golden analysis regression in CI

- Maintain a versioned manifest of selected commits/PRs, expected normalized analysis results, policy check results, and allowed volatile fields.
- Run the reviewer against those cases in GitHub Actions after unit/lint/type checks.
- Fail with a human-readable diff when stable findings or policy results change.
- Treat changed output as either a regression to fix or an intentional analysis improvement that requires updating the golden result with rationale.

## Milestone 2.7: external evidence snapshot model

- Define a local snapshot schema for OpenSSF-aligned external evidence before live integrations become sticky.
- Treat OpenSSF Scorecard, SLSA, Sigstore, OSV, OpenVEX, GUAC/Trustify, Security Insights, Criticality Score, and Package Analysis-style baselines as evidence providers, not verdict engines.
- Keep `review-commit` and `review-range` offline by default; live provider collection belongs in explicit collector commands or external tooling.
- Add synthetic golden fixtures proving external claims can be loaded, bounded, cited, and rendered deterministically.
- Allow external evidence to satisfy or fail policy evidence requirements only through explicit policy rules.

## Milestone 3: Linux-kernel impact and retest envelopes

- Map touched paths to kernel subsystems and maintainers where practical.
- Identify Kconfig, driver, arch, syscall, filesystem, networking, scheduler, memory-management, and security-sensitive surfaces.
- Generate retest obligations as policy results, not only informal hints.
- Keep kernel-specific envelopes isolated from the reusable git-repo core.

## Milestone 4: discussion correlation as process evidence

- Link commits/patch IDs/subjects to lore.kernel.org or other mailing-list archives.
- Track patch series revisions and review tags.
- Extract objections, acks, tested-by tags, and unresolved questions as evidence.
- Use discussion artifacts to satisfy or fail explicit process-envelope requirements; do not treat discussion metadata as a trust oracle.

## Milestone 5: malicious-change and integrity envelope checks

- Provenance and process rules: author/committer changes, signing gaps, timestamp constraints, unusual review paths, and required maintainer/test evidence.
- Multi-commit behavior rules: suspicious split changes, setup/use separation, semantic drift across refactors, and cross-subsystem coupling that require explicit rationale.
- Tree/artifact rules: object reachability, clean checkout verification, generated artifact comparison, reproducibility hooks, release tags, and binary/source correspondence.
- Historical author/work-area/co-change baselines may propose rules, but accepted rules must be explicit and logical before producing violations.

## Milestone 6: review packets

- Combine facts, context, risk hints, policy check results, retest obligations, missing evidence, exceptions, and uncertainty into a compact artifact suitable for release review.
- Every recommendation must trace to evidence and, when applicable, to a policy ID.
- Review packets support human decisions; they must not imply automatic trust decisions or hidden probability scores.
