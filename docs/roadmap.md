# Roadmap

## Milestone 0: project skeleton

- Public GitHub repository.
- README with purpose and trust posture.
- Initial architecture and roadmap docs.
- Minimal tested Python package and CLI placeholder.

## Milestone 1: deterministic git range facts

- Accept local repo path, base commit X, target commit Y.
- Emit commits, authors, dates, touched paths, diff stats, renames, signatures/tags when present.
- Store output as stable JSON for downstream tooling.
- Include fixtures for small synthetic histories.

## Milestone 2: Linux-kernel impact hints

- Map touched paths to kernel subsystems and maintainers where practical.
- Identify Kconfig, driver, arch, syscall, filesystem, networking, scheduler, memory-management, and security-sensitive surfaces.
- Generate initial retest hints.

## Milestone 3: discussion correlation

- Link commits/patch IDs/subjects to lore.kernel.org or other mailing-list archives.
- Track patch series revisions and review tags.
- Extract objections, acks, tested-by tags, and unresolved questions as evidence.

## Milestone 4: malicious-change and integrity heuristics

- Provenance anomaly checks: author/committer changes, signing gaps, suspicious timestamps, unusual review paths.
- Multi-commit behavior checks: suspicious split changes, setup/use separation, semantic drift across refactors.
- Tree/artifact checks: object reachability, clean checkout verification, generated artifact comparison, reproducibility hooks.

## Milestone 5: review packets

- Combine facts, context, risk hints, retest guidance, and uncertainty into a compact artifact suitable for release review.
