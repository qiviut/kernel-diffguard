# Architecture sketch

## Goal / problem framing

kernel-diffguard should answer two linked questions:

- supply-chain question: did a suspicious or malicious change enter a git history or generated artifact?
- impact question: what does moving a deployed system from commit X to commit Y require us to re-test and understand?

The Linux kernel is the first exemplar because it has scale, subsystem structure, public review trails, and real operational consequences. The project should not try to infer maliciousness from statistical abnormality alone. Its stronger architecture is deterministic evidence reduction followed by explicit operating-envelope checks: declared repository, subsystem, process, patch-shape, release, and target-profile rules that define what is permitted, what evidence is required, and how exceptions are reviewed.

## Proposed architecture

1. Repository evidence collector
   - Reads git objects, refs, commits, tags, notes, diffs, signatures, and path-level history.
   - Never treats repository data as trusted just because `git` can parse it.
2. GitHub input resolver
   - Accepts github.com commit and PR URLs, plus compact owner/repo@sha and owner/repo#number references.
   - Resolves remote inputs to immutable SHAs, repository identity, ordered commits, and provenance metadata before analysis.
   - Starts read-only; posting PR comments or acting as a bot is a later explicit integration.
3. Single-commit reviewer
   - Normalizes one commit into bounded evidence, runs first deterministic checks, and emits JSON/text findings.
   - Serves as the product-shaped core that local, GitHub commit, range, and PR modes compose.
4. Range impact analyzer
   - Turns X..Y into changed files, symbols when available, configs, subsystems, and likely runtime surfaces.
   - Produces retest recommendations tied to evidence.
5. Operating-envelope policy engine
   - Applies explicit allow-list-style policies over normalized evidence.
   - Emits check results such as satisfied, violated, missing evidence, not applicable, and inconclusive.
   - Treats historical baselines as candidate-policy input, never as a hidden anomaly detector or trust oracle.
6. Provenance and integrity analyzer
   - Checks authorship, review, signing, timestamp, ref, tree, submodule, generated-artifact, and release-path facts against declared envelope rules.
   - Separates ordinary policy violations from out-of-band tree or binary injection checks.
7. Patch complexity and obviousness analyzer
   - Explains patch-shape facts that can satisfy or violate policies, such as setup/use splits, generated/source coupling, high-risk semantic changes, or changes too complex for casual review.
   - Must explain features and policy consequences, not emit opaque scores alone.
8. Discussion/context correlator
   - Searches mailing-list archives and public review systems for patch discussion, vN series history, review tags, objections, and maintainer context.
   - Supplies hostile external evidence that may satisfy process-envelope requirements, such as review tags or unresolved-objection evidence.
9. External evidence snapshot ingester
   - Consumes local, bounded snapshots from OpenSSF-adjacent providers such as Scorecard, SLSA, Sigstore, OSV, OpenVEX, GUAC/Trustify, Security Insights, Criticality Score, and Package Analysis-style baselines.
   - Keeps review commands offline by default and treats provider output as evidence, not verdicts.
10. Normalized evidence schema catalog
   - Defines the first compatibility shapes for commit artifacts, commit-range manifests, mailing-list message artifacts, related-message candidates, policy artifacts, policy check results, findings, recommendations, and external evidence records.
   - Requires evidence references, trust-boundary labels, limits, and risk hints so schema boundaries stay visible as parser and resolver implementation hardens.
11. Review packet generator
   - Emits a concise packet containing facts, policy check results, links, uncertainties, retest guidance, missing evidence, external evidence references, and suggested next checks.

## Boundaries and trust zones

- Hostile input: git repository contents, commit metadata, emails, web pages, patches, logs, binaries, generated files.
- Hostile remote input: GitHub PR titles, descriptions, comments, labels, branch names, user/profile fields, API metadata, rendered HTML, and downloadable patches.
- Hostile external evidence: OpenSSF/provider snapshots, SBOM/advisory/provenance/signature metadata, provider scores, graph records, and vulnerability/exploitability statements.
- Deterministic low-privilege zone: parsers, reducers, hashing, object inspection, snapshot loading, and schema normalization.
- Operating-envelope zone: explicit policies and logical checks over reduced evidence. This zone can conclude that a rule is satisfied, violated, missing evidence, not applicable, or inconclusive; it should not silently infer probabilistic maliciousness from statistical abnormality.
- Heuristic/model-assisted zone: summarization, candidate-policy explanation, and semantic patch review. This zone receives reduced evidence and policy results, not raw unbounded hostile input by default.
- Human decision zone: final trust and release decisions remain explicit human/organization policy decisions.

## Key flows

### GitHub-hosted commit review

1. User supplies a github.com commit URL or owner/repo@sha input.
2. GitHub resolver validates the host and resolves the input to a repository identity plus immutable commit SHA.
3. Collector fetches or reuses a controlled local clone/cache without executing repository hooks or scripts.
4. Single-commit reviewer emits deterministic facts, risk hints, evidence references, and suggested next checks.
5. Operating-envelope checks turn relevant facts into policy results when a policy exists.

### GitHub PR review

1. User supplies a github.com PR URL or owner/repo#number input.
2. GitHub resolver records PR metadata as hostile evidence and resolves base/head SHAs plus ordered commits.
3. Reviewer runs the single-commit reviewer over each commit or an explicit range artifact.
4. Policy engine checks PR/range evidence against repository, process, patch-shape, and subsystem envelopes.
5. Review packet generator emits a read-only PR summary; posting comments is a later explicit integration.

### Commit range analysis

1. User supplies repo path plus X and Y.
2. Collector validates object reachability and extracts X..Y evidence.
3. Impact analyzer maps paths and diff features to subsystem and retest hints.
4. Operating-envelope checks identify satisfied rules, violations, missing evidence, and required exceptions.
5. Complexity analyzer explains review difficulty in terms of evidence and policy consequences.
6. Context correlator searches for public discussion that may satisfy or fail process-envelope requirements.
7. Optional external evidence snapshots add project posture, provenance, advisory, exploitability, graph, or criticality context without live network access.
8. Review packet generator emits the result.

### Tree/binary injection analysis

1. Collector records object IDs, tags, signatures, refs, and expected source tree state.
2. Integrity analyzer compares checked-out source, git object database, generated artifacts, and binaries where available.
3. Policy engine checks release/source/artifact correspondence envelopes.
4. Review packet reports mismatches, missing reproducibility evidence, and required rebuild checks.

## Evidence plan

Early evidence should include:

- official interface references for Git plumbing/formats, Python packaging/typing, public-inbox/lore, and Linux kernel process docs,
- reproducible tests for git and GitHub input parsing,
- golden fixtures for tricky histories,
- explicit hostile-input fixtures,
- golden analysis regression cases that compare normalized reviewer output for selected commits/PRs,
- documented operating-envelope fixtures for first logical policies,
- documented impact and complexity facts that can feed policy checks,
- traceable links from recommendations back to facts.

## Major risks / tradeoffs

- False confidence is worse than an incomplete tool; outputs must show uncertainty.
- Anomaly-detection drift is a core risk; history may suggest policies, but accepted policies must be explicit, inspectable, and versioned before they produce violations.
- Mailing-list correlation is valuable but messy: patches are revised, split, renamed, and quoted.
- Kernel-specific heuristics should be isolated so the general git-repo core remains reusable.
- Model-assisted analysis must not directly consume unbounded hostile input with secrets or high authority.
