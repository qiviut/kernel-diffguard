# Architecture sketch

## Goal / problem framing

kernel-diffguard should answer two linked questions:

- supply-chain question: did a suspicious or malicious change enter a git history or generated artifact?
- impact question: what does moving a deployed system from commit X to commit Y require us to re-test and understand?

The Linux kernel is the first exemplar because it has scale, subsystem structure, public review trails, and real operational consequences.

## Proposed architecture

1. Repository evidence collector
   - Reads git objects, refs, commits, tags, notes, diffs, signatures, and path-level history.
   - Never treats repository data as trusted just because `git` can parse it.
2. Range impact analyzer
   - Turns X..Y into changed files, symbols when available, configs, subsystems, and likely runtime surfaces.
   - Produces retest recommendations tied to evidence.
3. Provenance and integrity analyzer
   - Looks for authorship, review, signing, timestamp, ref, tree, submodule, and generated-artifact anomalies.
   - Separates ordinary suspicious commits from out-of-band tree or binary injection checks.
4. Patch complexity and obviousness scorer
   - Flags small mechanical changes, high-risk semantic changes, and changes too complex for casual review.
   - Must explain features, not emit opaque scores alone.
5. Discussion/context correlator
   - Searches mailing-list archives and public review systems for patch discussion, vN series history, review tags, objections, and maintainer context.
6. Review packet generator
   - Emits a concise packet containing facts, links, uncertainties, retest guidance, and suggested next checks.

## Boundaries and trust zones

- Hostile input: git repository contents, commit metadata, emails, web pages, patches, logs, binaries, generated files.
- Deterministic low-privilege zone: parsers, reducers, hashing, object inspection, and schema normalization.
- Heuristic/model-assisted zone: summarization, anomaly explanation, semantic patch review. This zone receives reduced evidence, not raw unbounded hostile input by default.
- Human decision zone: final trust and release decisions remain explicit human/organization policy decisions.

## Key flows

### Commit range analysis

1. User supplies repo path plus X and Y.
2. Collector validates object reachability and extracts X..Y evidence.
3. Impact analyzer maps paths and diff features to subsystem and retest hints.
4. Complexity analyzer classifies review difficulty.
5. Context correlator searches for public discussion.
6. Review packet generator emits the result.

### Tree/binary injection analysis

1. Collector records object IDs, tags, signatures, refs, and expected source tree state.
2. Integrity analyzer compares checked-out source, git object database, generated artifacts, and binaries where available.
3. Review packet reports mismatches, missing reproducibility evidence, and required rebuild checks.

## Evidence plan

Early evidence should include:

- reproducible tests for git range parsing,
- golden fixtures for tricky histories,
- explicit hostile-input fixtures,
- documented heuristics for impact and complexity,
- traceable links from recommendations back to facts.

## Major risks / tradeoffs

- False confidence is worse than an incomplete tool; outputs must show uncertainty.
- Mailing-list correlation is valuable but messy: patches are revised, split, renamed, and quoted.
- Kernel-specific heuristics should be isolated so the general git-repo core remains reusable.
- Model-assisted analysis must not directly consume unbounded hostile input with secrets or high authority.
