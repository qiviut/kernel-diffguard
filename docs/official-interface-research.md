# Official interface research

## Goal / problem framing

kernel-diffguard is starting to harden parsers, schemas, command-line behavior, and future remote/archive resolvers. This document records the official references and interface decisions that should guide those choices before they become sticky.

Research date: 2026-04-28.
Observed local tool versions for validation:

- Git 2.51.0
- Python 3.13.7

The design posture remains unchanged: repository contents, metadata, remote archive data, emails, paths, diffs, and external provider records are hostile input. Review commands should stay offline by default. Network collection belongs in explicit resolver/collector commands or separate fixtures, not hidden inside deterministic review commands.

## Official references

### Git plumbing and formats

Primary reference root: https://git-scm.com/docs

Interfaces to prefer:

- `git rev-parse`: https://git-scm.com/docs/git-rev-parse
  - Use for resolving and verifying user-supplied revisions before analysis.
  - Prefer `--verify` and type peeling such as `^{commit}` when a commit object is required.
  - Use `--end-of-options` when placing untrusted revision-like strings after options.
- `git rev-list`: https://git-scm.com/docs/git-rev-list
  - Use for deterministic commit set expansion from X..Y or explicit ranges.
  - Commit limiting happens before ordering/formatting; tests must lock traversal behavior rather than assuming option order is harmless.
- `git log`: https://git-scm.com/docs/git-log
  - Use only when log formatting is needed and when separators are explicit.
  - Do not parse human pretty output without hard separators.
- `git diff-tree`: https://git-scm.com/docs/git-diff-tree
  - Use for machine-oriented per-commit diff metadata.
  - Prefer raw/name-status/numstat modes with NUL termination where possible.
- `git cat-file`: https://git-scm.com/docs/git-cat-file
  - Use `--batch` or `--batch-check` for object type/size/content inspection and bounded object verification.
- `git show`: https://git-scm.com/docs/git-show
  - Useful for display and targeted object inspection, but not the preferred parser backbone when plumbing commands can provide narrower output.

Interface decision:

Use Git plumbing commands and explicit separators for normalized facts. Do not shell-interpolate untrusted refs, paths, or commit metadata. Do not run repository hooks or project scripts. Treat Git as a parser for hostile objects, not a trust oracle.

### Python packaging and typing

Primary references:

- Python Packaging User Guide: https://packaging.python.org/en/latest/
- `pyproject.toml` specification: https://packaging.python.org/en/latest/specifications/pyproject-toml/
- Python typing module docs: https://docs.python.org/3/library/typing.html
- Python typing specification: https://typing.python.org/en/latest/spec/

Relevant packaging choices:

- Keep project build metadata in `pyproject.toml`.
- Use `[build-system]` to declare build-time dependencies and backend.
- Use `[project]` for project metadata when it becomes useful to publish or package more formally.
- Keep development tool configuration centralized in `pyproject.toml` unless a tool has a strong reason for a separate file.

Relevant typing choices:

- Use standard-library typing first on Python 3.13.7.
- Prefer simple typed dictionaries or dataclasses for stable JSON-shaped records until a schema validator is justified.
- Use the typing specification at typing.python.org for semantics when tool behavior differs from docs or type-checker assumptions.
- Avoid runtime dependence on type-checker-only behavior. Types document and verify interfaces; they are not hostile-input validation.

Interface decision:

Keep the package ordinary and current: `pyproject.toml`, pytest, ruff, mypy, and small typed Python modules. Do not add a heavy schema/codegen framework until normalized evidence schemas need machine-readable external publication.

### public-inbox and lore.kernel.org

Primary references:

- public-inbox README: https://public-inbox.org/README.html
- lore.kernel.org LKML public-inbox help: https://lore.kernel.org/lkml/_/text/help/

Relevant facts from the official surfaces:

- public-inbox is an "archives first" approach to mailing lists.
- It exposes archives through git-backed storage and reader interfaces such as HTML, Atom, NNTP, IMAP, and POP3 depending on deployment.
- lore.kernel.org exposes thread mbox downloads such as `/t.mbox.gz` for a message thread.
- lore pages and mbox content are remote hostile input and must be normalized before any model-assisted analysis.

Interface decision:

The first mailing-list integration should support local fixture mbox data and explicit fetched snapshots. Default CI must not require live lore.kernel.org. Future collectors may fetch thread mboxes or public-inbox git data, but they should write bounded local artifacts that the reviewer consumes offline.

### Linux kernel process docs

Primary reference root: https://docs.kernel.org/process/index.html

Relevant pages:

- Submitting patches: https://docs.kernel.org/process/submitting-patches.html
- Maintainer PGP guide: https://docs.kernel.org/process/maintainer-pgp-guide.html
- Stable kernel rules: https://docs.kernel.org/process/stable-kernel-rules.html
- Email clients: https://docs.kernel.org/process/email-clients.html

Review-context signals to preserve:

- `Signed-off-by` lines and Developer Certificate of Origin flow.
- `Fixes:` tags and stable-backport cues.
- `Reported-by`, `Tested-by`, `Reviewed-by`, `Acked-by`, `Link:`, and related trailer evidence.
- Plain-text patch expectations and the risk that email clients mutate whitespace or patch text.
- PGP signatures, signed tags, and maintainer identity guidance as provenance context.

Interface decision:

Kernel process fields are evidence, not proof. The reviewer should preserve trailers and mailing-list context as bounded facts. A missing tag may be important for some workflows, but it is not automatically suspicious without subsystem and process context.

## Interface decisions

1. Local review remains the core.
   - `review-commit` and `review-range` continue to accept local repositories and immutable commit identifiers first.
   - Remote inputs and archive lookups should resolve into local snapshots before review.

2. Git command output must be machine-oriented.
   - Prefer `git rev-parse`, `git rev-list`, `git diff-tree`, and `git cat-file` over human display commands.
   - Use NUL termination and explicit separators where available.
   - Verify object type before interpreting an object as a commit, tree, blob, or tag.

3. Revision resolution must fail closed.
   - Ambiguous, unreachable, missing, or wrong-type revisions should produce structured errors.
   - Do not silently widen a range or substitute a branch head for an immutable commit.

4. Archive and provider data are snapshots.
   - lore/public-inbox, GitHub, OpenSSF, advisory, SBOM, and provenance inputs should be collected explicitly.
   - Review output should record collection source, time, digest, truncation, and evidence references.

5. Kernel process metadata is reviewer context.
   - Preserve trailers, signatures, thread links, review tags, and stable cues.
   - Avoid verdict language; emit reviewer-assistance signals and suggested next checks.

6. Python interfaces should remain simple.
   - Use typed functions, dataclasses or dictionaries, and direct tests.
   - Defer external schema frameworks until stable artifact exchange requires them.

## Version-sensitive behavior

### Git

Observed local version: Git 2.51.0.

Version-sensitive areas:

- Hash algorithm support: SHA-1 remains common, but Git supports repositories using different object formats. Code should not assume all object IDs are exactly 40 hexadecimal characters forever.
- Pretty formats and human display output can change. Prefer plumbing output and tests using synthetic repositories.
- Revision parsing is subtle. Always separate options from revisions and paths, and verify object type.
- Diff rename/copy detection and hunk heuristics can vary with options. Golden tests should pin the exact command options used for normalized facts.
- Commit traversal order depends on options. Range tests should explicitly cover linear history, merges, empty ranges, and explicit commit lists.

Minimum recommendation:

Use the Git version available in CI as the practical minimum for now, but write parsers to depend on documented stable plumbing behavior rather than local incidental formatting.

### Python

Observed local version: Python 3.13.7.

Version-sensitive areas:

- Standard-library typing evolves. Keep annotations compatible with the configured package requirement and mypy settings.
- TOML parsing support exists in the standard library through `tomllib` for modern Python, but writing TOML still requires another path if needed later.
- Packaging metadata behavior is specified by the PyPA specs, not just one build backend's behavior.

Minimum recommendation:

Keep the supported Python floor explicit in `pyproject.toml` and CI. If the floor is lowered later, check typing syntax, `tomllib`, pathlib behavior, and dataclass/typing features before claiming support.

### public-inbox and lore

Version-sensitive areas:

- lore.kernel.org URL surfaces and public-inbox rendering are external services. Treat fetched pages, Atom feeds, and mbox files as snapshots.
- Mailing-list archives can contain malformed or unusual MIME/email data. Use local fixtures before live network smoke tests.
- Thread matching by subject alone is unreliable across patch revisions, rerolls, quoted replies, and renamed subjects.

Minimum recommendation:

Start with mbox fixtures and message-id/thread mbox snapshot ingestion. Defer live archive traversal until local parsing and evidence references are stable.

### Linux kernel process

Version-sensitive areas:

- Kernel process documentation evolves with maintainer practice.
- Trailer expectations vary by subsystem and patch type.
- Stable backport rules and `Fixes:` usage are strong signals but not universal truth.

Minimum recommendation:

Record which docs were consulted and keep process-derived heuristics explainable and caveated.

## Alternatives and deferrals

Rejected or deferred for now:

- Parsing porcelain/human `git log` output as the main schema source. Use plumbing commands instead.
- Live lore.kernel.org or GitHub access inside default review commands. Use explicit collectors and snapshots instead.
- Treating `Signed-off-by`, `Fixes:`, Scorecard, SLSA, Sigstore, OSV, or any other provider as a verdict.
- Adding a heavy JSON Schema/Pydantic/codegen layer before the normalized evidence model stabilizes.
- Using mailing-list text directly as model instructions. It remains hostile input and must be reduced first.

Acceptable near-term alternatives:

- Add a small schema module using standard dataclasses or typed dictionaries.
- Add synthetic git and mbox fixtures for parser behavior.
- Add optional smoke scripts for live public data that are not part of default CI.
- Add fixture snapshots for OpenSSF/external evidence rather than live provider calls.

## Downstream beads

This research should guide these existing beads:

- `kernel-diffguard-nsj`: normalized evidence schemas and trust-boundary labels should use snapshot and evidence-reference fields from this document and `docs/external-evidence.md`.
- `kernel-diffguard-boh`: single-commit parsing should prefer `git rev-parse`, `git diff-tree`, and `git cat-file` with explicit separators and type checks.
- `kernel-diffguard-txj`: GitHub-hosted commit input should resolve to immutable commits and controlled local clones before review.
- `kernel-diffguard-8rz`: mailing-list correlation should start from local mbox/thread snapshots and public-inbox/lore evidence references.
- `kernel-diffguard-p58`: Raspberry Pi kernel exemplar work should document which official kernel and repository-process docs apply and where vendor practice differs from upstream Linux.
- `kernel-diffguard-ls4`: easy-win heuristics can safely add trailer, stable-cue, process-file, and patch-metadata fixtures as long as they remain reviewer-assistance signals.
