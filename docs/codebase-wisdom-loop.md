# Codebase-specific wisdom loop

## Goal / problem framing

kernel-diffguard should learn project and subsystem wisdom from repeated reviews
without turning history into an anomaly detector. The loop below captures useful
observations, promotes only reviewed knowledge into named questions or checks, and
keeps uncertain historical signals as evidence for humans rather than verdicts.

The operating rule is:

observation -> candidate expert question -> reviewed named check/envelope ->
golden case

Nothing history-derived may produce a violation until a human or project policy
has accepted the check/envelope and its evidence contract.

## Observation record

An observation is a bounded, reviewable claim about a repository or subsystem. It
must cite evidence, trust boundaries, and limits, and it must not say that a
change is malicious or statistically unusual. Initial observation classes are:

- subsystem invariant: a rule maintainers appear to rely on, such as locking,
  lifetime, ABI, permission, generated/source, or caller/callee assumptions.
- recurring review requirement: evidence reviewers repeatedly ask for, such as
  replacement tests, Tested-by tags, reproducer links, Kconfig coverage, or
  explicit maintainer rationale.
- coupling pattern: files, config, generated artifacts, tests, docs, or process
  paths that should usually be reviewed together.
- retest obligation: target, subsystem, or profile-specific tests that should be
  run when a declared surface changes.
- exception pattern: a scoped, explicit reason a project accepts deviation from a
  normal envelope, including owner, expiry/review date, and compensating control.

Every observation should include:

- `observation_id`: stable local identifier.
- `scope`: repository, subsystem, path prefix, release process, target profile, or
  patch shape.
- `class`: one of the classes above.
- `statement`: concise human-readable claim.
- `evidence_refs`: bounded facts, review packets, discussions, tests, or docs.
- `trust_boundary`: usually `derived_review_signal` or a specific hostile input
  boundary from the source artifact.
- `limits`: truncation, sample window, omitted records, or missing sources.
- `status`: candidate, accepted, superseded, retired, or rejected.
- `privacy`: public-fixture-safe, local-private, redacted, or do-not-persist.

## Promotion path

### 1. Capture candidate observations

Candidate observations can come from review packets, related mailing-list
messages, repeated missing-evidence recommendations, or explicit maintainer notes.
They remain notes. They can create `no_check_coverage` or `missing_evidence`
recommendations, but they cannot create violations.

### 2. Turn stable candidates into expert questions

A candidate becomes a question when it can be asked safely across future reviews.
The question should be added to `docs/expert-operating-questions.md` or a
repository-local equivalent and mapped in `docs/expert-question-evidence-map.md`.
The mapping must say what current evidence can answer, what remains missing, and
which weak signals must stay non-verdict evidence.

### 3. Promote reviewed questions into named checks or envelopes

A named check/envelope requires a small reviewed contract:

- the accepted question or invariant it answers,
- exact scope and preconditions,
- evidence consumed,
- satisfied, violated, missing_evidence, inconclusive, and not_applicable
  conditions,
- required next action for every non-satisfied status,
- exception shape, if exceptions are allowed,
- limits and privacy posture.

Implementation should remain ordinary reviewed code or compact data, not a broad
DSL. Prefer allow-list operating-envelope logic over anomaly scoring. If no
accepted check applies, report `no_check_coverage`, `inconclusive`, or
`not_applicable` rather than guessing.

### 4. Lock accepted behavior with tests and goldens

Promotion is not complete until a fixture or golden case proves the output shape.
Golden cases should include at least one satisfied/answered case, one violation
or missing-evidence case when applicable, and one coverage gap for unpromoted raw
evidence.

## Human/project acceptance gate

Historical summaries, co-change frequencies, author work areas, and recurring
review text are candidate-policy material only. A project must explicitly accept
a rule before future changes can violate it.

Acceptance should answer:

- Who accepts the rule for this repository or subsystem?
- Which paths, branches, releases, targets, or profiles are in scope?
- What evidence satisfies the rule?
- What exception is acceptable, who can approve it, and when is it reviewed?
- Which public fixtures can demonstrate it without leaking private context?

Without this gate, the tool may say:

- candidate policy available,
- missing accepted invariant,
- no named-check coverage,
- evidence insufficient,
- not applicable.

It must not say violated.

## Privacy and secrets posture

Treat all source repositories, review discussions, build logs, and external
snapshots as hostile input. Do not persist private repository specifics in public
fixtures by default.

Rules:

- Default observation storage is local and redacted unless explicitly marked
  public-fixture-safe.
- Never store secrets, credentials, private connection strings, private hostnames,
  or raw proprietary code excerpts in observation summaries.
- Prefer stable evidence refs and reduced facts over copied raw text.
- For public examples, synthesize fixtures or use already-public repositories and
  mailing-list messages.
- Preserve enough provenance to re-check an observation, but avoid recording more
  private context than the future check actually needs.

## Revision, retirement, and conflict handling

Wisdom changes as maintainers clarify intent or subsystem design changes. Every
accepted observation/check/envelope needs lifecycle handling:

- accepted: active and allowed to produce satisfied/violated/missing_evidence
  results.
- superseded: replaced by a newer observation or narrower check; old evidence
  remains audit history but should not fire.
- retired: no longer valid because design, process, or target profile changed.
- rejected: reviewed and intentionally not promoted; future packets may cite the
  rejection instead of re-asking the same question.

Revision should require the same acceptance gate as initial promotion and should
update tests/goldens. If two accepted rules conflict, prefer the narrower scope
and report an explicit `inconclusive` or `missing_evidence` result until a human
resolves the conflict.

## Review-packet integration

Review packets should make the loop visible:

- named checks answer expert questions with satisfied, violated,
  missing_evidence, inconclusive, or not_applicable status;
- raw findings not consumed by an accepted check appear as `no_check_coverage`;
- candidate observations may be recommended as next evidence to review;
- accepted exceptions are cited as evidence, not hidden overrides;
- every recommendation says what evidence, exception, or promotion decision a
  human should provide next.

This keeps accumulated wisdom inspectable while preserving the central promise:
deterministic evidence first, explicit accepted operating envelopes second, and no
probabilistic normality-is-good verdicts.
