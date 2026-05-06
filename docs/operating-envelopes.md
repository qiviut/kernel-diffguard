# Operating envelopes and logical policy checks

kernel-diffguard should not become a probabilistic anomaly detector that says a
change is suspicious merely because it is uncommon. The long-term direction is a
deterministic evidence reducer plus an explicit operating-envelope checker: turn
git, GitHub, mailing-list, build, generated-artifact, and external-evidence data
into bounded facts, then check those facts against declared rules about what a
repository, subsystem, process, target profile, or release path permits.

The IDS analogy is useful only up to a point. Intrusion-detection systems often
learn or approximate "normal" and then score deviations. kernel-diffguard should
prefer an allow-list style model: define the environment the attacker is forced
to operate inside, make violations explicit, and require human-approved
exceptions when a valid change needs to leave that envelope.

## Core model

The intended flow is:

1. Resolve inputs to immutable, bounded evidence.
2. Normalize evidence with trust-boundary labels and evidence references.
3. Ask explicit expert operating questions and map them to bounded evidence.
4. Apply explicit named checks or operating-envelope policies where they exist.
5. Emit check results: satisfied, violated, missing evidence, not applicable, or
   inconclusive.
6. Generate human review packets around violations, required exceptions, and
   retest obligations.

The tool should avoid claims like "this is probably malicious" unless they are
backed by a concrete violated rule or missing required evidence. A useful output
is instead:

- policy X applies to this commit/range/PR;
- artifact Y violates policy X, or required evidence Z is missing;
- the exact evidence references are A/B/C;
- the required next action is restore the invariant, add missing evidence, or
  record an explicit exception rationale for human review.

## Operating-envelope layers

Policies can exist at several layers. They should be independently versioned and
composable so projects can start small and become more precise over time.

### Repository envelope

Examples:

- Only immutable SHAs, signed release tags, or configured release refs are valid
  review inputs for release decisions.
- Generated artifacts may not change unless their source inputs and generator
  version are also present and consistent.
- Submodule changes require explicit pin, source, and review evidence.
- Workflow, build, or static-analysis configuration cannot remove gates without
  an exception.

### Subsystem envelope

Examples:

- Paths map to declared subsystems and authority boundaries.
- Touching a security boundary, syscall/ABI surface, Kconfig option, scheduler,
  memory-management path, filesystem, networking stack, or driver class creates
  explicit review and retest obligations.
- Certain path combinations are disallowed or require a cross-subsystem rationale
  because they couple setup/use, policy/enforcement, or generated/source changes.

### Process envelope

Examples:

- A given class of change requires review tags, tested-by evidence, public
  discussion, maintainer involvement, or documented exception rationale.
- Mailing-list or GitHub metadata can satisfy evidence requirements only as
  hostile external input with provenance and truncation bounds, never as a trust
  oracle.
- PR titles, branch names, labels, bodies, comments, and author fields must never
  steer tools directly.

### Patch-shape envelope

Examples:

- Removing tests requires replacement coverage or an explicit exception.
- Weakening warnings, CI, static analysis, fuzzing, or sanitizers requires an
  exception and a compensating control.
- Adding executable scripts in high-authority paths requires evidence that the
  script is intended, bounded, and not invoked unexpectedly.
- Refactors may not hide behavior changes without an explicit semantic-change
  declaration.

### Target-system envelope

Examples:

- A target profile declares kernel config, hardware/module inventory, distro or
  vendor patches, runtime services, and threat-model constraints.
- Changes outside the profile can be deprioritized, but changes inside the
  profile create concrete retest obligations.
- Private target profiles must not be committed to public fixtures by default.

## Role of history and baselines

Historical data can help propose envelopes, but it must not silently become the
authority. The safe path is:

observed history -> suggested policy -> human/project accepts policy -> future
changes are checked logically

The unsafe path is:

observed history -> anomaly score -> implied suspicion

Author work-area history, co-change history, maintainer history, and review-path
history are useful as evidence for designing candidate policies. They should not
produce unreviewable "unusual therefore bad" findings. If no policy covers a
change, the correct result is an explicit coverage gap such as `no_policy` or
`inconclusive`, not an invented probability.

## Expert questions before policy artifacts

At the current maturity level, kernel-diffguard should start from expert
operating questions rather than a broad user-authored policy DSL. The catalog in
`docs/expert-operating-questions.md` records generic, candidate kernel-specific,
and codebase-experience-dependent questions that security reviewers would ask.

The near-term implementation path is:

expert question -> evidence mapping -> named expert check -> check result ->
golden case

Only after multiple named checks show repeated structure should the project
factor that structure into reusable policy data.

## Policy artifact shape

A future policy artifact should be small, inspectable, and friendly to golden
fixtures. A starting schema should include:

- `policy_id`: stable identifier, for example
  `ci.static_analysis_gate.must_not_be_removed_without_exception`.
- `version`: policy schema and rule version.
- `scope`: repository, subsystem, process, patch-shape, target-profile, or
  release.
- `applies_to`: bounded predicates over evidence fields such as path globs,
  artifact types, finding IDs, commit roles, or profile capabilities.
- `allowed_if`: logical conditions that satisfy the envelope.
- `requires_evidence`: evidence artifact types or fields that must be present.
- `requires_review`: optional process obligations such as maintainer review,
  tested-by evidence, or exception approval.
- `exception_process`: how a legitimate violation is made explicit.
- `rationale`: why this envelope exists.
- `trust_boundary`: which inputs are treated as hostile while evaluating it.

## Check-result artifact shape

A future check result should include:

- `policy_id`
- `status`: `satisfied`, `violated`, `missing_evidence`, `not_applicable`, or
  `inconclusive`
- `subject`: commit, range, PR, path, subsystem, or profile target
- `evidence_refs`: exact artifacts and fields supporting the result
- `missing_evidence`: required evidence that was absent or unusable
- `required_next_action`: restore invariant, add evidence, add exception, retest,
  or inspect manually
- `uncertainty`: limited to what cannot be concluded from the available evidence,
  not a probability of maliciousness

## First demonstrable policies

The first useful demo does not need deep kernel semantics. It should prove the
shape of the system with tiny synthetic fixtures and CI golden cases:

1. Tests may not be removed without replacement coverage or exception rationale.
2. CI/static-analysis gates may not be removed without exception and compensating
   control.
3. High-authority executable scripts may not be added without explicit evidence
   of intended invocation and review.
4. Generated artifacts may not change without source/generator correspondence.
5. Kernel profile rules can map a small set of paths to required retest
   obligations.

Each policy should produce deterministic, evidence-linked check results in JSON
and text output. Golden regression cases should lock in violations and satisfied
checks so future changes cannot accidentally drift back into vague heuristic
signals.

## Relationship to current review signals

Existing findings such as `removed-test`, `ci-static-analysis-weakened`,
`suspicious-script-added`, `prompt-injection-text`, and `high-risk-path` remain
useful as low-level evidence. They should increasingly feed policy checks rather
than stand alone as implied verdicts. The project vocabulary should move from
"this looks suspicious" toward "this policy is violated, this evidence is
missing, or this envelope is not defined yet."
