# Named expert checks

## Goal / problem framing

This document defines how kernel-diffguard turns onboarding-stage expert
operating questions into named, reviewable checks.

A named expert check is reviewed Python code with a small contract around it. It
is not a user-authored DSL rule, not an anomaly detector, and not a maliciousness
verdict. In short: it is not a maliciousness verdict. The check answers a bounded
question against bounded evidence and says what a responsible reviewer must do
next.

The project is still being onboarded to real kernel codebases. Its first checks
therefore encode general security-review wisdom that is already useful across
repositories. Codebase-specific and subsystem-specific wisdom should be captured
as observations or candidate questions until repeated work, examples, and human
review justify promotion into a named check.

Intended progression:

1. Start with an expert operating question from
   `docs/expert-operating-questions.md`.
2. Confirm the evidence mapping in `docs/expert-question-evidence-map.md`.
3. Define a named-check contract before implementation.
4. Implement the check as ordinary reviewed Python code.
5. Add unit fixtures and at least one golden review-packet case when output
   becomes user-visible.
6. Refactor common structure only after several checks reveal a real pattern.

## Design posture

Named checks should preserve expert wisdom in a form a maintainer can inspect:

- Keep the check logic explicit and local to the check implementation.
- Prefer typed Python data structures and fixtures over a broad policy language.
- Report missing evidence as a first-class result.
- Cite evidence references, trust boundaries, and limits for every result.
- Require explicit exception or retest decisions for violations and unresolved
  missing evidence.
- Avoid scoring, suspicion labels, or claims about intent.

A check may be generic and still valuable. Output must be honest about that. For
example, detecting a removed test or weakened CI gate is generic repository
hygiene unless the check is backed by a kernel-specific envelope or subsystem
invariant.

## Named-check contract

Every named check must document these fields before implementation:

- check_id: stable identifier used in JSON, text output, tests, golden cases, and
  documentation.
- expert_question: the `UQ-*`, `KQ-*`, or `CQ-*` question the check answers.
- classification: `generic`, `candidate kernel-specific`, or
  `requires codebase experience`.
- applies_to: subject kinds and preconditions such as single commit, range,
  GitHub PR, generated artifact, target profile, or external evidence snapshot.
- evidence_consumed: normalized artifacts and fields the check reads.
- satisfied_when: exact condition that satisfies the review obligation.
- violated_when: exact condition that violates the obligation.
- missing_evidence_when: evidence absence that prevents a responsible answer.
- inconclusive_when: evidence exists but is ambiguous, partial, bounded away, or
  conflicting.
- not_applicable_when: condition proving the check does not apply to the subject.
- required_next_action: review, test, exception, retest, correspondence, or
  evidence-collection action required by non-satisfied statuses.
- rationale: why a security reviewer asks this question.
- limitations: what the check cannot conclude, including any generic-vs-specific
  limits.
- evidence_refs_required: minimum evidence references that must appear in a
  result.
- golden_case_requirement: fixture or golden output needed before user-visible
  behavior is considered stable.

The implementation may add internal helper fields, but those helper fields do
not replace this contract.

## Result vocabulary

Initial named-check results should use the `expert_check_result` artifact defined
in `src/kernel_diffguard/evidence_schema.py` and documented in
`docs/normalized-evidence-schemas.md`. The closed vocabulary is:

- satisfied: evidence shows the review obligation is met.
- violated: evidence shows the obligation is not met and needs human attention.
- missing_evidence: required evidence is absent or unusable.
- inconclusive: bounded evidence exists but cannot answer the question safely.
- not_applicable: the check does not apply to this subject.

Every non-`not_applicable` result should include:

- `check_id`
- `expert_question`
- `status`
- `evidence_refs`
- `trust_boundary`
- `limits`
- `required_next_action`
- `rationale`

`violated` does not mean malicious. `missing_evidence` does not mean suspicious.
Both mean the review packet should make the human decision explicit.

## First implementation-ready checks

These checks are ready to design and implement first because current artifacts
already expose enough bounded evidence to produce useful results.

### KDG-CHECK-REMOVED-TEST

check_id: `KDG-CHECK-REMOVED-TEST`

expert_question: `UQ-004: Are tests, CI, static analysis, warnings, fuzzing, or
sanitizers being weakened?`

classification: generic.

applies_to: single commits, commit ranges, and GitHub PRs with changed paths and
review-signal findings.

evidence_consumed:

- `commit_artifact.path_changes`
- touched test-like paths
- `finding.id == "removed-test"`
- range finding counts when reviewing multiple commits
- optional review discussion, replacement-coverage, or exception evidence once
  those artifacts exist

satisfied_when: removed tests are accompanied by bounded evidence of replacement
coverage, an equivalent moved/renamed test, or an accepted explicit exception.

violated_when: test files or test cases are removed or disabled and no
replacement coverage or explicit exception is present.

missing_evidence_when: the reducer reports removed-test evidence but no artifact
exists yet for replacement coverage, test movement, review rationale, or
exceptions.

inconclusive_when: the diff suggests test removal but the bounded excerpt cannot
distinguish deletion from rename, generator churn, test split, or framework
migration.

not_applicable_when: no test-like paths, test deletion markers, or removed-test
findings apply.

required_next_action: provide replacement test evidence, restore coverage, or
write a scoped maintainer exception with rationale and follow-up.

rationale: weakening tests reduces the chance that risky behavior is caught later
and is a common first question in security review.

limitations: the first implementation may only detect obvious path and marker
signals. It must not claim full semantic coverage analysis.

evidence_refs_required: commit artifact refs for affected paths and finding refs
for the removed-test signal.

golden_case_requirement: at least one fixture where a test deletion produces a
missing-evidence or violated check result, plus a later fixture where replacement
coverage satisfies it.

### KDG-CHECK-CI-STATIC-ANALYSIS-WEAKENED

check_id: `KDG-CHECK-CI-STATIC-ANALYSIS-WEAKENED`

expert_question: `UQ-004: Are tests, CI, static analysis, warnings, fuzzing, or
sanitizers being weakened?`

classification: generic.

applies_to: commits, ranges, and PRs that change CI workflows, build scripts,
lint/type/static-analysis invocations, warning policy, sanitizer/fuzzer config,
or required-gate documentation.

evidence_consumed:

- workflow and build-file path changes
- `finding.id == "ci-static-analysis-weakened"`
- `finding.id == "warning-policy-weakened"`
- bounded diff excerpts around command removals or flag changes
- optional repository-required-status-check evidence when available

satisfied_when: a gate change preserves equivalent or stronger coverage, replaces
one tool with an explicit equivalent, or records an accepted exception with
compensating control.

violated_when: a CI/static-analysis/warning/sanitizer/fuzzer gate is removed,
weakened, made non-blocking, or narrowed without equivalent replacement or
exception evidence.

missing_evidence_when: current evidence shows a gate-like command changed but no
artifact describes required gates, replacement command equivalence, or exception
approval.

inconclusive_when: the bounded diff cannot determine whether a command was
renamed, moved to a shared script, made conditional for legitimate reasons, or
replaced elsewhere.

not_applicable_when: the subject does not touch gate-like files, commands, or
review signals.

required_next_action: cite the replacement gate, provide required-check context,
restore the gate, or write an explicit exception.

rationale: weakened feedback loops create room for later unsafe changes to pass
undetected.

limitations: first implementation is marker and path based. It should recognize
that moving repeated commands into a shared script can be a strengthening, not a
weakening, when evidence shows the shared script runs the same gates.

evidence_refs_required: workflow/build-file refs, finding refs, and bounded diff
refs for changed commands.

golden_case_requirement: include one fixture for direct gate removal and one for
legitimate gate consolidation into a shared verification script.

### KDG-CHECK-HIGH-AUTHORITY-EXECUTABLE

check_id: `KDG-CHECK-HIGH-AUTHORITY-EXECUTABLE`

expert_question: `UQ-006: Did this change add or modify high-authority executable
code?`

classification: generic.

applies_to: commits, ranges, and PRs that add or modify executable files,
scripts, hooks, build tooling, installer/updater paths, GitHub Actions, release
automation, or generated executables.

evidence_consumed:

- file status and mode facts from local git
- script-like path and executable-name heuristics
- shebang snippets from bounded diff excerpts
- `finding.id == "suspicious-script-added"`
- workflow references or invocation sites when current evidence exposes them

satisfied_when: the executable's purpose, invocation path, execution authority,
and review rationale are explicit and bounded by project policy or accepted
review evidence.

violated_when: a high-authority executable is added or materially changed and the
subject provides no intended-invocation, review, or authority-boundary evidence.

missing_evidence_when: script-like evidence exists but invocation sites,
permissions, execution context, or review rationale are not collected.

inconclusive_when: a file looks executable or script-like but bounded evidence
cannot prove whether it is invoked, generated, test-only, documentation, or dead
code.

not_applicable_when: no executable/script-like file, workflow action, build tool,
installer, hook, or release automation change is present.

required_next_action: identify invocation sites and execution authority, prove the
script is bounded/test-only, or add an explicit maintainer review/exception.

rationale: scripts and automation can run with developer, CI, release, or target
system authority even when the source diff looks small.

limitations: script-like path detection is a cue. Authority depends on how the
file is invoked and with what permissions.

evidence_refs_required: changed-path refs, mode/shebang refs when available, and
finding refs for script-like evidence.

golden_case_requirement: include a fixture for a new script in a high-authority
path and a fixture for a script-like file that is not applicable or inconclusive.

### KDG-CHECK-GENERATED-CORRESPONDENCE

check_id: `KDG-CHECK-GENERATED-CORRESPONDENCE`

expert_question: `UQ-005: Are generated artifacts changing with corresponding
source, generator, or reproducibility evidence?`

classification: generic.

applies_to: commits, ranges, PRs, and later release artifacts that change
generated-looking source, checked-in snapshots, lock files, vendored output,
firmware blobs, binary/source pairs, or release archives.

evidence_consumed:

- generated-looking path and text markers
- `finding.id == "generated-code-churn"`
- changed generated artifact paths and diff stats
- source/generator/version correspondence records when available
- external evidence snapshots or artifact hashes when available

satisfied_when: changed generated artifacts are accompanied by corresponding
source input, generator version, reproducibility evidence, or accepted exception.

violated_when: generated or binary-like artifacts change without corresponding
source/generator/reproducibility/exception evidence.

missing_evidence_when: current evidence can identify generated-looking churn but
no correspondence artifact exists.

inconclusive_when: generated-looking markers overmatch documentation, snapshots,
fixtures, or files whose generated status is ambiguous.

not_applicable_when: no generated-looking path/text, binary-like artifact,
lockfile, vendored output, or generated-code finding is present.

required_next_action: provide source/generator correspondence, reproducibility
record, artifact hash comparison, or scoped exception.

rationale: generated artifacts and binaries can carry changes that are difficult
to review in ordinary source diffs.

limitations: first implementation cannot prove generation semantics from text
markers alone. It should prefer missing-evidence results over false precision.

evidence_refs_required: generated-path refs, finding refs, and correspondence
artifact refs when present.

golden_case_requirement: include one generated-file churn fixture without
correspondence and later one with explicit source/generator evidence.

### KDG-CHECK-KERNEL-RETEST-OBLIGATION

check_id: `KDG-CHECK-KERNEL-RETEST-OBLIGATION`

expert_question: `KQ-005: Are source changes separated from required kernel tests,
configs, or retest evidence?`

classification: candidate kernel-specific.

applies_to: commits, ranges, and PRs with `kernel_impacts` such as Kconfig,
drivers, architecture-specific code, syscall/ABI surfaces, filesystems,
networking, scheduler, memory management, or security-sensitive paths.

evidence_consumed:

- `kernel_impacts` from commit and range review output
- touched kernel path prefixes
- test/config/doc path changes in the same subject
- optional target-profile evidence when available
- mailing-list Tested-by/review tags when collected

satisfied_when: impacted kernel areas have matching test/config/retest evidence,
mailing-list Tested-by evidence, target-profile retest evidence, or an explicit
exception explaining why retest is unnecessary.

violated_when: a known impact area changes and accepted envelope rules require a
specific retest, but no retest or exception evidence exists.

missing_evidence_when: impact hints exist but there is no accepted retest
obligation map for the area, no target profile, or no collected test evidence.

inconclusive_when: path-level impact hints are too broad to know whether the
runtime surface is affected.

not_applicable_when: no kernel-impact hints or kernel path changes apply.

required_next_action: identify the affected kernel surface, run or cite relevant
retests, provide target-profile rationale, or record a maintainer exception.

rationale: update-impact review should say what must be retested when moving from
X to Y.

limitations: this starts as a simple retest-obligation question. It is not yet a
full subsystem semantic model and should not pretend to know all Linux retest
requirements.

evidence_refs_required: kernel-impact refs, touched-path refs, and any
retest/tag/exception refs used to satisfy the result.

golden_case_requirement: include a fixture where kernel-impact hints produce a
`missing_evidence` result because the retest map or target profile is absent.

## Deferred checks requiring codebase experience

These questions should remain deferred until project-specific or
subsystem-specific wisdom is reviewed and accepted:

- `UQ-002` / `CQ-001`: subsystem invariant weakening. Needs an accepted invariant
  catalog before violations are possible.
- `CQ-002`: expected co-change patterns. Range-local co-change evidence can
  suggest questions, but longitudinal patterns must not become anomaly scores.
- `CQ-003`: target-profile relevance. Requires a profile schema and private-data
  posture before enforcing profile-specific retest obligations.
- `CQ-004`: repeated review objections. Needs an observation-promotion loop and
  human acceptance before objections become durable checks.
- `KQ-003`: user-visible ABI/syscall/ioctl/netlink/procfs/sysfs behavior. Needs
  stronger semantic/path envelopes and kernel examples.
- `KQ-004`: scheduler, memory-management, locking, lifetime, concurrency, and
  privilege-sensitive internals. Needs subsystem expertise and focused fixtures.

Deferred does not mean ignored. It means the current responsible output is a
coverage gap such as `requires_codebase_experience`, `accepted_invariant_missing`,
`target_profile_missing`, or `no_check_coverage`.

## Review, testing, and promotion rules

A named check is ready for implementation only when:

1. Its contract is documented.
2. Its evidence inputs already exist or the missing evidence behavior is explicit.
3. It has unit fixtures for satisfied, violated, missing-evidence,
   inconclusive, and not-applicable cases where those statuses are reachable.
4. User-visible output has a golden case or a documented reason it is not yet
   stable enough for one.
5. The check text states what it cannot conclude.

Implementation rules:

- Use reviewed Python code, not a new DSL.
- Keep check IDs stable once golden cases depend on them.
- Put shared result-shape code in small typed helpers only after at least two
  checks need the same structure.
- Prefer explicit `if`/`match` logic and named predicates over clever generic
  evaluators.
- Include hostile-input tests for paths, commit messages, review text, and
  generated artifacts that might try to smuggle instructions into output.
- Require evidence references for every status except purely structural
  `not_applicable` results.

Promotion path for future wisdom:

observation -> candidate expert question -> evidence map -> named-check contract
-> implementation -> golden case -> review-packet reporting

Historical baselines may help propose observations, but a baseline alone must not
produce a violation. A human/project decision must accept the invariant,
co-change rule, retest obligation, or exception pattern first.

## Refactoring posture

Do not invent a broad policy DSL now. If the first several named checks develop
obvious repeated structure, refactor toward small internal helpers such as:

- a typed check-result object,
- evidence-reference validation,
- common status rendering,
- shared exception lookup,
- shared replacement-coverage lookup.

Those helpers should make checks easier to review. They should not hide the
expert question or turn the check inventory into opaque configuration.

## Downstream Beads

- `kernel-diffguard-ehv`: define the shared check-result/model contract after
  these named checks establish the first real shape.
- `kernel-diffguard-krn`: implement the first operating-envelope checker over
  review evidence.
- `kernel-diffguard-hsz`: add golden cases for named-check output.
- `kernel-diffguard-9fz`: report which expert questions were answered in review
  packets.
- `kernel-diffguard-6si`: design the codebase-specific wisdom accumulation loop
  that promotes observations without creating anomaly scoring.
