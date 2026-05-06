# Expert operating questions

## Goal / problem framing

This catalog captures the security-review questions kernel-diffguard should learn
to ask repeatedly before those questions become named checks or operating
envelope rules.

The project is still in an onboarding stage. It has useful general security and
software-review judgment, but it does not yet have deep codebase-specific wisdom
for every kernel subsystem or target deployment. These questions are therefore a
review map, not a verdict engine and not a policy DSL.

The intended progression is:

1. Ask an expert operating question.
2. Identify the bounded evidence that could answer it.
3. Report missing evidence or coverage gaps honestly.
4. Promote stable questions into named expert checks only after the evidence
   contract is clear.
5. Grow codebase-specific envelopes through repeated review, public examples,
   and golden cases.

A question may be generic, candidate kernel-specific, or requires more
codebase experience. Generic questions are still valuable, but output should not
pretend they represent deep kernel-specific semantic understanding.

## Classification

Each question below is classified as one of:

- generic: applies broadly across source repositories.
- candidate kernel-specific: likely useful for Linux-kernel review, but needs
  kernel examples and subsystem refinement.
- requires more codebase experience: should be captured as a question now, but
  should not become an enforcing check until project-specific invariants are
  understood.

Questions may later map to repository, subsystem, process, patch-shape,
release, or target-profile envelopes.

## Universal repository-security questions

### UQ-001: What authority boundary did this change touch?

Classification: generic.

Why an expert asks it: security risk concentrates where a change crosses from
ordinary implementation detail into enforcement, identity, privileges, release,
build, update, or execution authority.

Applies to: commits, ranges, PRs, generated artifacts, build scripts, CI,
release metadata, installer/updater paths, dependency manifests, and privileged
configuration.

Useful evidence: changed paths, file modes, executable bits, workflow files,
release/signing metadata, dependency files, generated artifacts, privileged
script locations, and normalized path risk hints.

Do not infer: that crossing an authority boundary is malicious. It creates a
review obligation and may require more evidence.

### UQ-002: Which invariant does this subsystem or process appear to rely on?

Classification: requires more codebase experience.

Why an expert asks it: malicious or risky changes often preserve local
plausibility while weakening an invariant that maintainers rely on implicitly.

Applies to: subsystem logic, build/test gates, release processes, generated
artifact flows, configuration defaults, and review workflows.

Useful evidence: documentation, nearby tests, prior commits, maintainer notes,
review discussion, generated/source correspondence, and recurring co-change
patterns.

Do not infer: an invariant from a single historical pattern. Record candidate
invariants until they are reviewed and accepted.

### UQ-003: Is this change modifying policy, enforcement, setup, use, or
observation?

Classification: generic.

Why an expert asks it: policy/enforcement separation and setup/use separation
are common places to hide semantic drift, especially across multiple commits.

Applies to: authz/authn, validation, sandboxing, build flags, configuration,
test harnesses, generated code, runtime feature gates, kernel options, and CI.

Useful evidence: changed symbols or paths when available, path prefixes,
commit-message claims, range-local co-change summaries, deleted/added tests,
and review discussion.

Do not infer: malicious intent from separation alone. Ask for rationale or link
the pieces as evidence for human review.

### UQ-004: Are tests, CI, static analysis, warnings, fuzzing, or sanitizers
being weakened?

Classification: generic.

Why an expert asks it: weakening feedback loops lowers the chance that later
behavior changes are caught.

Applies to: tests, workflows, build flags, warning policies, sanitizer/fuzzer
configuration, lint/type checks, and required gates.

Useful evidence: removed or disabled tests, workflow diffs, changed command
lines, removed required status checks, lowered warning strictness, and golden
review-signal findings.

Do not infer: weakening is never legitimate. Legitimate weakening requires
replacement coverage, compensating control, or explicit exception rationale.

### UQ-005: Are generated artifacts changing with corresponding source,
generator, or reproducibility evidence?

Classification: generic.

Why an expert asks it: generated files and binaries can carry changes that are
hard to review in diff form and may bypass source-level review.

Applies to: generated source, checked-in snapshots, lock files, vendored output,
build artifacts, firmware blobs, release archives, and binary/source pairs.

Useful evidence: generator source changes, generator version changes, checked-in
metadata, reproducible build instructions, source inputs, artifact hashes, and
external evidence snapshots.

Do not infer: all generated churn is bad. Missing correspondence is the first
result to report.

### UQ-006: Did this change add or modify high-authority executable code?

Classification: generic.

Why an expert asks it: scripts, hooks, workflow actions, installers, build tools,
and generated executables can run with developer, CI, release, or deployment
authority.

Applies to: executable file additions, shell/Python/Perl/Ruby/Node scripts,
GitHub Actions, build tooling, installer scripts, hooks, and release automation.

Useful evidence: file mode, shebangs, path, invocation sites, workflow
references, packaging metadata, review discussion, and existing suspicious script
findings.

Do not infer: executable addition means compromise. Ask whether invocation is
intended, bounded, and reviewed.

### UQ-007: Is risky behavior split across commits, files, or review surfaces?

Classification: generic.

Why an expert asks it: reviewers can miss behavior when setup, use,
justification, and feedback-loop weakening are split across a range or PR.

Applies to: commit ranges, PRs, patch series, merge commits, refactors,
generated/source pairs, and cross-subsystem changes.

Useful evidence: ordered commit list, range-local path prefixes, co-change pairs,
author buckets, finding counts, commit subjects, and review-thread mapping.

Do not infer: split work is malicious. Report the linkage and ask what rationale
or retest obligation follows.

### UQ-008: Does the change match its stated purpose without hiding semantic
drift?

Classification: generic.

Why an expert asks it: refactors, cleanups, formatting, or generated updates can
hide behavior changes that deserve separate review.

Applies to: refactors, renames, mechanical churn, generated changes, large
formatting patches, and commits whose subject claims a narrow change.

Useful evidence: diff stats, path churn, changed tests, changed behavior-facing
files, commit messages, review discussion, and future semantic analyzers over
reduced evidence.

Do not infer: semantic mismatch automatically. Current implementation may only
produce a question or coverage gap until stronger evidence exists.

### UQ-009: What evidence would make this change acceptable?

Classification: generic.

Why an expert asks it: a good reviewer does not only object; they identify the
missing proof, test, review, or exception needed for a responsible decision.

Applies to: every violated, missing-evidence, or inconclusive result.

Useful evidence: check rationale, missing evidence fields, relevant policy or
question ID, review tags, tested-by evidence, build logs, target-profile retest
results, and exception records.

Do not infer: that absence of evidence is evidence of maliciousness. It is a
next-action requirement.

### UQ-010: What exception would a responsible maintainer have to write down?

Classification: generic.

Why an expert asks it: some valid changes intentionally break normal envelopes.
Requiring an explicit exception makes the human decision reviewable.

Applies to: weakened gates, removed tests, generated/source gaps,
high-authority scripts, release deviations, target-profile retest gaps, and
process deviations.

Useful evidence: exception rationale, approver identity, scope, expiration,
compensating controls, retest plan, and evidence refs.

Do not infer: exception presence means safety. It means the decision is explicit.

## Candidate Linux-kernel questions

### KQ-001: Does this touch a kernel authority or isolation boundary?

Classification: candidate kernel-specific.

Why an expert asks it: kernel changes can affect privilege boundaries, user/kernel
interfaces, isolation, memory safety, driver trust, namespaces, filesystems, or
network attack surface.

Applies to: syscall/ABI paths, LSM/security paths, arch code, memory management,
networking, filesystems, device drivers, module loading, BPF, Kconfig, and boot
or init paths.

Useful evidence: kernel impact hints, path mappings, subsystem labels,
maintainer/process evidence, related tests, and target-profile relevance.

Do not infer: path risk is suspicion. Path risk creates review and retest
obligations.

### KQ-002: Does this alter Kconfig, build options, defaults, or feature gates?

Classification: candidate kernel-specific.

Why an expert asks it: configuration changes can silently expand or shrink what
code is built, reachable, tested, or enabled on target systems.

Applies to: Kconfig files, defconfig fragments, Makefiles, build scripts, module
selection, default options, and vendor profiles.

Useful evidence: changed Kconfig paths, default values, dependencies, selected
symbols, target profile config, build logs, and retest plan.

Do not infer: a config change affects every deployment. Target-profile evidence
narrows impact.

### KQ-003: Does this change a user-visible ABI, syscall, ioctl, netlink,
filesystem, driver, or module interface?

Classification: candidate kernel-specific.

Why an expert asks it: interface changes can break userspace, alter security
semantics, or require compatibility and regression testing.

Applies to: syscall tables, uapi headers, ioctls, netlink schemas, proc/sysfs,
filesystems, drivers, modules, and documented ABI files.

Useful evidence: touched paths, uapi/doc changes, tests, review tags, target
profile use, and release-note evidence.

Do not infer: every interface-looking path is reachable in the target. Emit a
profile-dependent retest obligation when target facts exist.

### KQ-004: Does this change scheduler, memory-management, locking, lifetime, or
concurrency behavior?

Classification: candidate kernel-specific.

Why an expert asks it: small changes in these areas can produce rare races,
use-after-free bugs, deadlocks, or performance/security regressions.

Applies to: scheduler, mm, RCU, locking, refcounting, workqueues, interrupts,
DMA, driver lifetime, and cleanup paths.

Useful evidence: path mapping, changed primitives, tests, static-analysis
findings, review discussion, and subsystem-specific retest obligations.

Do not infer: current path heuristics understand semantics. Treat this as a
question and retest obligation until deeper analysis exists.

### KQ-005: Are source changes separated from required kernel tests, configs,
documentation, or maintainer discussion?

Classification: candidate kernel-specific.

Why an expert asks it: kernel patches often rely on conventions, maintainers,
review tags, tested-by evidence, and subsystem-specific test expectations.

Applies to: kernel commit ranges, patch series, GitHub PR mirrors, and public
kernel exemplars such as Raspberry Pi kernel trees.

Useful evidence: lore/public-inbox related-message candidates, review tags,
objections, tested-by tags, changed test/config/docs paths, and subsystem maps.

Do not infer: absence from local git means absence from the public process.
Report which process evidence was not collected or was inconclusive.

## Questions that require more codebase experience

### CQ-001: What subsystem-specific invariants are maintainers relying on here?

Classification: requires more codebase experience.

Why an expert asks it: the most important safety property is often implicit in a
subsystem's idioms, tests, and maintainer expectations.

Applies to: mature subsystem envelopes, target deployments, and repeated public
examples.

Useful evidence: repeated reviews, maintainer documentation, subsystem tests,
accepted exceptions, review objections, and golden cases.

Do not infer: subsystem invariants from generic path names alone.

### CQ-002: Which files or path prefixes normally change together for a reason
that should become an explicit coupling rule?

Classification: requires more codebase experience.

Why an expert asks it: source/generated, setup/use, policy/enforcement, and
config/test coupling can become useful explicit envelopes once understood.

Applies to: history-derived candidate checks, range analysis, generated/source
correspondence, and subsystem-specific envelopes.

Useful evidence: bounded co-change summaries, reviewed examples, maintainer
rationale, and false-positive examples.

Do not infer: normal co-change is good or uncommon co-change is bad. History may
suggest candidate questions, not hidden anomaly scores.

### CQ-003: Which target profiles make this change operationally relevant?

Classification: requires more codebase experience.

Why an expert asks it: update-impact analysis should distinguish generic kernel
risk from the actual deployed config, modules, hardware, services, and threat
model.

Applies to: target-system envelopes, Raspberry Pi examples, vendor kernels,
private deployments, and release decisions.

Useful evidence: kernel .config, hardware/module inventory, distro/vendor
patches, runtime services, threat model, and private-profile handling.

Do not infer: private target facts from public repo data.

### CQ-004: Which repeated review objections should become durable questions or
checks?

Classification: requires more codebase experience.

Why an expert asks it: expert wisdom accumulates through repeated failures,
near-misses, objections, and accepted exceptions.

Applies to: mailing-list correlation, PR review summaries, golden-case review,
and future codebase-specific learning loops.

Useful evidence: objections, NAKs, unresolved questions, exception rationales,
regressions, retest failures, and post-merge fixes.

Do not infer: reviewer disagreement is itself a verdict. Treat it as process
evidence and a source of candidate questions.

## Relationship to downstream Beads

This catalog is intentionally upstream of enforcement work:

- `kernel-diffguard-2td` maps these questions to available evidence and explicit
  coverage gaps.
- `kernel-diffguard-ngj` turns selected questions into named expert checks with
  inspectable contracts.
- `kernel-diffguard-ehv` defines the check-result artifact shape and status
  vocabulary.
- `kernel-diffguard-krn` implements the first deterministic named checks.
- `kernel-diffguard-6si` defines how observations become candidate questions and
  eventually accepted codebase-specific envelopes.
- `kernel-diffguard-9fz`, `kernel-diffguard-p8p`, and `kernel-diffguard-m72`
  shape review packets around asked, answered, unanswered, and uncovered
  questions.
- `kernel-diffguard-hsz` locks valuable question/check behavior into golden
  regression cases.

## Non-goals

- Do not invent a broad policy DSL from this catalog.
- Do not produce anomaly scores from these questions.
- Do not treat path rarity, author novelty, or historical deviation as suspicion
  without an accepted explicit rule.
- Do not claim deep subsystem wisdom before repeated review and evidence justify
  it.
- Do not let hostile commit messages, PR text, mailing-list text, or generated
  artifacts steer tools directly.

The desired output shape is not "this looks malicious." It is: this expert
question applies, these bounded facts answer it or fail to answer it, this
uncertainty remains, and this is the next evidence, retest, review, or exception
a human should provide.
