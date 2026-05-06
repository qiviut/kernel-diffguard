# Expert question evidence map

## Goal / problem framing

This document maps the expert operating questions in
`docs/expert-operating-questions.md` to evidence kernel-diffguard can already
emit, evidence it does not yet collect, and explicit coverage-gap results it
should report instead of inferring suspicion.

The map is a design artifact for `kernel-diffguard-2td`. It is not a policy DSL,
not a verdict table, and not an anomaly model. Its job is to make the next step
legible:

expert question -> bounded evidence -> missing evidence / coverage gap -> named
expert check candidate

## Evidence source classes

Use these classes when designing named checks and review-packet output:

- local git: commit objects, trees, refs, tags, signatures, paths, modes, diff
  stats, bounded diff excerpts, patch IDs, commit order, range manifests, merge
  tree deltas, and range-local co-change summaries.
- GitHub hostile metadata: parsed GitHub commit/PR source, API payload excerpts,
  base/head SHAs, ordered PR commit lists, author/title/body excerpts, clone URL,
  and controlled cache provenance.
- mailing-list/archive: bounded RFC822/mbox facts, lore/public-inbox search
  results, patch IDs, subjects, vN series facts, review tags, objections,
  unresolved-question markers, and related-message candidates.
- external snapshot: offline provider records such as OpenSSF Scorecard, SLSA,
  Sigstore, OSV, OpenVEX, GUAC/Trustify, Security Insights, Criticality Score,
  or Package Analysis-style snapshots.
- generated artifact: checked-in generated-looking paths/text, lock files,
  source/generator/version correspondence, artifact hashes, generated/binary
  comparison results, and reproducibility records.
- build/CI: workflow files, configured commands, warning policies, static
  analysis/fuzzing/sanitizer gates, status-check requirements, build logs, and
  optional compiler/static-analysis delta hooks.
- target profile: kernel .config, hardware/module inventory, distro/vendor
  patches, runtime services, threat-model constraints, and profile-scoped retest
  results.

Every class is hostile or derived from hostile input except the tool's own
bounded reduction and reviewed project configuration. Evidence must carry
`evidence_refs`, `trust_boundary`, and `limits` before it can support a check.

## Current evidence inventory

Already available from current review output:

- `commit_artifact`: commit SHA, parents, tree, author/committer identity and
  timestamps, subject/body, touched paths, path changes, diff stats, patch ID,
  tags, signature status, bounded diff excerpt, evidence refs, trust boundaries,
  limits, and risk hints.
- single-commit review findings: `removed-test`, `ci-static-analysis-weakened`,
  `warning-policy-weakened`, `generated-code-churn`, `suspicious-script-added`,
  `commit-integrity-cue`, `prompt-injection-text`, `linux-security-cue`, and
  `high-risk-path`.
- single-commit review fields: `kernel_impacts`, `integrity_assessment`, and
  `optional_check_hooks` for compiler-warning and static-analyzer delta checks.
- `commit_range_manifest`: base/target, traversal mode, ordered commits,
  commit-artifact refs, commit facts, errors, evidence refs, trust boundary, and
  limits.
- range signals: author buckets, finding ID counts, top-level path-prefix counts,
  touched-path summaries, bounded same-commit co-changed path pairs,
  co-changed path-prefix pairs, co-change omission counters, and aggregated
  `kernel_impacts`.
- range findings: `split-setup-use-pattern`.
- merge review evidence: first-parent merge tree delta facts and explicit
  excluded-commit metadata.
- GitHub PR/commit evidence: immutable commit source parsing, controlled
  materialization, PR title/body excerpts, base/head SHAs, ordered commit list,
  author, provenance, evidence refs, limits, and remote trust boundary labels.
- mailing-list evidence: message IDs, subject/from/to/cc/list IDs,
  in-reply-to/references, body excerpt, patch facts, patch series metadata,
  review tags, objections/NAKs, unresolved markers, URLs/domains, attachments,
  evidence refs, limits, and archive trust boundary labels.
- related-message evidence: candidate links with commit refs, message refs,
  match evidence, discussion signals, and bounded candidate scoring details.
- external evidence schema: provider-neutral snapshot records exist as a schema
  and fixture contract, but live collection/use as policy evidence is not yet a
  default review command.

Important limitation: current findings are evidence inputs, not answers. A
finding such as `high-risk-path` means a path creates a review/retest question; it
is not a conclusion that the path is malicious or even wrong.

## Status vocabulary for evidence mapping

Named checks should report these evidence-coverage states before they report any
future policy status:

- answered_by_current_evidence: existing bounded artifacts are enough to answer
  the question for the subject.
- partially_answered: existing artifacts answer part of the question, but the
  result must cite missing fields or uncollected source classes.
- missing_evidence: required evidence class is absent or unusable.
- not_collected_by_default: evidence may exist externally, but default local/PR
  review does not collect it.
- requires_codebase_experience: the question depends on reviewed invariants or
  subsystem knowledge not yet encoded.
- no_check_coverage: no named check exists yet even though a question applies.

These are not suspicion states.

## Mapping: universal repository-security questions

### UQ-001: What authority boundary did this change touch?

Current evidence:

- local git: touched paths, path changes, diff stats, file status, bounded diff
  excerpt, tags, signature status, commit/tree object facts.
- GitHub hostile metadata: PR/commit source, base/head, ordered commits, title
  and body excerpts.
- build/CI: CI/workflow path changes and static-analysis marker findings.
- generated artifact: generated-looking path/text finding.
- review signals: `high-risk-path`, `suspicious-script-added`,
  `ci-static-analysis-weakened`, `warning-policy-weakened`,
  `generated-code-churn`, `commit-integrity-cue`, `kernel_impacts`.

Missing evidence:

- project-specific authority-boundary map beyond generic path heuristics.
- release-path configuration, required status checks, deployment/update authority
  rules, and repository-specific privileged script inventory.
- external release/signing/provenance snapshots beyond current local tag and
  commit-signature facts.

Coverage gap to report: `authority_boundary_map_missing` when only generic path
or finding heuristics apply.

Weak/ambiguous signals: `high-risk-path` and script-like path detection are
triage inputs only; they do not prove a boundary was actually reachable.

### UQ-002: Which invariant does this subsystem or process appear to rely on?

Current evidence:

- local git: nearby touched paths, tests/docs/config changes in the same commit
  or range, range-local co-change summaries, commit subjects/bodies.
- mailing-list/archive: review tags, objections, unresolved markers, and related
  discussion candidates when collected.
- review signals: removed tests, generated/source hints, warning/CI weakening,
  split setup/use range finding.

Missing evidence:

- accepted invariant catalog for repositories, subsystems, release paths, and
  target profiles.
- maintainer-authored rationale or durable exception history.
- longitudinal baseline promotion workflow from observations to accepted checks.

Coverage gap to report: `accepted_invariant_missing` or
`requires_codebase_experience`.

Weak/ambiguous signals: co-change history can suggest an invariant but must not
be treated as accepted policy.

### UQ-003: Is this change modifying policy, enforcement, setup, use, or observation?

Current evidence:

- local git: touched paths, path prefixes, path changes, diff stats, bounded diff
  excerpts, commit order.
- range evidence: `split-setup-use-pattern`, author/path-prefix/finding counts,
  co-changed path and prefix pairs.
- build/CI: warning and CI/static-analysis findings.
- generated artifact: generated/source-looking findings.

Missing evidence:

- semantic role labeling for code symbols or config keys.
- subsystem-specific role maps for policy/enforcement/setup/use/observation.
- model-assisted semantic analysis over sanitized evidence.

Coverage gap to report: `semantic_role_map_missing` when only path-level role
hints exist.

Weak/ambiguous signals: range-local split patterns are review-linkage evidence,
not a maliciousness claim.

### UQ-004: Are tests, CI, static analysis, warnings, fuzzing, or sanitizers being weakened?

Current evidence:

- local git/build/CI: deleted test paths, CI/workflow path changes,
  static-analysis marker diffs, warning-policy marker removals, optional compiler
  and static-analyzer delta hooks.
- review signals: `removed-test`, `ci-static-analysis-weakened`,
  `warning-policy-weakened`.

Missing evidence:

- replacement coverage detection.
- repository-required status-check configuration.
- actual CI run logs, sanitizer/fuzzer status, and project-specific build matrix.
- explicit exception or compensating-control records.

Coverage gap to report: `replacement_or_exception_evidence_missing`.

Weak/ambiguous signals: marker-based CI/static-analysis detection can say a gate
changed around known commands, but not whether the gate was fully removed,
renamed, or replaced.

### UQ-005: Are generated artifacts changing with corresponding source, generator, or reproducibility evidence?

Current evidence:

- local git/generated artifact: generated-looking paths or generated-text markers,
  diff stats, path changes, bounded diff excerpts.
- review signals: `generated-code-churn`.
- external snapshot: schema exists for offline provider records, but collection is
  not yet wired into default review.

Missing evidence:

- generator/source correspondence map.
- generator version/source-input records.
- artifact hash comparison and reproducible build output.
- binary/source correspondence and release-archive checks.

Coverage gap to report: `generated_source_correspondence_missing`.

Weak/ambiguous signals: generated-looking text/path markers can overmatch docs or
snapshots; they should create a correspondence question, not a violation by
itself.

### UQ-006: Did this change add or modify high-authority executable code?

Current evidence:

- local git: added script-like paths, executable-looking names, shebangs in diff
  excerpt when present, path changes, file mode/status facts where available.
- build/CI: workflow path changes and CI marker findings.
- review signals: `suspicious-script-added`, `ci-static-analysis-weakened`,
  `prompt-injection-text`.

Missing evidence:

- invocation-site graph for scripts and build tools.
- repository-specific high-authority path map.
- CI/release/deployment execution context and permissions.
- explicit intended-invocation/review evidence.

Coverage gap to report: `script_invocation_evidence_missing`.

Weak/ambiguous signals: a script-like filename is only a cue; authority depends
on whether and how it is invoked.

### UQ-007: Is risky behavior split across commits, files, or review surfaces?

Current evidence:

- local git/range: ordered commits, commit subjects, per-commit findings,
  range-local author buckets, path prefixes, co-change pairs, finding counts.
- GitHub hostile metadata: ordered PR commit lists and PR text excerpts.
- mailing-list/archive: patch series metadata and related-message candidates when
  collected.
- review signals: `split-setup-use-pattern`, warning/CI/test findings, high-risk
  path findings, generated/source cues.

Missing evidence:

- durable setup/use and policy/enforcement coupling rules.
- cross-review-surface correlation across PR, mailing list, and merge commits as
  a single packet.
- accepted rationale for splitting the work.

Coverage gap to report: `split_rationale_or_coupling_rule_missing`.

Weak/ambiguous signals: split work is normal in large projects; report the link,
not suspicion.

### UQ-008: Does the change match its stated purpose without hiding semantic drift?

Current evidence:

- local git: subject/body, path churn, diff stats, changed tests/docs/configs,
  generated-looking churn, bounded diff excerpt.
- range/PR: ordered commits, per-commit findings, PR title/body excerpts.
- mailing-list/archive: patch discussion, review objections, unresolved markers,
  vN series facts when collected.

Missing evidence:

- semantic diff classification beyond path and text heuristics.
- refactor-vs-behavior-change detector.
- subsystem-specific expectations for what counts as behavior-facing.

Coverage gap to report: `semantic_drift_analysis_missing`.

Weak/ambiguous signals: commit messages and PR descriptions are hostile claims,
not ground truth.

### UQ-009: What evidence would make this change acceptable?

Current evidence:

- current findings include suggested next checks.
- normalized artifacts include evidence refs, limits, trust boundaries, and risk
  hints.
- mailing-list evidence can include review/test tags and objections when
  collected.
- optional hooks can point to compiler-warning/static-analyzer delta checks.

Missing evidence:

- structured missing-evidence field on named check results.
- mapping from question/check to required evidence class.
- exception records, retest records, and project-specific acceptance criteria.

Coverage gap to report: `required_evidence_contract_missing` until named checks
provide explicit required evidence.

Weak/ambiguous signals: suggested next checks are prose hints, not yet a stable
check-result contract.

### UQ-010: What exception would a responsible maintainer have to write down?

Current evidence:

- local git and review findings can identify changes that likely require an
  exception: removed tests, weakened gates, generated/source gaps,
  high-authority scripts, release/provenance cues, and target-profile retest
  gaps once profiles exist.

Missing evidence:

- exception artifact schema.
- approval identity/scope/expiry/compensating-control fields.
- repository-specific exception workflow.

Coverage gap to report: `exception_process_missing`.

Weak/ambiguous signals: a future exception is a human decision record, not proof
that the change is safe.

## Mapping: candidate Linux-kernel questions

### KQ-001: Does this touch a kernel authority or isolation boundary?

Current evidence:

- local git: touched paths and diff stats.
- kernel hints: `kernel_impacts` for Kconfig, drivers, arch, syscall/ABI,
  filesystems, networking, scheduler, memory management, and security-sensitive
  paths.
- review signals: `high-risk-path`, `linux-security-cue`.

Missing evidence:

- subsystem/maintainer map.
- reachability and target-profile relevance.
- kernel-version-specific authority-boundary map.
- public process evidence tied to subsystem expectations.

Coverage gap to report: `kernel_subsystem_envelope_missing` or
`target_profile_relevance_missing`.

Weak/ambiguous signals: broad kernel path families are not semantic authority
proof.

### KQ-002: Does this alter Kconfig, build options, defaults, or feature gates?

Current evidence:

- local git: Kconfig/build paths, diff excerpt, path changes, diff stats.
- kernel hints: Kconfig/build-related `kernel_impacts`.
- build/CI: warning-policy and CI/static-analysis changes when present.

Missing evidence:

- parsed Kconfig symbol dependency/default changes.
- target `.config` impact calculation.
- build matrix, module inventory, and profile-scoped retest evidence.

Coverage gap to report: `kconfig_symbol_impact_missing` or
`target_config_missing`.

Weak/ambiguous signals: touching Kconfig does not mean a deployed config changes.

### KQ-003: Does this change a user-visible ABI, syscall, ioctl, netlink, filesystem, driver, or module interface?

Current evidence:

- local git: touched paths, uapi/doc path changes, diff excerpt.
- kernel hints: syscall/ABI, filesystem, networking, driver/module path impacts.
- mailing-list/archive: review/test tags and objections when collected.

Missing evidence:

- parsed ABI/interface symbol changes.
- compatibility/release-note evidence.
- target-profile use of the interface.

Coverage gap to report: `kernel_interface_semantics_missing` or
`interface_target_relevance_missing`.

Weak/ambiguous signals: uapi or driver paths are cues; actual interface change
requires deeper parsing or maintainer evidence.

### KQ-004: Does this change scheduler, memory-management, locking, lifetime, or concurrency behavior?

Current evidence:

- local git: touched paths and bounded diff excerpts.
- kernel hints: scheduler, memory-management, arch, driver, and security-sensitive
  path impacts.
- review signals: Linux security language cues such as lifetime or use-after-free
  when present.

Missing evidence:

- semantic primitive detection for locking/refcounting/RCU/workqueues/DMA.
- subsystem-specific tests and static-analysis results.
- performance/regression/reliability retest records.

Coverage gap to report: `kernel_concurrency_semantics_missing`.

Weak/ambiguous signals: path hints cannot establish concurrency behavior.

### KQ-005: Are source changes separated from required kernel tests, configs, documentation, or maintainer discussion?

Current evidence:

- local git/range: changed test/config/doc paths, ordered commits, range findings,
  path prefixes, co-change pairs.
- mailing-list/archive: related-message candidates, review tags, objections,
  unresolved markers, patch series vN facts.
- GitHub hostile metadata: PR commit ordering and text excerpts.

Missing evidence:

- accepted per-subsystem test/doc/process requirements.
- maintainer map and required review authority.
- default collection of process evidence for every local review.

Coverage gap to report: `kernel_process_requirement_missing` or
`process_evidence_not_collected`.

Weak/ambiguous signals: absence of local mailing-list evidence does not mean
absence of public review.

## Mapping: codebase-experience-dependent questions

### CQ-001: What subsystem-specific invariants are maintainers relying on here?

Current evidence:

- local git/range and mailing-list evidence can supply examples, tests,
  objections, and repeated patterns.
- golden cases can preserve known examples once accepted.

Missing evidence:

- accepted invariant catalog.
- review process for promoting observations into invariants.

Coverage gap to report: `subsystem_invariant_not_learned`.

Weak/ambiguous signals: generic path labels are not subsystem wisdom.

### CQ-002: Which files or path prefixes normally change together for a reason that should become an explicit coupling rule?

Current evidence:

- range-local co-changed path pairs and path-prefix pairs with omission counters.
- finding counts and author buckets.

Missing evidence:

- longitudinal co-change summaries reviewed by humans.
- explicit coupling rationale and false-positive examples.

Coverage gap to report: `coupling_rule_candidate_only`.

Weak/ambiguous signals: co-change normality is not goodness, and rarity is not
badness.

### CQ-003: Which target profiles make this change operationally relevant?

Current evidence:

- generic kernel impact hints and touched paths.
- future external/profile schemas can point to target-specific facts, but target
  profiles are not yet collected by default.

Missing evidence:

- target `.config`, module/hardware inventory, runtime services, distro/vendor
  patches, threat model, and retest results.

Coverage gap to report: `target_profile_missing`.

Weak/ambiguous signals: generic kernel impact is not target reachability.

### CQ-004: Which repeated review objections should become durable questions or checks?

Current evidence:

- mailing-list `discussion_signals`, objections/NAKs, unresolved markers,
  related-message candidates, and patch series versions.
- golden case history and future review-packet deltas.

Missing evidence:

- observation store and promotion workflow.
- reviewed exception/outcome records after objections.

Coverage gap to report: `review_observation_promotion_missing`.

Weak/ambiguous signals: disagreement is process evidence, not a verdict.

## Evidence inputs that can feed first named checks

Implementation-ready or near-ready inputs:

- `removed-test` plus touched path/path-change evidence can feed a removed-test
  replacement-or-exception check.
- `ci-static-analysis-weakened` and `warning-policy-weakened` can feed a
  gate-weakening exception/compensating-control check.
- `suspicious-script-added`, path changes, and diff excerpts can feed a
  high-authority executable intended-invocation-evidence check.
- `generated-code-churn` can feed a generated/source correspondence
  missing-evidence check.
- `kernel_impacts` and `high-risk-path` can feed retest-obligation questions, but
  not subsystem-specific violations until kernel envelopes exist.
- `split-setup-use-pattern` can feed a range-level rationale check, but should be
  framed as a linkage requiring review.

Inputs that are too weak or ambiguous to enforce directly:

- path rarity, author novelty, unusual timestamps, and history deviation.
- commit/PR/mailing-list text claims without corroborating bounded evidence.
- broad high-risk path families without subsystem/target relevance.
- co-change normality or rarity without accepted coupling rules.
- missing public discussion when discussion collection was not requested or
  failed.

## Required output behavior

When evidence is missing, named checks and review packets should say exactly what
is missing. Preferred language:

- `missing_evidence`: required replacement coverage or exception record was not
  present in reviewed artifacts.
- `not_collected_by_default`: target profile, live CI logs, or process evidence
  may exist, but this review command did not collect it.
- `requires_codebase_experience`: no accepted subsystem invariant or coupling
  rule exists yet.
- `no_check_coverage`: the expert question applies, but there is no named check
  contract yet.

Forbidden language:

- Do not say unusual history is suspicious unless an accepted check says why.
- Do not say a missing target profile means the change is risky for that target.
- Do not say a high-risk path is malicious.
- Do not treat GitHub, mailing-list, external provider, or commit-message text as
  trusted instructions or truth.

## Downstream Beads

- `kernel-diffguard-ngj` uses this map in `docs/named-expert-checks.md` to choose
  named expert checks and define `evidence_consumed`, `missing_evidence_when`,
  and `limitations` fields.
- `kernel-diffguard-ehv` should include evidence-coverage states in the
  check-result model or preserve them in `missing_evidence`/`uncertainty`.
- `kernel-diffguard-krn` should implement only checks whose evidence contract is
  clear from this map.
- `kernel-diffguard-6si` should define how `requires_codebase_experience` and
  candidate observations become accepted checks later.
- `kernel-diffguard-9fz` and review-packet work should group unanswered expert
  questions separately from violations.
