# Normalized evidence schemas

## Goal / problem framing

Normalized evidence schemas are the compatibility layer between local git parsing, commit-range review, mailing-list context, external evidence snapshots, operating-envelope policies, policy check results, findings, and later review packets. They make security-relevant boundaries visible before downstream parsers and resolvers harden.

The schemas are reviewer-assistance infrastructure. They are not verdicts and do not decide whether a commit, range, message, project, or artifact is safe or malicious. Policy schemas should support logical allow-list checks: whether a declared rule applies, is satisfied, is violated, lacks required evidence, or is inconclusive.

Every artifact shape must preserve three properties:

- `evidence_refs`: stable references back to the facts or records supporting the artifact.
- `trust_boundary`: an explicit label saying where hostile input enters or where a derived review signal begins.
- `limits`: bounded-output metadata such as truncation and omitted-record counts.

Raw git metadata, diffs, path names, remote archive messages, email text, and external provider records are hostile input even when they come from familiar public infrastructure.

## Trust-boundary labels

The first schema catalog in `src/kernel_diffguard/evidence_schema.py` defines these labels:

- `local_git_metadata_untrusted`: commit IDs, author fields, trailers, subjects, bodies, refs, and other git metadata parsed from a local repository.
- `local_git_diff_untrusted`: paths, modes, diff stats, rename/copy metadata, and bounded diff excerpts parsed from git objects.
- `remote_archive_email_untrusted`: public-inbox/lore or local mbox content, including headers, subjects, bodies, attachments, URLs, and list identifiers.
- `external_evidence_snapshot_untrusted`: OpenSSF Scorecard, SLSA, Sigstore, OSV, OpenVEX, GUAC/Trustify, Security Insights, Criticality Score, package-analysis-style, or other provider snapshots.
- `derived_review_signal`: deterministic signals produced by kernel-diffguard from bounded evidence. Derived signals still require human review; they are not verdicts.

Downstream code must not introduce an implicit trusted-by-default label. New labels should be added deliberately with tests and documentation.

## Artifact schemas

The initial normalized artifact schemas are:

### commit_artifact

Purpose: normalized facts for one local git commit and its bounded diff metadata.

Required common fields: `artifact_type`, `id`, `evidence_refs`, `trust_boundary`, `limits`, and `risk_hints`.

Additional required fields: `commit`, `parents`, and `touched_paths`.

Hostile fields include author/committer identity, subject/body text, touched paths, and diff excerpts.

### commit_range_manifest

Purpose: deterministic manifest for an explicit commit list or X..Y traversal.

Additional required fields: `base`, `target`, `traversal`, and `commits`.

It should record skipped, unreachable, or invalid revisions as bounded errors rather than silently widening analysis.

### mailing_list_message_artifact

Purpose: bounded RFC822/mbox message facts from local fixtures or explicit archive snapshots.

Additional required fields: `message_id`, `subject`, `from`, and `plain_text_excerpt`.

Headers and body excerpts remain hostile input and must be bounded before any model-assisted analysis.

### related_message_candidate

Purpose: evidence-scored candidate link between commit/range facts and message facts.

Additional required fields: `commit_refs`, `message_refs`, and `match_evidence`.

Candidates should expose evidence such as patch-id, subject cues, timestamp windows, list IDs, and changed subsystem cues instead of a single opaque confidence number.

### finding

Purpose: reviewer-assistance finding backed by deterministic evidence references.

Additional required fields: `severity`, `summary`, and `uncertainty`.

Findings must cite evidence and must distinguish facts, heuristics, and uncertainty.

### recommendation

Purpose: suggested next check or retest action tied to one or more findings or facts.

Additional required fields: `summary` and `recommended_action`.

Recommendations should be phrased as human-review next steps, not automated acceptance or rejection decisions.

### external_evidence_record

Purpose: provider-neutral OpenSSF-aligned snapshot record consumed offline.

Additional required fields: `provider`, `subject`, `source`, and `claims`.

External evidence records follow the snapshot-first model in `docs/external-evidence.md`: provider facts are context, not verdicts, and live network collection remains outside default review commands.

### named_expert_check

Purpose: reviewed-code check contract promoted from an expert operating question.

Additional required fields: `check_id`, `expert_question`, `classification`,
`applies_to`, `evidence_consumed`, `status_conditions`,
`required_next_action`, `rationale`, and `limitations`.

Allowed classifications are `generic`, `candidate_kernel_specific`, and
`requires_codebase_experience`. These classifications keep generic repository
hygiene separate from kernel-specific or project-specific wisdom.

`status_conditions` must define the closed status vocabulary: `satisfied`,
`violated`, `missing_evidence`, `not_applicable`, and `inconclusive`.

### expert_check_result

Purpose: deterministic result of applying one named expert check to bounded
evidence for one commit, range, PR, path, subsystem, generated artifact, or target
profile.

Additional required fields: `check_id`, `expert_question`, `status`, `subject`,
`missing_evidence`, `required_next_action`, `rationale`, and `limitations`.

Allowed statuses are `satisfied`, `violated`, `missing_evidence`,
`not_applicable`, and `inconclusive`. Statuses such as `suspicious`, `risky`, or
`anomalous` are intentionally not part of the schema. The result must cite
evidence and a required next action; it must not claim malicious intent.

### exception_record

Purpose: explicit human/project exception for a violated or missing-evidence
check result.

Additional required fields: `exception_id`, `scope`, `applies_to_check_ids`,
`rationale`, `approver`, `expires_or_review_by`, and `compensating_controls`.

Exception records make a decision reviewable. They do not make a change safe by
default and should be scoped, cited, and revisited.

### operating_envelope_policy

Purpose: explicit allow-list-style rule that describes what a repository, subsystem, process, patch shape, release path, or target profile permits.

Additional required fields should include `policy_id`, `version`, `scope`, `applies_to`, `allowed_if`, `requires_evidence`, `exception_process`, and `rationale`.

Policies should be inspectable and versioned. Historical data may suggest candidate policies, but accepted policies must not hide probabilistic anomaly detection behind policy-shaped output.

### policy_check_result

Purpose: deterministic result of applying one operating-envelope policy to one commit, range, PR, path, subsystem, or target profile.

Additional required fields should include `policy_id`, `status`, `subject`, `evidence_refs`, `missing_evidence`, `required_next_action`, and `uncertainty`.

Allowed statuses should include `satisfied`, `violated`, `missing_evidence`, `not_applicable`, and `inconclusive`. A policy check result should cite evidence and required action, not an opaque probability of maliciousness.

## Validation fixtures

`tests/test_evidence_schemas.py` validates representative artifacts for all schema kinds and confirms that invalid fixtures fail closed when evidence references are missing, trust-boundary labels are unknown, named-check classifications are unknown, or check-result statuses fall outside the closed vocabulary.

The validator is intentionally lightweight. It gives downstream implementation beads an executable contract without committing the project to a heavyweight JSON Schema/code-generation dependency before the interface stabilizes.

## Downstream implementation rules

- New parser outputs should use one of these artifact types or deliberately add a new schema with tests.
- Every artifact must include non-empty `evidence_refs`.
- Every artifact must include a known `trust_boundary` label.
- Every artifact must include `limits` with at least `truncated` and `omitted_record_count`.
- Every artifact should include `risk_hints`, even if empty, so hostile-input routing is visible.
- Review packets and scorecards should treat schema counts as steering signals, not product-success claims.
- Policy artifacts and policy check results must distinguish explicit rule violations from historical anomaly or baseline observations.
- Local `review-commit` and `review-range` should remain deterministic and offline by default.
