# External evidence and OpenSSF alignment

## Goal / problem framing

kernel-diffguard should stay a deterministic reviewer-assistance workbench for git history, commit ranges, and Linux-kernel-shaped review questions. OpenSSF projects should be treated as evidence providers and interoperability targets, not as replacements for the local reviewer.

The core boundary is:

- kernel-diffguard answers: what changed between X and Y, what reviewer-assistance signals follow from that change, and which evidence supports each signal?
- OpenSSF-aligned tools and specs answer: what security posture, provenance, advisory, exploitability, artifact, signing, or supply-chain graph evidence already exists around this project or artifact?

OpenSSF-derived facts are therefore inputs to review packets. They are not verdicts, and they must not decide that a commit, range, project, or artifact is safe or malicious by themselves.

## Snapshot-first architecture

External evidence must be collected into explicit local snapshots before review commands consume it. Review commands should be offline by default and should perform no live network fetches unless a future command name and option make collection explicit.

Preferred flow:

1. A collector command or external process fetches OpenSSF-adjacent data from a provider such as OpenSSF Scorecard, OSV, SLSA provenance, Sigstore verification, GUAC, Security Insights, OpenVEX, or another source.
2. The collector writes a bounded JSON snapshot with provider identity, source URI, collection time, input digest, schema version, freshness metadata, and normalized records.
3. The reviewer consumes one or more snapshots from disk together with local git evidence.
4. Review packets cite snapshot records through evidence references and preserve uncertainty.

This keeps default CI and golden analysis deterministic. Synthetic snapshots can cover behavior without network access, while optional public-data smoke tests can validate live provider assumptions separately.

Non-goals for the first interface:

- no live network access from `review-commit` or `review-range`,
- no provider credentials in review packet fixtures,
- no automatic trust decisions from provider scores,
- no requirement that a local/offline repository has OpenSSF metadata available.

## Normalized external evidence record

The first reusable record shape should be narrow and provider-neutral:

```json
{
  "schema_version": 1,
  "provider": "openssf-scorecard",
  "provider_record_type": "project_posture_check",
  "subject": {
    "kind": "repository",
    "identifier": "github.com/example/project",
    "revision": "optional immutable revision or null"
  },
  "source": {
    "uri": "https://example.invalid/source-or-api",
    "collected_at": "2026-04-28T00:00:00Z",
    "input_digest": "sha256:...",
    "collector": "manual-fixture-or-tool-name"
  },
  "freshness": {
    "stale_after": "2026-05-28T00:00:00Z",
    "is_live_network_result": false
  },
  "claims": [
    {
      "id": "scorecard.branch_protection",
      "kind": "project_posture",
      "summary": "Branch protection result from a snapshot",
      "value": "pass|fail|unknown|not_applicable",
      "confidence": "medium",
      "evidence_refs": ["external:scorecard:branch_protection"]
    }
  ],
  "limits": {
    "truncated": false,
    "omitted_record_count": 0
  }
}
```

Important fields:

- `provider` identifies the adapter, not a trust oracle.
- `subject` names the repository, artifact, package, advisory, or system-profile element being described.
- `source` records where the snapshot came from and how to reproduce or challenge it.
- `freshness` makes stale evidence visible to reviewers.
- `claims` are bounded facts or posture signals with evidence references.
- `limits` prevents large external graphs or advisory sets from becoming unbounded output.

Provider-specific raw payloads may be stored in a sidecar file, but review packets should cite normalized claims first.

## OpenSSF component mapping

### OpenSSF Scorecard

OpenSSF Scorecard assesses open source projects for security risks through automated checks. For kernel-diffguard, it fits as project posture context: branch protection, token permissions, security policy, dependency update hygiene, fuzzing, CI, code review, and similar controls.

Use it for:

- external project posture snapshots,
- CI/security-control context in review packets,
- inspiration for deterministic check documentation: risk, rationale, remediation, confidence.

Do not use it as a commit-risk oracle. A low or high Scorecard result is context, not a verdict about a specific change.

### SLSA

SLSA provides supply-chain levels and provenance concepts for software artifacts. It aligns with kernel-diffguard's provenance and generated-artifact questions.

Use it for:

- provenance vocabulary,
- source-to-build traceability,
- future generated-artifact comparison,
- detecting missing, stale, or mismatched provenance for artifacts tied to a reviewed range.

A useful future claim is whether an artifact has verified provenance that names the expected source revision and builder. Missing SLSA evidence should be reported as missing evidence, not as proof of compromise.

### Sigstore

Sigstore supports signing, verification, and protection of software artifacts. It fits artifact and attestation verification, especially for distro kernels, packaged outputs, CI artifacts, or kernel-diffguard's own release artifacts.

Use it for:

- verifying signatures and attestations when available,
- recording identities and transparency-log references as evidence,
- separating source-review findings from artifact-integrity findings.

Do not require Sigstore for upstream Linux commits where the relevant trust mechanism may be different.

### OSV

OSV provides vulnerability schema and advisory data for open source. It fits vulnerability/advisory context around touched versions, commits, paths, or packages.

Use it for:

- known-vulnerability context,
- fixed/introduced commit hints where available,
- advisory evidence in review packets,
- identifying ranges that may contain security fixes or vulnerability-adjacent churn.

OSV matches should preserve uncertainty because advisory-to-commit/path mapping can be incomplete or ambiguous.

### OpenVEX

OpenVEX describes exploitability status for vulnerabilities in a product or artifact context. It becomes most valuable with future system-profile impact analysis.

Use it for:

- affected/not-affected/fixed/under-investigation status,
- explaining why a kernel change may or may not matter for a deployed profile,
- narrowing retest guidance when a config, module, or hardware profile excludes affected code.

OpenVEX evidence is product-context evidence; it should not change generic source-history facts.

### GUAC and Trustify

GUAC maps software metadata such as SBOMs into a graph of relationships among artifacts, components, advisories, and dependencies. Trustify stores and retrieves SBOM and advisory documents.

Use them for:

- graph context around what an artifact contains,
- relationships from source revisions to packages, images, products, and advisories,
- future system-profile impact analysis,
- optional export or import of kernel-diffguard evidence relationships.

GUAC-style graph data should be bounded before review output. Large graph traversals need limits and omission counters.

### Security Insights and OSPS Baseline

Security Insights provides machine-processable project security information. OSPS Baseline provides structured security requirements aligned with standards and frameworks.

Use them for:

- project policy metadata,
- vulnerability-reporting and security-contact context,
- baseline-control context when reviewing changes to security policy, CI, release, signing, or dependency-management files.

These are project posture inputs, not per-commit conclusions.

### Criticality Score

OpenSSF Criticality Score quantifies project importance. Linux itself is already highly critical, so kernel-diffguard should mostly adapt the idea at finer granularity.

Use it for:

- project prioritization outside the Linux exemplar,
- subsystem/path criticality ideas,
- reviewer prioritization when combined with kernel impact hints and system-profile facts.

Avoid opaque criticality-only ordering. Explain the factors behind any priority signal.

### Package Analysis

OpenSSF Package Analysis detects malicious package behavior and tracks behavior changes over time. Direct package sandboxing is not the main Linux-kernel source-review workflow, but the longitudinal pattern is useful.

Use it for:

- inspiration for behavior-drift and baseline checks,
- author work-area drift,
- unusual co-change patterns,
- suspicious changes to scripts, build tooling, generated artifacts, or package/release behavior.

This maps most closely to future longitudinal baseline work.

## Trust boundaries and determinism

External provider output is hostile remote input. Even official-looking security metadata can be stale, malformed, incomplete, compromised, or irrelevant to the reviewed range.

Rules:

- Review commands consume local snapshots and have no live network by default.
- Every external claim carries provider, source, collection time, subject, and evidence references.
- Provider scores are reviewer-assistance signals, not verdicts.
- Raw external text is bounded before display or model-assisted analysis.
- Large advisory sets and graphs include truncation and omission metadata.
- Secrets, API tokens, and credentials never appear in snapshots or fixtures.
- Golden fixtures use synthetic provider records unless a public immutable artifact is intentionally pinned.

This preserves the existing trust posture: deterministic reduction first, optional bounded analysis later, human decision last.

## Integration order

Recommended order:

1. Define and test the normalized external evidence snapshot schema with synthetic fixtures.
2. Add a review-packet field that can cite external snapshot claims without changing existing core analysis.
3. Add one simple collector or fixture converter, likely OSV or OpenSSF Scorecard, because their records are easy to model as bounded claims.
4. Add provenance/signature providers later: SLSA and Sigstore.
5. Add graph/system-profile providers later: GUAC, Trustify, OpenVEX, and SBOM-related evidence.
6. Feed lessons into the normalized evidence schema and trust-boundary labels before they become sticky.

The next implementation slice should not wire live OpenSSF APIs into core review commands. It should create a tiny schema module and golden fixture proving that external claims can be loaded, bounded, cited, and rendered deterministically.
