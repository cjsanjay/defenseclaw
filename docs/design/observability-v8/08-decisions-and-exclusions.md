# Decisions, Assumptions, and Exclusions

## 1. Locked Product Decisions

These decisions came directly from the planning discussion and should not be
reopened during implementation without a spec amendment.

| ID | Decision |
|---|---|
| D-001 | Use two-stage control: collection first, routing second. |
| D-002 | Use fixed semantic buckets with source, connector, action, event name, and severity selectors. |
| D-003 | Use the fourteen-bucket catalog in this package. |
| D-004 | Treat AI Defense as a source, not a separate bucket. |
| D-005 | Replace separate OTel destinations and audit sinks with one optional-destination registry; keep mandatory local SQLite as an implicit built-in store backed by the same canonical pipeline. |
| D-006 | Allow a record to fan out to every independently matching destination. |
| D-007 | Use first-match-wins route precedence within each destination and signal only when the advanced `routes` form is selected. |
| D-008 | Let omitted destination policy express the full capability default; provide one concise `send` block for narrowing and explicit send/drop actions in the mutually exclusive advanced form. |
| D-009 | Use capability-default/per-destination/simple-send or per-advanced-route profile resolution with bucket/global fallback. |
| D-010 | Make `none` valid and default for catalog, local, and optional-destination projections; it needs no break-glass switch or warning, while policy changes remain audited. |
| D-011 | Provide built-in redaction profiles plus composition from built-in detectors/field classes; no arbitrary regex. |
| D-012 | Fail closed to whole-field redaction on redaction processing failure and continue safe delivery. |
| D-013 | Provide exactly one always-enabled implicit SQLite event-history destination backed by `audit.db`; do not require a destination or catch-all route in source YAML. The separate `judge_bodies.db` forensic database is not an event-history destination and is excluded from this exactly-one rule. |
| D-014 | Persist every collected log to SQLite plus normalized projections. |
| D-015 | Use versioned full-fidelity catalog defaults: every bucket collects every defined log/trace/metric signal and uses `none`; no remote transport starts until a destination is selected. |
| D-016 | Provide a mandatory local compliance/security floor that bypasses collection only for SQLite. |
| D-017 | Use one global retention age for event, evidence, and judge-body history. |
| D-018 | Default retention to 90 days; `0` retains forever. |
| D-019 | Use atomic live reload; invalid new configuration leaves old behavior active. |
| D-020 | `defenseclaw upgrade` automatically performs the one-time supported v7-to-v8 conversion; the gateway has no startup auto-migration or dual-format mode, and the standalone migration CLI is optional. |
| D-021 | An enabled destination with no `send` or `routes` receives every catalog bucket unredacted and all signals supported by that destination kind: logs for log-only kinds, metrics for Prometheus, and logs/traces/metrics for general OTLP. |
| D-022 | Preserve the merged PR #403 full root/subagent lifecycle and traceability model and PR #412 local-dashboard data corrections as the v8 compatibility floor; the ordinary upgrade refreshes mutually compatible DefenseClaw-owned local assets without resetting history volumes or requiring another migration command. |

## 2. Semantic Decisions Added During Clarification

| ID | Decision |
|---|---|
| S-001 | `compliance.activity` is the audit trail of operator/service/system control-plane actions, including attempted and rejected changes. Logging is mandatory; actor attribution is best available. |
| S-002 | `security.finding` is a concrete risk observation; it is not the automatic final stage of a guardrail evaluation. |
| S-003 | `guardrail.evaluation` records a control execution and decision and is not a superset of model or tool content. |
| S-004 | `model.io` owns model request/response content; other buckets reference it. |
| S-005 | `tool.activity` owns tool request/result content; guardrail evaluation references it. |
| S-006 | `asset.scan` is scan execution/summary; `security.finding` contains individual issues. |
| S-007 | `asset.lifecycle` records actual state transitions; `enforcement.action` records attempts to impose controls. Successful quarantine normally produces linked records in both buckets; failed quarantine does not invent a lifecycle transition. |
| S-008 | Every record has one primary bucket. Relationships use correlation IDs rather than multi-bucket duplication. |
| S-009 | v8 finding logs are immutable observations and do not add `status: open` or case-management transitions. |
| S-010 | Existing producer remediation remains supported; evidence summary and remediation normalization must be deterministic and safe, not silently hallucinated. |
| S-011 | Administrative authentication/authorization failures are `compliance.activity`; inbound telemetry authentication failures are `telemetry.ingest`; outbound destination authentication failures are `platform.health`. All are mandatory-floor logs. |
| S-012 | Alert acknowledgement and dismissal never mutate an immutable event's canonical severity or emit noncanonical `ACK` severity. Mutable acknowledgement state lives in a separate alert-state projection keyed to the immutable record, and every acknowledgement/dismissal change emits an immutable mandatory `compliance.activity` event. Legacy acknowledgement action rows map to canonical `INFO`; historical rows whose original severity was overwritten with `ACK` remain readable with explicit legacy-acknowledged metadata and no invented original severity. |

## 3. Specification Defaults Introduced to Remove Ambiguity

These defaults have been reviewed with the locked product direction and are the
approved v8 implementation defaults. Changing one requires the specification,
traceability target, and affected tests to change together before implementation
diverges.

| ID | Default | Rationale |
|---|---|---|
| P-001 | Preserve `audit_events` as the v8 event-history compatibility anchor and add canonical columns. | Minimizes API/history migration while making structured v8 queries possible. |
| P-002 | The compiler generates the local SQLite catch-all; source YAML cannot remove or bypass it. | Enforces “every collected log is local” without operator boilerplate. |
| P-003 | Remote log/trace queues drop the newest attempted enqueue when full. Prometheus has no push queue, and metric SDK reader/exporter backpressure follows the documented SDK contract. | Preserves older queued log/trace order, avoids blocking producers, retains the canonical local record, and does not invent queue semantics for pull or SDK-managed metric delivery. |
| P-004 | Canonical security severity is `INFO < LOW < MEDIUM < HIGH < CRITICAL`. Guardrail/judge producer `NONE` maps to `INFO` while retaining clean-evaluation semantics; `WARN`/`WARNING` maps to `MEDIUM` and may retain `log_level: WARN`; ERROR maps HIGH and FATAL maps CRITICAL. | Merges the existing audit `INFO` ladder and guardrail `NONE` ladder into one comparable five-level envelope without rejecting clean evaluations or inventing a WARN rung. |
| P-005 | Retention deletes rows strictly older than the cutoff; equality is retained. | Avoids boundary ambiguity. |
| P-006 | Reaper starts after startup and repeats every six hours in batches of 1,000. | Balances prompt cleanup with SQLite contention. |
| P-007 | Finding observations are not automatically deduplicated. | Avoids accidentally introducing mutable case semantics; downstream can aggregate using stable fields. |
| P-008 | Remediation catalog enrichment is optional and additive; absent remediation remains valid. | Preserves current producers and avoids fabricated advice. |
| P-009 | Live source uses implicit local storage and omitted destination policy for full-capability delivery; concise `send` expresses narrowing, while effective/reference views expose the generated graph. | Keeps common full-fidelity policy small without creating a second runtime pipeline or hiding defaults. |
| P-010 | Do not add `observability.from` or another include mechanism in v8. | Concise authoring removes the immediate size pressure and avoids multi-file trust, watch, and atomicity complexity. |
| P-011 | Do not add user-defined bucket sets in v8; presets materialize explicit bucket lists. | Keeps selectors obvious and avoids another indirection layer. |
| P-012 | Require comment-preserving mutation of existing v8 YAML. | The current Python full-file `safe_dump` path strips comments and would destroy embedded operator guidance. |
| P-013 | For `config_version: 8`, omitted `bucket_catalog_version` resolves to catalog 1; an explicit value is required only to advance beyond it. Optional-destination wildcards remain pinned to the effective version. | Preserves safe evolution without making normal users maintain an internal version knob. |
| P-014 | Materialize audience presets into explicit YAML at authoring time rather than resolving mutable audience presets at runtime. | Later preset changes become reviewable config diffs instead of silent policy changes. |
| P-015 | Reject YAML aliases, merge keys, and duplicate keys in v8 policy files. | Avoids hidden precedence, parser parity problems, alias expansion attacks, and comment-preserving edit ambiguity. |
| P-016 | Do not allow implicit observability environment variables to override an explicit v8 graph; allow only documented bootstrap values and source-declared secret references. | Keeps `config.yaml` the central reviewable policy and makes effective provenance reliable. |
| P-017 | The ordinary `defenseclaw upgrade` command automatically detects and migrates supported v7 configuration. | Keeps the operator workflow to one familiar command. |
| P-018 | The registered migration builds and validates the complete candidate before replacing any source file. | A conversion error never exposes partial v8 YAML. |
| P-019 | A required conversion failure leaves or restores exact v7 configuration and never starts the v8 gateway against it. | Prevents an invalid config/binary state without inventing a new rollback protocol. |
| P-020 | Reuse the existing verified release, backup, service stop/start, health-check, and migration-cursor mechanisms. | The change does not justify an intermediate bridge release or parallel installer architecture. |
| P-021 | Keep v8 SQLite migrations additive and readable by the immediately previous supported release. | Makes ordinary rollback sufficient for this feature. |
| P-022 | The existing upgrade confirmation or `--yes` is sufficient; the redacted migration summary appears in that prompt. | Avoids a plan file, hash, typed phrase, or second apply operation. |
| P-023 | The standalone migration CLI is an optional preview/support surface using the exact same library as upgrade. | Prevents preview and automatic conversion from drifting. |
| P-024 | Fail the normal upgrade permission preflight when active config cannot be backed up and atomically replaced; do not change ownership. | Respects configuration ownership without inventing a managed-config transaction. |
| P-025 | Optional exporter unavailability is degraded runtime health, not an upgrade rollback condition, when the gateway and built-in SQLite store are healthy. | Avoids making a valid local upgrade depend on remote service availability. |
| P-026 | Detector catalog v1 exposes exactly `pii`, `credentials`, and `secrets`, with the stable detector-ID membership defined in the redaction contract. | Makes custom-profile validation and behavior implementable and portable across Go/Python validation. |
| P-027 | OTLP signal transports are enabled by the union of signals selected by `send` or `routes`; `signal_overrides` changes endpoint/path details but has no second `enabled` gate. | Removes a common “route exists but transport is disabled” failure mode. |
| P-028 | Keep v7 notification-only `observability.connectors[*].webhooks` as a typed compatibility child while migrating/rejecting connector `audit_sinks`. | Avoids silently turning notifications into log sinks or expanding this breaking change into a notification redesign. |
| P-029 | Use pinned OTel stable and GenAI conventions as the portable trace base, with a focused `defenseclaw.*` overlay for security, policy, lifecycle, correlation, provenance, bucket, and privacy semantics. | Keeps common AI telemetry interoperable without forcing non-standard security concepts into apparently standard keys. |
| P-030 | Replace separately hand-authored OTel schema files with one logical OTel-registry-compatible registry, split into focused GenAI/security/operations authoring files, that generates the JSON Schema bundle, catalog, docs, constants/builders, fixtures, field classes, and vendor projections. | Avoids both a forest of duplicate schemas and one giant file; changes normally require one domain entry rather than synchronized artifacts. |
| P-031 | Treat OpenInference and Galileo shapes as generated compatibility projections from canonical OTel GenAI plus DefenseClaw data. | Preserves backend compatibility without making one vendor or alias schema canonical. |
| P-032 | Preserve current Galileo agent/LLM/tool behavior and add retriever/workflow shapes, judge-chat spans, safe security events, rich correlation/timing/error metadata, and full general-OTLP security graphs. | Provides richer AI observability while respecting Galileo’s supported shapes and retaining vendor-neutral traces. |
| P-033 | Use bounded short operation traces, span events, and links rather than one hours-long agent-session span. | Preserves real-time export, avoids backend finalization problems, and correlates long sessions through stable IDs. |
| P-034 | A successful security control returning block/deny is not itself an OTel error; the prevented requested operation may be an error with `error.type=policy_denied`. | Separates successful security decisions from control failure while keeping blocked operations visible. |
| P-035 | Compile omitted capability policy and concise source YAML into the same immutable effective route graph as advanced policy; generated objects never become a second runtime path. | Separates operator simplicity from internal completeness. |
| P-036 | Require only validate, effective/reference, plan, and destination-test UX for v8; defer path explain, advanced lint, event explanation, and interactive schema browsing. | Prevents optional diagnostics from delaying the core simplification. |
| P-037 | Gate rich telemetry/schema consolidation as a separate implementation phase built on the unified router. | Preserves the requested rich signals without coupling them to basic configuration parsing and migration. |
| P-038 | Use one cross-language HMAC-SHA-256 `hash-v1` contract, including lexical path/URI normalization and a versioned token; fail closed when the installation key is unavailable. | Prevents Go/Python drift and unkeyed reversal/correlation surprises. |
| P-039 | Apply guarded validation and dialing to every push exporter. Private/CGNAT collector access requires explicit per-destination YAML opt-ins; metadata/link-local endpoints remain blocked. | Makes the asserted SSRF safety a real transport contract while supporting intentional local collectors visibly. |
| P-040 | Bind `defenseclaw-genai-rich-v1` to one immutable four-version tuple and use `scripts/generate_telemetry_registry.py` through the existing `make check-schemas` gate. | Removes schema/profile ambiguity and avoids naming CI targets that do not exist. |
| P-041 | Preserve judge-body retention independently from its relocated path: explicit YAML wins except the current off-like environment override, absence remains default true, and the environment gate is retired after migration. | Prevents an upgrade from silently turning raw forensic retention on or off. |
| P-042 | Use one canonical outcome vocabulary in the envelope; each family registers a subset and cannot invent synonyms. | Keeps logs, traces, routing, dashboards, and generated schemas comparable. |
| P-043 | Treat the Galileo 1,000 ms scheduled delay as a deliberate v8 preset default; the real v7 inherited default is 5,000 ms and explicit operator values are preserved. | Corrects the baseline while making the v8 behavior change visible in migration. |
| P-044 | Automatic migration materializes any narrower or redacted v7 behavior instead of allowing fresh-v8 full-fidelity defaults to broaden an upgraded installation. | Makes the new default simple for new configurations without silently changing existing operators' collection, routing, or privacy posture. |
| P-045 | Keep the real 60-second delta metric-export default; the bundled Collector converts delta sums to cumulative Prometheus series, uses one application-metric path, and Grafana advertises a Prometheus interval of at least 60 seconds. | Preserves current runtime semantics and prevents the false `No data`/zero behavior fixed by PR #412. |
| P-046 | Generate a versioned `local-observability-v1` consumer profile from the telemetry registry and dashboard inventory, preserving Loki chronology, Prometheus aggregates, Tempo waterfall ownership, Agent360 spanmetrics dimensions, datasource/dashboard UIDs, aliases, source/packaged parity, and the immediately previous bundled query contract for one declared compatibility window. | Makes dashboards an explicit tested consumer instead of an implicit collection of fragile query strings and keeps a temporarily stale optional bundle useful after upgrade. |
| P-047 | Make `judge_bodies.db` the sole authoritative v8 judge-body store. Upgrade copies legacy `audit.db.judge_responses` idempotently by stable ID, verifies target commits before writer cutover or source cleanup, deduplicates compatibility reads/authorized local exports with the authoritative store first, completes export before purge, purges legacy copies before authoritative rows, and removes the runtime fallback that writes new bodies to `audit.db`. | Prevents dual writes, duplicate forensic results, unverified destructive cleanup, and silent reintroduction of raw judge bodies into the mandatory event-history database. |

## 4. Explicitly Excluded Behavior

The following MUST NOT appear incidentally in the v8 observability implementation:

- A global redaction-disable environment variable that bypasses all destinations.
- `DEFENSECLAW_REVEAL_PII` altering persistence, export, or judge-body retention;
  if retained, it is an authorized local display-only control.
- An enabled optional destination with omitted policy silently doing less than its
  documented all-bucket, all-capability, unredacted default.
- A route enabling a signal whose bucket collection is disabled.
- Built-in SQLite persistence being optional, disabled, or dependent on a
  user-authored catch-all route.
- Remote export of a floor-only record.
- Full prompt/tool content hidden in evaluation or finding fields.
- Arbitrary administrator regex redaction.
- Model-generated evidence/remediation treated as authoritative without explicit
  provenance and a separately approved feature.
- Finding case status, analyst assignment, SLA, comments, or ticket synchronization.
- Webhooks reclassified as generic log sinks.
- Exactly-once remote delivery claims.
- Automatic blocking VACUUM.
- Reaping current enforcement state or asset snapshots.
- Gateway startup or reload automatically rewriting v7 configuration. The normal
  upgrader performs the one-time migration.
- Running old and new observability pipelines in permanent parallel.
- Configuration includes, scoped policy files, or remote/globbed sources.
- Mutable runtime audience presets whose meaning can change after upgrade without a
  source-config diff.
- Silently delivering buckets introduced after the config's reviewed catalog
  version through a non-SQLite wildcard.
- Supported CLI/TUI mutations that strip operator comments or section guidance.
- Continuing a failed required v8 migration and asking the operator to repair it
  after the new gateway starts.
- Requiring users to hand-copy configuration as the normal rollback mechanism.
- Bypassing the existing verified release mechanism for an upgrade that mutates
  configuration.
- A DefenseClaw-only replacement for standard OTel/GenAI agent, model, tool, or
  retrieval fields when an applicable pinned standard field exists.
- Galileo-specific fields in the canonical producer model or Galileo becoming a
  forked canonical span schema.
- Independently hand-maintained per-family OTel schemas after the generated registry
  architecture is committed.
- Unbounded span names, attributes, events, links, content, or stack traces in the
  name of richer telemetry.
- Collapsing root-agent lineage, upstream conversation, stable lifecycle, execution
  attempt, operation, and bounded trace identity into one ID.
- Waiting for `Stop`/session end before exporting already completed model, tool,
  turn, decision, or lifecycle work.
- Treating a dashboard query that parses but addresses a nonexistent label/field,
  returns a cadence-induced false zero, or loses root/subagent scope as compatible.
- Resetting local Prometheus, Loki, Tempo, or Grafana volumes as part of upgrade.

## 5. Review Checklist

Before marking the spec approved, reviewers should answer yes to each question:

### Taxonomy

- Can every current producer fact be assigned one bucket without copying content?
- Are model/tool/evaluation/finding boundaries sufficiently clear?
- Are AI Defense and connector distinctions expressible through selectors?
- Is omission of finding workflow status intentional for this scope?
- Is the `NONE`-to-`INFO` clean-evaluation mapping acceptable while keeping the
  canonical five-rung route ladder?

### Configuration

- Does the YAML permit required audience profiles without hidden global behavior?
- Is multi-destination fan-out plus concise-versus-advanced routing clear?
- Is automatic, non-disableable local persistence acceptable without source
  boilerplate?
- Are full-fidelity `none` defaults and generated capability-wide destination sends
  visible enough in source/effective/plan/doctor/TUI views?
- Is compact source plus effective/reference output preferable to an enormous live
  all-knobs file?
- Is one concise source file sufficient without includes or bucket-set indirection?
- Are materialized authoring presets understandable?
- Is bucket-catalog pinning acceptable for optional-destination wildcards?
- Is route-derived OTLP signal activation clearer than a separate enablement map?
- Are the focused v8 CLI release gates sufficient, with advanced diagnostics
  deferred?
- Is preserving comments across every supported config mutation a release gate?
- Are private/CGNAT push-collector opt-ins narrow and visible enough, with metadata
  and link-local endpoints still unconditionally blocked?

### Privacy

- Can disabling content logs be verified end to end?
- Are field classes and unknown-field behavior fail-safe?
- Is the local judge-body exception sufficiently isolated?
- Are redaction failures safe and observable without leaking failed values?
- Is the cross-language keyed `hash-v1` normalization/token contract suitable for
  path correlation and key rotation?

### Operations

- Is 90 days and one global age acceptable?
- Is six-hour/1,000-row reaping appropriate?
- Is remote drop-newest backpressure acceptable?
- Are restart-required and reloadable fields correctly divided?
- Are the PR #403 lifecycle identity/event/phase and missing-data contracts
  preserved without requiring session end for completed-operation export?
- Do Loki, Prometheus, and Tempo retain their documented dashboard ownership, with
  60-second delta export and Collector delta-to-cumulative conversion?
- Do all fourteen dashboard UIDs, the Agent360 variable/query contracts, and
  source/packaged parity remain release-gated?

### Migration and upgrade

- Can every supported local v7 installation migrate with one ordinary
  `defenseclaw upgrade` command?
- Can connector-specific v7 overrides be translated without losing intent?
- Is the complete target candidate validated before the source file is replaced?
- Does a required conversion failure preserve exact v7 config and prevent an
  incompatible v8 gateway start?
- Are additive/backward-readable SQLite migrations sufficient for rollback?
- Does the optional standalone command produce exactly the same candidate as the
  automatic upgrade?
- Does read-only configuration fail early with an actionable path and no ownership
  change?
- Does the automatic migration preserve judge-body retention state independently of
  its database-path move and correctly disclose the Galileo preset-delay change?
- Are setup, doctor, TUI, dashboards, and docs included before release?
- Does the ordinary upgrade refresh compatible DefenseClaw-owned local-stack assets,
  preserve custom files and history volumes, and verify readiness without requiring
  a separate migration command?

## 6. Spec Change Control

Any implementation PR that intentionally differs from a normative requirement must:

1. Update this specification first or in the same reviewed stack base.
2. Identify the changed decision and downstream documents/tests.
3. Describe the compatibility, security, privacy, and operator impact.
4. Add or update acceptance tests.
5. List any remaining future work only through linked GitHub issues, following the
   repository PR instructions.

Every decision in this document is indexed by
`13-decision-traceability.md`. Spec lint MUST reject an ID missing from that
appendix, a duplicate mapping, or a mapping without both contract and verification
targets.
