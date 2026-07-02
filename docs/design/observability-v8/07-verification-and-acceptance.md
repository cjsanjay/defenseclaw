# Verification and Acceptance

## 1. Verification Strategy

The implementation is accepted only when behavior is demonstrated at five levels:

1. Pure unit tests for taxonomy, collection, selectors, redaction, and retention.
2. Component tests for SQLite, each destination adapter, OTel processors/readers,
   and reload.
3. Contract tests for schemas, CLI/config parity, and migration.
4. End-to-end tests for representative operator configurations and producer flows.
5. Security, race, performance, and failure-injection tests.

Tests must validate outputs, not merely that functions returned no error.

## 2. Traceability Matrix

| Requirement | Required evidence |
|---|---|
| One primary bucket | Exhaustive producer classification test and schema rejection of zero/multiple buckets |
| Separate collection controls | Unit and integration tests proving disabled log/trace/metric construction stops independently |
| Mandatory local floor | Tests for every floor event class with bucket logs disabled; built-in local row present and all optional destinations absent |
| SQLite coverage | One-row-per-collected-log integration tests without a source SQLite destination or catch-all route |
| Multi-destination fan-out | One event persisted locally and delivered independently to a Splunk fake and two OTLP fakes |
| Capability, concise, and advanced routing | Omitted policy compiles to one all-bucket capability route; `send` compiles to one deterministic narrowing route; advanced send/drop ordering remains first-match-wins and destination-independent |
| Selector logic | AND across fields, OR within a field, wildcard rules, absent-field behavior, severity threshold |
| Per-destination redaction | Golden concise-send and advanced-route projections under none/sensitive/content/strict/custom profiles |
| Immutable canonical record | Deep equality before/after all destination projections and race testing |
| Fail-closed redaction | Injected detector/parser/serializer failures and safe delivered projection/health result |
| Profile-faithful content | Under `none`, governed content is preserved only in schema-defined content fields; under redacting profiles, sensitive canaries are absent everywhere those profiles govern; metrics never contain content labels |
| Atomic reload | Invalid reload keeps old graph; valid reload swaps once and drains old exporters |
| Runtime v8 cutover | Legacy block rejection and actionable pointer to automatic upgrade or optional preview |
| Automatic migration | Golden v7-to-v8 conversions, complete pre-write validation, atomic write/backup, secrets masked, retry/idempotence |
| Global retention | Fake-clock boundary tests across every history table and both databases |
| Preserve state tables | Reaper tests showing actions/snapshots/schema metadata remain |
| Finding semantics | Occurrence fields/remediation/evidence tests and explicit absence of synthetic workflow status |
| Compact/effective/reference config | Golden compact source, fully expanded masked effective view, and schema-generated reference parity |
| Comment preservation | CLI/TUI/setup mutations retain seeded ASCII/header/inline/route comments and ordering |
| Bucket evolution | Catalog-version tests prove future buckets remain in built-in local history and do not enter pinned optional-destination wildcards |
| Upgrade integration | One-command registered migration, ordinary confirmation/`--yes`, complete pre-write validation, exact-config backup/recovery, cursor semantics, and incompatible-start prevention |
| Rich trace contract | Golden agent/model/tool/retrieval/workflow/security graphs with exact families, parents/links, events, status/outcome, fields, limits, and redaction |
| Trace sampling invariants | Explicit collection-before-construction, unsampled-route, durable-log, parent-coherence, safe-decision-debug, and targeted-canary tests in section 9.2 |
| Simplified telemetry schemas | One logical registry with a small focused authoring set generates deterministic bundle/catalog/docs/constants/fixtures/projections; every current field has a migration disposition |
| Agent lifecycle and dashboard compatibility | PR #403 root/subagent lifecycle, execution, phase, operation, decision, real-time completion, and missing-data goldens plus PR #412 metric/label/bucket/cadence, UID, query, live inventory, and source/packaged dashboard checks |
| Push network safety | HTTP JSONL, OTLP, and Splunk tests cover every prohibited address class, guarded dialing/DNS rebinding, disabled redirects, failure isolation, and narrowly bounded private/CGNAT opt-ins |

Decision-level coverage for `D-001` through `D-022`, `S-001` through `S-011`, and
`P-001` through `P-046` is normative in `13-decision-traceability.md`; this matrix is
the requirement-level summary rather than a competing decision index.

## 3. Taxonomy Tests

### 3.1 Catalog completeness

Tests MUST enumerate:

- Every current `gatewaylog.EventType`.
- Every current `audit.Action`.
- Every registered span family.
- Every metric instrument.
- Every inbound OTLP normalization output.
- Every normalized projection writer.

The test fails when a new item lacks a bucket, stable name, signal, schema/field
classification, and mandatory-floor decision.

### 3.2 Boundary cases

Required cases:

- A guardrail evaluation with no findings and allow decision.
- A guardrail evaluation with a finding but no enforcement.
- A guardrail block caused by policy without a security finding.
- A tool request, its evaluation, its finding, and its block as separate records.
- A clean asset scan with no findings.
- A scan with multiple findings.
- Failed quarantine with no asset lifecycle transition.
- Successful quarantine with linked enforcement and lifecycle records.
- Config reload rejection producing compliance activity plus platform-health state.
- Administrative authentication failure as mandatory `compliance.activity`,
  inbound telemetry authentication failure as mandatory `telemetry.ingest`, and
  destination credential rejection as mandatory `platform.health`, each with the
  owning bucket's ordinary logs disabled and no credential value persisted.
- AI Defense finding represented as `security.finding` with `source: ai_defense`.
- Every current `WARN`/`WARNING` producer normalizes to security severity `MEDIUM`
  (optionally `log_level: WARN`); severity threshold tests use only the canonical
  five-rung ladder.
- Clean guardrail/judge `NONE` normalizes to canonical `INFO`, retains clean-decision
  semantics, validates successfully, and compares at the `INFO` route threshold.

### 3.3 No-duplication assertions

For each representative action, assert exact event counts and IDs. In particular,
the old audit-to-gateway bridge and direct writer fan-out must not produce a second
copy after producer migration.

## 4. Configuration Tests

### 4.1 Defaults

Verify:

- Every unspecified bucket: logs, traces, and metrics true with catalog
  `redaction_profile: none`; logs persist locally unredacted.
- Schema-defined model/tool/message/evidence/error/path content supplied by a
  producer is captured and preserved by default with no hidden second content gate;
  genuinely absent content remains `reported=false`.
- Unspecified `model.io`, `tool.activity`, and `diagnostic` follow the same
  full-fidelity default rather than a hidden exception.
- With no optional destination, nothing is remotely exported. A present enabled
  destination with no `send`/`routes` receives all catalog buckets, unredacted, and
  exactly its capability signals: logs for log-only kinds, metrics for Prometheus,
  and logs/traces/metrics for general OTLP.
- Bucket overrides affect only named fields and inherit the remainder.
- Effective redaction resolves concise-send/advanced-route, then bucket, then
  configured global default, then built-in `none`.
- Built-in local SQLite exists without source boilerplate and retention defaults to
  90 days.
- A present optional destination defaults to enabled.
- OTLP selected route signals automatically enable their transports; omitted policy
  selects all three transports.
- Omitted trace/metric policy resolves to parent-based always-on sampling for
  collected traces and 60-second delta metrics; the bundled collector converts
  delta sums to cumulative Prometheus series and Grafana advertises at least 60s.

### 4.2 Invalid configuration matrix

Startup/reload validation MUST reject:

- `kind: sqlite` under source `destinations`.
- Operator-authored destination name `local-sqlite`.
- `enabled`, `send`, `routes`, or `redaction_profile` under `observability.local`.
- Duplicate destination/route names.
- Unknown destination kind, bucket, signal, selector, profile, detector group, field class,
  or transformation mode.
- Empty selector value list.
- Wildcard mixed with other values.
- Unsupported signal for destination.
- A destination mixing `send` and `routes`.
- Concise `send` containing advanced selectors, exclusions, or route-only fields.
- `signal_overrides` naming a signal not selected by `send`/`routes`.
- Profile inheritance cycle.
- Custom profile extending or aliasing `none`.
- Empty effective detector groups for a `detect` mode, `credential: preserve`, or
  `preserve` on a dynamic content/reason/evidence/error/path class.
- Enabled OTLP destination with no selected signal or resolved endpoint.
- Legacy `signal_transports` or a transport-level `enabled` flag.
- Invalid protocol, TLS, listener, queue, batch, interval, sampler, or retention.
- Invalid/unsafe push endpoint, inline URL credentials, prohibited resolved address,
  or unsupported `network_safety` field/value.
- Unknown trace semantic profile, incompatible compatibility-alias setting, or
  trace limit outside safe/family-required bounds.
- Secret reference that cannot be resolved for an enabled destination.
- Legacy `otel`, `audit_sinks`, or `privacy.disable_redaction`.
- Legacy `observability.connectors[*].audit_sinks` while continuing to accept the
  separately typed notification-only `observability.connectors[*].webhooks` child.
- Unsupported explicit bucket catalog version or a bucket newer than the effective
  version.
- `bucket_sets`, `@set`, `observability.from`, or any include/source indirection.
- Duplicate YAML keys, merge keys, aliases, oversized source, or excessive parsed
  nodes/routes/profiles.

Validation errors must identify the YAML path and corrective action without printing
secret values.

### 4.3 Configuration UX and source tests

- An absent observability block and `observability: {}` are both valid and produce
  identical full-fidelity collection plus unredacted local-log defaults.
- A bare logs-only, Prometheus, and general OTLP destination each compile to the
  documented capability-default send without authoring route boilerplate.
- A concise Galileo destination with no `enabled`, route wrapper, route name,
  selector object, or signal-enable map compiles to the same effective graph as its
  explicit advanced equivalent.
- Source validation rejects generated effective-only fields and the reserved
  `local-sqlite` destination identity.
- Minimal source resolves to the documented full-fidelity defaults.
- `config show --source` identifies the source file and masks secrets.
- `config show --effective` expands defaults, generated local storage, concise send
  routes, derived OTLP transports, presets, profiles, and wildcard catalog
  membership with provenance.
- Reference YAML/Markdown/JSON Schema are generated from the same schema and CI
  detects drift.
- `observability plan` produces an accurate bucket/signal/destination matrix.
- `config validate` performs no network I/O; explicit destination tests use only a
  marked synthetic non-sensitive record and mask credentials/response bodies.
- Invalid source updates retain the previous runtime graph.
- Mutating an unrelated scalar/list preserves seeded ASCII header, section comments,
  inline comments, route comments, order, style where safe, permissions, and lock
  semantics.
- Full normalization is performed only by an explicit command.
- Legacy/standard observability environment variables do not silently override an
  explicit v8 policy; explicit secret references and documented bootstrap variables
  resolve with masked provenance.
- Go and Python validators accept/reject the same v8 fixtures, including exact
  detector groups `pii`, `credentials`, and `secrets`; each rejects an unknown
  detector group and unmodeled observability field.
- Migration goldens cover top-level `audit_db`, `judge_bodies_db`, `otel.logs`,
  gateway JSONL/console, JSONL rotation, `DEFENSECLAW_JSONL_DISABLE`,
  `DEFENSECLAW_DISABLE_REDACTION`, display-only `DEFENSECLAW_REVEAL_PII`, and
  connector audit-sink/webhook coexistence; explicit/absent
  `guardrail.retain_judge_bodies`, every recognized
  `DEFENSECLAW_PERSIST_JUDGE` off spelling, and true/false/absent
  `ai_discovery.emit_otel` preserve their effective behavior.
- CLI/TUI/API policy mutations persist source YAML before runtime reload; restart
  proves no in-memory-only policy drift.

### 4.4 Bucket catalog evolution

Use catalog fixtures v1 and v2 where v2 adds a synthetic sensitive bucket:

- A v1 config on a v2 runtime collects the new bucket’s logs to the built-in local
  store only.
- A v1 optional-destination wildcard does not match the v2 bucket.
- The generated local catch-all does match the v2 bucket.
- Doctor, TUI, and `observability plan` identify the unreviewed bucket.
- Explicitly naming the v2 bucket while declaring v1 is invalid.
- Advancing to v2 changes the effective route plan only after a preview/write
  action and creates compliance activity.
- Concise sends and advanced routes cannot explicitly reference the new bucket until
  the catalog version advances.
- Historical v1 records retain their original bucket IDs.
- A deprecation keeps the old ID valid/routable for its declared window and emits a
  lint/doctor warning; early removal is rejected.
- A split allocates new bucket IDs, preserves the old ID for historical records and
  compatibility input, and requires an explicit catalog-advance preview showing
  every affected optional route; historical rows are not rewritten.
- A merge follows the same rule: new records use the reviewed successor, old IDs
  remain queryable, aliases carry a removal version, and pinned wildcards do not
  broaden silently.
- Catalog validation rejects rename-by-deletion, split/merge without lifecycle and
  migration metadata, an alias removed before `removed_in`, and reuse of a retired
  bucket ID.

## 5. Routing Tests

Use a table-driven fake destination suite with these minimum cases:

| Destination policy | Record | Expected |
|---|---|---|
| logs-only kind, no `send`/`routes` | any collected log | deliver unredacted; traces/metrics unsupported |
| Prometheus, no `send`/`routes` | any eligible metric | expose full metric; logs/traces unsupported |
| general OTLP, no `send`/`routes` | any collected log/trace/metric | deliver all three signals, all catalog buckets; logs/traces use `none` |
| explicit concise `send` on OTLP | unselected bucket/signal | no delivery, proving explicit policy replaces rather than augments capability default |
| concise `send` selects finding logs | security finding | one generated send route delivers |
| `security.finding send`, `* drop` | security finding | send |
| `diagnostic drop`, `* send` | diagnostic | drop |
| `* send`, `diagnostic drop` | diagnostic | send, proving first match wins |
| bucket + source + connector | all fields match | send |
| bucket + source + connector | one field differs | unmatched |
| sources `[a,b]` | source b | send, proving OR |
| `min_severity: HIGH` | HIGH/CRITICAL | send |
| `min_severity: HIGH` | absent/MEDIUM | unmatched |
| no route matches | any | no delivery |

Fan-out test: one `security.finding` log is persisted locally and matches JSONL,
Splunk, and OTLP; it must appear once in each with the same record/correlation IDs
and each destination policy’s expected redaction.

Collection test: disable the same log at bucket collection; it appears nowhere.
Repeat with a mandatory compliance record; it appears once in the built-in local
store only.

## 6. Redaction Tests

### 6.1 Detector corpus

Include positive and negative corpora for each built-in detector, including:

- Realistic but non-live test credentials.
- Emails, phone numbers, national identifiers, and IP addresses.
- Luhn-valid and invalid card-shaped numbers.
- Connection strings and sensitive URL query values.
- Unicode-adjacent and multiline values.
- Multiple and overlapping matches.

No test fixture may contain a live credential.

### 6.2 Structural cases

- Nested maps and arrays.
- Unknown dynamic keys.
- Explicit schema field classes.
- Null, Boolean, number, and binary-encoded inputs.
- Maximum depth, field count, string size, and total output.
- Malformed JSON stored as a content string.
- Duplicate/fake placeholder text.

### 6.3 Properties

- Deterministic output.
- Idempotence.
- UTF-8 validity.
- Canonical record unchanged.
- Different destination outputs do not alias memory.
- HMAC/content hash validates final projected bytes.
- Failure injection under every redacting profile results in whole-field redaction,
  never an unintended switch to `none`; the intentional `none` profile bypasses
  detection but still fails closed on schema/serialization failure.
- Go and Python produce byte-identical `hash-v1` tokens for golden ordinary text,
  POSIX, Windows, UNC, relative-parent, Unicode, and URI values; key rotation changes
  key ID/digest, and unavailable keys fail closed without unkeyed hashing.

### 6.4 Canary test

Inject unique canary values into prompt, response, tool arguments, tool results,
evidence, reason, error, path, headers, and unknown dynamic fields. Search all
captured outputs, SQLite tables, trace attributes/events, metrics, health errors,
JSONL, and fake remote requests. In the default `none` case, canaries appear only in
the schema-defined content fields delivered to local storage and capability-default
destinations; they never become metric labels, resource attributes, headers, or
unrelated wrapper fields. Repeat with `sensitive`, `content`, and `strict` overrides
and prove their projected outputs contain no prohibited canary while a parallel
`none` destination remains unchanged.

## 7. SQLite and Projection Tests

- Fresh database migration.
- Upgrade from representative historical schema versions.
- One event-history row for every collected log.
- Correct bucket/event/source/profile/mandatory/provenance columns.
- Correct record schema and bucket catalog versions for historical interpretation.
- Correct redacted `payload_json` and content hash.
- Atomic event plus required projection insert.
- Projection failure rollback/degraded behavior.
- Concurrent readers and writers under WAL.
- SQLite initialization and disk/write failure behavior.
- Existing scan, alert, egress, activity, and judge query compatibility.
- No raw judge body in ordinary event/projection tables.
- New and migrated DB files preserve required owner/managed permissions, reject
  untrusted/symlinked paths, and never widen existing permissions.
- Disk-full/quota failure changes health safely and never causes a raw remote
  fallback.
- Per-projection HMAC verifies after redaction, differs for differently redacted
  projections, records key identity, and reports unsigned state when no key exists.
- Integrity documentation/tests do not imply deletion-proof or append-only storage.

## 8. Retention Tests

Use a fake clock; tests MUST NOT wait for wall time.

Required cases:

- Default 90-day cutoff.
- Row one nanosecond/second before cutoff is deleted.
- Row exactly at cutoff is retained.
- Row after cutoff is retained.
- `retention_days: 0` schedules no deletion.
- `retention_days: 0` produces the required persistent lint/doctor unbounded-capacity
  warning without exposing stored content.
- 1,001 eligible rows require two transactions with maximum batch size 1,000.
- Child findings deleted before parent scans with foreign keys enabled.
- All included event/evidence tables are covered.
- `actions`, `target_snapshots`, and schema metadata are preserved.
- Both legacy and separate judge-response tables are reaped.
- Cancellation stops between batches.
- Reload from 90 to 30 days affects the next asynchronous run.
- Reload to invalid retention leaves the old policy active.
- Contention with a reader/writer does not hold one unbounded transaction.
- Failure emits one rate-limited health transition and preserves undeleted data.
- No automatic blocking VACUUM.

## 9. OTel Tests

### 9.1 Traces

- Disabled bucket creates no recording span/body work.
- Enabled bucket adds `defenseclaw.bucket`.
- Every span carries registered family/schema/source/config-generation metadata and
  truthful available correlations.
- Sampling and collection both apply.
- Destination filters work independently.
- Span attributes, events, links, status descriptions, exceptions, content aliases,
  and vendor wrappers are independently redacted per destination.
- Trace/span IDs remain stable across projections.
- One OTLP destination failure does not stop another.
- Golden trace trees cover bounded agent turns, model streaming/retry, tools,
  approvals, guardrail phases/judges/findings/enforcement, retrieval/workflows,
  scans, discovery, network, ingest, reload, export, and canaries.
- OTel status distinguishes successful security block decisions from control
  failures and blocked requested operations; technical errors include stable
  `error.type`.
- Missing token/content/timing fields are not fabricated; reported/state metadata
  distinguishes absent, preserved, redacted, truncated, and failed-closed values.
- Attribute/event/link/byte overflow follows deterministic priority and preserves
  required identity/outcome.
- Galileo retains current agent/LLM/tool eligibility and validates new
  retriever/workflow and judge-chat shapes without affecting general OTLP
  destinations.

### 9.2 Sampling

- With bucket trace collection disabled, no span, attributes, events, content body,
  or sampling work is constructed even if the process sampler would record it.
- With collection enabled and `always_off` or a deterministically unsampled ratio
  decision, a matching destination route exports nothing; changing the route cannot
  resurrect the span.
- A finding and an enforced outcome produced inside an unsampled trace still create
  their required durable SQLite log records, with correlation available when known.
- Parent-based tests prove an unsampled parent produces non-recording children and no
  orphan exports, while a sampled parent preserves one coherent trace ID and valid
  parent/span relationships across children and destination projections.
- Sampling decision/reason appears only in bounded safe diagnostic/health metadata;
  it contains no prompt, result, evidence, header, credential, or arbitrary error
  text.
- Ratio sampling applies to ordinary operations. Only the exact targeted canary
  operation bypasses it, carries the canary marker, cannot enable sibling/parent
  production spans, and is acknowledged only by its selected destination.

### 9.3 Metrics

- Disabled bucket records no measurement.
- Instrument registry is exhaustive.
- Allowed attributes are bounded.
- Content canaries never appear as labels.
- Prometheus and OTLP filters independently include/exclude instruments.
- Temporality/interval validation rejects incompatible configuration.

### 9.4 Logs

- OTLP log body and attributes derive from the route projection.
- Individual finding emission honors collection and routes.
- Severity mapping follows the canonical vocabulary.
- Clean guardrail/judge producer severity `NONE` maps to canonical `INFO`; `WARN`
  maps to `MEDIUM`; neither creates an extra canonical rung.
- Existing resource/correlation fields are preserved.

### 9.5 Inbound receiver

- Logs, traces, and metrics normalize to expected buckets.
- Collection is enforced before re-export.
- Malformed input records safe telemetry-ingest rejection.
- No opaque decoded HEC/raw body bypass survives.
- Origin/hop handling prevents export loops.

### 9.6 Telemetry registry and generated schemas

- The logical registry’s focused authoring files validate together against the
  pinned OTel/GenAI registry dependencies and DefenseClaw extension rules.
- Generated JSON Schema bundle, compact catalog, Markdown reference, Go/Python
  constants/builders, field-class maps, fixtures, and Galileo/OpenInference
  projections are deterministic and checked for drift.
- Every current OTel schema field, event, name/kind pattern, and Galileo requirement
  has an explicit preserved/aliased/removed/corrected migration disposition.
- Real Go and Python producers are validated, not hand-built substitute objects.
- GenAI fields retain upstream name/type/meaning; security extensions remain in the
  `defenseclaw.*` namespace.
- Every compatibility alias equals the canonical destination-redacted value.
- A pinned upstream semantic-convention update produces a reviewed machine-readable
  diff and cannot enter through an ordinary dependency update.
- The public bundle resolves all `$ref` values and generated standalone views are
  equivalent to their bundle definitions.
- Changing an attribute's `field_class` or `sensitivity` fails the ordinary
  additive-change path and requires the security-breaking review/version evidence
  declared by the registry rules.
- Removing an alias before its declared `removed_in` version fails; removal at that
  version still requires the query migration, compatibility fixture update, and
  reviewed generated semantic diff.
- The `defenseclaw-genai-rich-v1` manifest entry resolves exactly the four pinned
  profile/version members; independent overrides and lock mismatches fail.
- The canonical record `schema_version` and span `family_schema_version` coexist in
  fixtures without collision or ambiguous generated names.

### 9.7 Agent lifecycle and local dashboards

- Import merged PR #403 and PR #412 fixtures before changing producers or schemas;
  each field/query receives a preserved, aliased, migrated, or intentionally
  corrected disposition.
- Root agent plus nested subagents retain distinct conversation, current-agent,
  root/parent-agent, root/parent-session, lifecycle, execution, operation, run,
  trace, and span identities. Delegation lineage remains distinct from OTel parent
  edges and typed links.
- Lifecycle events/states, depth, session source/resume, monotonically increasing
  per-execution sequence, and the immutable phase-code map `1..12` pass golden
  schema plus real-producer tests.
- A long-running session exports completed turn, model, tool, approval, decision,
  and transition work before any `Stop`/session-end hook. Duplicate/out-of-order
  completion does not duplicate spans, logs, or metric counts.
- `hook_decision` preserves raw versus effective action, mode, would-block,
  enforced, evaluation/rule correlation, and the enclosing lifecycle/execution
  identity without advancing phase/sequence or inventing a retry.
- Missing parent, content, tokens, cost, and timing remain absent/not-reported; no
  dashboard renders an invented zero or empty report.
- The generated `local-observability-v1` profile covers every metric, allowed
  label, exact histogram boundary, Loki field, Tempo attribute, dashboard variable,
  link, datasource UID, and dashboard UID consumed by the bundle.
- Critical PR #412 contracts include approval (`result`, `auto`, `dangerous`),
  connector-hook outcome (`action`, `connector`, `event_type`, `severity`,
  `would_block`), guardrail evaluation (`guardrail_action_taken`,
  `guardrail_connector`, `guardrail_scanner`), and schema violation (`code`,
  `event_type`) labels plus the exact hook-latency histogram buckets.
- Gateway metrics default to 60-second delta export; the local Collector performs
  delta-to-cumulative conversion through one application remote-write path; the
  Grafana Prometheus datasource interval is at least 60 seconds.
- Agent360 durable counts/chronology use Loki, aggregates/phase/topology use
  Prometheus, and trace search/waterfall use Tempo. Static tests fail if a panel
  silently changes those semantics.
- All fourteen dashboard UIDs and the three stable datasource UIDs are unique and
  provisioned. Source and CLI-packaged dashboards/config are byte-identical.
- Static validation rejects nonexistent labels/fields and bad percentile/legend/
  bucket/cadence/query shapes. Live validation classifies expected-idle,
  unexpected-empty, and backend-unavailable instead of accepting every `No data`.

## 10. Reload and Concurrency Tests

- Valid reload swaps the graph exactly once.
- Invalid parse/validation/exporter initialization retains the exact old graph.
- Concurrent producers see either old or new policy, never a partially built mix.
- Removed exporter drains within deadline.
- Changed route affects new records only; queued projected payloads retain old
  projection/profile.
- SQLite path and judge-body path reload are rejected as restart-required.
- Retention age reload is accepted.
- Race detector reports no mutation of canonical records or policy snapshots.

## 11. Migration Tests

Golden fixtures MUST cover:

- Named OTel destinations with all signal combinations.
- Named `local-observability` destination with logs/traces/metrics, loopback/private
  endpoint intent, full `local-observability-v1` capability, and a deliberately
  narrowed fixture that preserves intent while reporting partial dashboard support.
- Galileo preset and span filter.
- Current resource/metrics/runtime-span/event schema set imported into the one
  registry with generated-artifact parity.
- Audit JSONL, Splunk, HTTP JSONL, and OTLP log sinks.
- Same endpoint but different credentials or batching, proving no unsafe merge.
- Connector-specific inherit, replace, and suppress behavior.
- Redaction enabled and globally disabled.
- Judge-body retention with explicit true/false, absent default true, and every
  off-like `DEFENSECLAW_PERSIST_JUDGE` value; migrated v8 ignores later environment
  changes and retains the materialized choice.
- `ai_discovery.emit_otel` true/false/absent, proving false does not disable local
  discovery logs and true preserves only the legacy OTLP signal intent without a
  second runtime emission gate. The baseline inventory test also proves there is no
  unhandled connector-level `emit_otel` config field.
- Inline and environment/key-store credential forms.
- Already-v8 input.
- Malformed/partially migrated input.

Assertions:

- Dry-run changes no bytes, timestamps, or permissions.
- Diff and error output contain no resolved secret.
- The normal upgrade creates the expected backup and atomically writes valid v8
  YAML through the registered required migration.
- Unrelated config remains semantically identical.
- Existing comments and ASCII guidance survive automatic migration.
- Migration emits no source SQLite destination/catch-all, uses concise `send` where
  one selector is sufficient, and uses advanced routes only when legacy exclusions
  or detailed selectors require them.
- A migrated destination never omits both `send` and `routes` unless its v7 behavior
  was already every supported signal, every catalog bucket, unredacted. Redacted or
  narrower v7 installations receive explicit collection/profile/routes and do not
  broaden to the fresh-v8 defaults.
- Migrated OTLP policy uses route-derived signals plus `signal_overrides`, not a
  second signal-enable map.
- Active migrated destinations omit redundant `enabled: true`; disabled legacy
  destinations retain explicit `enabled: false`.
- Generated config passes gateway and Python CLI parsing.
- The migration cursor records the conversion only after successful activation;
  already-v8 and retry cases do not duplicate output.
- Running v8 gateway rejects original legacy blocks with actionable instructions.
- The installed local bundle backup/refresh preserves arbitrary custom files and
  every history volume, refreshes mutually compatible DefenseClaw-owned Collector/
  datasource/dashboard/rule files, and restarts/verifies a previously running
  stack without a separate migration command.

## 12. End-to-End Scenarios

### E2E-1: Full-fidelity local default

- Use an otherwise empty observability block; do not configure a local destination.
- Produce one record from each bucket.
- Verify every defined signal is collected, every collected log is stored locally
  unredacted, no network exporter starts, and model/tool/diagnostic families have no
  hidden default exception.

### E2E-2: Multi-destination security operations

- Configure JSONL, Splunk fake, and general OTLP fake; use automatic local storage.
- Emit a high finding and successful block.
- Verify exactly one finding/action per expected destination, correlations match,
  redaction differs as configured, and local SQLite projections are queryable.

### E2E-3: AI Defense source filtering

- Route `security.finding` where `source: ai_defense` to a dedicated OTLP endpoint.
- Emit equivalent findings from AI Defense and CodeGuard.
- Verify only the AI Defense record reaches that endpoint while both remain local.

### E2E-4: Galileo traces only

- Enable model/tool/agent/guardrail traces and Galileo OTLP traces.
- Disable model/tool logs.
- Verify Galileo receives compliant redacted agent, model, tool, retriever,
  workflow, and judge-chat spans with current correlation fields plus safe security
  events; no content logs are created and metrics follow their independent policy.
- Verify native guardrail/policy/scan/health spans remain present at a general OTLP
  destination and are not misclassified merely to pass Galileo compatibility.
- Verify observed/eligible/ineligible/attempted/delivered/partial/rejected/failed
  counters and exact-trace canary acknowledgement.

### E2E-5: Capability-default export

- Add enabled JSONL, Prometheus, and general OTLP destinations with transport fields
  but no `send` or `routes`.
- Verify JSONL receives every log, Prometheus exposes every eligible metric, and
  OTLP receives every eligible log, trace, and metric; all content-bearing
  projections use `none`.
- Add an explicit strict destination and verify it remains redacted while the
  capability-default destinations remain unredacted.
- Verify effective/plan/doctor/TUI display generated routes, all-bucket membership,
  capability signals, and `none` plainly, without requiring a warning.

### E2E-6: Exporter isolation

- Make one remote exporter fail and fill its queue.
- Verify the built-in local store and other exporters continue, drops/health are
  bounded and visible, and recovery transitions to healthy.

### E2E-7: Retention

- Seed both databases and all event tables around a fake cutoff.
- Run reaper.
- Verify exact rows removed/preserved and current state unchanged.

### E2E-8: Atomic reload

- Begin with a valid graph and active traffic.
- Attempt invalid reload; verify old routing continues.
- Apply valid reload; verify new traffic follows the new graph and old exporter drains.

### E2E-9: Root agent, subagents, and local dashboards across upgrade

- Start the current bundled stack and emit a root session with two turns, reported
  and unreported model usage, tool/approval, raw-versus-effective hook decision,
  direct and nested subagents, compaction, resume, and a completed operation before
  session end.
- Run the ordinary upgrade and automatic v8 config/local-bundle migration while
  preserving Prometheus, Loki, Tempo, and Grafana volumes.
- Emit a second execution after upgrade. Verify stable lifecycle and root lineage,
  new execution identity, monotonic per-execution sequence, correct phase codes,
  no duplicate old/new pipeline events, and completed activity visible before
  `Stop`.
- Validate all fourteen Grafana UIDs and every query inventory entry. Agent360 must
  show the root tree, both executions, exact Loki chronology/counts, Prometheus
  phase/topology/latency, reported versus not-reported usage/cost, decision recovery,
  and a Tempo waterfall while historical pre-upgrade data remains queryable.

## 13. Security and Robustness Tests

- Fuzz canonical event parsing and dynamic body traversal.
- Fuzz route selectors and config decoding.
- Fuzz redaction around Unicode boundaries and malformed encodings.
- For each HTTP JSONL, OTLP, and Splunk adapter, endpoint validation and the actual
  dial path reject loopback, RFC1918, IPv6 ULA, RFC 6598, link-local, unspecified,
  multicast/reserved, mixed public/private answers, and representative cloud and
  container metadata/task-credential endpoints.
- DNS-rebinding tests validate a public answer followed by a private dial answer;
  the guarded dial rejects it. Redirect tests prove exporters do not follow any hop.
- Temporary DNS/network failure sends no request and degrades only that destination;
  an unsafe literal/resolution rejects the candidate graph and leaves the old graph
  active.
- `allow_private_networks` permits only loopback/RFC1918/IPv6 ULA and
  `allow_cgnat` permits only RFC 6598. Both produce warnings/audit. Link-local,
  metadata/task-credential, unspecified, multicast/reserved, and inline credentials
  remain blocked under both opt-ins; no environment-only bypass works.
- TLS certificate and hostname validation defaults secure.
- Header/token masking across error, health, doctor, TUI, migration, and compliance
  output.
- Log-injection/newline handling for console, JSONL, and HEC.
- Compression and decompression size limits.
- Inbound record and batch size limits.
- Queue and cardinality exhaustion tests.
- Recursive health/export failure guards.

## 14. Performance Acceptance

Benchmarks must be captured before and after producer migration on the same machine:

- Disabled log, trace, and metric hot paths.
- One built-in-local-only log.
- One locally persisted log plus three in-memory fake destinations.
- Sensitive redaction of representative plain text and nested JSON.
- Rich agent/model/tool/retrieval/workflow/guardrail span creation and one-, two-,
  and four-destination projection.
- Metric recording.
- Reaper batches of 1,000 rows under concurrent reads.

Acceptance requirements:

- Disabled collection does not construct content payloads or invoke redaction.
- Remote network I/O is absent from producer goroutines.
- Memory remains bounded by configured queue and payload limits.
- Reaper transactions never exceed the specified batch size.
- No benchmark shows uninvestigated time or allocation regression greater than 10%
  against the approved baseline; intentional regressions require documented review.

## 15. Commands Required in PR Test Plans

At minimum, after implementation paths exist, run and record observed results for:

```bash
go test ./internal/config ./internal/redaction ./internal/gatewaylog ./internal/audit ./internal/telemetry ./internal/scanner ./internal/gateway -count=1
go test -race ./internal/config ./internal/redaction ./internal/gatewaylog ./internal/audit ./internal/telemetry -count=1
go test ./test/e2e -run 'Observability|V8' -count=1
uv run python -m pytest cli/tests -q
go vet ./...
make check-schemas
make check-grafana-dashboards
uv run python -m pytest cli/tests/test_agent360_dashboard.py cli/tests/test_grafana_dashboards.py -q
make check-upgrade-manifest
make upgrade-smoke-matrix ARGS="--baseline-mode seed"
```

Phase PRs may run a justified subset while stacked, but the final integration PR
must run the full list plus the applicable end-to-end harnesses. The release job
also runs the finalized-artifact matrix with `--release-dir dist` and, against the
started local stack:

```bash
python scripts/check_grafana_dashboards.py --live --inventory --require-packaged
```

PR descriptions must show actual pass/fail counts or command results, not only
intended commands.

## 16. Automatic Upgrade Tests

### 16.1 Candidate generation and validation

- One ordinary `defenseclaw upgrade` detects supported v7 configuration and creates
  the expected deterministic v8 candidate.
- The automatic flow and optional standalone command generate byte-equivalent
  semantic candidates from the same fixture.
- Candidate generation and target validation complete before either active source
  file is replaced.
- Invalid, unsupported, or ambiguous v7 input fails with source files and migration
  cursor unchanged and never starts a v8 gateway against the v7 source.
- An already migrated v8 source is a no-op; retries do not duplicate destinations,
  routes, or database migrations.
- Migration output and the normal confirmation summary contain no resolved secrets
  or governed content.

### 16.2 Backup and atomicity

- Exact config bytes, mode, ownership metadata, path, and hash are captured before
  replacement.
- Comment-heavy fixtures preserve ASCII guidance, comments, order, unrelated
  sections, and safe scalar/list style.
- Config activation uses locking, temporary files, fsync, and atomic rename.
- A failure before rename never exposes a partial v8 file.
- Insufficient permissions or disk space fail before gateway shutdown where they
  can be determined locally.

### 16.3 Success, failure, and rollback

- Interactive upgrade uses the existing confirmation; noninteractive upgrade uses
  ordinary `--yes` with no additional plan/hash/phrase step.
- A successful upgrade starts v8, activates the expected config generation, writes
  SQLite, compiles the observability graph, and marks the existing migration cursor
  complete.
- Inject failures before validation and during multi-file config activation. The
  exact v7 source bytes remain or are restored, the cursor remains unapplied, and
  the v8 gateway is not started against v7 configuration.
- When the existing previous-gateway snapshot is used for recovery, v7 starts only
  after its exact source bytes are active.
- The additive v8 database schema remains readable by the immediately previous
  supported release.
- An unavailable optional remote exporter reports degraded runtime health but does
  not roll back a healthy gateway with writable SQLite.
- Re-running after interruption or rollback is safe and converges on one valid v8
  configuration.

### 16.4 Permissions and historical matrix

- Administrator-owned/read-only config fails the upgrade permission preflight
  without chmod, replacement, or service interruption and identifies the path that
  must be made writable by its owner.
- The release matrix covers every supported v7 baseline with named OTel
  destinations, audit sinks, connector overrides, global redaction disablement,
  JSONL/console behavior, Galileo, non-default paths, WAL databases, and
  comment-heavy YAML.
- Direct v8 gateway startup with v7 configuration rejects it and points first to
  `defenseclaw upgrade`, with the standalone preview as an optional diagnostic.
- A seeded local-observability bundle is backed up and refreshed automatically;
  custom files and persistent volumes survive, DefenseClaw-owned files match the
  target package, a previously running stack is restarted/verified, and optional
  stack failure is reported as degraded without rolling back a healthy gateway.
- When refresh/restart is fault-injected, the immediately previous PR #403/#412
  dashboard query contract still returns data through declared aliases, while
  upgrade/doctor reports the stale bundle and target-only capability gap.

## 17. Release Gates

Release is blocked until:

- Every catalog item is classified.
- Every collected log reaches SQLite exactly once.
- Canary tests prove content appears only where the effective `none` policy and
  schema allow it and is removed by every configured redacting profile.
- Effective unredacted/redacted policies are visible, and every policy mutation is
  audited.
- Legacy configuration rejection and migration are documented and tested.
- No duplicate old/new pipeline outputs remain.
- Retention protects current-state tables.
- All enabled destinations have independent health and failure isolation.
- Invalid live reload is proven non-disruptive.
- CLI, gateway, TUI, doctor, schemas, examples, and dashboards agree on v8.
- PR #403 root/subagent lifecycle and real-time traceability goldens pass, including
  operation completion without `Stop`, final hook decisions, and truthful missing
  usage/cost/content.
- PR #412 metric/label/histogram/cadence corrections remain intact;
  `local-observability-v1`, all fourteen dashboard UIDs, three datasource UIDs,
  source/packaged parity, and static/live query inventories pass.
- One-command upgrade refreshes compatible local-stack assets without resetting
  Prometheus/Loki/Tempo/Grafana history or requiring another migration command.
- Source/effective/reference views agree, comment-preserving mutation passes, and
  bucket catalog evolution cannot cause silent new optional-destination delivery.
- Historical one-command upgrades, failure injection, exact-config recovery,
  retry/idempotence, and permission tests pass for the v8 boundary.
- The repository-required PR structure and linked-follow-up rule are satisfied.
