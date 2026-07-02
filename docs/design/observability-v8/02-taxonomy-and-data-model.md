# Taxonomy and Canonical Data Model

## 1. Classification Principle

Buckets describe the semantic fact being recorded, not the vendor that produced it,
the destination receiving it, or the subsystem that happened to emit it.

- Cisco AI Defense is represented as `source: ai_defense`, not as a bucket.
- Galileo is represented as an OTLP destination preset, not as a bucket.
- “Audit” is a durability and governance property. Operator control-plane actions
  use `compliance.activity`; other buckets can also be mandatory audit records.
- A record MUST have one primary bucket. It MAY have source, connector, action,
  event-name, severity, phase, outcome, and correlation dimensions.

## 2. Bucket Catalog

The following fourteen IDs are bucket catalog version 1. IDs are stable public
contracts; future additions and deprecations follow the process in
`09-configuration-ux-and-bucket-evolution.md`.

### 2.1 `compliance.activity`

Purpose: durable control-plane audit trail for user, service, and system actions.

Example event names:

- `config.change.attempted`
- `config.change.applied`
- `config.reload.rejected`
- `policy.updated`
- `redaction.profile.updated`
- `destination.updated`
- `observability.profile.changed`
- `approval.resolved`
- `alert.acknowledgement.requested`
- `alert.dismissal.requested`
- `authentication.failed`
- `authorization.denied`

Example data: actor, actor type, authentication mechanism, origin, action, target,
sanitized before/after summary, outcome, reason, revision, and correlation IDs.

`authentication.failed` and `authorization.denied` belong here when the attempted
access is to an administrative/operator control-plane boundary. Actor identity may
be unknown; the record stores only safe origin/mechanism/result metadata and never
the submitted credential.

Default sensitivity: high. Default signal recommendation: logs. Traces and metrics
are normally unnecessary except aggregate mutation/error metrics.

### 2.2 `security.finding`

Purpose: one concrete security-risk observation produced by a scanner, detector,
correlator, admission control, runtime inspection, network control, or external
security system.

Example event names:

- `finding.observed`
- `finding.correlated`

Example data: occurrence ID, stable rule ID, category, title, severity, confidence,
source, target reference, safe location, evidence summary, evidence fingerprint,
optional redacted excerpt, optional remediation guidance, scan/evaluation ID, and
correlation IDs.

A finding is not the automatic final state of every guardrail evaluation. One
evaluation or scan can produce zero, one, or many findings.

Default sensitivity: high. Default signal recommendation: logs and bounded count
metrics. Finding details MUST NOT be metric attributes.

### 2.3 `guardrail.evaluation`

Purpose: one execution of a policy, detector, classifier, judge, or inspection
control and the resulting decision.

Example event names:

- `guardrail.evaluation.started`
- `guardrail.evaluation.completed`
- `guardrail.evaluation.failed`
- `hook_decision` (preserved compatibility event name for the final
  connector-facing result)

Example data: evaluation ID, stage, policy and rule-set versions, detector sources,
scores, matched rule IDs, decision, would-block, enforced, duration, input reference
or hash, finding IDs, and enforcement-action IDs.

This bucket MUST NOT contain a duplicate full prompt, response, tool argument set,
or tool result. It references `model.io` or `tool.activity` records and may contain
minimal redacted evidence.

`hook_decision` belongs primarily to `guardrail.evaluation`: it records the raw
guardrail action and the effective action returned after mode/capability mapping.
When `enforced: true` means an actual control was imposed, a separate linked
`enforcement.action` record owns that enforced attempt/outcome and qualifies for
the mandatory floor. The two records share evaluation/action/agent correlation but
do not duplicate model/tool content.

Default sensitivity: medium/high. Default signal recommendation: verdict logs,
evaluation traces, and aggregate metrics.

### 2.4 `enforcement.action`

Purpose: an actual attempt to impose or remove a control.

Example event names:

- `enforcement.block.requested`
- `enforcement.block.applied`
- `enforcement.block.failed`
- `enforcement.quarantine.applied`
- `enforcement.release.applied`
- `enforcement.redaction.applied`
- `enforcement.access.revoked`

Example data: action ID, action, target, requested/effective mode, initiator,
evaluation or finding references, outcome, reason, failure class, previous state,
and resulting state.

An action can fail without causing a lifecycle transition. Enforced outcomes are
part of the mandatory floor.

Default sensitivity: medium. Default signal recommendation: logs and aggregate
metrics; traces when action latency matters.

### 2.5 `model.io`

Purpose: interaction with a model provider.

Example event names:

- `model.request`
- `model.response`
- `model.stream.completed`
- `model.call.failed`

Example data: request/response ID, provider, model, operation, role structure,
prompt or response content when reported by the producer, content hashes, token counts, finish reason,
streaming state, latency, retry, and error class.

This is the canonical home of model content. Other buckets MUST reference these
records rather than copy their content.

Default sensitivity: critical. Default signal recommendation: traces and aggregate
metrics; content logs only through explicit policy.

### 2.6 `tool.activity`

Purpose: requested and completed agent tool interactions.

Example event names:

- `tool.invocation.requested`
- `tool.invocation.started`
- `tool.invocation.completed`
- `tool.invocation.blocked`
- `tool.invocation.failed`

Example data: invocation ID, tool name and class, caller, target, argument metadata
or reported content, result metadata or reported content, status, duration,
exit code, and error class.

Guardrail evaluation of a tool is a separate linked record. The evaluation is not a
superset of the tool record.

Default sensitivity: critical. Default signal recommendation: traces and aggregate
metrics; detailed logs by explicit policy.

### 2.7 `asset.scan`

Purpose: execution state and roll-up result of scanning an asset or content target.

Example event names:

- `scan.started`
- `scan.phase.completed`
- `scan.completed`
- `scan.failed`
- `scan.cancelled`

Example data: scan ID, scanner and rule-set version, target and revision, phases,
coverage, skipped checks, duration, exit state, maximum severity, and finding counts.

This is the scan process and summary. Individual issues are `security.finding`
records. A clean scan still produces `asset.scan` records and no findings.

Default sensitivity: medium. Default signal recommendation: summary logs, phase
traces, and duration/count metrics.

### 2.8 `asset.lifecycle`

Purpose: observed changes to the state of governed assets such as skills, MCP
servers, plugins, models, agent packages, policies, and other admitted components.

Example event names:

- `asset.discovered`
- `asset.registered`
- `asset.updated`
- `asset.admitted`
- `asset.activated`
- `asset.quarantined`
- `asset.released`
- `asset.disabled`
- `asset.removed`

Example data: asset ID, type, source, previous and new state, revision, provenance,
reason, and related scan or enforcement IDs.

If quarantine succeeds, emit one `enforcement.action` record for the attempted
control and one `asset.lifecycle` record for the resulting state transition. If
quarantine fails, emit the failed enforcement record but no false lifecycle change.

Default sensitivity: medium. Default signal recommendation: logs and inventory
metrics.

### 2.9 `network.egress`

Purpose: outbound network activity and its policy disposition.

Example event names:

- `egress.requested`
- `egress.allowed`
- `egress.blocked`
- `egress.completed`
- `egress.failed`

Example data: destination classification, redacted or normalized host, port,
protocol, method class, byte counts, policy rule, disposition, duration, and related
agent/tool/model identifiers.

Credentials, query secrets, full request bodies, and full response bodies MUST NOT
be included by default.

Default sensitivity: high. Default signal recommendation: metadata logs, traces,
and aggregate metrics.

### 2.10 `agent.lifecycle`

Purpose: lifecycle of an agent, session, run, or connector runtime.

Example event names:

- `session_start`
- `session_end`
- `subagent_start`
- `subagent_stop`
- `turn_start`
- `turn_end`
- `tool_start`
- `tool_end`
- `compact_start`
- `compact_end`
- `event`

Example data: conversation/current/root/parent agent, root/parent session, stable
lifecycle, execution attempt, operation, run, connector, depth, state, phase,
previous phase, immutable phase code, monotonically increasing per-execution
sequence, session source/resume state, transition, reason, and available user
correlation.

The required lifecycle vocabulary, identity semantics, phase-code mapping, and
root/subagent compatibility floor are defined in
`14-agent-lifecycle-and-dashboard-compatibility.md`. Delegation lineage is not the
same as OTel trace parentage. Completed turn/model/tool work remains visible before
a later `session_end`/`Stop` event.

Default sensitivity: low/medium. Default signal recommendation: logs, traces, and
availability metrics.

### 2.11 `ai.discovery`

Purpose: discovery of AI-related components and evidence supporting that discovery.

Example event names:

- `ai_component.discovered`
- `ai_component.changed`
- `ai_component.removed`
- `ai_component.confidence.changed`

Example data: component ID and type, detector, confidence, evidence types, scrubbed
basenames, hashes, match kind, and observed time.

Raw paths and arbitrary source contents MUST NOT be exported as discovery evidence.

Default sensitivity: medium. Default signal recommendation: change logs and bounded
inventory metrics.

### 2.12 `telemetry.ingest`

Purpose: inbound telemetry receiver behavior, normalization, and admission.

Example event names:

- `telemetry.batch.accepted`
- `telemetry.batch.rejected`
- `telemetry.batch.normalized`
- `telemetry.records.dropped`
- `telemetry.authentication.failed`
- `telemetry.authorization.denied`

Example data: protocol, signal, source connector, record count, byte count, schema
version, normalization result, rejection reason class, and latency.

Receiver authentication/authorization failures belong here because the protected
boundary is inbound telemetry admission. They are mandatory-floor logs even if
ordinary `telemetry.ingest` logs are disabled.

Opaque raw transport bodies MUST NOT bypass canonical routing. In particular,
special decoded HEC bodies must be normalized or safely summarized.

Default sensitivity: low/medium. Default signal recommendation: health logs and
metrics; diagnostic traces when troubleshooting ingestion.

### 2.13 `platform.health`

Purpose: operational state of DefenseClaw subsystems and observability components.

Example event names:

- `subsystem.ready`
- `subsystem.degraded`
- `subsystem.restored`
- `destination.queue_full`
- `destination.export_failed`
- `sqlite.write_failed`
- `schema.validation_failed`
- `redaction.failed_closed`
- `destination.authentication.failed`
- `destination.authorization.denied`

Example data: subsystem or destination, state transition, stable error code, retry
state, dropped count, queue utilization, and sanitized cause class.

Outbound exporter/destination credential rejection belongs here as component
health, not as operator authentication. These failure events are mandatory-floor
logs and MUST NOT include a token, authorization header, or credential value.

Default sensitivity: low. Default signal recommendation: logs and metrics. Health
records MUST avoid embedding the failed content.

### 2.14 `diagnostic`

Purpose: temporary developer troubleshooting that does not fit a stable production
event contract.

Example event names:

- `diagnostic.message`
- `diagnostic.snapshot`

Example data: component, bounded message, and classified fields.

Diagnostics MUST NOT be used as a shortcut around stable buckets. They are disabled
by recommended production profiles and must still pass central redaction.

Default sensitivity: high and unpredictable. Default signal recommendation:
disabled unless temporarily enabled.

### 2.15 Catalog v1 source defaults

These are the normative effective values when neither `observability.defaults` nor
a bucket override is present. Catalog v1 is intentionally full-fidelity: every
bucket collects every supported signal and uses `none` redaction. Operators narrow
collection or add redaction explicitly.

| Bucket | Logs | Traces | Metrics | Redaction |
|---|---:|---:|---:|---|
| `compliance.activity` | true | true | true | `none` |
| `security.finding` | true | true | true | `none` |
| `guardrail.evaluation` | true | true | true | `none` |
| `enforcement.action` | true | true | true | `none` |
| `model.io` | true | true | true | `none` |
| `tool.activity` | true | true | true | `none` |
| `asset.scan` | true | true | true | `none` |
| `asset.lifecycle` | true | true | true | `none` |
| `network.egress` | true | true | true | `none` |
| `agent.lifecycle` | true | true | true | `none` |
| `ai.discovery` | true | true | true | `none` |
| `telemetry.ingest` | true | true | true | `none` |
| `platform.health` | true | true | true | `none` |
| `diagnostic` | true | true | true | `none` |

“True” means that a producer records the signal when that bucket defines the
corresponding log family, span family, or metric instrument. It does not require
inventing a meaningless metric or span merely to fill the matrix.

For a collected log or trace, full-fidelity defaults also enable capture of the
family's schema-defined prompt, response, message, tool argument/result, evidence,
reason, error, and path fields when the producer has them. Missing producer data
remains honestly unreported; it is never fabricated.

## 3. Canonical Record Envelope

Every canonical record MUST carry:

| Field | Requirement |
|---|---|
| `schema_version` | Required; canonical record schema version |
| `bucket_catalog_version` | Required; catalog version under which the bucket assignment was emitted |
| `timestamp` | Required UTC event time |
| `observed_at` | Optional UTC receive/observe time when different |
| `record_id` | Required unique occurrence ID |
| `bucket` | Required catalog value |
| `signal` | Required: logs, traces, or metrics |
| `event_name` | Required stable registry ID: normally a dotted log event, trace family ID, or metric instrument ID, with registry-declared canonical snake_case lifecycle/compatibility names such as `session_start` and `hook_decision` also valid; route selectors never depend on a rendered high-cardinality span name |
| `span_name` | Trace-only OTel display/operation name derived from the registered family pattern, such as `chat {model}` |
| `severity` | Optional for records without severity semantics |
| `log_level` | Optional operational logging level; separate from security severity |
| `source` | Required stable producer identity such as `ai_defense`, `codeguard`, `gateway`, or `operator_api` |
| `connector` | Optional connector identity |
| `action` | Optional stable action vocabulary |
| `phase` | Optional lifecycle/evaluation phase |
| `outcome` | Optional stable outcome vocabulary |
| `mandatory` | Required Boolean for log records; true only for floor-qualified semantics |
| `correlation` | Required object, possibly empty, containing known join keys |
| `provenance` | Required producer, binary, schema/catalog, and configuration generation metadata |
| `body` | Required typed payload for logs and span events; metrics use instrument data |
| `field_classes` | Required internally or derivable from schema for all dynamic body fields |

The envelope `schema_version` is the version of the complete canonical record shape.
It is distinct from the telemetry registry version and from a span family's
`family_schema_version`.

### 3.1 Correlation fields

The envelope MUST preserve known identifiers without inventing values:

- run ID
- request ID
- session ID
- turn ID
- trace ID
- span ID
- agent ID
- agent instance ID
- policy ID/version
- evaluation ID
- scan ID
- finding occurrence ID
- enforcement action ID
- model request/response ID
- tool invocation ID
- destination ID when the record concerns a destination
- connector ID
- sidecar instance ID

### 3.2 Action, phase, decision, and outcome

These fields have different jobs and MUST NOT be used interchangeably:

- `action` names the requested operation, such as `config.change`, `block`,
  `quarantine`, or `release`.
- `phase` names bounded progress inside an operation, such as `attempt`, `validate`,
  `apply`, or `finalize`.
- A typed body `decision` records a domain verdict such as `allow`, `block`, `deny`,
  `review`, or `redact` when that family defines decision semantics.
- `outcome` records the observed result of the record's subject.

The canonical v8 outcome vocabulary is:

`attempted`, `validated`, `applied`, `completed`, `allowed`, `blocked`, `denied`,
`approved`, `quarantined`, `redacted`, `revoked`, `released`, `terminated`,
`rejected`, `failed`, `timed_out`, `cancelled`, `partial`, `skipped`, and
`no_change`.

Each family schema declares the applicable subset. Producers MUST NOT introduce an
unregistered family-specific synonym. For example, a successfully executed
guardrail that decides to block uses `decision: block` and `outcome: blocked`; its
OTel status can still be OK because the control itself succeeded. A configuration
mutation record uses the existing control-plane subset `attempted`, `validated`,
`applied`, `rejected`, or `failed`.

## 4. Severity

Canonical security severity uses the five-level vocabulary already ranked by
`internal/audit.SeverityRank` and scanner findings:

`INFO < LOW < MEDIUM < HIGH < CRITICAL`

DefenseClaw currently has two producer ladders: audit/scanner records use
`INFO..CRITICAL`, while guardrail/judge evaluation uses
`NONE < LOW < MEDIUM < HIGH < CRITICAL`. `NONE` means a clean evaluation with no
security concern; it is a valid producer value but not a sixth canonical security
rung. Both producer ladders merge into the five canonical values below.

`WARN`/`WARNING` is not a sixth security rung. Current code uses it in some
`gatewaylog`, audit, and OTel operational paths, but the audit/scanner comparison
functions do not rank it consistently. v8 resolves that inconsistency as follows:

| Producer value | Canonical `severity` | Optional `log_level` |
|---|---|---|
| `NONE` (clean guardrail/judge evaluation) | `INFO` | Absent unless the producer also has an operational level |
| `DEBUG` | `INFO` when a severity is required; otherwise absent | `DEBUG` |
| `INFO` | `INFO` | `INFO` |
| `LOW` | `LOW` | Producer level if known |
| `WARN` / `WARNING` (including `slog` WARN) | `MEDIUM` | `WARN` |
| `MEDIUM` / `MED` | `MEDIUM` | Producer level if known |
| `ERROR` | `HIGH` | `ERROR` |
| `HIGH` | `HIGH` | Producer level if known |
| `FATAL` / `CRITICAL` | `CRITICAL` | `FATAL` when applicable |

The original producer value MAY be retained as bounded metadata. Unknown severity is
invalid when a specific event contract requires severity and is otherwise absent,
not silently coerced to `INFO`.

The original `NONE` value remains expressible through the evaluation decision/result
fields and MAY also be retained as bounded producer metadata. It must never cause a
clean evaluation record to fail schema validation.

`min_severity` route comparison uses only the five canonical values. A record without
severity does not match a selector containing `min_severity`. `log_level` is not a
substitute for security severity and is not used by `min_severity` in v8.

## 5. Security Finding Contract

### 5.1 Required fields

A `security.finding` log MUST include:

- Unique occurrence `finding_id`.
- Stable `rule_id` or producer namespaced detection ID.
- `title`.
- Canonical severity.
- `source`.
- Target reference.
- Scan ID or evaluation ID when produced by a scan/evaluation.

### 5.2 Optional fields

- Category.
- Confidence in `[0,1]`.
- Safe location and line number.
- Evidence summary.
- Evidence fingerprint.
- Redacted evidence excerpt.
- Remediation guidance.
- Tags from a bounded or source-qualified vocabulary.

### 5.3 Evidence summary generation

The pipeline MUST NOT ask a general-purpose model to invent an evidence summary.
The normalizer chooses the first available source:

1. A producer-supplied structured, already bounded summary.
2. A deterministic versioned template associated with the rule ID.
3. A deterministic fallback: rule title, target type, and safe location.

The summary MUST NOT contain the complete matched credential, prompt, response, tool
argument, tool result, or file contents. It remains a `content` field and is
redacted again per route.

Evidence should prefer structured rule ID, source, target, location, confidence,
hash/fingerprint, and a redacted bounded excerpt over prose.

### 5.4 Remediation generation

Remediation is optional. Resolution order is:

1. Valid producer-supplied remediation.
2. A versioned remediation template associated with the rule ID or category.
3. Omit the field.

The record MUST identify the remediation source and catalog version when a catalog
template is used. The pipeline MUST NOT fabricate specific facts, claim that a fix
was applied, or treat guidance as an enforcement outcome.

Existing scanner-provided remediation remains supported. Producers that currently
emit no remediation are valid.

### 5.5 No finding workflow status in v8

This scope records immutable finding observations. It MUST NOT add `status: open`
to every occurrence. DefenseClaw currently does not own a finding case lifecycle,
and a logging refactor must not imply one.

If case management is added later, it requires a separate specification covering
stable deduplication fingerprints, state versus analyst disposition, concurrent
updates, source-of-truth ownership, APIs, TUI, remote synchronization, retention,
and transitions such as resolved and reopened.

### 5.6 Alert acknowledgement is a separate projection

Acknowledging or dismissing an alert does not mutate a finding occurrence,
overwrite its canonical severity, or add a finding workflow status. The mutable
alert acknowledgement projection stores the linked occurrence/event ID, current
disposition (`unreviewed`, `acknowledged`, or `dismissed`), actor, timestamps, and a
monotonically increasing per-alert `projection_version`. An absent row is
`unreviewed` at version zero.

Every acknowledgement or dismissal command MUST carry a stable `operation_id` and
the `expected_projection_version` observed by the caller. A state-changing command
is a compare-and-swap: it applies only when the expected version equals the stored
version and then advances the version by exactly one. The first transaction that
successfully commits that comparison is the winner; a concurrent command with the
same expected version is rejected with the now-current version. Wall-clock time,
actor identity, and lexical operation-ID order MUST NOT override commit order. A
command that already requests the current disposition succeeds with outcome
`no_change` and does not advance the version. Bulk operations apply this precondition
independently to every target and report per-target outcomes; they cannot perform a
blind last-write-wins update.

The first accepted use of an operation ID creates exactly one immutable, mandatory
`compliance.activity` event with canonical severity `INFO`. Its event name is
`alert.acknowledgement.requested` or `alert.dismissal.requested`; its body records the
operation ID, target occurrence/event ID, requested disposition, actor, outcome,
expected and observed versions, and projection versions before and after. Applied,
`no_change`, and stale-version `rejected` outcomes are all audited. The idempotency
record, compliance event, and any projection change are committed in one SQLite
transaction.

An exact retry with the same operation ID and normalized command fingerprint MUST
return the original outcome, event ID, and resulting version without changing the
projection, timestamps, or event count. Reusing an operation ID with a different
target, actor, action, expected version, or requested disposition is an idempotency
conflict: it cannot mutate the projection or replace the original event and is
audited as a rejected request through the ordinary request-audit path.

For one alert, applied compliance events are ordered by
`projection_version_after`, with every transition satisfying `before = N` and
`after = N + 1`; timestamps and record IDs are not ordering authorities. Rejected
and `no_change` events carry the version they observed but do not enter the applied
transition sequence. The immutable event history, including a versioned baseline
derived from legacy acknowledgement evidence, is authoritative. Reconciliation
MUST derive expected state from that contiguous applied sequence and transactionally
rebuild a missing or stale projection. A gap, conflicting event at one version, or
projection state ahead of the evidence MUST produce a mandatory `platform.health`
record, block further mutation of that alert, and never be resolved by guessing
from timestamps. Reconciliation does not fabricate a modern operator action for a
legacy baseline.

Legacy v7 `audit_events` rows whose `severity` was overwritten with `ACK` are read
as compatibility evidence of acknowledgement, not as a sixth canonical severity.
The v8 reader preserves raw `ACK` in legacy provenance, excludes it from severity
ranking, materializes the acknowledgement projection, and reports canonical
severity as unavailable/legacy-unknown when the original value cannot be recovered;
it does not rewrite historical bytes or guess the lost severity.

## 6. Boundary Examples

### 6.1 Model inspection

One model request can produce:

1. `model.io / model.request` — provider/model, content or content reference, token
   metadata.
2. `guardrail.evaluation / guardrail.evaluation.completed` — pre-model stage,
   policy versions, rule IDs, block decision, evaluation duration, input reference.
3. Zero or more `security.finding / finding.observed` — concrete detected risks.
4. `enforcement.action / enforcement.block.applied` — only if DefenseClaw actually
   blocked the call.

The four records share request, trace, and evaluation identifiers. They do not copy
the same body.

### 6.2 Tool inspection

One tool attempt can produce:

1. `tool.activity / tool.invocation.requested`.
2. `guardrail.evaluation / guardrail.evaluation.completed` with the invocation ID.
3. Optional findings.
4. Optional enforcement action.
5. `tool.activity / tool.invocation.blocked` or completed outcome.

### 6.3 Asset scan and quarantine

One scan can produce:

1. `asset.scan / scan.started`.
2. Trace spans for phases.
3. `asset.scan / scan.completed` with counts.
4. Zero or more `security.finding / finding.observed` records.
5. `enforcement.action / enforcement.quarantine.applied` if policy takes action.
6. `asset.lifecycle / asset.quarantined` only after the asset state actually changes.

## 7. Classification Rules

1. If the fact is “a control ran and decided,” use `guardrail.evaluation`.
2. If the fact is “a concrete risk was observed,” use `security.finding`.
3. If the fact is “a control was imposed,” use `enforcement.action`.
4. If the fact is “the governed object changed state,” use `asset.lifecycle`.
5. If the fact is “a scanner ran,” use `asset.scan`.
6. If the fact is model content/transport metadata, use `model.io`.
7. If the fact is a tool request/result, use `tool.activity`.
8. If the fact is an operator or system control-plane mutation, use
   `compliance.activity`.
9. An event name MUST NOT be assigned by matching arbitrary free-form message text.
10. Every producer added or migrated MUST have a classification-table test.

## 8. Recommended Audience Profiles

| Audience | Enable | Usually suppress or reduce |
|---|---|---|
| Compliance | Compliance activity, enforcement, asset lifecycle, high-severity findings, audit-integrity health | Model/tool content, diagnostics, detailed evaluation traces |
| SOC | Findings, guardrail evaluations, enforcement, egress, discovery, scans, platform health | Raw model/tool content except incident workflows |
| AI safety/detection engineering | Evaluations, sampled/redacted model I/O and tool activity, findings, evaluation traces/metrics | Unrelated lifecycle detail |
| Platform/SRE | Platform health, telemetry ingest, agent lifecycle, metrics and traces | Model/tool content logs |
| Developer troubleshooting | Temporarily enabled diagnostics, model/tool/evaluation traces and selected logs | Long retention and broad remote fan-out |
| Privacy-minimal production | Mandatory local floor, high-severity findings, enforced outcomes, aggregate metrics | Content-bearing logs and diagnostics |
