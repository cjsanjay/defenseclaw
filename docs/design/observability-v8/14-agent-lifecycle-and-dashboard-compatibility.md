# Agent Lifecycle and Local-Observability Compatibility Contract

## 1. Purpose and Baseline

This document prevents the v8 observability simplification from regressing the
full agent-lifecycle and dashboard behavior already merged by:

- DefenseClaw PR
  [#403](https://github.com/cisco-ai-defense/defenseclaw/pull/403), merge commit
  `9e417889c4c456bc3c7e6c160ee98c1add1094ee`.
- DefenseClaw PR
  [#412](https://github.com/cisco-ai-defense/defenseclaw/pull/412), merge commit
  `94dd46c689fefbcf85b8f478249e74f3925eca49`.

Both commits are part of the repository baseline for v8. Their schemas, real
producer output, local Collector configuration, Prometheus recording/alert rules,
Loki/Tempo wiring, Grafana dashboards, packaged copies, and tests are normative
migration inputs. V8 MAY replace their internal implementation with the unified
pipeline, but it MUST preserve their externally useful semantics or provide a
versioned compatibility projection and migrate every bundled consumer in the same
release.

This contract is intentionally stricter than “the dashboards still load.” A panel
that silently changes from real data to `No data`, a plausible zero, an empty
variable, or an incomplete root-agent tree is a compatibility failure.

### 1.1 Concrete migration inventory

At minimum the implementation inventory includes:

- `schemas/otel/agent-lifecycle-event.schema.json` and the runtime agent, LLM, tool,
  and approval span schemas.
- `schemas/gateway-event-envelope.json` plus the runtime gateway-log envelope and
  validator copy.
- `schemas/otel/metrics.schema.json`, `internal/telemetry/metrics.go`, lifecycle/
  provider/gateway-event emitters, and their tests.
- `internal/gateway/agent_hook.go` and model/tool event correlation paths.
- `bundles/local_observability_stack/otel-collector/config.yaml`, Grafana
  datasources/dashboards, Prometheus rules/alerts, Loki, Tempo, compose, and their
  CLI-packaged copies.
- `scripts/check_grafana_dashboards.py`,
  `cli/tests/test_agent360_dashboard.py`, and
  `cli/tests/test_grafana_dashboards.py`.

The migration inventory is generated and reviewed. A source disappearing from this
list because files were consolidated does not authorize its semantics to disappear.

## 2. Non-Negotiable Outcomes

After migration:

1. A root agent, every known subagent, every execution attempt, turn, model call,
   tool call, approval, guardrail decision, and lifecycle transition remains
   joinable using stable identities.
2. Start and completed-operation telemetry exports during a long-running agent
   session. A final `Stop`/session-end hook is not required before activity appears.
3. Root-agent/subagent lineage remains distinct from OTel parentage. Delegation is
   not rewritten as a false span parent merely to draw a tree.
4. The Agent360 directory, lifecycle funnel, ordered chronology, phase timeline,
   phase graph, topology, decision/recovery view, trace list, and trace waterfall
   continue to return truthful data.
5. The other thirteen bundled dashboards continue to use valid metric names,
   labels, histogram buckets, Loki fields, Tempo fields, datasource UIDs, and
   cadence.
6. Missing tokens, cost, content, timing, parentage, or identity are not fabricated.
   “Not reported” remains distinguishable from a reported zero or empty value.
7. Local history volumes survive the configuration and bundle upgrade. No reset of
   Prometheus, Loki, Tempo, or Grafana state is part of the v8 migration.

## 3. Canonical Agent Identity Contract

### 3.1 Identity layers

The following fields have distinct meanings and MUST NOT be collapsed:

| Field | Contract |
|---|---|
| `gen_ai.conversation.id` | Upstream resumable conversation/session identity. It can outlive one execution attempt. |
| `gen_ai.agent.id` | Logical identity of the agent that performed this operation. For a subagent this is the subagent, not the root. |
| `defenseclaw.agent.root.id` | Root of the delegation tree. It equals the current agent for a root operation and remains the same on known descendants. |
| `defenseclaw.agent.parent.id` | Immediate logical delegating agent for a known child. It is absent when the current agent is root or the parent is genuinely unknown. |
| `defenseclaw.session.root.id` | Root upstream session for the agent tree. It is distinct from the logical root-agent ID. |
| `defenseclaw.session.parent.id` | Immediate parent conversation/session when a child has its own session. |
| `defenseclaw.agent.lifecycle.id` | Stable identity for the same root agent or subagent across gateway restarts. Format remains `lifecycle-[0-9a-f]{16}` for the compatibility window. |
| `defenseclaw.agent.execution.id` | One start or resume attempt within a lifecycle, even when the gateway did not restart. Format remains `execution-[0-9a-f]{16}` for the compatibility window. |
| `defenseclaw.operation.id` | Stable join key for the bounded hook/model/tool/lifecycle operation represented by the record or span. |
| `defenseclaw.run.id` | Gateway/sidecar process run when known; it is not a substitute for lifecycle or execution identity. |
| `trace_id` / `span_id` | OTel causal identity for one bounded trace; it is not the agent directory key. |

Fallbacks MUST be explicit in producer normalization and MUST NOT conflate these
layers. Metric projections MAY use a bounded `unknown` label when required by the
instrument contract, but log/trace schemas MUST omit unknown optional identities
rather than emit a fabricated ID. The directory may use the current agent as root
only when the producer has positively classified the operation as a root operation.

### 3.2 Required lifecycle observation

An agent lifecycle observation requires:

- `gen_ai.conversation.id`
- `gen_ai.agent.id`
- `defenseclaw.agent.root.id`
- `defenseclaw.session.root.id`
- `defenseclaw.agent.lifecycle.id`
- `defenseclaw.agent.execution.id`
- `defenseclaw.agent.lifecycle.event`
- `defenseclaw.agent.lifecycle.state`
- `defenseclaw.agent.depth`

It carries agent name/type, parent-agent/session IDs, phase, previous phase, phase
code, sequence, operation ID, session source/resume state, and user identity when
the connector actually supplies or DefenseClaw safely derives them.

The lifecycle event vocabulary remains:

```text
session_start  session_end  subagent_start  subagent_stop
turn_start     turn_end     tool_start      tool_end
compact_start  compact_end  event
```

The lifecycle state vocabulary remains:

```text
active  completed  failed  interrupted  observed
```

Adding a lifecycle event or state is an additive registry change. Renaming or
removing one requires a compatibility alias, dashboard/query migration, and a new
family-schema version.

### 3.3 Phase and ordering contract

The phase vocabulary and durable numeric codes are:

| Code | Phase |
|---:|---|
| 0 | unknown/unrecognized; never a claimed producer phase |
| 1 | `session` |
| 2 | `planning` |
| 3 | `model` |
| 4 | `tool` |
| 5 | `approval` |
| 6 | `waiting` |
| 7 | `responding` |
| 8 | `maintenance` |
| 9 | `completed` |
| 10 | `failed` |
| 11 | `interrupted` |
| 12 | `observed` |

Existing numbers MUST NEVER be renumbered because historical Prometheus samples
and live samples share the same Grafana value mapping. A new phase appends a new
code; it never reuses a retired code.

The pre-v8 PR #403 Galileo test vector that paired `phase=model` with
`previous_phase=turn` and `code=4` is intentionally corrected to
`phase=model`, `previous_phase=planning`, and `code=3`. `turn` is a lifecycle
event, not a phase, and code 4 is permanently `tool`; the invalid fixture is not a
legacy alias and MUST NOT be accepted or reproduced by migration.

`defenseclaw.agent.sequence` is monotonically increasing within one execution and
orders normalized hook observations when timestamps tie or arrive close together.
A derived observation such as `hook_decision` MUST reuse the operation's identity
without advancing the phase cursor or sequence a second time. Duplicate delivery
or replay MUST NOT invent a phase transition.

Session source values currently include `startup`, `resume`, `clear`, and `compact`.
They are inherited by later observations in the same execution. An unknown source
is reported as unknown/absent, not coerced into `startup`.

## 4. Event and Trace Boundaries

### 4.1 Real-time completion

Each hook delivery receives a short bounded `invoke_agent` anchor. A completed
`chat`, `execute_tool`, approval, decision, or lifecycle span is exported as soon
as its terminal evidence is available and remains independently indexable. The
implementation MUST NOT hold completed operations until session end.

Connector-specific terminal behavior is preserved:

- A post-model hook completes the model span when the connector provides one.
- A `Stop` hook MAY be a connector-specific model-completion fallback.
- `Stop` is terminal lifecycle evidence, not a universal prerequisite for exporting
  earlier work.
- Compaction, resume, subagent, and terminal hooks create bounded transitions even
  when the hook contains no assistant text.

Correlation caches are bounded and expiring. A missing start or completion is
observable as a safe health/diagnostic fact. Eviction does not synthesize content,
duration, success, or lineage.

### 4.2 Parentage, lineage, and links

Parent-child OTel edges represent known synchronous causal work in one bounded
trace. Root/parent agent fields represent delegation lineage across bounded traces.
They are complementary:

```text
root agent A (stable tree identity)
├── execution A1
│   ├── bounded turn trace T1
│   └── bounded tool trace T2
└── child agent B (parent=A, root=A)
    ├── execution B1
    └── bounded model trace T3
```

A subagent start MAY link the child's first bounded trace to the delegating
operation. It MUST NOT use an unrelated or reconstructed span as a parent. Resume,
asynchronous completion, and post-hoc correlation use typed links. The relation
types `caused_by`, `resumes`, `derived_from`, and `correlates_with` remain bounded.

### 4.3 Deduplication

Semantic deduplication keys include connector, lifecycle/execution/operation
identity, normalized event, and the producer's safe event identity when present.
Duplicate terminal hooks do not create duplicate completed spans or lifecycle
counts. Deduplication MUST NOT merge two distinct executions merely because they
share an upstream conversation, agent name, tool name, timestamp, or payload hash.

## 5. Model, Tool, Turn, and Approval Continuity

The v8 registry and builders MUST preserve the current runtime agent, model, tool,
and approval schemas as conformance fixtures.

Every model/tool/approval operation carries the agent correlation group when known:
conversation, current agent, root agent, parent agent, root/parent session,
lifecycle, execution, phase, sequence, and operation. Tool-call identity remains
distinct from the hook operation ID. A turn is correlated through lifecycle and
operation data; it is not inferred from adjacency alone.

The following rules remain mandatory:

- Model usage is emitted only when reported by the provider/connector.
- Reported cost is emitted only when explicitly reported or calculated under the
  separately versioned cost contract; missing cost is absent/`not_reported`.
- Tool arguments/results and model input/output use the destination's projected
  content value and content-state fields.
- A prompt, response, tool argument, or result is never copied into a metric label.
- A child model/tool span inherits known agent identity from the active operation;
  it does not create a new agent identity because a connector omitted repeated
  fields on the completion hook.

## 6. Final Hook-Decision Contract

`hook_decision` is the final connector-facing action after mode and connector
capability mapping. It is not interchangeable with the guardrail's raw verdict.
The canonical payload contains:

| Field | Meaning |
|---|---|
| `connector`, `event` | Connector and normalized hook event that received the decision |
| `result` | Hook handling result (`ok` or `panic`) |
| `raw_action` | Guardrail action before observe-mode/capability mapping |
| `action` | Action actually returned to the connector |
| `severity` | Producer severity, normalized to the canonical envelope ladder |
| `mode` | Effective enforcement/observe mode |
| `would_block` | Whether enforcement mode would have blocked |
| `enforced` | Whether a control was actually imposed |
| `step_idx`, `latency_ms` | Bounded connector step/timing when reported |
| `reason` | Bounded centrally projected reason |
| `evaluation_id`, `rule_ids` | Correlation to evaluation and at most eight bounded rule IDs |

It also carries all known agent, session, lifecycle, execution, operation, trace,
turn, tool, and policy correlation from the enclosing canonical record.

`hook_decision` is a `guardrail.evaluation` durable log and a safe summary/event on
the active hook span. If `enforced: true` represents an actual imposed control, a
separate linked `enforcement.action` record owns that attempt/outcome and mandatory
floor; the decision record is not relabeled or duplicated across buckets. Emitting
the decision does not update the lifecycle phase cursor. The next actual hook shows
whether the agent retried, selected another tool, called the model, stopped, or did
something else; DefenseClaw MUST NOT infer or fabricate a recovery action.

## 7. Signal Ownership for the Bundled Dashboards

The local stack deliberately uses each backend for the question it answers best:

| Backend | Authoritative dashboard use |
|---|---|
| Loki | Durable event chronology, exact completed turn/model/tool/lifecycle counts, hook decisions, recovery sequences, content-bearing structured logs |
| Prometheus | Aggregated rates/counts, latency histograms, phase state/transitions, reported token/cost aggregates, agent directory/last-seen, and bounded topology dimensions |
| Tempo | Selected bounded trace search and parent/link-aware waterfall |
| SQLite/JSONL | Local audit/history and forensic query compatibility outside Grafana |
| Galileo | Independently routed eligible agent/model/tool/retriever/workflow traces and exact canary acknowledgement |

V8 MUST NOT replace a durable Loki count with spanmetrics solely for convenience;
sampling or late span completion could undercount it. It MUST NOT use Loki to
recompute a high-volume latency distribution already owned by a bounded histogram.
Tempo is the operation waterfall, not the durable agent directory.

## 8. `local-observability-v1` Compatibility Profile

### 8.1 Registry ownership

The telemetry registry defines a generated destination/query compatibility profile
named `local-observability-v1`. It owns:

- Every telemetry family and field consumed by the bundled dashboards.
- The OTel-to-Prometheus normalized metric names and allowed labels.
- Histogram bucket boundaries used by dashboard quantiles and alerts.
- Loki JSON field names used by LogQL parsing and correlations.
- Tempo span attributes used by TraceQL variables, trace search, and waterfall.
- Datasource UIDs, dashboard UIDs, links, and required cadence.
- Legacy aliases/dual-emitted series still consumed by a bundled panel.

The profile is generated from canonical registry entries plus parsed checked-in
consumer assets: all fourteen source dashboards, rules, Collector configuration,
datasource configuration, compose/package inputs, and their packaged copies.
`compatibility/local-observability.json` is the checked-in generated consumer
manifest; there is no separately hand-maintained telemetry field or query list.
Dashboard JSON MUST NOT become an unparsed, implicit schema. The compiler/checker
extracts every query dependency and fails when it is absent from the compatibility
profile, while independently checking source/package parity.

### 8.2 Critical Prometheus contracts

The complete contract is generated from the current metrics registry and dashboard
inventory. At minimum it preserves these security-sensitive series/labels, whose
absence can produce plausible but false zeroes:

| Normalized series | Required instrument labels |
|---|---|
| `defenseclaw_approval_count_total` | `result`, `auto`, `dangerous` |
| `defenseclaw_connector_hook_outcome_total` | `action`, `connector`, `event_type`, `severity`, `would_block` |
| `defenseclaw_guardrail_evaluations_total` | `guardrail_action_taken`, `guardrail_connector`, `guardrail_scanner` |
| `defenseclaw_schema_violations_total` | `code`, `event_type` |

The hook-latency histogram keeps the exact millisecond `le` values:

```text
1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf
```

The Agent360 native/derived contract includes the existing last-seen, lifecycle
transition, current phase, phase transition, token usage, reported cost, span-call,
span-duration, connector hook, guardrail, and approval metrics. The generated
inventory records canonical OTel instrument names and normalized Prometheus names
so suffix/unit normalization cannot drift silently.

The current Agent360 name mapping includes:

| Canonical OTel instrument/source | Prometheus compatibility series |
|---|---|
| `defenseclaw.agent.last_seen` (`s`) | `defenseclaw_agent_last_seen_seconds` |
| `defenseclaw.agent.lifecycle.transitions` | `defenseclaw_agent_lifecycle_transitions_total` |
| `defenseclaw.agent.phase.current` (`1`) | `defenseclaw_agent_phase_current_ratio` |
| `defenseclaw.agent.phase.transitions` | `defenseclaw_agent_phase_transitions_total` |
| `defenseclaw.agent.token.usage` | `defenseclaw_agent_token_usage_total` |
| `defenseclaw.agent.reported_cost` (`USD`) | `defenseclaw_agent_reported_cost_USD`; series is absent when cost is not reported |
| `spanmetrics/agent360` call count | `defenseclaw_agent_span_calls_total` |
| `spanmetrics/agent360` duration | `defenseclaw_agent_span_duration_milliseconds_bucket`, `_sum`, and `_count` |

Unit/counter suffix casing is part of the compatibility profile even when it is a
Collector/exporter projection rather than the canonical OTel instrument name.

The six native Agent360 canonical label sets are exact:

- `defenseclaw.agent.last_seen`: `defenseclaw.connector.source`,
  `defenseclaw.agent.execution.id`, `defenseclaw.agent.lifecycle.id`,
  `defenseclaw.agent.parent.id`, `defenseclaw.agent.root.id`,
  `defenseclaw.session.root.id`, `gen_ai.agent.id`, `gen_ai.agent.name`, and
  `defenseclaw.agent.type`.
- `defenseclaw.agent.lifecycle.transitions`: `defenseclaw.connector.source`,
  `defenseclaw.agent.depth`, `defenseclaw.agent.execution.id`,
  `defenseclaw.agent.lifecycle.event`, `defenseclaw.agent.lifecycle.id`,
  `defenseclaw.agent.lifecycle.state`, `defenseclaw.agent.parent.id`,
  `defenseclaw.agent.root.id`, `defenseclaw.session.root.id`, `gen_ai.agent.id`,
  `gen_ai.agent.name`, `defenseclaw.agent.type`, `gen_ai.provider.name`, and
  `gen_ai.request.model`.
- `defenseclaw.agent.phase.current`: `defenseclaw.connector.source`,
  `defenseclaw.agent.execution.id`, `defenseclaw.agent.lifecycle.id`,
  `defenseclaw.agent.root.id`, `gen_ai.agent.id`, and `gen_ai.agent.name`.
- `defenseclaw.agent.phase.transitions`: `defenseclaw.connector.source`,
  `defenseclaw.agent.execution.id`, `defenseclaw.agent.phase.from`,
  `defenseclaw.agent.phase.to`, `defenseclaw.agent.root.id`, `gen_ai.agent.id`,
  and `gen_ai.agent.name`.
- `defenseclaw.agent.reported_cost`: `defenseclaw.connector.source`,
  `defenseclaw.agent.execution.id`, `defenseclaw.agent.lifecycle.id`,
  `defenseclaw.agent.root.id`, `gen_ai.agent.id`, `gen_ai.agent.name`,
  `gen_ai.provider.name`, and `gen_ai.request.model`.
- `defenseclaw.agent.token.usage`: `defenseclaw.connector.source`,
  `defenseclaw.agent.execution.id`, `defenseclaw.agent.lifecycle.id`,
  `defenseclaw.agent.root.id`, `gen_ai.agent.id`, `gen_ai.agent.name`,
  `gen_ai.provider.name`, `gen_ai.request.model`, and `gen_ai.token.type`.

The local projection renames canonical `defenseclaw.connector.source`,
`defenseclaw.agent.type`, and `gen_ai.token.type` to the frozen `connector`,
`gen_ai.agent.type`, and `kind` labels. These six application families may use
their reviewed high-cardinality identity labels only under the 2,048-tuple
per-family cap.

Two standard GenAI client families retain the same narrow 2,048-tuple
compatibility exception:

- `gen_ai.client.operation.duration`: `gen_ai.agent.id`, `gen_ai.agent.name`,
  `gen_ai.operation.name`, `gen_ai.provider.name`, and `gen_ai.request.model`.
- `gen_ai.client.token.usage`: `gen_ai.agent.id`, `gen_ai.agent.name`,
  `gen_ai.conversation.id`, `gen_ai.operation.name`, `gen_ai.provider.name`,
  `gen_ai.request.model`, and `gen_ai.token.type`.

The separate derived `spanmetrics/agent360` pipeline uses the Collector's
10,000-entry dimension cache, 1,000-entry resource-metrics cache, and 24-hour
series expiration. No other native or derived metric family inherits either
exception.

The current `defenseclaw.inspect.*` and connector-hook dual emission remains until
every bundled and documented query is migrated in one release. It may then be
removed only through a declared alias-removal version and historical query test.

### 8.3 Spanmetrics dimensions

The bundled Collector's `spanmetrics/agent360` connector preserves these bounded
dimensions:

```text
gen_ai.operation.name
gen_ai.agent.id
gen_ai.agent.name
gen_ai.agent.type
defenseclaw.agent.root.id
defenseclaw.agent.parent.id
defenseclaw.agent.lifecycle.id
defenseclaw.agent.execution.id
defenseclaw.agent.lifecycle.event
defenseclaw.agent.lifecycle.state
defenseclaw.agent.phase
defenseclaw.agent.phase.previous
defenseclaw.agent.phase.code
connector
gen_ai.tool.name
defenseclaw.destination.app
gen_ai.provider.name
gen_ai.request.model
```

`gen_ai.agent.type` in this list is the frozen PR #403/#412 Collector and dashboard
compatibility label. The canonical registry field is `defenseclaw.agent.type`; the
local-observability projection emits the legacy label from that same
destination-redacted value until the Collector and every current/historical query
are migrated under the declared alias-removal lifecycle.

Request, turn, trace, span, prompt, response, argument, result, reason, evidence,
URL, user, and arbitrary error values are forbidden spanmetrics dimensions. Adding
a dimension requires a cardinality/security review and a dashboard need.

### 8.4 Cadence and temporality

The application metric default remains 60-second delta export, matching the real v7
baseline. The local Collector converts delta sums to cumulative series before
Prometheus remote write. There is one application-metric path: OTLP and derived
spanmetrics reach Prometheus through remote write; the Collector's own operational
metrics alone use its operational scrape endpoint.

Grafana Prometheus `jsonData.timeInterval` MUST be at least 60 seconds while this is
the gateway default. A 15-second dashboard refresh is allowed; it does not change
the query step/cadence contract. Lowering the gateway interval later requires a
reviewed coordinated change, not a dashboard-only edit.

### 8.5 Local Collector and datasource identity

The compatibility baseline uses Collector Contrib `0.153.0`; a version change must
pass the entire generated metric/query inventory and live validation. The local
OTLP receiver accepts logs, traces, and metrics. Its pipelines preserve:

```text
traces  -> Tempo + spanmetrics/agent360
metrics -> resource + delta-to-cumulative + batch -> Prometheus remote write
logs    -> bounded/body-safe processing -> Loki
```

The stable Grafana datasource UIDs are:

```text
defenseclaw-prometheus
defenseclaw-loki
defenseclaw-tempo
```

A datasource may be replaced internally only if its UID, query behavior, and
provisioned links remain compatible or every consumer is migrated atomically.

## 9. Dashboard Compatibility Surface

The following dashboard UIDs remain provisioned and unique:

```text
defenseclaw-activity
defenseclaw-agent-360
defenseclaw-agent-identity
defenseclaw-ai-discovery
defenseclaw-connector-detail
defenseclaw-connectors
defenseclaw-findings
defenseclaw-hitl
defenseclaw-overview
defenseclaw-policy-decisions
defenseclaw-runtime
defenseclaw-scanners
defenseclaw-security
defenseclaw-traffic
```

Dashboard title/layout changes are not automatically breaking. UID, datasource,
variable, link, query-field, metric-label, and semantic-answer changes are.
Source dashboards under
`bundles/local_observability_stack/grafana/dashboards/` and CLI-packaged dashboards
under `cli/defenseclaw/_data/local_observability_stack/grafana/dashboards/` MUST be
byte-identical; the same parity rule applies to provisioned datasource and Collector
configuration consumed by the installed bundle.

Agent360 specifically preserves variables for connector, agent, scope label,
lifecycle, execution, and trace. Its agent scope supports both the selected agent
and root-agent tree. It retains:

- Agent directory and identity drill-down.
- Durable lifecycle/execution funnel and ordered chronology.
- Completed turn, model, and tool counts sourced from Loki.
- Phase timeline and directed phase-transition network sourced from Prometheus.
- Agent/subagent/model/tool topology with bounded dimensions.
- Input/output availability and reported token/cost behavior.
- Hook-decision and subsequent-operation recovery chronology.
- Tempo trace list for completed tool/turn/session/subagent operations and security
  decisions, with a selected-trace waterfall.

A compatibility test MUST fail when a query parses but addresses a nonexistent
label or field. A query returning no live series is classified as expected-idle,
unexpected-empty, or backend-unavailable; it is never silently treated as success.

## 10. Configuration and Migration

### 10.1 Destination migration

The existing named `local-observability` OTLP destination is migrated to the v8
destination registry with its endpoint/protocol/TLS/network intent preserved. Its
effective policy MUST include logs, traces, and metrics and every bucket/family
needed by `local-observability-v1`. If the v7 destination already received every
signal/bucket unredacted, the v8 capability-default form is exact and no `send`
block is necessary. Otherwise the migrator materializes the narrower/redacted v7
behavior, and the upgrade report identifies any dashboard feature that would be
unavailable under that preserved policy.

An operator explicitly narrowing the v8 local destination is allowed. Validation
and `observability plan` then show which local dashboard capabilities become
partial. This is a warning, not a hidden override: configuration remains the
operator's central control.

Loopback/private endpoint access remains an explicit visible network-safety opt-in
for the local destination; migration preserves the known local-stack intent without
creating a process-wide bypass.

### 10.2 One-command upgrade of local assets

`defenseclaw upgrade` handles the v8 compatibility transition as part of the same
registered migration; no separate migration command is required. When a seeded
local-observability bundle exists, upgrade:

1. Includes its DefenseClaw-owned Collector, datasource, dashboard, Prometheus,
   Loki, Tempo, recording-rule, and alert-rule files in the ordinary upgrade backup.
2. Replaces the DefenseClaw-owned files with the target release's mutually
   compatible bundle and packaged dashboard copy. The target manifest is validated
   before restart; a partial file-set refresh restores the backed-up managed set.
3. Preserves arbitrary operator-created files and every persistent Docker volume.
4. Records any overwritten operator modification in the backup and reports the
   affected path; it never silently discards the only copy.
5. Uses the existing stop/refresh/restart path when the local stack is running, then
   waits for Collector, Prometheus, Loki, Tempo, and Grafana readiness.
6. Runs static inventory validation and a bounded live smoke check. Optional local
   stack unavailability degrades upgrade status but does not roll back an otherwise
   healthy gateway/SQLite migration.

The operation MUST NOT reset volumes, delete arbitrary custom dashboards, or
require `setup local-observability reset`. A later ordinary
`defenseclaw setup local-observability up` continues to refresh the target bundle
by default and is a recovery action, not a prerequisite for the normal upgrade.

The v8 producer/Collector compatibility surface retains the immediately previous
bundled dashboard query contract for at least one compatibility release. Therefore,
a backed-up but temporarily unrefreshable or unrestartable local stack keeps its
existing PR #403/#412 queries valid rather than silently falling to `No data`.
Target-only panels may remain unavailable until recovery; upgrade/doctor/status
identify the stale bundle version and affected capabilities. This compatibility
window does not justify indefinite duplicate metrics: every alias has a declared
removal release and a successful bundle-upgrade test.

### 10.3 Compatibility change procedure

A telemetry change consumed by a dashboard is complete only when one change set:

1. Updates the canonical registry and generated `local-observability-v1` inventory.
2. Adds an alias/dual emission when historical and current queries need overlap.
3. Updates every source dashboard, packaged copy, rule, alert, and documentation
   query that consumes the old contract.
4. Updates static, generated-inventory, live, and historical-query fixtures.
5. Declares the alias removal version and records a semantic diff.

Removing a dashboard panel is a product decision and does not authorize deleting
the telemetry still used by another consumer.

## 11. Required Verification

### 11.1 Golden lifecycle scenarios

Tests cover at least:

- Root session start, two turns, model call, tool call, and session end.
- Root session that remains running after completed model/tool operations; those
  operations are already visible in Loki, Prometheus, and Tempo.
- Root plus direct and nested subagents with correct root/parent/session lineage.
- Resume across gateway restart: stable lifecycle, new execution, continued
  conversation, new run ID.
- Clear/new session: identity changes according to the producer event rather than
  being inferred from name.
- Compaction start/end with no fabricated model content.
- Duplicate completion and out-of-order hook delivery.
- Missing parent, tokens, cost, content, and timing represented as not reported.
- Raw block downgraded in observe mode, producing distinct raw/effective actions,
  followed by an actual retry/tool/model/stop event without inferred recovery.
- Sampled and unsampled bounded traces while lifecycle/finding/enforcement logs
  remain durable as required.

Every scenario asserts exact record/span/metric counts, stable correlation, phase
codes and sequence, parent/link shape, reported-state behavior, and no duplicate
old/new pipeline output.

### 11.2 Static and packaged dashboard checks

The release runs:

```bash
make check-grafana-dashboards
uv run python -m pytest cli/tests/test_agent360_dashboard.py cli/tests/test_grafana_dashboards.py -q
```

The checker validates source/packaged parity, unique UIDs, datasource UIDs,
Prometheus cadence, PromQL/LogQL/TraceQL shape, registered metrics and labels,
histogram buckets, legends, percentile grouping, dashboard links, variable
datasources, and the generated compatibility inventory.

### 11.3 Live bundle checks

A release candidate starts the bundled stack, emits the golden root/subagent
scenario through real producers, and validates:

- All five services are ready.
- Prometheus inventory contains expected non-empty series and labels.
- Loki chronology returns exact lifecycle/model/tool/decision records.
- Tempo finds the completed operation and returns the expected waterfall.
- Grafana provisions all fourteen UIDs and every query is classified.
- Tokens/cost render as not reported when absent and as the reported value when
  present.
- A second run after upgrade preserves historical volumes and adds current data.

The canonical live audit command is the dashboard checker with its live and
packaged requirements enabled:

```bash
python scripts/check_grafana_dashboards.py --live --inventory --require-packaged
```

Release automation records the exact command and observed query inventory rather
than only reporting that containers started.

## 12. Release Gate

V8 cannot ship if any of these is true:

- A merged PR #403 identity, lifecycle event, phase, operation boundary, decision,
  reported-state, or correlation has no registry disposition.
- A merged PR #412 metric/label/bucket/cadence correction is reversed.
- Agent360 depends on session-end to display completed work.
- A dashboard query points to a missing field/label or returns a false zero because
  of cadence or label drift.
- Source and packaged dashboards differ.
- Local upgrade requires volume reset or an extra manual migration step.
- A compatibility alias is removed before all bundled consumers and historical
  fixtures migrate.
