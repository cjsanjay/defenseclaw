# Simplified Telemetry Schema Architecture

## 1. Decision

DefenseClaw v8 uses a **composed schema**, not a DefenseClaw-only replacement and
not GenAI conventions alone:

```text
stable OTel resource / HTTP / RPC / error conventions
                         +
version-pinned OTel GenAI conventions for agent/model/tool/retrieval
                         +
small DefenseClaw overlay for security, policy, enforcement, lifecycle,
correlation, provenance, collection bucket, and redaction field classes
                         +
generated destination projections (Galileo/OpenInference compatibility)
```

This is the most open and understandable option:

- Standard consumers can use `gen_ai.*`, HTTP/RPC, resource, status, and error
  fields without knowing DefenseClaw.
- DefenseClaw does not misuse `gen_ai.*` for security concepts that the standard
  does not define.
- Galileo and other backends receive generated compatibility projections rather
  than becoming the canonical schema.
- One logical registry with a small focused authoring set replaces many
  independently maintained JSON files.

Relevant upstream sources:

- OpenTelemetry semantic-convention registry:
  <https://github.com/open-telemetry/semantic-conventions>
- OpenTelemetry GenAI registry model:
  <https://github.com/open-telemetry/semantic-conventions-genai>
- OpenTelemetry core semantic-conventions `v1.42.0` release:
  <https://github.com/open-telemetry/semantic-conventions/releases/tag/v1.42.0>
- OpenTelemetry GenAI registry revision used by v8:
  <https://github.com/open-telemetry/semantic-conventions-genai/tree/b028dceecdad117461a785c3af35315e7184e813>
- OpenInference semantic-conventions `v0.1.30` release:
  <https://github.com/Arize-ai/openinference/releases/tag/python-openinference-semantic-conventions-v0.1.30>
- OpenTelemetry specification guidance that semantic-convention YAML is the source
  for generated constants:
  <https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/overview.md>

## 2. Why GenAI Alone Is Insufficient

OTel GenAI conventions cover portable AI operation semantics such as agent calls,
model inference, tool execution, conversations, request/response models, usage, and
content. They do not fully define DefenseClaw concepts such as:

- Collection bucket and route identity.
- Guardrail strategy, phase, decision, severity, would-block, and enforced state.
- Security finding, scan, enforcement action, approval, and asset lifecycle IDs.
- Connector/root-agent/session/lifecycle/execution correlation.
- Redaction field class and destination projection state.
- Config generation, policy version, audit-mandatory status, or evidence
  fingerprint.

Forcing those into invented `gen_ai.*` attributes would look standard while being
non-standard. DefenseClaw-specific semantics therefore remain in the
`defenseclaw.*` namespace.

### 2.1 Registry scope

The logical telemetry registry owns canonical observability log/event bodies, span
families, span events/links, resources, and metric instruments. It generates or is
referenced by JSONL, OTLP, SQLite projection, CLI export, and vendor compatibility
schemas.

Unrelated product contracts remain separate: configuration schema, release/upgrade
manifest, plugin/registry manifest, API request/response schemas, and other non-
telemetry data do not get forced into the telemetry registry.

## 3. Canonical Namespace Ownership

| Namespace | Owner | DefenseClaw rule |
|---|---|---|
| OTel resource/general | OpenTelemetry | Use pinned standard name/type/meaning; do not redefine |
| `http.*`, `url.*`, `server.*`, `network.*`, `rpc.*`, `error.*`, exception event | OpenTelemetry | Use stable protocol/error conventions |
| `gen_ai.*` | Pinned OTel GenAI profile | Portable agent/model/tool/retrieval fields only |
| `db.*` | OpenTelemetry | Retrieval/database operation semantics when applicable |
| `openinference.*` | OpenInference compatibility profile | Generated compatibility alias/projection, not primary ownership |
| `defenseclaw.*` | DefenseClaw | Security, policy, lifecycle, provenance, correlation, bucket, and privacy overlay |
| `galileo.*` | Galileo adapter | Destination-specific resource/routing projection only; never producer-canonical |

A field has exactly one canonical owner. Aliases declare `alias_of` and a removal
version; they do not become independent values.

## 4. One Logical Source of Truth

### 4.1 Authoring layout

The target authoring layout is intentionally small but not one enormous file. One
registry manifest composes three focused domain files:

```text
schemas/telemetry/v8/
  registry.yaml              # manifest, versions, dependencies, group imports
  genai.yaml                 # GenAI groups and agent/model/tool/retrieval/workflow families
  security.yaml              # security groups and guardrail/finding/enforcement/approval families
  operations.yaml            # operational families, including span.destination.* and span.admin.*
  semconv.lock.yaml          # exact upstream dependency versions/digests
  examples.yaml              # valid/invalid representative records
  README.md                  # generated quick-start and ownership guide

schemas/telemetry/generated/
  telemetry.schema.json      # complete JSON Schema bundle with $defs
  catalog.json               # compact machine-readable catalog
  catalog.md                 # searchable human reference
  otlp-fixtures/             # generated conformance fixtures
  compatibility/galileo.json
  compatibility/openinference.json
  compatibility/local-observability.json # generated dashboard/query consumer profile
  compatibility/v7-exporter-selection.json # generated migration eligibility/profile map
```

The manifest, three domain model files, lock, and curated examples are the only
human-authored sources of canonical telemetry semantics. Common attributes are
defined once and referenced across those files. Machine-derived normalized
upstream snapshots are immutable build inputs named and digested by the lock, not
additional authoring surfaces. Bundled dashboards, rules, Collector configuration,
datasource configuration, and their packaged copies remain independently owned
consumer assets that the compiler parses; they are not copied into a second
hand-maintained telemetry manifest. Everything under `generated/` is reproducible
and carries a generated-file header. CI fails on drift. Contributors normally
touch one domain file for a new family; consumers normally open only the generated
catalog or bundle.

There is no separately authored trace or span-family file. Each span family from
`11-trace-and-span-contract.md` section 7 is owned by its primary semantic domain:

| Authoring file | Span-family ownership |
|---|---|
| `genai.yaml` | `span.agent.invoke`, `span.workflow.run`, `span.model.*`, `span.tool.*`, and `span.retrieval.*` |
| `security.yaml` | `span.guardrail.*`, `span.enforcement.*`, `span.approval.*`, and `span.finding.*`; `span.guardrail.judge` may reference the GenAI model groups without changing ownership |
| `operations.yaml` | `span.agent.transition`, `span.asset.*`, `span.network.*`, `span.ai.discovery.*`, `span.telemetry.*`, `span.destination.*`, `span.config.*`, `span.admin.*`, and `span.diagnostic.*` |

Log and metric families follow the same primary-domain rule. Reusable groups may
be referenced across files, but a family definition has exactly one authoring
owner. `registry.yaml` composes the three sets into the versioned trace profile.

### 4.2 OTel registry compatibility

The registry MUST use the OpenTelemetry semantic-convention registry model and
OTel Weaver-compatible groups/references wherever they represent the required
contract. DefenseClaw extensions are limited to namespaced metadata required by
this product:

- `bucket`
- `field_class`
- `sensitivity`
- `cardinality`
- `route_selector`
- `mandatory_floor`
- `compatibility_aliases`
- `projection_profiles`

If upstream Weaver cannot preserve an extension, the compiler keeps it in a
namespaced `x-defenseclaw-*` block rather than forking the meaning of an upstream
field.

The v8 lock was reviewed against the authoritative upstream repositories on
2026-07-02 and pins these immutable revisions:

| Dependency | Version/profile | Immutable revision |
|---|---|---|
| OpenTelemetry core semantic conventions | `v1.42.0` | `ae3a98640194ed405c4c797281502e4d3bd258b3` |
| OpenTelemetry GenAI semantic conventions | `otel-genai-b028dceecdad117461a785c3af35315e7184e813` | `b028dceecdad117461a785c3af35315e7184e813` |
| OpenInference semantic conventions | `openinference-semantic-conventions-v0.1.30` | `789d41974c08a9a13147977f28ef4142a07e2106` |

The core `v1.42.0` release moved `gen_ai.*` ownership to the dedicated GenAI
repository. That repository had no release tag for this snapshot, so v8 uses its
full commit as the profile identifier rather than a mutable branch name. Builds do
not fetch mutable `main` definitions, and a tag moving to a different commit fails
lock validation.

Every lock member names the upstream repository, immutable revision, normalized
snapshot path, normalization format, and SHA-256 digest. The compiler validates the
digest before loading the snapshot and fails if a referenced standard field's name,
type, stability, enum/deprecation metadata, or original source pointer is absent or
inconsistent. Normal registry generation is entirely offline. A snapshot may be
refreshed only by an explicit dependency-update operation that derives it from the
pinned revision and produces a reviewed semantic diff; a self-authored subset plus
its own digest is not sufficient provenance.

OpenInference normalization uses only the pinned Python semantic-conventions
package version source, its trace and resource constant modules, and
`spec/semantic_conventions.md`. The Reserved Attributes table is authoritative for
direct trace-attribute names, types, and meanings, while the released Python
constants prove that the SDK symbol exists. Direct trace entries are the exact
intersection, except OTel-standard exception fields remain OTel-core owned;
`openinference.project.name` is the explicit resource-module exception. The
released package has no per-row stability field, so the normalized stability is a
documented compatibility-profile policy rather than an upstream row claim.
Instrumentation, examples, tests, internal documentation, and other language SDKs
never contribute attributes to the Python `0.1.30` profile.

OpenInference unions and structured collections retain their upstream wire shape.
`String/Integer` is a closed scalar union. `List of objects` is an indexed,
zero-based flattened-prefix template and `Image Object` is an object-prefix
template; neither becomes a literal OTLP array or object attribute. Prefix/template
components are projection metadata, not generic DefenseClaw attribute types.

Dependency overlap records provenance, not shared canonical ownership. The
dedicated GenAI snapshot owns every current definition it contains. Deprecated
core definitions moved to that repository are legacy migration provenance; an
active duplicate is accepted only when its complete shape is equal, an active
conflict fails, and a deprecated/current type change requires an explicit migration
disposition. Core-only deprecated GenAI definitions cannot satisfy an ordinary
family reference. OTel core remains the canonical owner of standard fields also
named by OpenInference, while OpenInference-only fields are compatibility-projection
inputs and never override OTel or OTel GenAI ownership.

## 5. Registry Composition Model

The registry defines reusable groups rather than copying every common attribute
into every span schema.

### 5.1 Reusable groups

The v8 reusable groups are:

| Group | Contents |
|---|---|
| `resource.core` | Service, deployment, instance, host, tenant/workspace, device identity |
| `span.core` | Bucket, family, family schema version, source, config generation, outcome |
| `correlation.request` | Request/turn/trace identifiers |
| `correlation.agent` | Conversation, agent, root/parent, lifecycle, execution, phase, sequence |
| `correlation.security` | Evaluation, finding, scan, policy, enforcement, approval IDs |
| `content.input` | Input messages/value, reported/state/length/hash/MIME and field class |
| `content.output` | Output messages/value, reported/state/length/hash/MIME and field class |
| `error.core` | OTel status/error type plus bounded redacted description |
| `genai.agent` | Pinned standard agent operation fields |
| `genai.model` | Pinned model request/response/usage fields |
| `genai.tool` | Pinned tool operation/call fields |
| `genai.retrieval` | DB/retrieval fields |
| `security.guardrail` | Decision, severity, phase, source, evidence/reference fields |
| `security.enforcement` | Requested/effective action, mode, outcome, state transition |
| `lifecycle.agent` | Lifecycle event/state/source/resume/depth |
| `transport.http` | Stable HTTP client/server fields |

### 5.2 Family definitions

A span/log/metric family references groups and declares only its unique shape. A
conceptual authoring entry looks like:

```yaml
groups:
  - id: span.model.chat
    type: span
    stability: stable
    brief: One model chat invocation.
    extends:
      - span.core
      - correlation.request
      - correlation.agent
      - content.input
      - content.output
      - error.core
      - genai.model
    span:
      name: "chat {gen_ai.request.model}"
      kind: client
    x-defenseclaw:
      bucket: model.io
      family_schema_version: 1
      events: [model.stream.first_token, model.retry, guardrail.decision]
      compatibility_profiles: [openinference-v1, galileo-rich-v2]
```

The compiler's concrete YAML grammar MUST encode these semantic rules and MUST NOT
weaken them. Grammar-only refinements do not reopen the reviewed family ownership,
group composition, version, privacy, or compatibility decisions.

Every placeholder in a span `name_pattern` is a complete inherited attribute
reference. The compiler rejects unknown placeholders, aliases, format expressions,
and attributes classified as content, path, credential, reason, evidence, error,
or high-cardinality. Fixed names need no placeholder. Span names therefore remain
bounded even when the corresponding span carries richer values as attributes.

#### 5.2.1 Deterministic group resolution

The compiler preserves every direct attribute use and also materializes one
immutable resolved-use contract for every family. Resolution is structural and
monotone; source order or a nearest-parent override never weakens a requirement.

- An `attribute_group` resolves its inherited and direct uses as attributes.
- A `body_group` transposes every inherited and direct use into `body_fields`.
  A log family extends exactly one `body_group` and no non-body group, so all of
  its resolved payload uses have an unambiguous body role.
- Span, resource, metric, and span-event families cannot inherit a body use.
  Their resolved uses remain attributes; metric attributes are the canonical
  label schema described in section 5.4.
- Repeated references merge by the non-weakening requirement lattice
  `required > conditional > recommended > optional`. A required use dominates a
  conditional use. If conditional is the strongest surviving level, every
  surviving use must reference the same stable root-catalog condition ID or
  compilation fails; free-form conditional prose is invalid.
- Per-use constraints merge only by a representable restrictive intersection:
  lower maxima, higher minima, enum intersection, and identical portable patterns.
  An empty/inconsistent range or enum, two different patterns, an invalid item
  bound, or any other non-representable intersection fails. An absent constraint
  never removes a constraint declared by another use.
- The compiler retains the contributing direct uses for provenance and emits the
  resolved role, requirement, condition, and effective constraints for builders,
  schemas, the catalog, and field-class derivation. Unknown, cyclic, mixed-role,
  or unresolved inheritance fails before any output is written.

The checked v1 source satisfies these rules without an exception: every log
extends exactly one body group, body transposition resolves its inherited
correlation/content/security fields, and every duplicate requirement has one
non-weakening result. Generated code MUST consume the materialized result rather
than independently walking the YAML hierarchy.

Every log/span family registers both `outcome_requirement` and
`allowed_outcomes`. `outcome_requirement` is exactly `required`, `optional`, or
`forbidden`. A required/optional family has a nonempty, canonical-order subset of
the global outcome vocabulary; a forbidden family has an explicit empty list and
rejects an envelope outcome. The global vocabulary is not a family default:
copying every canonical outcome into a family without family-specific
applicability and tests is invalid. Generated builders reject a missing required
outcome and a globally valid but family-inapplicable outcome.

Metric families omit both keys because instrument recording is not an
outcome-bearing envelope operation. A metric label may still reference the
canonical `defenseclaw.outcome` attribute, in which case its live values use the
canonical outcome vocabulary and any old `ok`, `success`, `delivered`,
`accepted`, `upstream-error`, `cooldown_suppressed`, `circuit_open`, or arbitrary
`http-N` label is migrated through an explicit compatibility projection/reason or
status-code label. It is never modeled as the metric family's envelope outcome.

The registry manifest also owns immutable semantic-profile bindings. The
`defenseclaw-genai-rich-v1` entry is exactly:

```yaml
id: defenseclaw-genai-rich-v1
trace_schema_version: defenseclaw-trace-v1
gen_ai_semconv_profile: otel-genai-b028dceecdad117461a785c3af35315e7184e813
openinference_profile: openinference-semantic-conventions-v0.1.30
galileo_compatibility_profile: galileo-rich-v2
```

These are four independent literal identifiers. The envelope `schema_version` and
each span's `family_schema_version` remain separate versions and are not members of
this tuple. The four profile members cannot be overridden independently in config;
changing one creates a new semantic-profile ID. Registry validation fails if this
tuple's upstream-pinned OTel core, GenAI, and OpenInference members disagree with
`semconv.lock.yaml`. The DefenseClaw-owned trace-schema and Galileo compatibility
profile IDs are validated against their registry entries instead of being invented
as upstream lock members.

The effective plan derives this tuple from the embedded registry and lock; the Go
runtime does not duplicate repository URLs, snapshot paths/digests, or upstream
revision provenance. It separately compares the derived tuple with the semantic
profile, trace schema, GenAI/OpenInference vocabulary, and Galileo projection
capabilities compiled into the binary. Source derivation determines what was
authored, while the capability check proves this binary implements it. A changed
tuple under the same profile ID therefore fails closed, and a new profile ID remains
unsupported until its builders and adapters ship together.

#### 5.2.2 Typed structural contract

`registry.yaml` contains exactly one authored `structural_contract`. It is the
source for the canonical envelope and signal payload structures that cannot be
expressed by domain attribute groups alone:

```yaml
structural_contract:
  id: defenseclaw.canonical-record
  version: 1
  runtime_binding:
    record: internal/observability.Record
    input: internal/observability.RecordInput
    value: internal/observability.Value
    schema_derived_constructor: internal/observability.newSchemaDerivedRecord
    schema_derived_log_constructor: internal/observability.newSchemaDerivedLogRecord
  limits:
    record_id_utf8_bytes: 512
    correlation_id_utf8_bytes: 512
    span_name_utf8_bytes: 512
    binary_version_utf8_bytes: 256
    provenance_hex_ascii_bytes: 128
    stable_token_ascii_bytes: 128
    payload_depth: 32
    payload_members: 8192
    payload_encoded_bytes: 1048576
    record_encoded_bytes: 4194304
  envelope:
    additional_properties: false
    fields: [] # the authored source contains the closed envelope field list
    signal_arms: [] # the authored source contains logs/traces/metrics arms
  correlation: {additional_properties: false, fields: []}
  provenance: {additional_properties: false, fields: []}
  trace:
    body: {additional_properties: false, fields: [], relations: []}
    resource: {additional_properties: false, fields: []}
    scope: {additional_properties: false, fields: []}
    status: {additional_properties: false, fields: []}
    events: {additional_properties: false, fields: []}
    links: {additional_properties: false, fields: []}
  metric:
    instrument_data: {additional_properties: false, fields: []}
  canonical_to_otlp: {} # exact typed mappings are authored here
```

This is a source-shaped hierarchy excerpt: empty collections stand only for
omitted authored entries. There are no `objects`, root `signal_arms`, or
`otlp_representations` keys; copying those conceptual labels into the source is a
schema error.

The compiler accepts no second structural-contract ID or version and no unknown
member. `runtime_binding` is an asserted parity boundary, not a code-generation
request for a new record. Generated Go builders construct the existing
`RecordInput`, materialize the registered body and field-class map, and terminate
at the existing unexported schema-derived constructor. Generated log builders use
the separate log-only schema-derived constructor when the catalog derives
`mandatory`; ordinary callers still cannot assert either trust marker. Tests
compare every bound, version, vocabulary, and regex with the existing Go constants
and validation; a registry/Go mismatch fails generation.

Each structural field is a closed record with `name`, `type`, `required`, and,
where applicable, `const`, `enum`, `object_ref`, `item_ref`, `semantic_ref`,
`semantic_format`, `field_class`, `sensitivity`, `normalization`, and `otlp`. Its
`type` is exactly one of `boolean`, `int64`, `uint32`, `uint64`, `double`,
`metric_number`, `string`, `timestamp`, `object`, `array`, `canonical_json`, or
`field_class_map`. `metric_number` is resolved per family to exactly finite
`int64` or `double`; it is not a third wire-number type and never coerces an integer
through binary float. `semantic_ref` inherits type, privacy, and normalization from
one ordinary registry attribute or resolves one closed registry-owned dynamic
family/group contract; it cannot be an unchecked string. An inline dynamic leaf
supplies all three itself. `semantic_format` is closed to the executable nonzero
OTel trace/span ID formats. Timestamps are UTC RFC 3339-nano on the canonical wire.
`uint32`/`uint64` use exact nonnegative JSON integers rather than binary-float
coercion.

The envelope, exact twenty-key correlation object, provenance object, signal arms,
and payload-rooted field-class rules are those in
`02-taxonomy-and-data-model.md` §§3-3.6. In particular, metrics forbid envelope
outcome/severity/log-level state and `instrument_data` is only `{value,
attributes}`; repeated instrument identity/type/unit/temporality data is invalid.
Every object sets `additionalProperties: false`.

The trace-body, status, resource, scope, event, link, equality, privacy, and nested
dropped-count structures are exactly `11-trace-and-span-contract.md` §§5.4-5.5.
The structural registry registers `defenseclaw.trace.schema_version`,
`defenseclaw.semantic_profile`, `defenseclaw.link.relation`, and the bounded
low-cardinality `defenseclaw.workflow.name`; reusable scope/link groups reference
those attributes rather than hiding strings in adapters. The canonical workflow
name pattern is exactly `workflow {defenseclaw.workflow.name}`. The producer
supplies that identifier under its explicit 128-byte ASCII token bound; neither a
migration nor a destination projector derives a missing value by parsing a
rendered name. A Galileo projection may add its versioned compatibility-profile
attribute after route redaction; canonical scope data remains destination-neutral.

The trace signal arm explicitly requires `correlation.trace_id` and
`correlation.span_id`. `otel-trace-id-v1` and `otel-span-id-v1` reject all-zero or
wrong-width identifiers. The trace-body relation `trace-time-order-v1` requires
positive start/end nanoseconds and `start_time_unix_nano <=
end_time_unix_nano`. These builder-enforced relations remain annotations in JSON
Schema where the dialect cannot compare two instance fields.

`field_classes` contains concrete RFC 6901 pointers rooted at the selected payload,
not at the envelope. The compiler derives structural leaf classes from this
contract and domain leaf classes from the resolved family. At runtime the builder
expands each concrete array index and materializes the complete map. `/message`,
`/attributes/defenseclaw.source`, and
`/attributes/defenseclaw.connector.source` are valid examples;
`/body/message` and `/instrument_data/attributes/...` are invalid. No container
classification covers descendants.

Structural privacy is closed. Trace kind, timestamps, dropped counts, status code,
schema URLs, and scope name/version are `metadata`/`safe`; parent/link IDs are
`identifier`/`internal`; link trace state is `metadata`/`internal`; and status
description is `error`/`sensitive`. Metric observation value is
`metadata`/`safe`. Registered attributes inherit their ordinary registry class and
sensitivity without an override. Envelope and provenance fields are not selected-
payload leaves and therefore do not appear in `field_classes`, but the structural
contract still marks their safe/internal handling: occurrence and correlation IDs
are identifiers, connector/config digest are internal, and versions, timestamps,
bucket/signal/severity/log-level/action/phase/outcome/mandatory are bounded
metadata. A structural field with missing privacy metadata fails compilation.

Structural normalization reuses the root normalizer catalog. Exact OTel IDs add a
nonzero lowercase-hex format check; timestamps use UTC RFC 3339-nano; counts use
finite numeric ranges; W3C trace state is at most 512 UTF-8 bytes; and every text
field remains under the P2 bounds above or a stricter family bound. The structural
contract cannot introduce a prose-only normalizer or weaken a P2 maximum.

The typed OTLP representation declares an exact canonical source and protobuf
target for each field. It covers trace/span/parent IDs, rendered name, kind,
timestamps, status, resource/scope schema URLs, every attribute set, events, links,
and all span/resource/scope/event/link dropped counts. Its value table maps each
canonical scalar/array/structured type to a compatible non-null OTLP `AnyValue`
arm without stringification: Boolean to `boolValue`, `int64` to `intValue`, finite
double to `doubleValue`, string to `stringValue`, array to `arrayValue`, and object
to `kvlistValue`; canonical null has explicit `null_value_policy: reject`. The
closed `object_contexts` map identifies exact protobuf placement for Span,
ResourceSpans resource, ScopeSpans scope, Status, Event, and Link fields, so a leaf
target such as `schemaUrl` cannot accidentally bind to the wrong wrapper. The
closed `field_context_overrides` map handles the two wrapper-owned leaves:
`trace_resource.schema_url` belongs to `ResourceSpans` and
`trace_scope.schema_url` belongs to `ResourceSpans.scopeSpans[]`. The resource and
scope containers themselves do not map to nonexistent Span fields; the projector
traverses them and re-roots their registered children in those wrapper contexts.
Metric
mappings record the raw value and exact labels through the generated SDK instrument
so SDK aggregation owns OTLP data-point and
temporality shape. The v8 OTLP-log compatibility representation remains an
explicit versioned projection of the already route-redacted record; changing it to
a different structured log-body representation requires its own profile/version
and golden migration rather than an adapter-local reinterpretation.

##### Stable conditions

Conditional uses reference `conditional: <id>`; prose in a use is invalid. The root
`conditions` catalog accepts exactly `enforcement.kind: json_schema` or
`enforcement.kind: builder_fact`. A JSON-Schema condition supplies a closed typed
predicate over independent record fields. A builder-fact condition supplies one
closed fact token; generated builders evaluate it from typed producer state before
record construction. Each row declares `false_requirement: optional|forbidden`;
an adapter cannot treat omission and permission as the same fallback. The current
seven conditions all require producer knowledge
that has no independent serialized discriminator, so all seven are
`builder_fact`:

| ID | Typed truth condition | False behavior |
|---|---|---|
| `connector-known-v1` | A positively normalized nonempty connector identity exists; an `unknown` placeholder does not count | Conditioned connector field forbidden |
| `operation-terminal-v1` | Terminal evidence exists for this bounded operation; when true the final outcome and trace end are present and coherent | Conditioned outcome remains optional because a nonterminal `attempted` observation is valid |
| `technical-failure-v1` | The operation/control itself technically failed under the status contract; a successful block decision or caller cancellation alone is not such a failure | Conditioned error field optional because a prevented requested operation may still use `policy_denied` |
| `guardrail-terminal-decision-available-v1` | The control reached a final typed decision | Conditioned decision forbidden |
| `security-severity-available-v1` | A recognized producer severity exists or was canonically normalized, including `NONE` to `INFO` | Conditioned severity forbidden |
| `judge-output-parse-failed-v1` | Judge output parsing failed and a bounded centrally redacted parse-error value exists | Conditioned parse error forbidden |
| `admin-principal-known-v1` | A positively authenticated/authorized administrative principal is known; submitted credentials and origin metadata cannot synthesize one | Conditioned principal forbidden |

Calling one of these `json_schema` merely because the conditioned field is present
would be a tautology and is forbidden. Group resolution compares stable condition
IDs, not human prose. Generated-schema annotations identify builder-fact
enforcement for offline consumers, while emitted-record conformance proves the
builder applied it.

##### Agent phase/code value catalog

The root `registry.yaml` `value_catalogs` owns one catalog
`agent-phase-v1` with exact `kind: string-int64-bijection`. Its ordered
`value_attributes` are `defenseclaw.agent.phase`,
`defenseclaw.agent.phase.previous`, `defenseclaw.agent.phase.from`, and
`defenseclaw.agent.phase.to`; `paired_value_attribute` identifies the current
phase paired with `code_attribute: defenseclaw.agent.phase.code`. Its authored
closed `compatibility` object reserves `code: 0`, `value: unknown`, and
`canonical_emittable: false`; the compiler never synthesizes this metadata. The
immutable canonical entries are:

```text
1 session       2 planning      3 model       4 tool
5 approval      6 waiting       7 responding  8 maintenance
9 completed    10 failed       11 interrupted 12 observed
```

The compiler derives the exact four string enums and numeric range `1..12`; the
attributes cannot hand-author a different enum/range. When current phase and code
coexist, their pair must match. Code `0` remains reserved for
unknown/unrecognized compatibility input, has `canonical_emittable: false`, and is
not part of either canonical normalizer. Evolution is append-only: an existing
value/code cannot be renamed, removed, or renumbered, and a new phase receives the
next unused positive code.

##### Group and family lifecycle

Every group has required top-level `introduced_in` and optional top-level
`deprecated_in` and `removed_in`, matching attribute lifecycle vocabulary rather
than adding a second nested dialect. Deprecated stability requires
`deprecated_in`, and removal requires deprecation. Removed families remain in the
historical catalog but cannot be built or route-selected.

The semantic-diff gate evaluates each fully resolved family, including inherited
group changes. A required-field, type, meaning, bucket, span-name/kind, applicable
outcome, field-class, or sensitivity break requires a family-schema-version bump
and reviewed compatibility disposition. Editing a reusable group cannot evade that
rule; an optional safe addition may retain the family version.

##### Complete single-fault examples

Every `examples.yaml` valid record is a complete canonical record accepted by the
generated builder and public bundle, not a partial illustrative fragment. Trace
examples place IDs only in envelope correlation and the rendered name only in
`span_name`; their body uses the snake_case structure in §5.4 with status,
resource, and scope. Log and trace field-class pointers are payload-rooted. Metric
examples omit envelope outcome, use only `{value, attributes}` in
`instrument_data`, and use canonical label names rather than compatibility labels.

Each invalid example is derived from `base_example` by one closed `mutation`
whose `kind` equals the exact stable error code and whose ordered `changes` use
RFC 6901 pointers rooted at `{signal,family?,record}`. Each change is `add`,
`replace`, or `remove`; values are required for add/replace and forbidden for
remove. The compiler applies that one semantic mutation and requires byte-equivalent
structured equality with the authored invalid vector. It MUST NOT omit unrelated
required fields or contain a second defect that could fail first. The minimum
single-fault corpus covers both-arm/neither-arm and forbidden-envelope states;
envelope-prefixed field-class pointers; unknown structural members; trace
camelCase/duplicate identity fields; zero/malformed IDs; end-before-start; invalid
status aliases; every nested dropped-count overflow; scope/profile and family
equality mismatch; metric unknown labels and outcome; each condition true with its
field absent and each forbidden false-state field present; all twelve valid phase
pairs, a mismatched pair, and reserved phase code zero.

### 5.3 Canonical families and producer mappings

Canonical log families and current producer identities are different registry
concepts. The fourteen gateway event types and 188 audit actions are producer
mappings; they are not 202 additional log-family definitions. Each mapping records
its typed producer key, source, event-name policy, default identity or closed set of
allowed contextual identities, severity policy, mandatory-floor rules, companion
rules, and compatibility lifecycle. It references registered log identities and
MUST NOT define a body schema, override a referenced family's bucket, or create an
implicit family.

To keep this exact mapping inventory reviewable, a repeated closed contextual set
is declared once as a named producer-identity set and mappings reference exactly
one set. The compiler expands the reference into an immutable explicit identity
tuple before producing runtime data. Sets cannot include other sets, use wildcard
members, inherit, union, or supply a fallback. Empty, duplicate, unknown, unused,
or policy-incompatible sets are errors, so factoring cannot broaden a producer's
allowed identities.

The canonical log-identity baseline contains 75 dotted event identities and twelve
lifecycle/compatibility identities. This includes `guardrail.judge.completed`,
whose existing fixed `judge` producer mapping and distinct judge payload require a
canonical guardrail log family rather than an alias to
`guardrail.evaluation.completed`. Producer-derived contextual identities and
compatibility-window `legacy.audit.*` identities are registered through producer
mappings rather than copied into another family list. A `legacy.audit.*` identity
is explicitly compatibility-only and has no generated family builder. The compiler
fails if the current-state inventory of fourteen gateway types or 188 audit actions
differs from the mappings, if a mapping can resolve to an unregistered identity, or
if a non-legacy resolved identity's bucket conflicts with its canonical family.
Generated route/classification registries consume these mappings directly.

### 5.4 Metric labels and compatibility projections

For a metric family, its inherited `attributes` are its complete canonical label
schema. The metric block adds `empty_labels_reason` if and only if the resolved set
is empty; an unexplained empty set is invalid. During the v7-to-v8 cutover, the
machine-derived current-state inventory records the exact labels observed at every
real `Add`/`Record` callsite and the reason for each genuinely label-free
instrument. The compiler requires equality for all 131 families. After callsites
use generated per-family APIs, those APIs and real-producer conformance replace the
temporary bootstrap extractor; Go does not remain a second authoring source.

Canonical labels use pinned standard names or the `defenseclaw.*` namespace.
Current unqualified, deprecated, or otherwise compatibility-only names are emitted
through a family-local projection:

```yaml
metric:
  # instrument_name/type/value_type/unit/description/temporality/boundaries omitted
  label_projections:
    - profile: local-observability-v1
      mappings:
        - ref: http.request.method
          label: http.method
```

There is at most one entry per profile. Every mapping source is a resolved
canonical label and appears once; projected names are unique. An omitted canonical
label projects unchanged. The projected set, not the canonical set, must equal the
frozen v7/local-observability inventory. This preserves current Prometheus queries
without making deprecated `http.method`, nonstandard `gen_ai.agent.type`, or an
ambiguous unqualified `state` canonical. Alias collisions, unknown profiles, and
unqualified custom canonical attributes fail.

Ordinary metric families reject high-cardinality labels and content, credential,
path, reason, evidence, and error classes. The only application-metric exceptions
are the exact six Agent360 native families and the two pinned GenAI client families
listed by `local-observability-v1`, with their exact label sets. Each remains under
the current 2,048-tuple application-family cardinality limit. Separately, the
derived Agent360 spanmetrics projection retains its existing Collector limits:
10,000 dimension-cache entries, 1,000 resource-metrics-cache entries, and 24-hour
series expiration. Neither exception has a wildcard, set composition, or effect on
unlisted OTLP metric schemas.

The registry metric default is `cardinality_limit: 2048`, enforced on each
ordinary family's distinct canonical label tuple before export. A non-Agent360
string label uses `enum-v1`, or uses `bounded-v1`/`identifier-v1` with an effective
`max_utf8_bytes` bound and the family tuple cap; a `low`/`bounded` declaration or
human note alone is insufficient. Known status, type, severity, code, and subsystem
vocabularies use closed enums. The eight exact compatibility families above retain
the same 2,048 application limit and do not raise it globally.

## 6. Generated Public Artifacts

### 6.1 One bundle for most consumers

`telemetry.schema.json` is the recommended public artifact. It contains:

- A top-level discriminated union by signal and family.
- Reusable `$defs` for resources, envelopes, attributes, content state, events,
  links, metrics, and domain bodies.
- Stable `$id` and version.
- No copied definitions with divergent meaning.

Transport envelopes such as gateway JSONL and CLI scan export either become
generated views or reference generated canonical body `$defs`. Transport-only
fields remain with the transport envelope; domain fields are not re-authored.

External consumers can validate one bundle and select a `$defs` pointer. They do
not need to discover which of many similarly named files applies.

The candidate bundle is acceptable only when its top-level union and every family
definition are generated from the same materialized structural/domain IR as the
builders. All curated valid examples must pass both, and every single-fault invalid
example must fail both with the declared code. A candidate that merely renders
attribute skeletons, lacks the exact envelope/correlation/provenance or signal
arms, permits unknown members, omits structural privacy, conditions, lifecycle,
phase/code, or OTLP mapping metadata, or accepts a builder-rejected shape is not a
complete `telemetry.schema.json` and cannot become public authority.

### 6.2 Compact catalog

`catalog.json` is designed for SDKs, setup tools, UI, and downstream mapping. For
each family it exposes:

- Signal, bucket, stable family ID, name pattern, and kind.
- Required/conditional/optional attributes.
- Type, stability, owner, field class, sensitivity, and cardinality.
- Allowed events/links.
- Compatibility-profile identifiers and links to their generated manifests.
- Introduced/deprecated/removed versions.

The portable catalog MUST NOT contain dashboard consumers, datasource or dashboard
UIDs, normalized Prometheus names/labels/buckets, Loki/Tempo query fields, or
dashboard-query aliases. Those consumer-specific mappings live only in
`compatibility/local-observability.json`.

### 6.3 Human reference

`catalog.md` provides:

- One-page namespace decision.
- Trace-tree examples.
- Per-family required and useful fields.
- Redaction classification.
- Backend compatibility matrix.
- Query examples using standard fields first and DefenseClaw overlay second.

It is generated from the same registry, so documentation cannot silently drift.

### 6.4 Per-family files only when required

Some integrations or installed binaries may require a standalone schema. Those
files are generated views of the bundle, never separately authored contracts. A
small generated standalone set is acceptable for:

- Runtime embedding where a whole bundle is too expensive.
- A CLI `--schema` command.
- A vendor conformance harness.
- A downstream system that cannot resolve `$ref` into the bundle.

`compatibility/local-observability.json` is generated because it is a consumer
manifest rather than a canonical family schema. It is the only generated registry
artifact that binds registry fields to the exact metric normalization, bounded
labels, histogram buckets, Loki JSON fields, Tempo attributes,
datasource/dashboard UIDs, and aliases consumed by the bundled dashboards. The
portable catalog may link to this manifest by compatibility-profile ID but does not
copy its mappings. The dashboard checker parses every query and fails when its
dependency is absent from this manifest.

`compatibility/v7-exporter-selection.json` is the migration counterpart. For every
current v7 log, trace, metric, audit action, gateway JSONL/console event, OTel span
filter operation, and destination-specific emission path, it records the canonical
v8 signal, bucket, source, event/family/instrument identity, eligibility, and
`legacy-v7` projection disposition. The converter consumes this generated artifact
and MUST NOT contain a hand-maintained duplicate family list. It is versioned with
the registry, deterministic, secret-free, and fails generation when a current
producer/exporter has no unambiguous disposition.

### 6.5 Generated compatibility views and embed APIs

The existing public telemetry schema paths remain available during the
compatibility window as generated standalone views of `telemetry.schema.json`.
Each view preserves its existing `$id` and independently resolvable local `$ref`
behavior; an old path MUST NOT become a network-dependent pointer to the bundle.
The thirteen current `schemas/otel/*.json` files and the current top-level activity,
audit, gateway, hook-audit, network-egress, scan-event, scan-finding, and scan-result
schemas are generated views after cutover, not separately authored contracts.

`schemas/embed.go` retains its copy-safe manifest and dependency-lock accessors and
adds copy-safe bundle/catalog accessors. Gateway or CLI schema mirrors are generated
from the same bytes. Runtime and public-schema consumers switch to these artifacts
only after byte/semantic, `$id`/`$ref`, fixture, and embed parity passes in one
cutover change; merely adding candidate generated files does not make them a second
active source of truth.

Coarse `legacy_bindings` are not sufficient authority for that cutover. Before an
existing public path becomes generated, the registry owns a typed `public_views`
entry containing its exact output path, JSON Schema dialect, `$id`, compatibility
lifecycle, root/transport template, definition and discriminator layout,
`additionalProperties` policy, local and cross-resource reference closure, mirror
and embed targets, and a field-level disposition for every legacy JSON Pointer.
Each field disposition is exactly one of preserved, renamed/alias, removed, or
corrected; preserved/renamed fields identify their canonical source, projected
name, requiredness, constraints, encoding conversion, redaction/class parity, and
fixture coverage. Transport-only fields are explicit and classified rather than
being inferred from a similarly named canonical attribute.

The immutable migration baseline may be a digest-pinned normalized snapshot of the
current twenty-one public schemas, but generated output can never recursively serve
as its own migration input. The compiler rejects a missing field disposition,
unresolved `$ref`, changed dialect/ID, incomplete offline resource closure, mirror
or wheel byte drift, and any compatibility view whose dynamic leaves lack an exact
field-class derivation. Candidate bundle/catalog artifacts may land before this
metadata; no existing public path changes authority until the complete parity gate.

The baseline is read from one full pre-cutover Git commit, never from the worktree.
Its lossless JSON canonicalizer rejects duplicate keys, invalid UTF-8, lone
surrogates, non-finite values, unsupported nested-ID/anchor/dynamic/recursive
reference semantics, and excessive nesting while retaining every numeric token
lexeme (`0.0`, `-0`, large integers, and exponent spelling). Each resource digest
is domain-separated by algorithm version, path, dialect, `$id`, and complete
canonical document. The baseline records commit/tree/blob provenance, source and
canonical digests, all twenty-one documents, and exact offline reference closure.
Refresh is permitted only in the same pre-cutover epoch; future evolution starts a
new explicitly acknowledged epoch rather than snapshotting generated output.

Every generated JSON public view carries the exact top-level custom keyword
`x-defenseclaw-generated` with a closed object containing generator ID, registry
version, public-view ID, and baseline epoch. That keyword is a typed declared
extension/patch in `public_views`, not an unreviewed annotation. The generated
output manifest also lists every public output path. Baseline tooling rejects a
source commit when either marker says any of the twenty-one source files already
has generated authority. Marker omission, disagreement, or an output-manifest
claim without the per-file marker fails the eventual cutover gate.

## 7. Standard Base Plus DefenseClaw Overlay

### 7.1 Agent/model/tool/retrieval

These families use OTel GenAI names and meanings as their portable primary fields.
Examples:

- `gen_ai.operation.name`
- `gen_ai.provider.name`
- `gen_ai.agent.*`
- `gen_ai.conversation.id`
- `gen_ai.request.*`
- `gen_ai.response.*`
- `gen_ai.usage.*`
- `gen_ai.tool.*`
- `gen_ai.input.messages`
- `gen_ai.output.messages`

DefenseClaw adds only what the standard does not represent, such as bucket, policy,
guardrail, enforcement, connector lifecycle, config generation, and redaction
state.

### 7.2 Guardrail/enforcement/finding

These are DefenseClaw domain families because no stable GenAI convention fully
defines them. They still reuse standard status, error, resource, HTTP/RPC, and GenAI
model-call groups where applicable.

An LLM judge therefore composes:

```text
standard model chat span
+ DefenseClaw guardrail evaluation correlation
+ route-specific content projection
```

It is not a proprietary “judge span” that loses model observability, nor is the
whole guardrail decision incorrectly forced into a model attribute.

### 7.3 OpenInference

OpenInference fields remain useful for Galileo and other AI-observability tools, but
they are a generated compatibility view:

- `openinference.span.kind` is derived from the canonical family.
- `input.value` and `output.value` derive from the same redacted canonical content
  as GenAI messages.
- Alias equality and redaction parity are tested.
- Consumers are directed to the OTel GenAI fields for portable new integrations.

## 8. Required Registry Metadata

Every attribute definition includes:

| Metadata | Purpose |
|---|---|
| `type` | Wire type; no implicit stringification |
| `brief` and `examples` | Human understanding |
| `requirement_level` | Required, conditional, recommended, optional |
| `stability` | Development, stable, deprecated |
| `owner` | OTel, OTel GenAI, OpenInference compatibility, or DefenseClaw |
| `field_class` | Metadata, identifier, content, reason, evidence, error, path, credential |
| `sensitivity` | Safe, internal, sensitive, critical |
| `cardinality` | Low, bounded, high; metrics reject high-cardinality dimensions |
| `normalization` | Versioned normalizer plus typed effective constraints; prose notes are non-semantic |
| `introduced_in` | First schema version |
| `deprecated_in` / `removed_in` | Lifecycle when applicable |
| `alias_of` | Canonical source for compatibility aliases |

Missing field-class or sensitivity metadata is a compiler error for dynamic strings
and structured content.

Pinned upstream definitions receive a DefenseClaw `attribute_extensions` entry
whenever a canonical family references them. An extension supplies exactly
`field_class`, `sensitivity`, `cardinality`, and `normalization`; it cannot override
the upstream name, type, owner, or stability. Every referenced upstream attribute
has exactly one extension, and unknown, duplicate, missing, or unreferenced
extensions fail. This is how standard fields such as `gen_ai.input.messages` enter
the same centralized redaction and metric-cardinality policy as DefenseClaw fields.

The registry root owns the closed versioned normalizer catalog. Each entry has
`id`, `kind`, `default_constraints`, and `allowed_overrides`; v1 contains exactly
`identity-v1`, `bounded-v1`, `enum-v1`, `identifier-v1`,
`numeric-range-v1`, `structured-content-v1`, `redacted-content-v1`, `path-v1`,
`url-v1`, and `digest-v1`. Attribute and extension use is exact:

```yaml
normalization:
  id: identifier-v1
  overrides:
    max_utf8_bytes: 128
  notes: Human explanation only; generated validators ignore this text.
```

Effective constraints are catalog defaults replaced only by named allowlisted
overrides; a null value cannot remove a bound. Supported constraint keys are
`enum`, portable-RE2 `pattern`, `min`, `max`, `min_items`, `max_items`,
`max_utf8_bytes`, `max_item_utf8_bytes`, `max_depth`, and `max_properties`.
Enums are nonempty unique JSON scalars. Numeric bounds are finite, type-correct,
and ordered; `numeric-range-v1` has no implicit range, so every numeric field states
both bounds. Counts are integers, minima are nonnegative, maxima are positive, and
item bounds are ordered. `max_utf8_bytes` is the total canonical value budget;
`max_item_utf8_bytes` bounds each string element or structured string leaf.
Structured values always have byte, item, depth, and property bounds. Regexes reject
lookaround, backreferences, named groups, and other constructs outside the shared
Go/Python RE2 subset. The compiler rejects a normalizer incompatible with the
attribute type, so human prose can never be the only executable validation rule.

## 9. Schema and Configuration Are Separate

Operators do not choose arbitrary schemas in `config.yaml`. The producer family
selects the canonical contract. Config controls:

- Whether the bucket/signal is collected.
- Which destinations receive it.
- Route-specific redaction.
- Trace limits and the shipped semantic profile.
- Whether temporary documented compatibility aliases are emitted.

An administrator cannot define arbitrary new attributes, redefine standard types,
or upload a vendor schema through YAML. Custom producer/plugin schemas require a
separately reviewed extension namespace and registration process.

## 10. Version and Compatibility Model

### 10.1 Independent versions

The system tracks:

- Config schema version.
- Bucket catalog version.
- Telemetry registry version.
- Trace semantic-profile schema version (`trace_schema_version`).
- Individual family schema version (`family_schema_version`, emitted on spans as
  `defenseclaw.span.family_schema_version`).
- Upstream OTel general semantic-convention version.
- Upstream OTel GenAI profile version.
- OpenInference compatibility-profile version.
- Destination compatibility-profile version.

These are not collapsed into one `schema_version` integer. The canonical record
envelope retains `schema_version`, which versions the complete record shape.
Instrumentation-scope/schema metadata uses `trace_schema_version` for the composed
trace contract selected by the semantic profile. Each span independently carries
its family's `family_schema_version`. A family change does not by itself change the
envelope version, and an envelope change does not renumber unchanged span families;
a new composed trace profile may bind a new mix of family and dependency versions.
The effective view and record provenance identify all relevant versions without
forcing unrelated changes to bump every contract.

### 10.2 Change rules

| Change | Rule |
|---|---|
| Add optional safe attribute | Additive family change; regenerate fixtures/docs |
| Add required attribute | Breaking family version unless safely derivable for all producers |
| Rename standard attribute | Follow pinned upstream migration; compatibility alias and release note |
| Change type or meaning | Breaking family version |
| Add family | Additive registry change plus bucket/privacy/route review |
| Remove alias | Only at declared removal version with query migration |
| Change Galileo profile | Version profile; preview eligible-span diff |
| Change field class/sensitivity | Security-relevant breaking review even if wire name is unchanged |

### 10.3 Upstream updates

A dedicated command/report compares the pinned OTel/GenAI registry with a candidate
version and classifies added, changed, deprecated, and removed definitions. Updates
are deliberate pull requests, not dependency side effects.

## 11. Simplified Developer Workflow

To add or change telemetry:

1. Choose an existing standard attribute before adding a DefenseClaw attribute.
2. Add or update one family/group in the appropriate focused domain file.
3. Assign bucket, field class, sensitivity, cardinality, and compatibility profiles.
4. Regenerate the bundle, catalog, docs, constants, and fixtures.
5. Update the producer using generated constants/builders.
6. Run emitted-record conformance tests and destination projections.
7. Review the generated semantic diff.

Developers do not manually synchronize a Go string, Python string, four JSON
schemas, a Galileo filter, and a Markdown table.

### 11.1 Compiler and repository command

`scripts/generate_telemetry_registry.py` is the sole registry compiler. It accepts
`--write` to regenerate checked-in outputs and `--check` to regenerate in a
temporary location, compare every output byte, and fail on drift. The compiler
validates imports, lock digests, semantic-profile tuples, aliases, lifecycle
metadata, field classes, sensitivity, bucket ownership, event selectors, and vendor
projection requirements before emitting anything.

The existing `scripts/check_schemas.py` invokes the compiler in `--check` mode, so
contributors and CI use the existing `make check-schemas` target. The implementation
phase creates the compiler and integration; this specification does not pretend that
separate `telemetry-registry-check` Make targets already exist.

## 12. Generated APIs and Builders

The registry compiler MUST generate:

- Go and Python constants for stable family/event/attribute IDs.
- Typed builder validation for required fields and correct value types.
- Field-class maps for destination redaction.
- Route/classification registry entries.
- Schema fixtures and documentation.
- Galileo/OpenInference projection validators.
- The local-observability consumer manifest and checker inputs for Prometheus,
  Loki, Tempo, datasource/dashboard identities, and query compatibility.

Generated builders do not hide domain decisions. Required/conditional fields remain
visible to the caller, and unavailable data stays unavailable rather than receiving
synthetic defaults.

## 13. Migration From Current Schema Files

The current telemetry files are migration inputs:

- `resource.schema.json`
- `metrics.schema.json`
- Runtime agent, LLM, tool, and approval span schemas.
- Lifecycle, asset, scan, finding, alert, and connector event schemas.
- Galileo export profile.
- Gateway event envelope and its activity/scan/finding child schemas.
- Audit, hook-audit, and network-egress event schemas.
- CLI scan-result schema where it overlaps canonical scan/finding bodies.
- Merged PR #403 root/subagent lifecycle, runtime span, gateway envelope,
  hook-decision, metric, Collector spanmetrics, and missing-data contracts.
- Merged PR #412 dashboard queries, corrected metric/label/histogram contracts,
  datasource cadence, source/packaged parity, and static/live checker inventory.

Migration proceeds in stages:

1. Snapshot all twenty-one current public schemas as an immutable digest-pinned
   migration baseline, and import every field, type, requirement, name/kind
   pattern, event, Galileo eligibility, public identity, reference closure, and
   field-level disposition into registry v1 `public_views` metadata.
2. Detect duplicate definitions and incompatible meanings for the same key.
3. Assign standard/DefenseClaw/compatibility ownership.
4. Extract common resource, correlation, content, error, lifecycle, and security
   groups.
5. Generate schemas equivalent to current OTel and event contracts and prove
   fixture parity. Transport envelopes retain their distinct wire shape while
   referencing one canonical domain definition.
6. Add the rich v8 fields/families from `11-trace-and-span-contract.md`.
7. Switch conformance tests to the generated bundle/catalog.
8. After byte/semantic, `$id`/`$ref`, fixture, and embed parity, replace existing
   public per-family paths with generated standalone views in the same logical
   cutover that removes their hand-authored definitions. Retain those generated
   compatibility views for at least the required compatibility release.
9. Generate `local-observability-v1`, prove all fourteen dashboards and rules are
   covered, and keep aliases/dual emission until every current and historical query
   fixture has migrated.
10. Generate the v7 exporter/family compatibility selection, prove every current
    producer/action/signal/export path has one migration disposition, and make the
    converter fail when the generated artifact lacks an exact mapping.

No current schema is deleted merely because the registry exists. The release gate
requires a machine-generated inventory showing every old field as preserved,
renamed with alias, intentionally removed, or corrected with a breaking note.

## 14. Validation Layers

The architecture retains distinct enforcement levels:

- **Builder/runtime validation:** required type/shape/size checks before canonical
  record acceptance, without running a general JSON Schema interpreter on every hot
  span mutation.
- **Destination projection validation:** redaction, capability, and vendor-shape
  checks before export.
- **CI emitted-record conformance:** real Go/Python producers emit records compared
  with the registry/generated schema.
- **Public JSON Schema:** downstream and offline validation.
- **Golden semantic diff:** release review of schema changes.

## 15. Galileo as a Projection, Not a Schema Fork

`compatibility/galileo.json` is generated from:

- Galileo’s supported agent, LLM, tool, retriever, and workflow shapes.
- The canonical OTel GenAI groups.
- Required OpenInference aliases.
- DefenseClaw’s safe overlay allowlist.
- Destination-specific headers/resource projection and error requirements.

It answers “can this already-redacted span be ingested usefully by Galileo?” It does
not redefine the canonical family. General OTLP destinations continue to receive
native guardrail, scan, enforcement, network, platform, and compliance spans.

## 16. Generated Discoverability

The v8 release requires generated catalog and reference documentation. The
following interactive schema/explain commands are explicitly deferred follow-up
surfaces rather than blockers for the core configuration and registry migration:

```text
defenseclaw observability schema list
defenseclaw observability schema show span.model.chat
defenseclaw observability schema show --attribute gen_ai.request.model
defenseclaw observability schema compatibility span.model.chat galileo
defenseclaw observability schema diff --from REGISTRY_VERSION --to REGISTRY_VERSION
defenseclaw observability explain-event --family span.model.chat
```

Output shows portable standard fields first, then the DefenseClaw overlay,
redaction classes, examples, compatibility, and version provenance. It never prints
live content or secret values.

## 17. Acceptance Criteria

- One logical registry with the fixed manifest/GenAI/security/operations authoring
  set is the canonical telemetry source.
- Every current schema field appears in the migration inventory.
- Generated bundle, catalog, docs, constants, fixtures, and projections are
  deterministic and drift-free.
- Agent/model/tool/retrieval consumers can operate using standard fields without
  DefenseClaw-specific parsing.
- Security/policy consumers get the full DefenseClaw overlay without overloaded
  standard keys.
- OpenInference and Galileo aliases are provably derived from the same redacted
  canonical values.
- Go and Python producers pass the same generated conformance fixtures.
- Upstream semantic-convention changes cannot enter without a pinned-version diff.
- A new family normally changes one registry entry and producer code, not many
  hand-maintained schemas.
- Human documentation clearly distinguishes canonical, compatibility, required,
  optional, sensitive, and deprecated fields.
- Every PR #403 lifecycle identity/event/state/phase, operation boundary,
  connector-facing decision, missing-data flag, and Agent360 dimension has an
  explicit registry disposition.
- Every PR #412 metric name/label/histogram/cadence correction is represented by
  `local-observability-v1`; all fourteen source dashboards match their packaged
  copies and pass static plus live query validation.
- The generated v7 exporter-selection artifact covers every current producer,
  action, signal, span-filter operation, and destination eligibility rule; the
  migration converter consumes it without a duplicate hand-authored family list.
