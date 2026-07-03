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

Only the manifest, three domain model files, lock, and curated examples are edited
by humans. Common attributes are defined once and referenced across those files.
Everything under `generated/` is reproducible and carries a generated-file header.
CI fails on drift. Contributors normally touch one domain file for a new family;
consumers normally open only the generated catalog or bundle.

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
| `normalization` | Canonical enum/casing/length behavior |
| `introduced_in` | First schema version |
| `deprecated_in` / `removed_in` | Lifecycle when applicable |
| `alias_of` | Canonical source for compatibility aliases |

Missing field-class or sensitivity metadata is a compiler error for dynamic strings
and structured content.

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

1. Import all current fields, types, requirements, name/kind patterns, events, and
   Galileo eligibility into registry v1.
2. Detect duplicate definitions and incompatible meanings for the same key.
3. Assign standard/DefenseClaw/compatibility ownership.
4. Extract common resource, correlation, content, error, lifecycle, and security
   groups.
5. Generate schemas equivalent to current OTel and event contracts and prove
   fixture parity. Transport envelopes retain their distinct wire shape while
   referencing one canonical domain definition.
6. Add the rich v8 fields/families from `11-trace-and-span-contract.md`.
7. Switch conformance tests to the generated bundle/catalog.
8. Retire hand-authored per-family JSON only after byte/semantic parity and one
   compatibility release where needed.
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
