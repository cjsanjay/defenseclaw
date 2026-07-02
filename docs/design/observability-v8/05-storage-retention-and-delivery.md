# Storage, Retention, and Delivery

## 1. Storage Roles

The v8 design has three distinct storage roles:

1. **Required event history** — the built-in SQLite `audit.db` store records every
   collected log after application of the bucket/default projection profile; that
   profile is `none` by default.
2. **Normalized projections** — query-oriented tables retain scan, finding,
   compliance activity, egress, and destination-health shapes required by APIs,
   CLI, TUI, dashboards, and policy workflows.
3. **Local forensic judge bodies** — a separate SQLite database stores explicitly
   retained raw judge responses and is never a general log-export source.

SQLite does not store complete trace graphs or raw metric series. Queryable summary
logs and normalized projections may describe trace/metric health.

## 2. Built-in SQLite Store

### 2.1 Initialization

- Exactly one SQLite store is created internally; it is not listed under source
  `destinations` and cannot be disabled.
- The gateway MUST open the database, apply append-only migrations, verify required
  pragmas and write capability, and initialize the reaper before reporting ready.
- Failure to initialize the built-in SQLite store causes startup failure.
- Existing database migrations are never reordered or removed.
- The SQLite path is restart-required.
- Newly created data directories use owner-only permissions and database files use
  mode `0600` unless an explicitly supported managed group-readable mode is
  configured and validated. Existing permissions must never be widened by startup,
  migration, or retention.
- Database paths must pass symlink, ownership, and managed-enterprise trust checks.

### 2.2 Write contract

For every collected log:

1. Resolve the bucket profile, configured global profile, then the bucket's
   versioned catalog default.
2. Clone and redact using that effective profile.
3. Validate the projected record.
4. Insert one event-history row.
5. Insert or update applicable normalized projections in the same transaction when
   atomic visibility is required.

Mandatory-floor-only records follow the same sequence but are minimal and skip all
optional destinations.

The row persisted in SQLite is the canonical **local representation**, not a direct
producer object. With the default `none` profile its governed content remains
unredacted, while schema validation, bounds, serialization, provenance, and
integrity rules still apply. Selecting a redacting default/bucket profile changes
new local projections. Judge bodies remain the separate forensic store described in
section 4 because they are not ordinary canonical log bodies.

### 2.3 Event-history schema evolution

The existing `audit_events` table remains the compatibility anchor. Its current
operator-facing columns remain readable. A v8 migration adds or standardizes:

| Column | Purpose |
|---|---|
| `bucket` | Required v8 semantic bucket |
| `event_name` | Required stable event name |
| `source` | Required normalized producer |
| `connector` | Optional connector |
| `signal` | `logs`; reserved for explicit future local signal summaries |
| `bucket_catalog_version` | Catalog version governing the stored bucket assignment |
| `payload_json` | Complete redacted typed body for the SQLite projection |
| `redaction_profile` | Effective profile name used for persistence |
| `mandatory` | Whether the event belongs to the compliance floor |
| `request_id`, `session_id`, `turn_id`, `trace_id` | Direct indexed correlation keys |
| `evaluation_id`, `scan_id`, `finding_id`, `enforcement_action_id` | Direct semantic join keys |
| `schema_version`, `content_hash`, `generation`, `binary_version` | Provenance/integrity metadata |

`action`, `target`, `actor`, `details`, `structured_json`, `severity`, and existing
correlation fields remain populated where meaningful during compatibility. New v8
readers use bucket, event name, and typed payload rather than parsing `details`.

The `audit_events.schema_version` column (and the envelope field it projects) is the
version of an individual event schema. The SQLite table named `schema_version` is
database-migration state. They are unrelated despite the shared name; the table is
protected current state and is never reaped.

Payload JSON MUST be bounded, deterministic for integrity purposes, and already
redacted. Content hash is computed from the projected canonical serialization.

### 2.4 Normalized projections

The following query-oriented projections remain supported:

- `scan_results` for `asset.scan` summaries.
- Legacy `findings` during compatibility reads.
- `scan_findings` for `security.finding` detail.
- `activity_events` for `compliance.activity` mutations.
- `network_egress_events` for `network.egress` queries.
- `sink_health`, renamed in API vocabulary to destination health while retaining
  the table for migration compatibility.
- Legacy `judge_responses` in `audit.db` until migration/retention has removed all
  required compatibility data.

The event-history row is authoritative for v8 observability. Projections are derived
transactionally and MUST NOT cause a second exported event. A projection failure
rolls back the event insert when the API requires the projection for correctness;
otherwise it creates a mandatory projection-health failure with explicit degraded
state.

### 2.5 State tables are not event history

The following are current-state stores and MUST NOT be deleted by event retention:

- `actions`
- `target_snapshots`
- `schema_version`

Any new current-state table must explicitly declare retention ownership before
being added.

## 3. Finding Persistence

- Each observed finding is an immutable occurrence with its own `finding_id`.
- `rule_id` is stable for aggregation but is not itself an occurrence ID.
- Scan/evaluation correlation must be retained.
- Evidence summary, description, location, and remediation are stored after the
  local bucket/default projection; by default that projection is unredacted.
- v8 does not add `status: open` or update a row to resolved/reopened.
- Repeated observations may be aggregated in queries using rule ID, target, and a
  safe fingerprint, but the logger does not silently collapse occurrences.

If a later case-management feature introduces mutable finding cases, it must use a
separate table and event stream rather than changing the meaning of occurrence rows.

## 4. Judge-Body Store

- `judge_bodies.db` remains a separate schema and connection pool.
- Its `judge_responses` rows retain raw response bodies only when forensic retention
  is explicitly enabled by the guardrail configuration.
- Raw judge bodies are never copied to `audit_events.payload_json`, JSONL, console,
  Splunk, HTTP JSONL, or OTLP.
- The store retains request/trace/run/session/agent/policy/tool correlation and
  provenance needed for local investigation.
- The store follows the same age cutoff as event history.
- If the feature is disabled, new bodies are not written; existing bodies age out
  under retention rather than being immediately destroyed unless a separate
  explicit purge command is invoked.
- Because judge bodies can contain raw model output, the judge-body file must never
  be more permissive than the audit database and should be called out separately by
  doctor when permissions are unsafe.

## 5. Retention Contract

### 5.1 Configuration

- One global `retention_days` value lives under `observability.local`.
- Default: 90 days.
- `0`: retain event/evidence history forever and do not schedule deletion.
- Positive integer: delete rows strictly older than the UTC cutoff.
- Negative, fractional, or unreasonably large values that overflow duration
  calculation are invalid.

The cutoff is calculated once per reaper run from an injected clock:

`cutoff = now.UTC() - retention_days * 24h`

Rows with timestamp equal to the cutoff are retained. Rows older than it are
eligible.

### 5.2 Included tables

The reaper covers:

- `audit_events`
- `activity_events`
- `network_egress_events`
- `sink_health`
- `scan_findings`
- Legacy `findings`
- `scan_results`
- Legacy `audit.db` `judge_responses`
- Separate `judge_bodies.db` `judge_responses`

New event-history/projection tables MUST be added to the reaper registry in the same
change that creates them. A completeness test compares the table registry with the
migration catalog.

### 5.3 Deletion order

Within scan history, delete children before parents:

1. `scan_findings`
2. Legacy `findings`
3. `scan_results`

Other independent history tables may be deleted in deterministic table order.
Foreign keys remain enabled; the implementation MUST NOT disable integrity checks to
make retention succeed.

### 5.4 Scheduling and batching

- Run once after successful startup initialization.
- Run every six hours thereafter.
- Use an injected clock and scheduler in tests.
- Delete at most 1,000 rows per table per transaction.
- Commit between batches and yield so interactive queries and writes can proceed.
- Continue batches until no eligible rows remain or context is cancelled.
- Use indexed timestamp predicates.
- A live reload of `retention_days` changes the next run and MAY trigger one prompt
  asynchronous run when the age becomes shorter.

### 5.5 Maintenance

- Do not run blocking `VACUUM` automatically.
- A passive WAL checkpoint MAY run after a successful reaper cycle.
- Full compaction remains an explicit maintenance command.
- Retention failure leaves the affected data intact, changes health to degraded,
  increments bounded failure metrics, and emits a mandatory record.

### 5.6 Retention telemetry

Per run, record bounded metrics:

- Rows deleted by table class.
- Run duration.
- Batch count.
- Last successful completion time.
- Failure count by stable error class.

Table names in metrics must come from the fixed reaper registry.

## 6. Optional Destination Delivery

### 6.1 Isolation

Every optional push destination owns:

- Transport client.
- Bounded queue.
- Batch processor where applicable.
- Retry/circuit state.
- Health state.
- Counters for accepted, delivered, retried, dropped, and rejected records.

No optional destination shares a queue with SQLite or another destination.

### 6.2 Enqueue and backpressure

- Producer paths MUST NOT wait indefinitely for a remote destination.
- Queues are bounded by validated configuration.
- When a remote log/trace queue is full, the newest attempted enqueue is dropped for
  that destination, the locally persisted record remains available, and bounded
  health telemetry records the drop.
- Drop health emission must be rate-limited and recursion-safe.
- Prometheus is a pull destination and does not use a push queue.
- Metric SDK reader/exporter backpressure follows SDK semantics but must expose
  export failures and collection duration.

### 6.3 Retry

- Retry only failures classified as transient by the transport adapter.
- Do not retry authentication or permanently malformed payload failures until
  configuration changes or the circuit probe interval elapses.
- Use bounded exponential backoff with jitter.
- Respect shutdown deadlines and request context.
- Do not re-run redaction on every retry; retry the immutable projected payload.

### 6.4 Per-destination health states

Destinations report:

- `disabled`
- `initializing`
- `healthy`
- `degraded`
- `failing`
- `draining`
- `stopped`

Health transitions, not every identical failure, produce mandatory health logs.
Detailed attempt counters remain metrics/projections.

### 6.5 Delivery guarantees

- SQLite: required local durability after a successful transaction.
- Optional remote push destinations: at-most-once enqueue with bounded in-process
  retry; duplicates MAY occur after ambiguous transport acknowledgements.
- The record ID and content hash permit downstream deduplication.
- No claim of exactly-once remote delivery is made.

## 7. JSONL and Console

- JSONL receives the same projected record shape as other log destinations.
- Existing file ownership, permissions, and reopen behavior must be preserved and
  documented by the adapter. The v7 gateway defaults become explicit rotation
  knobs: 50 MiB, 5 backups, 30 days, and compression enabled.
- The v7 `DEFENSECLAW_JSONL_DISABLE` state is migrated once into the destination's
  `enabled` value; v8 does not continue consulting that environment kill switch.
- Console rendering derives from the projected record and must never reach back to
  the canonical raw body for “pretty” output.
- Failure to write optional JSONL or console output does not fail SQLite writes.

## 8. Inbound OTLP

- Inbound OTLP logs, traces, and metrics are producer inputs, not trusted pre-routed
  output.
- Normalize supported records into canonical buckets and event names.
- Apply collection before local persistence or re-export.
- Malformed batches follow the existing retry-suppression requirements only where
  returning a transport error would create an unsafe retry storm; the rejection is
  still recorded as `telemetry.ingest` health metadata.
- Remove opaque transport-specific raw bypasses such as preserved decoded HEC event
  blobs. Retain safe normalized fields or bounded redacted summaries.
- A receiver must not export a record back to its origin in an infinite loop;
  provenance and hop limits are required.

## 9. Query and Operator Surfaces

- Existing audit, alert, scan, and egress API/TUI queries continue to work through
  projections during migration.
- New queries support bucket, event name, source, connector, severity, time, and
  correlation identifiers without parsing free text.
- Doctor and TUI expose SQLite status, retention, last reaper result, destination
  health, queue drops, and effective unredacted/redacted profiles.
- `DEFENSECLAW_REVEAL_PII`, if retained, is an authorized local display-time reveal
  control only. It does not change persisted/exported route projections or enable
  judge-body retention.

## 10. Record Integrity and Verification

DefenseClaw currently supports payload HMACs derived from the device identity. v8
preserves this capability but moves it after route-specific redaction.

- Every log destination projection MAY carry `payload_hmac`, `integrity_algorithm`,
  and `integrity_key_id` when an integrity key is available.
- The HMAC covers the final canonical serialized envelope and redacted body, excluding
  the HMAC field itself.
- SQLite stores the HMAC for its own projection. A Splunk/OTLP/JSONL projection with
  different redaction has a different valid HMAC.
- Content hash is useful for equality/deduplication but is not a substitute for a
  keyed integrity value.
- Key derivation remains domain-separated from other device-key uses. Key material
  is never placed in config, logs, errors, or destination payloads.
- If the key is unavailable, delivery and the mandatory local floor continue, but
  platform health and doctor report that records are unsigned. A future policy may
  make signing required, but v8 does not silently fail all audit writes solely due
  to boot-order/key availability.
- Key rotation must change `integrity_key_id`; verification tooling must identify
  records whose prior key is unavailable rather than labeling them corrupt.
- Provide local verification by record ID/range and machine-readable results without
  exposing redacted content.

Per-record HMAC does not prove that a row was never deleted and does not make SQLite
an append-only ledger. Normal retention intentionally deletes history. A chained or
externally anchored tamper-evident audit ledger is outside this scope and must not be
claimed by product documentation.

## 11. At-Rest Protection and Capacity

- v8 guarantees redaction, strict filesystem permissions, and path trust checks; it
  does not claim application-level database encryption unless an encrypted SQLite
  backend is separately implemented and tested.
- Product documentation should recommend platform disk encryption for hosts that
  retain sensitive local history or raw judge bodies.
- `retention_days: 0` is intentionally unbounded and must produce a lint/doctor
  capacity warning unless the operator explicitly acknowledges it.
- Doctor/TUI report database file size, free filesystem capacity, last successful
  write, last reaper result, and estimated growth where sufficient history exists.
- A disk-full or quota failure changes SQLite health to failed, emits the safest
  possible stderr/platform signal, and follows mandatory local-integrity failure
  behavior. It must not cause remote exporters to receive a raw fallback record.
- Automatic deletion remains age-based; v8 does not invent an undocumented
  size-based deletion order that could remove recent compliance history.
