# DefenseClaw Observability v8 — Codex Execution Manifest

```yaml
spec_status: approved-for-implementation
goal_status: active
current_phase: P2
target_config_version: 8
baseline_commit: fd13acedfcffc0cc431d5a72f329b56b50b22baa
last_verified_commit: 39fe480d1266164aef2e0f2b5c70c7a02daec53e
last_updated: 2026-07-03
```

## Goal Contract

Implement DefenseClaw observability v8 end to end from the tracked normative
specification package, preserving PR #403 root/subagent Agent360 lifecycle and
traceability and PR #412 local-observability dashboard behavior, with an automatic
one-command v7-to-v8 upgrade and every release gate passing.

This file is the execution ledger for the active Codex goal. It is not a fifteenth
normative observability contract. Normative behavior lives in
[the observability v8 specification package](docs/design/observability-v8/README.md).

The goal is complete only when every release-blocking work package and phase gate
is `DONE`, the final verification suite passes at the final commit, the PR is open
from this branch against `main`, all required CI/CD checks are green, review issues
are resolved, and no required work remains. Partial implementation, budget pressure,
or a plausible-looking dashboard is not completion.

## Current Execution Snapshot

| Field | Value |
|---|---|
| Active work package | `P2-WP05` — global retention reaper and immutable atomic runtime graph/reload/health |
| Ready queue | `P2-GATE` after the reaper, graph swap, rollback, and health gates are complete |
| Blocked | None |
| Next phase gate | `P2-GATE` — canonical router, redaction, SQLite, retention, and representative safe-path integration without producer-wide cutover |
| Root coordinator | Primary Codex thread |
| Implementation branch | `codex/observability-v8-spec-implementation` from `main` |

The root coordinator updates this snapshot whenever ownership, active work, the
ready queue, or the next gate changes.

## Authority and Precedence

1. Repository and user instructions, including `AGENTS.md`.
2. This execution manifest for work ordering, ownership, and evidence.
3. The normative package under `docs/design/observability-v8/` for product and
   implementation behavior.

Every package document is normative according to its own scope. If implementation
reveals an ambiguity or infeasible requirement, amend the affected normative
document, the D-/S-/P- decision log, the traceability appendix, and acceptance tests
before changing behavior. No agent may silently reopen a locked decision, weaken a
release gate, or create a second configuration/telemetry pipeline.

The specification passed `P0-GATE` at commit `963b1bc9f`. Behavior-changing
implementation follows the phase order and locked decisions below. A later
ambiguity requires an explicit spec amendment and traceability update; it does not
silently return the package to draft or authorize implementation divergence.

## Normative Source Map

| Contract | Authority |
|---|---|
| [Architecture and requirements](docs/design/observability-v8/01-architecture-and-requirements.md) | Goals, pipeline, invariants, mandatory floor |
| [Taxonomy and data model](docs/design/observability-v8/02-taxonomy-and-data-model.md) | Fourteen buckets, envelopes, severity, finding semantics |
| [Configuration contract](docs/design/observability-v8/03-configuration-contract.md) | v8 YAML, defaults, capabilities, routes, validation, reload |
| [Redaction contract](docs/design/observability-v8/04-redaction-contract.md) | Profiles, detector groups, field classes, hash contract, failure behavior |
| [Storage, retention, and delivery](docs/design/observability-v8/05-storage-retention-and-delivery.md) | SQLite, projections, reaper, queues, health |
| [Migration and implementation](docs/design/observability-v8/06-migration-and-implementation.md) | Current mapping, phases, compatibility, removal scope |
| [Verification and acceptance](docs/design/observability-v8/07-verification-and-acceptance.md) | Test matrices, E2E scenarios, commands, release gates |
| [Decisions and exclusions](docs/design/observability-v8/08-decisions-and-exclusions.md) | D-/S-/P- log, exclusions, change control |
| [Configuration UX and bucket evolution](docs/design/observability-v8/09-configuration-ux-and-bucket-evolution.md) | Concise source, effective/reference views, catalog evolution |
| [Automatic upgrade](docs/design/observability-v8/10-automatic-upgrade-and-migration.md) | One-command migration, backup, failure, rollback |
| [Trace and span contract](docs/design/observability-v8/11-trace-and-span-contract.md) | Rich topology, families, events, links, Galileo, sampling |
| [Telemetry schema architecture](docs/design/observability-v8/12-telemetry-schema-architecture.md) | Canonical registry and generated artifacts |
| [Decision traceability](docs/design/observability-v8/13-decision-traceability.md) | Mechanical D-/S-/P- contract/test index |
| [Agent lifecycle and dashboard compatibility](docs/design/observability-v8/14-agent-lifecycle-and-dashboard-compatibility.md) | PR #403/#412 compatibility floor and local bundle |
| [Current-state inventory](docs/design/observability-v8/current-state-inventory.yaml) | Drift-checked v7 config, producer, schema, metric, dashboard, datasource, and pinned PR #403/#412 compatibility-baseline migration inputs |
| [Minimal configuration](docs/design/observability-v8/config-v8-observability-minimal.yaml) | Compact authoring example |
| [Reference configuration](docs/design/observability-v8/config-v8-observability-reference.yaml) | All-knobs generated/reference target |

Pinned compatibility baselines:

- PR #403 merge: `9e417889c4c456bc3c7e6c160ee98c1add1094ee`.
- PR #412 merge: `94dd46c689fefbcf85b8f478249e74f3925eca49`.

## Non-Negotiable Invariants

- Every canonical record has exactly one primary bucket.
- Collection is evaluated before construction, sampling, routing, and redaction.
- Exactly one implicit mandatory SQLite store receives every collected log and the
  local-only mandatory floor.
- Fresh v8 defaults collect every defined signal and preserve schema-eligible
  content unredacted; no remote export starts without a configured destination.
- An enabled destination with omitted policy receives every supported signal and
  catalog bucket unredacted. Explicit `send` or `routes` narrows that behavior.
- A record fans out independently to every matching destination. Advanced routes
  are first-match-wins within each destination and signal.
- The canonical record is immutable. Redaction and vendor adaptation operate on
  destination-owned projections.
- Automatic migration preserves narrower or redacted v7 behavior rather than
  broadening it to fresh-v8 defaults.
- Labels, span names, events, links, queues, caches, bodies, and cardinality are
  bounded; content and credentials never become metric labels.
- Valid reload swaps one immutable graph atomically; invalid reload leaves the old
  graph active.
- One semantic action produces one canonical record and expected projections; old
  and new direct paths must not duplicate it.
- Missing tokens, cost, content, timing, and parentage remain truthfully absent or
  `not_reported`; no producer or dashboard fabricates zero/empty values.
- PR #403 root/subagent, lifecycle/execution, phase/sequence/operation,
  hook-decision, and completed-operation-before-Stop behavior remains intact.
- PR #412 metric names, labels, histogram buckets, 60-second delta cadence,
  fourteen dashboard UIDs, three datasource UIDs, and source/packaged parity remain
  intact.
- `defenseclaw upgrade` performs the required atomic migration and compatible local
  bundle refresh while preserving custom files and history volumes.

## Status Vocabulary

Use only these values in work-package and gate tables:

| Status | Meaning |
|---|---|
| `TODO` | Defined but dependencies or capacity are not ready |
| `READY` | Dependencies are `DONE`; safe to assign |
| `IN_PROGRESS` | One named owner is actively working it |
| `BLOCKED` | Cannot progress; row records reason and unblock action |
| `DONE` | Root verified deliverables and commit-specific evidence |
| `SUPERSEDED` | Replaced by another named work package |

Only the root coordinator changes phase/work-package status. A subagent proposes
completion; the root verifies and records it. Relevant changes invalidate previous
evidence and move the affected gate out of `DONE` until reverified.

## Definition of Ready

A subagent work package is `READY` only when it has:

- One bounded objective and explicit non-goals.
- Normative document/decision references.
- Satisfied dependencies.
- Exclusive write scope and named shared hotspots.
- Expected artifacts and exact verification commands.
- Compatibility, privacy, security, migration, and performance constraints.

## Definition of Done

A work package is `DONE` only when:

- Implementation, tests, generated artifacts, docs, and fixtures for its scope are
  complete.
- No generated file was hand-edited when a generator owns it.
- Exact commands and observed results are recorded at the current commit.
- The diff contains no unrelated user changes or broad formatting churn.
- Compatibility/security implications were reviewed against D-/S-/P- decisions.
- Root integration verification passes and the work is committed.

## Dependency Graph

```text
P0 specification import/freeze and baseline inventory
  └─> P1 contracts, config compiler, strict validation, converter engine/API
       └─> P2 canonical model, router, redaction, SQLite, retention
            ├─> P3 destinations, OTel signals, Galileo, local profile
            │    └─> P4 producer migration and duplicate-path removal
            └─> P5 telemetry registry and rich trace/schema generation
                  └─> P5-WP06 generated v7 selection + converter goldens
P4 + P5-WP06 ─────────────────────────> P6 operator UX, dashboards, docs
P1 + P3 + P5-WP06 + P6 ───────────────> P7 one-command upgrade integration
P0..P7 ────────────────────────────> P8 final security/perf/release gates
```

P5 may begin after P2 while P3/P4 continue, but its destination projections depend
on stable P3 contracts. No phase is complete merely because code exists; its phase
gate must pass.

`P1-GATE` approves the side-effect-free converter engine and the strict typed API
that consumes generated compatibility data; it does not certify final v7 family
eligibility, local-dashboard coverage, or the complete migration golden matrix.
`P5-WP06` supplies those generated inputs from the sole registry compiler, proves
every current exporter/family mapping, and completes the goldens. It is a hard
dependency of automatic activation in P7 and final release, and neither phase may
substitute a converter-local family list, `*`, or all-catalog-buckets fallback.

## Phase and Work-Package Ledger

### P0 — Specification Import, Freeze, and Baseline

| ID | Status | Owner | Depends on | Deliverable | Verification/evidence |
|---|---|---|---|---|---|
| `P0-WP01` | `DONE` | root | — | Track normative package, root manifest, docs index; remove temporary-path claims | Commit `b5167c2d9`; link/YAML/decision lint passed |
| `P0-WP02` | `DONE` | subagent, root verified | `P0-WP01` | Machine-readable inventory of current config fields, producers, schemas, metrics, dashboards, and migration disposition | 37 anchors, 14 events, 188 actions, 131 metrics, 22 schemas, 14 dashboards, 3 datasources, 2 compatibility commits; checker and 6 tests passed at `963b1bc9f` |
| `P0-WP03` | `DONE` | subagents + root | `P0-WP01` | Review D-/S- locks and P-* proposed defaults; resolve contradictions in-package | 81 decisions mechanically traceable; two CodeRabbit review passes raised 23 total findings, all valid findings resolved; commit `963b1bc9f` |
| `P0-GATE` | `DONE` | root | `P0-WP01..03` | Specification approved for behavior-changing implementation | `make check`, 42 focused tests, Ruff, and diff validation passed at `963b1bc9f` |

### P1 — Contracts, Configuration, and Converter

| ID | Status | Owner | Depends on | Deliverable | Verification/evidence |
|---|---|---|---|---|---|
| `P1-WP01` | `DONE` | subagent + root | `P0-GATE` | Bucket/signal/event/severity/source/selector types and classification contract | 14 gateway events and 188 audit actions exhaustively classified; focused Go tests/vet at `d15292434` |
| `P1-WP02` | `DONE` | root + subagents | `P1-WP01` | Go v8 schema, defaults, compiler, capabilities, routes, profiles, strict legacy rejection | Closed schema and embedded registry; strict parser; immutable/masked plan; capability/preset/route/profile/secret/path/endpoint/provenance diagnostics; normal/race/vet/schema suites and `make check` passed at `780adcf72` |
| `P1-WP03` | `DONE` | root + subagents | `P1-WP02` | Python source/schema parity with registry-owned selectors delegated to the canonical Go helper; comment-preserving writer; source/effective/reference/plan generation | Commits `3c9739c0c..c7234b5de`; 82 focused Python tests, normal/race Go tests, schema/reference drift gates, Ruff, and real Go/Python bridge passed |
| `P1-WP04` | `DONE` | root + subagents + Claude review | `P1-WP02..03` | Side-effect-free deterministic v7-to-v8 converter engine plus a strict typed contract for generated v7 eligibility, exact filter predicates, adapter routes, and local-profile coverage; no generated registry data is hand-authored here | Commits `bf4fed78b..c29cdddc4`; 237 focused converter/contract tests, Ruff/format/diff checks, exhaustive v7 precedence/secret/filter/parser/idempotence cases, and two canonical Go candidate validations passed. Synthetic fixtures prove missing, malformed, duplicate, incomplete, or inexact contract data fail closed; semantic family completeness/ambiguity/staleness remains `P5-WP06`/P7. |
| `P1-GATE` | `DONE` | root | `P1-WP01..04` | Immutable validated runtime plan plus converter engine/artifact API from YAML; runtime producers not switched and final generated selection/goldens explicitly remain in `P5-WP06` | At `c29cdddc4`: 334 broad Python tests; Go normal/race/vet; schema/reference/spec and full `make check`; local and multi-destination candidates compiled valid by the real Go helper. This gate does not certify final v7 family eligibility, PR #403/#412 dashboard coverage, Galileo equivalence, or complete migration goldens. |

### P2 — Canonical Router, Redaction, SQLite, Retention

| ID | Status | Owner | Depends on | Deliverable | Verification/evidence |
|---|---|---|---|---|---|
| `P2-WP01` | `DONE` | root + subagents | `P1-GATE` | Immutable generic canonical record substrate, deterministic current classified-log builder, and strict registered-identity validation; generated trace/metric family builders remain `P5-WP02` | Commits `13fddfe7c..b328351a6`; lossless lexical JSON, exact union/classes/bounds, immutable values/records, registry-resolved builders, authenticated minimal floor, adversarial normal/race/vet gates |
| `P2-WP02` | `DONE` | root + subagent | `P2-WP01` | Collection/floor gates and per-destination route compiler/evaluator | Commit `b8a2a9823`; immutable metadata, zero-allocation collection admission, floor over/understatement prevention, ordered selectors/drop/fan-out/capability tests, normal/race/vet gates |
| `P2-WP03` | `DONE` | root + subagents + Claude review | `P2-WP01` | Central profiles/detectors/field transforms and cross-language `hash-v1` | Commits `ba0f56636..b5890a92c`; exact profiles, 14-detector conformance, Unicode/hash parity, pure legacy-v7, key custody, immutable projection, P-060/P-061 privacy hardening, config adapter, normal/race/vet/schema/spec gates |
| `P2-WP04` | `DONE` | root + SQLite/judge/storage/graph subagents + Claude + CodeRabbit | `P2-WP01..03` | Implicit SQLite store, projections, integrity, judge separation | Commits `4f2a80166`, `1e0b9ea42`, `39fe480d1`: exact graph-bound local projections, mandatory all-bucket SQLite pipeline, hardened main/sidecar paths and readiness, correlation-key integrity, immutable finding plus mutable alert CAS/receipts/replay, retention-safe judge separation, post-commit reentrant health, and rollback-readable additive schemas. Normal/race/vet/Windows/make/spec/inventory gates passed; 12 of 16 CodeRabbit issues fixed and 4 contract/query-invalid suggestions rejected with evidence. |
| `P2-WP05` | `IN_PROGRESS` | root + runtime/storage subagents | `P2-WP04` | Global retention reaper and immutable atomic runtime graph/reload/health | Fake-clock/race/failure tests in progress |
| `P2-GATE` | `TODO` | root | `P2-WP01..05` | Representative producers route once through safe canonical path | Exactly-once/failure-injection evidence |

### P3 — Destinations, OTel, Galileo, Local Observability

| ID | Status | Owner | Depends on | Deliverable | Verification/evidence |
|---|---|---|---|---|---|
| `P3-WP01` | `TODO` | unassigned | `P2-GATE` | JSONL, console, Splunk HEC, HTTP JSONL adapters and isolated queues | Adapter/backpressure/network tests |
| `P3-WP02` | `TODO` | unassigned | `P2-GATE` | OTLP log/trace/metric routing, projection, sampling, inbound normalization | OTel signal/sampling/loop tests |
| `P3-WP03` | `TODO` | unassigned | `P3-WP02` | Metric catalog/gates/bounded attributes and native Prometheus option | Instrument/temporality tests |
| `P3-WP04` | `TODO` | unassigned | `P3-WP02` | Galileo projection, delivery funnel, partial success, exact canary | Galileo schema/canary tests |
| `P3-WP05` | `TODO` | unassigned | `P3-WP02..03` | `local-observability-v1`, Collector pipeline, PR #412 query inventory | Dashboard static/live compatibility tests |
| `P3-GATE` | `TODO` | root | `P3-WP01..05` | All destinations isolated; Galileo and local stack preserve baseline | Phase E2E evidence |

### P4 — Producer Migration and Legacy Removal

| ID | Status | Owner | Depends on | Deliverable | Verification/evidence |
|---|---|---|---|---|---|
| `P4-WP01` | `TODO` | unassigned | `P3-GATE` | Control-plane/platform/health producers migrated | Exact-count classification tests |
| `P4-WP02` | `TODO` | unassigned | `P3-GATE` | Guardrail/model/tool/approval/enforcement producers migrated | PR #403 correlation goldens |
| `P4-WP03` | `TODO` | unassigned | `P3-GATE` | Scan/asset/network/discovery/ingest producers migrated | Domain projection tests |
| `P4-WP04` | `TODO` | unassigned | `P4-WP01..03` | Duplicate bridges/direct fan-out/global toggles/legacy emit gates removed | Repository search plus no-dup tests |
| `P4-GATE` | `TODO` | root | `P4-WP01..04` | Every current producer classified; no active duplicate/legacy path | Exhaustive producer inventory |

### P5 — Rich Telemetry Registry and Trace Contracts

| ID | Status | Owner | Depends on | Deliverable | Verification/evidence |
|---|---|---|---|---|---|
| `P5-WP01` | `TODO` | unassigned | `P2-GATE` | Registry authoring model, dependency lock, sole compiler | `make check-schemas` drift checks |
| `P5-WP02` | `TODO` | unassigned | `P5-WP01` | Generated bundle/catalog/docs/constants/builders/field classes/selector registries/fixtures | Determinism and conformance tests |
| `P5-WP03` | `TODO` | unassigned | `P5-WP01`, `P3-WP02` | Rich bounded spans/events/links/status/content/retry/timing | Golden topology/sampling tests |
| `P5-WP04` | `TODO` | unassigned | `P5-WP02..03` | PR #403 lifecycle fixture migration and missing-data fidelity | Root/subagent real-producer goldens |
| `P5-WP05` | `TODO` | unassigned | `P3-WP05`, `P5-WP02` | Galileo/OpenInference/local-observability generated projections | Vendor/dashboard inventory tests |
| `P5-WP06` | `TODO` | unassigned | `P1-WP04`, `P5-WP02..05` | Generate `compatibility/v7-exporter-selection.json`, integrate it and the generated local-observability/Galileo profiles with the converter engine, and complete the reviewed mapping-by-mapping v7-to-v8 golden matrix without wildcard broadening | Generated-artifact schema/determinism/drift tests; every current log/trace/metric/action/adapter path mapped exactly; full/partial local coverage, filter-predicate, canonical Go candidate, and missing-mapping goldens pass |
| `P5-GATE` | `TODO` | root | `P5-WP01..06` | One canonical registry, complete generated migration selection, and no independently maintained telemetry schemas or converter family lists | Generated semantic diff and complete converter golden matrix reviewed |

### P6 — Operator Experience, Dashboards, and Documentation

| ID | Status | Owner | Depends on | Deliverable | Verification/evidence |
|---|---|---|---|---|---|
| `P6-WP01` | `TODO` | unassigned | `P4-GATE`, `P5-GATE` | Validate/effective/reference/plan/destination-test UX | CLI contract tests |
| `P6-WP02` | `TODO` | unassigned | `P6-WP01` | Setup/TUI/doctor destination, privacy, retention, and health UX | Python/TUI integration tests |
| `P6-WP03` | `TODO` | unassigned | `P3-WP05`, `P5-GATE` | Coordinated dashboard/rule/query migration and local-stack validation | 14 dashboards/313+ panels static/live checks |
| `P6-WP04` | `TODO` | unassigned | `P6-WP01..03` | User/admin/developer/migration/release documentation | Link/schema/example checks |
| `P6-GATE` | `TODO` | root | `P6-WP01..04` | Operators can author, inspect, test, and diagnose the full graph | UX and dashboard E2E evidence |

### P7 — Automatic Upgrade Integration

| ID | Status | Owner | Depends on | Deliverable | Verification/evidence |
|---|---|---|---|---|---|
| `P7-WP01` | `TODO` | unassigned | `P1-GATE`, `P5-WP06`, `P6-GATE` | Required migration registration using the generated compatibility selection and incompatible-start prevention | Manifest/cursor/failure tests; activation cannot proceed with a missing, stale, or ambiguous generated selection |
| `P7-WP02` | `TODO` | unassigned | `P7-WP01` | Exact backup, atomic config activation, restoration, idempotence | Fault-injection tests |
| `P7-WP03` | `TODO` | unassigned | `P3-GATE`, `P6-GATE` | Local bundle backup/refresh/restart with custom files/volumes preserved | Bundle upgrade/live inventory tests |
| `P7-WP04` | `TODO` | unassigned | `P7-WP01..03` | Historical baseline, permissions, retry, rollback matrix | Upgrade smoke matrix |
| `P7-GATE` | `TODO` | root | `P7-WP01..04` | One ordinary upgrade converges safely on complete v8 state | Full upgrade evidence |

### P8 — Final Integration, Security, Performance, CI/CD, and PR

| ID | Status | Owner | Depends on | Deliverable | Verification/evidence |
|---|---|---|---|---|---|
| `P8-WP01` | `TODO` | unassigned | `P0..P7` | Security/fuzz/network/redaction/canary audit | Security test suite/results |
| `P8-WP02` | `TODO` | unassigned | `P0..P7` | Race/performance/cardinality/queue/reaper benchmarks | Approved baseline comparison |
| `P8-WP03` | `TODO` | unassigned | `P0..P7` | E2E-1 through E2E-9 and final command suite | Commit-specific verification ledger |
| `P8-WP04` | `TODO` | unassigned | `P8-WP01..03` | Final legacy/duplicate-path/generated-drift/secret review | Search and review evidence |
| `P8-WP05` | `TODO` | root | `P8-WP01..04` | Detailed PR against `main`, CodeRabbit review/fixes, all CI/CD green | PR URL and green checks |
| `P8-GATE` | `TODO` | root | `P8-WP01..05` | Every requirement proven; active goal may be completed | Completion audit |

## Agent Coordination Protocol

- The root coordinator owns this file, integration ordering, task assignment,
  shared hotspots, commits, branch/PR operations, and final status.
- A subagent receives one concrete work package with normative references,
  dependencies, exclusive write scope, deliverables, and exact tests.
- Read-only inspection is unrestricted. Concurrent writes must not overlap.
- Shared hotspots require root ownership or an explicit handoff: `internal/config/`,
  migration registry/manifest, canonical telemetry registry, generated outputs,
  Makefile, local dashboard bundle, and this manifest.
- Exactly one agent at a time runs generators that write telemetry/dashboard
  artifacts. Generated outputs are changed through their generator only.
- A subagent handoff reports files changed, decisions made, exact commands/results,
  remaining risks, and current diff/commit state.
- Subagents propose `DONE`; root reviews the diff and reruns proportional tests
  before updating status and committing.
- Preserve unrelated user changes. Do not broadly format, destructively reset, or
  expand authority beyond the assigned package.
- A decision blocker pauses only the affected work package. Record the impacted
  D-/S-/P- IDs and continue independent `READY` work.

## Verification Ledger

Results are commit-specific. Append one row per meaningful command run; do not write
only “passed.” A relevant change invalidates old evidence.

| Run ID | Date | Commit | Work package/phase | Command | Observed result | Agent |
|---|---|---|---|---|---|---|
| `V-0001` | 2026-07-02 | `b5167c2d95d72ae2b1c71813aa35fd065c8a2d63` | P0 | `.venv/bin/python scripts/check_grafana_dashboards.py --require-packaged` | 14 dashboards, 313 panels; passed | root |
| `V-0002` | 2026-07-02 | `b5167c2d95d72ae2b1c71813aa35fd065c8a2d63` | P0 | `uv run python -m pytest cli/tests/test_agent360_dashboard.py cli/tests/test_grafana_dashboards.py -q` | 33 passed in 0.61s | root |
| `V-0003` | 2026-07-02 | `963b1bc9fb5a564c53809a70b452e61e888f768c` | P0 | `make check` | v7 parity, 81-decision spec, current-state inventory, 14 dashboards/313 panels, Go/TS provider coverage, catalog, and upgrade manifest passed | root |
| `V-0004` | 2026-07-02 | `963b1bc9fb5a564c53809a70b452e61e888f768c` | P0 | `.venv/bin/python -m pytest cli/tests/test_observability_v8_spec.py cli/tests/test_observability_v8_inventory.py cli/tests/test_agent360_dashboard.py cli/tests/test_grafana_dashboards.py -q` | 42 passed in 3.38s | root |
| `V-0005` | 2026-07-02 | `44b0b059c1f7441279f8f2318ed61c80a4cd25be` | P0 | `make check-observability-v8-spec` and focused spec tests/Ruff | 81 decisions valid; 5 fence-aware spec tests passed; all 5 post-approval CodeRabbit findings resolved | root |
| `V-0006` | 2026-07-02 | `d152924345426208223a07c75be6d8853b86a41c` | P1 | `go test ./internal/audit ./internal/gatewaylog ./internal/observability -count=1 && go vet ./internal/observability` | 14 gateway events and 188 audit actions classified; tests and vet passed | root |
| `V-0007` | 2026-07-02 | `705b185c982e9e6a83c292443689bf6abac06bf1` | P1-WP02 | `go test ./internal/observability -count=1` | Canonical event registry matched 14 gateway/188 audit classifications, 25 trace families, 131 metric instruments, and lifecycle aliases; passed | root + subagent |
| `V-0008` | 2026-07-02 | `780adcf72bf3db0cd1041abf2855197fe95b39f9` | P1-WP02 | `go test ./internal/observability ./internal/config ./schemas -count=1`; focused config race; vet; schema/spec checks; `make check` | Normal/race/vet passed; 23 JSON schemas plus v8 semantic lock passed; 83 decisions valid; v7 parity, 14 dashboards/313 panels, Go/TS provider coverage, LLM catalog, and upgrade manifest passed | root + subagents |
| `V-0009` | 2026-07-02 | `c7234b5de4baa4092761ad886a24ebcba8478af8` | P1-WP03 | `go test ./internal/observability ./internal/config ./internal/cli ./schemas -count=1`; `go test -race ./internal/config ./internal/cli -count=1`; focused v8 Python suite | Normal and race suites passed; 82 Python validator/writer/reference/parity/bridge/CLI tests passed | root + subagents |
| `V-0010` | 2026-07-02 | `c7234b5de4baa4092761ad886a24ebcba8478af8` | P1-WP03 | `uv run python scripts/generate_observability_v8_reference.py --check`; `uv run python scripts/check_schemas.py`; focused Ruff | Six generated/reference/wheel mirrors, 23 JSON schemas, 131-metric catalog, schema mirrors, and all Python lint checks passed | root + subagent |
| `V-0011` | 2026-07-02 | `c7234b5de4baa4092761ad886a24ebcba8478af8` | P1-WP03 | Build real gateway; run `defenseclaw config validate/show/reference` and `defenseclaw observability plan` against a temporary v8 install | Versioned Go/Python bridge, full-capability OTLP expansion, generated reference, and filtered canonical-plan rendering passed | root |
| `V-0012` | 2026-07-02 | `c29cdddc4e785463d8f26da43df199897051c163` | P1-WP04 | `uv run --project cli pytest -q cli/tests/test_observability_v8_migration.py cli/tests/test_observability_v8_compatibility.py`; targeted Ruff/format and `git diff --check` | 237 focused converter/typed-contract tests passed; lint, format, and diff checks passed | root + subagents + Claude review |
| `V-0013` | 2026-07-02 | `c29cdddc4e785463d8f26da43df199897051c163` | P1-GATE | Broad v8 Python suite covering migration, compatibility, config, YAML, parity, reference, spec, config-v8 commands, plan, inspect, and environment-registry coverage | 334 passed in 13.92s | root |
| `V-0014` | 2026-07-02 | `c29cdddc4e785463d8f26da43df199897051c163` | P1-GATE | `go test` normal and race plus `go vet` for `./internal/observability ./internal/config ./internal/cli ./schemas`; `make check` | Go normal/race/vet passed; v7 parity, 91-decision spec, inventory, 23 schemas/131 metrics, 14 dashboards/313 panels, Go/TS provider coverage, catalog, and upgrade manifest passed | root |
| `V-0015` | 2026-07-02 | `c29cdddc4e785463d8f26da43df199897051c163` | P1-GATE | Build `/tmp/defenseclaw-v8`; convert and run `config-v8 validate` for full local-observability and multi-destination/audit/filter candidates | Both real Go compiler results returned `valid:true`; this proves candidate validity, not generated family mapping completeness | root |
| `V-0016` | 2026-07-02 | `b328351a64554dcf47a046d5ed24fd1f0290d833` | P2-WP01 | `go test ./internal/observability -count=1`; `go test -race ./internal/observability -count=1`; `go vet ./internal/observability`; `git diff --check` | Canonical value/record/builder normal and race suites passed after two adversarial subagent passes; all nine original trust-boundary/serialization findings closed or explicitly assigned to generated P5 family validation | root + subagents |
| `V-0017` | 2026-07-02 | `b8a2a982366fc6e6040d39f0b726bc75286dcfa9` | P2-WP02 | `make check-observability-v8-spec`; focused spec tests; `go test ./internal/observability ./internal/observability/router ./internal/config -count=1`; router/record race; vet; diff check | 92-decision spec and 5 tests passed; router/record/config normal suites, record/router race, and vet passed; disabled collection is lazy, current log floor eligibility is catalog-derived and immutable, floor is minimal/local-only, and destination routing is ordered independent fan-out | root + subagents |
| `V-0018` | 2026-07-02 | `ba0f56636` | P2-WP03 | Isolated Go hash normal/race/vet; shared Go/Python golden tests; `scripts/generate_unicode13_repertoire.py --check`; `scripts/check_schemas.py` | Exact 32-byte keyed hash-v1, Unicode-13 repertoire, Windows/UNC/path/URI normalization, shared success/error parity, and generated drift checks passed | root + subagent + Claude review |
| `V-0019` | 2026-07-02 | `bb245eb03` | P2-WP03 | `go test ./internal/redaction -count=1`; `go test -race ./internal/redaction -count=1`; `go vet ./internal/redaction` | Pure legacy-v7 string/entity/content/reason/evidence goldens, global/environment invariance, idempotence, spoof resistance, coordinates, and compatible sink wrappers passed | root + subagent |
| `V-0020` | 2026-07-02 | `bf0def9af` | P2-WP03 | Detector Go normal/race/vet; generated catalog check; `scripts/check_schemas.py`; focused Python config/catalog tests and Ruff | Machine catalog/schema/generated Go/Python parity passed; 14 bounded recognizers, work limits, original-byte intervals, overlap union, token domains, and synthetic corpus passed; exhaustive §6.1 expansion remains active | root + subagent + Claude review |
| `V-0021` | 2026-07-02 | `d44a58f5f` | P2-WP03 | Redaction package normal/race/vet; compile-only tests for Linux, FreeBSD, OpenBSD, NetBSD, DragonFly BSD, and unsupported Windows | Fixed-path key create/load, concurrent convergence, no-follow/type/owner/mode/length validation, entropy/interruption cleanup, immutable access, safe errors, and portability passed | root + subagent + Claude review |
| `V-0022` | 2026-07-02 | `b5890a92c202dd18a1b8c8742187d784fb9b424d` | P2-WP03 gate | `go test` and `go test -race` for `./internal/observability/... ./internal/redaction ./internal/config`; `go vet`; 69 focused Python hash/catalog/config/spec tests; Unicode/catalog generators; schema/spec checks; diff check | All Go normal/race/vet passed; 69 Python tests passed; six generated config mirrors, detector/Unicode artifacts, 23 schemas, 131 metrics, and 95 decision-traceability entries were current and valid | root + subagents + Claude review |
| `V-0023` | 2026-07-02 | `4f2a80166d3dbf477897b2fbd67587e485ae8382` | P2-WP04 immutable event history | `go test ./internal/audit -count=1`; focused `-race`; `go vet ./internal/audit`; actual `origin/main` reopen/read probe | Additive event-history migration preserved v7 provenance meanings, stored exact post-redaction envelopes with projection hash/HMAC metadata, verified bounded ID/ranges, enforced mandatory readiness, and remained readable by the previous code | root + subagents + Claude review |
| `V-0024` | 2026-07-02 | `1e0b9ea426f7acdcaa34e184592dfd4eb4d386ee` | P2-WP04 judge-body cutover | `go test ./internal/audit ./internal/gateway -count=1`; `go test -race ./internal/audit ./internal/gateway -count=1`; focused post-review race; `go vet ./internal/audit ./internal/gateway ./internal/telemetry`; Linux/Windows test compilation | Broad normal passed (`audit` 6.539s, `gateway` 46.699s); broad race passed (`audit` 154.450s, `gateway` 506.823s); focused race, vet, and both cross-platform compile gates passed after all review fixes | root + SQLite/judge subagents + direct/Claude-assisted review |
| `V-0025` | 2026-07-02 | `1e0b9ea426f7acdcaa34e184592dfd4eb4d386ee` | P2-WP04 judge compatibility/security | `make check-observability-v8-spec`; focused TUI pytest/Ruff; create v8 audit/judge DBs, reopen/write with actual `origin/main`, reopen/repair with v8 | 95-decision spec passed; 8 TUI history tests and Ruff passed; actual previous release opened both additive schemas, wrote legacy-shaped rows, and v8 reopened/read them with non-NULL normalized timestamps in all four rows | root + subagents |
| `V-0026` | 2026-07-03 | `39fe480d1266164aef2e0f2b5c70c7a02daec53e` | P2-WP04 implicit SQLite/local pipeline | `go test ./internal/audit ./internal/observability/pipeline ./internal/observability/router ./internal/config ./internal/telemetry -count=1`; focused post-review race; `go vet` for the same packages; Windows amd64 test compilation for audit/telemetry/pipeline | Final normal suite passed (`audit` 9.307s, pipeline 0.764s, router 1.724s, config 1.065s, telemetry 1.274s); final focused race passed (`audit` 64.667s, pipeline 2.967s); vet and all Windows compile gates passed | root + storage/graph/alert subagents |
| `V-0027` | 2026-07-03 | `39fe480d1266164aef2e0f2b5c70c7a02daec53e` | P2-WP04 repository/review gate | `make check`; `.venv/bin/python -m pytest cli/tests/test_observability_v8_inventory.py -q`; `coderabbit review --agent -t uncommitted`; `git diff --check` | Repository check passed: v7 parity, 23 baseline schemas plus separate v8 redaction schemas, 95 decisions, 14 dashboards/313 panels, Go/TS provider coverage, catalog, and upgrade manifest. Inventory tests 8/8 passed. CodeRabbit raised 16 issues: 12 valid issues fixed and reverified; 4 suggestions rejected because they contradicted locked unbounded receipt/ACK initialization decisions, requested unsafe error disclosure, or indexed an unqueried field. | root + Claude + CodeRabbit |

Final integration requires, at minimum:

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
python scripts/check_grafana_dashboards.py --live --inventory --require-packaged
```

The last command runs against a started local-observability stack with generated
root/subagent traffic. Galileo validation additionally exercises eligible
agent/model/tool/retriever/workflow/judge spans, partial success, delivery counters,
and exact-trace canary acknowledgement against its conformance harness.

## Decision, Blocker, and Change Ledger

| ID | Date | Type | Affected work | D-/S-/P- IDs | Resolution or required spec change | Status |
|---|---|---|---|---|---|---|
| `C-0001` | 2026-07-02 | setup | `P0-WP01` | D-022, P-045, P-046 | Track package in repository and use this root execution ledger | complete |
| `C-0002` | 2026-07-02 | gate | `P0-WP02..03`, `P0-GATE` | D-001..022, S-001..012, P-001..047 | Approve the mechanically validated contract after current-state inventory, compatibility, and two CodeRabbit review passes | complete |
| `C-0003` | 2026-07-02 | architecture | `P1-WP03`, `P5-WP01..02` | D-019, P-010, P-030, P-046 | Python validates source/schema semantics and renders the masked source; canonical effective compilation and registered action/event selector validation always run in Go. P5's sole registry compiler will generate the shared Python selector constants instead of introducing a hand-maintained duplicate in P1. | complete |
| `C-0004` | 2026-07-02 | dependency | `P1-WP04`, `P1-GATE`, `P5-WP06`, `P7-WP01` | D-020, P-030, P-044, P-046, P-056, P-057 | Split converter-engine/API completion from generated family-selection integration: P1 may unblock canonical runtime work only after strict typed fail-closed engine tests; P5's sole compiler owns the complete compatibility artifact and mapping goldens, which remain mandatory before automatic migration or release. | complete |
| `C-0005` | 2026-07-02 | gate | `P1-WP04`, `P1-GATE`, `P2-WP01`, `P5-WP06`, `P7-WP01` | D-020, P-030, P-044, P-046, P-056, P-057 | Close P1 at `c29cdddc4` after independent/subagent/Claude review and exact-HEAD gates. The immutable plan and converter engine/API may unblock P2; generated v7 family eligibility, complete migration goldens, PR #403/#412 dashboard equivalence, Galileo conformance, and activation remain mandatory in their existing P5/P6/P7 work packages. | complete |
| `C-0006` | 2026-07-02 | security architecture | `P2-WP01..02`, `P5-WP02` | D-001, D-016, P-042, P-058 | Public generic construction requires complete exact leaf classes and cannot assert schema derivation or mandatory state. Current log metadata/builders resolve registered producer kind/key/typed facts internally; disabled-floor construction uses a separate content-free authenticated marker accepted only by local SQLite. Generated event-to-bucket ownership, family outcome subsets, schema-derived classes, and richer reviewed floor bodies remain solely P5 registry outputs. | complete |
| `C-0007` | 2026-07-02 | privacy architecture | `P2-WP03`, `P5-WP02` | D-011, P-059, P-060, P-061 | Custom redacting profiles cannot rewrite metadata/schema-approved identifiers. Delivery projections retain only surviving original field-class provenance, omit removed object pointers, and recursively prune containers emptied solely by descendant removal; array indices remain stable through `null` without synthesizing classes. Object member names are schema-owned vocabulary, while dynamic names are classified values. Canonical records retain their complete immutable maps. | complete |
| `C-0008` | 2026-07-02 | gate | `P2-WP03`, `P2-WP04` | D-009..012, P-026, P-038, P-051, P-059..061 | Close the central redaction work package after exhaustive detector grammar coverage, cross-language hash parity, secure fixed key custody, pure legacy-v7 compatibility, immutable per-route projection, structural-name protection, fail-closed plan adaptation, independent adversarial review, Claude review/fixes, and exact-HEAD normal/race/vet/schema/spec gates. This unblocks SQLite projection persistence but not producer cutover or remote adapters. | complete |
| `C-0009` | 2026-07-02 | storage architecture | `P2-WP04`, `P2-WP05` | P-021, P-045, P-047 | Preserve v7 audit column meanings while adding distinct exact-projection/hash/HMAC fields; cut retained raw judge bodies over once to an owner-only dedicated database with crash-resumable verification, normalized indexed instants, no audit.db writer fallback, and authoritative-first compatibility reads. Unix/Windows main and auxiliary SQLite paths fail closed across ownership, link/reparse, ACL, mutable-ancestor, and stale-sidecar hazards. The global age reaper and cutover-marker cleanup remain the next P2-WP05 scope. | complete |
| `C-0010` | 2026-07-03 | gate | `P2-WP04`, `P2-WP05`, `P2-GATE` | D-013..016, S-012, P-005..008, P-021, P-045, P-047 | Close P2-WP04 at `39fe480d1` after implicit all-bucket SQLite persistence, exact runtime-graph projection binding, hardened readiness/path/sidecar handling, correlation-key integrity, protected alert receipts and streaming replay, post-lifecycle health dispatch, adversarial Claude/storage review, one consolidated CodeRabbit pass, and final normal/race/vet/cross-platform/repository gates. P2-WP05 now owns the global age reaper, protected-state exclusions/capacity health, atomic graph reload/swap, and cleanup markers; representative producer cutover remains P2-GATE. | complete |

A new product choice requires a new decision ID and traceability row. A behavior
change updates its contract and required test in the same change. Deferred release
work must be explicitly excluded by the normative package; before it appears in a
PR follow-up, create and link a GitHub issue as required by `AGENTS.md`.

## Commit and PR Protocol

- Commit after each verified work package or coherent integration milestone.
- Commit messages identify the behavioral scope and verification, not only files.
- Do not mix unrelated work packages in one commit when they can be reviewed
  independently.
- Before every checkpoint: review `git diff`, run proportional tests, update this
  ledger, then commit.
- The final PR targets `main` and follows the repository-required sections:
  stack/base note, Problem, Current Situation, Solution, architecture diagram when
  useful, What Changed table, Breaking Changes, Open Issues/Follow-ups, and exact
  Test Plan results.
- Future work in the PR body must link an existing issue; otherwise write `None`.
- Run CodeRabbit only on an intentional committed/uncommitted scope, address all
  actionable issues, rerun tests, and record the result.
- Do not declare completion until every required CI/CD check on the PR is green.

## Final Completion Audit

Before marking `P8-GATE` and the active Codex goal complete, prove all of the
following against the final commit and live PR state:

- Every release gate in `07-verification-and-acceptance.md` section 17 passes.
- Every work package and phase gate is `DONE`; no release requirement is hidden in
  `TODO`, `READY`, or prose.
- D-/S-/P- decisions are unique, complete, traceable to contracts and tests, and
  reflected in implementation.
- Every current producer is classified and routed through one canonical pipeline.
- Legacy runtime toggles, direct sink fan-out, and duplicate old/new outputs are
  removed or proven inactive as specified.
- The complete migration fixture matrix and fault-injection matrix pass.
- PR #403 lifecycle/traceability and PR #412 dashboard goldens pass without losing
  pre-upgrade history.
- Local observability starts cleanly; all dashboards and live query inventory work.
- Galileo conformance, delivery health, and exact canary work for supported shapes.
- Generated docs/schemas/examples are current and drift-free.
- Security review finds no secret/content leakage or unsafe exporter path.
- The full final command suite is recorded at the final commit.
- The PR is against `main`, follows `AGENTS.md`, has no unlinked follow-ups, and all
  required CI/CD checks are green.

Only after this audit may the root coordinator mark the active goal complete.
