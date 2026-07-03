# Automatic v7-to-v8 Upgrade Migration

## 1. Locked Decision

For a normal locally managed installation, the complete operator workflow is:

```text
defenseclaw upgrade
```

`defenseclaw upgrade` detects supported v7 observability configuration and converts
it to v8 as an ordinary version migration. The existing confirmation prompt, or
the existing `--yes` option, is sufficient.

The operator does not install an intermediate release, generate or approve a plan,
run a separate apply command, type a special acknowledgement, or manually switch
configuration files.

The gateway itself remains strict: a v8 gateway does not rewrite v7 configuration
at startup or reload, and the runtime does not support v7 and v8 formats in
parallel.

## 2. Reuse the Existing Upgrade Path

This change extends the current upgrader; it does not create another upgrade
framework.

| Existing mechanism | v8 use |
|---|---|
| Verified target artifacts | Unchanged |
| Ordinary upgrade confirmation / `--yes` | Shows that observability config will be migrated |
| `_create_backup` | Backs up the root config and, when installed, DefenseClaw-owned local-observability bundle files that the migration will replace |
| Installed-version migration registry | Registers the v8 observability conversion once |
| Migration cursor | Makes conversion retry-safe and prevents duplicate application |
| `upgrade-manifest.json` required migrations | Marks the v8 conversion required with failure policy `fail` |
| Atomic config writer | Replaces the source only after the complete candidate validates |
| Existing service stop/start and health poll | Starts and verifies the v8 gateway after migration; the existing local-stack lifecycle refreshes/restarts a previously running optional bundle |
| Previous gateway-binary snapshot | Provides the existing recovery artifact if target startup fails |

No protocol-v2 design, bridge release, plan file/hash, side-by-side component
layout, transaction journal, or special gateway validation mode is required.

## 3. Upgrade Flow

The v8 release follows this sequence inside the existing command:

1. Resolve, download, and verify the target release as today.
2. Detect whether the active source is v7, already v8, or unsupported.
3. Add a concise, redacted observability summary to the normal upgrade prompt.
4. Back up the exact config source, the ancillary `.env` when migration will
   promote a v7 secret/header value, and any installed DefenseClaw-owned
   local-observability files that will be refreshed. Preserve custom files and
   persistent volumes.
5. Stop the gateway and install the target artifacts through the existing path.
6. Run the registered target-version migrations.
7. The observability migration builds the complete v8 candidate in memory,
   validates it, and atomically writes it.
8. Record the migration in the existing cursor only after the write succeeds.
9. Refresh the installed local-observability bundle to the target Collector,
   datasource, dashboard, rule, and config set. If it was running, use the existing
   stop/restart path without resetting volumes.
10. Restart the gateway, run the existing health poll, and perform bounded local
    stack readiness/query checks when that optional stack is installed.

Example prompt addition:

```text
This upgrade will also migrate observability config v7 -> v8:
  3 OTel destinations
  2 audit sinks
  SQLite, JSONL, console, and Galileo settings preserved
  Agent360 lifecycle and local dashboard compatibility preserved
  existing redacted/unredacted behavior preserved under v8 profiles
```

No prompt, response, tool content, evidence, credential, or resolved secret may
appear in this summary.

## 4. Registered Migration Contract

The migration is implemented as one normal entry in
`cli/defenseclaw/migrations.py`, at the release version that introduces config v8.
It calls one deterministic conversion function shared with the optional preview.

The conversion function is side-effect-free: it returns the v8 candidate,
secret-free summary/warnings, and declarative ancillary `.env` edits. Phase 7
upgrade integration alone locks, backs up, applies, restores, restarts, and marks
the cursor. Ordinary Python writer/runtime dispatch by `config_version` is delivered
in Phase 4 and is a prerequisite for activation, so neither preview nor upgrade can
accidentally re-save a v8 source through the legacy connector-only dataclass.

The conversion function MUST:

- Treat an already valid v8 source as a no-op.
- Accept every supported v7 shape documented in
  `06-migration-and-implementation.md`.
- Treat an absent or numeric-zero version stamp as v7 only after the complete
  document validates as the current v7 shape with no v8-only observability key;
  reject an ambiguous mixed shape rather than guessing.
- Preserve unrelated config sections and notification-only webhooks.
- Preserve comments, key order, the ASCII operator guide, file mode, and ownership.
- Preserve destination identity when endpoint, credentials, TLS, batching,
  enabled signals, or routing intent differs.
- Promote every inline token/bearer token and interpolated secret header to a
  deterministic environment reference. The complete effective value exists only
  in the locked ancillary `.env` edit and backup/rollback unit; it never
  enters YAML, candidate/diff objects, or output.
- Materialize every effective non-secret legacy OTel environment input into v8
  destination policy. Secret-bearing environment/header inputs remain references
  or use the deterministic ancillary promotion above; v8 does not continue ambient
  OTel policy overrides after migration.
- Split a v7 destination with different effective per-signal protocols into stable
  signal-suffixed destinations. If effective metric interval/temporality policies
  conflict, fail before write and name the destinations/fields plus the exact
  align-or-remove remediation instead of broadening or guessing.
- Preserve Splunk `sourcetype_overrides` and OTLP-log `logger_name` as typed v8
  adapter fields.
- Materialize `network_safety.allow_private_networks: true` separately on every
  translated destination whose explicit v7 literal is loopback, RFC1918, or IPv6
  ULA, with warning/audit and no global bypass. Always-prohibited address classes
  remain invalid.
- Preserve the effective behavior of SQLite, judge-body storage, JSONL, console,
  OTel, audit sinks, connector overrides, Galileo, resource attributes, sampling,
  metric policy, and span filters as defined by the mapping table.
- Preserve judge-body retention enablement separately from the relocated database
  path, including the current off-like `DEFENSECLAW_PERSIST_JUDGE` override and the
  default-true case, then retire runtime consultation of that variable.
- Preserve explicit Galileo batch delays; disclose and materialize the deliberate
  v8 1,000 ms preset only where v7 inherited its 5,000 ms default.
- Preserve legacy redacted/unredacted intent for both local and optional
  destinations. Because fresh v8 defaults are unredacted and all-signals, migration
  materializes any narrower v7 collection, routing, or redaction needed to avoid
  broadening an upgraded installation. Effective v7 redaction uses immutable
  built-in `legacy-v7`; a v7 global bypass uses `none`.
- Derive current v7 log/trace/metric/action/exporter eligibility from the generated
  telemetry-registry compatibility selection. A missing/ambiguous family mapping
  fails before write; the converter has no hand-maintained family list or wildcard
  broadening fallback.
- Preserve the merged PR #403 root/subagent lifecycle, execution, phase, operation,
  hook-decision, real-time completion, and missing-data behavior and the merged PR
  #412 dashboard metric/label/bucket/cadence corrections through the
  `local-observability-v1` compatibility profile.
- Migrate the named local-observability destination with logs/traces/metrics and
  every required family unless explicit v7 narrowing must be preserved; report the
  resulting partial dashboard capability when policy remains narrower.
- Back up and refresh target-owned local Collector/datasource/dashboard/rule/config
  assets, preserve arbitrary custom files and all Prometheus/Loki/Tempo/Grafana
  volumes, validate the complete target asset manifest before restart, restore the
  backed-up managed file set on partial refresh, and retain the only copy of any
  overwritten local modification in the upgrade backup.
- Emit `config_version: 8`; omitted bucket catalog resolves deterministically to 1.
- Never resolve a secret into YAML, an in-memory display/diff candidate, or
  diagnostic output. A complete value needed for ancillary promotion is confined
  to the locked `.env` write object, excluded from representations, and
  discarded after activation/rollback.
- Validate the entire candidate before changing the source file.
- Use lock, temporary file, fsync, and rename for activation.
- Be idempotent so an interrupted or retried upgrade does not duplicate routes,
  destinations, comments, or schema migrations.

The full field mapping remains in `06-migration-and-implementation.md`; it is not
duplicated here.

## 5. Required-Failure Behavior

The current migration framework may continue after an individual migration
function raises, then use the release manifest and migration cursor to decide
whether a missing migration is fatal. The v8 release MUST list this migration as
required and use failure policy `fail`.

For this required migration, the upgrader MUST NOT follow its current unconditional
restart path and start a v8 gateway against v7 config. Instead:

- Candidate construction or validation failure leaves the original source bytes
  untouched.
- A partial multi-file activation restores the config and every ancillary changed
  file from the backup.
- The command exits nonzero, prints the migration error and backup path, and does
  not report upgrade success.
- If the previous gateway binary is restored through the existing binary snapshot,
  it is restarted only after the exact v7 source is restored.
- Retrying `defenseclaw upgrade` reruns the unapplied migration through the existing
  cursor semantics.

This is a small fail-safe adjustment to the current upgrader, not a new general
cross-component rollback protocol. Broader package-manager rollback behavior is
outside this observability change.

An unavailable optional remote exporter is not a migration failure. If the v8
gateway starts, SQLite is writable, and the observability graph compiles, ordinary
destination health reports the exporter as degraded.

Likewise, failure to start or query an installed optional local-observability stack
is reported as degraded upgrade status after its files are safely backed up. It
does not roll back a healthy gateway/SQLite migration. The report identifies the
failing service and points to ordinary `setup local-observability up/status` recovery;
it does not require another schema/config migration or a volume reset.
The target keeps the immediately previous bundled query contract through generated
aliases for at least one compatibility release, so a temporarily stale PR #403/#412
bundle remains useful while target-only panels are reported as unavailable.

## 6. Optional Preview

For support and managed deployments, the same converter MAY be exposed read-only:

```text
defenseclaw setup observability migrate-v8 --dry-run
```

It prints a secret-free diff and warnings but does not modify live configuration.
It is optional, is not mentioned as a prerequisite in the normal upgrade flow, and
does not have a second apply/commit protocol. `defenseclaw upgrade` remains the
normal writer.

If configuration permissions prevent backup or atomic replacement, the upgrade
fails before mutation with the path and required permission fix. It does not change
ownership or invent a separate managed-config transaction.

## 7. Verification

Acceptance requires tests proving:

- One `defenseclaw upgrade` converts representative supported v7 fixtures and
  starts a healthy v8 gateway.
- Interactive confirmation and ordinary `--yes` both work without another flag or
  acknowledgement.
- The migration registry and release manifest run the conversion exactly once.
- Already-v8 and retry cases are no-ops without duplicate destinations or routes.
- Every mapping in `06-migration-and-implementation.md` has a golden fixture.
- Inline/interpolated credentials become stable references, ancillary `.env`
  values never appear in YAML/output, retry is idempotent, and an injected second-
  file failure restores both exact originals.
- Per-signal protocol differences split deterministically; conflicting metric
  policies fail with the documented remediation and no write.
- Generated registry compatibility selection, not a converter-local family list,
  determines current v7 eligibility; missing mappings fail closed.
- Every explicit private literal gets only its own reviewed opt-in, and all legacy
  non-secret OTel environment inputs are materialized before those inputs retire.
- Splunk sourcetype overrides, OTLP logger scope, and `legacy-v7` projections match
  pre-upgrade adapter/redaction goldens.
- Comments, ASCII guidance, order, unrelated sections, and permissions survive.
- Invalid candidates never replace the original source.
- A required migration failure never starts v8 against v7 config and never reports
  success.
- The previous config is recoverable byte-for-byte from the normal upgrade backup.
- Output contains no governed content or resolved secrets.
- The optional preview and automatic migration produce the same semantic candidate.
- Temporarily unavailable optional exporters do not fail an otherwise healthy
  upgrade.
- Installed local-observability assets are backed up and refreshed to one mutually
  compatible version; custom files and persistent volumes survive, a previously
  running stack restarts, and all services plus static/live dashboard inventory are
  verified.
- Pre-upgrade and post-upgrade root/subagent activity remains queryable in the same
  Agent360 dashboard with stable lifecycle/root identity and distinct execution
  attempts.
- Injected local-stack restart/refresh failure leaves the previous dashboard query
  contract functional through declared aliases and reports the stale bundle/target-
  only capability gap without hiding it as success.

The supported historical-version matrix belongs in the existing upgrade smoke
tests. No second upgrade harness is introduced for observability v8.
