# Central Redaction Contract

## 1. Security Objective

The projection system must apply the configured privacy choice consistently while
preserving structure for debugging, correlation, alerting, and aggregation. The v8
default choice is `none` (unredacted); when a redacting profile is selected, its
transformations must be centralized, destination-aware, deterministic, idempotent,
and fail closed.

Redaction is not authorization. A destination must still be explicitly routed to
receive a record.

## 2. Processing Boundary

All collected logs and all exported trace attributes/events MUST pass through the
central redaction engine after route selection and before destination serialization.
For traces this boundary also covers link attributes, status descriptions,
exception messages/stack traces, GenAI/OpenInference aliases, and vendor wrappers.
Content aliases MUST be generated from one already-redacted typed value; no alias
may retain a less restrictive projection.

Metrics MUST be designed to contain no content-bearing attributes. The redaction
engine validates metric attribute classes but does not attempt expensive free-text
scanning of every metric sample.

The following are prohibited:

- A destination adapter reading an unredacted producer object directly.
- A producer pre-serializing an opaque JSON payload that bypasses field
  classification.
- Copying raw inbound HEC/OTLP bodies into reserved hidden fields.
- Applying redaction after HMAC/signature generation.
- Mutating the canonical record while preparing one destination.

## 3. Built-in Profiles

### 3.1 `none`

- No content redaction.
- Structural validation, size limits, and safe serialization still apply.
- Catalog default for built-in local persistence and capability-default optional
  delivery.
- Valid in defaults, bucket policy, concise sends, advanced routes, and local
  projection resolution.
- Does not produce a warning merely because it is active; configuration mutations
  remain compliance activity.

### 3.2 `sensitive`

- Detect and replace sensitive substrings inside ordinary content strings.
- Entirely remove or replace credential-class fields.
- Preserve non-sensitive surrounding text and structured shape.
- Hash or normalize paths according to the field contract.
- Intended default for local operational logs and controlled security destinations.

### 3.3 `content`

- Replace complete content-bearing fields rather than inspecting substrings.
- Applies to prompts, responses, tool arguments/results, evidence bodies, judge
  bodies, full reasons derived from user content, and equivalent dynamic fields.
- Preserve metadata such as length, content type, hash, rule IDs, status, duration,
  token counts, and correlation IDs where those values are independently safe.
- Intended for destinations that need operational metadata but not content.

### 3.4 `strict`

- Allow only fields explicitly classified as safe metadata or safe identifiers.
- Remove or replace all content, reason, evidence, error, path, credential, and
  unknown dynamic-string fields.
- Intended for compliance summaries, health logs, and broadly accessible consoles.

For the `path` field class, the built-in `sensitive` and `content` profiles use
`hash-v1` as defined in §7.4; `strict` removes the path field. A schema may expose a
separately classified safe basename or destination class, but it cannot relabel the
original path as metadata. This behavior is fixed profile data, not an
implementation-language default.

### 3.5 `legacy-v7`

`legacy-v7` is an immutable built-in route projection used only to preserve the
effective redacting behavior of an upgraded v7 installation. It is not the default
for a fresh v8 source and it is not a synonym for `sensitive`, `content`, or
`strict`:

- Safe metadata is preserved.
- General strings, model/tool content, errors, paths, credentials, and other v7
  whole-field surfaces use the existing v7 length/hash placeholder behavior.
- Entity/identifier fields retain the v7 entity-placeholder rules, including the
  reviewed long-value prefix threshold.
- Reasons retain the v7 bounded token-aware behavior that preserves reviewed rule
  IDs and safe enum/key glue while whole-redacting dynamic values.
- Evidence retains the v7 evidence placeholder and bounded match-coordinate
  metadata.
- Existing v7 placeholder recognition, idempotence, spoof resistance, short-value
  handling, and SHA-256 compatibility token grammar are preserved exactly by
  generated golden vectors.

The profile is selected explicitly on migration-generated local/bucket/destination
routes when v7 redaction was effective. When v7 redaction was globally disabled,
migration selects the ordinary `none` behavior instead. `legacy-v7` is implemented
in the central Phase 2 projection engine; it does not keep a second v7 fan-out or
producer-side redaction path alive.

## 4. Custom Profile Composition

A custom redacting profile MUST extend exactly one of `sensitive`, `content`, or
`strict`; neither `none` nor `legacy-v7` can be extended or aliased. `none` has no
transformations to compose, while `legacy-v7` is a fixed migration-compatibility
contract rather than an authoring base. A custom profile MAY change only:

- Enabled built-in detector groups.
- Per-field-class transformation mode.
- Documented safe size and excerpt limits.

Allowed field-class modes are:

- `preserve`
- `detect`
- `whole`
- `hash`
- `remove`

Profile-strength validation prevents a custom profile from becoming an unlabelled
raw bypass:

- `preserve` is allowed only for schema-approved `metadata` and `identifier`
  classes.
- `credential` may use only `remove` or `whole`.
- `detect` requires at least one effective detector group.
- `content`, `reason`, `evidence`, `error`, and `path` cannot be set to `preserve`.
- A profile that needs raw dynamic fields must use the built-in `none` profile and
  therefore receives the ordinary unredacted behavior.

Custom profiles MUST NOT contain arbitrary regex, executable scripts, expressions,
network calls, or model prompts. Unknown detector groups, field classes, or modes
are startup errors.

Profiles are resolved at configuration load. Inheritance is deliberately
single-level: a custom profile extends one built-in redacting profile, so cycles
and multiple inheritance are not representable.

## 5. Field Classes

Every dynamic body field is assigned one of:

| Class | Examples | Redacting-profile behavior |
|---|---|---|
| `metadata` | version, duration, count, mode, protocol, bounded enum | Preserve |
| `identifier` | request ID, trace ID, scan ID, stable rule ID | Preserve if schema-approved |
| `content` | prompt, response, tool args/result, message, raw body | Detect or whole by profile |
| `reason` | policy reason, operator reason, decision explanation | Detect |
| `evidence` | matched excerpt, detector context, judge evidence | Detect or whole |
| `error` | external/provider error text and causes | Detect |
| `path` | file paths, workspace paths, URLs with path/query | Hash/normalize |
| `credential` | token, password, secret, auth header, private key | Remove or whole |

Unknown keys in dynamic objects are classified as `content`. Schema-owned fields
must declare classes in the event contract. A field name alone is insufficient to
upgrade an unknown field to safe metadata.

## 6. Built-in Detector Groups

Detector catalog version 1 defines exactly three operator-facing group tokens.
These are the only values valid in `redaction_profiles.*.detectors`:

| Group token | Detector IDs enabled | Intended coverage |
|---|---|---|
| `pii` | `pii.email`, `pii.telephone`, `pii.national_identifier`, `pii.payment_card`, `pii.ip_address` | Email addresses, telephone numbers, U.S. Social Security numbers and supported equivalent national identifiers, payment-card candidates validated with Luhn where applicable, and IP addresses when the field/profile policy treats them as personal data |
| `credentials` | `credentials.api_token`, `credentials.private_key`, `credentials.authorization`, `credentials.cookie`, `credentials.connection_string` | Known API/access-token forms, private keys or certificates containing private material, authorization/header values, authentication cookies, and connection strings containing credentials |
| `secrets` | `secrets.assignment`, `secrets.high_entropy`, `secrets.url_query`, `secrets.cloud_account_identifier` | Password/secret assignments, bounded generic or high-entropy secret candidates, sensitive URL query values, and common cloud/account identifiers classified as sensitive |

Group membership is versioned data, not inferred from the group name at runtime.
An implementation MAY use several lexical and semantic recognizers behind one
detector ID, but validation, replacement type, metrics, and provenance use the
stable detector ID above. A custom profile selects groups, not individual detector
IDs. Unknown group tokens are startup/reload errors.

The built-in `sensitive`, `content`, and `strict` profiles enable all three groups;
their different field-class modes determine whether detection is reached or a
field is removed/whole-redacted first. `none` enables no detector group. For a
custom profile, omitted `detectors` inherits the base profile's set, while a
present nonempty list is the complete replacement set. An explicit empty list is
invalid; an operator who intends raw output uses the built-in `none` profile.
Changing detector groups does not weaken independent `credential: remove`,
`content: whole`, or strict allowlist behavior inherited from the base profile.

Detector versions MUST be recorded in provenance or health metadata. Detection
must use bounded input sizes and avoid catastrophic backtracking. Validators such
as Luhn checks must run after a lexical candidate match to reduce false positives.

## 7. Transformation Semantics

### 7.1 Structured data

- Traverse maps/objects and arrays recursively.
- Preserve object/array shape unless the field-class mode is `remove`.
- Apply schema field classes before heuristic key classification.
- Enforce depth, field-count, string-length, and total-output limits.
- Sort map keys only when required for deterministic serialization/signing; do not
  change semantic array order.

### 7.2 Plain text

- `detect` replaces only matched sensitive ranges.
- Overlapping matches are coalesced before replacement.
- Replacement order is deterministic.
- Unicode boundaries must remain valid.
- `whole` replaces the entire string.

### 7.3 Replacement token

Detected substrings use a deterministic non-secret token of the form:

`<redacted type=TYPE len=N sha=XXXXXXXX>`

Where:

- `TYPE` is a bounded detector type, not the matched value.
- `N` is the original byte length.
- `sha` is the first eight lowercase hex characters of a keyed or documented
  one-way digest suitable for correlation within the configured scope.

Whole-field replacement uses an equivalent field-level token. The digest MUST NOT
make low-entropy secrets easily reversible; keyed hashing is preferred for values
such as short identifiers.

### 7.4 `hash` mode

`hash` is a deterministic, non-reversible field-class transformation for local
correlation. Go and Python MUST implement the same `hash-v1` algorithm:

1. Reject invalid UTF-8 and otherwise normalize text to Unicode NFC. Do not trim,
   case-fold, expand environment variables/`~`, or consult the filesystem.
2. For `path`, apply lexical normalization only: convert `\\` to `/`; preserve an
   initial `/` or UNC `//`; lowercase only a Windows drive letter; collapse repeated
   separators after the root; remove `.` segments; resolve `..` against a preceding
   ordinary segment without crossing an absolute root; preserve unresolved leading
   `..` on relative paths; and remove a trailing slash except for a root. Do not
   resolve symlinks or apply platform-dependent filesystem case rules.
3. When the value is an absolute URI, use RFC 3986 URI normalization instead of the
   file-path step: lowercase the scheme and host, remove the default port, normalize
   path dot segments, uppercase percent-escape hex digits, decode percent-escaped
   unreserved characters, preserve query item order and values, and discard the
   fragment. User information is accepted only as hash input and is never emitted.
4. Compute HMAC-SHA-256 using the installation redaction-correlation key over the
   exact UTF-8 bytes
   `defenseclaw-redaction-hash-v1 || 0x00 || FIELD_CLASS || 0x00 || NORMALIZED_VALUE`,
   where `||` means byte concatenation and the separators are single NUL bytes.
5. Emit the full 32-byte digest as 64 lowercase hexadecimal characters in
   `<hashed class=CLASS v=1 key=KEY_ID len=N hmac=HEX>`, where `N` is the original
   UTF-8 byte length and `KEY_ID` is a safe key identifier, never key material.

The correlation key is at least 32 random bytes, is stored with owner-only access,
and is shared by the Go and Python processes for one installation. Rotation changes
future digests and the key ID; it does not rewrite historical records. If the key is
missing, unreadable, or invalid, `hash` fails closed to whole-field redaction and
emits safe health telemetry. It MUST NOT fall back to unkeyed SHA-256. Registry
golden vectors cover ordinary text, POSIX paths, Windows paths, UNC paths, relative
`..`, Unicode, and URIs across both implementations.

### 7.5 Idempotence and spoof resistance

- Applying the same profile twice produces the same output.
- Only placeholders created and internally marked by the current redaction engine
  are trusted as placeholders.
- User-supplied strings that look like placeholders are processed as ordinary
  untrusted text.

### 7.6 Oversize data

- Oversize strings are not passed through raw.
- The engine processes a bounded prefix/suffix only when safe and otherwise applies
  whole-field redaction.
- Output records include safe original-length metadata and an oversize marker.

## 8. Evidence and Remediation

- Finding evidence summaries are `content`.
- Evidence excerpts are `evidence`.
- Remediation text is `reason` unless a schema marks a bounded catalog remediation
  as safe metadata; even then it is scanned for accidentally embedded values.
- Evidence fingerprints and stable rule IDs are identifiers.
- Complete prompts, responses, and tool data MUST NOT be stored as finding evidence
  merely because a stricter route can later redact them.

## 9. Failure Behavior

### 9.1 Field processing failure

If parsing, classification, detection, encoding, or size handling fails for a
dynamic field:

1. Replace the complete field with a fail-closed redaction token.
2. Continue processing the rest of the projection.
3. Mark the projection with a safe redaction-failure indicator.
4. Emit a bounded `platform.health / redaction.failed_closed` signal containing
   profile, destination, field class, and error code, but not the field value.

### 9.2 Record processing failure

If a complete projection cannot be safely serialized:

- Do not deliver the unsafe projection.
- Emit a rate-limited health transition.
- Preserve delivery to other destinations whose projections succeed.
- For SQLite, write a minimal mandatory failure record; inability to write that
  record changes SQLite health to failed and follows the local-integrity failure
  path.

### 9.3 Profile-faithful failure behavior

There is no environment variable or runtime error path that changes the selected
profile. Under `sensitive`, `content`, `strict`, `legacy-v7`, or a custom redacting
profile, redaction errors fail closed and never fall back to raw output. Under the
selected `none` profile, raw content is intentional and no detector is expected to
run; the projection still enforces schema, type, size, and serialization
constraints.

The v7 `DEFENSECLAW_DISABLE_REDACTION` behavior is removed from both Go and Python
surfaces during migration. `DEFENSECLAW_REVEAL_PII` may remain only as an
authorized, local, display-time reveal control: it MUST NOT alter collection,
redaction, SQLite persistence, judge-body retention, or any exported projection.
Any existing coupling between that variable and retention must be removed.

## 10. Local Forensic Judge Bodies

Raw judge response retention remains an explicit local forensic feature, separate
from ordinary log routing. Requirements:

- Judge bodies are stored only in the configured judge-body SQLite database.
- They are never copied into canonical logs or remote destination projections.
- Retention follows the global local event/evidence retention age.
- Access paths must be authenticated/locally authorized and must make raw-content
  display explicit.
- Enabling or disabling raw judge retention is compliance activity.
- The observability migration must remove the current global redaction bypass from
  this path; forensic retention is a scoped exception, not a universal one.

## 11. Verification Properties

The redaction implementation MUST be tested for:

- Nested objects and arrays.
- Unicode and invalid byte handling at input boundaries.
- Multiple and overlapping detector matches.
- Luhn-positive and Luhn-negative payment-card candidates.
- Credential fields regardless of key casing.
- User-supplied fake placeholders.
- Idempotence.
- Determinism under map ordering differences.
- Oversize and deeply nested values.
- Malformed structured strings.
- Independent outputs for two destinations using different profiles.
- No mutation of the canonical record.
- Failure-closed behavior and recursion protection.
- Cross-language `hash-v1` golden vectors, path/URI normalization edge cases, key
  rotation, and unavailable-key fail-closed behavior.
- `legacy-v7` golden vectors for each v7 string/entity/content/reason/evidence
  helper, placeholder grammar, repeated application, spoofed placeholders, and
  globally disabled versus redacting migration outcomes.
- GenAI, OpenInference, legacy, span-event, link, exception, and Galileo projection
  aliases all receive equal-or-stronger redaction from one canonical value.
- Input/output `reported` and redaction-state metadata remain truthful after whole,
  partial, truncation, missing-data, and fail-closed projection.
