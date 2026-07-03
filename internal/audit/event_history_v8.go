// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const (
	// ProjectionHashAlgorithm is the v8 event-history projection-hash
	// algorithm. The stored value is this prefix followed by lower-case hex.
	ProjectionHashAlgorithm = "sha256"
	// ProjectionIntegrityAlgorithm identifies a full HMAC-SHA-256 digest over
	// the domain-separated final projected envelope.
	ProjectionIntegrityAlgorithm = "hmac-sha256"

	projectionIntegrityDomain = "defenseclaw-observability-projection-integrity-v1"
)

const maxEventHistoryVerificationRange = 1000

// EventHistoryVerificationStatus is a bounded, machine-readable local
// integrity result. No status embeds persisted record content or database
// diagnostics.
type EventHistoryVerificationStatus string

const (
	EventHistoryVerified         EventHistoryVerificationStatus = "verified"
	EventHistoryUnsigned         EventHistoryVerificationStatus = "unsigned"
	EventHistoryKeyUnavailable   EventHistoryVerificationStatus = "key_unavailable"
	EventHistoryNotProjected     EventHistoryVerificationStatus = "not_projected"
	EventHistoryHashMismatch     EventHistoryVerificationStatus = "hash_mismatch"
	EventHistoryHMACMismatch     EventHistoryVerificationStatus = "hmac_mismatch"
	EventHistoryInvalidIntegrity EventHistoryVerificationStatus = "invalid_integrity_metadata"
)

// EventHistoryVerification deliberately contains identifiers and bounded
// status only. Verification APIs never return projected or raw record bytes.
type EventHistoryVerification struct {
	RecordID            string                         `json:"record_id"`
	Status              EventHistoryVerificationStatus `json:"status"`
	ProjectionHashValid bool                           `json:"projection_hash_valid"`
	IntegrityVerified   bool                           `json:"integrity_verified"`
	IntegrityKeyID      string                         `json:"integrity_key_id,omitempty"`
}

// EventHistoryVerificationRange is explicit about bounded output. Callers must
// not treat a truncated page as a complete range attestation.
type EventHistoryVerificationRange struct {
	Records   []EventHistoryVerification `json:"records"`
	Truncated bool                       `json:"truncated"`
}

// ErrIntegrityKeyUnavailable lets a signer report expected boot-order or key
// custody unavailability. V8 writes the projection as unsigned in this case;
// every other signing error aborts the write.
var ErrIntegrityKeyUnavailable = errors.New("projection integrity key unavailable")

// ProjectionIntegritySigner owns integrity key material. The writer supplies a
// domain-separated message and requires a full 32-byte HMAC-SHA-256 result;
// neither key material nor signer errors enter the stored event.
type ProjectionIntegritySigner interface {
	KeyID() string
	HMACSHA256(context.Context, []byte) ([]byte, error)
}

// EventHistoryHealthCode is a bounded failure/degraded-state vocabulary. It is
// safe to bridge into a mandatory platform.health event because it contains no
// record values, JSON pointers, signer error strings, or database diagnostics.
type EventHistoryHealthCode string

const (
	EventHistoryHealthProjectionRejected EventHistoryHealthCode = "projection_rejected"
	EventHistoryHealthUnsigned           EventHistoryHealthCode = "integrity_unsigned"
	EventHistoryHealthSigningFailed      EventHistoryHealthCode = "integrity_signing_failed"
	EventHistoryHealthWriteFailed        EventHistoryHealthCode = "sqlite_write_failed"
)

type EventHistoryHealthReporter interface {
	ReportEventHistoryHealth(EventHistoryHealthCode)
}

// EventHistoryWriter appends immutable v8 log projections to audit_events. A
// nil signer is valid and produces an explicitly unsigned row.
type EventHistoryWriter struct {
	store            *Store
	signer           ProjectionIntegritySigner
	healthReporter   EventHistoryHealthReporter
	healthReporting  atomic.Bool
	unsignedReported atomic.Bool
}

// NewEventHistoryWriter injects the mandatory local store and optional
// integrity signer without changing the legacy Store constructor or APIs.
func NewEventHistoryWriter(
	store *Store,
	signer ProjectionIntegritySigner,
	healthReporter EventHistoryHealthReporter,
) (*EventHistoryWriter, error) {
	if store == nil || store.db == nil {
		return nil, fmt.Errorf("audit: v8 event-history store is required")
	}
	return &EventHistoryWriter{store: store, signer: signer, healthReporter: healthReporter}, nil
}

// Append persists exactly one local event-history row using a background
// context. Call AppendContext when cancellation must be propagated.
func (writer *EventHistoryWriter) Append(
	record observability.Record,
	projection observabilityredaction.Projection,
	expectedProfile observabilityredaction.ProfileName,
) error {
	return writer.AppendContext(context.Background(), record, projection, expectedProfile)
}

// AppendContext validates that projection is the immutable local projection of
// record, hashes and optionally signs its final serialization, then commits one
// row atomically. It never falls back to record.Body or record.Bytes for stored
// payload data.
func (writer *EventHistoryWriter) AppendContext(
	ctx context.Context,
	record observability.Record,
	projection observabilityredaction.Projection,
	expectedProfile observabilityredaction.ProfileName,
) error {
	if writer == nil || writer.store == nil || writer.store.db == nil {
		return fmt.Errorf("audit: v8 event-history writer is not initialized")
	}
	if ctx == nil {
		return fmt.Errorf("audit: v8 event-history context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.Signal() != observability.SignalLogs {
		writer.reportHealth(EventHistoryHealthProjectionRejected)
		return fmt.Errorf("audit: v8 event history accepts log records only")
	}

	projectedEnvelope, payloadJSON, err := validateLocalProjection(record, projection, expectedProfile)
	if err != nil {
		writer.reportHealth(EventHistoryHealthProjectionRejected)
		return err
	}
	contentDigest := sha256.Sum256(projectedEnvelope)
	projectionHash := ProjectionHashAlgorithm + ":" + hex.EncodeToString(contentDigest[:])

	payloadHMAC, integrityAlgorithm, integrityKeyID, err := writer.integrity(ctx, projectedEnvelope)
	if err != nil {
		return err
	}

	correlation := record.Correlation()
	provenance := record.Provenance()
	metadata := projection.Metadata()
	target := projectedCompatibilityTarget(projection)
	details := projectedCompatibilityDetails(projection, string(record.EventName()))
	severity, hasSeverity := record.Severity()
	var severityValue any
	if hasSeverity {
		severityValue = string(severity)
	}
	action := record.Action()
	if action == "" {
		action = string(record.EventName())
	}
	enforced := record.Outcome() == observability.OutcomeBlocked ||
		record.Outcome() == observability.OutcomeDenied ||
		record.Outcome() == observability.OutcomeQuarantined ||
		record.Outcome() == observability.OutcomeRevoked ||
		record.Outcome() == observability.OutcomeTerminated

	tx, err := writer.store.db.BeginTx(ctx, nil)
	if err != nil {
		writer.reportHealth(EventHistoryHealthWriteFailed)
		return fmt.Errorf("audit: begin v8 event-history write: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	_, err = txExec(tx, "v8_event_history_insert", `
		INSERT INTO audit_events (
			id, timestamp, action, target, actor, details, structured_json, severity,
			run_id, trace_id, request_id, session_id, agent_instance_id, policy_id, tool_id,
			schema_version, content_hash, generation, binary_version, agent_id, sidecar_instance_id,
			connector, enforced,
			bucket, event_name, source, signal, bucket_catalog_version, payload_json, projected_record_json,
			record_schema_version, projection_hash,
			redaction_profile, mandatory, turn_id, evaluation_id, scan_id, finding_id,
			enforcement_action_id, payload_hmac, integrity_algorithm, integrity_key_id
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?,
			?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?
		)`,
		record.RecordID(), record.Timestamp().Format(time.RFC3339Nano),
		action, nullStr(target), provenance.Producer, details, string(payloadJSON), severityValue,
		nullStr(correlation.RunID), nullStr(correlation.TraceID), nullStr(correlation.RequestID),
		nullStr(correlation.SessionID), nullStr(correlation.AgentInstanceID), nullStr(correlation.PolicyID),
		nullStr(correlation.ToolInvocationID),
		version.SchemaVersion, nullStr(provenance.ConfigDigest),
		provenance.ConfigGeneration, provenance.BinaryVersion,
		nullStr(correlation.AgentID), nullStr(correlation.SidecarInstanceID),
		nullStr(record.Connector()), nullBool(enforced),
		string(record.Bucket()), string(record.EventName()), string(record.Source()), string(record.Signal()),
		record.BucketCatalogVersion(), string(payloadJSON), string(projectedEnvelope),
		record.SchemaVersion(), projectionHash,
		metadata.RedactionProfile, boolInt(record.Mandatory()),
		nullStr(correlation.TurnID), nullStr(correlation.EvaluationID), nullStr(correlation.ScanID),
		nullStr(correlation.FindingOccurrenceID), nullStr(correlation.EnforcementActionID),
		nullStr(payloadHMAC), nullStr(integrityAlgorithm), nullStr(integrityKeyID),
	)
	if err != nil {
		writer.reportHealth(EventHistoryHealthWriteFailed)
		return errors.New("audit: insert v8 event-history row failed")
	}
	if err := tx.Commit(); err != nil {
		writer.reportHealth(EventHistoryHealthWriteFailed)
		return fmt.Errorf("audit: commit v8 event-history row: %w", err)
	}
	return nil
}

func (writer *EventHistoryWriter) reportHealth(code EventHistoryHealthCode) {
	if writer == nil || writer.healthReporter == nil || !writer.healthReporting.CompareAndSwap(false, true) {
		return
	}
	defer writer.healthReporting.Store(false)
	writer.healthReporter.ReportEventHistoryHealth(code)
}

func (writer *EventHistoryWriter) reportUnsigned() {
	if writer != nil && writer.unsignedReported.CompareAndSwap(false, true) {
		writer.reportHealth(EventHistoryHealthUnsigned)
	}
}

func projectedCompatibilityTarget(projection observabilityredaction.Projection) string {
	payload, err := projection.Payload().Object()
	if err != nil {
		return ""
	}
	target, _ := payload["target"].(string)
	return target
}

func projectedCompatibilityDetails(projection observabilityredaction.Projection, fallback string) string {
	payload, err := projection.Payload().Object()
	if err != nil {
		return fallback
	}
	for _, field := range []string{"message", "description", "reason"} {
		if value, ok := payload[field].(string); ok && value != "" {
			return value
		}
	}
	return fallback
}

func (writer *EventHistoryWriter) integrity(
	ctx context.Context,
	projectedEnvelope []byte,
) (payloadHMAC, algorithm, keyID string, err error) {
	if writer.signer == nil {
		writer.reportUnsigned()
		return "", "", "", nil
	}
	keyID = writer.signer.KeyID()
	if err := validateIntegrityKeyID(keyID); err != nil {
		writer.reportHealth(EventHistoryHealthSigningFailed)
		return "", "", "", err
	}
	message := projectionIntegrityMessage(projectedEnvelope, ProjectionIntegrityAlgorithm, keyID)
	signature, signErr := writer.signer.HMACSHA256(ctx, message)
	for index := range message {
		message[index] = 0
	}
	if errors.Is(signErr, ErrIntegrityKeyUnavailable) {
		writer.reportUnsigned()
		return "", "", "", nil
	}
	if signErr != nil {
		writer.reportHealth(EventHistoryHealthSigningFailed)
		return "", "", "", errors.New("audit: sign v8 event-history projection failed")
	}
	if len(signature) != sha256.Size {
		writer.reportHealth(EventHistoryHealthSigningFailed)
		return "", "", "", fmt.Errorf("audit: projection integrity signer returned an invalid digest")
	}
	writer.unsignedReported.Store(false)
	return hex.EncodeToString(signature), ProjectionIntegrityAlgorithm, keyID, nil
}

func validateIntegrityKeyID(keyID string) error {
	if keyID == "" || !utf8.ValidString(keyID) || len(keyID) > observability.MaxCorrelationIDBytes {
		return fmt.Errorf("audit: projection integrity key ID is invalid")
	}
	for _, character := range keyID {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("audit: projection integrity key ID is invalid")
		}
	}
	return nil
}

func validateLocalProjection(
	record observability.Record,
	projection observabilityredaction.Projection,
	expectedProfile observabilityredaction.ProfileName,
) ([]byte, []byte, error) {
	if !observability.IsStableToken(string(expectedProfile)) {
		return nil, nil, fmt.Errorf("audit: effective local redaction profile is invalid")
	}
	canonicalEnvelope, err := record.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("audit: canonical log record is invalid")
	}
	projectedEnvelope, err := projection.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("audit: local log projection is invalid")
	}
	canonical, err := decodeEnvelope(canonicalEnvelope)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: canonical log record is invalid")
	}
	projected, err := decodeEnvelope(projectedEnvelope)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: local log projection is invalid")
	}

	for key, value := range canonical {
		switch key {
		case "body", "field_classes":
			continue
		}
		projectedValue, present := projected[key]
		if !present || !bytes.Equal(value, projectedValue) {
			return nil, nil, fmt.Errorf("audit: record and local projection do not correspond")
		}
	}
	if len(projected) != len(canonical)+1 {
		return nil, nil, fmt.Errorf("audit: local log projection has an invalid envelope")
	}

	payloadJSON := projection.Payload().Bytes()
	if len(payloadJSON) == 0 || !bytes.Equal(projected["body"], payloadJSON) {
		return nil, nil, fmt.Errorf("audit: local log projection payload is invalid")
	}
	if _, exists := projected["instrument_data"]; exists {
		return nil, nil, fmt.Errorf("audit: local log projection has an invalid payload arm")
	}

	var metadata observabilityredaction.ProjectionMetadata
	if err := json.Unmarshal(projected["projection"], &metadata); err != nil ||
		!reflect.DeepEqual(metadata, projection.Metadata()) {
		return nil, nil, fmt.Errorf("audit: local log projection metadata is invalid")
	}
	if metadata.RedactionProfile != string(expectedProfile) {
		return nil, nil, fmt.Errorf("audit: local log projection profile does not match the effective route")
	}
	var projectedClasses map[string]observability.FieldClass
	if err := json.Unmarshal(projected["field_classes"], &projectedClasses); err != nil {
		return nil, nil, fmt.Errorf("audit: local log projection field classes are invalid")
	}
	canonicalClasses := record.FieldClasses()
	for pointer, class := range projectedClasses {
		if canonicalClass, present := canonicalClasses[pointer]; !present || canonicalClass != class {
			return nil, nil, fmt.Errorf("audit: record and local projection field classes do not correspond")
		}
	}
	return append([]byte(nil), projectedEnvelope...), append([]byte(nil), payloadJSON...), nil
}

// VerifyEventHistoryRecord verifies one stored projection without returning its
// content. A missing/rotated key is distinct from corruption.
func (writer *EventHistoryWriter) VerifyEventHistoryRecord(
	ctx context.Context,
	recordID string,
) (EventHistoryVerification, error) {
	if writer == nil || writer.store == nil || writer.store.db == nil {
		return EventHistoryVerification{}, fmt.Errorf("audit: v8 event-history writer is not initialized")
	}
	if ctx == nil {
		return EventHistoryVerification{}, fmt.Errorf("audit: v8 event-history context is required")
	}
	if recordID == "" || len(recordID) > observability.MaxRecordIDBytes || !utf8.ValidString(recordID) {
		return EventHistoryVerification{}, fmt.Errorf("audit: v8 event-history record ID is invalid")
	}
	var projected, projectionHash, payloadHMAC, algorithm, keyID string
	err := writer.store.db.QueryRowContext(ctx, `
		SELECT COALESCE(projected_record_json,''), COALESCE(projection_hash,''),
		       COALESCE(payload_hmac,''), COALESCE(integrity_algorithm,''),
		       COALESCE(integrity_key_id,'')
		FROM audit_events WHERE id = ?`, recordID).Scan(
		&projected, &projectionHash, &payloadHMAC, &algorithm, &keyID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EventHistoryVerification{}, fmt.Errorf("audit: v8 event-history record was not found")
		}
		return EventHistoryVerification{}, fmt.Errorf("audit: read v8 event-history verification fields: %w", err)
	}
	return writer.verifyStoredProjection(ctx, recordID, []byte(projected), projectionHash, payloadHMAC, algorithm, keyID)
}

// VerifyEventHistoryRange verifies a half-open UTC timestamp range. The result
// order is stable and contains no record content.
func (writer *EventHistoryWriter) VerifyEventHistoryRange(
	ctx context.Context,
	from, until time.Time,
	limit int,
) (EventHistoryVerificationRange, error) {
	if writer == nil || writer.store == nil || writer.store.db == nil {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: v8 event-history writer is not initialized")
	}
	if ctx == nil {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: v8 event-history context is required")
	}
	if from.IsZero() || until.IsZero() || !from.Before(until) {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: v8 event-history verification range is invalid")
	}
	if limit <= 0 || limit > maxEventHistoryVerificationRange {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: v8 event-history verification limit is invalid")
	}
	rows, err := writer.store.db.QueryContext(ctx, `
		SELECT id, COALESCE(projected_record_json,''), COALESCE(projection_hash,''),
		       COALESCE(payload_hmac,''), COALESCE(integrity_algorithm,''),
		       COALESCE(integrity_key_id,'')
		FROM audit_events
		WHERE julianday(timestamp) >= julianday(?) AND julianday(timestamp) < julianday(?)
		ORDER BY julianday(timestamp) ASC, id ASC LIMIT ?`,
		from.UTC().Format(time.RFC3339Nano), until.UTC().Format(time.RFC3339Nano), limit+1,
	)
	if err != nil {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: read v8 event-history verification range: %w", err)
	}
	defer rows.Close()
	results := make([]EventHistoryVerification, 0, limit+1)
	for rows.Next() {
		var recordID, projected, projectionHash, payloadHMAC, algorithm, keyID string
		if err := rows.Scan(&recordID, &projected, &projectionHash, &payloadHMAC, &algorithm, &keyID); err != nil {
			return EventHistoryVerificationRange{}, fmt.Errorf("audit: scan v8 event-history verification range")
		}
		result, err := writer.verifyStoredProjection(
			ctx, recordID, []byte(projected), projectionHash, payloadHMAC, algorithm, keyID,
		)
		if err != nil {
			return EventHistoryVerificationRange{}, err
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: iterate v8 event-history verification range: %w", err)
	}
	page := EventHistoryVerificationRange{Records: results}
	if len(page.Records) > limit {
		page.Records = page.Records[:limit]
		page.Truncated = true
	}
	return page, nil
}

func (writer *EventHistoryWriter) verifyStoredProjection(
	ctx context.Context,
	recordID string,
	projected []byte,
	projectionHash, payloadHMAC, algorithm, keyID string,
) (EventHistoryVerification, error) {
	result := EventHistoryVerification{RecordID: recordID}
	if len(projected) == 0 && projectionHash == "" && payloadHMAC == "" && algorithm == "" && keyID == "" {
		result.Status = EventHistoryNotProjected
		return result, nil
	}
	digest := sha256.Sum256(projected)
	wantHash := ProjectionHashAlgorithm + ":" + hex.EncodeToString(digest[:])
	result.ProjectionHashValid = subtle.ConstantTimeCompare([]byte(projectionHash), []byte(wantHash)) == 1
	if !result.ProjectionHashValid {
		result.Status = EventHistoryHashMismatch
		return result, nil
	}
	if payloadHMAC == "" && algorithm == "" && keyID == "" {
		result.Status = EventHistoryUnsigned
		return result, nil
	}
	if payloadHMAC == "" || algorithm != ProjectionIntegrityAlgorithm || validateIntegrityKeyID(keyID) != nil {
		result.Status = EventHistoryInvalidIntegrity
		return result, nil
	}
	result.IntegrityKeyID = keyID
	storedMAC, err := hex.DecodeString(payloadHMAC)
	if err != nil || len(storedMAC) != sha256.Size {
		result.Status = EventHistoryInvalidIntegrity
		return result, nil
	}
	if writer.signer == nil || writer.signer.KeyID() != keyID {
		result.Status = EventHistoryKeyUnavailable
		return result, nil
	}
	message := projectionIntegrityMessage(projected, algorithm, keyID)
	calculated, signErr := writer.signer.HMACSHA256(ctx, message)
	for index := range message {
		message[index] = 0
	}
	if errors.Is(signErr, ErrIntegrityKeyUnavailable) {
		result.Status = EventHistoryKeyUnavailable
		return result, nil
	}
	if signErr != nil {
		return EventHistoryVerification{}, errors.New("audit: verify v8 event-history projection failed")
	}
	if len(calculated) != sha256.Size || !hmac.Equal(storedMAC, calculated) {
		result.Status = EventHistoryHMACMismatch
		return result, nil
	}
	result.Status = EventHistoryVerified
	result.IntegrityVerified = true
	return result, nil
}

func projectionIntegrityMessage(projectedEnvelope []byte, algorithm, keyID string) []byte {
	message := make([]byte, 0, len(projectionIntegrityDomain)+len(algorithm)+len(keyID)+3+len(projectedEnvelope))
	message = append(message, projectionIntegrityDomain...)
	message = append(message, 0)
	message = append(message, algorithm...)
	message = append(message, 0)
	message = append(message, keyID...)
	message = append(message, 0)
	message = append(message, projectedEnvelope...)
	return message
}

func decodeEnvelope(encoded []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var envelope map[string]json.RawMessage
	if err := decoder.Decode(&envelope); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("trailing envelope data")
	}
	return envelope, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
