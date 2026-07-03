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

package observability

import "sort"

// documentedLogEventNames is the closed log-event vocabulary declared by the
// v8 taxonomy. Producer classification defaults are added separately below so
// legacy audit identities remain routable during the compatibility window.
var documentedLogEventNames = [...]EventName{
	"ai_component.changed",
	"ai_component.confidence.changed",
	"ai_component.discovered",
	"ai_component.removed",
	"alert.acknowledgement.requested",
	"alert.dismissal.requested",
	"approval.resolved",
	"asset.activated",
	"asset.admitted",
	"asset.disabled",
	"asset.discovered",
	"asset.quarantined",
	"asset.registered",
	"asset.released",
	"asset.removed",
	"asset.updated",
	"authentication.failed",
	"authorization.denied",
	"config.change.applied",
	"config.change.attempted",
	"config.reload.rejected",
	"destination.authentication.failed",
	"destination.authorization.denied",
	"destination.export_failed",
	"destination.queue_full",
	"destination.updated",
	"diagnostic.message",
	"diagnostic.snapshot",
	"egress.allowed",
	"egress.blocked",
	"egress.completed",
	"egress.failed",
	"egress.requested",
	"enforcement.access.revoked",
	"enforcement.block.applied",
	"enforcement.block.failed",
	"enforcement.block.requested",
	"enforcement.quarantine.applied",
	"enforcement.redaction.applied",
	"enforcement.release.applied",
	"finding.correlated",
	"finding.observed",
	"guardrail.evaluation.completed",
	"guardrail.evaluation.failed",
	"guardrail.evaluation.started",
	"model.call.failed",
	"model.request",
	"model.response",
	"model.stream.completed",
	"observability.profile.changed",
	"policy.updated",
	"redaction.failed_closed",
	"redaction.profile.updated",
	"scan.cancelled",
	"scan.completed",
	"scan.failed",
	"scan.phase.completed",
	"scan.started",
	"schema.validation_failed",
	"sqlite.write_failed",
	"subsystem.degraded",
	"subsystem.ready",
	"subsystem.restored",
	"telemetry.authentication.failed",
	"telemetry.authorization.denied",
	"telemetry.batch.accepted",
	"telemetry.batch.normalized",
	"telemetry.batch.rejected",
	"telemetry.records.dropped",
	"tool.invocation.blocked",
	"tool.invocation.completed",
	"tool.invocation.failed",
	"tool.invocation.requested",
	"tool.invocation.started",
}

// compatibilityEventNames are the deliberately registered snake_case names.
// Arbitrary names matching this lexical shape are not accepted by the registry.
var compatibilityEventNames = [...]EventName{
	"compact_end",
	"compact_start",
	"event",
	"hook_decision",
	"session_end",
	"session_start",
	"subagent_start",
	"subagent_stop",
	"tool_end",
	"tool_start",
	"turn_end",
	"turn_start",
}

// spanFamilyEventNames mirrors the stable family IDs in spec 11 section 7.
// Rendered, high-cardinality span names are intentionally absent.
var spanFamilyEventNames = [...]EventName{
	"span.admin.operation",
	"span.agent.invoke",
	"span.agent.transition",
	"span.ai.discovery",
	"span.ai.discovery.detector",
	"span.approval.resolve",
	"span.asset.scan",
	"span.asset.scan.phase",
	"span.asset.transition",
	"span.config.reload",
	"span.destination.export",
	"span.diagnostic.canary",
	"span.enforcement.apply",
	"span.finding.enrich",
	"span.guardrail.apply",
	"span.guardrail.judge",
	"span.guardrail.phase",
	"span.model.chat",
	"span.model.embeddings",
	"span.network.request",
	"span.retrieval.search",
	"span.telemetry.normalize",
	"span.telemetry.receive",
	"span.tool.execute",
	"span.workflow.run",
}

// metricInstrumentEventNames is generated from the exhaustive
// x-emitted-metrics catalog in schemas/otel/metrics.schema.json. A drift test
// requires an intentional registry update whenever that catalog changes.
var metricInstrumentEventNames = [...]EventName{
	"defenseclaw.activity.diff_entries",
	"defenseclaw.activity.total",
	"defenseclaw.admission.decisions",
	"defenseclaw.agent.discovery.duration",
	"defenseclaw.agent.discovery.errors",
	"defenseclaw.agent.discovery.installed",
	"defenseclaw.agent.discovery.runs",
	"defenseclaw.agent.discovery.signals",
	"defenseclaw.agent.last_seen",
	"defenseclaw.agent.lifecycle.transitions",
	"defenseclaw.agent.phase.current",
	"defenseclaw.agent.phase.transitions",
	"defenseclaw.agent.reported_cost",
	"defenseclaw.agent.token.usage",
	"defenseclaw.ai.components.installs",
	"defenseclaw.ai.components.observations",
	"defenseclaw.ai.components.workspaces",
	"defenseclaw.ai.confidence.identity_score",
	"defenseclaw.ai.confidence.presence_score",
	"defenseclaw.ai.discovery.active_signals",
	"defenseclaw.ai.discovery.dedupe_suppressed",
	"defenseclaw.ai.discovery.duration",
	"defenseclaw.ai.discovery.errors",
	"defenseclaw.ai.discovery.files_scanned",
	"defenseclaw.ai.discovery.gone_signals",
	"defenseclaw.ai.discovery.new_signals",
	"defenseclaw.ai.discovery.runs",
	"defenseclaw.ai.discovery.signals",
	"defenseclaw.alert.count",
	"defenseclaw.approval.count",
	"defenseclaw.audit.db.errors",
	"defenseclaw.audit.events.total",
	"defenseclaw.audit.sink.batches.delivered",
	"defenseclaw.audit.sink.batches.dropped",
	"defenseclaw.audit.sink.circuit.state",
	"defenseclaw.audit.sink.delivery.latency",
	"defenseclaw.audit.sink.failures",
	"defenseclaw.audit.sink.queue.depth",
	"defenseclaw.cisco.errors",
	"defenseclaw.cisco_inspect.latency",
	"defenseclaw.codex.notify",
	"defenseclaw.codex.notify.malformed",
	"defenseclaw.config.load.errors",
	"defenseclaw.connector.hook.invocations",
	"defenseclaw.connector.hook.latency",
	"defenseclaw.connector.hook.outcome",
	"defenseclaw.connector.hook.tokens",
	"defenseclaw.connector.hook.unified_dispatch",
	"defenseclaw.egress.events",
	"defenseclaw.gateway.errors",
	"defenseclaw.gateway.events.emitted",
	"defenseclaw.gateway.forwarded_headers",
	"defenseclaw.gateway.judge.errors",
	"defenseclaw.gateway.judge.invocations",
	"defenseclaw.gateway.judge.latency",
	"defenseclaw.gateway.verdicts",
	"defenseclaw.guardrail.cache.hits",
	"defenseclaw.guardrail.cache.misses",
	"defenseclaw.guardrail.evaluations",
	"defenseclaw.guardrail.judge.latency",
	"defenseclaw.guardrail.latency",
	"defenseclaw.http.auth.failures",
	"defenseclaw.http.rate_limit.breaches",
	"defenseclaw.http.request.count",
	"defenseclaw.http.request.duration",
	"defenseclaw.inspect.evaluations",
	"defenseclaw.inspect.latency",
	"defenseclaw.judge.persist.batch_size",
	"defenseclaw.judge.persist.drops",
	"defenseclaw.judge.persist.queue_depth",
	"defenseclaw.judge.semaphore.depth",
	"defenseclaw.judge.semaphore.drops",
	"defenseclaw.llm_bridge.latency",
	"defenseclaw.openshell.exit",
	"defenseclaw.otel.ingest.bytes",
	"defenseclaw.otel.ingest.last_seen_ts",
	"defenseclaw.otel.ingest.malformed",
	"defenseclaw.otel.ingest.records",
	"defenseclaw.otel.ingest.requests",
	"defenseclaw.panics.total",
	"defenseclaw.policy.evaluations",
	"defenseclaw.policy.latency",
	"defenseclaw.policy.reloads",
	"defenseclaw.process.uptime_seconds",
	"defenseclaw.provenance.bumps",
	"defenseclaw.quarantine.actions",
	"defenseclaw.queue.depth",
	"defenseclaw.queue.drops",
	"defenseclaw.redaction.applied",
	"defenseclaw.runtime.fd.in_use",
	"defenseclaw.runtime.gc.pause",
	"defenseclaw.runtime.goroutines",
	"defenseclaw.runtime.heap.alloc",
	"defenseclaw.runtime.heap.objects",
	"defenseclaw.scan.count",
	"defenseclaw.scan.duration",
	"defenseclaw.scan.errors",
	"defenseclaw.scan.findings",
	"defenseclaw.scan.findings.by_rule",
	"defenseclaw.scan.findings.gauge",
	"defenseclaw.scanner.queue.depth",
	"defenseclaw.schema.violations",
	"defenseclaw.slo.block.latency",
	"defenseclaw.slo.tui.refresh",
	"defenseclaw.sqlite.busy_retries",
	"defenseclaw.sqlite.checkpoint.duration",
	"defenseclaw.sqlite.db.bytes",
	"defenseclaw.sqlite.freelist_count",
	"defenseclaw.sqlite.page_count",
	"defenseclaw.sqlite.wal.bytes",
	"defenseclaw.stream.bytes_sent",
	"defenseclaw.stream.duration_ms",
	"defenseclaw.stream.lifecycle",
	"defenseclaw.telemetry.destination.exports",
	"defenseclaw.telemetry.destination.spans",
	"defenseclaw.telemetry.exporter.errors",
	"defenseclaw.telemetry.exporter.last_export_ts",
	"defenseclaw.tool.calls",
	"defenseclaw.tool.duration",
	"defenseclaw.tool.errors",
	"defenseclaw.tui.filter.applied",
	"defenseclaw.watcher.errors",
	"defenseclaw.watcher.events",
	"defenseclaw.watcher.restarts",
	"defenseclaw.webhook.circuit_breaker",
	"defenseclaw.webhook.cooldown.suppressed",
	"defenseclaw.webhook.dispatches",
	"defenseclaw.webhook.failures",
	"defenseclaw.webhook.latency",
	"gen_ai.client.operation.duration",
	"gen_ai.client.token.usage",
}

var registeredEventNameSet, registeredEventNameOrder = buildEventNameRegistry(
	gatewayEventClassifications,
	auditActionClassifications,
)

func buildEventNameRegistry(
	gateway map[ProducerKey]Classification,
	audit map[ProducerKey]Classification,
) (map[EventName]struct{}, []EventName) {
	registered := make(map[EventName]struct{},
		len(documentedLogEventNames)+len(compatibilityEventNames)+
			len(spanFamilyEventNames)+len(metricInstrumentEventNames)+len(gateway)+len(audit),
	)
	add := func(name EventName) {
		if err := name.Validate(); err != nil {
			panic("invalid registered observability event name: " + err.Error())
		}
		registered[name] = struct{}{}
	}
	for _, names := range [][]EventName{
		documentedLogEventNames[:],
		compatibilityEventNames[:],
		spanFamilyEventNames[:],
		metricInstrumentEventNames[:],
	} {
		for _, name := range names {
			add(name)
		}
	}
	for _, classifications := range []map[ProducerKey]Classification{gateway, audit} {
		for _, classification := range classifications {
			if classification.DefaultEventName != "" {
				add(classification.DefaultEventName)
			}
		}
	}

	ordered := make([]EventName, 0, len(registered))
	for name := range registered {
		ordered = append(ordered, name)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	return registered, ordered
}

// IsRegisteredEventName reports whether name is a declared v8 routing identity.
// Lexical validity alone is deliberately insufficient.
func IsRegisteredEventName(name EventName) bool {
	_, ok := registeredEventNameSet[name]
	return ok
}

// EventNames returns the complete registry in deterministic lexical order. The
// returned slice is a copy and can be modified safely by the caller.
func EventNames() []EventName {
	return append([]EventName(nil), registeredEventNameOrder...)
}
