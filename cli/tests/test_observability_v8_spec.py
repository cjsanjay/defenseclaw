"""Regression tests for the tracked observability-v8 specification gate."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_observability_v8_spec.py"
PACKAGE = ROOT / "docs" / "design" / "observability-v8"


def _run(package: Path = PACKAGE) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--package", str(package)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _copy_package(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    target = repository / "docs" / "design" / "observability-v8"
    repository.mkdir()
    shutil.copy2(ROOT / "spec.md", repository / "spec.md")
    target.parent.mkdir(parents=True)
    shutil.copytree(PACKAGE, target)
    return target


def test_observability_v8_spec_is_complete_and_traceable() -> None:
    result = _run()

    assert result.returncode == 0, result.stdout + result.stderr
    assert "D=22 S=12 P=70 total=104" in result.stdout


def test_observability_v8_redaction_contract_locks_machine_boundaries() -> None:
    redaction = (PACKAGE / "04-redaction-contract.md").read_text(encoding="utf-8")
    verification = (PACKAGE / "07-verification-and-acceptance.md").read_text(encoding="utf-8")
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(encoding="utf-8")

    assert "| `credential` | `preserve` | `remove` | `remove` | `remove` |" in redaction
    assert "schemas/telemetry/v8/redaction/detector-catalog-v1.yaml" in redaction
    assert "raw|inspected|transformed|failed_closed" in redaction
    assert "at most 4,198,400 bytes" in redaction
    assert "unicode-age-13.0.json" in redaction
    assert "projection_context_mismatch" in redaction
    assert "one shared success/error fixture" in redaction
    assert "`P-001` through `P-070`" in verification
    assert "| P-038 | 04 §7.6 | 07 §6.3 |" in traceability


def test_observability_v8_structural_contract_is_normative() -> None:
    taxonomy = (PACKAGE / "02-taxonomy-and-data-model.md").read_text(encoding="utf-8")
    verification = (PACKAGE / "07-verification-and-acceptance.md").read_text(
        encoding="utf-8",
    )
    decisions = (PACKAGE / "08-decisions-and-exclusions.md").read_text(encoding="utf-8")
    traces = (PACKAGE / "11-trace-and-span-contract.md").read_text(encoding="utf-8")
    schemas = (PACKAGE / "12-telemetry-schema-architecture.md").read_text(encoding="utf-8")
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(encoding="utf-8")

    assert "| P-069 | Define one typed `registry.yaml` `structural_contract`" in decisions
    assert "| P-069 | 02 §§3-3.6; 11 §§5-6; 12 §§4-6.1,8,10-12 |" in traceability
    assert "`/body/message` and" in taxonomy
    assert "`instrument_data` object is exactly `{value, attributes}`" in taxonomy
    assert "`start_time_unix_nano`" in traces
    assert "Span, event, link, resource, and scope dropped" in verification
    assert "workflow {defenseclaw.workflow.name}" in traces
    assert "id: defenseclaw.canonical-record" in schemas
    assert "connector-known-v1" in schemas
    assert "admin-principal-known-v1" in schemas
    assert "agent-phase-v1" in schemas
    assert "kind: string-int64-bijection" in schemas
    assert "Complete single-fault examples" in schemas
    assert "Candidate-bundle acceptance" in verification


def test_observability_v8_generated_builder_source_contract_is_normative() -> None:
    verification = (PACKAGE / "07-verification-and-acceptance.md").read_text(
        encoding="utf-8",
    )
    decisions = (PACKAGE / "08-decisions-and-exclusions.md").read_text(encoding="utf-8")
    schemas = (PACKAGE / "12-telemetry-schema-architecture.md").read_text(
        encoding="utf-8",
    )
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(
        encoding="utf-8",
    )

    assert "| P-070 | Add one closed generated-builder source contract" in decisions
    assert "| P-070 | 12 §§5.2.3,6,12,17 |" in traceability
    assert "`mandatory_rule_catalog` is the closed object" in schemas
    assert "eleven rules" in schemas
    for rule in (
        "always",
        "control_plane_mutation",
        "approval_resolution",
        "alert_mutation",
        "protected_boundary_auth_failure",
        "enforced_outcome",
        "enforcement_state_change",
        "schema_validation_failure",
        "sqlite_failure",
        "exporter_initialization_failure",
        "durable_health_transition",
    ):
        assert f"`{rule}`" in schemas
    assert "`structured_types`" in schemas
    assert "`structured_bindings`" in schemas
    assert "The scalar-leaf arm is" in schemas
    assert "The container/reference arm is" in schemas
    assert "Scalar items use exactly" in schemas
    assert "{name, required, type, field_class, sensitivity, normalization}" in schemas
    assert "{name, required, structured_ref}" in schemas
    assert "{type, field_class, sensitivity, normalization}" in schemas
    assert "{name, type: string, field_class, sensitivity, normalization}" in schemas
    assert "tagged-union discriminators" in verification
    assert "every reachable concrete leaf exactly once" in verification
    assert "object/array/variant container carry none" in verification
    assert "`go_symbol_policy` is exactly" in schemas
    assert "defenseclaw: DefenseClaw" in schemas
    assert "opentelemetry: OpenTelemetry" in schemas
    assert "otel: OTel" in schemas
    assert "separators: ['.', '-', '/', '_']" in schemas
    assert (
        "initialisms: [AI, API, DB, HEC, HTTP, ID, JSON, LLM, OTEL, OTLP, PII, "
        "RPC, SDK, SQL, TLS, URL, UTF8]"
    ) in schemas
    assert "lowercase `brand_spellings` lookup first" in schemas
    assert "uppercase `initialisms` lookup second" in schemas
    assert "ordinary title-case last" in schemas
    for namespace in (
        "TelemetryAttribute<Name>",
        "TelemetryFamily<Name>",
        "TelemetryEvent<Name>",
        "TelemetrySpanEvent<Name>",
        "TelemetryLinkRelation<Name>",
        "TelemetryInstrument<Name>",
        "TelemetryCondition<Name>",
        "TelemetryConditionFact<Name>",
        "TelemetryPhase<Name>",
        "TelemetryPhaseCode<Name>",
        "TelemetrySemanticProfile<Name>",
        "Log<Name>Input",
        "Span<Name>Input",
        "Metric<Name>Input",
        "BuildLog<Name>",
        "BuildSpan<Name>",
        "BuildMetric<Name>",
        "NewSpan<FamilyName><EventName>Event",
        "NewSpan<FamilyName><RelationName>Link",
    ):
        assert f"`{namespace}`" in schemas
    assert "auto_suffix_policy: reject" in schemas
    assert "collision_policy: reject" in schemas
    assert "never appends a numeric, signal, or" in schemas
    assert "BuildTelemetry<Family>" not in schemas
    assert "Telemetry<Family>Input" not in schemas
    assert "`GoSymbolTableIR`" in schemas
    assert "`builder_context`" in schemas
    assert "`CandidateRenderIndex`" in schemas
    assert "`EnrichedFieldDescriptor`" in schemas
    assert "`EnrichedContainerDescriptor`" in schemas
    assert "carrying no field class, sensitivity, or" in schemas
    for path in (
        "internal/observability/zz_generated_telemetry_ids.go",
        "internal/observability/zz_generated_telemetry_catalog.go",
        "internal/observability/zz_generated_telemetry_producers.go",
        "internal/observability/zz_generated_telemetry_builders_genai.go",
        "internal/observability/zz_generated_telemetry_builders_security.go",
        "internal/observability/zz_generated_telemetry_builders_operations.go",
        "internal/observability/zz_generated_telemetry_builder_fixtures_test.go",
    ):
        assert path in schemas
    assert "accept all seven or none" in schemas
    assert "`legacy.audit.*`" in schemas
    assert "Candidate generation MUST remain incomplete" in schemas
    assert "Generated-builder source authority" in verification
    assert "exactly version 1 and its eleven" in verification
    assert "accepted together or none is accepted" in verification


def test_observability_v8_delivery_contract_locks_machine_boundaries() -> None:
    configuration = (PACKAGE / "03-configuration-contract.md").read_text(
        encoding="utf-8",
    )
    storage = (PACKAGE / "05-storage-retention-and-delivery.md").read_text(
        encoding="utf-8",
    )
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(
        encoding="utf-8",
    )

    assert "`batch.max_queue_bytes`" in configuration
    assert "`batch.max_export_batch_bytes`" in configuration
    assert "newest attempted enqueue is dropped" in storage
    assert "immutable projection selected and redacted for that" in storage
    assert "Splunk destination" in storage
    assert "| P-062 | 01 §10; 03 §§1.1,2.1,4.4; 05 §§6-7 |" in traceability
    assert "| P-063 | 03 §4.4; 05 §7.1 |" in traceability


def test_observability_v8_spec_detects_missing_traceability(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "13-decision-traceability.md"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace("| P-047 |", "| P-999 |", 1),
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 1
    assert "decisions missing traceability rows: ['P-047']" in result.stderr
    assert "traceability rows without decisions: ['P-999']" in result.stderr


def test_observability_v8_spec_detects_broken_package_link(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "README.md"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n[missing](not-present.md)\n",
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 1
    assert "README.md: missing linked path 'not-present.md'" in result.stderr


def test_observability_v8_spec_ignores_rows_and_links_in_fences(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "README.md"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n```markdown\n"
        + "| D-001 | illustrative duplicate |\n"
        + "| P-999 | illustrative contract | illustrative test |\n"
        + "[illustrative missing link](not-present.md)\n"
        + "```\n",
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 0, result.stdout + result.stderr


def test_observability_v8_spec_detects_unclosed_tilde_fence(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "README.md"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n~~~yaml\nunclosed: true\n",
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 1
    assert "README.md: unbalanced fenced code blocks" in result.stderr
