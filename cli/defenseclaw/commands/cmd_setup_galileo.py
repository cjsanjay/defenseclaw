# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""First-class Galileo Cloud and self-hosted observability setup."""

from __future__ import annotations

import json
import os
import secrets
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse, urlunparse

import click
import yaml

from defenseclaw import ux
from defenseclaw.commands.cmd_setup_observability import (
    _add_v8_destination,
    _remove_v8_destination,
    _set_v8_destination_enabled,
    _test_v8_destination,
    _v8_operator_status,
)
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.observability import (
    apply_preset,
    list_destinations,
    remove_destination,
    resolve_preset,
    set_destination_enabled,
)

_DESTINATION = "galileo"
_KEY_ENV = "GALILEO_API_KEY"
_CLOUD_TRACE_ENDPOINT = "https://api.galileo.ai/otel/traces"


@click.group("galileo", invoke_without_command=True)
@click.option(
    "--deployment",
    type=click.Choice(["cloud", "self-hosted"]),
    default="cloud",
    show_default=True,
)
@click.option("--project", default=None, help="Galileo project name or ID")
@click.option("--logstream", default=None, help="Galileo Log stream name or ID")
@click.option(
    "--console-url",
    default=None,
    help="Self-hosted Galileo console URL; the API trace endpoint is derived from it.",
)
@click.option(
    "--trace-endpoint",
    default=None,
    help="Exact Galileo OTLP HTTP traces endpoint (overrides URL derivation).",
)
@click.option(
    "--persist-api-key",
    is_flag=True,
    help="Copy GALILEO_API_KEY from the environment into ~/.defenseclaw/.env.",
)
@click.option("--disabled", is_flag=True, help="Write the destination disabled.")
@click.option("--dry-run", is_flag=True, help="Preview config changes without writing.")
@click.option("--non-interactive", is_flag=True, help="Require all values through flags/environment.")
@click.pass_context
def galileo(
    ctx: click.Context,
    deployment: str,
    project: str | None,
    logstream: str | None,
    console_url: str | None,
    trace_endpoint: str | None,
    persist_api_key: bool,
    disabled: bool,
    dry_run: bool,
    non_interactive: bool,
) -> None:
    """Configure Galileo OTLP trace export.

    With no subcommand this runs the guided cloud/self-hosted setup. Galileo
    receives traces only; local-observability can remain enabled alongside it.
    """

    if ctx.invoked_subcommand is not None:
        return
    app = ctx.find_object(AppContext)
    if app is None:
        raise click.ClickException("DefenseClaw application context is unavailable")

    if not non_interactive:
        ux.section("Galileo Observability Setup")
        deployment = click.prompt(
            "  Deployment",
            type=click.Choice(["cloud", "self-hosted"]),
            default=deployment,
        )
        if deployment == "self-hosted" and not console_url and not trace_endpoint:
            console_url = click.prompt("  Galileo console URL")
        project = project or click.prompt("  Galileo project name or ID")
        logstream = logstream or click.prompt("  Galileo Log stream", default="default")
        api_key: str | None = None
        if not _resolve_secret(app.cfg.data_dir):
            api_key = click.prompt("  Galileo API key", hide_input=True, confirmation_prompt=True)
    else:
        api_key = None

    if not project:
        raise click.ClickException("--project is required")
    if not logstream:
        raise click.ClickException("--logstream is required")
    project = _validate_routing_header("project", project)
    logstream = _validate_routing_header("logstream", logstream)
    endpoint = _resolve_trace_endpoint(deployment, console_url, trace_endpoint)
    resolved_key = api_key or _resolve_secret(app.cfg.data_dir)
    if not resolved_key:
        raise click.ClickException(f"{_KEY_ENV} is not set; export it or omit --non-interactive for a hidden prompt")

    inputs = {"endpoint": endpoint, "project": project, "logstream": logstream}
    v8_status = _v8_operator_status(app.cfg.data_dir)
    if v8_status is not None:
        existed = any(destination.name == _DESTINATION for destination in v8_status.destinations)
        try:
            result, warnings = _add_v8_destination(
                app.cfg.data_dir,
                resolve_preset("galileo"),
                inputs,
                name=_DESTINATION,
                enabled=not disabled,
                signals=("traces",),
                token_value=resolved_key if api_key or persist_api_key else None,
                target=None,
                dry_run=dry_run,
            )
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        _print_v8_setup_result(
            result,
            warnings,
            deployment=deployment,
            endpoint=endpoint,
            project=project,
            logstream=logstream,
            dry_run=dry_run,
            existed=existed,
        )
        return

    result = apply_preset(
        "galileo",
        inputs,
        app.cfg.data_dir,
        name=_DESTINATION,
        enabled=not disabled,
        signals=("traces",),
        secret_value=resolved_key if api_key or persist_api_key else None,
        dry_run=dry_run,
    )
    click.echo()
    ux.section("Galileo configured" if not dry_run else "Galileo configuration preview")
    updating = any("overwriting existing" in warning for warning in result.warnings)
    click.echo(f"  Action:      {'UPDATE' if updating else 'ADD'}")
    click.echo(f"  Deployment:  {deployment}")
    click.echo(f"  Destination: {_DESTINATION}")
    click.echo(f"  Endpoint:    {endpoint}")
    click.echo(f"  Project:     {project}")
    click.echo(f"  Log stream:  {logstream}")
    click.echo("  Signals:     traces")
    click.echo("  Delivery:    real-time after each completed model/tool operation (≤1s batch delay)")
    for line in result.yaml_changes:
        click.echo(f"  {ux.dim('yaml:')} {line}")
    for line in result.dotenv_changes:
        click.echo(f"  {ux.dim('env:')}  {line}")
    for line in result.warnings:
        ux.warn(line, indent="  ")
    if not dry_run:
        ux.subhead("Next: defenseclaw setup galileo test")


@galileo.command("status")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
@pass_ctx
def status_cmd(app: AppContext, as_json: bool) -> None:
    """Show the configured Galileo destination without secret values."""

    v8_status = _v8_operator_status(app.cfg.data_dir)
    if v8_status is not None:
        payload = _v8_status_payload(app, v8_status)
        _print_status_payload(payload, as_json=as_json)
        return

    destination = next((d for d in list_destinations(app.cfg.data_dir) if d.name == _DESTINATION), None)
    payload = {
        "configured": destination is not None,
        "name": _DESTINATION,
        "enabled": bool(destination and destination.enabled),
        "endpoint": destination.endpoint if destination else "",
        "signals": destination.signals if destination else {},
        "api_key": "configured" if _resolve_secret(app.cfg.data_dir) else "missing",
    }
    live = _live_galileo_health(app)
    if live:
        payload["routing"] = live.get("routing", {})
        payload["delivery"] = live.get("delivery", {})
    _print_status_payload(payload, as_json=as_json)


@galileo.command("enable")
@pass_ctx
def enable_cmd(app: AppContext) -> None:
    """Enable the Galileo destination."""

    if _v8_operator_status(app.cfg.data_dir) is not None:
        _set_v8_destination_enabled(app.cfg.data_dir, _DESTINATION, True, "")
        return
    try:
        set_destination_enabled(_DESTINATION, True, app.cfg.data_dir)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("  Galileo destination enabled.")


@galileo.command("disable")
@pass_ctx
def disable_cmd(app: AppContext) -> None:
    """Disable Galileo without deleting its configuration."""

    if _v8_operator_status(app.cfg.data_dir) is not None:
        _set_v8_destination_enabled(app.cfg.data_dir, _DESTINATION, False, "")
        return
    try:
        set_destination_enabled(_DESTINATION, False, app.cfg.data_dir)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("  Galileo destination disabled.")


@galileo.command("remove")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@pass_ctx
def remove_cmd(app: AppContext, yes: bool) -> None:
    """Remove the Galileo destination; the shared API key is preserved."""

    if not yes and not click.confirm("  Remove the Galileo OTLP destination?", default=False):
        click.echo("  Aborted.")
        return
    if _v8_operator_status(app.cfg.data_dir) is not None:
        _remove_v8_destination(app.cfg.data_dir, _DESTINATION, "")
        click.echo("  GALILEO_API_KEY was preserved.")
        return
    try:
        remove_destination(_DESTINATION, app.cfg.data_dir)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("  Galileo destination removed (GALILEO_API_KEY was preserved).")


@galileo.command("test")
@click.option("--timeout", type=float, default=15.0, show_default=True)
@click.option(
    "--direct",
    is_flag=True,
    help="Bypass the gateway and probe Galileo directly (troubleshooting only).",
)
@pass_ctx
def test_cmd(app: AppContext, timeout: float, direct: bool) -> None:
    """Send a canary through the real gateway/filter/exporter path by default."""

    if _v8_operator_status(app.cfg.data_dir) is not None:
        if direct:
            raise click.ClickException(
                "--direct is not supported for v8 Galileo because OTLP has no isolated write-probe; "
                "omit --direct to use the canonical content-free destination handshake and use "
                "gateway telemetry health for runtime delivery evidence"
            )
        # v8 destination tests are isolated, content-free handshakes against
        # the canonical effective plan.  They deliberately do not claim that
        # an ordinary trace was delivered or invent exporter delivery counts.
        _test_v8_destination(
            app.cfg.data_dir,
            _DESTINATION,
            timeout,
            write_probe=False,
        )
        return

    raw = _load_config(app.cfg.data_dir)
    destination = _raw_destination(raw)
    if destination is None:
        raise click.ClickException("Galileo is not configured; run `defenseclaw setup galileo` first")
    secret = _resolve_secret(app.cfg.data_dir)
    if not secret:
        raise click.ClickException(f"{_KEY_ENV} is not set")

    # Re-validate the persisted value before attaching a credential. An
    # operator may have edited config.yaml after setup; never forward the API
    # key to plaintext HTTP or a URL containing userinfo.
    endpoint = _validate_https_endpoint(str(destination.get("endpoint", "") or ""))
    if not direct:
        payload = _runtime_canary_request(app, timeout)
        trace_id = str(payload.get("trace_id", ""))
        delivery = payload.get("delivery") or {}
        click.echo(f"  ✓ Galileo OTLP collector accepted runtime trace {trace_id}")
        click.echo(
            "  Delivery: "
            f"attempted={delivery.get('attempted', 0)} "
            f"pending={delivery.get('pending', 0)} "
            f"collector_accepted={delivery.get('collector_accepted', delivery.get('delivered', 0))} "
            f"rejected={delivery.get('rejected', 0)} "
            f"failed={delivery.get('failed', 0)}"
        )
        click.echo("  Indexing: unverified by OTLP; confirm the trace in Galileo Logs.")
        return

    # Direct mode deliberately retains the old endpoint probe so operators can
    # distinguish remote auth/connectivity from a gateway runtime problem.
    headers = {str(k): _expand_env(str(v), app.cfg.data_dir) for k, v in (destination.get("headers") or {}).items()}
    headers["Galileo-API-Key"] = secret
    trace_id, body = _canary_request()
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={**headers, "Content-Type": "application/x-protobuf"},
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirectHandler(),
    )
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310 - validated HTTPS below
            response_body = response.read()
            if not 200 <= response.status < 300:
                raise click.ClickException(f"Galileo returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read(1024).decode("utf-8", "replace")
        raise click.ClickException(f"Galileo returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        raise click.ClickException(f"Galileo OTLP request failed: {exc}") from exc

    partial = _partial_success_error(response_body)
    if partial:
        raise click.ClickException(f"Galileo partially rejected the canary: {partial}")
    click.echo(f"  ✓ Galileo OTLP collector accepted direct canary trace {trace_id}")
    click.echo("  Direct probe bypassed the DefenseClaw runtime pipeline.")


def _print_v8_setup_result(
    result,
    warnings: list[str],
    *,
    deployment: str,
    endpoint: str,
    project: str,
    logstream: str,
    dry_run: bool,
    existed: bool,
) -> None:
    """Render one secret-free result from the canonical v8 writer."""

    click.echo()
    ux.section("Galileo configured" if not dry_run else "Galileo configuration preview")
    click.echo(f"  Action:      {'UPDATE' if existed else 'ADD'}")
    click.echo(f"  Deployment:  {deployment}")
    click.echo(f"  Destination: {_DESTINATION}")
    click.echo(f"  Endpoint:    {endpoint}")
    click.echo(f"  Project:     {project}")
    click.echo(f"  Log stream:  {logstream}")
    click.echo("  Signals:     traces")
    click.echo("  Delivery:    real-time after each completed model/tool operation (≤1s batch delay)")
    click.echo(f"  Config:      v8 ({'changed' if result.changed else 'already configured'})")
    for warning in warnings:
        ux.warn(warning, indent="  ")
    if not dry_run:
        ux.subhead("Next: defenseclaw setup galileo test")


def _v8_status_payload(app: AppContext, status) -> dict:
    """Build a v8 Galileo status solely from masked plan and safe health."""

    destination = next(
        (item for item in status.destinations if item.name == _DESTINATION),
        None,
    )
    selected = set(destination.selected_signals) if destination else set()
    payload = {
        "configured": destination is not None,
        "name": _DESTINATION,
        "enabled": bool(destination and destination.enabled),
        "endpoint": destination.endpoint if destination else "",
        "signals": {
            "traces": "traces" in selected,
            "metrics": "metrics" in selected,
            "logs": "logs" in selected,
        },
        "api_key": "configured" if _resolve_secret(app.cfg.data_dir) else "missing",
        "config_version": 8,
    }
    if destination is None:
        return payload

    from defenseclaw.observability.v8_status import destination_health_from_gateway

    health = destination_health_from_gateway(_gateway_health_snapshot(app)).get(_DESTINATION)
    if health is None:
        return payload
    safe_health = {
        key: value
        for key, value in {
            "state": health.state,
            "reason": health.reason,
            "queue_items": health.queue_items,
            "queue_bytes": health.queue_bytes,
            "queue_max_items": health.queue_max_items,
            "queue_max_bytes": health.queue_max_bytes,
            "dropped": health.dropped,
            "last_success": health.last_success,
            "last_failure": health.last_failure,
            "last_error_class": health.last_error_class,
        }.items()
        if value not in (None, "")
    }
    if safe_health:
        payload["health"] = safe_health
    return payload


def _print_status_payload(payload: dict, *, as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    ux.section("Galileo status")
    for key, value in payload.items():
        click.echo(f"  {key.replace('_', ' ').title():<12} {value}")


def _gateway_api_base(app: AppContext) -> str:
    host = str(getattr(app.cfg.gateway, "api_bind", "") or "127.0.0.1")
    if host in {"0.0.0.0", "::", "[::]", "localhost"}:
        host = "127.0.0.1"
    port = int(getattr(app.cfg.gateway, "api_port", 18970) or 18970)
    return f"http://{host}:{port}"


def _runtime_canary_request(app: AppContext, timeout: float) -> dict:
    token = app.cfg.gateway.resolved_token()
    if not token:
        raise click.ClickException("gateway token is unavailable; start/reconfigure the gateway before testing")
    request = urllib.request.Request(
        _gateway_api_base(app) + "/api/v1/telemetry/canary",
        data=json.dumps({"destination": _DESTINATION}).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-DefenseClaw-Client": "python-cli",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - loopback gateway
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read(2048).decode("utf-8", "replace")
        raise click.ClickException(f"gateway runtime Galileo test failed (HTTP {exc.code}): {detail}") from exc
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise click.ClickException(
            "cannot run the real-time Galileo test through the gateway; "
            "ensure defenseclaw-gateway is running (use --direct only to isolate remote connectivity): "
            f"{exc}"
        ) from exc
    if not payload.get("acknowledged"):
        raise click.ClickException(f"gateway did not observe a Galileo acknowledgement: {payload}")
    return payload


def _gateway_health_snapshot(app: AppContext) -> dict:
    request = urllib.request.Request(_gateway_api_base(app) + "/health", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:  # noqa: S310 - loopback gateway
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return {}
    return body if isinstance(body, dict) else {}


def _live_galileo_health(app: AppContext) -> dict:
    body = _gateway_health_snapshot(app)
    telemetry = body.get("telemetry") or {}
    details = telemetry.get("details") or {}
    for destination in details.get("destinations") or []:
        if destination.get("name") == _DESTINATION or destination.get("preset") == "galileo":
            return destination
    return {}


def _resolve_trace_endpoint(deployment: str, console_url: str | None, override: str | None) -> str:
    if override:
        return _validate_https_endpoint(override)
    if deployment == "cloud":
        return _CLOUD_TRACE_ENDPOINT
    if not console_url:
        raise click.ClickException("--console-url or --trace-endpoint is required for self-hosted Galileo")
    parsed = urlparse(console_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise click.ClickException("self-hosted Galileo console URL must be credential-free https://")
    host = parsed.hostname
    if host.startswith("console-"):
        host = "api-" + host[len("console-") :]
    elif host.startswith("console."):
        host = "api." + host[len("console.") :]
    elif host == "console":
        host = "api"
    else:
        raise click.ClickException("cannot derive Galileo API hostname; pass --trace-endpoint explicitly")
    if parsed.port:
        host = f"{host}:{parsed.port}"
    path = parsed.path.rstrip("/") + "/otel/traces"
    return urlunparse(("https", host, path, "", "", ""))


def _validate_https_endpoint(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise click.ClickException("Galileo trace endpoint must be credential-free https:// without query or fragment")
    return value.rstrip("/")


def _validate_routing_header(name: str, value: str) -> str:
    """Reject metadata that the Go secret-header expander could reinterpret."""

    value = value.strip()
    if not value:
        raise click.ClickException(f"Galileo {name} must not be empty")
    if len(value) > 512:
        raise click.ClickException(f"Galileo {name} must be 512 characters or fewer")
    if "$" in value or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise click.ClickException(f"Galileo {name} must not contain '$' or control characters")
    return value


def _load_config(data_dir: str) -> dict:
    path = os.path.join(data_dir, "config.yaml")
    try:
        with open(path) as handle:
            raw = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise click.ClickException(f"cannot read {path}: {exc}") from exc
    return raw if isinstance(raw, dict) else {}


def _raw_destination(raw: dict) -> dict | None:
    destinations = (raw.get("otel") or {}).get("destinations") or []
    return next(
        (d for d in destinations if isinstance(d, dict) and d.get("name") == _DESTINATION),
        None,
    )


def _dotenv_value(data_dir: str, key: str) -> str:
    try:
        with open(os.path.join(data_dir, ".env")) as handle:
            for line in handle:
                if line.startswith(f"{key}="):
                    value = line.split("=", 1)[1].strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                        value = value[1:-1]
                    return value
    except OSError:
        pass
    return ""


def _resolve_secret(data_dir: str) -> str:
    return os.environ.get(_KEY_ENV, "") or _dotenv_value(data_dir, _KEY_ENV)


def _expand_env(value: str, data_dir: str) -> str:
    if value.startswith("${") and value.endswith("}"):
        key = value[2:-1]
        return os.environ.get(key, "") or _dotenv_value(data_dir, key)
    return value


def _canary_request() -> tuple[str, bytes]:
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

    trace_id_bytes = secrets.token_bytes(16)
    span_id_bytes = secrets.token_bytes(8)
    now = time.time_ns()
    request = ExportTraceServiceRequest()
    resource_spans = request.resource_spans.add()
    service_name = resource_spans.resource.attributes.add()
    service_name.key = "service.name"
    service_name.value.string_value = "defenseclaw"
    scope_spans = resource_spans.scope_spans.add()
    scope_spans.scope.name = "defenseclaw.setup.galileo"
    span = scope_spans.spans.add()
    span.trace_id = trace_id_bytes
    span.span_id = span_id_bytes
    span.name = "defenseclaw.galileo.canary"
    span.kind = 3  # SPAN_KIND_CLIENT
    span.start_time_unix_nano = now
    span.end_time_unix_nano = now + 1_000_000

    def string_attribute(key: str, value: str) -> None:
        attribute = span.attributes.add()
        attribute.key = key
        attribute.value.string_value = value

    marker = span.attributes.add()
    marker.key = "defenseclaw.canary"
    marker.value.bool_value = True
    # Galileo accepts only spans that satisfy OTel GenAI or OpenInference
    # semantic conventions. This is a synthetic chat operation (no model is
    # called), but it carries the minimum standard attributes needed to prove
    # ingestion all the way through the Galileo trace pipeline.
    input_messages = json.dumps(
        [{"role": "user", "content": "DefenseClaw Galileo canary request"}],
        separators=(",", ":"),
    )
    output_messages = json.dumps(
        [{"role": "assistant", "content": "DefenseClaw Galileo canary response"}],
        separators=(",", ":"),
    )
    for key, value in (
        ("gen_ai.operation.name", "chat"),
        ("gen_ai.provider.name", "openai"),
        ("gen_ai.system", "openai"),
        ("gen_ai.request.model", "gpt-4o-mini"),
        ("gen_ai.response.model", "gpt-4o-mini"),
        ("gen_ai.input.messages", input_messages),
        ("gen_ai.output.messages", output_messages),
        ("openinference.span.kind", "LLM"),
        ("input.value", "DefenseClaw Galileo canary request"),
        ("input.mime_type", "text/plain"),
        ("output.value", "DefenseClaw Galileo canary response"),
        ("output.mime_type", "text/plain"),
    ):
        string_attribute(key, value)
    return trace_id_bytes.hex(), request.SerializeToString()


def _partial_success_error(body: bytes) -> str:
    if not body:
        return ""
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        from google.protobuf.message import DecodeError
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse

        try:
            partial = ExportTraceServiceResponse.FromString(body).partial_success
        except DecodeError:
            return ""
        if partial.rejected_spans:
            return partial.error_message or str(partial.rejected_spans)
        return ""
    partial = payload.get("partialSuccess") or payload.get("partial_success") or {}
    rejected = partial.get("rejectedSpans") or partial.get("rejected_spans") or 0
    if rejected:
        return str(partial.get("errorMessage") or partial.get("error_message") or rejected)
    return ""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirects disabled", headers, fp)
