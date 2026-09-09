"""Authoritative, side-effect-free Recorder Next HTTP operation catalog.

This module is deliberately independent from ``openapi`` and from the
service implementation.  The same immutable operation and DTO metadata is
used for admission, OpenAPI generation, and the checked-in coverage matrix.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import copy
import hashlib
import json
import re
from typing import Any, Iterable

from .api_models import (
    ARCHIVE_TURN,
    DEVICE_REGISTER,
    DEVICE_REVOKE,
    DIAGNOSTICS_BUNDLE,
    DIAGNOSTICS_DELETE,
    DIAGNOSTICS_EVENT,
    DIAGNOSTICS_OPT_IN,
    EAVESDROP_ACTION,
    EAVESDROP_ROUTE,
    EAVESDROP_ROUTE_PATH,
    EAVESDROP_SEGMENT,
    EAVESDROP_START,
    EVENT_ACK,
    EXPECTED_VERSION,
    FINISH_PART,
    ObjectModel,
    OWNER_PROOF,
    PLAYBACK_ACK,
    PROJECT_CREATE,
    PROJECT_PATCH,
    RELAY_RECEIVED,
    REQUEST_MODELS,
    SCHEDULE_CREATE,
    SCHEDULER_FIRE,
    SCHEDULER_RECOVER,
    TURN_CREATE,
    WORKER_CLAIM,
    WORKER_COMPLETE,
    WORKER_FAIL,
    WORKER_RECOVER,
    WORKER_RECEIPT,
    WORKER_RUN,
    ModelValidationError,
)
from .errors import NotFoundError, UnsupportedMediaType, ValidationError
from .ingress_contract import strict_json_loads


@dataclass(frozen=True)
class Parameter:
    name: str
    location: str
    required: bool = False
    schema_type: str = "string"
    format: str | None = None
    enum: tuple[str, ...] = ()
    minimum: int | None = None
    pattern: str | None = None
    internal: bool = False

    def openapi_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {"type": self.schema_type}
        if self.format:
            schema["format"] = self.format
        if self.enum:
            schema["enum"] = list(self.enum)
        if self.minimum is not None:
            schema["minimum"] = self.minimum
        if self.pattern:
            schema["pattern"] = self.pattern
        return schema


@dataclass(frozen=True)
class ResponseSpec:
    status: int
    description: str
    schema_name: str | None = None
    media_type: str | None = "application/json"
    headers: tuple[str, ...] = ()
    no_body: bool = False

    @property
    def status_text(self) -> str:
        return str(self.status)


@dataclass(frozen=True)
class Operation:
    path_template: str
    method: str
    operation_id: str
    handler_key: str
    parameters: tuple[Parameter, ...] = ()
    request_model: ObjectModel | None = None
    request_media_types: tuple[str, ...] = ()
    request_required: bool = False
    deprecated: bool = False
    public: bool = False
    principal_policy: str = "principal"
    responses: tuple[ResponseSpec, ...] = ()
    allow_empty_body_with_query_identity: bool = False

    @property
    def requires_principal(self) -> bool:
        return self.principal_policy == "principal"

    @property
    def path_parameters(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.parameters if item.location == "path" and not item.internal)

    @property
    def query_parameters(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.parameters if item.location == "query" and not item.internal)

    @property
    def header_parameters(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.parameters if item.location == "header" and not item.internal)

    @property
    def path_params(self) -> tuple[str, ...]:
        return self.path_parameters

    @property
    def query_params(self) -> tuple[str, ...]:
        return self.query_parameters

    @property
    def headers(self) -> tuple[str, ...]:
        return self.header_parameters

    @property
    def body_descriptor(self) -> tuple[tuple[str, str], ...]:
        if not self.request_media_types:
            return ()
        schema_name = self.request_model.name if self.request_model else "ChunkUpload"
        return tuple((media, f"#/components/schemas/{schema_name}") for media in self.request_media_types)

    @property
    def body(self) -> tuple[tuple[str, str], ...]:
        return self.body_descriptor

    @property
    def success_statuses(self) -> tuple[str, ...]:
        return tuple(item.status_text for item in self.responses if item.status < 400)

    @property
    def error_statuses(self) -> tuple[str, ...]:
        return tuple(item.status_text for item in self.responses if item.status >= 400)

    def response(self, status: int) -> ResponseSpec:
        for item in self.responses:
            if item.status == status:
                return item
        raise ValueError(f"{self.method} {self.path_template} does not declare HTTP {status}")


def _path(name: str, *, schema_type: str = "string", format: str | None = None, pattern: str | None = None, minimum: int | None = None) -> Parameter:
    return Parameter(name, "path", required=True, schema_type=schema_type, format=format, pattern=pattern, minimum=minimum)


def _query(name: str, *, required: bool = False, schema_type: str = "string", minimum: int | None = None, enum: tuple[str, ...] = (), internal: bool = False) -> Parameter:
    return Parameter(name, "query", required=required, schema_type=schema_type, enum=enum, minimum=minimum, internal=internal)


def _header(name: str, *, required: bool = False, internal: bool = False) -> Parameter:
    return Parameter(name, "header", required=required, internal=internal)


_PRINCIPAL = (
    _header("X-Recorder-Principal-User", required=True),
    _header("X-Recorder-Principal-Device", required=True),
    _header("X-Recorder-Principal-Signature", required=True),
    _header("X-Recorder-User-ID"),
    _header("X-Recorder-Device-ID"),
)
_OWNER_QUERY = (_query("user_id"), _query("device_id"), _query("now", internal=True))
_PHONE_QUERY = _OWNER_QUERY + (_query("phone_device_id"),)
_JSON = ("application/json",)
_BINARY = ("application/octet-stream",)


def _errors(*statuses: int, forbidden: bool = False) -> tuple[ResponseSpec, ...]:
    values = list(statuses)
    if forbidden:
        values.append(403)
    seen: set[int] = set()
    result: list[ResponseSpec] = []
    for status in values:
        if status in seen:
            continue
        seen.add(status)
        result.append(ResponseSpec(status, "Structured Recorder error", "Error", "application/json"))
    return tuple(result)


def _responses(
    success: tuple[ResponseSpec, ...],
    *,
    errors: tuple[int, ...] = (400, 401, 404, 409, 413, 415, 500),
    forbidden: bool = False,
) -> tuple[ResponseSpec, ...]:
    return success + _errors(*errors, forbidden=forbidden)


def _json_success(status: int, schema_name: str, description: str) -> ResponseSpec:
    return ResponseSpec(status, description, schema_name, "application/json")


def _op(
    path: str,
    method: str,
    *,
    request_model: ObjectModel | None = None,
    request_required: bool = False,
    request_media_types: tuple[str, ...] | None = None,
    parameters: tuple[Parameter, ...] = (),
    responses: tuple[ResponseSpec, ...],
    operation_id: str | None = None,
    handler_key: str | None = None,
    deprecated: bool = False,
    public: bool = False,
    principal_policy: str = "principal",
    allow_empty_body_with_query_identity: bool = False,
) -> Operation:
    upper = method.upper()
    default_id = f"{method.lower()}_{path.strip('/').replace('/', '_').replace('{', '').replace('}', '')}"
    return Operation(
        path,
        upper,
        operation_id or default_id,
        handler_key or operation_id or default_id,
        parameters,
        request_model,
        request_media_types if request_media_types is not None else (_JSON if request_model else ()),
        request_required,
        deprecated,
        public,
        principal_policy,
        responses,
        allow_empty_body_with_query_identity,
    )


def _protected(*extra: Parameter, phone: bool = False) -> tuple[Parameter, ...]:
    query = _PHONE_QUERY if phone else _OWNER_QUERY
    return _PRINCIPAL + query + extra


_BASE_OPERATIONS: tuple[Operation, ...] = (
    _op("/v1/health", "GET", parameters=(), responses=_responses((_json_success(200, "HealthResponse", "Readiness"),), errors=(500,)), public=True, principal_policy="public"),
    _op("/v1/openapi.json", "GET", parameters=(), responses=_responses((_json_success(200, "OpenAPIDocument", "This contract"),), errors=(500,)), public=True, principal_policy="public"),
    _op("/v1/devices", "POST", request_model=DEVICE_REGISTER, request_required=True, parameters=_PRINCIPAL, responses=_responses((_json_success(201, "DeviceResponse", "Registered device"),), errors=(400, 401, 409, 413, 415, 500))),
    _op("/v1/devices/{device_id}/revoke", "POST", request_model=DEVICE_REVOKE, request_required=True, parameters=_protected(_path("device_id")), responses=_responses((_json_success(200, "DeviceResponse", "Revoked device"),))),
    _op("/v1/turns", "POST", request_model=TURN_CREATE, request_required=True, parameters=_PRINCIPAL, responses=_responses((_json_success(201, "TurnResponse", "Receiving turn"), _json_success(202, "TurnResponse", "Accepted text turn")), errors=(400, 401, 409, 413, 415, 500))),
    _op("/v1/turns/{turn_id}", "GET", parameters=_protected(_path("turn_id", format="uuid")), responses=_responses((_json_success(200, "TurnResponse", "Turn ledger"),))),
    _op("/v1/turns/{turn_id}/accept", "POST", request_model=OWNER_PROOF, request_required=True, parameters=_protected(_path("turn_id", format="uuid")), responses=_responses((_json_success(200, "TurnResponse", "Durable ACCEPTED"),))),
    _op("/v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}", "PUT", request_media_types=_BINARY, request_required=True, parameters=_protected(_path("turn_id", format="uuid"), _path("part_id"), _path("sequence", schema_type="integer", minimum=0), _header("X-Chunk-SHA256", required=True)), responses=_responses((_json_success(200, "ChunkReceipt", "Chunk receipt"),))),
    _op("/v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}", "POST", request_media_types=_BINARY, request_required=True, parameters=_protected(_path("turn_id", format="uuid"), _path("part_id"), _path("sequence", schema_type="integer", minimum=0), _header("X-Chunk-SHA256", required=True)), responses=_responses((_json_success(200, "ChunkReceipt", "Chunk receipt"),)), operation_id="ChunkUploadPost"),
    _op("/v1/turns/{turn_id}/parts/{part_id}/missing", "GET", parameters=_protected(_path("turn_id", format="uuid"), _path("part_id"), _query("total_chunks", required=True, schema_type="integer", minimum=1), _query("offset", schema_type="integer", minimum=0), _query("limit", schema_type="integer", minimum=1), _query("encoding", enum=("list", "ranges"))), responses=_responses((_json_success(200, "MissingSequencePage", "Missing sequence list"),))),
    _op("/v1/turns/{turn_id}/parts/{part_id}/finish", "POST", request_model=FINISH_PART, request_required=True, parameters=_protected(_path("turn_id", format="uuid"), _path("part_id")), responses=_responses((_json_success(200, "TurnPartResponse", "Verified part"),))),
    _op("/v1/turns/{turn_id}/events/{event_id}/ack", "POST", request_model=EVENT_ACK, request_required=True, parameters=_protected(_path("turn_id", format="uuid"), _path("event_id")), responses=_responses((_json_success(200, "EventAckResponse", "Event ACK"),))),
    _op("/v1/outbox", "GET", parameters=_protected(_query("limit", schema_type="integer", minimum=1)), responses=_responses((_json_success(200, "OutboxResponse", "Origin-device ordered outbox"),))),
    _op("/v1/tts/{artifact_id}", "GET", parameters=_protected(_path("artifact_id")), responses=_responses((_json_success(200, "TTSResponse", "TTS payload"),), errors=(400, 401, 404, 409, 500))),
    _op("/v1/tts/{artifact_id}/bridge-read", "GET", parameters=_protected(_path("artifact_id")), responses=_responses((_json_success(200, "TTSResponse", "TTS payload"),), errors=(400, 401, 404, 409, 500))),
    _op("/v1/tts/{artifact_id}/playback-ack", "POST", request_model=PLAYBACK_ACK, request_required=True, parameters=_protected(_path("artifact_id")), responses=_responses((_json_success(200, "PlaybackAckResponse", "Target playback completion"),), errors=(400, 401, 404, 409, 413, 415, 500))),
    _op("/v1/tts/{artifact_id}/relay-received", "POST", request_model=RELAY_RECEIVED, request_required=True, parameters=_protected(_path("artifact_id")), responses=_responses((_json_success(200, "RelayReceivedResponse", "Non-origin relay receipt"),))),
    _op("/v1/projects", "GET", parameters=_protected(_query("include_archived", schema_type="boolean")), responses=_responses((_json_success(200, "ProjectListResponse", "Project registry"),))),
    _op("/v1/projects", "POST", request_model=PROJECT_CREATE, request_required=True, parameters=_PRINCIPAL, responses=_responses((_json_success(201, "ProjectResponse", "Project"),), errors=(400, 401, 409, 413, 415, 500))),
    _op("/v1/projects/search", "GET", parameters=_protected(_query("q"), _query("include_archived", schema_type="boolean")), responses=_responses((_json_success(200, "ProjectListResponse", "Project search"),))),
    _op("/v1/projects/{project_id}", "GET", parameters=_protected(_path("project_id")), responses=_responses((_json_success(200, "ProjectResponse", "Project"),))),
    _op("/v1/projects/{project_id}", "PATCH", request_model=PROJECT_PATCH, request_required=True, parameters=_protected(_path("project_id")), responses=_responses((_json_success(200, "ProjectResponse", "CAS update"),))),
    _op("/v1/turns/{turn_id}/archive", "POST", request_model=ARCHIVE_TURN, request_required=True, parameters=_protected(_path("turn_id", format="uuid")), responses=_responses((_json_success(200, "TurnResponse", "Archive-only turn retention"),))),
    _op("/v1/projects/{project_id}/archive", "POST", request_model=EXPECTED_VERSION, request_required=True, parameters=_protected(_path("project_id")), responses=_responses((_json_success(200, "ProjectResponse", "Archive-only transition"),))),
    _op("/v1/internal/schedule_create", "POST", request_model=SCHEDULE_CREATE, request_required=True, parameters=_protected(_header("X-Recorder-Internal-Trusted")), responses=_responses((_json_success(201, "ScheduleResponse", "Durably scheduled with atomic confirmation FINAL"),), errors=(400, 401, 409, 413, 415, 500))),
    _op("/v1/internal/scheduler/fire", "POST", request_model=SCHEDULER_FIRE, request_required=True, parameters=_protected(), responses=_responses((_json_success(200, "SchedulerFireResponse", "Scheduled FINAL readback"),), forbidden=True)),
    _op("/v1/internal/scheduler/recover", "POST", request_model=SCHEDULER_RECOVER, request_required=True, parameters=_protected(), responses=_responses((_json_success(200, "SchedulerRecoveryResponse", "Recovery counts"),), forbidden=True)),
    _op("/v1/schedules/{schedule_id}", "GET", parameters=_protected(_path("schedule_id")), responses=_responses((_json_success(200, "ScheduleResponse", "Schedule and occurrence readback"),))),
    _op("/v1/updates/{channel}/manifest", "GET", parameters=(_path("channel"), _header("If-None-Match")), responses=_responses((_json_success(200, "UpdateManifestResponse", "Current immutable channel manifest"), ResponseSpec(304, "ETag matched", None, None, ("ETag", "Cache-Control"), True)), errors=(400, 404, 500)), principal_policy="none"),
    _op("/v1/updates/{channel}/{generation}/{artifact_name}", "GET", parameters=(_path("channel"), _path("generation", schema_type="integer", minimum=1), _path("artifact_name"), _header("Range"), _header("If-Range"), _header("If-None-Match")), responses=_responses((ResponseSpec(200, "Hash-bound APK bytes", "BinaryBody", "application/vnd.android.package-archive", ("Content-Type", "Content-Length", "ETag", "Accept-Ranges", "Cache-Control")), ResponseSpec(206, "Byte range", "BinaryBody", "application/vnd.android.package-archive", ("Content-Type", "Content-Length", "ETag", "Accept-Ranges", "Content-Range", "Cache-Control")), ResponseSpec(304, "ETag matched", None, None, ("ETag", "Content-Length", "Cache-Control"), True), ResponseSpec(416, "Unsatisfiable range", None, None, ("ETag", "Content-Length", "Accept-Ranges", "Content-Range", "Cache-Control"), True)), errors=(400, 404, 500)), principal_policy="none"),
    _op("/v1/history", "GET", parameters=_protected(_query("project_id"), _query("include_archived", schema_type="boolean"), _query("input_type"), _query("cursor"), _query("since_seq", schema_type="integer", minimum=0), _query("limit", schema_type="integer", minimum=1)), responses=_responses((_json_success(200, "HistoryResponse", "Paired user/assistant messages"),))),
    _op("/v1/eavesdrop", "POST", request_model=EAVESDROP_START, request_required=True, parameters=_PRINCIPAL, responses=_responses((_json_success(201, "EavesdropSessionResponse", "Created session"),), errors=(400, 401, 409, 413, 415, 500))),
    _op("/v1/eavesdrop/{session_id}", "GET", parameters=_protected(_path("session_id"), phone=True), responses=_responses((_json_success(200, "EavesdropSessionResponse", "Session state"),))),
    _op("/v1/eavesdrop/{session_id}/activate", "POST", request_model=EAVESDROP_ACTION, request_required=True, parameters=_protected(_path("session_id"), phone=True), responses=_responses((_json_success(200, "EavesdropSessionResponse", "Activated eavesdrop session"),))),
    _op("/v1/eavesdrop/{session_id}/pause", "POST", request_model=EAVESDROP_ACTION, request_required=True, parameters=_protected(_path("session_id"), phone=True), responses=_responses((_json_success(200, "EavesdropSessionResponse", "Paused eavesdrop session"),))),
    _op("/v1/eavesdrop/{session_id}/resume", "POST", request_model=EAVESDROP_ACTION, request_required=True, parameters=_protected(_path("session_id"), phone=True), responses=_responses((_json_success(200, "EavesdropSessionResponse", "Resumed eavesdrop session"),))),
    _op("/v1/eavesdrop/{session_id}/stop", "POST", request_model=EAVESDROP_ACTION, request_required=True, parameters=_protected(_path("session_id"), phone=True), responses=_responses((_json_success(200, "EavesdropSessionResponse", "Stopped eavesdrop session"),))),
    _op("/v1/eavesdrop/{session_id}/segments", "POST", request_model=EAVESDROP_SEGMENT, request_required=True, parameters=_protected(_path("session_id"), phone=True), responses=_responses((_json_success(201, "EavesdropSegmentResponse", "Eavesdrop segment receipt"),))),
    _op("/v1/eavesdrop/{session_id}/replies", "GET", parameters=_protected(_path("session_id"), phone=True), responses=_responses((_json_success(200, "EavesdropRepliesResponse", "Optional response receipts"),))),
    _op("/v1/diagnostics/opt-in", "POST", request_model=DIAGNOSTICS_OPT_IN, request_required=True, parameters=_PRINCIPAL, responses=_responses((_json_success(201, "DiagnosticsConsentResponse", "Consent event"),), errors=(400, 401, 409, 413, 415, 500))),
    _op("/v1/diagnostics/events", "POST", request_model=DIAGNOSTICS_EVENT, request_required=True, parameters=_PRINCIPAL, responses=_responses((_json_success(201, "DiagnosticEventResponse", "Redacted diagnostic event"),), errors=(400, 401, 409, 413, 415, 500))),
    _op("/v1/diagnostics/bundles", "POST", request_model=DIAGNOSTICS_BUNDLE, request_required=True, parameters=_PRINCIPAL, responses=_responses((_json_success(201, "DiagnosticBundleResponse", "Bounded compressed diagnostic bundle"),), errors=(400, 401, 409, 413, 415, 500))),
    _op("/v1/diagnostics", "GET", parameters=_protected(_query("category"), _query("stage"), _query("limit", schema_type="integer", minimum=1)), responses=_responses((_json_success(200, "DiagnosticListResponse", "Diagnostic metadata"),))),
    _op("/v1/diagnostics", "DELETE", request_model=DIAGNOSTICS_DELETE, request_required=True, parameters=_protected(), responses=_responses((_json_success(200, "DeletionReceipt", "Deletion receipt and tombstones"),), errors=(400, 401, 409, 413, 415, 500)), allow_empty_body_with_query_identity=True),
    _op("/v1/diagnostics/delete", "POST", request_model=DIAGNOSTICS_DELETE, request_required=True, parameters=_PRINCIPAL, responses=_responses((_json_success(200, "DeletionReceipt", "Deletion receipt and tombstones"),), errors=(400, 401, 409, 413, 415, 500))),
    _op("/v1/internal/worker/claim", "POST", request_model=WORKER_CLAIM, request_required=True, parameters=_protected(), responses=_responses((_json_success(200, "WorkerClaimResponse", "Claim one durable worker lease"),), forbidden=True)),
    _op("/v1/internal/worker/recover", "POST", request_model=WORKER_RECOVER, request_required=True, parameters=_protected(), responses=_responses((_json_success(200, "WorkerRecoveryResponse", "Recover expired worker leases"),), forbidden=True)),
    _op("/v1/internal/worker/complete", "POST", request_model=WORKER_COMPLETE, request_required=True, parameters=_protected(), responses=_responses((_json_success(200, "WorkerMutationResponse", "Complete one durable worker lease"),), forbidden=True)),
    _op("/v1/internal/worker/fail", "POST", request_model=WORKER_FAIL, request_required=True, parameters=_protected(), responses=_responses((_json_success(200, "WorkerMutationResponse", "Record one durable worker failure"),), forbidden=True)),
    _op("/v1/internal/worker/run", "POST", request_model=WORKER_RUN, request_required=True, parameters=_protected(), responses=_responses((_json_success(200, "WorkerRunResponse", "Run one durable worker lease operation"),), forbidden=True)),
    _op("/v1/internal/worker/health", "GET", parameters=_protected(), responses=_responses((_json_success(200, "WorkerHealth", "Bounded worker backlog and lease health"),), forbidden=True)),
    _op("/v1/eavesdrop/{session_id}/segments/{segment_sequence}/route", "POST", request_model=EAVESDROP_ROUTE_PATH, request_required=True, parameters=_protected(_path("session_id"), _path("segment_sequence", schema_type="integer", minimum=0)), responses=_responses((_json_success(200, "RoutingDecisionResponse", "Idempotent fixed-project routing decision"),))),
    _op("/v1/eavesdrop/{session_id}/segments/route", "POST", request_model=EAVESDROP_ROUTE, request_required=True, parameters=_protected(_path("session_id")), responses=_responses((_json_success(200, "RoutingDecisionResponse", "Deprecated body-sequence routing alias"),)), operation_id="EavesdropRouteBodyAlias", deprecated=True),
    _op("/v1/eavesdrop/{session_id}/decisions", "GET", parameters=_protected(_path("session_id"), phone=True), responses=_responses((_json_success(200, "RoutingDecisionsResponse", "Eavesdrop routing decision ledger"),))),
    _op("/v1/diagnostics/export", "GET", parameters=_protected(_query("category"), _query("stage"), _query("cursor"), _query("limit", schema_type="integer", minimum=1), _query("max_bytes", schema_type="integer", minimum=1024)), responses=_responses((_json_success(200, "DiagnosticExportResponse", "Redacted diagnostic export"),))),
)


_ALIAS_OPERATIONS: tuple[Operation, ...] = (
    _op("/healthz", "GET", responses=_responses((_json_success(200, "HealthResponse", "Readiness"),), errors=(500,)), operation_id="HealthAlias", deprecated=True, public=True, principal_policy="public"),
    _op("/v1/devices/register", "POST", request_model=DEVICE_REGISTER, request_required=True, parameters=_PRINCIPAL, responses=_responses((_json_success(201, "DeviceResponse", "Confirmed device"),), errors=(400, 401, 409, 413, 415, 500)), operation_id="DeviceConfirm"),
    _op("/v1/turns/{turn_id}/events/{event_id}", "POST", request_model=EVENT_ACK, request_required=True, parameters=_protected(_path("turn_id", format="uuid"), _path("event_id")), responses=_responses((_json_success(200, "EventAckResponse", "Event ACK"),)), operation_id="EventAckAlias"),
    _op("/v1/updates/{channel}/manifest.json", "GET", parameters=(_path("channel"), _header("If-None-Match")), responses=_responses((_json_success(200, "UpdateManifestResponse", "Current immutable channel manifest"), ResponseSpec(304, "ETag matched", None, None, ("ETag", "Cache-Control"), True)), errors=(400, 404, 500)), operation_id="UpdateManifestJson", deprecated=True, principal_policy="none"),
)


def _template_regex(template: str) -> re.Pattern[str]:
    parts: list[str] = []
    for part in template.strip("/").split("/") if template != "/" else []:
        parts.append(r"[^/]+" if part.startswith("{") and part.endswith("}") else re.escape(part))
    return re.compile(r"^/" + "/".join(parts) + r"/?$")


def _head_operation(operation: Operation) -> Operation:
    if operation.method != "GET":
        return operation
    success = tuple(
        ResponseSpec(item.status, item.description, None if item.no_body else item.schema_name, None if item.no_body else item.media_type, item.headers, True)
        for item in operation.responses
        if item.status < 400
    )
    errors = tuple(item for item in operation.responses if item.status >= 400)
    return Operation(
        operation.path_template,
        "HEAD",
        f"head_{operation.operation_id}",
        f"head_{operation.handler_key}",
        operation.parameters,
        None,
        (),
        False,
        operation.deprecated,
        operation.public,
        operation.principal_policy,
        success + errors,
    )


_OPERATIONS: tuple[Operation, ...] = tuple(
    item
    for operation in _BASE_OPERATIONS + _ALIAS_OPERATIONS
    for item in ((operation, _head_operation(operation)) if operation.method == "GET" else (operation,))
)
_MATCH_OPERATIONS: tuple[tuple[Operation, re.Pattern[str]], ...] = tuple((item, _template_regex(item.path_template)) for item in _OPERATIONS)


def route_catalog() -> tuple[Operation, ...]:
    """Return the immutable catalog snapshot in deterministic order."""

    return _OPERATIONS


def match_operation(path: str, method: str) -> Operation:
    """Return an exact operation or raise a non-mutating 404.

    HTTP HEAD is catalogued separately so its no-body policy is executable;
    the service may still share the GET handler implementation.
    """

    normalized_path = path.rstrip("/") or "/"
    normalized_method = method.upper()
    for operation, pattern in _MATCH_OPERATIONS:
        if operation.method == normalized_method and pattern.fullmatch(normalized_path):
            return operation
    raise NotFoundError("route not found")


def _path_values(operation: Operation, path: str) -> dict[str, str]:
    template_parts = operation.path_template.strip("/").split("/") if operation.path_template != "/" else []
    path_parts = path.rstrip("/").strip("/").split("/") if path.rstrip("/") != "/" else []
    if len(template_parts) != len(path_parts):
        raise ValidationError("path does not match the operation template")
    values: dict[str, str] = {}
    for template_part, value in zip(template_parts, path_parts):
        if template_part.startswith("{") and template_part.endswith("}"):
            values[template_part[1:-1]] = value
    return values


def _validate_parameter(parameter: Parameter, value: str, *, path: str) -> None:
    if parameter.schema_type == "integer":
        if not re.fullmatch(r"[0-9]+", value):
            raise ValidationError(f"{path} must be a non-negative integer")
        if parameter.minimum is not None and int(value) < parameter.minimum:
            raise ValidationError(f"{path} is below the minimum")
    elif parameter.schema_type == "boolean" and value not in {"true", "false"}:
        raise ValidationError(f"{path} must be boolean")
    if parameter.enum and value not in parameter.enum:
        raise ValidationError(f"{path} has an unsupported value")
    if parameter.pattern and re.fullmatch(parameter.pattern, value) is None:
        raise ValidationError(f"{path} has an invalid format")


def validate_request(
    operation: Operation,
    *,
    path: str,
    query: Mapping[str, str],
    headers: Mapping[str, str],
    body: bytes,
    decoded: Mapping[str, Any] | None = None,
    network: bool = False,
) -> dict[str, Any] | None:
    """Validate a request without invoking a handler or mutating state."""

    values = _path_values(operation, path)
    parameters_by_location = {
        location: {item.name: item for item in operation.parameters if item.location == location}
        for location in ("path", "query", "header")
    }
    for name in query:
        if name not in parameters_by_location["query"]:
            raise ValidationError(f"query parameter {name} is not declared for this operation")
    for parameter in parameters_by_location["path"].values():
        value = values.get(parameter.name)
        if value is None:
            raise ValidationError(f"path parameter {parameter.name} is required")
        _validate_parameter(parameter, value, path=parameter.name)
    for parameter in parameters_by_location["query"].values():
        value = query.get(parameter.name)
        if value is None:
            # Domain handlers perform owner/authentication before consuming
            # required query values.  Keeping that ordering preserves a
            # precise 401 for an unregistered owner instead of leaking a
            # pre-authentication 400 for a missing filter.
            continue
        if parameter.internal and network:
            raise ValidationError("server time cannot be supplied by a client")
        _validate_parameter(parameter, value, path=parameter.name)
    for parameter in parameters_by_location["header"].values():
        values_for_header = [value for key, value in headers.items() if str(key).lower() == parameter.name.lower()]
        if len(values_for_header) > 1:
            raise ValidationError(f"duplicate {parameter.name} headers are not permitted")

    if operation.method == "HEAD":
        if body:
            raise ValidationError("HEAD requests do not accept a body")
        return None
    if not operation.request_model:
        if body:
            if operation.request_media_types == _BINARY:
                if network:
                    content_type = next((value for key, value in headers.items() if str(key).lower() == "content-type"), None)
                    media = content_type.split(";", 1)[0].strip().lower() if isinstance(content_type, str) else None
                    if media != "application/octet-stream":
                        raise UnsupportedMediaType("chunk routes require an octet-stream body")
                return None
            raise ValidationError("request body is not declared for this operation")
        if operation.request_required:
            raise ValidationError("request body is required")
        return None
    if body:
        if network:
            content_type = next((value for key, value in headers.items() if str(key).lower() == "content-type"), None)
            media = content_type.split(";", 1)[0].strip().lower() if isinstance(content_type, str) else None
            if media not in operation.request_media_types:
                raise UnsupportedMediaType("JSON routes require Content-Type: application/json")
        if decoded is None:
            try:
                decoded_value = strict_json_loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise ValidationError("request body is not valid JSON") from exc
        else:
            decoded_value = decoded
        if not isinstance(decoded_value, Mapping):
            raise ValidationError("request body must be a JSON object")
    else:
        decoded_value = {}
        if operation.request_required and not (operation.allow_empty_body_with_query_identity and query.get("user_id") and query.get("device_id")):
            # Optional-field internal controls intentionally accept an empty
            # object, while required public DTOs fail closed.
            required = {item.name for item in operation.request_model.fields if item.required}
            if required:
                operation.request_model.validate(decoded_value)
    if network:
        internal_names = {item.name for item in operation.request_model.fields if item.internal}
        if internal_names.intersection(decoded_value):
            raise ValidationError("server time cannot be supplied by a client")
    try:
        operation.request_model.validate(decoded_value, allow_missing_required=not body and operation.allow_empty_body_with_query_identity)
    except ModelValidationError as exc:
        raise ValidationError(str(exc)) from exc
    return dict(decoded_value)


def validate_response(operation: Operation, status: int, headers: Mapping[str, str], payload: Any) -> None:
    """Assert that a handler result remains within its catalog response policy."""

    response = operation.response(status)
    if response.no_body:
        if payload not in (b"", None):
            raise ValueError(f"{operation.operation_id} declared a no-body response")
        return
    header_names = {str(name).lower() for name in headers}
    missing_headers = [name for name in response.headers if name.lower() not in header_names]
    if missing_headers:
        raise ValueError(f"{operation.operation_id} is missing response headers: {', '.join(missing_headers)}")
    content_type = next((str(value).split(";", 1)[0].strip().lower() for name, value in headers.items() if str(name).lower() == "content-type"), None)
    expected_media = response.media_type.lower() if response.media_type else None
    if expected_media and content_type and content_type != expected_media:
        raise ValueError(f"{operation.operation_id} returned an unexpected Content-Type")
    if expected_media and expected_media != "application/json" and not isinstance(payload, bytes):
        raise ValueError(f"{operation.operation_id} declared a binary response")
    if expected_media == "application/json" and isinstance(payload, bytes):
        raise ValueError(f"{operation.operation_id} declared a JSON response")
    if response.schema_name:
        schema = _schema_registry().get(response.schema_name)
        if schema is None:
            raise ValueError(f"{operation.operation_id} references unknown response schema {response.schema_name}")
        _validate_schema_value(schema, payload, path=response.schema_name, registry=_schema_registry())


def _ref(name: str) -> dict[str, str]:
    return {"$ref": f"#/components/schemas/{name}"}


def _scalar(kind: str, *, nullable: bool = False, format: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": kind}
    if format:
        schema["format"] = format
    if nullable:
        schema["nullable"] = True
    return schema


def _array(item: dict[str, Any]) -> dict[str, Any]:
    return {"type": "array", "items": item}


def _object(properties: Mapping[str, Any], *, required: tuple[str, ...] = ()) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "additionalProperties": False, "properties": dict(properties)}
    if required:
        schema["required"] = list(required)
    return schema


_PART_RESPONSE = _object({
    "turn_id": _scalar("string"), "part_id": _scalar("string"), "kind": _scalar("string"), "mime": _scalar("string"),
    "declared_bytes": _scalar("integer", nullable=True), "declared_sha256": _scalar("string", nullable=True),
    "relationship": _scalar("string", nullable=True), "caption_hash": _scalar("string", nullable=True),
    "duration_ms": _scalar("integer", nullable=True), "streaming": _scalar("integer"), "status": _scalar("string"),
    "total_chunks": _scalar("integer", nullable=True), "total_bytes": _scalar("integer", nullable=True),
    "whole_stream_sha256": _scalar("string", nullable=True), "source_available": _scalar("boolean"),
    "source_deleted_at": _scalar("string", nullable=True), "archived_at": _scalar("string", nullable=True),
})
_EVENT = _object({
    "event_id": _scalar("string"), "event_kind": _scalar("string"), "event_version": _scalar("integer"),
    "turn_event_seq": _scalar("integer", nullable=True), "required_device_id": _scalar("string", nullable=True),
    "payload_sha256": _scalar("string"), "outcome": _scalar("string", nullable=True), "error_kind": _scalar("string", nullable=True),
    "created_at": _scalar("string"),
})
_EFFECT_RECEIPT = _object({
    "effect_id": _scalar("string"), "status": _scalar("string"), "job_id": _scalar("string", nullable=True),
    "idempotency_key": _scalar("string", nullable=True), "stage": _scalar("string", nullable=True),
    "outcome": _scalar("string", nullable=True), "state": _scalar("string", nullable=True), "count": _scalar("integer", nullable=True),
}, required=("effect_id", "status"))
_EFFECT_RECEIPT_OR_NULL = {**_EFFECT_RECEIPT, "nullable": True}
_SCALAR_VALUE = {"anyOf": [_scalar("string"), _scalar("integer"), _scalar("number"), _scalar("boolean")]}
_PROVIDER_TARGET = _object({
    "alias": _scalar("string"), "kind": _scalar("string"), "source": _scalar("string"), "retries": _scalar("integer"),
    "timeout_seconds": _scalar("number"), "credential_configured": _scalar("boolean"), "profile": _scalar("string", nullable=True),
    "model": _scalar("string", nullable=True), "voice": _scalar("string", nullable=True), "language": _scalar("string", nullable=True),
    "endpoint_contract": _scalar("string", nullable=True), "fallback_of": _scalar("string", nullable=True),
    "health_path": _scalar("string", nullable=True), "capability_path": _scalar("string", nullable=True), "endpoint": _scalar("string", nullable=True),
    "output_format": _scalar("string", nullable=True), "rate": _scalar("number", nullable=True), "pitch": _scalar("number", nullable=True),
    "volume": _scalar("number", nullable=True), "credential_ref_sha256": _scalar("string", nullable=True),
    "priority": _scalar("integer", nullable=True), "max_bytes": _scalar("integer", nullable=True),
    "media_types": _array(_scalar("string")), "options": {"type": "object", "additionalProperties": _SCALAR_VALUE},
})
_PROVIDER_CHAIN = _object({
    "version": _scalar("integer"), "kind": _scalar("string"), "generation": _scalar("string"), "fingerprint": _scalar("string"),
    "overall_deadline_seconds": _scalar("number"), "targets": _array(_PROVIDER_TARGET),
})
_WORKER_PAYLOAD = {
    "oneOf": [
        _object({"turn_id": _scalar("string"), "user_id": _scalar("string", nullable=True), "artifact_id": _scalar("string", nullable=True)}, required=("turn_id",)),
        _object({"turn_id": _scalar("string"), "session_id": _scalar("string"), "hermes_submission_id": _scalar("string")}, required=("turn_id", "session_id", "hermes_submission_id")),
        _object({"session_id": _scalar("string"), "segment_sequence": _scalar("integer"), "segment_sha256": _scalar("string")}, required=("session_id", "segment_sequence", "segment_sha256")),
    ]
}
_EVENT_PAYLOAD = {
    "oneOf": [
        _object({"type": _scalar("string"), "turn_id": _scalar("string"), "accepted_seq": _scalar("integer"), "initial_fingerprint": _scalar("string")}, required=("type", "turn_id", "accepted_seq", "initial_fingerprint")),
        _object({"type": _scalar("string"), "turn_id": _scalar("string"), "route_decision_id": _scalar("string"), "project_id": _scalar("string", nullable=True), "session_key": _scalar("string", nullable=True), "project_record_version": _scalar("integer", nullable=True), "text": _scalar("string", nullable=True), "decision_reason_code": _scalar("string", nullable=True)}, required=("type", "turn_id", "route_decision_id")),
        _object({"type": _scalar("string"), "turn_id": _scalar("string"), "event_version": _scalar("integer"), "text": _scalar("string", nullable=True), "outcome": _scalar("string"), "error_kind": _scalar("string", nullable=True), "source": _scalar("string", nullable=True), "source_ref": _scalar("string", nullable=True), "recovered_from_error": _scalar("boolean", nullable=True)}, required=("type", "turn_id", "event_version", "outcome")),
    ]
}
_OUTBOX_ITEM = _object({
    "outbox_id": _scalar("string"), "event_id": _scalar("string"), "turn_id": _scalar("string"),
    "event_kind": _scalar("string"), "event_version": _scalar("integer"), "turn_event_seq": _scalar("integer"),
    "state": _scalar("string"), "required_device_id": _scalar("string", nullable=True), "payload_sha256": _scalar("string"),
    "payload": _EVENT_PAYLOAD, "created_at": _scalar("string"), "acknowledged_at": _scalar("string", nullable=True),
})
_TTS_ARTIFACT = _object({
    "artifact_id": _scalar("string"), "turn_id": _scalar("string"), "event_id": _scalar("string", nullable=True),
    "event_kind": _scalar("string", nullable=True), "artifact_version": _scalar("integer"), "output_kind": _scalar("string"),
    "origin_device_id": _scalar("string", nullable=True), "delivery_target_device_id": _scalar("string", nullable=True),
    "payload_sha256": _scalar("string", nullable=True), "byte_size": _scalar("integer", nullable=True),
    "content_type": _scalar("string", nullable=True), "provider_name": _scalar("string", nullable=True),
    "expires_at": _scalar("string", nullable=True), "relay_state": _scalar("string", nullable=True),
    "playback_ack_at": _scalar("string", nullable=True), "retention_outcome": _scalar("string", nullable=True),
    "status": _scalar("string"), "mode": _scalar("string", nullable=True), "delivery_seq": _scalar("integer", nullable=True),
    "created_at": _scalar("string", nullable=True), "updated_at": _scalar("string", nullable=True), "played_at": _scalar("string", nullable=True),
})
_ASR_ATTEMPT = _object({
    "attempt_id": _scalar("string"), "generation": _scalar("integer"), "stage": _scalar("string"),
    "outcome": _scalar("string", nullable=True), "detail": _scalar("string", nullable=True),
    "transcript": _scalar("string", nullable=True), "committed_at": _scalar("string", nullable=True),
})
_HERMES_RESULT_REF = _object({
    "attempt_seq": _scalar("integer"), "assistant_message_id": _scalar("string", nullable=True),
    "content_hash": _scalar("string", nullable=True), "source": _scalar("string", nullable=True), "committed_at": _scalar("string", nullable=True),
})
_FINAL_VERSION_REF = _object({
    "event_version": _scalar("integer"), "source": _scalar("string", nullable=True), "outcome": _scalar("string", nullable=True),
    "error_kind": _scalar("string", nullable=True), "source_ref": _scalar("string", nullable=True),
    "content_hash": _scalar("string", nullable=True), "combined_content_hash": _scalar("string", nullable=True), "committed_at": _scalar("string", nullable=True),
})
_TURN_MANIFEST = _object({
    "schema_version": _scalar("integer"), "user_id": _scalar("string"), "turn_id": _scalar("string"),
    "origin_device_id": _scalar("string"), "client_created_at": _scalar("string"), "current_project_number": _scalar("string", nullable=True),
    "prefer_current_project": _scalar("boolean"), "parts": _array(_ref("TurnPart")),
})
_TURN = _object({
    "turn_id": _scalar("string"), "user_id": _scalar("string"), "origin_device_id": _scalar("string"), "delivery_target_device_id": _scalar("string", nullable=True),
    "client_created_at": _scalar("string"), "created_at": _scalar("string"), "updated_at": _scalar("string"), "state": _scalar("string"),
    "turn_source": _scalar("string"), "project_id": _scalar("string", nullable=True), "session_key": _scalar("string", nullable=True),
    "current_project_number": _scalar("string", nullable=True), "prefer_current_project": _scalar("integer"), "initial_fingerprint": _scalar("string"),
    "manifest": _TURN_MANIFEST, "parts": _array(_PART_RESPONSE), "events": _array(_EVENT), "outbox": _array(_OUTBOX_ITEM),
    "tts_artifacts": _array(_TTS_ARTIFACT), "asr_attempts": _array(_ASR_ATTEMPT), "hermes_result_refs": _array(_HERMES_RESULT_REF), "final_version_refs": _array(_FINAL_VERSION_REF),
    "transcript": _scalar("string", nullable=True), "final_content": _scalar("string", nullable=True), "final_combined_hash": _scalar("string", nullable=True),
    "final_event_version": _scalar("integer", nullable=True), "accepted_seq": _scalar("integer", nullable=True), "final_outcome": _scalar("string", nullable=True),
    "final_error_kind": _scalar("string", nullable=True), "asr_generation": _scalar("integer"), "asr_stage": _scalar("string"),
    "authoritative_asr_outcome": _scalar("string", nullable=True), "archived_at": _scalar("string", nullable=True), "fired_at": _scalar("string", nullable=True),
    "grace_until": _scalar("string", nullable=True), "parent_turn_id": _scalar("string", nullable=True), "previous_turn_id": _scalar("string", nullable=True),
    "previous_turn_origin_device_id": _scalar("string", nullable=True), "route_decision_id": _scalar("string", nullable=True), "schedule_id": _scalar("string", nullable=True),
    "scheduled_for": _scalar("string", nullable=True), "trigger_instance_id": _scalar("string", nullable=True), "source_deleted": _scalar("integer"),
    "turn_event_seq": _scalar("integer"),
})
_PROJECT = _object({
    "stable_project_id": _scalar("string"), "user_id": _scalar("string"), "project_number": _scalar("string"), "name": _scalar("string"),
    "aliases": _array(_scalar("string")), "description": _scalar("string"), "default_session_key": _scalar("string"), "status": _scalar("string"),
    "record_version": _scalar("integer"), "created_at": _scalar("string"), "updated_at": _scalar("string"), "archived_at": _scalar("string", nullable=True),
})
_EAVESDROP_SEGMENT_ITEM = _object({
    "session_id": _scalar("string"), "sequence": _scalar("integer"), "client_segment_id": _scalar("string"),
    "audio_sha256": _scalar("string"), "byte_length": _scalar("integer"), "transcript": _scalar("string", nullable=True), "created_at": _scalar("string"),
})
_EAVESDROP_REPLY_ITEM = _object({
    "reply_id": _scalar("string"), "session_id": _scalar("string"), "segment_sequence": _scalar("integer"),
    "text_hash": _scalar("string"), "reply_text": _scalar("string"), "tts_requested": _scalar("integer"), "hermes_requested": _scalar("integer"), "created_at": _scalar("string"),
})
_EAVESDROP_DECISION_ITEM = _object({
    "decision_id": _scalar("string"), "session_id": _scalar("string"), "segment_sequence": _scalar("integer"),
    "decision": _scalar("string"), "reason": _scalar("string"), "project_id": _scalar("string", nullable=True),
    "gateway_session_key": _scalar("string", nullable=True), "hermes_submission_id": _scalar("string", nullable=True), "policy_version": _scalar("string", nullable=True),
    "covered_start_sequence": _scalar("integer", nullable=True), "covered_end_sequence": _scalar("integer", nullable=True), "dedupe_key": _scalar("string", nullable=True),
    "result_state": _scalar("string"), "effect_receipt_json": _EFFECT_RECEIPT_OR_NULL,
    "gateway_profile": _scalar("string", nullable=True), "created_at": _scalar("string"),
})
_EAVESDROP = _object({
    "session_id": _scalar("string"), "user_id": _scalar("string"), "phone_device_id": _scalar("string"), "watch_device_id": _scalar("string", nullable=True),
    "project_id": _scalar("string", nullable=True), "state": _scalar("string"), "routing_mode": _scalar("string"), "provenance": _scalar("string"),
    "response_enabled": _scalar("boolean"), "tts_enabled": _scalar("boolean"), "hermes_enabled": _scalar("boolean"), "idempotency_key": _scalar("string", nullable=True),
    "accumulated_transcript": _scalar("string"), "next_sequence": _scalar("integer"), "created_at": _scalar("string"), "updated_at": _scalar("string"),
    "expires_at": _scalar("string"), "stopped_at": _scalar("string", nullable=True), "failure_kind": _scalar("string", nullable=True),
    "segments": _array(_EAVESDROP_SEGMENT_ITEM), "replies": _array(_EAVESDROP_REPLY_ITEM), "routing_decisions": _array(_EAVESDROP_DECISION_ITEM),
})
_DIAGNOSTIC_EVENT_ITEM = _object({
    "type": _scalar("string"), "event_id": _scalar("string"), "category": _scalar("string"), "stage": _scalar("string"),
    "metadata": _ref("DiagnosticMetadata"), "occurred_at": _scalar("string"), "retention_deadline": _scalar("string"),
}, required=("type", "event_id", "category", "stage", "metadata", "occurred_at", "retention_deadline"))
_DIAGNOSTIC_BUNDLE_ITEM = _object({
    "type": _scalar("string"), "bundle_id": _scalar("string"), "compressed_size": _scalar("integer"), "expanded_size": _scalar("integer"),
    "created_at": _scalar("string"), "retention_deadline": _scalar("string"),
}, required=("type", "bundle_id", "compressed_size", "expanded_size", "created_at", "retention_deadline"))
_DIAGNOSTIC = {"oneOf": [_DIAGNOSTIC_EVENT_ITEM, _DIAGNOSTIC_BUNDLE_ITEM]}
_TOMBSTONE = _object({
    "entity_type": _scalar("string"), "entity_id": _scalar("string"), "deleted_at": _scalar("string"),
    "tombstone_id": _scalar("string", nullable=True), "subject_kind": _scalar("string", nullable=True), "subject_id": _scalar("string", nullable=True),
    "retention_deadline": _scalar("string", nullable=True),
})
_WORKER_JOB = _object({
    "job_id": _scalar("string"), "idempotency_key": _scalar("string"), "kind": _scalar("string"), "stage": _scalar("string"),
    "payload_sha256": _scalar("string"), "chain_generation": _scalar("string", nullable=True), "chain_fingerprint": _scalar("string", nullable=True),
    "overall_deadline_at": _scalar("string", nullable=True), "status": _scalar("string"), "owner": _scalar("string", nullable=True),
    "lease_token": _scalar("string", nullable=True), "lease_expires_at": _scalar("string", nullable=True), "next_attempt_at": _scalar("string", nullable=True),
    "attempt_count": _scalar("integer"), "max_attempts": _scalar("integer"), "last_error_kind": _scalar("string", nullable=True),
    "last_error_status_code": _scalar("integer", nullable=True), "effect_receipt": _EFFECT_RECEIPT_OR_NULL, "effect_receipt_sha256": _scalar("string", nullable=True),
    "created_at": _scalar("string"), "updated_at": _scalar("string"), "completed_at": _scalar("string", nullable=True),
    "payload": _WORKER_PAYLOAD, "provider_chain": {**_PROVIDER_CHAIN, "nullable": True},
})
_SCHEDULED_DELIVERY = _object({
    "schedule_id": _scalar("string"), "trigger_instance_id": _scalar("string"), "turn_id": _scalar("string"),
    "event_id": _scalar("string", nullable=True), "artifact_id": _scalar("string", nullable=True), "turn": _TURN,
})
_SCHEDULE_OCCURRENCE = _object({
    "trigger_instance_id": _scalar("string"), "schedule_id": _scalar("string"), "scheduled_for": _scalar("string"),
    "state": _scalar("string"), "turn_id": _scalar("string", nullable=True), "event_id": _scalar("string", nullable=True),
    "artifact_id": _scalar("string", nullable=True), "attempts": _scalar("integer"), "last_error": _scalar("string", nullable=True),
    "created_at": _scalar("string"), "updated_at": _scalar("string"),
})
_OPENAPI_SCHEMA_NODE_REF = _ref("OpenAPISchemaNode")
_OPENAPI_SCHEMA_NODE = _object({
    "$ref": _scalar("string", nullable=True), "type": _scalar("string", nullable=True), "format": _scalar("string", nullable=True),
    "title": _scalar("string", nullable=True), "description": _scalar("string", nullable=True), "nullable": _scalar("boolean", nullable=True),
    "deprecated": _scalar("boolean", nullable=True), "readOnly": _scalar("boolean", nullable=True), "writeOnly": _scalar("boolean", nullable=True),
    "minLength": _scalar("integer", nullable=True), "maxLength": _scalar("integer", nullable=True), "pattern": _scalar("string", nullable=True),
    "minimum": _scalar("number", nullable=True), "maximum": _scalar("number", nullable=True),
    "enum": _array(_SCALAR_VALUE), "required": _array(_scalar("string")),
    "properties": {"type": "object", "additionalProperties": _OPENAPI_SCHEMA_NODE_REF},
    "items": _OPENAPI_SCHEMA_NODE_REF, "oneOf": _array(_OPENAPI_SCHEMA_NODE_REF), "anyOf": _array(_OPENAPI_SCHEMA_NODE_REF),
    "allOf": _array(_OPENAPI_SCHEMA_NODE_REF), "additionalProperties": {"oneOf": [_scalar("boolean"), _OPENAPI_SCHEMA_NODE_REF]},
})
_OPENAPI_MEDIA = _object({"schema": _OPENAPI_SCHEMA_NODE})
_OPENAPI_PARAMETER_REF = _object({"$ref": _scalar("string")}, required=("$ref",))
_OPENAPI_PARAMETER = _object({
    "name": _scalar("string"), "in": _scalar("string"), "required": _scalar("boolean"), "schema": _OPENAPI_SCHEMA_NODE,
})
_OPENAPI_HEADER = _object({"schema": _OPENAPI_SCHEMA_NODE}, required=("schema",))
_OPENAPI_RESPONSE = _object({
    "description": _scalar("string"), "content": {"type": "object", "additionalProperties": _OPENAPI_MEDIA},
    "headers": {"type": "object", "additionalProperties": _OPENAPI_HEADER}, "x-no-body": _scalar("boolean", nullable=True),
})
_OPENAPI_REQUEST_BODY = _object({
    "required": _scalar("boolean"), "content": {"type": "object", "additionalProperties": _OPENAPI_MEDIA},
})
_OPENAPI_OPERATION = _object({
    "operationId": _scalar("string"), "x-handler-key": _scalar("string"), "parameters": _array(_OPENAPI_PARAMETER_REF),
    "requestBody": {**_OPENAPI_REQUEST_BODY, "nullable": True},
    "security": _array({"type": "object", "additionalProperties": _array(_scalar("string"))}),
    "deprecated": _scalar("boolean", nullable=True), "responses": {"type": "object", "additionalProperties": _OPENAPI_RESPONSE},
})
_OPENAPI_PATH_ITEM = _object({
    "get": _OPENAPI_OPERATION, "post": _OPENAPI_OPERATION, "put": _OPENAPI_OPERATION, "patch": _OPENAPI_OPERATION,
    "delete": _OPENAPI_OPERATION, "head": _OPENAPI_OPERATION, "options": _OPENAPI_OPERATION, "trace": _OPENAPI_OPERATION,
})
_OPENAPI_SECURITY_SCHEME = _object({
    "type": _scalar("string"), "in": _scalar("string", nullable=True), "name": _scalar("string", nullable=True),
    "description": _scalar("string", nullable=True),
})
_OPENAPI_COMPONENTS = _object({
    "securitySchemes": {"type": "object", "additionalProperties": _OPENAPI_SECURITY_SCHEME},
    "parameters": {"type": "object", "additionalProperties": _OPENAPI_PARAMETER},
    "schemas": {"type": "object", "additionalProperties": _OPENAPI_SCHEMA_NODE},
})
_OPENAPI_DOCUMENT = _object({
    "openapi": _scalar("string"), "info": _object({"title": _scalar("string"), "version": _scalar("string"), "description": _scalar("string")}, required=("title", "version", "description")),
    "servers": _array(_object({"url": _scalar("string")}, required=("url",))),
    "paths": {"type": "object", "additionalProperties": _OPENAPI_PATH_ITEM}, "components": _OPENAPI_COMPONENTS,
}, required=("openapi", "info", "servers", "paths", "components"))
_RESPONSE_SCHEMAS: dict[str, dict[str, Any]] = {
    "Error": _object({"error": _object({"code": _scalar("string"), "message": _scalar("string")}, required=("code", "message"))}, required=("error",)),
    "HealthResponse": _object({"status": _scalar("string"), "product_identity": _scalar("string"), "api_version": _scalar("string"), "worker": _ref("WorkerHealth")}),
    "OpenAPIDocument": _OPENAPI_DOCUMENT, "OpenAPISchemaNode": _OPENAPI_SCHEMA_NODE,
    "DeviceResponse": _object({"user_id": _scalar("string"), "device_id": _scalar("string"), "kind": _scalar("string"), "status": _scalar("string"), "created_at": _scalar("string"), "revoked_at": _scalar("string", nullable=True)}),
    "TurnResponse": _TURN, "TurnPartResponse": _PART_RESPONSE,
    "ChunkReceipt": _object({"turn_id": _scalar("string"), "part_id": _scalar("string"), "sequence": _scalar("integer"), "byte_length": _scalar("integer"), "sha256": _scalar("string"), "storage_path": _scalar("string"), "received_at": _scalar("string"), "duplicate": _scalar("boolean")}),
    "MissingSequencePage": _object({"missing": _array(_scalar("integer")), "complete": _scalar("boolean"), "total_missing": _scalar("integer"), "offset": _scalar("integer"), "limit": _scalar("integer"), "next_offset": _scalar("integer", nullable=True), "encoding": _scalar("string"), "source_available": _scalar("boolean")}),
    "EventAckResponse": _object({"event_id": _scalar("string", nullable=True), "state": _scalar("string", nullable=True), "turn_id": _scalar("string", nullable=True), "outbox": _array(_OUTBOX_ITEM), "payload_sha256": _scalar("string", nullable=True)}),
    "OutboxResponse": _object({"items": _array(_OUTBOX_ITEM)}),
    "TTSResponse": _object({"artifact_id": _scalar("string"), "turn_id": _scalar("string"), "event_id": _scalar("string", nullable=True), "artifact_version": _scalar("integer"), "output_kind": _scalar("string"), "status": _scalar("string"), "payload_sha256": _scalar("string"), "delivery_target_device_id": _scalar("string", nullable=True), "content_type": _scalar("string", nullable=True), "byte_length": _scalar("integer", nullable=True), "audio_base64": _scalar("string"), "created_at": _scalar("string", nullable=True), "expires_at": _scalar("string", nullable=True), "played_at": _scalar("string", nullable=True), "relay_received_at": _scalar("string", nullable=True)}),
    "PlaybackAckResponse": _object({"artifact_id": _scalar("string"), "status": _scalar("string"), "played_at": _scalar("string", nullable=True)}), "RelayReceivedResponse": _object({"artifact_id": _scalar("string"), "status": _scalar("string"), "relay_received_at": _scalar("string", nullable=True)}),
    "ProjectResponse": _PROJECT, "ProjectListResponse": _object({"items": _array(_PROJECT)}),
    "ScheduleResponse": _object({"schedule_id": _scalar("string"), "state": _scalar("string"), "parent_turn_id": _scalar("string"), "project_id": _scalar("string"), "session_key": _scalar("string"), "origin_device_id": _scalar("string"), "delivery_target_device_id": _scalar("string"), "fire_at_utc": _scalar("string"), "timezone_offset": _scalar("string"), "reminder_text": _scalar("string"), "confirmation_text": _scalar("string"), "trigger_instance_id": _scalar("string", nullable=True), "confirmation_event_id": _scalar("string", nullable=True), "occurrences": _array(_SCHEDULE_OCCURRENCE), "created_at": _scalar("string", nullable=True), "updated_at": _scalar("string", nullable=True)}),
    "UpdateManifestResponse": _object({"schema_version": _scalar("integer"), "platform": _scalar("string"), "channel": _scalar("string"), "version": _scalar("string"), "version_code": _scalar("integer", nullable=True), "version_name": _scalar("string", nullable=True), "sha256": _scalar("string"), "artifact_sha256": _scalar("string", nullable=True), "signer_digest": _scalar("string"), "changelog": _scalar("string"), "min_server_version": _scalar("string"), "min_supported_version": _scalar("integer", nullable=True), "authorization_policy": _scalar("string"), "content_type": _scalar("string"), "download_path": _scalar("string"), "manifest_sha256": _scalar("string"), "current": _scalar("boolean"), "channel_generation": _scalar("integer", nullable=True), "generation": _scalar("integer", nullable=True), "artifact_name": _scalar("string", nullable=True), "size": _scalar("integer", nullable=True), "etag": _scalar("string", nullable=True), "published_at": _scalar("string", nullable=True), "current_generation": _scalar("integer", nullable=True)}),
    "BinaryBody": {"type": "string", "format": "binary"}, "HistoryResponse": _object({"items": _array(_object({"type": _scalar("string"), "turn_id": _scalar("string"), "project_id": _scalar("string", nullable=True), "message_id": _scalar("string"), "role": _scalar("string"), "content": _scalar("string", nullable=True), "content_hash": _scalar("string", nullable=True), "created_at": _scalar("string"), "accepted_seq": _scalar("integer", nullable=True), "archived": _scalar("boolean") })), "next_cursor": _scalar("string", nullable=True), "accepted_seq": _scalar("integer", nullable=True), "truncated": _scalar("boolean", nullable=True)}),
    "EavesdropSessionResponse": _EAVESDROP, "EavesdropSegmentResponse": _object({"session_id": _scalar("string", nullable=True), "sequence": _scalar("integer"), "client_segment_id": _scalar("string", nullable=True), "sha256": _scalar("string"), "audio_sha256": _scalar("string", nullable=True), "byte_length": _scalar("integer"), "duplicate": _scalar("boolean"), "state": _scalar("string", nullable=True), "stored": _scalar("boolean", nullable=True), "transcript": _scalar("string", nullable=True), "reply_text": _scalar("string", nullable=True)}),
    "EavesdropRepliesResponse": _object({"items": _array(_EAVESDROP_REPLY_ITEM)}), "RoutingDecisionResponse": _EAVESDROP_DECISION_ITEM, "RoutingDecisionsResponse": _object({"items": _array(_EAVESDROP_DECISION_ITEM)}),
    "DiagnosticsConsentResponse": _object({"event_id": _scalar("string"), "user_id": _scalar("string"), "device_id": _scalar("string"), "enabled": _scalar("boolean"), "expires_at": _scalar("string", nullable=True), "created_at": _scalar("string")}), "DiagnosticEventResponse": _DIAGNOSTIC_EVENT_ITEM, "DiagnosticBundleResponse": _DIAGNOSTIC_BUNDLE_ITEM, "DiagnosticListResponse": _object({"items": _array(_DIAGNOSTIC), "has_more": _scalar("boolean")}), "DiagnosticExportResponse": _object({"schema_version": _scalar("integer"), "items": _array(_DIAGNOSTIC), "tombstones": _array(_TOMBSTONE), "next_cursor": _scalar("string", nullable=True), "truncated": _scalar("boolean")}), "DeletionReceipt": _object({"events": _scalar("integer"), "bundles": _scalar("integer"), "tombstones": _scalar("integer")}),
    "WorkerHealth": _object({"as_of": _scalar("string"), "bounded": _scalar("boolean"), "counts": _object({"CLAIMED": _scalar("integer"), "FAILED_PERMANENT": _scalar("integer"), "PENDING": _scalar("integer"), "RETRY_WAIT": _scalar("integer"), "SUCCEEDED": _scalar("integer")}), "due": _scalar("integer"), "expired_deadlines": _scalar("integer"), "expired_leases": _scalar("integer"), "leased": _scalar("integer")}), "WorkerReceipt": _EFFECT_RECEIPT, "WorkerClaimResponse": _object({"job": {**_WORKER_JOB, "nullable": True}}), "WorkerRecoveryResponse": _object({"requeued": _scalar("integer"), "failed": _scalar("integer")}), "WorkerMutationResponse": _WORKER_JOB, "WorkerRunResponse": _object({"job": {**_WORKER_JOB, "nullable": True}}), "SchedulerFireResponse": _object({"items": _array(_SCHEDULED_DELIVERY)}), "SchedulerRecoveryResponse": _object({"requeued": _scalar("integer"), "failed": _scalar("integer")}),
}


def _schema_registry() -> dict[str, dict[str, Any]]:
    registry = {model.name: model.openapi_schema() for model in REQUEST_MODELS}
    registry.update(_RESPONSE_SCHEMAS)
    return registry


def _resolve_schema(schema: Mapping[str, Any], registry: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
    reference = schema.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/components/schemas/"):
        name = reference.rsplit("/", 1)[-1]
        try:
            return registry[name]
        except KeyError as exc:
            raise ValueError(f"unknown response schema {name}") from exc
    return schema


def _schema_type_matches(schema_type: str, value: Any) -> bool:
    if schema_type == "object":
        return isinstance(value, Mapping)
    if schema_type == "array":
        return isinstance(value, list)
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if schema_type == "boolean":
        return isinstance(value, bool)
    return True


def _validate_schema_value(schema: Mapping[str, Any], value: Any, *, path: str, registry: Mapping[str, Mapping[str, Any]]) -> None:
    schema = _resolve_schema(schema, registry)
    if value is None:
        if schema.get("nullable"):
            return
        raise ValueError(f"{path} must not be null")
    alternatives = schema.get("oneOf")
    if isinstance(alternatives, list):
        errors: list[str] = []
        matches = 0
        for index, candidate in enumerate(alternatives):
            try:
                _validate_schema_value(candidate, value, path=path, registry=registry)
            except ValueError as exc:
                errors.append(f"option {index}: {exc}")
            else:
                matches += 1
        if matches != 1:
            detail = "; ".join(errors[:2])
            raise ValueError(f"{path} does not match exactly one schema ({detail})")
        return
    any_alternatives = schema.get("anyOf")
    if isinstance(any_alternatives, list):
        for candidate in any_alternatives:
            try:
                _validate_schema_value(candidate, value, path=path, registry=registry)
            except ValueError:
                continue
            else:
                return
        raise ValueError(f"{path} does not match any schema")
    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not _schema_type_matches(expected_type, value):
        raise ValueError(f"{path} must be {expected_type}")
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        raise ValueError(f"{path} has an unsupported value")
    if expected_type == "object":
        assert isinstance(value, Mapping)
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            properties = {}
        if schema.get("additionalProperties") is False:
            unknown = sorted(str(key) for key in value if key not in properties)
            if unknown:
                raise ValueError(f"{path} contains undeclared fields: {', '.join(unknown)}")
        required = schema.get("required", [])
        if isinstance(required, list):
            missing = [name for name in required if name not in value]
            if missing:
                raise ValueError(f"{path} is missing required fields: {', '.join(missing)}")
        for key, child_schema in properties.items():
            if key in value and isinstance(child_schema, Mapping):
                _validate_schema_value(child_schema, value[key], path=f"{path}.{key}", registry=registry)
        additional = schema.get("additionalProperties")
        if isinstance(additional, Mapping):
            for key, child in value.items():
                if key not in properties:
                    _validate_schema_value(additional, child, path=f"{path}.{key}", registry=registry)
    elif expected_type == "array":
        assert isinstance(value, list)
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate_schema_value(item_schema, item, path=f"{path}[{index}]", registry=registry)


def _project_schema_value(schema: Mapping[str, Any], value: Any, *, registry: Mapping[str, Mapping[str, Any]]) -> Any:
    schema = _resolve_schema(schema, registry)
    if value is None:
        return None
    alternatives = schema.get("oneOf")
    if isinstance(alternatives, list):
        if isinstance(value, Mapping):
            required_matches = [
                candidate
                for candidate in alternatives
                if isinstance(candidate, Mapping)
                and all(name in value for name in candidate.get("required", []))
            ]
            if required_matches:
                return _project_schema_value(required_matches[0], value, registry=registry)
        return _project_schema_value(alternatives[0], value, registry=registry)
    any_alternatives = schema.get("anyOf")
    if isinstance(any_alternatives, list):
        for candidate in any_alternatives:
            try:
                _validate_schema_value(candidate, value, path="value", registry=registry)
            except ValueError:
                continue
            return _project_schema_value(candidate, value, registry=registry)
        return copy.deepcopy(value)
    expected_type = schema.get("type")
    if expected_type == "object" and isinstance(value, Mapping):
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            properties = {}
        projected = {
            key: _project_schema_value(child_schema, value[key], registry=registry)
            for key, child_schema in properties.items()
            if key in value and isinstance(child_schema, Mapping)
        }
        additional = schema.get("additionalProperties")
        if additional is True:
            for key, item in value.items():
                if key not in projected:
                    projected[copy.deepcopy(key)] = copy.deepcopy(item)
        elif isinstance(additional, Mapping):
            for key, item in value.items():
                if key not in projected:
                    projected[copy.deepcopy(key)] = _project_schema_value(additional, item, registry=registry)
        return projected
    if expected_type == "array" and isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            return [_project_schema_value(item_schema, item, registry=registry) for item in value]
    return copy.deepcopy(value)


def project_response(operation: Operation, status: int, payload: Any) -> Any:
    """Return a fresh response DTO containing only catalog-declared fields."""

    response = operation.response(status)
    if response.no_body or response.schema_name is None:
        return b"" if response.no_body else copy.deepcopy(payload)
    schema = _schema_registry().get(response.schema_name)
    if schema is None:
        raise ValueError(f"unknown response schema {response.schema_name}")
    return _project_schema_value(schema, payload, registry=_schema_registry())


def response_schemas() -> dict[str, dict[str, Any]]:
    """Return a fresh copy of response schemas for OpenAPI generation."""

    return copy.deepcopy(_RESPONSE_SCHEMAS)


def _parameter_component_name(parameter: Parameter) -> str:
    names = {
        ("header", "X-Recorder-Principal-User"): "PrincipalUserHeader", ("header", "X-Recorder-Principal-Device"): "PrincipalDeviceHeader", ("header", "X-Recorder-Principal-Signature"): "PrincipalSignatureHeader",
        ("header", "X-Recorder-User-ID"): "LegacyUserHeader", ("header", "X-Recorder-Device-ID"): "LegacyDeviceHeader", ("header", "X-Chunk-SHA256"): "ChunkSha256Header",
        ("header", "X-Recorder-Internal-Trusted"): "InternalTrustedHeader", ("header", "If-None-Match"): "IfNoneMatchHeader", ("header", "If-Range"): "IfRangeHeader", ("header", "Range"): "RangeHeader",
    }
    if (parameter.location, parameter.name) in names:
        return names[(parameter.location, parameter.name)]
    location = {"path": "Path", "query": "Query", "header": "Header"}[parameter.location]
    return parameter.name.replace("_", " ").title().replace(" ", "") + location


def _component_parameters() -> dict[str, dict[str, Any]]:
    parameters: dict[str, dict[str, Any]] = {}
    for operation in _OPERATIONS:
        for parameter in operation.parameters:
            if parameter.internal:
                continue
            name = _parameter_component_name(parameter)
            value: dict[str, Any] = {"name": parameter.name, "in": parameter.location, "required": parameter.required, "schema": parameter.openapi_schema()}
            parameters.setdefault(name, value)
    return parameters


def _operation_document(operation: Operation) -> dict[str, Any]:
    document: dict[str, Any] = {"operationId": operation.operation_id, "x-handler-key": operation.handler_key, "responses": {}}
    public_parameters = [item for item in operation.parameters if not item.internal]
    if public_parameters:
        document["parameters"] = [{"$ref": f"#/components/parameters/{_parameter_component_name(item)}"} for item in public_parameters]
    if operation.request_media_types:
        schema_name = operation.request_model.name if operation.request_model else "ChunkUpload"
        document["requestBody"] = {
            "required": operation.request_required,
            "content": {media: {"schema": {"$ref": f"#/components/schemas/{schema_name}"}} for media in operation.request_media_types},
        }
    if operation.principal_policy == "principal":
        document["security"] = [{"RecorderPrincipal": []}]
    if operation.deprecated:
        document["deprecated"] = True
    for response in operation.responses:
        value: dict[str, Any] = {"description": response.description}
        if response.no_body:
            value["x-no-body"] = True
        elif response.schema_name is not None:
            value["content"] = {response.media_type or "application/json": {"schema": _ref(response.schema_name)}}
        if response.headers:
            value["headers"] = {name: {"schema": {"type": "string"}} for name in response.headers}
        document["responses"][response.status_text] = value
    return document


def build_openapi_document() -> dict[str, Any]:
    """Project the authoritative catalog into a deterministic OpenAPI map."""

    paths: dict[str, dict[str, Any]] = {}
    for operation in _OPERATIONS:
        paths.setdefault(operation.path_template, {})[operation.method.lower()] = _operation_document(operation)
    schemas = {model.name: model.openapi_schema() for model in REQUEST_MODELS}
    schemas.update(response_schemas())
    schemas["ChunkUpload"] = {"type": "string", "format": "binary"}
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Recorder Next Server",
            "version": "1.0.0",
            "description": "Standalone reliable Recorder adapter; Hermes core and legacy port 5000 are out of scope.",
        },
        "servers": [{"url": "/"}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "RecorderPrincipal": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Recorder-Principal-Signature",
                    "description": "HMAC-SHA256 proof over X-Recorder-Principal-User, a NUL byte, and X-Recorder-Principal-Device.",
                }
            },
            "parameters": _component_parameters(),
            "schemas": schemas,
        },
    }


def validate_openapi_contract(document: Mapping[str, Any] | None = None) -> None:
    """Reject route, response, or schema drift from the authoritative catalog."""

    expected = build_openapi_document()
    actual = OPENAPI if document is None else document
    if actual != expected:
        raise ValueError("OpenAPI document does not match the authoritative operation catalog")


def operation_coverage() -> dict[str, Any]:
    return {
        "schema": "recorder-next-operation-coverage/v1",
        "operations": [
            {
                "method": operation.method,
                "path": operation.path_template,
                "operation_id": operation.operation_id,
                "handler_key": operation.handler_key,
                "request": {"required": operation.request_required, "media_types": list(operation.request_media_types), "schema": operation.request_model.name if operation.request_model else None},
                "responses": [{"status": item.status, "body": "none" if item.no_body else item.schema_name, "media_type": item.media_type, "headers": list(item.headers)} for item in operation.responses],
            }
            for operation in _OPERATIONS
        ],
    }


def operation_catalog_fingerprint() -> str:
    payload = json.dumps(operation_coverage(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


OPENAPI = build_openapi_document()


__all__ = [
    "OPENAPI", "Operation", "Parameter", "ResponseSpec", "build_openapi_document", "match_operation", "operation_catalog_fingerprint",
    "operation_coverage", "project_response", "response_schemas", "route_catalog", "validate_openapi_contract", "validate_request", "validate_response",
]