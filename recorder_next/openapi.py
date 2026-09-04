"""Machine-readable Recorder Next v1 HTTP contract."""

import re

OPENAPI = {
    "openapi": "3.0.3",
    "info": {
        "title": "Recorder Next Server",
        "version": "1.0.0",
        "description": "Standalone reliable Recorder adapter; Hermes core and legacy port 5000 are out of scope.",
    },
    "servers": [{"url": "/"}],
    "paths": {
        "/v1/health": {"get": {"responses": {"200": {"description": "Readiness"}}}},
        "/v1/openapi.json": {"get": {"responses": {"200": {"description": "This contract"}}}},
        "/v1/devices": {"post": {"responses": {"201": {"description": "Registered device"}}}},
        "/v1/devices/{device_id}/revoke": {"post": {"responses": {"200": {"description": "Revoked device"}}}},
        "/v1/turns": {
            "post": {
                "summary": "Create an immutable turn envelope or complete a text turn",
                "responses": {"201": {"description": "Receiving turn"}, "202": {"description": "Accepted text turn"}, "409": {"description": "TURN_ID_CONFLICT"}},
            }
        },
        "/v1/turns/{turn_id}": {"get": {"parameters": [{"$ref": "#/components/parameters/TurnId"}], "responses": {"200": {"description": "Turn ledger"}}}},
        "/v1/turns/{turn_id}/accept": {"post": {"responses": {"200": {"description": "Durable ACCEPTED"}, "409": {"description": "Incomplete parts"}}}},
        "/v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}": {"put": {"responses": {"200": {"description": "Chunk receipt"}, "409": {"description": "Chunk conflict"}}}},
        "/v1/turns/{turn_id}/parts/{part_id}/missing": {"get": {"responses": {"200": {"description": "Missing sequence list"}}}},
        "/v1/turns/{turn_id}/parts/{part_id}/finish": {"post": {"responses": {"200": {"description": "Verified part"}}}},
        "/v1/turns/{turn_id}/events/{event_id}/ack": {"post": {"responses": {"200": {"description": "Event ACK"}}}},
        "/v1/outbox": {"get": {"responses": {"200": {"description": "Origin-device ordered outbox"}}}},
        "/v1/tts/{artifact_id}": {
            "get": {
                "summary": "Read target TTS or bridge it through an authenticated registered Phone",
                "parameters": [{"$ref": "#/components/parameters/ArtifactId"}, {"$ref": "#/components/parameters/DeviceId"}],
                "responses": {"200": {"description": "TTS payload"}, "401": {"description": "Device is not the target or an active Phone bridge"}, "409": {"description": "TTS payload is unavailable"}},
            }
        },
        "/v1/tts/{artifact_id}/bridge-read": {
            "get": {
                "summary": "Read Watch-targeted TTS through an authenticated registered Phone bridge",
                "parameters": [{"$ref": "#/components/parameters/ArtifactId"}, {"$ref": "#/components/parameters/DeviceId"}],
                "responses": {"200": {"description": "TTS payload"}, "401": {"description": "Active registered Phone bridge required"}, "409": {"description": "TTS payload is unavailable"}},
            }
        },
        "/v1/tts/{artifact_id}/playback-ack": {
            "post": {
                "summary": "Complete playback on the actual TTS delivery target",
                "parameters": [{"$ref": "#/components/parameters/ArtifactId"}],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlaybackAck"}}}},
                "responses": {"200": {"description": "Target playback completion"}, "400": {"description": "Required receipt field missing or invalid"}, "401": {"description": "Only the delivery target may complete playback"}, "409": {"description": "Receipt does not match the stored artifact"}},
            }
        },
        "/v1/tts/{artifact_id}/relay-received": {"post": {"responses": {"200": {"description": "Non-origin relay receipt"}}}},
        "/v1/projects": {"get": {"responses": {"200": {"description": "Project registry"}}}, "post": {"responses": {"201": {"description": "Project"}}}},
        "/v1/projects/search": {"get": {"responses": {"200": {"description": "Project search"}}}},
        "/v1/projects/{project_id}": {"get": {"responses": {"200": {"description": "Project"}}}, "patch": {"responses": {"200": {"description": "CAS update"}}}},
        "/v1/turns/{turn_id}/archive": {"post": {"responses": {"200": {"description": "Archive-only turn retention"}}}},
        "/v1/projects/{project_id}/archive": {"post": {"responses": {"200": {"description": "Archive-only transition"}}}},
        "/v1/internal/router": {"post": {"responses": {"200": {"description": "Internal router worker step"}}}},
        "/v1/internal/hermes": {"post": {"responses": {"200": {"description": "Internal Hermes worker step"}}}},
        "/v1/internal/tts": {"post": {"responses": {"200": {"description": "Internal TTS worker step"}}}},
        "/v1/internal/schedule_create": {"post": {"summary": "Trusted Recorder adapter schedule creation", "responses": {"201": {"description": "Durably scheduled with atomic confirmation FINAL"}, "401": {"description": "Trusted adapter header required"}, "409": {"description": "Immutable schedule conflict"}}}},
        "/v1/internal/scheduler/fire": {"post": {"summary": "Claim and fire due server schedules", "responses": {"200": {"description": "Scheduled FINAL readback"}}}},
        "/v1/internal/scheduler/recover": {"post": {"summary": "Requeue expired scheduler leases", "responses": {"200": {"description": "Recovery counts"}}}},
        "/v1/schedules/{schedule_id}": {"get": {"parameters": [{"name": "schedule_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "Schedule and occurrence readback"}}}},
        "/v1/updates/{channel}/manifest": {"get": {"responses": {"200": {"description": "Current immutable channel manifest"}}}},
        "/v1/updates/{channel}/{generation}/{artifact_name}": {"get": {"responses": {"200": {"description": "Hash-bound APK bytes"}, "206": {"description": "Byte range"}, "304": {"description": "ETag matched"}, "416": {"description": "Unsatisfiable range"}}}, "head": {"responses": {"200": {"description": "APK metadata"}}}},
        "/v1/history": {"get": {"summary": "Project-scoped keyset history read model", "responses": {"200": {"description": "Paired user/assistant messages"}}}},
        "/v1/eavesdrop": {"post": {"summary": "Start a phone-mediated eavesdrop session", "responses": {"201": {"description": "Created session"}}}},
        "/v1/eavesdrop/{session_id}": {"get": {"responses": {"200": {"description": "Session state"}}}},
        "/v1/eavesdrop/{session_id}/{action}": {"post": {"parameters": [{"name": "action", "in": "path", "required": True, "schema": {"type": "string", "enum": ["activate", "pause", "resume", "stop", "segments"]}}], "responses": {"200": {"description": "State transition or segment receipt"}}}},
        "/v1/eavesdrop/{session_id}/replies": {"get": {"responses": {"200": {"description": "Optional response receipts"}}}},
        "/v1/diagnostics/opt-in": {"post": {"responses": {"201": {"description": "Consent event"}}}},
        "/v1/diagnostics/events": {"post": {"responses": {"201": {"description": "Redacted diagnostic event"}}}},
        "/v1/diagnostics/bundles": {"post": {"responses": {"201": {"description": "Bounded compressed diagnostic bundle"}}}},
        "/v1/diagnostics": {"get": {"responses": {"200": {"description": "Diagnostic metadata"}}}, "delete": {"responses": {"200": {"description": "Deletion receipt and tombstones"}}}},
        "/v1/diagnostics/delete": {"post": {"responses": {"200": {"description": "Deletion receipt and tombstones"}}}},
        "/v1/internal/worker/claim": {"post": {"responses": {"200": {"description": "Claim one durable worker lease"}}}},
        "/v1/internal/worker/recover": {"post": {"responses": {"200": {"description": "Recover expired worker leases"}}}},
        "/v1/internal/worker/complete": {"post": {"responses": {"200": {"description": "Complete one durable worker lease"}}}},
        "/v1/internal/worker/fail": {"post": {"responses": {"200": {"description": "Record one durable worker failure"}}}},
        "/v1/internal/worker/run": {"post": {"responses": {"200": {"description": "Run one durable worker lease operation"}}}},
        "/v1/internal/worker/health": {"get": {"responses": {"200": {"description": "Bounded worker backlog and lease health"}}}},
        "/v1/eavesdrop/{session_id}/segments/{segment_sequence}/route": {"post": {"responses": {"200": {"description": "Idempotent fixed-project routing decision"}}}},
        "/v1/eavesdrop/{session_id}/decisions": {"get": {"responses": {"200": {"description": "Eavesdrop routing decision ledger"}}}},
        "/v1/diagnostics/export": {"get": {"responses": {"200": {"description": "Redacted diagnostic export"}}}},
    },
    "components": {
        "parameters": {
            "TurnId": {"name": "turn_id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}},
            "ArtifactId": {"name": "artifact_id", "in": "path", "required": True, "schema": {"type": "string"}},
            "DeviceId": {"name": "device_id", "in": "query", "required": True, "description": "Registered active device identity; a Phone may bridge-read a Watch-targeted artifact.", "schema": {"type": "string", "minLength": 1}},
            "UserId": {"name": "user_id", "in": "query", "required": True, "description": "Owner identity paired with the registered active device.", "schema": {"type": "string", "minLength": 1}},
            "DevicePath": {"name": "device_id", "in": "path", "required": True, "schema": {"type": "string", "minLength": 1}},
            "PartId": {"name": "part_id", "in": "path", "required": True, "schema": {"type": "string", "minLength": 1}},
            "Sequence": {"name": "sequence", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 0}},
            "EventId": {"name": "event_id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}},
            "ProjectId": {"name": "project_id", "in": "path", "required": True, "schema": {"type": "string", "minLength": 1}},
            "ScheduleId": {"name": "schedule_id", "in": "path", "required": True, "schema": {"type": "string", "minLength": 1}},
            "Channel": {"name": "channel", "in": "path", "required": True, "schema": {"type": "string", "minLength": 1}},
            "Generation": {"name": "generation", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}},
            "ArtifactName": {"name": "artifact_name", "in": "path", "required": True, "schema": {"type": "string", "minLength": 1}},
            "SessionId": {"name": "session_id", "in": "path", "required": True, "schema": {"type": "string", "minLength": 1}},
            "Action": {"name": "action", "in": "path", "required": True, "schema": {"type": "string", "enum": ["activate", "pause", "resume", "stop", "segments"]}},
            "SegmentSequence": {"name": "segment_sequence", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 0}},
        },
        "schemas": {
            "TurnState": {"type": "string", "enum": ["RECEIVING", "ACCEPTED", "PREPROCESSING", "ROUTING", "ROUTED", "HERMES_PENDING", "FINAL_READY", "DELIVERY_PENDING", "RETRY_WAIT", "LATE_RESULT_GRACE", "DELIVERED", "FAILED_PERMANENT", "EXPIRED"]},
            "EventKind": {"type": "string", "enum": ["ACCEPTED", "ROUTED", "FINAL"]},
            "ArtifactState": {"type": "string", "enum": ["PENDING", "READY", "DELIVERY_PENDING", "PLAYED", "FAILED_GENERATION", "EXPIRED"]},
            "ScheduleState": {"type": "string", "enum": ["SCHEDULED", "CLAIMED", "FIRED", "FAILED", "CANCELLED"]},
            "ServerTurnSource": {"type": "string", "enum": ["server_schedule"]},
            "PlaybackAck": {
                "type": "object",
                "required": ["user_id", "device_id", "payload_sha256", "turn_id", "artifact_version"],
                "additionalProperties": False,
                "properties": {
                    "user_id": {"type": "string", "minLength": 1},
                    "device_id": {"type": "string", "minLength": 1},
                    "payload_sha256": {"type": "string", "minLength": 1},
                    "turn_id": {"type": "string", "format": "uuid", "minLength": 1},
                    "artifact_version": {"type": "integer", "minimum": 1},
                },
            },
            "Error": {"type": "object", "required": ["error"], "properties": {"error": {"type": "object", "properties": {"code": {"type": "string"}, "message": {"type": "string"}}}}},
        },
    },
}


_PATH_VARIABLE = re.compile(r"{([^{}]+)}")
_OPENAPI_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
_PATH_PARAMETER_COMPONENTS = {
    "device_id": "DevicePath",
    "turn_id": "TurnId",
    "part_id": "PartId",
    "sequence": "Sequence",
    "event_id": "EventId",
    "artifact_id": "ArtifactId",
    "project_id": "ProjectId",
    "schedule_id": "ScheduleId",
    "channel": "Channel",
    "generation": "Generation",
    "artifact_name": "ArtifactName",
    "session_id": "SessionId",
    "action": "Action",
    "segment_sequence": "SegmentSequence",
}


def _resolve_parameter(document: dict, parameter: object) -> dict:
    if not isinstance(parameter, dict):
        raise ValueError("OpenAPI parameter must be an object")
    ref = parameter.get("$ref")
    if ref is not None:
        prefix = "#/components/parameters/"
        if not isinstance(ref, str) or not ref.startswith(prefix):
            raise ValueError("OpenAPI parameter reference is invalid")
        parameter = document.get("components", {}).get("parameters", {}).get(ref[len(prefix):])
        if not isinstance(parameter, dict):
            raise ValueError(f"OpenAPI parameter reference is unresolved: {ref}")
    return parameter


def _parameter_name(document: dict, parameter: object) -> str:
    parameter = _resolve_parameter(document, parameter)
    name = parameter.get("name")
    location = parameter.get("in")
    if not isinstance(name, str) or not name or not isinstance(location, str):
        raise ValueError("OpenAPI parameter requires name and in")
    if location == "path" and parameter.get("required") is not True:
        raise ValueError(f"OpenAPI path parameter {name!r} must be required")
    return name


def _add_path_parameters(document: dict) -> None:
    for path, item in document.get("paths", {}).items():
        if not isinstance(item, dict):
            raise ValueError(f"OpenAPI path item is not an object: {path}")
        variables = _PATH_VARIABLE.findall(path)
        path_parameters = item.get("parameters")
        if path_parameters is None:
            path_parameters = []
            if variables:
                item["parameters"] = path_parameters
        if not isinstance(path_parameters, list):
            raise ValueError(f"OpenAPI path parameters must be a list: {path}")

        declared = {_parameter_name(document, parameter) for parameter in path_parameters}
        operation_parameters = {
            _parameter_name(document, parameter)
            for operation_name, operation in item.items()
            if operation_name in _OPENAPI_METHODS and isinstance(operation, dict)
            for parameter in operation.get("parameters", [])
        }
        for variable in variables:
            if variable not in declared and variable not in operation_parameters:
                component = _PATH_PARAMETER_COMPONENTS.get(variable)
                if component is None:
                    raise ValueError(f"OpenAPI has no path parameter component for {variable}")
                path_parameters.append({"$ref": f"#/components/parameters/{component}"})
                declared.add(variable)
        if not path_parameters and "parameters" in item:
            item.pop("parameters")


def _add_owner_contract(document: dict) -> None:
    schemas = document.setdefault("components", {}).setdefault("schemas", {})
    schemas.setdefault(
        "OwnerProof",
        {
            "type": "object",
            "required": ["user_id", "device_id"],
            "additionalProperties": False,
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "device_id": {"type": "string", "minLength": 1},
            },
        },
    )
    schemas.setdefault(
        "TurnCreate",
        {
            "type": "object",
            "required": ["user_id", "turn_id", "origin_device_id", "parts"],
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "turn_id": {"type": "string", "format": "uuid"},
                "origin_device_id": {"type": "string", "minLength": 1},
                "parts": {"type": "array", "minItems": 1},
            },
        },
    )
    schemas.setdefault(
        "DeviceRevoke",
        {
            "type": "object",
            "required": ["user_id", "actor_device_id"],
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "actor_device_id": {"type": "string", "minLength": 1},
            },
            "additionalProperties": False,
        },
    )
    schemas.setdefault(
        "FinishPart",
        {
            "type": "object",
            "required": ["total_chunks", "total_bytes", "whole_stream_sha256"],
            "properties": {
                "total_chunks": {"type": "integer", "minimum": 1},
                "total_bytes": {"type": "integer", "minimum": 0},
                "whole_stream_sha256": {"type": "string", "minLength": 1},
                "duration_ms": {"type": ["integer", "null"], "minimum": 0},
            },
        },
    )
    schemas.setdefault(
        "EventAck",
        {
            "type": "object",
            "required": ["user_id", "device_id", "event_version", "payload_sha256"],
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "device_id": {"type": "string", "minLength": 1},
                "event_version": {"type": "integer", "minimum": 1},
                "payload_sha256": {"type": "string", "minLength": 1},
            },
        },
    )
    schemas.setdefault(
        "RelayReceived",
        {
            "type": "object",
            "required": ["user_id", "device_id", "payload_sha256"],
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "device_id": {"type": "string", "minLength": 1},
                "payload_sha256": {"type": "string", "minLength": 1},
            },
        },
    )
    query_owner_paths = {
        "/v1/turns/{turn_id}": {"get"},
        "/v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}": {"put", "post"},
        "/v1/turns/{turn_id}/parts/{part_id}/missing": {"get"},
        "/v1/turns/{turn_id}/parts/{part_id}/finish": {"post"},
        "/v1/turns/{turn_id}/archive": {"post"},
        "/v1/outbox": {"get"},
        "/v1/tts/{artifact_id}": {"get"},
        "/v1/tts/{artifact_id}/bridge-read": {"get"},
        "/v1/history": {"get"},
        "/v1/projects": {"get"},
        "/v1/projects/search": {"get"},
        "/v1/projects/{project_id}": {"get", "patch"},
        "/v1/projects/{project_id}/archive": {"post"},
        "/v1/schedules/{schedule_id}": {"get"},
        "/v1/diagnostics": {"get"},
        "/v1/diagnostics/export": {"get"},
    }
    for path, methods in query_owner_paths.items():
        item = document["paths"].get(path)
        if not isinstance(item, dict):
            continue
        for method in methods:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            parameters = operation.setdefault("parameters", [])
            if not isinstance(parameters, list):
                raise ValueError(f"OpenAPI operation parameters must be a list: {path} {method}")
            names = {
                (_resolve_parameter(document, parameter).get("name"), _resolve_parameter(document, parameter).get("in"))
                for parameter in parameters
            }
            for component in ("UserId", "DeviceId"):
                parameter = document["components"]["parameters"][component]
                key = (parameter["name"], parameter["in"])
                if key not in names:
                    parameters.append({"$ref": f"#/components/parameters/{component}"})
                    names.add(key)

    body_refs = {
        "/v1/devices/{device_id}/revoke": {"post": "DeviceRevoke"},
        "/v1/turns": {"post": "TurnCreate"},
        "/v1/turns/{turn_id}/accept": {"post": "OwnerProof"},
        "/v1/turns/{turn_id}/parts/{part_id}/finish": {"post": "FinishPart"},
        "/v1/turns/{turn_id}/events/{event_id}/ack": {"post": "EventAck"},
        "/v1/tts/{artifact_id}/relay-received": {"post": "RelayReceived"},
        "/v1/tts/{artifact_id}/playback-ack": {"post": "PlaybackAck"},
        "/v1/diagnostics": {"delete": "OwnerProof"},
        "/v1/diagnostics/delete": {"post": "OwnerProof"},
    }
    for path, methods in body_refs.items():
        item = document["paths"].get(path)
        if not isinstance(item, dict):
            continue
        for method, schema in methods.items():
            operation = item.get(method)
            if isinstance(operation, dict):
                operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{schema}"}}}}


def validate_openapi_contract(document: dict | None = None) -> bool:
    """Validate resolved path parameters and the exact worker operation set."""

    document = OPENAPI if document is None else document
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("OpenAPI document must contain an object-valued paths member")
    if "/v1/internal/worker/{action}" in document["paths"]:
        raise ValueError("generic worker action route is not part of the contract")
    required_worker_paths = {
        "/v1/internal/worker/claim",
        "/v1/internal/worker/recover",
        "/v1/internal/worker/complete",
        "/v1/internal/worker/fail",
        "/v1/internal/worker/run",
    }
    if not required_worker_paths.issubset(document["paths"]):
        raise ValueError("OpenAPI worker contract is incomplete")
    for path, item in document["paths"].items():
        variables = set(_PATH_VARIABLE.findall(path))
        declared: dict[str, int] = {}
        locations: dict[str, set[str]] = {}
        parameters = item.get("parameters", [])
        if not isinstance(parameters, list):
            raise ValueError(f"OpenAPI path parameters must be a list: {path}")
        for parameter in parameters:
            resolved = _resolve_parameter(document, parameter)
            name = _parameter_name(document, resolved)
            declared[name] = declared.get(name, 0) + 1
            locations.setdefault(name, set()).add(resolved["in"])
        for operation_name, operation in item.items():
            if operation_name not in _OPENAPI_METHODS or not isinstance(operation, dict):
                continue
            operation_parameters = operation.get("parameters", [])
            if not isinstance(operation_parameters, list):
                raise ValueError(f"OpenAPI operation parameters must be a list: {path} {operation_name}")
            for parameter in operation_parameters:
                resolved = _resolve_parameter(document, parameter)
                name = _parameter_name(document, resolved)
                declared[name] = declared.get(name, 0) + 1
                locations.setdefault(name, set()).add(resolved["in"])
        for variable in variables:
            if declared.get(variable, 0) != 1 or locations.get(variable) != {"path"}:
                raise ValueError(f"OpenAPI path variable {variable!r} is not declared exactly once: {path}")
    return True


_add_path_parameters(OPENAPI)
_add_owner_contract(OPENAPI)
validate_openapi_contract(OPENAPI)
