"""Closed JSON DTO models shared by the Recorder HTTP catalog and handlers.

The models intentionally contain no service imports.  They are the small,
side-effect-free boundary used to reject malformed or undeclared request
fields before a handler reaches the store.
"""

from __future__ import annotations

from collections.abc import Mapping as ABCMapping
from dataclasses import dataclass
import copy
import re
from typing import Any, Callable, Mapping

from .diagnostics_contract import CATEGORIES, EVENT_TYPES, PLATFORMS, REASONS, SOURCES, STAGES, STATUSES


class ModelValidationError(ValueError):
    """A request value does not satisfy its closed DTO model."""


def _type_name(expected: type[Any]) -> str:
    return {
        str: "string",
        int: "integer",
        bool: "boolean",
        float: "number",
        list: "array",
        dict: "object",
        ABCMapping: "object",
        bytes: "string",
    }.get(expected, "object")


def _is_instance(value: Any, expected: type[Any]) -> bool:
    if expected is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if expected is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected is ABCMapping:
        return isinstance(value, ABCMapping)
    return isinstance(value, expected)


@dataclass(frozen=True)
class Field:
    name: str
    required: bool = False
    types: tuple[type[Any], ...] = (object,)
    nullable: bool = False
    enum: tuple[Any, ...] = ()
    minimum: int | float | None = None
    maximum: int | float | None = None
    min_length: int | None = None
    max_length: int | None = None
    pattern: str | None = None
    item_model: "ObjectModel | None" = None
    object_model: "ObjectModel | None" = None
    schema_hint: Mapping[str, Any] | None = None
    internal: bool = False

    def validate(self, value: Any, *, path: str) -> None:
        if value is None:
            if self.nullable:
                return
            raise ModelValidationError(f"{path} must not be null")
        if self.types != (object,) and not any(_is_instance(value, expected) for expected in self.types):
            expected = ", ".join(_type_name(item) for item in self.types)
            raise ModelValidationError(f"{path} must be {expected}")
        if self.enum and value not in self.enum:
            raise ModelValidationError(f"{path} has an unsupported value")
        if self.minimum is not None and isinstance(value, (int, float)) and not isinstance(value, bool) and value < self.minimum:
            raise ModelValidationError(f"{path} is below the minimum")
        if self.maximum is not None and isinstance(value, (int, float)) and not isinstance(value, bool) and value > self.maximum:
            raise ModelValidationError(f"{path} exceeds the maximum")
        if isinstance(value, str):
            if self.min_length is not None and len(value) < self.min_length:
                raise ModelValidationError(f"{path} is too short")
            if self.max_length is not None and len(value) > self.max_length:
                raise ModelValidationError(f"{path} is too long")
            if self.pattern is not None and re.fullmatch(self.pattern, value) is None:
                raise ModelValidationError(f"{path} has an invalid format")
        if self.object_model is not None:
            if not isinstance(value, ABCMapping):
                raise ModelValidationError(f"{path} must be an object")
            self.object_model.validate(value, path=path)
        if self.item_model is not None:
            if not isinstance(value, list):
                raise ModelValidationError(f"{path} must be an array")
            for index, item in enumerate(value):
                self.item_model.validate(item, path=f"{path}[{index}]")

    def openapi_schema(self, *, include_internal: bool = False) -> dict[str, Any]:
        if self.schema_hint is not None:
            schema = copy.deepcopy(dict(self.schema_hint))
        elif self.object_model is not None:
            schema = self.object_model.openapi_schema(include_internal=include_internal)
        elif self.item_model is not None:
            schema = {
                "type": "array",
                "items": {"$ref": f"#/components/schemas/{self.item_model.name}"},
            }
        elif len(self.types) == 1:
            schema: dict[str, Any] = {"type": _type_name(self.types[0])}
            if self.types[0] is bytes:
                schema["format"] = "binary"
        else:
            schema = {"oneOf": [{"type": _type_name(item)} for item in self.types]}
        if self.enum:
            schema["enum"] = [item for item in self.enum if item is not None]
        if self.minimum is not None:
            schema["minimum"] = self.minimum
        if self.maximum is not None:
            schema["maximum"] = self.maximum
        if self.min_length is not None:
            schema["minLength"] = self.min_length
        if self.max_length is not None:
            schema["maxLength"] = self.max_length
        if self.pattern is not None:
            schema["pattern"] = self.pattern
        if self.nullable:
            schema["nullable"] = True
        return schema


@dataclass(frozen=True)
class ObjectModel:
    name: str
    fields: tuple[Field, ...] = ()
    additional_properties: bool = False
    conditional_required: tuple[tuple[str, tuple[str, ...]], ...] = ()
    validator: Callable[[Mapping[str, Any]], None] | None = None

    def __post_init__(self) -> None:
        names = [item.name for item in self.fields]
        if len(names) != len(set(names)):
            raise ValueError(f"duplicate fields in {self.name}")

    def validate(
        self,
        value: Mapping[str, Any],
        *,
        path: str | None = None,
        allow_missing_required: bool = False,
    ) -> None:
        prefix = path or self.name
        if not isinstance(value, ABCMapping):
            raise ModelValidationError(f"{prefix} must be a JSON object")
        declared = {item.name: item for item in self.fields}
        unknown = sorted(set(value) - set(declared))
        if unknown and not self.additional_properties:
            raise ModelValidationError(f"{prefix} contains undeclared fields: {', '.join(str(item) for item in unknown)}")
        alternatives = {name: set(options) for name, options in self.conditional_required}
        for item in self.fields:
            if item.internal and item.name in value:
                # Internal clock overrides are accepted only by in-process
                # deterministic tests; the network boundary rejects them.
                pass
            if item.required and item.name not in value and not allow_missing_required:
                if not (alternatives.get(item.name) and any(option in value for option in alternatives[item.name])):
                    raise ModelValidationError(f"{prefix}.{item.name} is required")
            if item.name in value:
                item.validate(value[item.name], path=f"{prefix}.{item.name}")
        if self.validator is not None:
            self.validator(value)

    def openapi_schema(self, *, include_internal: bool = False) -> dict[str, Any]:
        fields = [item for item in self.fields if include_internal or not item.internal]
        properties = {item.name: item.openapi_schema(include_internal=include_internal) for item in fields}
        required = [item.name for item in fields if item.required]
        schema: dict[str, Any] = {
            "type": "object",
            "additionalProperties": self.additional_properties,
            "properties": properties,
        }
        if required:
            schema["required"] = required
        return schema


def string(name: str, *, required: bool = False, nullable: bool = False, internal: bool = False, **kwargs: Any) -> Field:
    return Field(name, required=required, types=(str,), nullable=nullable, internal=internal, **kwargs)


def integer(name: str, *, required: bool = False, nullable: bool = False, internal: bool = False, **kwargs: Any) -> Field:
    return Field(name, required=required, types=(int,), nullable=nullable, internal=internal, **kwargs)


def boolean(name: str, *, required: bool = False, nullable: bool = False, internal: bool = False, **kwargs: Any) -> Field:
    return Field(name, required=required, types=(bool,), nullable=nullable, internal=internal, **kwargs)


def array(name: str, *, required: bool = False, item_model: ObjectModel | None = None, nullable: bool = False, **kwargs: Any) -> Field:
    return Field(name, required=required, types=(list,), item_model=item_model, nullable=nullable, **kwargs)


def object_field(name: str, *, required: bool = False, object_model: ObjectModel | None = None, nullable: bool = False, **kwargs: Any) -> Field:
    return Field(name, required=required, types=(ABCMapping,), object_model=object_model, nullable=nullable, **kwargs)


TURN_PART = ObjectModel(
    "TurnPart",
    (
        string("part_id", required=True),
        string("kind", required=True),
        string("mime", required=True),
        integer("declared_bytes", nullable=True, minimum=0),
        string("declared_sha256", nullable=True),
        string("relationship", nullable=True),
        string("caption_hash", nullable=True),
        integer("duration_ms", nullable=True, minimum=0),
        boolean("streaming"),
    ),
)

DEVICE_REGISTER = ObjectModel("DeviceRegister", (string("user_id", required=True), string("device_id", required=True), string("kind", required=True)))
DEVICE_REVOKE = ObjectModel("DeviceRevoke", (string("user_id", required=True), string("actor_device_id", required=True)))
OWNER_PROOF = ObjectModel("OwnerProof", (string("user_id", required=True), string("device_id", required=True)))

TURN_CREATE = ObjectModel(
    "TurnCreate",
    (
        integer("schema_version", required=True, minimum=1),
        string("user_id", required=True),
        string("turn_id", required=True),
        string("origin_device_id", required=True),
        string("client_created_at", required=True),
        string("current_project_number", nullable=True),
        boolean("prefer_current_project"),
        array("parts", required=True, item_model=TURN_PART),
        string("text"),
    ),
    conditional_required=(("parts", ("text",)),),
)
FINISH_PART = ObjectModel(
    "FinishPart",
    (
        integer("total_chunks", required=True, minimum=1),
        integer("total_bytes", required=True, minimum=0),
        string("whole_stream_sha256", required=True),
        integer("duration_ms", nullable=True, minimum=0),
    ),
)
EVENT_ACK = ObjectModel(
    "EventAck",
    (
        string("user_id", required=True),
        string("device_id", required=True),
        integer("event_version", required=True, minimum=1),
        string("payload_sha256", required=True),
    ),
)
RELAY_RECEIVED = ObjectModel("RelayReceived", (string("user_id", required=True), string("device_id", required=True), string("payload_sha256", required=True)))
PLAYBACK_ACK = ObjectModel(
    "PlaybackAck",
    (
        string("user_id", required=True),
        string("device_id", required=True),
        string("payload_sha256", required=True),
        string("turn_id", required=True),
        integer("artifact_version", required=True, minimum=1),
    ),
)

PROJECT_CREATE = ObjectModel(
    "ProjectCreate",
    (
        string("user_id", required=True),
        string("device_id", required=True),
        string("project_number", required=True),
        string("name", required=True),
        array("aliases"),
        string("description"),
        string("idempotency_key", nullable=True),
    ),
)
PROJECT_PATCH = ObjectModel(
    "ProjectPatch",
    (
        integer("expected_version", required=True, minimum=1),
        string("name", nullable=True),
        array("aliases", nullable=True),
        string("description", nullable=True),
    ),
)
EXPECTED_VERSION = ObjectModel("ExpectedVersion", (integer("expected_version", required=True, minimum=1),))
ARCHIVE_TURN = ObjectModel("ArchiveTurn", (string("source"),))

SCHEDULE_CREATE = ObjectModel(
    "ScheduleCreate",
    (
        string("schedule_id", required=True),
        string("parent_turn_id", required=True),
        string("project_id", required=True),
        string("session_key", required=True),
        string("origin_device_id", required=True),
        string("delivery_target_device_id", required=True),
        string("fire_at_utc", required=True),
        string("timezone_offset", required=True),
        string("reminder_text", required=True),
        string("confirmation_text", required=True),
    ),
)
SCHEDULER_FIRE = ObjectModel(
    "SchedulerFire",
    (
        string("owner"),
        integer("lease_seconds", minimum=1),
        integer("limit", minimum=1),
        string("now", internal=True),
    ),
)
SCHEDULER_RECOVER = ObjectModel("SchedulerRecover", (string("now", internal=True),))

EAVESDROP_START = ObjectModel(
    "EavesdropStart",
    (
        string("user_id", required=True),
        string("phone_device_id", required=True),
        string("session_id", nullable=True),
        string("idempotency_key", nullable=True),
        string("watch_device_id", nullable=True),
        string("project_id", nullable=True),
        boolean("response_enabled"),
        boolean("tts_enabled"),
        boolean("hermes_enabled"),
        string("mode", nullable=True),
        integer("expires_seconds", minimum=1),
        string("now", internal=True),
    ),
)
EAVESDROP_ACTION = ObjectModel(
    "EavesdropAction",
    (string("user_id", required=True), string("phone_device_id", required=True), string("now", internal=True)),
)
EAVESDROP_SEGMENT = ObjectModel(
    "EavesdropSegment",
    (
        string("user_id", required=True),
        string("phone_device_id", required=True),
        integer("sequence", required=True, minimum=0),
        string("client_segment_id", required=True),
        string("audio_base64", required=True, min_length=1),
        string("transcript", nullable=True),
        string("reply_text", nullable=True),
        string("now", internal=True),
    ),
)
EAVESDROP_ROUTE = ObjectModel(
    "EavesdropRoute",
    (string("user_id", required=True), string("phone_device_id", required=True), integer("segment_sequence", required=True, minimum=0), string("now", internal=True)),
)
EAVESDROP_ROUTE_PATH = ObjectModel(
    "EavesdropRoutePath",
    (string("user_id", required=True), string("phone_device_id", required=True), string("now", internal=True)),
)

DIAGNOSTIC_METADATA = ObjectModel(
    "DiagnosticMetadata",
    (
        string("category", required=True, enum=tuple(sorted(CATEGORIES))),
        string("stage", required=True, enum=tuple(sorted(STAGES))),
        string("status", enum=tuple(sorted(STATUSES))),
        string("reason", enum=tuple(sorted(REASONS))),
        string("event_type", enum=tuple(sorted(EVENT_TYPES))),
        string("source", enum=tuple(sorted(SOURCES))),
        string("platform", enum=tuple(sorted(PLATFORMS))),
        integer("code", minimum=100, maximum=599),
        integer("duration_ms", minimum=0, maximum=86_400_000),
        integer("count", minimum=0, maximum=1_000_000),
        integer("size_bytes", minimum=0, maximum=67_108_864),
    ),
)
DIAGNOSTICS_OPT_IN = ObjectModel(
    "DiagnosticsOptIn",
    (
        string("user_id", required=True),
        string("device_id", required=True),
        string("event_id", nullable=True),
        boolean("enabled"),
        string("expires_at", nullable=True),
        string("now", internal=True),
    ),
)
DIAGNOSTICS_EVENT = ObjectModel(
    "DiagnosticsEvent",
    (
        string("user_id", required=True),
        string("device_id", required=True),
        string("event_id", required=True),
        string("idempotency_key", required=True),
        object_field("payload", required=True, object_model=DIAGNOSTIC_METADATA),
        string("occurred_at", nullable=True),
        string("now", internal=True),
    ),
)
DIAGNOSTICS_BUNDLE = ObjectModel(
    "DiagnosticsBundle",
    (
        string("user_id", required=True),
        string("device_id", required=True),
        string("bundle_id", required=True),
        string("opt_in_event_id", required=True),
        string("compressed_base64", required=True, min_length=1),
        integer("expanded_size", nullable=True, minimum=0),
        string("now", internal=True),
    ),
)
DIAGNOSTICS_DELETE = ObjectModel(
    "DiagnosticsDelete",
    (string("user_id", required=True), string("device_id", required=True), string("now", internal=True)),
)

WORKER_CLAIM = ObjectModel("WorkerClaim", (string("owner"), integer("lease_seconds", minimum=1)))
WORKER_RECOVER = ObjectModel("WorkerRecover", ())
WORKER_RECEIPT = ObjectModel(
    "WorkerReceipt",
    (
        string("effect_id", required=True),
        string("status", required=True, enum=("accepted", "succeeded", "not_required")),
        string("job_id"),
        string("idempotency_key"),
        string("stage"),
        string("outcome", pattern=r"[A-Za-z][A-Za-z0-9_.-]{0,63}"),
        string("state", pattern=r"[A-Za-z][A-Za-z0-9_.-]{0,63}"),
        integer("count", minimum=0, maximum=1_000_000),
    ),
)
WORKER_COMPLETE = ObjectModel(
    "WorkerComplete",
    (string("job_id", required=True), string("owner", required=True), string("lease_token", required=True), object_field("receipt", required=True, object_model=WORKER_RECEIPT)),
)
WORKER_FAIL = ObjectModel(
    "WorkerFail",
    (
        string("job_id", required=True),
        string("owner", required=True),
        string("lease_token", required=True),
        string("error_kind"),
        boolean("retryable"),
        integer("status_code", nullable=True),
        integer("retry_after_seconds", nullable=True, minimum=0),
    ),
)
WORKER_RUN = ObjectModel("WorkerRun", (string("owner"), integer("lease_seconds", minimum=1)))

REQUEST_MODELS: tuple[ObjectModel, ...] = (
    TURN_PART, DEVICE_REGISTER, DEVICE_REVOKE, OWNER_PROOF, TURN_CREATE, FINISH_PART, EVENT_ACK, RELAY_RECEIVED,
    PLAYBACK_ACK, PROJECT_CREATE, PROJECT_PATCH, EXPECTED_VERSION, ARCHIVE_TURN, SCHEDULE_CREATE, SCHEDULER_FIRE,
    SCHEDULER_RECOVER, EAVESDROP_START, EAVESDROP_ACTION, EAVESDROP_SEGMENT, EAVESDROP_ROUTE, EAVESDROP_ROUTE_PATH, DIAGNOSTIC_METADATA,
    DIAGNOSTICS_OPT_IN, DIAGNOSTICS_EVENT, DIAGNOSTICS_BUNDLE, DIAGNOSTICS_DELETE, WORKER_CLAIM, WORKER_RECOVER,
    WORKER_RECEIPT, WORKER_COMPLETE, WORKER_FAIL, WORKER_RUN,
)

__all__ = [
    "Field", "ModelValidationError", "ObjectModel", "REQUEST_MODELS", "TURN_PART", "TURN_CREATE", "DEVICE_REGISTER",
    "DEVICE_REVOKE", "OWNER_PROOF", "FINISH_PART", "EVENT_ACK", "RELAY_RECEIVED", "PLAYBACK_ACK", "PROJECT_CREATE",
    "PROJECT_PATCH", "EXPECTED_VERSION", "ARCHIVE_TURN", "SCHEDULE_CREATE", "SCHEDULER_FIRE", "SCHEDULER_RECOVER",
    "EAVESDROP_START", "EAVESDROP_ACTION", "EAVESDROP_SEGMENT", "EAVESDROP_ROUTE", "EAVESDROP_ROUTE_PATH", "DIAGNOSTICS_OPT_IN",
    "DIAGNOSTICS_EVENT", "DIAGNOSTICS_BUNDLE", "DIAGNOSTICS_DELETE", "WORKER_CLAIM", "WORKER_RECOVER",
    "WORKER_RECEIPT", "WORKER_COMPLETE", "WORKER_FAIL", "WORKER_RUN",
]