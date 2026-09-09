from __future__ import annotations

import math
from typing import Any, Mapping


class MetadataValidationError(ValueError):
    """Raised when required diagnostic metadata is malformed."""


CATEGORIES = {"voice", "transport", "worker", "routing", "delivery", "update", "diagnostics", "other"}
STAGES = {"capture", "upload", "accept", "asr", "routing", "hermes", "tts", "delivery", "playback", "schedule", "update", "diagnostics", "other"}
STATUSES = {"ok", "pending", "retry", "failed", "skipped", "expired", "other"}
REASONS = {"none", "timeout", "unavailable", "unauthorized", "validation", "conflict", "rate_limited", "lease_expired", "deadline", "max_attempts", "cancelled", "other"}
EVENT_TYPES = {"started", "completed", "failed", "retried", "skipped", "expired", "other"}
SOURCES = {"phone", "watch", "server", "ingress", "worker", "other"}
PLATFORMS = {"android", "wear_os", "linux", "other"}


def _enum(value: Any, allowed: set[str], field: str, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise MetadataValidationError(f"diagnostic {field} is required")
        return None
    if not isinstance(value, str):
        if required:
            raise MetadataValidationError(f"diagnostic {field} is invalid")
        return "other"
    if value in allowed:
        return value
    if required:
        raise MetadataValidationError(f"diagnostic {field} is invalid")
    return "other"


def _metric(value: Any, field: str, minimum: int, maximum: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, float) and not math.isfinite(value):
            raise MetadataValidationError(f"diagnostic {field} is non-finite")
        return None
    if minimum <= value <= maximum:
        return value
    return None


def project_metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Project arbitrary legacy input into the closed flat metadata-v2 DTO."""
    if not isinstance(payload, Mapping):
        raise MetadataValidationError("diagnostic metadata must be an object")
    category = _enum(payload.get("category"), CATEGORIES, "category", required=True)
    stage = _enum(payload.get("stage"), STAGES, "stage", required=True)
    result: dict[str, Any] = {"category": category, "stage": stage}
    for field, allowed in (
        ("status", STATUSES),
        ("reason", REASONS),
        ("event_type", EVENT_TYPES),
        ("source", SOURCES),
        ("platform", PLATFORMS),
    ):
        value = _enum(payload.get(field), allowed, field)
        if value is not None:
            result[field] = value
    for field, minimum, maximum in (
        ("code", 100, 599),
        ("duration_ms", 0, 86_400_000),
        ("count", 0, 1_000_000),
        ("size_bytes", 0, 67_108_864),
    ):
        value = _metric(payload.get(field), field, minimum, maximum)
        if value is not None:
            result[field] = value
    return result


def project_bundle(events: Any, *, max_events: int = 64) -> dict[str, list[dict[str, Any]]]:
    if isinstance(events, Mapping) and "events" in events:
        events = events["events"]
    elif isinstance(events, Mapping):
        events = [events]
    if not isinstance(events, list) or len(events) > max_events:
        raise MetadataValidationError("diagnostic bundle events are invalid")
    return {"events": [project_metadata(item) for item in events]}


__all__ = ["CATEGORIES", "STAGES", "MetadataValidationError", "project_metadata", "project_bundle"]
