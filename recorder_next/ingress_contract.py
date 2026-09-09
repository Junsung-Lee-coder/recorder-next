from __future__ import annotations

import datetime as dt
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import canonical_json
from .errors import UnsupportedMediaType, ValidationError


TURN_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
PART_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
MIME_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")


class ManifestValidationError(ValidationError):
    """Raised when a turn-create envelope is not an admitted v1 value."""


class UnsupportedManifestMediaError(UnsupportedMediaType, ManifestValidationError):
    """Raised for document/binary media intentionally outside the public API."""

    code = "UNSUPPORTED_MEDIA_TYPE"
    status = 415


@dataclass(frozen=True)
class ManifestPolicy:
    max_parts: int = 20
    max_turn_bytes: int = 1024 * 1024 * 1024
    max_audio_bytes: int = 1024 * 1024 * 1024
    max_audio_minutes: int = 120
    max_text_bytes: int = 10 * 1024 * 1024
    max_attachment_bytes: int = 250 * 1024 * 1024


def _fail(message: str) -> None:
    raise ManifestValidationError(message)


def _unsupported(message: str) -> None:
    raise UnsupportedManifestMediaError(message)


def _bounded_string(value: Any, field: str, *, max_bytes: int = 128, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        _fail(f"{field} must be a non-empty string")
    if not allow_empty and not value.strip():
        _fail(f"{field} must be a non-empty string")
    for char in value:
        category = unicodedata.category(char)
        if category.startswith("C"):
            _fail(f"{field} contains a control character")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeEncodeError:
        _fail(f"{field} contains an invalid Unicode scalar")
    if size > max_bytes:
        _fail(f"{field} exceeds its UTF-8 byte limit")
    return value


def _native_int(value: Any, field: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(f"{field} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        _fail(f"{field} is outside its allowed range")
    return value


def _rfc3339(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 32:
        _fail("client_created_at must be an ASCII RFC3339 timestamp")
    try:
        if len(value.encode("ascii", "strict")) != len(value):
            _fail("client_created_at must be an ASCII RFC3339 timestamp")
    except UnicodeEncodeError:
        _fail("client_created_at must be an ASCII RFC3339 timestamp")
    if "T" not in value or value.count("T") != 1:
        _fail("client_created_at must use an uppercase T separator")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value):
        _fail("client_created_at must be timezone-qualified RFC3339")
    if value[17:19] == "60":
        _fail("leap-second timestamps are not supported")
    try:
        dt.datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        _fail("client_created_at is not a valid calendar date")
    return value


def _mime(value: Any, kind: str) -> tuple[str, str]:
    if not isinstance(value, str):
        _fail("mime is invalid")
    pieces = value.split(";")
    token = pieces[0].strip()
    if not MIME_RE.fullmatch(token):
        _fail("mime is invalid")
    lower = token.lower()
    if lower in {"application/pdf", "text/csv", "application/octet-stream"}:
        _unsupported("document and binary attachments are not supported")
    if len(pieces) > 1:
        if kind != "text" or len(pieces) != 2 or pieces[1].strip().lower() != "charset=utf-8":
            _fail("mime parameters are not supported for this part")
    preserved = value.strip()
    allowed: dict[str, set[str]] = {
        "text": {"text/plain"},
        "audio": {"audio/wav", "audio/x-wav"},
        "image": {"image/png", "image/jpeg", "image/webp", "image/gif"},
        "attachment": {"image/png", "image/jpeg", "image/webp", "image/gif"},
    }
    if lower not in allowed.get(kind, set()):
        if kind == "attachment":
            _unsupported("only image attachments are supported")
        _fail(f"mime is not supported for {kind}")
    return preserved, lower


def _hash(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        _fail(f"{field} must be null or a 64-character hexadecimal digest")
    return value


def _part(value: Any, policy: ManifestPolicy, *, seen: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("part descriptor must be an object")
    allowed = {"part_id", "kind", "mime", "declared_bytes", "declared_sha256", "relationship", "caption_hash", "duration_ms", "streaming"}
    if set(value) - allowed:
        _fail("part descriptor contains unsupported fields")
    part_id = value.get("part_id")
    if not isinstance(part_id, str) or PART_ID_RE.fullmatch(part_id) is None or part_id in {".", ".."}:
        _fail("part_id is invalid")
    if part_id in seen:
        _fail("part_id values must be unique")
    seen.add(part_id)
    kind = value.get("kind")
    if kind in {"document", "file", "binary"}:
        _unsupported("document and binary parts are not supported")
    if kind not in {"text", "audio", "image", "attachment"}:
        _fail("part kind is unsupported")
    mime_original, mime = _mime(value.get("mime"), kind)
    declared = value.get("declared_bytes")
    if declared is not None:
        declared = _native_int(declared, "declared_bytes")
        limit = policy.max_text_bytes if kind == "text" else policy.max_audio_bytes if kind == "audio" else policy.max_attachment_bytes
        if declared > limit:
            raise ValidationError("part exceeds its configured size limit")
    elif kind in {"image", "attachment"}:
        _fail("image parts require declared_bytes")
    duration = value.get("duration_ms")
    if duration is not None:
        duration = _native_int(duration, "duration_ms", maximum=policy.max_audio_minutes * 60 * 1000)
        if kind != "audio":
            _fail("duration_ms is only valid for audio")
    streaming = value.get("streaming", False)
    if not isinstance(streaming, bool):
        _fail("streaming must be boolean")
    if streaming and kind != "audio":
        _fail("streaming is only valid for audio")
    relationship = value.get("relationship")
    if relationship is not None:
        relationship = _bounded_string(relationship, "relationship", max_bytes=128)
    caption_hash = _hash(value.get("caption_hash"), "caption_hash")
    declared_sha256 = _hash(value.get("declared_sha256"), "declared_sha256")
    return {
        "part_id": part_id,
        "kind": kind,
        "mime": mime_original,
        "declared_bytes": declared,
        "declared_sha256": declared_sha256,
        "relationship": relationship,
        "caption_hash": caption_hash,
        "duration_ms": duration,
        "streaming": streaming,
    }


def validate_turn_manifest(value: Mapping[str, Any], policy: ManifestPolicy | None = None) -> dict[str, Any]:
    """Validate and project the closed v1 turn-create contract.

    The returned object is a fresh JSON-compatible projection.  Unknown keys,
    coercions and client-controlled policy values never reach persistence.
    """
    if policy is None:
        policy = ManifestPolicy()
    if not isinstance(value, Mapping):
        _fail("turn manifest must be an object")
    allowed = {"schema_version", "user_id", "turn_id", "origin_device_id", "client_created_at", "current_project_number", "prefer_current_project", "parts", "text"}
    if set(value) - allowed:
        _fail("turn manifest contains unsupported fields")
    schema_version = value.get("schema_version")
    if schema_version != 1 or isinstance(schema_version, bool) or not isinstance(schema_version, int):
        _fail("schema_version must be integer 1")
    user_id = _bounded_string(value.get("user_id"), "user_id")
    turn_id = value.get("turn_id")
    if not isinstance(turn_id, str) or TURN_ID_RE.fullmatch(turn_id) is None:
        _fail("turn_id must be a UUID string")
    origin = _bounded_string(value.get("origin_device_id"), "origin_device_id")
    created = _rfc3339(value.get("client_created_at"))
    project = value.get("current_project_number")
    if project is not None:
        project = _bounded_string(project, "current_project_number")
    prefer = value.get("prefer_current_project", False)
    if not isinstance(prefer, bool):
        _fail("prefer_current_project must be boolean")
    has_text = "text" in value
    parts_value = value.get("parts")
    if has_text:
        if not isinstance(value.get("text"), str):
            _fail("text must be a string")
        text = value["text"]
        try:
            text.encode("utf-8", "strict")
        except UnicodeEncodeError:
            _fail("text is not valid UTF-8")
        if not text:
            _fail("text must be non-empty")
        if parts_value not in (None, []):
            _fail("text shortcut cannot be combined with non-empty parts")
        parts_value = [{"part_id": "text-1", "kind": "text", "mime": "text/plain", "declared_bytes": len(text.encode("utf-8")), "declared_sha256": None, "relationship": None, "caption_hash": None, "duration_ms": None, "streaming": False}]
    elif parts_value is None:
        _fail("parts must be an array")
    if not isinstance(parts_value, list) or not 1 <= len(parts_value) <= policy.max_parts:
        _fail("parts must contain between one and the configured maximum number of entries")
    seen: set[str] = set()
    parts = [_part(part, policy, seen=seen) for part in parts_value]
    if sum(part["kind"] == "audio" for part in parts) > 1:
        _fail("at most one audio part is allowed")
    known_total = sum(part["declared_bytes"] or 0 for part in parts)
    if known_total > policy.max_turn_bytes:
        raise ValidationError("turn exceeds configured byte limit")
    return {
        "schema_version": 1,
        "user_id": user_id,
        "turn_id": turn_id,
        "origin_device_id": origin,
        "client_created_at": created,
        "current_project_number": project,
        "prefer_current_project": prefer,
        "parts": parts,
    }


def strict_json_loads(raw: bytes | str) -> Any:
    """Decode network JSON without duplicate keys, NaN or lone surrogates."""
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", "strict")
    elif isinstance(raw, str):
        text = raw
    else:
        raise ManifestValidationError("JSON body is invalid")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ManifestValidationError("JSON object contains duplicate keys")
            result[key] = item
        return result

    def constant(token: str) -> Any:
        raise ManifestValidationError("JSON number is not finite")

    try:
        result = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
        canonical_json(result)
    except (UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, ManifestValidationError):
            raise
        raise ManifestValidationError("JSON body is invalid") from exc
    return result


__all__ = ["ManifestPolicy", "ManifestValidationError", "UnsupportedManifestMediaError", "validate_turn_manifest", "strict_json_loads"]
