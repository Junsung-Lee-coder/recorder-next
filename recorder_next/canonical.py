"""Deterministic canonical values used by the Recorder protocol."""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from typing import Any


def _reject_non_finite(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite numbers are not valid canonical JSON")
    if isinstance(value, dict):
        return {str(k): _reject_non_finite(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_reject_non_finite(v) for v in value]
    return value


def canonical_json(value: Any) -> bytes:
    """Return the RFC 8785-compatible JSON form for protocol values.

    Recorder fingerprints use strings, booleans, integers, null, arrays, and
    objects.  The stdlib encoder with sorted keys and compact separators is
    JCS-equivalent for that restricted protocol domain; non-finite numbers are
    rejected rather than silently normalized.
    """

    checked = _reject_non_finite(value)
    return json.dumps(
        checked,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def normalize_hermes_text(text: str) -> str:
    """Apply the frozen NFC + CRLF/CR-to-LF normalization only."""

    return unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))


def hermes_content_hash(text: str) -> str:
    return sha256_bytes(normalize_hermes_text(text).encode("utf-8"))


def normalize_aliases(value: Any) -> list[str]:
    """Validate and canonicalize the closed project-alias array.

    Aliases are user-visible identifiers rather than arbitrary JSON values.
    Keep this pure helper shared by HTTP and direct store callers so a caller
    cannot bypass the request DTO and commit an invalid alias before response
    projection.
    """

    if not isinstance(value, list):
        raise ValueError("aliases must be a native array")
    if len(value) > 32:
        raise ValueError("aliases must contain at most 32 items")
    normalized: list[str] = []
    for alias in value:
        if not isinstance(alias, str):
            raise ValueError("each alias must be a string")
        try:
            item = unicodedata.normalize("NFC", alias).strip()
            encoded = item.encode("utf-8", "strict")
        except (UnicodeError, UnicodeEncodeError) as exc:
            raise ValueError("alias must be valid UTF-8 text") from exc
        if not 1 <= len(item) <= 128:
            raise ValueError("each alias must contain 1 to 128 characters")
        if len(encoded) > 512:
            raise ValueError("each alias must be at most 512 UTF-8 bytes")
        if any(unicodedata.category(char) in {"Cc", "Cf"} for char in item):
            raise ValueError("aliases must not contain control characters")
        if item in normalized:
            raise ValueError("aliases must be unique after normalization")
        normalized.append(item)
    return normalized
