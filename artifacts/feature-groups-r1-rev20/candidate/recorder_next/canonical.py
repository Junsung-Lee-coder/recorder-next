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
