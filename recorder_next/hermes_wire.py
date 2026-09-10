from __future__ import annotations

import base64
import binascii
import json
import math
from dataclasses import dataclass
from typing import Any, Mapping


class GatewayRequestTooLarge(ValueError):
    """Raised before a request can reach the Gateway body parser."""


class WireContractError(ValueError):
    pass


@dataclass(frozen=True)
class SubmissionContext:
    """Immutable Recorder-owned identity for one Hermes run submission."""

    submission_id: str
    subject_kind: str
    marker: str
    gateway_session_key: str
    canonical_request_sha256: str
    wire_revision: str
    request: Mapping[str, Any]
    turn_id: str | None = None
    eavesdrop_session_id: str | None = None
    segment_sequence: int | None = None
    segment_sha256: str | None = None
    run_id: str | None = None
    gateway_identity: str = "default"

    @property
    def session_key(self) -> str:
        return self.gateway_session_key

    @property
    def request_sha256(self) -> str:
        return self.canonical_request_sha256


def serialize_json(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise WireContractError("request cannot be serialized as canonical JSON") from exc


@dataclass(frozen=True)
class WirePolicy:
    gateway_max_request_bytes: int = 10_000_000
    gateway_max_response_bytes: int = 1_048_576
    text_reserve_bytes: int = 1_048_576
    session_reserve_bytes: int = 1_024

    def __post_init__(self) -> None:
        if not isinstance(self.gateway_max_request_bytes, int) or isinstance(self.gateway_max_request_bytes, bool) or not 1 <= self.gateway_max_request_bytes <= 10_000_000:
            raise ValueError("gateway_max_request_bytes must be between 1 and 10000000")
        if not isinstance(self.gateway_max_response_bytes, int) or isinstance(self.gateway_max_response_bytes, bool) or not 1 <= self.gateway_max_response_bytes <= 1_048_576:
            raise ValueError("gateway_max_response_bytes must be between 1 and 1048576")
        if self.text_reserve_bytes < 0 or self.session_reserve_bytes < 0:
            raise ValueError("wire reserves cannot be negative")

    def ensure_size(self, body: bytes) -> bytes:
        if not isinstance(body, bytes):
            raise WireContractError("serialized request must be bytes")
        if len(body) > self.gateway_max_request_bytes:
            raise GatewayRequestTooLarge("Gateway request body exceeds the configured consumer limit")
        return body


def _image_declared_bytes(value: Any) -> int | None:
    if not isinstance(value, Mapping):
        return None
    for key in ("declared_bytes", "byte_count", "bytes"):
        candidate = value.get(key)
        if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate >= 0:
            return candidate
    image_url = value.get("image_url")
    if isinstance(image_url, str) and image_url.startswith("data:"):
        try:
            payload = image_url.split(",", 1)[1]
            return (len(payload.rstrip("=")) * 3) // 4
        except (IndexError, ValueError):
            return None
    return None


def _iter_image_sizes(value: Any):
    if isinstance(value, Mapping):
        kind = value.get("type")
        if kind in {"input_image", "image", "image_url"}:
            size = _image_declared_bytes(value)
            if size is not None:
                yield size
        for child in value.values():
            yield from _iter_image_sizes(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _iter_image_sizes(child)


def _zero_text(value: Any) -> Any:
    if isinstance(value, str):
        return ""
    if isinstance(value, list):
        return [_zero_text(child) for child in value]
    if isinstance(value, tuple):
        return [_zero_text(child) for child in value]
    if isinstance(value, Mapping):
        return {key: _zero_text(child) for key, child in value.items()}
    return value


def _base64_symbols(byte_count: int) -> int:
    return 4 * ((byte_count + 2) // 3)


def estimate_run_body_upper_bound(
    body: Mapping[str, Any],
    *,
    text_reserve: int = 1_048_576,
    session_reserve: int = 1_024,
    image_declared_bytes: list[int] | None = None,
) -> int:
    """Return a conservative bound for the exact projected run envelope.

    The skeleton is measured with empty text/session values; images are charged
    using their declared bytes and base64 expansion.  The reserves cover JSON
    escaping, router output, transcript and the session projection.
    """
    if not isinstance(body, Mapping):
        raise WireContractError("run body must be an object")
    skeleton = _zero_text(dict(body))
    skeleton_bytes = len(serialize_json(skeleton))
    sizes = image_declared_bytes if image_declared_bytes is not None else list(_iter_image_sizes(body))
    if any(not isinstance(size, int) or isinstance(size, bool) or size < 0 for size in sizes):
        raise WireContractError("image sizes must be non-negative integers")
    return skeleton_bytes + text_reserve + session_reserve + sum(_base64_symbols(size) for size in sizes)


def checked_request(body: Mapping[str, Any], policy: WirePolicy | None = None) -> bytes:
    policy = policy or WirePolicy()
    return policy.ensure_size(serialize_json(body))


def base64_size(byte_count: int) -> int:
    if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
        raise ValueError("byte_count must be non-negative integer")
    return _base64_symbols(byte_count)


__all__ = ["GatewayRequestTooLarge", "WireContractError", "SubmissionContext", "WirePolicy", "serialize_json", "estimate_run_body_upper_bound", "checked_request", "base64_size"]
