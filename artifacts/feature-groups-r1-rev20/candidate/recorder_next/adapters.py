"""Provider and Hermes seams used by the standalone server.

The server owns durable receipts; these adapters deliberately do not attempt to
change Hermes core or make an exactly-once claim about a remote chat call.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import socket
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import quote
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .canonical import sha256_bytes
from .models import AsrResult, HermesResult, RouterDecision, TTSResult


class CredentialError(ValueError):
    """Raised when the configured Hermes credential is unsafe or malformed."""


def _trusted_systemd_credential_path(path: str | os.PathLike[str]) -> tuple[Path, str] | None:
    """Return the trusted systemd credential root and direct child name.

    A system manager may own the credential inode and add a named read ACL for
    the service UID.  That is intentionally trusted only for a direct child of
    the manager-provided ``$CREDENTIALS_DIRECTORY``; arbitrary paths continue
    through the strict owner-only checks below.
    """

    raw_root = os.environ.get("CREDENTIALS_DIRECTORY")
    raw_path = os.fspath(path)
    if not raw_root or not os.path.isabs(raw_root) or not os.path.isabs(raw_path):
        return None
    root = Path(os.path.normpath(raw_root))
    candidate = Path(os.path.abspath(raw_path))
    if root == Path(os.sep):
        return None
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return None
    if len(relative.parts) != 1 or relative.name in {"", ".", ".."}:
        return None
    return root, relative.name


def _open_directory_without_symlinks(path: Path) -> int:
    """Open an absolute directory one component at a time without links."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(os.sep, flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


def _open_api_key_file(path: str | os.PathLike[str]) -> tuple[int, bool]:
    """Open the file and report whether systemd credential trust was used."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    trusted = _trusted_systemd_credential_path(path)
    if trusted is None:
        return os.open(os.fspath(path), flags), False

    root, leaf = trusted
    root_descriptor = _open_directory_without_symlinks(root)
    try:
        root_info = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) != 0o550:
            raise CredentialError("credential directory is untrusted")
        return os.open(leaf, flags, dir_fd=root_descriptor), True
    finally:
        os.close(root_descriptor)


def _read_api_key_file(path: str | os.PathLike[str]) -> str:
    """Read one API_SERVER_KEY without exposing its value.

    Direct source files must be owned by the running UID and use exactly 0400
    or 0600.  A root-owned 0440 file is accepted only when systemd supplied it
    as a direct child of its trusted 0550 credential directory.
    """

    try:
        descriptor, trusted = _open_api_key_file(path)
    except CredentialError:
        raise
    except OSError:
        raise CredentialError("credential file is missing or unreadable") from None

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise CredentialError("credential file must be regular")
        permissions = stat.S_IMODE(info.st_mode)
        if trusted:
            if info.st_uid != 0 or permissions != 0o440:
                raise CredentialError("systemd credential metadata is unsafe")
        else:
            if info.st_uid != os.getuid():
                raise CredentialError("credential file ownership is unsafe")
            if permissions not in {0o400, 0o600}:
                raise CredentialError("credential file permissions are unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(4097)
    except CredentialError:
        raise
    except (OSError, ValueError):
        raise CredentialError("credential file is unreadable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if not raw or len(raw) > 4096:
        raise CredentialError("credential file format is invalid")
    if raw.endswith(b"\r\n"):
        line_bytes = raw[:-2]
    elif raw.endswith(b"\n"):
        line_bytes = raw[:-1]
    else:
        line_bytes = raw
    if b"\r" in line_bytes or b"\n" in line_bytes:
        raise CredentialError("credential file format is invalid")
    try:
        line = line_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise CredentialError("credential file format is invalid") from None
    if not line.startswith("API_SERVER_KEY="):
        raise CredentialError("credential file format is invalid")
    token = line[len("API_SERVER_KEY=") :]
    if not token or any(not 0x21 <= ord(character) <= 0x7E for character in token):
        raise CredentialError("credential file format is invalid")
    return token


class RouterAdapter(Protocol):
    def decide(self, turn: Mapping[str, Any], projects: list[Mapping[str, Any]]) -> RouterDecision | None: ...


class HermesGateway(Protocol):
    def submit(self, *, session_key: str, request: Mapping[str, Any], submission_id: str, marker: str) -> HermesResult | None: ...

    def history(self, *, session_key: str, marker: str) -> HermesResult | None: ...

    def history_messages(self, *, session_key: str, marker: str) -> list[HermesResult]: ...


class ASRProvider(Protocol):
    name: str

    def transcribe(self, audio: bytes, *, turn_id: str, generation: int) -> AsrResult: ...


class TTSProvider(Protocol):
    name: str

    def synthesize(self, text: str, *, artifact_id: str) -> TTSResult: ...


class ScheduleCreateAdapter(Protocol):
    def schedule_create(self, command: Mapping[str, Any]) -> dict[str, Any]: ...


class TrustedScheduleCreateAdapter:
    """Structured Recorder-side seam; apps never call the store directly."""

    def __init__(self, store: Any):
        self.store = store

    def schedule_create(self, command: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(command, Mapping):
            raise TypeError("schedule_create command must be an object")
        return self.store.create_schedule(command)


TrustedScheduleAdapter = TrustedScheduleCreateAdapter


class DeterministicRouter:
    """Small fixture-safe router; production deployments inject the agent seam."""

    def decide(self, turn: Mapping[str, Any], projects: list[Mapping[str, Any]]) -> RouterDecision | None:
        current = turn.get("current_project_number")
        active = [project for project in projects if project.get("status") == "active"]
        selected = next((project for project in active if project.get("project_number") == current), None)
        if current and selected is None:
            # The frozen contract forbids silently falling back from an invalid
            # explicitly supplied project.  Returning None lets the service
            # commit the fixed routing error instead.
            return None
        if selected is None:
            if not active:
                return None
            selected = active[0]
        return RouterDecision(
            route_decision_id=f"fixture-route:{turn['turn_id']}",
            project_id=selected["stable_project_id"],
            session_key=selected["default_session_key"],
            project_record_version=int(selected["record_version"]),
            routed_text="요청을 프로젝트 세션에 전달했습니다.",
            decision_reason_code="fixture_current_project" if current else "fixture_first_active_project",
        )


class StaticRouter:
    """Test/operation adapter returning a precomputed decision by turn id."""

    def __init__(self, decisions: Mapping[str, RouterDecision | None]):
        self.decisions = dict(decisions)

    def decide(self, turn: Mapping[str, Any], projects: list[Mapping[str, Any]]) -> RouterDecision | None:
        return self.decisions.get(turn["turn_id"])


class MemoryHermesGateway:
    """Deterministic gateway fixture with optional ambiguous responses."""

    def __init__(self, responses: Mapping[str, HermesResult | None] | None = None):
        self.responses = dict(responses or {})
        self.history_responses: dict[str, HermesResult | None] = {}
        self.history_message_responses: dict[str, list[HermesResult]] = {}
        self.calls: list[dict[str, Any]] = []

    def submit(self, *, session_key: str, request: Mapping[str, Any], submission_id: str, marker: str) -> HermesResult | None:
        self.calls.append({"kind": "submit", "session_key": session_key, "submission_id": submission_id, "marker": marker, "request": dict(request)})
        return self.responses.get(submission_id)

    def history(self, *, session_key: str, marker: str) -> HermesResult | None:
        self.calls.append({"kind": "history", "session_key": session_key, "marker": marker})
        return self.history_responses.get(marker)

    def history_messages(self, *, session_key: str, marker: str) -> list[HermesResult]:
        values = self.history_message_responses.get(marker)
        if values is not None:
            return list(values)
        single = self.history_responses.get(marker)
        return [single] if single is not None else []


class HttpHermesGateway:
    """Minimal adapter for the existing Hermes HTTP session/chat seam."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        gateway_session_key: str | None = None,
        api_key_file: str | os.PathLike[str] | None = None,
        attachment_resolver: Any | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.gateway_session_key = gateway_session_key
        self._api_key = _read_api_key_file(api_key_file) if api_key_file is not None else None
        self._attachment_resolver = attachment_resolver

    def _session_headers(self, session_key: str) -> dict[str, str]:
        headers = {"X-Hermes-Session-Key": session_key}
        if self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _request(self, method: str, path: str, payload: Mapping[str, Any] | None = None, *, extra_headers: Mapping[str, str] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json", **dict(extra_headers or {})},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            raw = response.read()
        return json.loads(raw.decode("utf-8")) if raw else {}

    @staticmethod
    def _attachment_references(
        projected: Mapping[str, Any],
        *,
        fallback_scope: str | None = None,
        require_complete: bool = True,
    ) -> list[dict[str, Any]]:
        parts = projected.get("parts")
        if not isinstance(parts, list):
            return []
        turn_id = projected.get("turn_id") or fallback_scope
        references: list[dict[str, Any]] = []
        for part in parts:
            if not isinstance(part, Mapping):
                raise ValueError("attachment part must be an object")
            kind = part.get("kind")
            # Text and audio are represented by the normalized input when
            # available.  Every other completed part needs an opaque fetch
            # reference or the request must fail closed.
            is_attachment = kind in {"attachment", "image", "document", "file", "binary"} or (kind == "text" and not part.get("text"))
            if not is_attachment:
                continue
            if part.get("status") != "COMPLETE":
                if not require_complete:
                    continue
                raise ValueError("attachment part is not complete")
            reference_turn_id = part.get("turn_id") or turn_id
            if not isinstance(reference_turn_id, str) or not reference_turn_id:
                raise ValueError("attachment projection requires turn_id")
            part_id = part.get("part_id")
            mime = part.get("mime")
            digest = part.get("whole_stream_sha256") or part.get("declared_sha256")
            byte_length = part.get("total_bytes")
            if byte_length is None:
                byte_length = part.get("declared_bytes")
            if not isinstance(part_id, str) or not part_id or not isinstance(mime, str) or not mime:
                raise ValueError("attachment projection is missing identity or MIME")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                raise ValueError("attachment projection requires a SHA-256 digest")
            if byte_length is not None and (
                not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length < 0
            ):
                raise ValueError("attachment projection requires a valid byte length")
            reference = f"recorder://v1/turns/{quote(reference_turn_id, safe='')}/parts/{quote(part_id, safe='')}?sha256={digest}"
            references.append(
                {
                    "reference": reference,
                    "part_id": part_id,
                    "kind": kind,
                    "mime": mime,
                    "byte_length": byte_length,
                    "sha256": digest,
                }
            )
        return references

    def submit(self, *, session_key: str, request: Mapping[str, Any], submission_id: str, marker: str) -> HermesResult | None:
        # The durable session_ingress row stores an envelope containing the
        # normalized request plus route metadata.  Project only the inner
        # request into Hermes.  Attachments use opaque, hash-bound references;
        # spool paths, manifests, and device metadata never cross this seam.
        projected_value = request.get("request") if isinstance(request.get("request"), Mapping) else request
        if not isinstance(projected_value, Mapping):
            raise ValueError("Hermes request projection must be an object")
        projected = projected_value
        body = {"input": projected.get("input") or projected.get("text") or ""}
        references = self._attachment_references(
            projected,
            fallback_scope=None if self._attachment_resolver is not None else submission_id,
            require_complete=True,
        )
        if references and self._attachment_resolver is None:
            raise ValueError("attachment byte resolver is required")
        if not body["input"] and not references:
            raise ValueError("attachment-only projection has no complete references")
        if references:
            if self._attachment_resolver is not None:
                resolved: list[dict[str, Any]] = []
                for reference in references:
                    try:
                        fetched = self._attachment_resolver(reference["reference"])
                    except Exception as exc:
                        raise ValueError("attachment resolver failed") from exc
                    if not isinstance(fetched, Mapping):
                        raise ValueError("attachment resolver returned an invalid result")
                    raw = fetched.get("body")
                    if not isinstance(raw, bytes) or not raw:
                        raise ValueError("attachment resolver returned invalid bytes")
                    digest = fetched.get("sha256")
                    mime = fetched.get("mime")
                    length = fetched.get("byte_length", len(raw))
                    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                        raise ValueError("attachment resolver returned an invalid hash")
                    if digest.lower() != reference["sha256"].lower() or sha256_bytes(raw) != digest.lower():
                        raise ValueError("attachment resolver bytes do not match the declared hash")
                    if not isinstance(length, int) or isinstance(length, bool) or length != len(raw):
                        raise ValueError("attachment resolver bytes do not match the declared size")
                    if not isinstance(mime, str) or not mime or mime.split(";", 1)[0].lower() != reference["mime"].split(";", 1)[0].lower():
                        raise ValueError("attachment resolver MIME does not match the declared MIME")
                    delivered = dict(reference)
                    delivered["byte_length"] = len(raw)
                    delivered["data_url"] = f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"
                    resolved.append(delivered)
                references = resolved
            body["attachment_schema"] = "recorder-next/attachment-reference/v1"
            body["attachments"] = references
            if not body["input"]:
                body["input"] = "Process the attached file(s) using the provided references."
        encoded_session = quote(session_key, safe="")
        body["marker"] = marker
        body["hermes_submission_id"] = submission_id
        try:
            headers = self._session_headers(session_key)
            headers["Idempotency-Key"] = submission_id
            result = self._request("POST", f"/api/sessions/{encoded_session}/chat", body, extra_headers=headers)
        except (urllib.error.URLError, TimeoutError):
            return None
        return self._parse_result(result)

    def history(self, *, session_key: str, marker: str) -> HermesResult | None:
        values = self.history_messages(session_key=session_key, marker=marker)
        return values[-1] if values else None

    def history_messages(self, *, session_key: str, marker: str) -> list[HermesResult]:
        encoded_session = quote(session_key, safe="")
        try:
            result = self._request("GET", f"/api/sessions/{encoded_session}/messages", extra_headers=self._session_headers(session_key))
        except (urllib.error.URLError, TimeoutError):
            return []
        messages = result.get("messages", result if isinstance(result, list) else [])
        if not isinstance(messages, list):
            return []
        marker_index = -1
        for index, message in enumerate(messages):
            if marker in json.dumps(message, ensure_ascii=False, sort_keys=True):
                marker_index = index
        if marker_index < 0:
            return []
        parsed: list[HermesResult] = []
        for message in messages[marker_index + 1 :]:
            if not isinstance(message, Mapping):
                continue
            role = str(message.get("role") or message.get("author_role") or "assistant")
            if role not in {"assistant", "model", "bot"}:
                continue
            content = message.get("content") or message.get("assistant_content")
            if isinstance(content, list):
                content = "".join(str(item.get("text", "")) for item in content if isinstance(item, Mapping))
            if content:
                parsed.append(HermesResult(str(message.get("id") or marker), str(content), True, "hermes-history"))
        return parsed

    @staticmethod
    def _parse_result(result: Any) -> HermesResult | None:
        if not isinstance(result, Mapping):
            return None
        text = result.get("text") or result.get("content") or result.get("assistant_content")
        if isinstance(text, list):
            text = "".join(str(item.get("text", "")) for item in text if isinstance(item, Mapping))
        if not text:
            return None
        return HermesResult(
            str(result.get("assistant_message_id") or result.get("message_id") or result.get("id") or "hermes-response"),
            str(text),
            True,
            "hermes-chat",
        )


@dataclass
class StaticASRProvider:
    name: str
    result: AsrResult

    def transcribe(self, audio: bytes, *, turn_id: str, generation: int) -> AsrResult:
        return self.result


@dataclass
class StaticTTSProvider:
    name: str = "fixture"
    prefix: bytes = b"ID3FIXTURE"

    def synthesize(self, text: str, *, artifact_id: str) -> TTSResult:
        return TTSResult(self.prefix + text.encode("utf-8"), mode="file", content_type="audio/mpeg")


class ProviderFailure(RuntimeError):
    """Safe classification for a production provider failure.

    The exception deliberately exposes only a bounded class and HTTP status;
    provider response bodies, credentials, transcript text, and request bytes
    never become part of its string representation.
    """

    def __init__(self, kind: str, *, retryable: bool, status_code: int | None = None):
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", kind):
            kind = "provider_error"
        self.kind = kind
        self.retryable = bool(retryable)
        self.status_code = status_code
        suffix = f" ({status_code})" if status_code is not None else ""
        super().__init__(f"provider failure: {kind}{suffix}")


def _read_provider_credential(path: str | os.PathLike[str]) -> str:
    """Read one owner-only provider token without exposing its value."""

    try:
        descriptor, trusted = _open_api_key_file(path)
    except CredentialError:
        raise
    except OSError:
        raise CredentialError("provider credential file is missing or unreadable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise CredentialError("provider credential file must be regular")
        permissions = stat.S_IMODE(info.st_mode)
        if trusted:
            if info.st_uid != 0 or permissions != 0o440:
                raise CredentialError("systemd provider credential metadata is unsafe")
        elif info.st_uid != os.getuid() or permissions not in {0o400, 0o600}:
            raise CredentialError("provider credential metadata is unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(4097)
    except CredentialError:
        raise
    except (OSError, ValueError):
        raise CredentialError("provider credential file is unreadable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > 4096:
        raise CredentialError("provider credential format is invalid")
    line_bytes = raw[:-2] if raw.endswith(b"\r\n") else raw[:-1] if raw.endswith(b"\n") else raw
    if b"\r" in line_bytes or b"\n" in line_bytes:
        raise CredentialError("provider credential format is invalid")
    try:
        line = line_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise CredentialError("provider credential format is invalid") from None
    for prefix in ("API_SERVER_KEY=", "API_KEY=", "TOKEN="):
        if line.startswith(prefix):
            line = line[len(prefix) :]
            break
    if not line or any(not 0x21 <= ord(character) <= 0x7E for character in line):
        raise CredentialError("provider credential format is invalid")
    return line


def _provider_failure_for_http(status_code: int) -> ProviderFailure:
    if status_code == 429:
        return ProviderFailure("rate_limited", retryable=True, status_code=status_code)
    if status_code == 408:
        return ProviderFailure("timeout", retryable=True, status_code=status_code)
    if 500 <= status_code <= 599:
        return ProviderFailure("server", retryable=True, status_code=status_code)
    if status_code in {401, 403}:
        return ProviderFailure("auth", retryable=False, status_code=status_code)
    if status_code == 415:
        return ProviderFailure("unsupported_media", retryable=False, status_code=status_code)
    if status_code in {409, 425}:
        return ProviderFailure("transport", retryable=True, status_code=status_code)
    return ProviderFailure("client", retryable=False, status_code=status_code)


class _HTTPProvider:
    def __init__(
        self,
        endpoint: str,
        *,
        timeout: float,
        credential_file: str | os.PathLike[str] | None,
        health_path: str | None = None,
        capability_path: str | None = None,
    ):
        if not isinstance(endpoint, str) or not endpoint.startswith(("http://", "https://")):
            raise ValueError("provider endpoint must use HTTP or HTTPS")
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.username or parsed.password or any(
            key.lower() in {"key", "token", "secret", "password", "authorization"}
            for key, _value in (part.split("=", 1) for part in parsed.query.split("&") if "=" in part)
        ):
            raise ValueError("provider endpoint contains credentials")
        if timeout <= 0:
            raise ValueError("provider timeout must be positive")
        self.endpoint = endpoint
        self.timeout = float(timeout)
        self.health_path = self._validate_probe_path(health_path)
        self.capability_path = self._validate_probe_path(capability_path)
        self._credential = _read_provider_credential(credential_file) if credential_file is not None else None

    @staticmethod
    def _validate_probe_path(path: str | None) -> str | None:
        if path is None:
            return None
        if not isinstance(path, str) or not path.startswith("/") or len(path) > 256 or any(ord(char) < 0x20 for char in path):
            raise ValueError("provider probe path is invalid")
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("provider probe path must be an origin-relative path")
        return path

    def _request(self, payload: Mapping[str, Any], *, max_response_bytes: int = 16 * 1024 * 1024) -> tuple[str, bytes]:
        if not isinstance(max_response_bytes, int) or max_response_bytes < 1:
            raise ValueError("provider response limit is invalid")
        body = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json, audio/mpeg", "Content-Type": "application/json"}
        if self._credential is not None:
            headers["Authorization"] = f"Bearer {self._credential}"
        request = urllib.request.Request(self.endpoint, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(max_response_bytes + 1)
                if len(raw) > max_response_bytes:
                    raise ProviderFailure("response_too_large", retryable=False)
                return response.headers.get("Content-Type", ""), raw
        except urllib.error.HTTPError as exc:
            raise _provider_failure_for_http(exc.code) from None
        except (socket.timeout, TimeoutError):
            raise ProviderFailure("timeout", retryable=True) from None
        except urllib.error.URLError:
            raise ProviderFailure("transport", retryable=True) from None

    def _probe(self, path: str | None) -> dict[str, Any]:
        if path is None:
            return {"configured": False}
        parsed = urllib.parse.urlsplit(self.endpoint)
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        headers = {"Accept": "application/json"}
        if self._credential is not None:
            headers["Authorization"] = f"Bearer {self._credential}"
        request = urllib.request.Request(url, method="GET", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(64 * 1024 + 1)
                status_code = int(getattr(response, "status", 200))
        except urllib.error.HTTPError as exc:
            raise _provider_failure_for_http(exc.code) from None
        except (socket.timeout, TimeoutError):
            raise ProviderFailure("timeout", retryable=True) from None
        except urllib.error.URLError:
            raise ProviderFailure("transport", retryable=True) from None
        if status_code < 200 or status_code >= 300 or len(raw) > 64 * 1024:
            raise ProviderFailure("malformed_probe", retryable=False, status_code=status_code)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderFailure("malformed_probe", retryable=False) from None
        if not isinstance(payload, Mapping):
            raise ProviderFailure("malformed_probe", retryable=False)
        allowed = {"ok", "ready", "status", "provider", "model", "profile", "version", "capabilities", "media_types"}
        result: dict[str, Any] = {}
        for key in allowed:
            value = payload.get(key)
            if isinstance(value, (str, int, float, bool)):
                result[key] = value
            elif key in {"capabilities", "media_types"} and isinstance(value, list) and all(isinstance(item, str) and len(item) <= 128 for item in value):
                result[key] = list(value)
        return result

    def health_check(self) -> dict[str, Any]:
        result = self._probe(self.health_path)
        if result.get("ok") is False or result.get("ready") is False:
            raise ProviderFailure("provider_unavailable", retryable=True)
        return result

    def capability_check(self) -> dict[str, Any]:
        return self._probe(self.capability_path)


class HttpASRProvider(_HTTPProvider):
    """Production HTTP ASR adapter with fail-closed response parsing."""

    name = "http-asr"
    mode = "remote"

    def __init__(
        self,
        endpoint: str,
        *,
        model: str,
        timeout: float = 10.0,
        credential_file: str | os.PathLike[str] | None,
        language: str = "ko-KR",
        max_bytes: int | None = None,
        media_types: Sequence[str] | None = None,
        health_path: str | None = None,
        capability_path: str | None = None,
    ):
        if not isinstance(model, str) or not model:
            raise ValueError("ASR model is required")
        self.model = model
        self.language = language
        self.max_bytes = max_bytes
        self.media_types = tuple(media_types or ("audio/wav", "audio/x-wav"))
        if any(not isinstance(media_type, str) or not media_type.startswith("audio/") for media_type in self.media_types):
            raise ValueError("ASR media types must be audio MIME types")
        super().__init__(endpoint, timeout=timeout, credential_file=credential_file, health_path=health_path, capability_path=capability_path)

    def transcribe(self, audio: bytes, *, turn_id: str, generation: int) -> AsrResult:
        if not isinstance(audio, bytes) or not audio or (self.max_bytes is not None and len(audio) > self.max_bytes):
            raise ProviderFailure("unsupported_media", retryable=False)
        content_type, raw = self._request(
            {
                "model": self.model,
                "language": self.language,
                "audio_base64": base64.b64encode(audio).decode("ascii"),
                "turn_id": turn_id,
                "generation": generation,
            },
            max_response_bytes=16 * 1024 * 1024,
        )
        del content_type
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderFailure("malformed_success", retryable=False) from None
        if not isinstance(payload, Mapping):
            raise ProviderFailure("malformed_success", retryable=False)
        outcome = payload.get("outcome")
        if outcome in {"NO_SPEECH", "no_speech", "empty"}:
            return AsrResult(
                "NO_SPEECH",
                metadata={
                    "mode": self.mode,
                    "endpoint_contract": self.endpoint,
                    "provider": self.name,
                    "model": self.model,
                    "input_sha256": sha256_bytes(audio),
                    "content_type": "audio/wav",
                    "byte_size": len(audio),
                    "attempt_identity": f"{turn_id}:{generation}",
                },
            )
        text = payload.get("transcript") or payload.get("text")
        if isinstance(text, str) and text.strip():
            normalized = text.strip()
            return AsrResult(
                "VALID_TRANSCRIPT",
                transcript=normalized,
                metadata={
                    "mode": self.mode,
                    "endpoint_contract": self.endpoint,
                    "provider": self.name,
                    "model": self.model,
                    "input_sha256": sha256_bytes(audio),
                    "output_sha256": sha256_bytes(normalized.encode("utf-8")),
                    "content_type": "audio/wav",
                    "byte_size": len(audio),
                    "attempt_identity": f"{turn_id}:{generation}",
                },
            )
        raise ProviderFailure("malformed_success", retryable=False)


class NemotronASRProvider(HttpASRProvider):
    """Named Nemotron-compatible ASR adapter for explicit configurations."""

    name = "nemotron"
    mode = "nemotron"


class WhisperASRProvider(HttpASRProvider):
    """Named Whisper-compatible ASR adapter for explicit configurations."""

    name = "whisper-compatible"
    mode = "whisper"


PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _hermes_profile_endpoint(base_url: str, path: str, profile: str) -> str:
    if not PROFILE_RE.fullmatch(profile):
        raise ValueError("Hermes profile must be a bounded identifier")
    return f"{base_url.rstrip('/')}{path}?profile={quote(profile, safe='')}"


def _safe_provider_name(value: Any) -> str:
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        return value
    return "hermes"


class HermesAudioASRProvider(_HTTPProvider):
    """Use Hermes' profile-scoped configured STT chain as the default ASR."""

    name = "hermes"
    mode = "hermes"

    def __init__(
        self,
        base_url: str,
        *,
        profile: str = "default",
        timeout: float = 10.0,
        credential_file: str | os.PathLike[str] | None,
        max_bytes: int | None = None,
        health_path: str | None = "/health",
        capability_path: str | None = "/api/audio/voice-config",
    ):
        self.profile = profile
        self.max_bytes = max_bytes
        self.endpoint_contract = "/api/audio/transcribe?profile=" + quote(profile, safe="")
        super().__init__(
            _hermes_profile_endpoint(base_url, "/api/audio/transcribe", profile),
            timeout=timeout,
            credential_file=credential_file,
            health_path=health_path,
            capability_path=capability_path,
        )

    def transcribe(self, audio: bytes, *, turn_id: str, generation: int) -> AsrResult:
        if not isinstance(audio, bytes) or not audio or (self.max_bytes is not None and len(audio) > self.max_bytes):
            raise ProviderFailure("oversized_or_empty_media", retryable=False)
        data_url = "data:audio/wav;base64," + base64.b64encode(audio).decode("ascii")
        _content_type, raw = self._request({"audio": data_url}, max_response_bytes=16 * 1024 * 1024)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderFailure("malformed_response", retryable=False) from None
        if not isinstance(payload, Mapping):
            raise ProviderFailure("malformed_response", retryable=False)
        nested = payload.get("result") if isinstance(payload.get("result"), Mapping) else payload
        outcome = nested.get("outcome") or nested.get("status") if isinstance(nested, Mapping) else None
        provider_value = nested.get("provider") if isinstance(nested, Mapping) else None
        if isinstance(outcome, str) and outcome.lower().replace("-", "_") in {"no_speech", "empty", "no_audio"}:
            return AsrResult("NO_SPEECH", metadata={"mode": self.mode, "provider": _safe_provider_name(provider_value or payload.get("provider")), "hermes_profile": self.profile, "endpoint_contract": self.endpoint_contract, "input_sha256": sha256_bytes(audio), "content_type": "audio/wav", "byte_size": len(audio), "attempt_identity": f"{turn_id}:{generation}"})
        text = nested.get("text") or nested.get("transcript") or nested.get("transcription") if isinstance(nested, Mapping) else None
        if not isinstance(text, str) or not text.strip():
            raise ProviderFailure("malformed_response", retryable=False)
        normalized = text.strip()
        return AsrResult(
            "VALID_TRANSCRIPT",
            transcript=normalized,
            metadata={
                "mode": self.mode,
                "hermes_profile": self.profile,
                "endpoint_contract": self.endpoint_contract,
                "provider": _safe_provider_name(provider_value or payload.get("provider")),
                "input_sha256": sha256_bytes(audio),
                "output_sha256": sha256_bytes(normalized.encode("utf-8")),
                "content_type": "audio/wav",
                "byte_size": len(audio),
                "attempt_identity": f"{turn_id}:{generation}",
            },
        )


class HttpTTSProvider(_HTTPProvider):
    """Production HTTP TTS adapter; requests Korean explicitly."""

    name = "http-tts"
    language = "ko-KR"

    def __init__(
        self,
        endpoint: str,
        *,
        model: str,
        voice: str,
        timeout: float = 10.0,
        credential_file: str | os.PathLike[str] | None,
        language: str = "ko-KR",
        max_bytes: int | None = None,
        rate: float | None = None,
        pitch: float | None = None,
        volume: float | None = None,
        output_format: str = "mp3",
        options: Mapping[str, Any] | None = None,
        health_path: str | None = None,
        capability_path: str | None = None,
    ):
        if not isinstance(model, str) or not model or not isinstance(voice, str) or not voice:
            raise ValueError("TTS model and voice are required")
        if language.lower() not in {"ko", "ko-kr", "korean"}:
            raise ValueError("the Recorder TTS contract requires a Korean-capable language")
        self.model = model
        self.voice = voice
        self.language = language
        self.max_bytes = max_bytes
        self.rate = rate
        self.pitch = pitch
        self.volume = volume
        self.output_format = output_format
        self.options = dict(options or {})
        if any(str(key).lower() in {"api_key", "authorization", "credential", "password", "secret", "token"} for key in self.options):
            raise ValueError("TTS options cannot contain credentials")
        super().__init__(endpoint, timeout=timeout, credential_file=credential_file, health_path=health_path, capability_path=capability_path)

    def synthesize(self, text: str, *, artifact_id: str) -> TTSResult:
        if not isinstance(text, str) or not text:
            raise ProviderFailure("malformed_request", retryable=False)
        request_payload: dict[str, Any] = {
                "model": self.model,
                "voice": self.voice,
                "language": self.language,
                "text": text,
                "artifact_id": artifact_id,
                "response_format": self.output_format,
            }
        for key, value in (("rate", self.rate), ("pitch", self.pitch), ("volume", self.volume)):
            if value is not None:
                request_payload[key] = value
        request_payload.update(self.options)
        content_type, raw = self._request(
            request_payload,
            max_response_bytes=self.max_bytes or 16 * 1024 * 1024,
        )
        returned_http_type = _audio_content_type(content_type)
        if returned_http_type is not None:
            audio = raw
            returned_type = returned_http_type
        else:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ProviderFailure("malformed_success", retryable=False) from None
            if not isinstance(payload, Mapping):
                raise ProviderFailure("malformed_success", retryable=False)
            encoded = payload.get("audio_base64") or payload.get("audio")
            if not isinstance(encoded, str) or not encoded:
                raise ProviderFailure("malformed_success", retryable=False)
            try:
                audio = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                raise ProviderFailure("malformed_success", retryable=False) from None
            returned_type = _audio_content_type(payload.get("content_type") or "audio/mpeg")
            if returned_type is None:
                raise ProviderFailure("malformed_success", retryable=False)
        if not audio or (self.max_bytes is not None and len(audio) > self.max_bytes):
            raise ProviderFailure("malformed_success", retryable=False)
        return TTSResult(
            audio,
            mode="file",
            content_type=returned_type,
            metadata={
                "provider": self.name,
                "model": self.model,
                "voice": self.voice,
                "language": self.language,
                "input_sha256": sha256_bytes(text.encode("utf-8")),
                "output_sha256": sha256_bytes(audio),
                "content_type": returned_type,
                "byte_size": len(audio),
                "attempt_identity": artifact_id,
            },
        )


class EdgeTTSProvider(HttpTTSProvider):
    """Named Edge-compatible Korean TTS adapter.

    Edge deployments may expose either a JSON wrapper or an audio response;
    ``HttpTTSProvider`` handles both while this class makes the selected
    provider identity explicit in receipts and frozen configuration.
    """

    name = "edge-tts"


def _audio_content_type(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    base = value.split(";", 1)[0].strip().lower()
    if re.fullmatch(r"audio/[a-z0-9][a-z0-9.+-]{0,31}", base):
        return base
    return None


def _decode_audio_data(value: Any) -> tuple[bytes, str]:
    if not isinstance(value, str) or not value:
        raise ProviderFailure("malformed_data_url", retryable=False)
    content_type = "audio/mpeg"
    encoded = value
    if value.startswith("data:"):
        header, separator, encoded = value.partition(",")
        if not separator or ";base64" not in header:
            raise ProviderFailure("malformed_data_url", retryable=False)
        content_type = header[5:].split(";", 1)[0] or content_type
    try:
        audio = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ProviderFailure("malformed_data_url", retryable=False) from None
    if not audio or _audio_content_type(content_type) is None:
        raise ProviderFailure("malformed_data_url", retryable=False)
    return audio, _audio_content_type(content_type) or "audio/mpeg"


class HermesAudioTTSProvider(_HTTPProvider):
    """Use Hermes' profile-scoped configured TTS chain; no direct fallback."""

    name = "hermes"
    mode = "hermes"

    def __init__(
        self,
        base_url: str,
        *,
        profile: str = "default",
        timeout: float = 10.0,
        credential_file: str | os.PathLike[str] | None,
        max_bytes: int | None = None,
        health_path: str | None = "/health",
        capability_path: str | None = "/api/audio/voice-config",
    ):
        self.profile = profile
        self.max_bytes = max_bytes
        self.endpoint_contract = "/api/audio/speak?profile=" + quote(profile, safe="")
        super().__init__(
            _hermes_profile_endpoint(base_url, "/api/audio/speak", profile),
            timeout=timeout,
            credential_file=credential_file,
            health_path=health_path,
            capability_path=capability_path,
        )

    def synthesize(self, text: str, *, artifact_id: str) -> TTSResult:
        if not isinstance(text, str) or not text.strip():
            raise ProviderFailure("malformed_request", retryable=False)
        content_type, raw = self._request({"text": text}, max_response_bytes=self.max_bytes or 16 * 1024 * 1024)
        returned_http_type = _audio_content_type(content_type)
        if returned_http_type is not None:
            audio, returned_type = raw, returned_http_type
            provider = "hermes"
        else:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ProviderFailure("malformed_response", retryable=False) from None
            if not isinstance(payload, Mapping):
                raise ProviderFailure("malformed_response", retryable=False)
            value = payload.get("audio_data_url") or payload.get("data_url") or payload.get("audio") or payload.get("audio_base64")
            audio, returned_type = _decode_audio_data(value)
            provider = _safe_provider_name(payload.get("provider"))
            if "mime" in payload:
                mime_type = _audio_content_type(payload.get("mime"))
                if mime_type is None:
                    raise ProviderFailure("malformed_response", retryable=False)
                returned_type = mime_type
        if not audio or (self.max_bytes is not None and len(audio) > self.max_bytes):
            raise ProviderFailure("malformed_response", retryable=False)
        return TTSResult(
            audio,
            mode="file",
            content_type=returned_type,
            metadata={
                "mode": self.mode,
                "hermes_profile": self.profile,
                "endpoint_contract": self.endpoint_contract,
                "provider": provider,
                "input_sha256": sha256_bytes(text.encode("utf-8")),
                "output_sha256": sha256_bytes(audio),
                "content_type": returned_type,
                "byte_size": len(audio),
                "attempt_identity": artifact_id,
            },
        )


class ChainFailure(RuntimeError):
    """A fully classified chain failure with redaction-safe target metadata."""

    def __init__(self, kind: str, statuses: list[dict[str, Any]], *, retryable: bool = False):
        self.kind = kind if re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", kind) else "chain_error"
        self.statuses = tuple(dict(item) for item in statuses)
        self.retryable = bool(retryable)
        super().__init__(f"provider chain failure: {self.kind}")


@dataclass(frozen=True)
class ProviderTarget:
    """One declared ASR/TTS target; credentials are held only by ``provider``."""

    alias: str
    kind: str
    source: str
    provider: Any
    retries: int = 0
    timeout_seconds: float = 10.0
    declared: Mapping[str, Any] = field(default_factory=dict)

    def safe_config(self) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", self.alias):
            raise ValueError("provider target alias is invalid")
        if self.kind not in {"asr", "tts"}:
            raise ValueError("provider target kind is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", self.source):
            raise ValueError("provider target source is invalid")
        source_kind = self.source.lower()
        if self.kind == "asr" and source_kind in {"edge", "edge-tts", "http-tts"}:
            raise ValueError("TTS adapter cannot be used in an ASR chain")
        if self.kind == "tts" and source_kind in {"nemotron", "whisper", "whisper-compatible", "http-asr"}:
            raise ValueError("ASR adapter cannot be used in a TTS chain")
        if not isinstance(self.retries, int) or not 0 <= self.retries <= 10:
            raise ValueError("provider target retries are invalid")
        if not isinstance(self.timeout_seconds, (int, float)) or not 0 < float(self.timeout_seconds) <= 300:
            raise ValueError("provider target timeout is invalid")
        declared = self.declared if isinstance(self.declared, Mapping) else {}
        sensitive = {"api_key", "authorization", "credential", "credential_file", "password", "secret", "token"}
        # These two fields are generated, redaction-safe metadata.  They are
        # deliberately allowed in a frozen declaration even though their
        # names contain the credential marker used to reject secrets.
        safe_credential_metadata = {"credential_configured", "credential_ref_sha256"}
        for key in declared:
            key_text = str(key).lower()
            if key_text in safe_credential_metadata or key_text == "credential_file":
                continue
            if any(token in key_text for token in sensitive):
                raise ValueError("inline provider secrets are not allowed")
        safe: dict[str, Any] = {
            "alias": self.alias,
            "kind": self.kind,
            "source": self.source,
            "retries": self.retries,
            "timeout_seconds": float(self.timeout_seconds),
            "credential_configured": bool(declared.get("credential_file") or declared.get("credential_configured")),
        }
        for key in ("profile", "model", "voice", "language", "endpoint_contract", "fallback_of", "health_path", "capability_path", "output_format", "credential_ref_sha256"):
            value = declared.get(key)
            if value is not None:
                if not isinstance(value, (str, int, float, bool)):
                    raise ValueError("provider target configuration is not scalar")
                if isinstance(value, str) and (len(value) > 256 or any(ord(char) < 0x20 for char in value)):
                    raise ValueError("provider target configuration is invalid")
                safe[key] = value
        for key in ("priority", "max_bytes"):
            value = declared.get(key)
            if value is not None:
                if not isinstance(value, int) or isinstance(value, bool):
                    raise ValueError("provider target numeric configuration is invalid")
                safe[key] = value
        media_types = declared.get("media_types")
        if media_types is not None:
            if not isinstance(media_types, list) or any(not isinstance(value, str) for value in media_types):
                raise ValueError("provider target media configuration is invalid")
            safe["media_types"] = list(media_types)
        options = declared.get("options")
        if options is not None:
            if not isinstance(options, Mapping):
                raise ValueError("provider target options are invalid")
            if any(any(token in str(key).lower() for token in sensitive) for key in options):
                raise ValueError("provider target options contain secret-like names")
            safe["options"] = {str(key): value for key, value in sorted(options.items()) if isinstance(value, (str, int, float, bool))}
        endpoint = declared.get("endpoint")
        if endpoint is not None:
            if not isinstance(endpoint, str) or len(endpoint) > 512 or not endpoint.startswith(("http://", "https://")):
                raise ValueError("provider target endpoint is invalid")
            parsed = urllib.parse.urlsplit(endpoint)
            if parsed.username or parsed.password or any(part.lower() in {"key", "token", "secret", "authorization"} for part in parsed.query.split("&") if "=" in part for part in [part.split("=", 1)[0]]):
                raise ValueError("provider target endpoint contains credentials")
            safe["endpoint"] = endpoint
        return safe


class ProviderChain:
    """Ordered, frozen, fail-closed provider execution for ASR or TTS."""

    _eligible = {"transport", "dns", "connect", "timeout", "rate_limited", "server", "provider_unavailable", "unavailable", "capacity"}

    def __init__(self, kind: str, targets: Sequence[ProviderTarget], *, overall_deadline_seconds: float = 60.0):
        if kind not in {"asr", "tts"}:
            raise ValueError("provider chain kind is invalid")
        if not targets:
            raise ValueError("provider chain must have one usable target")
        if not 0 < float(overall_deadline_seconds) <= 1800:
            raise ValueError("provider chain deadline is invalid")
        self.kind = kind
        self.targets = tuple(targets)
        self.overall_deadline_seconds = float(overall_deadline_seconds)
        safe = [target.safe_config() for target in self.targets]
        aliases = [item["alias"] for item in safe]
        if len(set(aliases)) != len(aliases):
            raise ValueError("provider chain contains duplicate aliases")
        identities = [(item.get("source"), item.get("profile"), item.get("endpoint"), item.get("model"), item.get("voice")) for item in safe]
        if len(set(identities)) != len(identities):
            raise ValueError("provider chain contains duplicate targets")
        graph = {item["alias"]: item.get("fallback_of") for item in safe if item.get("fallback_of") is not None}
        for alias in graph:
            seen: set[str] = set()
            current: str | None = alias
            while current is not None and current in graph:
                if current in seen:
                    raise ValueError("provider chain fallback cycle")
                seen.add(current)
                current = str(graph[current])
                if current not in {item["alias"] for item in safe}:
                    raise ValueError("provider chain fallback target is missing")
        self._safe_targets = tuple(safe)
        serialized = json.dumps({"kind": self.kind, "targets": self._safe_targets, "overall_deadline_seconds": self.overall_deadline_seconds}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.fingerprint = sha256_bytes(serialized)
        self.generation = self.fingerprint[:16]

    @classmethod
    def from_providers(cls, kind: str, providers: Sequence[tuple[str, Any]], *, source: str = "declared", overall_deadline_seconds: float = 60.0) -> "ProviderChain":
        targets = [ProviderTarget(alias=alias, kind=kind, source=source, provider=provider, declared={"credential_configured": True}) for alias, provider in providers]
        return cls(kind, targets, overall_deadline_seconds=overall_deadline_seconds)

    def freeze(self) -> dict[str, Any]:
        return {"version": 1, "kind": self.kind, "generation": self.generation, "fingerprint": self.fingerprint, "overall_deadline_seconds": self.overall_deadline_seconds, "targets": [dict(item) for item in self._safe_targets]}

    def validate_frozen(self, frozen: Mapping[str, Any] | None) -> None:
        if frozen is None:
            return
        if not isinstance(frozen, Mapping) or frozen.get("version") != 1 or frozen.get("kind") != self.kind or frozen.get("generation") != self.generation or frozen.get("fingerprint") != self.fingerprint or frozen.get("targets") != list(self._safe_targets):
            raise ChainFailure("chain_changed", [], retryable=False)

    @staticmethod
    def _safe_status(target: ProviderTarget, *, status: str, retry_count: int, error: ProviderFailure | None = None) -> dict[str, Any]:
        entry: dict[str, Any] = {"alias": target.alias, "source": target.source, "status": status, "retry_count": retry_count}
        if error is not None:
            entry["error_kind"] = error.kind
            if error.status_code is not None:
                entry["status_code"] = error.status_code
        return entry

    def _execute(self, operation: str, value: Any, identifier: str, *, frozen: Mapping[str, Any] | None = None) -> Any:
        self.validate_frozen(frozen)
        deadline = time.monotonic() + self.overall_deadline_seconds
        statuses: list[dict[str, Any]] = []
        for index, target in enumerate(self.targets):
            target_status: dict[str, Any] | None = None
            attempts = target.retries + 1
            for attempt in range(attempts):
                if time.monotonic() >= deadline:
                    raise ChainFailure("deadline", statuses, retryable=False)
                try:
                    request_generation = index * 100 + attempt
                    result = target.provider.transcribe(value, turn_id=identifier, generation=request_generation) if operation == "asr" else target.provider.synthesize(value, artifact_id=identifier)
                    if time.monotonic() >= deadline:
                        statuses.append(self._safe_status(target, status="deadline", retry_count=attempt))
                        raise ChainFailure("deadline", statuses, retryable=False)
                    if operation == "asr":
                        if not isinstance(result, AsrResult) or result.outcome not in {"VALID_TRANSCRIPT", "NO_SPEECH"}:
                            raise ChainFailure("malformed_success", statuses, retryable=False)
                        if result.outcome == "VALID_TRANSCRIPT":
                            if not isinstance(result.transcript, str) or not result.transcript.strip():
                                raise ChainFailure("malformed_success", statuses, retryable=False)
                            if result.transcript != result.transcript.strip():
                                result = replace(result, transcript=result.transcript.strip())
                        metadata = dict(result.metadata)
                        metadata.update({"chain_generation": self.generation, "chain_fingerprint": self.fingerprint, "winner": target.alias, "fallback_count": index, "retry_count": attempt, "source": target.source})
                        result = replace(result, metadata=metadata)
                    else:
                        if not isinstance(result, TTSResult) or not isinstance(result.audio, bytes) or not result.audio or not isinstance(result.content_type, str) or not re.fullmatch(r"audio/[A-Za-z0-9.+-]+", result.content_type):
                            raise ChainFailure("integrity_invalid", statuses, retryable=False)
                        metadata = dict(result.metadata)
                        expected = metadata.get("output_sha256")
                        actual = sha256_bytes(result.audio)
                        if expected is not None and expected != actual:
                            raise ChainFailure("integrity_invalid", statuses, retryable=False)
                        metadata.update({"chain_generation": self.generation, "chain_fingerprint": self.fingerprint, "winner": target.alias, "fallback_count": index, "retry_count": attempt, "source": target.source, "output_sha256": actual, "byte_size": len(result.audio), "content_type": result.content_type})
                        result = replace(result, metadata=metadata)
                    return result
                except ChainFailure:
                    raise
                except ProviderFailure as exc:
                    # A later target is safe only after a bounded retryable
                    # failure, or when the provider explicitly reports that it
                    # is unavailable/capacity constrained.  Permanent server
                    # and auth failures must not silently switch providers.
                    eligible = (exc.retryable and exc.kind in self._eligible) or exc.kind in {"provider_unavailable", "unavailable", "capacity"}
                    target_status = self._safe_status(target, status="retryable_failure" if eligible else "permanent_failure", retry_count=attempt, error=exc)
                    if not eligible:
                        statuses.append(target_status)
                        raise ChainFailure(exc.kind, statuses, retryable=False)
                    if attempt + 1 < attempts:
                        continue
                    statuses.append(target_status)
                except (TimeoutError, socket.timeout, urllib.error.URLError):
                    failure = ProviderFailure("transport", retryable=True)
                    target_status = self._safe_status(target, status="retryable_failure", retry_count=attempt, error=failure)
                    if attempt + 1 < attempts:
                        continue
                    statuses.append(target_status)
                except Exception:
                    failure = ProviderFailure("provider_error", retryable=False)
                    statuses.append(self._safe_status(target, status="permanent_failure", retry_count=attempt, error=failure))
                    raise ChainFailure("provider_error", statuses, retryable=False)
        raise ChainFailure("all_targets_failed", statuses, retryable=False)

    def execute_asr(self, audio: bytes, *, turn_id: str, frozen: Mapping[str, Any] | None = None) -> AsrResult:
        return self._execute("asr", audio, turn_id, frozen=frozen)

    def execute_tts(self, text: str, *, artifact_id: str, frozen: Mapping[str, Any] | None = None) -> TTSResult:
        return self._execute("tts", text, artifact_id, frozen=frozen)


HermesASRProvider = HermesAudioASRProvider
HermesTTSProvider = HermesAudioTTSProvider
ProductionASRProvider = HttpASRProvider
KoreanTTSProvider = HttpTTSProvider


class DisabledTTSProvider:
    """Explicit production-disabled TTS seam; never falls back to fixtures."""

    name = "disabled"

    def synthesize(self, text: str, *, artifact_id: str) -> TTSResult:
        raise ProviderFailure("disabled", retryable=False)
