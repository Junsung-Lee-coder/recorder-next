"""Provider and Hermes seams used by the standalone server.

The server owns durable receipts; these adapters deliberately do not attempt to
change Hermes core or make an exactly-once claim about a remote chat call.
"""

from __future__ import annotations

import json
import os
import re
import stat
import urllib.error
import urllib.request
from urllib.parse import quote
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

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
        self.calls.append({"kind": "submit", "session_key": session_key, "submission_id": submission_id, "marker": marker})
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
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.gateway_session_key = gateway_session_key
        self._api_key = _read_api_key_file(api_key_file) if api_key_file is not None else None

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
            if not isinstance(turn_id, str) or not turn_id:
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
            reference = f"recorder://v1/turns/{quote(turn_id, safe='')}/parts/{quote(part_id, safe='')}?sha256={digest}"
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
        projected = request.get("request") if isinstance(request.get("request"), Mapping) else request
        body = {"input": projected.get("input") or projected.get("text") or ""}
        references = self._attachment_references(
            projected,
            fallback_scope=submission_id,
            require_complete=not bool(body["input"]),
        )
        if not body["input"] and not references:
            raise ValueError("attachment-only projection has no complete references")
        if references:
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
