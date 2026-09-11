"""Provider and Hermes seams used by the standalone server.

The server owns durable receipts; these adapters deliberately do not attempt to
change Hermes core or make an exactly-once claim about a remote chat call.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import inspect
import io
import json
import os
import re
import select
import socket
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import quote
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from .canonical import sha256_bytes
from .hermes_wire import SubmissionContext, WirePolicy, serialize_json
from .media import ASRInput, MediaValidationError, validate_wav
from .models import AsrResult, HermesResult, RouterDecision, TTSResult


class _DeadlineExceeded(TimeoutError):
    """Raised when an interruptible provider I/O operation hits its deadline."""


class _ProviderResponseFramingError(ValueError):
    """Raised when an upstream response cannot be safely framed."""


class _ProviderResponseTooLargeError(ValueError):
    """Raised when an upstream response exceeds the configured byte limit."""


class _DeadlineSocket:
    """Socket facade that makes send and receive progress deadline-aware."""

    def __init__(self, sock: Any, deadline_at: float):
        self._sock = sock
        self._deadline_at = deadline_at
        self._closed = False
        self._socket_closed = False
        self._file_count = 0
        self._sock.setblocking(False)

    def _wait_for_io(self, *, readable: bool, writable: bool) -> None:
        if self._socket_closed:
            raise OSError("provider socket is closed")
        if readable:
            try:
                pending = getattr(self._sock, "pending", None)
                if callable(pending) and pending():
                    return
            except OSError:
                pass
        while True:
            remaining = self._deadline_at - time.monotonic()
            if remaining <= 0:
                raise _DeadlineExceeded("provider I/O deadline expired")
            try:
                ready_read, ready_write, _ = select.select(
                    [self._sock] if readable else [],
                    [self._sock] if writable else [],
                    [],
                    remaining,
                )
            except InterruptedError:
                continue
            if ready_read or ready_write:
                return
            raise _DeadlineExceeded("provider I/O deadline expired")

    def sendall(self, data: Any) -> None:
        view = memoryview(data)
        wait_for_read = False
        while view:
            self._wait_for_io(readable=wait_for_read, writable=not wait_for_read)
            try:
                sent = self._sock.send(view)
                wait_for_read = False
            except ssl.SSLWantReadError:
                wait_for_read = True
                continue
            except ssl.SSLWantWriteError:
                wait_for_read = False
                continue
            except (BlockingIOError, InterruptedError):
                continue
            if sent <= 0:
                raise OSError("provider socket closed during write")
            view = view[sent:]

    def send(self, data: Any, *args: Any) -> int:
        self._wait_for_io(readable=False, writable=True)
        while True:
            try:
                return self._sock.send(data, *args)
            except ssl.SSLWantReadError:
                self._wait_for_io(readable=True, writable=False)
            except ssl.SSLWantWriteError:
                self._wait_for_io(readable=False, writable=True)
            except (BlockingIOError, InterruptedError):
                self._wait_for_io(readable=False, writable=True)

    def recv_into(self, buffer: Any, *args: Any) -> int:
        wait_for_write = False
        while True:
            self._wait_for_io(readable=not wait_for_write, writable=wait_for_write)
            try:
                return self._sock.recv_into(buffer, *args)
            except ssl.SSLWantReadError:
                wait_for_write = False
            except ssl.SSLWantWriteError:
                wait_for_write = True
            except (BlockingIOError, InterruptedError):
                pass

    def recv(self, bufsize: int, *args: Any) -> bytes:
        buffer = bytearray(bufsize)
        size = self.recv_into(buffer, *args)
        return bytes(buffer[:size])

    def makefile(self, mode: str = "r", buffering: int | None = None, *args: Any, **kwargs: Any) -> Any:
        if "b" not in mode or "r" not in mode:
            return self._sock.makefile(mode, -1 if buffering is None else buffering, *args, **kwargs)
        raw = _DeadlineSocketRaw(self)
        self._file_count += 1
        if buffering == 0:
            return raw
        buffer_size = io.DEFAULT_BUFFER_SIZE if buffering is None or buffering < 0 else buffering
        return io.BufferedReader(raw, buffer_size=buffer_size)

    def _file_closed(self) -> None:
        self._file_count = max(0, self._file_count - 1)
        if self._closed and self._file_count == 0:
            self._force_close()

    def _force_close(self) -> None:
        if self._socket_closed:
            return
        self._closed = True
        self._socket_closed = True
        self._sock.close()

    def close(self) -> None:
        self._closed = True
        if self._file_count == 0:
            self._force_close()

    def fileno(self) -> int:
        if self._socket_closed:
            return -1
        return self._sock.fileno()

    def settimeout(self, value: float | None) -> None:
        if not self._socket_closed:
            self._sock.settimeout(value)

    def gettimeout(self) -> float | None:
        return None if self._socket_closed else self._sock.gettimeout()

    def __getattr__(self, name: str) -> Any:
        sock = self.__dict__.get("_sock")
        if sock is None:
            raise AttributeError(name)
        return getattr(sock, name)


class _DeadlineSocketRaw(io.RawIOBase):
    """Raw binary reader used by HTTPResponse without buffered blocking I/O."""

    def __init__(self, owner: _DeadlineSocket):
        super().__init__()
        self._owner = owner

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def readinto(self, buffer: Any) -> int:
        return self._owner.recv_into(buffer)

    def fileno(self) -> int:
        return self._owner.fileno()

    def close(self) -> None:
        if not self.closed:
            try:
                super().close()
            finally:
                self._owner._file_closed()


class _DeadlineConnectionMixin:
    """Install a deadline socket after the HTTP connection is established."""

    timeout: float | None
    sock: Any

    def __init__(self, *args: Any, deadline_at: float | None = None, **kwargs: Any):
        self._deadline_at = deadline_at
        self._deadline_socket: _DeadlineSocket | None = None
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        if self._deadline_at is None:
            getattr(super(), "connect")()
            return
        remaining = self._deadline_at - time.monotonic()
        if remaining <= 0:
            raise _DeadlineExceeded("provider I/O deadline expired")
        original_timeout = self.timeout
        if original_timeout is None or original_timeout > remaining:
            self.timeout = remaining
        try:
            getattr(super(), "connect")()
        finally:
            self.timeout = original_timeout
        if time.monotonic() >= self._deadline_at:
            getattr(super(), "close")()
            raise _DeadlineExceeded("provider I/O deadline expired")
        if self.sock is not None:
            self._deadline_socket = _DeadlineSocket(self.sock, self._deadline_at)
            self.sock = self._deadline_socket

class _DeadlineHTTPConnection(_DeadlineConnectionMixin, http.client.HTTPConnection):
    pass


class _DeadlineHTTPSConnection(_DeadlineConnectionMixin, http.client.HTTPSConnection):
    pass


class _DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(
            _DeadlineHTTPConnection,
            req,
            deadline_at=getattr(req, "_recorder_deadline_at", None),
        )


class _DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(
            _DeadlineHTTPSConnection,
            req,
            context=self._context,
            deadline_at=getattr(req, "_recorder_deadline_at", None),
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never replay a credential-bearing request at a redirected origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirects are disabled for provider requests", headers, fp)


_NO_REDIRECT_OPENER = urllib.request.build_opener(
    _DeadlineHTTPHandler(),
    _DeadlineHTTPSHandler(),
    _NoRedirectHandler(),
)


def _urlopen_no_redirect(
    request: urllib.request.Request,
    *,
    timeout: float,
    deadline_at: float | None = None,
):
    if deadline_at is not None:
        setattr(request, "_recorder_deadline_at", deadline_at)
    try:
        return _NO_REDIRECT_OPENER.open(request, timeout=timeout)
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, _DeadlineExceeded):
            raise exc.reason from None
        raise


def _close_http_error(exc: urllib.error.HTTPError) -> None:
    """Close an HTTP error and the response body it owns."""
    body = getattr(exc, "fp", None)
    try:
        exc.close()
    finally:
        if body is not None:
            body.close()


def _read_bounded_response(response: Any, limit: int, *, deadline_at: float | None = None) -> bytes:
    """Read a bounded response while enforcing one monotonic deadline."""

    headers = getattr(response, "headers", None)
    declared_values = headers.get_all("Content-Length") if headers is not None and hasattr(headers, "get_all") else None
    if declared_values is not None and len(declared_values) != 1:
        raise _ProviderResponseFramingError("provider response Content-Length is duplicated")
    declared = headers.get("Content-Length") if headers is not None else None
    declared_size: int | None = None
    if declared is not None:
        try:
            declared_size = int(declared)
        except (TypeError, ValueError):
            raise _ProviderResponseFramingError("provider response Content-Length is invalid") from None
        if declared_size < 0:
            raise _ProviderResponseFramingError("provider response Content-Length is invalid")
        if declared_size > limit:
            raise _ProviderResponseTooLargeError("provider response exceeds the configured limit")
    encoding = headers.get("Content-Encoding") if headers is not None else None
    if encoding is not None and encoding.strip().lower() not in {"", "identity"}:
        raise _ProviderResponseFramingError("provider response Content-Encoding is unsupported")
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        if deadline_at is not None and time.monotonic() >= deadline_at:
            raise TimeoutError("provider response deadline expired")
        requested = min(65_536, limit + 1 - total)
        try:
            chunk = response.read(requested)
        except socket.timeout as exc:
            raise TimeoutError("provider response deadline expired") from exc
        except (http.client.HTTPException, ValueError) as exc:
            raise _ProviderResponseFramingError("provider response body framing is invalid") from exc
        if deadline_at is not None and time.monotonic() >= deadline_at:
            raise TimeoutError("provider response deadline expired")
        if not isinstance(chunk, (bytes, bytearray)):
            raise _ProviderResponseFramingError("provider response body is invalid")
        if len(chunk) > requested:
            raise _ProviderResponseFramingError("provider response reader exceeded its bound")
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise _ProviderResponseTooLargeError("provider response exceeds the configured limit")
        chunks.append(bytes(chunk))
    if declared is not None and total != declared_size:
        raise _ProviderResponseFramingError("provider response length does not match Content-Length")
    return b"".join(chunks)


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
            raw = handle.read(4113)
    except CredentialError:
        raise
    except (OSError, ValueError):
        raise CredentialError("credential file is unreadable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    return _parse_credential_record(raw)


def _parse_credential_record(raw: bytes) -> str:
    """One ASCII record, at most 4096 token bytes and one optional final LF."""
    if len(raw) > 4112:
        raise CredentialError("credential file format is invalid")
    match = re.fullmatch(rb"API_SERVER_KEY=([A-Za-z0-9._~+/=-]{1,4096})\n?", raw)
    if match is None:
        raise CredentialError("credential file format is invalid")
    return match[1].decode("ascii")


class RouterAdapter(Protocol):
    def decide(self, turn: Mapping[str, Any], projects: list[Mapping[str, Any]]) -> RouterDecision | None: ...


class HermesGateway(Protocol):
    def submit(
        self,
        *,
        session_key: str,
        request: Mapping[str, Any],
        submission_id: str,
        marker: str,
        context: SubmissionContext | None = None,
        on_run_accepted: Callable[[str], bool] | None = None,
    ) -> HermesResult | None: ...

    def history(self, *, session_key: str, marker: str) -> HermesResult | None: ...

    def history_messages(self, *, session_key: str, marker: str) -> list[HermesResult]: ...


class ASRProvider(Protocol):
    name: str

    def transcribe(self, audio: ASRInput | bytes, *, turn_id: str, generation: int) -> AsrResult: ...


class TTSProvider(Protocol):
    name: str

    def synthesize(self, text: str, *, artifact_id: str) -> TTSResult: ...


class ScheduleCreateAdapter(Protocol):
    def schedule_create(
        self,
        command: Mapping[str, Any],
        *,
        principal: tuple[str, str] | None = None,
    ) -> dict[str, Any]: ...


class TrustedScheduleCreateAdapter:
    """Structured Recorder-side seam; apps never call the store directly."""

    def __init__(self, store: Any):
        self.store = store

    def schedule_create(
        self,
        command: Mapping[str, Any],
        *,
        principal: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(command, Mapping):
            raise TypeError("schedule_create command must be an object")
        if principal is None:
            return self.store.create_schedule(command)
        return self.store.create_schedule(command, principal=principal)


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
            routed_text=str(turn.get("input") or turn.get("transcript") or ""),
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

    def submit(
        self,
        *,
        session_key: str,
        request: Mapping[str, Any],
        submission_id: str,
        marker: str,
        context: SubmissionContext | None = None,
        on_run_accepted: Callable[[str], bool] | None = None,
    ) -> HermesResult | None:
        self.calls.append({"kind": "submit", "session_key": session_key, "submission_id": submission_id, "marker": marker, "request": dict(request)})
        result = self.responses.get(submission_id)
        if context is not None and result is not None:
            run_id = result.run_id or f"memory-run:{submission_id}"
            if on_run_accepted is not None and not on_run_accepted(run_id):
                return None
            return replace(result, run_id=run_id, submission_id=context.submission_id, turn_id=context.turn_id, marker=context.marker, session_key=context.gateway_session_key, request_sha256=context.canonical_request_sha256, subject_kind=context.subject_kind, eavesdrop_session_id=context.eavesdrop_session_id, segment_sequence=context.segment_sequence, segment_sha256=context.segment_sha256)
        return result

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
    """Recorder client for Hermes' durable, idempotent ``/v1/runs`` seam.

    The OpenAI-compatible run endpoint is intentionally used instead of the
    legacy session-chat endpoint.  ``Idempotency-Key`` is persisted by Hermes,
    so a response lost after admission can be replayed without starting a
    second agent/tool invocation.  The returned ``run_id`` is the durable
    correlation identity stored by Recorder.
    """

    durable_correlation = True
    _RUN_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "expired", "stopped"}
    _RUN_PENDING_STATUSES = {"queued", "started", "running", "in_progress", "waiting_for_approval"}

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        gateway_session_key: str | None = None,
        api_key_file: str | os.PathLike[str] | None = None,
        attachment_resolver: Any | None = None,
        max_submit_attempts: int = 2,
        poll_interval_seconds: float = 1.0,
        run_timeout_seconds: float = 120.0,
        max_request_bytes: int = 10_000_000,
        max_response_bytes: int = 1_048_576,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.gateway_session_key = gateway_session_key
        self._api_key = _read_api_key_file(api_key_file) if api_key_file is not None else None
        self._attachment_resolver = attachment_resolver
        if not isinstance(max_submit_attempts, int) or isinstance(max_submit_attempts, bool) or not 1 <= max_submit_attempts <= 5:
            raise ValueError("Hermes submission attempts must be between 1 and 5")
        if not isinstance(poll_interval_seconds, (int, float)) or isinstance(poll_interval_seconds, bool) or not 0 <= float(poll_interval_seconds) <= 60:
            raise ValueError("Hermes run poll interval must be between 0 and 60 seconds")
        if not isinstance(run_timeout_seconds, (int, float)) or isinstance(run_timeout_seconds, bool) or not 0 < float(run_timeout_seconds) <= 3600:
            raise ValueError("Hermes run timeout must be between 0 and 3600 seconds")
        if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or not 1 <= max_response_bytes <= 1_048_576:
            raise ValueError("Hermes response limit is invalid")
        self.max_submit_attempts = max_submit_attempts
        self.poll_interval_seconds = float(poll_interval_seconds)
        self.run_timeout_seconds = float(run_timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self._wire_policy = WirePolicy(
            gateway_max_request_bytes=max_request_bytes,
            gateway_max_response_bytes=max_response_bytes,
        )

    def _session_headers(self, session_key: str) -> dict[str, str]:
        headers = {"X-Hermes-Session-Key": session_key}
        if self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        extra_headers: Mapping[str, str] | None = None,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> Any:
        body = None if payload is None else self._wire_policy.ensure_size(serialize_json(payload))
        request_headers = {"Accept": "application/json", **dict(extra_headers or {})}
        if body is not None:
            request_headers.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            method=method,
            headers=request_headers,
        )
        timeout = self.timeout if timeout_seconds is None else min(self.timeout, float(timeout_seconds))
        if timeout <= 0:
            raise TimeoutError("Hermes request deadline expired")
        if deadline_at is None:
            deadline_at = time.monotonic() + timeout
        setattr(request, "_recorder_deadline_at", deadline_at)
        remaining = min(timeout, deadline_at - time.monotonic())
        if remaining <= 0:
            raise TimeoutError("Hermes request deadline expired")
        with _urlopen_no_redirect(request, timeout=remaining) as response:
            raw = _read_bounded_response(response, self.max_response_bytes, deadline_at=deadline_at)
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _request_with_timeout(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        extra_headers: Mapping[str, str] | None = None,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> Any:
        """Call the request seam while retaining compatibility test doubles."""

        kwargs: dict[str, Any] = {"extra_headers": extra_headers}
        try:
            parameters = tuple(inspect.signature(self._request).parameters.values())
        except (TypeError, ValueError):
            parameters = ()
        accepts_kwargs = any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters)
        if timeout_seconds is not None:
            if accepts_kwargs or any(parameter.name == "timeout_seconds" for parameter in parameters):
                kwargs["timeout_seconds"] = timeout_seconds
        if deadline_at is not None and (accepts_kwargs or any(parameter.name == "deadline_at" for parameter in parameters)):
            kwargs["deadline_at"] = deadline_at
        return self._request(method, path, payload, **kwargs)

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
            mime_value = part.get("mime")
            normalized_mime = mime_value.split(";", 1)[0].strip().lower() if isinstance(mime_value, str) else ""
            if kind == "document" or (kind in {"attachment", "image", "file", "binary"} and not normalized_mime.startswith("image/")):
                raise ValueError("document input is unsupported by Hermes /v1/runs")
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

    @staticmethod
    def _input_with_inline_images(text: Any, attachments: list[dict[str, Any]]) -> str | list[dict[str, Any]]:
        if isinstance(text, list):
            if not text:
                raise ValueError("Hermes input list must contain a user message")
            content: list[dict[str, Any]] = []
            for item in text:
                if not isinstance(item, Mapping):
                    raise ValueError("Hermes input messages must be objects")
                content.append(dict(item))
            if attachments:
                user_index = next((index for index in range(len(content) - 1, -1, -1) if content[index].get("role") == "user"), None)
                if user_index is None:
                    raise ValueError("Hermes multimodal input requires a user message")
                user_message = content[user_index]
                existing = user_message.get("content", "")
                if isinstance(existing, str):
                    blocks: list[dict[str, Any]] = [{"type": "input_text", "text": existing}] if existing else []
                elif isinstance(existing, list):
                    blocks = [dict(block) for block in existing if isinstance(block, Mapping)]
                    if len(blocks) != len(existing):
                        raise ValueError("Hermes user content blocks must be objects")
                else:
                    raise ValueError("Hermes user content must be text or content blocks")
                for attachment in attachments:
                    mime = str(attachment["mime"]).split(";", 1)[0].strip().lower()
                    if not mime.startswith("image/"):
                        raise ValueError("document input is unsupported by Hermes /v1/runs")
                    data_url = attachment.get("data_url")
                    if not isinstance(data_url, str) or not data_url.startswith("data:"):
                        raise ValueError("image attachment is missing an inline data URL")
                    blocks.append({"type": "input_image", "image_url": data_url})
                user_message["content"] = blocks
            return content
        if not isinstance(text, str):
            raise ValueError("Hermes input must be a string or multimodal message list")
        if not attachments:
            if not text:
                raise ValueError("Hermes projection has no input")
            return text
        blocks: list[dict[str, Any]] = []
        if text:
            blocks.append({"type": "input_text", "text": text})
        for attachment in attachments:
            mime = str(attachment["mime"]).split(";", 1)[0].strip().lower()
            if not mime.startswith("image/"):
                raise ValueError("document input is unsupported by Hermes /v1/runs")
            data_url = attachment.get("data_url")
            if not isinstance(data_url, str) or not data_url.startswith("data:"):
                raise ValueError("image attachment is missing an inline data URL")
            blocks.append({"type": "input_image", "image_url": data_url})
        if not blocks:
            raise ValueError("attachment-only projection has no supported input")
        return [{"role": "user", "content": blocks}]

    def _resolve_inline_attachments(self, projected: Mapping[str, Any], *, submission_id: str) -> list[dict[str, Any]]:
        references = self._attachment_references(
            projected,
            fallback_scope=None if self._attachment_resolver is not None else submission_id,
            require_complete=True,
        )
        if not references:
            return []
        if self._attachment_resolver is None:
            raise ValueError("attachment byte resolver is required")
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
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError("attachment exceeds Hermes inline input limit")
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
            base_mime = mime.split(";", 1)[0].strip().lower()
            delivered = dict(reference)
            delivered["mime"] = base_mime
            delivered["byte_length"] = len(raw)
            delivered["data_url"] = f"data:{base_mime};base64,{base64.b64encode(raw).decode('ascii')}"
            resolved.append(delivered)
        return resolved

    @staticmethod
    def _run_text(result: Mapping[str, Any]) -> str:
        value = result.get("output") or result.get("text") or result.get("content") or result.get("assistant_content")
        if isinstance(value, Mapping):
            value = value.get("content") or value.get("text")
        if isinstance(value, list):
            values: list[str] = []
            for item in value:
                if isinstance(item, str):
                    values.append(item)
                elif isinstance(item, Mapping):
                    text = item.get("text") or item.get("content")
                    if isinstance(text, str):
                        values.append(text)
            value = "".join(values)
        return value.strip() if isinstance(value, str) else ""

    def _parse_run_result(self, result: Any, run_id: str, context: SubmissionContext | None = None) -> HermesResult | None:
        if not isinstance(result, Mapping):
            return None
        status = str(result.get("status") or "").lower().replace("-", "_")
        if context is not None and status != "completed":
            return None
        if context is None and status and status not in self._RUN_TERMINAL_STATUSES:
            return None
        text = self._run_text(result)
        if not text:
            return None
        response_run_id = result.get("run_id") or result.get("id")
        if response_run_id is not None and response_run_id != run_id:
            return None
        assistant_id = result.get("assistant_message_id") or result.get("message_id") or result.get("response_id") or run_id
        if context is None:
            return HermesResult(str(assistant_id), text, True, "hermes-run", run_id=run_id)
        for key, expected in (("submission_id", context.submission_id), ("turn_id", context.turn_id), ("eavesdrop_session_id", context.eavesdrop_session_id), ("segment_sequence", context.segment_sequence), ("segment_sha256", context.segment_sha256), ("marker", context.marker), ("session_key", context.gateway_session_key), ("request_sha256", context.canonical_request_sha256), ("subject_kind", context.subject_kind)):
            if result.get(key) is not None and result.get(key) != expected:
                return None
        return HermesResult(
            str(assistant_id),
            text,
            True,
            "hermes-run",
            submission_id=context.submission_id,
            turn_id=context.turn_id,
            marker=context.marker,
            session_key=context.gateway_session_key,
            run_id=run_id,
            request_sha256=context.canonical_request_sha256,
            subject_kind=context.subject_kind,
            eavesdrop_session_id=context.eavesdrop_session_id,
            segment_sequence=context.segment_sequence,
            segment_sha256=context.segment_sha256,
        )

    def _submit_legacy_session_chat(
        self,
        *,
        session_key: str,
        body: Mapping[str, Any],
        headers: Mapping[str, str],
        submission_id: str,
        marker: str,
        first_error: urllib.error.HTTPError | None = None,
        deadline_at: float | None = None,
    ) -> HermesResult | None:
        """Use the older session-chat route only as a compatibility fallback.

        New deployments use ``/v1/runs`` above, whose idempotency store owns
        the downstream effect.  Keeping this fallback preserves older Hermes
        listeners and, importantly, still correlates their response rather
        than treating an arbitrary chat reply as this turn's result.
        """
        encoded_session = quote(session_key, safe="")
        chat_path = f"/api/sessions/{encoded_session}/chat"
        legacy_body = dict(body)
        legacy_body["marker"] = marker
        legacy_body["hermes_submission_id"] = submission_id
        status_code: int | None = None
        result: Any = None
        remaining = self.timeout if deadline_at is None else deadline_at - time.monotonic()
        if remaining <= 0:
            if first_error is not None:
                _close_http_error(first_error)
            return None
        if first_error is not None:
            status_code = first_error.code
            _close_http_error(first_error)
        else:
            try:
                result = self._request_with_timeout(
                    "POST",
                    chat_path,
                    legacy_body,
                    extra_headers=headers,
                    timeout_seconds=remaining,
                    deadline_at=deadline_at,
                )
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                _close_http_error(exc)
            except (urllib.error.URLError, TimeoutError):
                return None
        if status_code == 404:
            try:
                self._request_with_timeout(
                    "POST",
                    "/api/sessions",
                    {"id": session_key, "source": "api_server"},
                    extra_headers=self._session_headers(session_key),
                    timeout_seconds=deadline_at - time.monotonic() if deadline_at is not None else None,
                    deadline_at=deadline_at,
                )
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                _close_http_error(exc)
                if status_code != 409:
                    return None
            except (urllib.error.URLError, TimeoutError):
                return None
            try:
                remaining = self.timeout if deadline_at is None else deadline_at - time.monotonic()
                if remaining <= 0:
                    return None
                result = self._request_with_timeout(
                    "POST",
                    chat_path,
                    legacy_body,
                    extra_headers=headers,
                    timeout_seconds=remaining,
                    deadline_at=deadline_at,
                )
            except urllib.error.HTTPError as exc:
                _close_http_error(exc)
                return None
            except (urllib.error.URLError, TimeoutError):
                return None
        elif status_code is not None:
            return None
        parsed = self._parse_result(result)
        if parsed is None:
            return None
        if parsed.marker is not None and parsed.marker != marker:
            return None
        if parsed.submission_id is not None and parsed.submission_id != submission_id:
            return None
        return parsed

    def submit(
        self,
        *,
        session_key: str,
        request: Mapping[str, Any],
        submission_id: str,
        marker: str,
        context: SubmissionContext | None = None,
        on_run_accepted: Callable[[str], bool] | None = None,
    ) -> HermesResult | None:
        # The durable session_ingress row stores an envelope containing the
        # normalized request plus route metadata.  Only user input bytes cross
        # this seam; Recorder IDs are transport/session state, not prompt text.
        projected_value = request.get("request") if isinstance(request.get("request"), Mapping) else request
        if not isinstance(projected_value, Mapping):
            raise ValueError("Hermes request projection must be an object")
        if not isinstance(submission_id, str) or not 1 <= len(submission_id) <= 255 or any(ord(ch) < 33 or ord(ch) > 126 for ch in submission_id):
            raise ValueError("Hermes submission id is not a valid Idempotency-Key")
        json_session = request.get("session_id")
        if json_session is not None and json_session != session_key:
            raise ValueError("JSON session_id conflicts with X-Hermes-Session-Key")
        projected = projected_value
        text = projected.get("input") or projected.get("text") or ""
        attachments = self._resolve_inline_attachments(projected, submission_id=submission_id)
        if not text and not attachments:
            raise ValueError("Hermes projection has no input")
        body: dict[str, Any] = {
            "input": self._input_with_inline_images(text, attachments),
            "session_id": session_key,
        }
        headers = self._session_headers(session_key)
        headers["Idempotency-Key"] = submission_id
        if context is not None:
            if context.submission_id != submission_id or context.marker != marker or context.gateway_session_key != session_key:
                raise ValueError("Hermes submission context does not match the request")
            headers.update({
                "X-Hermes-Submission-ID": context.submission_id,
                "X-Hermes-Marker": context.marker,
                "X-Hermes-Wire-Revision": context.wire_revision,
            })
        deadline = time.monotonic() + self.run_timeout_seconds
        accepted: Mapping[str, Any] | None = None
        accepted_run_id: str | None = context.run_id if context is not None else None
        for attempt in range(self.max_submit_attempts):
            if accepted_run_id is not None:
                accepted = {"run_id": accepted_run_id}
                break
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                response = self._request_with_timeout(
                    "POST",
                    "/v1/runs",
                    body,
                    extra_headers=headers,
                    timeout_seconds=remaining,
                    deadline_at=deadline,
                )
            except urllib.error.HTTPError as exc:
                if context is None and attempt == 0:
                    return self._submit_legacy_session_chat(
                        session_key=session_key,
                        body=body,
                        headers=headers,
                        submission_id=submission_id,
                        marker=marker,
                        first_error=exc,
                        deadline_at=deadline,
                    )
                _close_http_error(exc)
                return None
            except (urllib.error.URLError, TimeoutError):
                if attempt + 1 >= self.max_submit_attempts:
                    return None
                continue
            if not isinstance(response, Mapping):
                return None
            run_id = response.get("run_id") or response.get("id")
            if isinstance(run_id, str) and run_id:
                if accepted_run_id is not None and run_id != accepted_run_id:
                    return None
                accepted_run_id = run_id
                accepted = response
                break
            return None
        if accepted is None:
            return None
        run_id = str(accepted.get("run_id") or accepted.get("id"))
        if context is not None and on_run_accepted is not None and context.run_id is None:
            try:
                if not on_run_accepted(run_id):
                    return None
            except Exception:
                return None
        immediate = self._parse_run_result(accepted, run_id, context)
        if immediate is not None:
            return immediate
        while time.monotonic() <= deadline:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                status = self._request_with_timeout(
                    "GET",
                    f"/v1/runs/{quote(run_id, safe='')}",
                    extra_headers=self._session_headers(session_key),
                    timeout_seconds=remaining,
                    deadline_at=deadline,
                )
            except (urllib.error.URLError, TimeoutError):
                if time.monotonic() >= deadline:
                    return None
                if self.poll_interval_seconds:
                    time.sleep(min(self.poll_interval_seconds, max(0.0, deadline - time.monotonic())))
                continue
            if isinstance(status, Mapping):
                normalized = str(status.get("status") or "").lower().replace("-", "_")
                parsed = self._parse_run_result(status, run_id, context)
                if parsed is not None:
                    return parsed
                if normalized in self._RUN_TERMINAL_STATUSES:
                    return None
                if normalized not in self._RUN_PENDING_STATUSES:
                    return None
            if self.poll_interval_seconds:
                time.sleep(min(self.poll_interval_seconds, max(0.0, deadline - time.monotonic())))
        return None

    def history(self, *, session_key: str, marker: str) -> HermesResult | None:
        values = self.history_messages(session_key=session_key, marker=marker)
        return values[-1] if values else None

    def history_messages(self, *, session_key: str, marker: str) -> list[HermesResult]:
        encoded_session = quote(session_key, safe="")
        deadline = time.monotonic() + self.timeout
        try:
            result = self._request_with_timeout(
                "GET",
                f"/api/sessions/{encoded_session}/messages",
                extra_headers=self._session_headers(session_key),
                timeout_seconds=self.timeout,
                deadline_at=deadline,
            )
        except urllib.error.HTTPError as exc:
            _close_http_error(exc)
            return []
        except (urllib.error.URLError, TimeoutError):
            return []
        if isinstance(result, Mapping):
            messages = result.get("messages") or result.get("data") or []
        else:
            messages = result if isinstance(result, list) else []
        if not isinstance(messages, list):
            return []
        marker_indices: list[int] = []
        for index, message in enumerate(messages):
            if not isinstance(message, Mapping):
                continue
            role = self._message_role(message)
            if role in {"user", "human", "client"} and self._message_matches_marker(message, marker):
                marker_indices.append(index)
        # A marker is a correlation token, not a substring search across the
        # entire conversation.  Multiple matching user messages are ambiguous
        # and must not produce a late result for the wrong turn.
        if len(marker_indices) != 1:
            return []
        marker_index = marker_indices[0]
        next_user = len(messages)
        for index in range(marker_index + 1, len(messages)):
            message = messages[index]
            if not isinstance(message, Mapping):
                continue
            role = self._message_role(message)
            if role in {"user", "human", "client"}:
                next_user = index
                break
        parsed: list[HermesResult] = []
        for message in messages[marker_index + 1 : next_user]:
            if not isinstance(message, Mapping):
                continue
            role = self._message_role(message)
            if role is not None and not isinstance(role, str):
                continue
            role = role or "assistant"
            if role not in {"assistant", "model", "bot"}:
                continue
            parsed_result = self._parse_result(message, source="hermes-history")
            if parsed_result is not None and parsed_result.terminal is True and (parsed_result.marker is None or parsed_result.marker == marker):
                parsed.append(parsed_result)
        return parsed

    @classmethod
    def _message_role(cls, message: Mapping[str, Any]) -> Any:
        role = cls._first_present(message, ("role", "author_role"))
        if role is None and isinstance(message.get("message"), Mapping):
            role = cls._first_present(message["message"], ("role", "author_role"))
        return role

    @classmethod
    def _message_matches_marker(cls, message: Mapping[str, Any], marker: str) -> bool:
        """Match a user turn by structured correlation before text fallback."""
        containers: list[Mapping[str, Any]] = [message]
        nested = message.get("message")
        if isinstance(nested, Mapping):
            containers.append(nested)
        for container in tuple(containers):
            metadata = container.get("metadata")
            if isinstance(metadata, Mapping):
                containers.append(metadata)
        structured: list[str] = []
        for container in containers:
            for key in ("marker", "correlation_id"):
                if key not in container:
                    continue
                value = container[key]
                if not isinstance(value, str) or not value.strip():
                    return False
                structured.append(value.strip())
        if structured:
            return len(set(structured)) == 1 and structured[0] == marker
        for container in containers:
            for key in ("content", "text", "input", "prompt"):
                value = container.get(key)
                if isinstance(value, str) and marker in value:
                    return True
                if isinstance(value, list) and any(isinstance(item, str) and marker in item for item in value):
                    return True
        return False

    @staticmethod
    def _first_present(source: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
        for key in keys:
            if key in source:
                return source[key]
        return None

    @classmethod
    def _envelope_containers(cls, result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        """Return the bounded envelope containers used for consistency checks."""
        containers: list[Mapping[str, Any]] = []
        pending: list[Mapping[str, Any]] = [result]
        seen: set[int] = set()
        while pending and len(containers) < 16:
            container = pending.pop(0)
            marker = id(container)
            if marker in seen:
                continue
            seen.add(marker)
            containers.append(container)
            for key in ("message", "data", "result", "metadata"):
                nested = container.get(key)
                if isinstance(nested, Mapping):
                    pending.append(nested)
        return containers

    @staticmethod
    def _consistent_values(containers: Sequence[Mapping[str, Any]], keys: tuple[str, ...]) -> tuple[bool, list[Any]]:
        values: list[Any] = []
        for container in containers:
            for key in keys:
                if key in container:
                    values.append(container[key])
        if not values:
            return True, []
        first = values[0]
        return all(value == first for value in values[1:]), values

    @staticmethod
    def _normalized_state(value: Any) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        return value.strip().lower().replace("-", "_").replace(".", "_").replace(" ", "_")

    @classmethod
    def _parse_result(cls, result: Any, *, source: str = "hermes-chat") -> HermesResult | None:
        if not isinstance(result, Mapping):
            return None
        containers = cls._envelope_containers(result)
        message = result.get("message")
        nested_message = message if isinstance(message, Mapping) else {}
        object_type = result.get("object")
        if object_type is not None and (not isinstance(object_type, str) or object_type not in {"hermes.session.chat.completion", "assistant_message", "message"}):
            return None

        role_values: list[Any] = []
        for container in containers:
            for key in ("role", "author_role"):
                if key in container:
                    role_values.append(container[key])
        if role_values and (any(not isinstance(value, str) or value not in {"assistant", "model", "bot"} for value in role_values) or any(value != role_values[0] for value in role_values[1:])):
            return None

        state: bool | None = None
        progress_states = {"progress", "in_progress", "pending", "queued", "running", "started", "streaming", "partial", "incomplete", "working"}
        terminal_states = {"completed", "complete", "success", "succeeded", "final", "done", "terminal"}
        failure_states = {"failed", "failure", "error", "errors", "unsuccessful", "not_completed", "cancelled", "canceled", "rejected", "denied"}
        envelope_types = {"assistant_message", "message", "hermes_session_chat_completion", "chat_completion"}
        for container in containers:
            explicit = container.get("terminal")
            if explicit is not None:
                if not isinstance(explicit, bool):
                    return None
                if state is not None and state is not explicit:
                    return None
                state = explicit
            for key in ("status", "state", "outcome", "event", "type"):
                value = container.get(key)
                if value is None:
                    continue
                normalized = cls._normalized_state(value)
                if normalized is None:
                    return None
                if key == "type" and normalized in envelope_types:
                    continue
                if normalized in failure_states or normalized.startswith(("fail", "error", "unsuccess", "not_completed", "cancel", "reject")):
                    return None
                if normalized in progress_states or any(token in normalized for token in ("progress", "streaming", "partial", "in_progress")):
                    candidate_state = False
                elif normalized in terminal_states or any(token in normalized for token in ("completed", "complete", "final", "succeeded", "success")):
                    candidate_state = True
                else:
                    return None
                if state is not None and state is not candidate_state:
                    return None
                state = candidate_state
            if "error" in container and container["error"] not in (None, False, ""):
                return None
        text_values: list[Any] = []
        for container in containers:
            for key in ("text", "content", "assistant_content", "response"):
                if key in container and container[key] is not None:
                    text_values.append(container[key])
        text: Any = next((value for value in text_values if isinstance(value, str) and value.strip()), None)
        if text_values and any(not isinstance(value, (str, list)) for value in text_values):
            return None
        if len([value for value in text_values if isinstance(value, str) and value.strip()]) > 1:
            nonempty = [value.strip() for value in text_values if isinstance(value, str) and value.strip()]
            if any(value != nonempty[0] for value in nonempty[1:]):
                return None
        if isinstance(text, list):
            pieces: list[str] = []
            for item in text:
                if isinstance(item, str):
                    pieces.append(item)
                elif isinstance(item, Mapping) and isinstance(item.get("text"), str):
                    pieces.append(item["text"])
                else:
                    return None
            text = "".join(pieces) if pieces else None
        if not isinstance(text, str) or not text.strip():
            text = None

        if state is None:
            # The current Hermes chat endpoint uses a completion object or a
            # compact assistant-message envelope without a status field.
            # Preserve those known legacy success envelopes, but do not infer
            # terminality from an unknown status-bearing object.
            state = True
        if text is None:
            return None
        consistent, ids = cls._consistent_values(containers, ("assistant_message_id", "message_id", "id"))
        if not consistent:
            return None
        assistant_message_id = ids[0] if ids else "hermes-response"
        if not isinstance(assistant_message_id, str) or not assistant_message_id.strip():
            return None
        consistent, values = cls._consistent_values(containers, ("submission_id", "hermes_submission_id"))
        if not consistent:
            return None
        submission_id = values[0] if values else None
        consistent, values = cls._consistent_values(containers, ("turn_id", "recorder_turn_id"))
        if not consistent:
            return None
        turn_id = values[0] if values else None
        consistent, values = cls._consistent_values(containers, ("marker", "correlation_id"))
        if not consistent:
            return None
        result_marker = values[0] if values else None
        for label, value in (("submission_id", submission_id), ("turn_id", turn_id), ("marker", result_marker)):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                return None
        return HermesResult(
            assistant_message_id.strip(),
            text,
            state,
            source,
            submission_id.strip() if isinstance(submission_id, str) else None,
            turn_id.strip() if isinstance(turn_id, str) else None,
            result_marker.strip() if isinstance(result_marker, str) else None,
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
            raw = handle.read(4113)
    except CredentialError:
        raise
    except (OSError, ValueError):
        raise CredentialError("provider credential file is unreadable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return _parse_credential_record(raw)


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

    def _auth_headers(self) -> dict[str, str]:
        if self._credential is None:
            return {}
        return {"Authorization": f"Bearer {self._credential}"}

    def _request(
        self,
        payload: Mapping[str, Any],
        *,
        max_response_bytes: int = 16 * 1024 * 1024,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> tuple[str, bytes]:
        if not isinstance(max_response_bytes, int) or max_response_bytes < 1:
            raise ValueError("provider response limit is invalid")
        body = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json, audio/mpeg", "Content-Type": "application/json"}
        headers.update(self._auth_headers())
        timeout = self.timeout if timeout_seconds is None else min(self.timeout, float(timeout_seconds))
        if timeout <= 0:
            raise ProviderFailure("timeout", retryable=True)
        if deadline_at is None:
            deadline_at = time.monotonic() + timeout
        remaining = min(timeout, deadline_at - time.monotonic())
        if remaining <= 0:
            raise ProviderFailure("timeout", retryable=True)
        request = urllib.request.Request(self.endpoint, data=body, method="POST", headers=headers)
        setattr(request, "_recorder_deadline_at", deadline_at)
        try:
            with _urlopen_no_redirect(request, timeout=remaining) as response:
                try:
                    raw = _read_bounded_response(response, max_response_bytes, deadline_at=deadline_at)
                except _ProviderResponseTooLargeError as exc:
                    raise ProviderFailure("response_too_large", retryable=False) from exc
                except _ProviderResponseFramingError as exc:
                    raise ProviderFailure("response_framing", retryable=True) from exc
                return response.headers.get("Content-Type", ""), raw
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            exc.close()
            raise _provider_failure_for_http(status_code) from None
        except (socket.timeout, TimeoutError):
            raise ProviderFailure("timeout", retryable=True) from None
        except http.client.HTTPException:
            raise ProviderFailure("response_framing", retryable=True) from None
        except urllib.error.URLError:
            raise ProviderFailure("transport", retryable=True) from None

    def _request_bytes(
        self,
        body: bytes,
        *,
        content_type: str,
        max_response_bytes: int = 16 * 1024 * 1024,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> tuple[str, bytes]:
        if not isinstance(body, bytes) or not body:
            raise ProviderFailure("unsupported_media", retryable=False)
        if not isinstance(content_type, str) or not content_type or any(ord(char) < 0x20 for char in content_type):
            raise ValueError("provider content type is invalid")
        if not isinstance(max_response_bytes, int) or max_response_bytes < 1:
            raise ValueError("provider response limit is invalid")
        headers = {"Accept": "application/json, audio/mpeg", "Content-Type": content_type, "Content-Length": str(len(body))}
        headers.update(self._auth_headers())
        timeout = self.timeout if timeout_seconds is None else min(self.timeout, float(timeout_seconds))
        if timeout <= 0:
            raise ProviderFailure("timeout", retryable=True)
        if deadline_at is None:
            deadline_at = time.monotonic() + timeout
        remaining = min(timeout, deadline_at - time.monotonic())
        if remaining <= 0:
            raise ProviderFailure("timeout", retryable=True)
        request = urllib.request.Request(self.endpoint, data=body, method="POST", headers=headers)
        setattr(request, "_recorder_deadline_at", deadline_at)
        try:
            with _urlopen_no_redirect(request, timeout=remaining) as response:
                try:
                    raw = _read_bounded_response(response, max_response_bytes, deadline_at=deadline_at)
                except _ProviderResponseTooLargeError as exc:
                    raise ProviderFailure("response_too_large", retryable=False) from exc
                except _ProviderResponseFramingError as exc:
                    raise ProviderFailure("response_framing", retryable=True) from exc
                return response.headers.get("Content-Type", ""), raw
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            _close_http_error(exc)
            raise _provider_failure_for_http(status_code) from None
        except (socket.timeout, TimeoutError):
            raise ProviderFailure("timeout", retryable=True) from None
        except http.client.HTTPException:
            raise ProviderFailure("response_framing", retryable=True) from None
        except urllib.error.URLError:
            raise ProviderFailure("transport", retryable=True) from None

    def _probe(
        self,
        path: str | None,
        *,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> dict[str, Any]:
        if path is None:
            return {"configured": False}
        parsed = urllib.parse.urlsplit(self.endpoint)
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        headers = {"Accept": "application/json"}
        headers.update(self._auth_headers())
        request = urllib.request.Request(url, method="GET", headers=headers)
        timeout = self.timeout if timeout_seconds is None else min(self.timeout, float(timeout_seconds))
        if deadline_at is None:
            deadline_at = time.monotonic() + timeout
        setattr(request, "_recorder_deadline_at", deadline_at)
        remaining = min(timeout, deadline_at - time.monotonic())
        if remaining <= 0:
            raise ProviderFailure("timeout", retryable=True)
        try:
            with _urlopen_no_redirect(request, timeout=remaining) as response:
                raw = _read_bounded_response(response, 64 * 1024, deadline_at=deadline_at)
                status_code = int(getattr(response, "status", 200))
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            exc.close()
            raw = b""
        except ValueError:
            raise ProviderFailure("malformed_probe", retryable=False) from None
        except (socket.timeout, TimeoutError):
            raise ProviderFailure("timeout", retryable=True) from None
        except urllib.error.URLError:
            raise ProviderFailure("transport", retryable=True) from None
        if status_code < 200 or status_code >= 300:
            if 400 <= status_code < 500:
                raise ProviderFailure("client", retryable=False, status_code=status_code)
            if status_code >= 500:
                raise ProviderFailure("server", retryable=True, status_code=status_code)
            raise ProviderFailure("malformed_probe", retryable=False, status_code=status_code)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderFailure("malformed_probe", retryable=False) from None
        if not isinstance(payload, Mapping):
            raise ProviderFailure("malformed_probe", retryable=False)
        allowed = {"ok", "ready", "status", "provider", "model", "profile", "version", "capabilities", "media_types", "audio_api", "stt"}
        result: dict[str, Any] = {}
        for key in allowed:
            value = payload.get(key)
            if isinstance(value, (str, int, float, bool)):
                result[key] = value
            elif key in {"capabilities", "media_types"} and isinstance(value, list) and all(isinstance(item, str) and len(item) <= 128 for item in value):
                result[key] = list(value)
            elif key in {"capabilities", "stt"} and isinstance(value, Mapping):
                nested: dict[str, Any] = {}
                for nested_key, nested_value in value.items():
                    if str(nested_key).lower() in {"api_key", "authorization", "credential", "password", "secret", "token"}:
                        continue
                    if isinstance(nested_value, (str, int, float, bool)):
                        nested[str(nested_key)] = nested_value
                    elif isinstance(nested_value, list) and all(isinstance(item, str) and len(item) <= 128 for item in nested_value):
                        nested[str(nested_key)] = list(nested_value)
                result[key] = nested
        return result

    def health_check(self, *, timeout_seconds: float | None = None, deadline_at: float | None = None) -> dict[str, Any]:
        result = self._probe(self.health_path, timeout_seconds=timeout_seconds, deadline_at=deadline_at)
        if result.get("ok") is False or result.get("ready") is False:
            raise ProviderFailure("provider_unavailable", retryable=True)
        return result

    def capability_check(self, *, timeout_seconds: float | None = None, deadline_at: float | None = None) -> dict[str, Any]:
        return self._probe(self.capability_path, timeout_seconds=timeout_seconds, deadline_at=deadline_at)


_ASR_FAILURE_STATES = {
    "failed",
    "failure",
    "error",
    "errors",
    "provider_error",
    "unsuccessful",
    "not_completed",
    "cancelled",
    "canceled",
    "rejected",
    "denied",
}
_ASR_PROGRESS_STATES = {
    "progress",
    "in_progress",
    "pending",
    "queued",
    "running",
    "started",
    "streaming",
    "partial",
    "incomplete",
    "working",
}
_ASR_SUCCESS_STATES = {
    "ok",
    "accepted",
    "ready",
    "completed",
    "complete",
    "success",
    "succeeded",
    "final",
    "done",
    "terminal",
    "valid_transcript",
    "no_speech",
    "empty",
    "silence",
    "no_audio",
}


def _asr_payload_containers(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return a bounded set of nested ASR envelope objects."""
    containers: list[Mapping[str, Any]] = []
    pending: list[Mapping[str, Any]] = [payload]
    seen: set[int] = set()
    while pending and len(containers) < 16:
        container = pending.pop(0)
        identity = id(container)
        if identity in seen:
            continue
        seen.add(identity)
        containers.append(container)
        for key in ("data", "result", "response", "message", "output", "metadata"):
            nested = container.get(key)
            if isinstance(nested, Mapping):
                pending.append(nested)
    return containers


def _asr_payload_details(payload: Mapping[str, Any]) -> tuple[str, str | None, str | None]:
    """Validate an ASR envelope before accepting transcript text.

    Status, outcome, error, and boolean success markers are authoritative even
    when a response also contains a non-empty diagnostic string.  Text-only
    responses remain supported for the documented legacy endpoint contract.
    """
    containers = _asr_payload_containers(payload)
    states: list[str] = []
    for container in containers:
        for key in ("status", "state", "outcome"):
            if key not in container or container[key] is None:
                continue
            value = container[key]
            if not isinstance(value, str) or not value.strip():
                raise ProviderFailure("malformed_success", retryable=False)
            normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
            if normalized in _ASR_FAILURE_STATES or normalized.startswith(("fail", "error", "unsuccess", "not_completed", "cancel", "reject", "den")):
                raise ProviderFailure("provider_error", retryable=False)
            if normalized in _ASR_PROGRESS_STATES or any(token in normalized for token in ("progress", "streaming", "partial", "in_progress")):
                raise ProviderFailure("malformed_success", retryable=False)
            if normalized not in _ASR_SUCCESS_STATES:
                raise ProviderFailure("malformed_success", retryable=False)
            states.append(normalized)
        for key in ("ok", "success", "completed", "terminal"):
            if key not in container or container[key] is None:
                continue
            value = container[key]
            if not isinstance(value, bool):
                raise ProviderFailure("malformed_success", retryable=False)
            if not value:
                raise ProviderFailure("provider_error", retryable=False)
        error = container.get("error")
        if error not in (None, False, "", {}, []):
            raise ProviderFailure("provider_error", retryable=False)

    text_values: list[str] = []
    for container in containers:
        for key in ("transcript", "text", "transcription"):
            value = container.get(key)
            if value is None:
                continue
            if not isinstance(value, str):
                raise ProviderFailure("malformed_success", retryable=False)
            if value.strip():
                text_values.append(value.strip())
    if len(set(text_values)) > 1:
        raise ProviderFailure("malformed_success", retryable=False)
    text = text_values[0] if text_values else None
    no_speech = any(state in {"no_speech", "empty", "silence", "no_audio"} for state in states)
    if no_speech:
        if text is not None:
            raise ProviderFailure("malformed_success", retryable=False)
        outcome = "NO_SPEECH"
    else:
        if text is None:
            raise ProviderFailure("malformed_success", retryable=False)
        outcome = "VALID_TRANSCRIPT"
    provider: str | None = None
    for container in containers:
        value = container.get("provider")
        if value is not None:
            if not isinstance(value, str) or not value.strip():
                raise ProviderFailure("malformed_success", retryable=False)
            if provider is not None and provider != value.strip():
                raise ProviderFailure("malformed_success", retryable=False)
            provider = value.strip()
    return outcome, text, provider


def _coerce_asr_input(audio: ASRInput | bytes, *, part_id: str = "audio-1") -> ASRInput:
    if isinstance(audio, ASRInput):
        return audio
    if isinstance(audio, bytes):
        try:
            return validate_wav(audio, part_id=part_id, mime="audio/wav")
        except MediaValidationError as exc:
            raise ProviderFailure("unsupported_media", retryable=False) from exc
    raise ProviderFailure("unsupported_media", retryable=False)


def _language_code(language: str) -> str:
    if not isinstance(language, str) or not re.fullmatch(r"[A-Za-z]{2}(?:-[A-Za-z]{2})?", language):
        raise ValueError("ASR language must be an ISO-639-1 code or locale")
    return language[:2].lower()


def _multipart_form(fields: Mapping[str, str], *, filename: str, content_type: str, file_bytes: bytes) -> tuple[str, bytes]:
    boundary = "----recorder-next-" + os.urandom(16).hex()
    chunks: list[bytes] = []
    for name, value in fields.items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) or any(ord(char) < 0x20 for char in value):
            raise ValueError("multipart field is invalid")
        chunks.extend([f"--{boundary}\r\n".encode("ascii"), f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("ascii"), value.encode("utf-8"), b"\r\n"])
    chunks.extend([
        f"--{boundary}\r\n".encode("ascii"),
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("ascii"),
        f"Content-Type: {content_type}\r\n\r\n".encode("ascii"),
        file_bytes,
        b"\r\n",
        f"--{boundary}--\r\n".encode("ascii"),
    ])
    return f"multipart/form-data; boundary={boundary}", b"".join(chunks)


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
        if any(not isinstance(media_type, str) or media_type.lower() not in {"audio/wav", "audio/x-wav"} for media_type in self.media_types):
            raise ValueError("ASR media types must be audio MIME types")
        super().__init__(endpoint, timeout=timeout, credential_file=credential_file, health_path=health_path, capability_path=capability_path)

    def transcribe(self, audio: ASRInput | bytes, *, turn_id: str, generation: int, timeout_seconds: float | None = None, deadline_at: float | None = None) -> AsrResult:
        value = _coerce_asr_input(audio)
        if value.canonical_mime not in {item.lower() for item in self.media_types} or (self.max_bytes is not None and value.byte_count > self.max_bytes):
            raise ProviderFailure("unsupported_media", retryable=False)
        content_type, raw = self._request(
            {
                "model": self.model,
                "language": self.language,
                "audio_base64": base64.b64encode(value.data).decode("ascii"),
                "turn_id": turn_id,
                "generation": generation,
            },
            max_response_bytes=16 * 1024 * 1024,
            timeout_seconds=timeout_seconds,
            deadline_at=deadline_at,
        )
        del content_type
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderFailure("malformed_success", retryable=False) from None
        if not isinstance(payload, Mapping):
            raise ProviderFailure("malformed_success", retryable=False)
        outcome, text, _provider = _asr_payload_details(payload)
        if outcome == "NO_SPEECH":
            return AsrResult(
                "NO_SPEECH",
                metadata={
                    "mode": self.mode,
                    "endpoint_contract": self.endpoint,
                    "provider": self.name,
                    "model": self.model,
                    "input_sha256": value.sha256,
                    "content_type": "audio/wav",
                    "byte_size": value.byte_count,
                    "media_revision": "wav-pcm-s16le-16k-mono-v1",
                    "attempt_identity": f"{turn_id}:{generation}",
                },
            )
        assert text is not None
        return AsrResult(
            "VALID_TRANSCRIPT",
            transcript=text,
            metadata={
                "mode": self.mode,
                "endpoint_contract": self.endpoint,
                "provider": self.name,
                "model": self.model,
                "input_sha256": value.sha256,
                "output_sha256": sha256_bytes(text.encode("utf-8")),
                "content_type": "audio/wav",
                "byte_size": value.byte_count,
                "media_revision": "wav-pcm-s16le-16k-mono-v1",
                "attempt_identity": f"{turn_id}:{generation}",
            },
        )


class NemotronASRProvider(HttpASRProvider):
    """Named Nemotron-compatible ASR adapter for explicit configurations."""

    name = "nemotron"
    mode = "nemotron"


class WhisperASRProvider(HttpASRProvider):
    """Named Whisper-compatible ASR adapter for explicit configurations."""

    name = "whisper-compatible"
    mode = "whisper"

    def transcribe(
        self,
        audio: ASRInput | bytes,
        *,
        turn_id: str,
        generation: int,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> AsrResult:
        value = _coerce_asr_input(audio)
        if value.canonical_mime not in {item.lower() for item in self.media_types} or (self.max_bytes is not None and value.byte_count > self.max_bytes):
            raise ProviderFailure("unsupported_media", retryable=False)
        fields = {"model": self.model, "response_format": "json"}
        if self.language:
            fields["language"] = _language_code(self.language)
        content_type, body = _multipart_form(fields, filename="audio.wav", content_type="audio/wav", file_bytes=value.data)
        _response_type, raw = self._request_bytes(
            body,
            content_type=content_type,
            timeout_seconds=timeout_seconds,
            deadline_at=deadline_at,
        )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderFailure("malformed_success", retryable=False) from None
        if not isinstance(payload, Mapping) or "text" not in payload or not isinstance(payload["text"], str):
            raise ProviderFailure("malformed_success", retryable=False)
        text = payload["text"].strip()
        metadata = {
            "mode": self.mode,
            "provider": self.name,
            "model": self.model,
            "endpoint_contract": self.endpoint,
            "input_sha256": value.sha256,
            "output_sha256": sha256_bytes(text.encode("utf-8")),
            "content_type": "audio/wav",
            "byte_size": value.byte_count,
            "media_revision": "wav-pcm-s16le-16k-mono-v1",
            "wire_revision": "whisper-multipart-v1",
            "attempt_identity": f"{turn_id}:{generation}",
        }
        if not text:
            return AsrResult("NO_SPEECH", metadata=metadata)
        return AsrResult("VALID_TRANSCRIPT", transcript=text, metadata=metadata)


PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _hermes_profile_endpoint(base_url: str, path: str, profile: str) -> str:
    if not isinstance(base_url, str):
        raise ValueError("Hermes base URL must be a string")
    parsed = urllib.parse.urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Hermes base URL must not contain query or credentials")
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
        health_path: str | None = "/api/health",
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

    def transcribe(
        self,
        audio: ASRInput | bytes,
        *,
        turn_id: str,
        generation: int,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> AsrResult:
        value = _coerce_asr_input(audio)
        if self.max_bytes is not None and value.byte_count > self.max_bytes:
            raise ProviderFailure("oversized_or_empty_media", retryable=False)
        data_url = "data:audio/wav;base64," + base64.b64encode(value.data).decode("ascii")
        request_kwargs: dict[str, Any] = {"max_response_bytes": 16 * 1024 * 1024}
        if timeout_seconds is not None:
            request_kwargs["timeout_seconds"] = timeout_seconds
        if deadline_at is not None:
            request_kwargs["deadline_at"] = deadline_at
        _content_type, raw = self._request({"data_url": data_url, "mime_type": "audio/wav"}, **request_kwargs)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderFailure("malformed_response", retryable=False) from None
        if not isinstance(payload, Mapping):
            raise ProviderFailure("malformed_response", retryable=False)
        outcome, text, provider_value = _asr_payload_details(payload)
        if outcome == "NO_SPEECH":
            return AsrResult("NO_SPEECH", metadata={"mode": self.mode, "provider": _safe_provider_name(provider_value or payload.get("provider")), "hermes_profile": self.profile, "endpoint_contract": self.endpoint_contract, "input_sha256": value.sha256, "content_type": "audio/wav", "byte_size": value.byte_count, "media_revision": "wav-pcm-s16le-16k-mono-v1", "attempt_identity": f"{turn_id}:{generation}"})
        assert text is not None
        normalized = text.strip()
        return AsrResult(
            "VALID_TRANSCRIPT",
            transcript=normalized,
            metadata={
                "mode": self.mode,
                "hermes_profile": self.profile,
                "endpoint_contract": self.endpoint_contract,
                "provider": _safe_provider_name(provider_value or payload.get("provider")),
                "input_sha256": value.sha256,
                "output_sha256": sha256_bytes(normalized.encode("utf-8")),
                "content_type": "audio/wav",
                "byte_size": value.byte_count,
                "media_revision": "wav-pcm-s16le-16k-mono-v1",
                "attempt_identity": f"{turn_id}:{generation}",
            },
        )

    def readiness_check(self) -> dict[str, Any]:
        """Verify the isolated Hermes audio listener exposes usable STT."""
        health = self.health_check()
        capability = self.capability_check()
        if capability.get("ok") is False or capability.get("ready") is False:
            raise ProviderFailure("stt_unavailable", retryable=True)
        if capability.get("audio_api") is False:
            raise ProviderFailure("stt_audio_api_unavailable", retryable=True)
        stt = capability.get("stt")
        if isinstance(stt, Mapping):
            mode = str(stt.get("mode") or "").strip().lower()
            if mode in {"disabled", "off", "none"}:
                raise ProviderFailure("stt_disabled", retryable=False)
            reason = str(stt.get("reason") or "").strip().lower()
            if mode == "relay" and reason in {"stt disabled", "resolution error"}:
                raise ProviderFailure(
                    "stt_disabled" if reason == "stt disabled" else "stt_unavailable",
                    retryable=reason != "stt disabled",
                )
        elif capability.get("provider") is None and capability.get("status") is None:
            raise ProviderFailure("stt_capability_unknown", retryable=True)
        return {"health": health, "capability": capability, "endpoint_contract": self.endpoint_contract}


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
        if any(str(key).lower() in {"text", "model", "voice", "language", "artifact_id", "response_format", "output_format", "format", "rate", "pitch", "volume"} for key in self.options):
            raise ValueError("TTS option is reserved by the provider contract")
        super().__init__(endpoint, timeout=timeout, credential_file=credential_file, health_path=health_path, capability_path=capability_path)

    def synthesize(self, text: str, *, artifact_id: str, timeout_seconds: float | None = None, deadline_at: float | None = None) -> TTSResult:
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
            max_response_bytes=min(16 * 1024 * 1024, max(64 * 1024, (self.max_bytes or 0) * 2 + 4096)),
            timeout_seconds=timeout_seconds,
            deadline_at=deadline_at,
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
        health_path: str | None = "/api/health",
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

    def _auth_headers(self) -> dict[str, str]:
        headers = super()._auth_headers()
        if self._credential is not None:
            # Hermes' dashboard audio route prefers its dedicated session
            # header; Authorization remains present for legacy clients and
            # authenticated protocol fixtures.
            headers["X-Hermes-Session-Token"] = self._credential
        return headers

    def _request(
        self,
        payload: Mapping[str, Any],
        *,
        max_response_bytes: int = 16 * 1024 * 1024,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> tuple[str, bytes]:
        """Classify an API-only Hermes listener as unavailable for TTS.

        The Gateway API and the dashboard web server are separate Hermes
        surfaces.  The former can be healthy while not exposing the desktop
        ``/api/audio/speak`` route, which otherwise becomes a misleading
        generic client failure after the HTTP 404 mapping in ``_HTTPProvider``.
        Keep the status code for a redaction-safe operator receipt, but make
        the capability mismatch explicit to provider-chain fallback logic.
        """
        try:
            return super()._request(
                payload,
                max_response_bytes=max_response_bytes,
                timeout_seconds=timeout_seconds,
                deadline_at=deadline_at,
            )
        except ProviderFailure as exc:
            if exc.status_code == 404:
                raise ProviderFailure("provider_unavailable", retryable=False, status_code=404) from None
            raise

    def synthesize(self, text: str, *, artifact_id: str, timeout_seconds: float | None = None, deadline_at: float | None = None) -> TTSResult:
        if not isinstance(text, str) or not text.strip():
            raise ProviderFailure("malformed_request", retryable=False)
        content_type, raw = self._request(
            {"text": text},
            max_response_bytes=min(16 * 1024 * 1024, max(64 * 1024, (self.max_bytes or 0) * 2 + 4096)),
            timeout_seconds=timeout_seconds,
            deadline_at=deadline_at,
        )
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
        for key in ("profile", "model", "voice", "language", "endpoint_contract", "fallback_of", "health_path", "capability_path", "output_format", "rate", "pitch", "volume", "credential_ref_sha256"):
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

    _eligible = {"transport", "dns", "connect", "timeout", "rate_limited", "server", "response_framing", "provider_unavailable", "unavailable", "capacity"}

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
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ChainFailure("deadline", statuses, retryable=False)
                    request_timeout = min(remaining, target.timeout_seconds)
                    if request_timeout <= 0:
                        raise ChainFailure("deadline", statuses, retryable=False)
                    request_generation = index * 100 + attempt
                    provider: Any = target.provider
                    if operation == "asr":
                        if isinstance(provider, _HTTPProvider):
                            result = getattr(provider, "transcribe")(value, turn_id=identifier, generation=request_generation, timeout_seconds=request_timeout, deadline_at=deadline)
                        else:
                            result = provider.transcribe(value.data if isinstance(value, ASRInput) else value, turn_id=identifier, generation=request_generation)
                    else:
                        if isinstance(provider, _HTTPProvider):
                            result = getattr(provider, "synthesize")(value, artifact_id=identifier, timeout_seconds=request_timeout, deadline_at=deadline)
                        else:
                            result = provider.synthesize(value, artifact_id=identifier)
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
                    if time.monotonic() >= deadline:
                        statuses.append(self._safe_status(target, status="deadline", retry_count=attempt, error=exc))
                        raise ChainFailure("deadline", statuses, retryable=False)
                    client_terminal = (
                        isinstance(exc.status_code, int)
                        and 400 <= exc.status_code < 500
                        and exc.status_code not in {408, 429}
                    )
                    eligible = not client_terminal and (
                        (exc.retryable and exc.kind in self._eligible)
                        or exc.kind in {"provider_unavailable", "unavailable", "capacity"}
                    )
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
        terminal_kind = "all_targets_failed"
        if statuses and all(
            item.get("error_kind") in {"provider_unavailable", "unavailable", "capacity"}
            for item in statuses
        ):
            terminal_kind = "provider_unavailable"
        retryable = bool(statuses) and all(item.get("status") == "retryable_failure" for item in statuses)
        raise ChainFailure(terminal_kind, statuses, retryable=retryable)

    def execute_asr(self, audio: ASRInput | bytes, *, turn_id: str, frozen: Mapping[str, Any] | None = None) -> AsrResult:
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
