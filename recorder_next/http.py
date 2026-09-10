from __future__ import annotations

import io
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .errors import RecorderError
from .service import RecorderService


_HEADER_DEADLINE_SECONDS = 5.0
_BODY_DEADLINE_SECONDS = 30.0
_IDLE_IO_DEADLINE_SECONDS = 5.0
_RESPONSE_DEADLINE_SECONDS = 30.0
_MAX_HEADER_BYTES = 64 * 1024
_IO_BUFFER_BYTES = 8192


class _DeadlineExceeded(TimeoutError):
    pass


class _HeaderTooLarge(ValueError):
    pass


class _DeadlineSocketReader(io.RawIOBase):
    """Socket reader with absolute header/body and idle progress deadlines."""

    def __init__(
        self,
        connection: socket.socket,
        accepted_at: float,
        *,
        header_deadline_seconds: float = _HEADER_DEADLINE_SECONDS,
        body_deadline_seconds: float = _BODY_DEADLINE_SECONDS,
        idle_deadline_seconds: float = _IDLE_IO_DEADLINE_SECONDS,
    ):
        self.connection = connection
        self._phase = "header"
        self._body_deadline_seconds = body_deadline_seconds
        self._idle_deadline_seconds = idle_deadline_seconds
        self._deadline = accepted_at + header_deadline_seconds
        self._last_progress = accepted_at
        self._header_bytes = 0
        self._header_tail = b""
        self._header_complete = False

    def readable(self) -> bool:
        return True

    @property
    def phase(self) -> str:
        return self._phase

    def begin_body(self) -> None:
        self._phase = "body"
        self._deadline = time.monotonic() + self._body_deadline_seconds
        self._last_progress = time.monotonic()

    def _remaining(self) -> float:
        remaining = min(
            self._deadline - time.monotonic(),
            self._last_progress + self._idle_deadline_seconds - time.monotonic(),
        )
        if remaining <= 0:
            raise _DeadlineExceeded("request read deadline exceeded")
        return remaining

    def _record_header(self, data: bytes) -> None:
        if self._header_complete:
            return
        previous_tail = self._header_tail
        combined = previous_tail + data
        marker_at = combined.find(b"\r\n\r\n")
        if marker_at < 0:
            self._header_bytes += len(data)
            self._header_tail = combined[-3:]
        else:
            header_end = marker_at + 4
            self._header_bytes += max(0, header_end - len(previous_tail))
            self._header_complete = True
        if self._header_bytes > _MAX_HEADER_BYTES:
            raise _HeaderTooLarge("request headers exceed the configured limit")

    def readinto(self, buffer: bytearray | memoryview) -> int:
        if not buffer:
            return 0
        view = memoryview(buffer)[:_IO_BUFFER_BYTES]
        remaining = self._remaining()
        previous_timeout = self.connection.gettimeout()
        try:
            self.connection.settimeout(remaining)
            count = self.connection.recv_into(view)
        except socket.timeout as exc:
            raise _DeadlineExceeded("request read deadline exceeded") from exc
        finally:
            self.connection.settimeout(previous_timeout)
        if count:
            self._record_header(bytes(view[:count]))
            self._last_progress = time.monotonic()
        return count


class _DeadlineSocketWriter:
    """Immediate socket writer bounded by a response deadline."""

    def __init__(
        self,
        connection: socket.socket,
        *,
        deadline_seconds: float = _RESPONSE_DEADLINE_SECONDS,
        idle_deadline_seconds: float = _IDLE_IO_DEADLINE_SECONDS,
    ):
        self.connection = connection
        self._deadline_seconds = deadline_seconds
        self._idle_deadline_seconds = idle_deadline_seconds
        self._deadline: float | None = None
        self._last_progress = time.monotonic()
        self._closed = False

    def begin(self) -> None:
        self._deadline = time.monotonic() + self._deadline_seconds
        self._last_progress = time.monotonic()

    def writable(self) -> bool:
        return True

    @property
    def closed(self) -> bool:
        return self._closed

    def _remaining(self) -> float:
        if self._deadline is None:
            self.begin()
        assert self._deadline is not None
        remaining = min(
            self._deadline - time.monotonic(),
            self._last_progress + self._idle_deadline_seconds - time.monotonic(),
        )
        if remaining <= 0:
            raise _DeadlineExceeded("response write deadline exceeded")
        return remaining

    def write(self, data: bytes | bytearray | memoryview) -> int:
        view = memoryview(data)
        sent_total = 0
        while sent_total < len(view):
            remaining = self._remaining()
            previous_timeout = self.connection.gettimeout()
            try:
                self.connection.settimeout(remaining)
                sent = self.connection.send(view[sent_total:])
            except socket.timeout as exc:
                raise _DeadlineExceeded("response write deadline exceeded") from exc
            finally:
                self.connection.settimeout(previous_timeout)
            if sent <= 0:
                raise ConnectionError("client disconnected while writing response")
            sent_total += sent
            self._last_progress = time.monotonic()
        return sent_total

    def flush(self) -> None:
        return

    def close(self) -> None:
        self._closed = True


class _RecorderHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16
    max_concurrent_handlers = 8

    def __init__(self, server_address, service: RecorderService):
        self.service = service
        self.max_request_bytes = service._wire_policy.gateway_max_request_bytes
        self._handler_slots = threading.BoundedSemaphore(self.max_concurrent_handlers)
        self._accepted_times: dict[int, float] = {}
        self._accepted_times_lock = threading.Lock()
        super().__init__(server_address, RecorderRequestHandler)

    def process_request(self, request, client_address) -> None:
        if not self._handler_slots.acquire(blocking=False):
            try:
                self.shutdown_request(request)
            except OSError:
                pass
            return
        request_key = id(request)
        with self._accepted_times_lock:
            self._accepted_times[request_key] = time.monotonic()
        try:
            worker = threading.Thread(
                target=self.process_request_thread,
                args=(request, client_address),
                daemon=self.daemon_threads,
            )
            worker.start()
        except BaseException:
            try:
                self.shutdown_request(request)
            except OSError:
                pass
            finally:
                with self._accepted_times_lock:
                    self._accepted_times.pop(request_key, None)
                self._handler_slots.release()
            return

    def process_request_thread(self, request, client_address) -> None:
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            try:
                self.shutdown_request(request)
            except OSError:
                pass
            finally:
                with self._accepted_times_lock:
                    self._accepted_times.pop(id(request), None)
                self._handler_slots.release()


class RecorderRequestHandler(BaseHTTPRequestHandler):
    server: _RecorderHTTPServer
    protocol_version = "HTTP/1.1"
    header_deadline_seconds = _HEADER_DEADLINE_SECONDS
    body_deadline_seconds = _BODY_DEADLINE_SECONDS
    idle_io_deadline_seconds = _IDLE_IO_DEADLINE_SECONDS
    response_deadline_seconds = _RESPONSE_DEADLINE_SECONDS

    def setup(self) -> None:
        self.connection = self.request
        with self.server._accepted_times_lock:
            accepted_at = self.server._accepted_times.pop(id(self.request), time.monotonic())
        self._reader = _DeadlineSocketReader(
            self.connection,
            accepted_at,
            header_deadline_seconds=self.header_deadline_seconds,
            body_deadline_seconds=self.body_deadline_seconds,
            idle_deadline_seconds=self.idle_io_deadline_seconds,
        )
        self.rfile = io.BufferedReader(self._reader, buffer_size=_IO_BUFFER_BYTES)
        self._writer = _DeadlineSocketWriter(
            self.connection,
            deadline_seconds=self.response_deadline_seconds,
            idle_deadline_seconds=self.idle_io_deadline_seconds,
        )
        self.wfile = self._writer
        self._expect_continue = False

    def handle(self) -> None:
        self.close_connection = True
        try:
            self.handle_one_request()
        except (_HeaderTooLarge, _DeadlineExceeded, socket.timeout, OSError):
            # Header timeout/overflow and client disconnects are deliberately
            # silent.  A body timeout is handled after successful preflight.
            self.close_connection = True
        except Exception:
            self.close_connection = True

    def parse_request(self) -> bool:
        parsed = super().parse_request()
        self.close_connection = True
        return parsed

    def handle_expect_100(self) -> bool:
        values = self.headers.get_all("Expect") or []
        if len(values) == 1 and values[0].strip().lower() == "100-continue":
            self._expect_continue = True
            return True
        self._send_framing_error(400, "INVALID_FRAMING", "unsupported Expect header")
        return False

    def log_message(self, format: str, *args: Any) -> None:
        # Access logs must not accidentally include request bodies or transcript data.
        return

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def _dispatch(self, method: str) -> None:
        length, framing_error = self._validated_content_length()
        if framing_error is not None:
            self._send_framing_error(*framing_error, head=method == "HEAD")
            return
        try:
            self.server.service.preflight_http(
                method,
                self.path,
                self.headers,
                body_length=length,
                peer_addr=self.client_address,
            )
        except RecorderError as exc:
            self._send_payload(exc.status, {}, {"error": {"code": exc.code, "message": exc.message}}, head=method == "HEAD")
            return
        except (KeyError, TypeError, ValueError):
            self._send_payload(400, {}, {"error": {"code": "INVALID_REQUEST", "message": "request is invalid"}}, head=method == "HEAD")
            return
        except Exception:
            self._send_payload(500, {}, {"error": {"code": "INTERNAL_ERROR", "message": "request could not be completed"}}, head=method == "HEAD")
            return

        if self._expect_continue and length:
            try:
                self._writer.begin()
                self.send_response_only(100)
                self.end_headers()
            except (OSError, _DeadlineExceeded):
                return
        self._reader.begin_body()
        try:
            body = self.rfile.read(length) if length else b""
        except (_DeadlineExceeded, socket.timeout):
            self._send_framing_error(408, "REQUEST_TIMEOUT", "request body read timed out", head=method == "HEAD")
            return
        if len(body) != length:
            self._send_framing_error(400, "INVALID_FRAMING", "request body is shorter than Content-Length", head=method == "HEAD")
            return
        try:
            status, headers, payload = self.server.service.handle_http(
                method,
                self.path,
                self.headers,
                body,
                peer_addr=self.client_address,
            )
        except RecorderError as exc:
            status, headers, payload = exc.status, {}, {"error": {"code": exc.code, "message": exc.message}}
        except (KeyError, TypeError, ValueError):
            status, headers, payload = 400, {}, {"error": {"code": "INVALID_REQUEST", "message": "request is invalid"}}
        except Exception:
            status, headers, payload = 500, {}, {"error": {"code": "INTERNAL_ERROR", "message": "request could not be completed"}}
        self._send_payload(status, headers, payload, head=method == "HEAD")

    def _send_payload(self, status: int, headers: dict[str, str], payload: Any, *, head: bool = False) -> None:
        if isinstance(payload, bytes):
            encoded = payload
            default_content_type = "application/octet-stream"
        else:
            encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            default_content_type = "application/json; charset=utf-8"
        try:
            self._writer.begin()
            self.send_response(status)
            self.send_header("Content-Type", self._header_value(headers, "Content-Type") or default_content_type)
            self.send_header("Content-Length", self._header_value(headers, "Content-Length") or str(len(encoded)))
            if self._header_value(headers, "Cache-Control") is None:
                self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            for key, value in headers.items():
                if key.lower() in {"content-type", "content-length", "cache-control", "connection"}:
                    continue
                self.send_header(key, value)
            self.end_headers()
            if not head:
                self.wfile.write(encoded)
        except (OSError, _DeadlineExceeded):
            self.close_connection = True

    @staticmethod
    def _header_value(headers: dict[str, str], name: str) -> str | None:
        wanted = name.lower()
        for key, value in headers.items():
            if key.lower() == wanted:
                return value
        return None

    def _validated_content_length(self) -> tuple[int, tuple[int, str, str] | None]:
        if self.headers.get_all("Transfer-Encoding"):
            return 0, (400, "INVALID_FRAMING", "Transfer-Encoding is not supported")
        values = self.headers.get_all("Content-Length") or []
        if len(values) > 1:
            return 0, (400, "INVALID_FRAMING", "duplicate Content-Length is not permitted")
        if not values:
            return 0, None
        raw = values[0].strip()
        if not raw or not raw.isascii() or not raw.isdigit():
            return 0, (400, "INVALID_FRAMING", "Content-Length must be a non-negative decimal integer")
        # Avoid converting attacker-controlled arbitrarily long digit strings
        # before the configured bound is known. Leading zeroes are harmless,
        # but a non-zero value wider than the decimal bound is necessarily too
        # large and must still receive a bounded framing response.
        normalized = raw.lstrip("0") or "0"
        maximum_digits = len(str(self.server.max_request_bytes))
        if len(normalized) > maximum_digits:
            return 0, (413, "REQUEST_TOO_LARGE", "request body exceeds server limit")
        length = int(normalized)
        if length > self.server.max_request_bytes:
            return 0, (413, "REQUEST_TOO_LARGE", "request body exceeds server limit")
        return length, None

    def _send_framing_error(self, status: int, code: str, message: str, *, head: bool = False) -> None:
        payload = {"error": {"code": code, "message": message}}
        self._send_payload(status, {}, payload, head=head)
        self.close_connection = True


def create_http_server(service: RecorderService, *, host: str = "127.0.0.1", port: int = 8643) -> ThreadingHTTPServer:
    if port == 5000:
        raise ValueError("Recorder Next must not bind the protected legacy port 5000")
    return _RecorderHTTPServer((host, port), service)
