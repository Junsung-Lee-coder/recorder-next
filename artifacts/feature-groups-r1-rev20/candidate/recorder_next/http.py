from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .errors import RecorderError
from .service import RecorderService


class _RecorderHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, service: RecorderService):
        self.service = service
        super().__init__(server_address, RecorderRequestHandler)


class RecorderRequestHandler(BaseHTTPRequestHandler):
    server: _RecorderHTTPServer
    protocol_version = "HTTP/1.1"
    max_request_bytes = 16 * 1024 * 1024

    def log_message(self, format: str, *args: Any) -> None:
        # Access logs must not accidentally include request bodies or transcript data.
        return

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def _dispatch(self, method: str) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length < 0 or length > self.max_request_bytes:
            encoded = b'{"error":{"code":"REQUEST_TOO_LARGE","message":"request body exceeds server limit"}}'
            self.send_response(413)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)
            self.close_connection = True
            return
        body = self.rfile.read(max(0, length))
        try:
            status, headers, payload = self.server.service.handle_http(method, self.path, self.headers, body)
        except RecorderError as exc:
            status, headers, payload = exc.status, {}, {"error": {"code": exc.code, "message": exc.message}}
        except (KeyError, TypeError, ValueError):
            status, headers, payload = 400, {}, {"error": {"code": "INVALID_REQUEST", "message": "request is invalid"}}
        except Exception:
            status, headers, payload = 500, {}, {"error": {"code": "INTERNAL_ERROR", "message": "request could not be completed"}}
        if isinstance(payload, bytes):
            encoded = payload
            default_content_type = "application/octet-stream"
        else:
            encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            default_content_type = "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", headers.get("Content-Type", default_content_type))
        self.send_header("Content-Length", headers.get("Content-Length", str(len(encoded))))
        if "Cache-Control" not in headers:
            self.send_header("Cache-Control", "no-store")
        for key, value in headers.items():
            if key.lower() in {"content-type", "content-length", "cache-control"}:
                continue
            self.send_header(key, value)
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(encoded)


def create_http_server(service: RecorderService, *, host: str = "127.0.0.1", port: int = 8643) -> ThreadingHTTPServer:
    if port == 5000:
        raise ValueError("Recorder Next must not bind the protected legacy port 5000")
    return _RecorderHTTPServer((host, port), service)
