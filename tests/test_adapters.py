import io
import hashlib
import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recorder_next.adapters import (
    HttpHermesGateway,
    HttpASRProvider,
    ChainFailure,
    ProviderChain,
    ProviderFailure,
    ProviderTarget,
    StaticASRProvider,
    _HTTPProvider,
    _ProviderResponseFramingError,
    _provider_failure_for_http,
    _read_bounded_response,
    _urlopen_no_redirect,
)
from recorder_next.models import AsrResult
from tests.r25_test_helpers import canonical_wav


class HermesAdapterContractTests(unittest.TestCase):
    def test_http_submit_uses_durable_runs_and_parses_current_envelope(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self):
                super().__init__("http://127.0.0.1:9", poll_interval_seconds=0)
                self.calls = []

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.calls.append((method, path, payload, dict(extra_headers or {})))
                if method == "POST" and path == "/v1/runs":
                    return {"run_id": "run-current", "status": "queued"}
                return {"run_id": "run-current", "status": "completed", "output": "ok-current-envelope"}

        gateway = ProbeGateway()
        result = gateway.submit(
            session_key="project:abc:default",
            request={"input": "normalized"},
            submission_id="sub-current",
            marker="marker-current",
        )

        self.assertEqual(result.content, "ok-current-envelope")
        self.assertEqual([call[0:2] for call in gateway.calls], [
            ("POST", "/v1/runs"),
            ("GET", "/v1/runs/run-current"),
        ])
        self.assertEqual(gateway.calls[0][2], {"input": "normalized", "session_id": "project:abc:default"})
        self.assertEqual(gateway.calls[0][3]["Idempotency-Key"], "sub-current")

    def test_http_history_parses_current_data_envelope(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self):
                super().__init__("http://127.0.0.1:9")

            def _request(self, method, path, payload=None, *, extra_headers=None):
                return {
                    "object": "list",
                    "data": [
                        {"id": "u-1", "role": "user", "content": "marker-current"},
                        {"id": "a-1", "role": "assistant", "content": "history-current-envelope"},
                    ],
                }

        result = ProbeGateway().history(
            session_key="project:abc:default",
            marker="marker-current",
        )
        self.assertEqual(result.content, "history-current-envelope")

    def test_http_submit_projects_only_input_marker_and_submission_identity(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self):
                super().__init__("http://127.0.0.1:9", poll_interval_seconds=0)
                self.seen = []

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.seen.append({"method": method, "path": path, "payload": payload, "headers": dict(extra_headers or {})})
                if method == "POST":
                    return {"run_id": "run-1", "status": "queued"}
                return {"run_id": "run-1", "status": "completed", "output": "ok", "assistant_message_id": "m-1"}

        gateway = ProbeGateway()
        result = gateway.submit(session_key="project:abc:default", request={"input": "normalized", "parts": [{"text": "secret metadata"}], "manifest": {"device": "watch"}}, submission_id="sub-1", marker="marker-1")
        self.assertEqual(result.content, "ok")
        self.assertEqual(gateway.seen[0]["payload"], {"input": "normalized", "session_id": "project:abc:default"})
        self.assertNotIn("parts", gateway.seen[0]["payload"])
        self.assertNotIn("manifest", gateway.seen[0]["payload"])
        self.assertNotIn("marker-1", json.dumps(gateway.seen[0]["payload"]))
        self.assertEqual(gateway.seen[0]["headers"]["X-Hermes-Session-Key"], "project:abc:default")
        self.assertEqual(gateway.seen[0]["headers"]["Idempotency-Key"], "sub-1")

    def test_http_submit_projects_inner_request_from_durable_ingress_envelope(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self):
                super().__init__("http://127.0.0.1:9", poll_interval_seconds=0)
                self.seen = []

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.seen.append({"method": method, "path": path, "payload": payload, "headers": dict(extra_headers or {})})
                if method == "POST":
                    return {"run_id": "run-2", "status": "queued"}
                return {"run_id": "run-2", "status": "completed", "output": "ok", "assistant_message_id": "m-2"}

        gateway = ProbeGateway()
        gateway.submit(
            session_key="project:abc:default",
            request={
                "submission_id": "sub-2",
                "marker": "marker-2",
                "request": {"input": "normalized from durable ingress", "parts": [{"kind": "text", "text": "normalized from durable ingress"}]},
                "route": {"project_id": "abc"},
            },
            submission_id="sub-2",
            marker="marker-2",
        )
        self.assertEqual(
            gateway.seen[0]["payload"],
            {"input": "normalized from durable ingress", "session_id": "project:abc:default"},
        )
        self.assertEqual(gateway.seen[0]["headers"]["Idempotency-Key"], "sub-2")

    def test_http_submit_projects_each_attachment_type_as_safe_reference(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self, mime):
                attachment_sha256 = hashlib.sha256(b"x" * 42).hexdigest()
                super().__init__(
                    "http://127.0.0.1:9",
                    poll_interval_seconds=0,
                    attachment_resolver=lambda _reference: {
                        "body": b"x" * 42,
                        "sha256": attachment_sha256,
                        "mime": mime,
                    },
                )
                self.seen = []

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.seen.append({"method": method, "path": path, "payload": payload, "headers": dict(extra_headers or {})})
                if method == "POST":
                    return {"run_id": "run-attachments", "status": "queued"}
                return {"run_id": "run-attachments", "status": "completed", "output": "ok"}

        cases = {
            "image_png": ("image/png", "image-1"),
            "document_pdf": ("application/pdf", "document-1"),
            "text_txt": ("text/plain; charset=utf-8", "text-1"),
            "data_csv": ("text/csv; charset=utf-8", "csv-1"),
            "generic_binary": ("application/octet-stream", "binary-1"),
        }
        attachment_sha256 = hashlib.sha256(b"x" * 42).hexdigest()
        for name, (mime, part_id) in cases.items():
            with self.subTest(attachment=name):
                gateway = ProbeGateway(mime)
                request = {
                    "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890aa",
                    "origin_device_id": "private-device-must-not-leak",
                    "input": "",
                    "parts": [
                        {
                            "part_id": part_id,
                            "kind": "attachment",
                            "mime": mime,
                            "declared_bytes": 42,
                            "total_bytes": 42,
                            "whole_stream_sha256": attachment_sha256,
                            "status": "COMPLETE",
                            "source_path": "/private/spool/never-send",
                        }
                    ],
                }
                if name == "image_png":
                    result = gateway.submit(
                        session_key="project:attachments:default",
                        request=request,
                        submission_id=f"sub-{name}",
                        marker=f"marker-{name}",
                    )
                    self.assertEqual(result.content, "ok")
                    payload = gateway.seen[0]["payload"]
                    self.assertEqual(payload["session_id"], "project:attachments:default")
                    self.assertEqual(payload["input"][0]["role"], "user")
                    self.assertEqual(payload["input"][0]["content"][0]["type"], "input_image")
                    self.assertTrue(payload["input"][0]["content"][0]["image_url"].startswith("data:image/png;base64,"))
                    self.assertNotIn("source_path", json.dumps(payload, ensure_ascii=False))
                    self.assertNotIn("private-device-must-not-leak", json.dumps(payload, ensure_ascii=False))
                else:
                    with self.assertRaisesRegex(ValueError, "document input"):
                        gateway.submit(
                            session_key="project:attachments:default",
                            request=request,
                            submission_id=f"sub-{name}",
                            marker=f"marker-{name}",
                        )
                    self.assertEqual(gateway.seen, [])

    def test_http_submit_rejects_empty_attachment_only_projection_before_upstream_call(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self):
                super().__init__("http://127.0.0.1:9")
                self.request_count = 0

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.request_count += 1
                return {"assistant_message_id": "must-not-run", "content": "unexpected"}

        for projected in ({"input": ""}, {"input": "", "parts": []}):
            with self.subTest(projected=projected):
                gateway = ProbeGateway()
                with self.assertRaisesRegex(ValueError, "projection has no input"):
                    gateway.submit(
                        session_key="project:empty/default",
                        request=projected,
                        submission_id="empty-submission",
                        marker="empty-marker",
                    )
                self.assertEqual(gateway.request_count, 0)

    def test_http_submit_projects_authoritative_assistant_message_id(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self):
                super().__init__("http://127.0.0.1:9", poll_interval_seconds=0)

            def _request(self, method, path, payload=None, *, extra_headers=None):
                if method == "POST":
                    return {"run_id": "run-authoritative", "status": "queued"}
                return {"run_id": "run-authoritative", "status": "completed", "output": "ok", "assistant_message_id": "authoritative-id"}

        result = ProbeGateway().submit(
            session_key="project:id/default",
            request={"input": "hello"},
            submission_id="submission-id",
            marker="marker-id",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.assistant_message_id, "authoritative-id")

    def test_provider_request_methods_distinguish_framing_from_size_failures(self):
        class ProviderResponseHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                pass

            def do_POST(self):
                try:
                    request_length = int(self.headers.get("Content-Length", "0"))
                    if request_length:
                        self.rfile.read(request_length)
                    case = self.path.rsplit("/", 1)[-1]
                    self.close_connection = True
                    if case == "truncated":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", "4")
                        self.end_headers()
                        self.wfile.write(b"{}")
                        self.wfile.flush()
                        return
                    body = b"{}"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    if case == "duplicate":
                        self.send_header("Content-Length", "2")
                        self.send_header("Content-Length", "2")
                    elif case == "unsupported":
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Content-Encoding", "gzip")
                    elif case == "duplicate-content-encoding":
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Content-Encoding", "identity")
                        self.send_header("Content-Encoding", "gzip")
                    elif case == "unsupported-transfer-encoding":
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Transfer-Encoding", "compress")
                    elif case == "combined-transfer-encoding":
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Transfer-Encoding", "chunked, compress")
                    elif case == "duplicate-transfer-encoding":
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Transfer-Encoding", "compress")
                        self.send_header("Transfer-Encoding", "compress")
                    elif case == "oversize":
                        self.send_header("Content-Length", "1024")
                    elif case == "oversize-body":
                        body = b"123456789"
                        self.send_header("Content-Length", str(len(body)))
                    elif case == "bad-chunk":
                        self.send_header("Transfer-Encoding", "chunked")
                    else:
                        body = b'{"text":"ok"}'
                        self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if case == "bad-chunk":
                        self.wfile.write(b"invalid\r\n")
                    else:
                        self.wfile.write(body)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), ProviderResponseHandler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_port}"
        try:
            for case in (
                "truncated",
                "duplicate",
                "unsupported",
                "duplicate-content-encoding",
                "unsupported-transfer-encoding",
                "combined-transfer-encoding",
                "duplicate-transfer-encoding",
                "bad-chunk",
            ):
                for request_method in ("json", "bytes"):
                    with self.subTest(case=case, request_method=request_method):
                        provider = _HTTPProvider(f"{endpoint}/{case}", timeout=1.0, credential_file=None)
                        with self.assertRaises(ProviderFailure) as caught:
                            if request_method == "json":
                                provider._request({"input": "test"}, max_response_bytes=8)
                            else:
                                provider._request_bytes(b"audio", content_type="audio/wav", max_response_bytes=8)
                        self.assertEqual(caught.exception.kind, "response_framing")
                        self.assertTrue(caught.exception.retryable)

            for case in ("oversize", "oversize-body"):
                for request_method in ("json", "bytes"):
                    with self.subTest(case=case, request_method=request_method):
                        provider = _HTTPProvider(f"{endpoint}/{case}", timeout=1.0, credential_file=None)
                        with self.assertRaises(ProviderFailure) as caught:
                            if request_method == "json":
                                provider._request({"input": "test"}, max_response_bytes=8)
                            else:
                                provider._request_bytes(b"audio", content_type="audio/wav", max_response_bytes=8)
                        self.assertEqual(caught.exception.kind, "response_too_large")
                        self.assertFalse(caught.exception.retryable)

            for request_method in ("json", "bytes"):
                with self.subTest(case="valid", request_method=request_method):
                    provider = _HTTPProvider(f"{endpoint}/valid", timeout=1.0, credential_file=None)
                    if request_method == "json":
                        content_type, raw = provider._request({"input": "test"}, max_response_bytes=64)
                    else:
                        content_type, raw = provider._request_bytes(b"audio", content_type="audio/wav", max_response_bytes=64)
                    self.assertEqual(content_type, "application/json")
                    self.assertEqual(raw, b'{"text":"ok"}')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    def test_provider_chain_falls_back_after_response_framing_failure(self):
        class TruncatedHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                pass

            def do_POST(self):
                try:
                    request_length = int(self.headers.get("Content-Length", "0"))
                    if request_length:
                        self.rfile.read(request_length)
                    self.close_connection = True
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    if self.path.endswith("/unsupported-transfer"):
                        self.send_header("Content-Length", "2")
                        self.send_header("Transfer-Encoding", "compress")
                    else:
                        self.send_header("Content-Length", "4")
                    self.end_headers()
                    self.wfile.write(b"{}")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), TruncatedHandler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_port}"
        try:
            primary = HttpASRProvider(endpoint, model="primary", timeout=1.0, credential_file=None)
            fallback = StaticASRProvider("fallback", AsrResult.valid("fallback transcript"))
            chain = ProviderChain(
                "asr",
                [
                    ProviderTarget("primary", "asr", "http-asr", primary, declared={"endpoint": endpoint, "model": "primary"}),
                    ProviderTarget("fallback", "asr", "fixture", fallback, declared={"endpoint": "http://127.0.0.1:1", "model": "fallback"}),
                ],
            )
            result = chain.execute_asr(canonical_wav(), turn_id="turn")
            self.assertEqual(result.transcript, "fallback transcript")
            self.assertEqual(result.metadata["winner"], "fallback")
            self.assertEqual(result.metadata["fallback_count"], 1)

            unsupported_primary = HttpASRProvider(
                f"{endpoint}/unsupported-transfer",
                model="primary",
                timeout=1.0,
                credential_file=None,
            )
            unsupported_chain = ProviderChain(
                "asr",
                [
                    ProviderTarget(
                        "primary",
                        "asr",
                        "http-asr",
                        unsupported_primary,
                        declared={"endpoint": unsupported_primary.endpoint, "model": "primary"},
                    ),
                    ProviderTarget(
                        "fallback",
                        "asr",
                        "fixture",
                        fallback,
                        declared={"endpoint": "http://127.0.0.1:1", "model": "fallback"},
                    ),
                ],
            )
            unsupported_result = unsupported_chain.execute_asr(canonical_wav(), turn_id="turn-unsupported")
            self.assertEqual(unsupported_result.transcript, "fallback transcript")
            self.assertEqual(unsupported_result.metadata["winner"], "fallback")
            self.assertEqual(unsupported_result.metadata["fallback_count"], 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    def test_response_framing_rejects_ambiguous_and_malformed_lengths_before_body_read(self):
        class Headers:
            def __init__(self, pairs):
                self.pairs = pairs

            def get_all(self, name):
                return [value for key, value in self.pairs if key.lower() == name.lower()] or None

            def get(self, name, default=None):
                values = self.get_all(name)
                return values[0] if values else default

        class UnreadableResponse:
            def __init__(self, pairs):
                self.headers = Headers(pairs)
                self.body_read = False

            def read(self, _size=-1):
                self.body_read = True
                raise AssertionError("body must not be read after framing rejection")

        cases = (
            (("Transfer-Encoding", "chunked"), ("Content-Length", "2")),
            (("Content-Length", "2"), ("Content-Length", "2")),
            (("Content-Length", ""),),
            (("Content-Length", "+2"),),
            (("Content-Length", "\u00a02"),),
            (("Content-Length", 2),),
        )
        for pairs in cases:
            with self.subTest(pairs=pairs):
                response = UnreadableResponse(pairs)
                with self.assertRaises(_ProviderResponseFramingError):
                    _read_bounded_response(response, 64)
                self.assertFalse(response.body_read)

    def test_provider_chain_uses_http_status_policy_for_retry_and_terminal_client_errors(self):
        class StatusASR:
            name = "status"

            def __init__(self, status):
                self.status = status

            def transcribe(self, _audio, *, turn_id, generation, timeout_seconds=None, deadline_at=None):
                del turn_id, generation, timeout_seconds, deadline_at
                raise _provider_failure_for_http(self.status)

        fallback = StaticASRProvider("fallback", AsrResult.valid("fallback transcript"))
        for status in (409, 425):
            primary = StatusASR(status)
            chain = ProviderChain(
                "asr",
                [
                    ProviderTarget("primary", "asr", "http-asr", primary, declared={"endpoint": "http://127.0.0.1:9"}),
                    ProviderTarget("fallback", "asr", "fixture", fallback, declared={"endpoint": "http://127.0.0.1:1"}),
                ],
            )
            result = chain.execute_asr(canonical_wav(), turn_id=f"turn-{status}")
            self.assertEqual(result.transcript, "fallback transcript")
            self.assertEqual(result.metadata["fallback_count"], 1)

        terminal_chain = ProviderChain(
            "asr",
            [
                ProviderTarget("primary", "asr", "http-asr", StatusASR(400), declared={"endpoint": "http://127.0.0.1:9"}),
                ProviderTarget("fallback", "asr", "fixture", fallback, declared={"endpoint": "http://127.0.0.1:1"}),
            ],
        )
        with self.assertRaises(ChainFailure):
            terminal_chain.execute_asr(canonical_wav(), turn_id="turn-400")

    def test_http_deadline_interrupts_all_response_framings(self):
        class DribbleHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                pass

            def do_GET(self):
                try:
                    if self.path == "/content-length":
                        self.send_response(200)
                        self.send_header("Content-Length", "8")
                        self.end_headers()
                        for value in b"abcdefgh":
                            self.wfile.write(bytes((value,)))
                            self.wfile.flush()
                            time.sleep(0.03)
                    elif self.path == "/chunked":
                        self.send_response(200)
                        self.send_header("Transfer-Encoding", "chunked")
                        self.end_headers()
                        for value in (b"ab", b"cd", b"ef", b"gh"):
                            self.wfile.write(f"{len(value):x}".encode() + b"\r\n")
                            self.wfile.flush()
                            time.sleep(0.03)
                            self.wfile.write(value + b"\r\n")
                            self.wfile.flush()
                            time.sleep(0.03)
                        self.wfile.write(b"0\r\n\r\n")
                        self.wfile.flush()
                    elif self.path == "/eof":
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(1)
                except BrokenPipeError:
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), DribbleHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for path in ("/content-length", "/chunked", "/eof"):
                with self.subTest(path=path):
                    started = time.monotonic()
                    deadline = started + 0.12
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{server.server_port}{path}",
                        method="GET",
                    )
                    with self.assertRaises(TimeoutError):
                        with _urlopen_no_redirect(request, timeout=0.12, deadline_at=deadline) as response:
                            _read_bounded_response(response, 1024, deadline_at=deadline)
                    self.assertLess(time.monotonic() - started, 0.3)
        finally:
            server.shutdown()
            server.server_close()

    def test_http_deadline_is_shared_by_gateway_provider_and_probe(self):
        class DribbleHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                pass

            def _dribble(self):
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    for value in body:
                        self.wfile.write(bytes((value,)))
                        self.wfile.flush()
                        time.sleep(0.03)
                except BrokenPipeError:
                    pass

            def do_GET(self):
                self._dribble()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self._dribble()

        server = ThreadingHTTPServer(("127.0.0.1", 0), DribbleHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_port}"
        try:
            gateway = HttpHermesGateway(endpoint, poll_interval_seconds=0, run_timeout_seconds=0.12)
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                gateway._request("POST", "/v1/runs", {"input": "hello"}, timeout_seconds=0.12)
            self.assertLess(time.monotonic() - started, 0.3)

            provider = _HTTPProvider(endpoint, timeout=0.12, credential_file=None, health_path="/health")
            started = time.monotonic()
            with self.assertRaises(ProviderFailure) as request_failure:
                provider._request({"input": "hello"}, timeout_seconds=0.12)
            self.assertEqual(request_failure.exception.kind, "timeout")
            self.assertLess(time.monotonic() - started, 0.3)

            started = time.monotonic()
            with self.assertRaises(ProviderFailure) as probe_failure:
                provider._probe("/health", timeout_seconds=0.12)
            self.assertEqual(probe_failure.exception.kind, "timeout")
            self.assertLess(time.monotonic() - started, 0.3)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
