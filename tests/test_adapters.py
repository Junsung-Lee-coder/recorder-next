import io
import hashlib
import json
import unittest
import urllib.error

from recorder_next.adapters import HttpHermesGateway


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


if __name__ == "__main__":
    unittest.main()
