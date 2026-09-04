import hashlib
import json
import unittest

from recorder_next.adapters import HttpHermesGateway


class HermesAdapterContractTests(unittest.TestCase):
    def test_http_submit_projects_only_input_marker_and_submission_identity(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self):
                super().__init__("http://127.0.0.1:9")
                self.seen = None

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.seen = {"method": method, "path": path, "payload": payload, "headers": dict(extra_headers or {})}
                return {"assistant_message_id": "m-1", "content": "ok"}

        gateway = ProbeGateway()
        result = gateway.submit(session_key="project:abc:default", request={"input": "normalized", "parts": [{"text": "secret metadata"}], "manifest": {"device": "watch"}}, submission_id="sub-1", marker="marker-1")
        self.assertEqual(result.content, "ok")
        self.assertEqual(gateway.seen["payload"], {"input": "normalized", "marker": "marker-1", "hermes_submission_id": "sub-1"})
        self.assertNotIn("parts", gateway.seen["payload"])
        self.assertNotIn("manifest", gateway.seen["payload"])
        self.assertEqual(gateway.seen["headers"]["X-Hermes-Session-Key"], "project:abc:default")

    def test_http_submit_projects_inner_request_from_durable_ingress_envelope(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self):
                super().__init__("http://127.0.0.1:9")
                self.seen = None

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.seen = {"method": method, "path": path, "payload": payload, "headers": dict(extra_headers or {})}
                return {"assistant_message_id": "m-2", "content": "ok"}

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
            gateway.seen["payload"],
            {"input": "normalized from durable ingress", "marker": "marker-2", "hermes_submission_id": "sub-2"},
        )

    def test_http_submit_projects_each_attachment_type_as_safe_reference(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self, mime):
                attachment_sha256 = hashlib.sha256(b"x" * 42).hexdigest()
                super().__init__(
                    "http://127.0.0.1:9",
                    attachment_resolver=lambda _reference: {
                        "body": b"x" * 42,
                        "sha256": attachment_sha256,
                        "mime": mime,
                    },
                )
                self.seen = None

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.seen = {"method": method, "path": path, "payload": payload, "headers": dict(extra_headers or {})}
                return {"assistant_message_id": "m-attachments", "content": "ok"}

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
                gateway.submit(
                    session_key="project:attachments:default",
                    request={
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
                    },
                    submission_id=f"sub-{name}",
                    marker=f"marker-{name}",
                )
                payload = gateway.seen["payload"]
                self.assertTrue(payload["input"])
                self.assertEqual(payload["attachment_schema"], "recorder-next/attachment-reference/v1")
                self.assertEqual(len(payload["attachments"]), 1)
                reference = payload["attachments"][0]
                self.assertEqual(reference["part_id"], part_id)
                self.assertEqual(reference["mime"], mime)
                self.assertEqual(reference["byte_length"], 42)
                self.assertEqual(reference["sha256"], attachment_sha256)
                self.assertTrue(reference["reference"].startswith("recorder://"))
                serialized = json.dumps(payload, ensure_ascii=False)
                self.assertNotIn("source_path", serialized)
                self.assertNotIn("private-device-must-not-leak", serialized)
                self.assertNotIn("parts", payload)

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
                with self.assertRaisesRegex(ValueError, "attachment-only projection"):
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
                super().__init__("http://127.0.0.1:9")

            def _request(self, method, path, payload=None, *, extra_headers=None):
                return {"assistant_message_id": "authoritative-id", "content": "ok"}

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
