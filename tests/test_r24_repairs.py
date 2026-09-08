import base64
import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import uuid
from pathlib import Path

from recorder_next.adapters import HermesAudioASRProvider, HttpHermesGateway, MemoryHermesGateway, ProviderFailure, StaticTTSProvider
from recorder_next.config import RecorderConfig
from recorder_next.openapi import OPENAPI, validate_openapi_contract
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


class R24HermesContractTests(unittest.TestCase):
    def test_hermes_asr_uses_pinned_data_url_contract_and_mime(self):
        class ProbeProvider(HermesAudioASRProvider):
            def __init__(self):
                super().__init__("http://127.0.0.1:9120", profile="default", credential_file=None)
                self.payload = None

            def _request(self, payload, *, max_response_bytes=0):
                self.payload = dict(payload)
                return "application/json", json.dumps({"ok": True, "transcript": "hello"}).encode()

        provider = ProbeProvider()
        audio = b"RIFFfixture"
        result = provider.transcribe(audio, turn_id="turn-1", generation=2)

        self.assertEqual(result.transcript, "hello")
        self.assertIn("data_url", provider.payload)
        self.assertNotIn("audio", provider.payload)
        self.assertEqual(provider.payload["mime_type"], "audio/wav")
        header, encoded = provider.payload["data_url"].split(",", 1)
        self.assertEqual(header, "data:audio/wav;base64")
        self.assertEqual(base64.b64decode(encoded), audio)

    def test_run_submission_replays_same_downstream_effect_after_ambiguous_response(self):
        class Downstream:
            def __init__(self):
                self.effects = 0
                self.run_id = "run_stable"
                self.status_reads = 0
                self.readable = False

            def request(self, method, path, payload=None, *, extra_headers=None):
                if method == "POST" and path == "/v1/runs":
                    if self.effects == 0:
                        self.effects += 1
                    self.assert_idempotency(extra_headers)
                    return {"run_id": self.run_id, "status": "started", "replayed": self.effects > 1}
                if method == "GET" and path == "/v1/runs/run_stable":
                    self.status_reads += 1
                    if not self.readable:
                        raise urllib.error.URLError("response lost")
                    return {"run_id": self.run_id, "status": "completed", "output": "one effect"}
                return {"content": "legacy route"}

            def assert_idempotency(self, headers):
                self.last_key = dict(headers or {}).get("Idempotency-Key")

        downstream = Downstream()

        class ProbeGateway(HttpHermesGateway):
            def __init__(self, server, **kwargs):
                super().__init__(
                    "http://127.0.0.1:8642",
                    api_key_file=None,
                    **kwargs,
                )
                self.server = server
                self.calls = []

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.calls.append((method, path, payload, dict(extra_headers or {})))
                return self.server.request(method, path, payload, extra_headers=extra_headers)

        first = ProbeGateway(downstream, max_submit_attempts=1, run_timeout_seconds=0.01, poll_interval_seconds=0)
        self.assertIsNone(first.submit(
            session_key="project:one:default",
            request={"input": "hello"},
            submission_id="submission-1",
            marker="marker-1",
        ))

        # A new adapter instance models a Recorder restart.  The same key and
        # body must recover the already admitted run without a second effect.
        downstream.readable = True
        second = ProbeGateway(downstream)
        result = second.submit(
            session_key="project:one:default",
            request={"input": "hello"},
            submission_id="submission-1",
            marker="marker-1",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.content, "one effect")
        self.assertEqual(result.assistant_message_id, "run_stable")
        self.assertEqual(downstream.effects, 1)
        self.assertEqual(
            [call[0:2] for call in second.calls],
            [("POST", "/v1/runs"), ("GET", "/v1/runs/run_stable")],
        )
        self.assertEqual(second.calls[0][3]["Idempotency-Key"], "submission-1")

    def test_run_submission_retries_after_post_response_loss_without_a_second_effect(self):
        class Downstream:
            def __init__(self):
                self.effects = 0
                self.post_calls = 0

            def request(self, method, path, payload=None, *, extra_headers=None):
                if method == "POST" and path == "/v1/runs":
                    self.post_calls += 1
                    if (extra_headers or {}).get("Idempotency-Key") != "submission-loss":
                        raise AssertionError(extra_headers)
                    if self.post_calls == 1:
                        self.effects += 1
                        raise urllib.error.URLError("POST response lost after admission")
                    return {"run_id": "run-loss", "status": "started"}
                if method == "GET" and path == "/v1/runs/run-loss":
                    return {"run_id": "run-loss", "status": "completed", "output": "one effect"}
                raise AssertionError((method, path))

        class ProbeGateway(HttpHermesGateway):
            def __init__(self, downstream):
                super().__init__(
                    "http://127.0.0.1:8642",
                    api_key_file=None,
                    max_submit_attempts=2,
                    poll_interval_seconds=0,
                    run_timeout_seconds=1,
                )
                self.downstream = downstream

            def _request(self, method, path, payload=None, *, extra_headers=None):
                return self.downstream.request(method, path, payload, extra_headers=extra_headers)

        downstream = Downstream()
        result = ProbeGateway(downstream).submit(
            session_key="project:loss:default",
            request={"input": "hello"},
            submission_id="submission-loss",
            marker="marker-loss",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.content, "one effect")
        self.assertEqual(downstream.effects, 1)
        self.assertEqual(downstream.post_calls, 2)

    def test_image_bytes_are_inlined_and_documents_fail_before_submit(self):
        image_bytes = b"PNG-bytes"
        image_sha = hashlib.sha256(image_bytes).hexdigest()

        class ProbeGateway(HttpHermesGateway):
            def __init__(self, mime="image/png"):
                super().__init__(
                    "http://127.0.0.1:8642",
                    api_key_file=None,
                    attachment_resolver=lambda _reference: {
                        "body": image_bytes,
                        "sha256": image_sha,
                        "mime": mime,
                    },
                )
                self.payload = None
                self.calls = 0

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.calls += 1
                if payload is not None:
                    self.payload = payload
                if method == "POST" and path == "/v1/runs":
                    return {"run_id": "run-image", "status": "started"}
                if method == "GET" and path == "/v1/runs/run-image":
                    return {"run_id": "run-image", "status": "completed", "output": "seen"}
                return {"content": "legacy route"}

        image_gateway = ProbeGateway()
        result = image_gateway.submit(
            session_key="project:image:default",
            request={
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890aa",
                "input": "Describe this image",
                "parts": [{
                    "part_id": "image-1",
                    "kind": "attachment",
                    "mime": "image/png",
                    "total_bytes": len(image_bytes),
                    "whole_stream_sha256": image_sha,
                    "status": "COMPLETE",
                }],
            },
            submission_id="submission-image",
            marker="marker-image",
        )
        self.assertEqual(result.content, "seen")
        content = image_gateway.payload["input"][0]["content"]
        self.assertEqual(content[0], {"type": "input_text", "text": "Describe this image"})
        self.assertEqual(content[1]["type"], "input_image")
        self.assertEqual(content[1]["image_url"], "data:image/png;base64," + base64.b64encode(image_bytes).decode())
        self.assertNotIn("attachments", image_gateway.payload)

        document_gateway = ProbeGateway(mime="application/pdf")
        with self.assertRaisesRegex(ValueError, "document input is unsupported"):
            document_gateway.submit(
                session_key="project:document:default",
                request={
                    "input": "Summarize this document",
                    "parts": [{
                        "part_id": "document-1",
                        "kind": "document",
                        "mime": "application/pdf",
                        "total_bytes": len(image_bytes),
                        "whole_stream_sha256": image_sha,
                        "status": "COMPLETE",
                    }],
                },
                submission_id="submission-document",
                marker="marker-document",
            )
        self.assertEqual(document_gateway.calls, 0)

    def test_router_receives_canonical_text_and_rejects_unsupported_documents_durably(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            project = store.create_project("user-1", project_number="P-1", name="Project")

            text_manifest = {
                "schema_version": 1,
                "user_id": "user-1",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890ab",
                "origin_device_id": "device-1",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": "P-1",
                "prefer_current_project": True,
                "parts": [{"part_id": "text-1", "kind": "text", "mime": "text/plain", "declared_bytes": 5}],
            }
            store.create_turn(text_manifest)
            store.put_chunk(text_manifest["turn_id"], "text-1", 0, b"hello")
            store.finish_part(text_manifest["turn_id"], "text-1", total_chunks=1, total_bytes=5, whole_stream_sha256=hashlib.sha256(b"hello").hexdigest())
            store.accept_turn(text_manifest["turn_id"])
            gateway = MemoryHermesGateway()
            service = RecorderService(store, hermes=gateway, tts=StaticTTSProvider())
            routed = service.route_next("user-1")
            self.assertEqual(routed["state"], "HERMES_PENDING")
            self.assertEqual(gateway.calls, [])
            submission_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:submission:{text_manifest['turn_id']}"))
            ingress = store.get_ingress(submission_id)
            self.assertEqual(ingress["payload"]["request"]["input"], "hello")

            document = b"pdf"
            document_project = store.create_project("user-1", project_number="P-2", name="Document project")
            document_id = "018f5a2e-7b6e-7abc-8d11-1234567890ac"
            document_manifest = {
                **text_manifest,
                "turn_id": document_id,
                "current_project_number": "P-2",
                "parts": [{"part_id": "document-1", "kind": "attachment", "mime": "application/pdf", "declared_bytes": len(document), "declared_sha256": hashlib.sha256(document).hexdigest()}],
            }
            store.create_turn(document_manifest)
            store.put_chunk(document_id, "document-1", 0, document)
            store.finish_part(document_id, "document-1", total_chunks=1, total_bytes=len(document), whole_stream_sha256=hashlib.sha256(document).hexdigest())
            store.accept_turn(document_id)
            routed_document = service.route_next("user-1")
            self.assertEqual(routed_document["state"], "HERMES_PENDING")
            rejected = service.process_next_hermes(document_project["stable_project_id"])
            self.assertEqual(rejected["state"], "FINAL_READY")
            self.assertEqual(rejected["final_outcome"], "error")
            self.assertEqual(rejected["final_error_kind"], "hermes")
            self.assertIn("첨부 파일 형식", rejected["final_content"])
            self.assertEqual(gateway.calls, [])

    def test_isolated_audio_readiness_rejects_disabled_stt_capability(self):
        class ProbeProvider(HermesAudioASRProvider):
            def __init__(self):
                super().__init__("http://127.0.0.1:9120", profile="default", credential_file=None)

            def health_check(self):
                return {"ok": True, "status": "ok"}

            def capability_check(self):
                return {"ok": True, "stt": {"mode": "relay", "reason": "stt disabled"}}

        with self.assertRaisesRegex(ProviderFailure, "stt_disabled"):
            ProbeProvider().readiness_check()


class R24DiagnosticsAndOpenAPITests(unittest.TestCase):
    def test_chunk_write_cannot_be_cleaned_between_file_and_row_commit(self):
        from recorder_next.features import FeatureGroups

        class RacingFeatures(FeatureGroups):
            def __init__(self, store):
                super().__init__(store)
                self.cleanup_started = threading.Event()
                self.allow_cleanup = threading.Event()

            def _cleanup_reference_state(self, receipt):
                self.cleanup_started.set()
                self.allow_cleanup.wait(timeout=2)
                return super()._cleanup_reference_state(receipt)

        class RacingStore(RecorderStore):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.write_finished = threading.Event()
                self.allow_commit = threading.Event()
                self.recovery_invoked = threading.Event()
                self._features = RacingFeatures(self)

            def _safe_write(self, path, payload):
                super()._safe_write(path, payload)
                self.write_finished.set()
                self.allow_commit.wait(timeout=2)

            def recover_cleanup_receipts(self, *, receipt_ids=None, now=None):
                self.recovery_invoked.set()
                return super().recover_cleanup_receipts(receipt_ids=receipt_ids, now=now)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RacingStore(root / "state.sqlite3", storage_root=root / "data")
            store.create_turn(
                {
                    "schema_version": 1,
                    "user_id": "race-user",
                    "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890ff",
                    "origin_device_id": "race-phone",
                    "client_created_at": "2026-09-09T00:00:00Z",
                    "parts": [
                        {
                            "part_id": "part-1",
                            "kind": "text",
                            "mime": "text/plain",
                            "declared_bytes": 5,
                            "declared_sha256": hashlib.sha256(b"hello").hexdigest(),
                        }
                    ],
                }
            )
            result = {}
            failure = []

            def write_chunk():
                try:
                    result.update(store.put_chunk("018f5a2e-7b6e-7abc-8d11-1234567890ff", "part-1", 0, b"hello"))
                except BaseException as exc:
                    failure.append(exc)

            writer = threading.Thread(target=write_chunk)
            recovery = threading.Thread(target=store.recover_cleanup_receipts)
            writer.start()
            self.assertTrue(store.write_finished.wait(timeout=2))
            recovery.start()
            self.assertTrue(store.recovery_invoked.wait(timeout=2))
            try:
                self.assertFalse(store._features.cleanup_started.wait(timeout=0.25))
            finally:
                store.allow_commit.set()
                writer.join(timeout=2)
                store._features.allow_cleanup.set()
                recovery.join(timeout=2)

            self.assertFalse(writer.is_alive())
            self.assertFalse(recovery.is_alive())
            self.assertEqual(failure, [])
            self.assertTrue(Path(result["storage_path"]).is_file())

    def test_audio_provider_never_inherits_main_hermes_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credential = root / "credential.env"
            credential.write_text("API_SERVER_KEY=fixture-value", encoding="ascii")
            credential.chmod(0o600)
            config = RecorderConfig(
                database=str(root / "state.sqlite3"),
                storage_root=str(root / "data"),
                hermes_base_url="http://127.0.0.1:8642",
                hermes_api_key_file=str(credential),
                tts_provider="disabled",
                tts_source="disabled",
            )
            from recorder_next.service import create_configured_service

            service = create_configured_service(config)
            self.assertIsNone(service.asr_chain)

    def test_diagnostics_limits_are_validated_before_store_use(self):
        for field_name, value in (
            ("diagnostics_tombstone_retention_seconds", 0),
            ("diagnostics_tombstone_retention_seconds", 367 * 86400),
            ("diagnostics_export_max_bytes", 1023),
            ("diagnostics_export_max_bytes", 65 * 1024 * 1024),
        ):
            with self.subTest(field_name=field_name, value=value):
                config = RecorderConfig()
                object.__setattr__(config, field_name, value)
                with self.assertRaises(ValueError):
                    config.validate()

    def test_openapi_describes_raw_chunk_bytes_as_octet_stream(self):
        operation = OPENAPI["paths"]["/v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}"]["put"]
        content = operation["requestBody"]["content"]
        self.assertEqual(set(content), {"application/octet-stream"})
        self.assertEqual(content["application/octet-stream"]["schema"]["$ref"], "#/components/schemas/ChunkUpload")

    def test_static_openapi_projection_matches_runtime_contract(self):
        static_document = json.loads((Path(__file__).parents[1] / "api/openapi.json").read_text(encoding="utf-8"))
        self.assertEqual(static_document, OPENAPI)

    def test_diagnostics_export_is_count_bounded_cursorable_and_tombstones_expire(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(
                Path(tmp) / "state.sqlite3",
                storage_root=Path(tmp) / "data",
                diagnostics_retention_seconds=1,
                diagnostics_tombstone_retention_seconds=1,
            )
            store.register_device("user-1", "phone-1", "phone")
            consent = store.record_diagnostics_opt_in("user-1", "phone-1", now="2026-09-09T00:00:00+00:00")
            event_ids = []
            for index in range(4):
                event_id = str(uuid.uuid4())
                event_ids.append(event_id)
                store.ingest_diagnostic_event(
                    "user-1",
                    "phone-1",
                    event_id=event_id,
                    idempotency_key=f"diag-{index}",
                    payload={"category": "voice", "stage": f"stage-{index}", "index": index},
                    now="2026-09-09T00:00:00+00:00",
                )

            first = store.export_diagnostics("user-1", "phone-1", limit=2, max_bytes=100_000)
            self.assertEqual(len(first["items"]), 2)
            self.assertTrue(first["truncated"])
            self.assertIsNotNone(first["next_cursor"])
            second = store.export_diagnostics(
                "user-1",
                "phone-1",
                cursor=first["next_cursor"],
                limit=2,
                max_bytes=100_000,
            )
            self.assertEqual(len(second["items"]), 2)
            self.assertFalse({item["event_id"] for item in first["items"]} & {item["event_id"] for item in second["items"]})

            deleted = store.delete_diagnostics("user-1", "phone-1", now="2026-09-09T00:00:01+00:00")
            self.assertEqual(deleted["tombstones"], 4)
            export_with_tombstones = store.export_diagnostics("user-1", "phone-1", limit=10, max_bytes=100_000)
            self.assertEqual(len(export_with_tombstones["tombstones"]), 4)
            purged = store.purge_diagnostics(now="2026-09-09T00:00:03+00:00")
            self.assertEqual(purged["tombstones"], 4)
            self.assertEqual(store.export_diagnostics("user-1", "phone-1", limit=10, max_bytes=100_000)["tombstones"], [])
            self.assertEqual(consent["device_id"], "phone-1")

    def test_openapi_has_executable_body_models_for_public_runtime_operations(self):
        validate_openapi_contract()
        schemas = OPENAPI["components"]["schemas"]
        self.assertIn("TurnPart", schemas)
        self.assertEqual(schemas["TurnCreate"]["properties"]["parts"]["items"]["$ref"], "#/components/schemas/TurnPart")
        self.assertEqual(set(schemas["TurnPart"]["required"]), {"part_id", "kind", "mime"})
        self.assertIn(schemas["TurnPart"]["properties"]["declared_bytes"]["type"], ("integer", ["integer", "null"]))
        self.assertEqual(schemas["TurnPart"]["properties"]["streaming"]["type"], "boolean")

        required_body_refs = {
            ("/v1/devices", "post"),
            ("/v1/devices/{device_id}/revoke", "post"),
            ("/v1/turns", "post"),
            ("/v1/turns/{turn_id}/accept", "post"),
            ("/v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}", "put"),
            ("/v1/turns/{turn_id}/parts/{part_id}/finish", "post"),
            ("/v1/turns/{turn_id}/events/{event_id}/ack", "post"),
            ("/v1/tts/{artifact_id}/relay-received", "post"),
            ("/v1/tts/{artifact_id}/playback-ack", "post"),
            ("/v1/projects", "post"),
            ("/v1/projects/{project_id}", "patch"),
            ("/v1/projects/{project_id}/archive", "post"),
            ("/v1/turns/{turn_id}/archive", "post"),
            ("/v1/eavesdrop", "post"),
            ("/v1/eavesdrop/{session_id}/activate", "post"),
            ("/v1/eavesdrop/{session_id}/segments", "post"),
            ("/v1/diagnostics/opt-in", "post"),
            ("/v1/diagnostics/events", "post"),
            ("/v1/diagnostics/bundles", "post"),
            ("/v1/diagnostics", "delete"),
            ("/v1/diagnostics/delete", "post"),
        }
        for path, method in required_body_refs:
            with self.subTest(path=path, method=method):
                operation = OPENAPI["paths"][path][method]
                self.assertTrue(operation.get("requestBody", {}).get("required"), path)

        for path in ("/v1/history", "/v1/turns/{turn_id}", "/v1/diagnostics/export"):
            operation = OPENAPI["paths"][path]["get"]
            parameter_names = {item.get("$ref") for item in operation.get("parameters", [])}
            self.assertIn("#/components/parameters/PrincipalUserHeader", parameter_names)
            self.assertIn("#/components/parameters/PrincipalDeviceHeader", parameter_names)


if __name__ == "__main__":
    unittest.main()
