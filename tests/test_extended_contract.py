import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from recorder_next.adapters import StaticASRProvider, StaticTTSProvider
from recorder_next.canonical import hermes_content_hash, normalize_hermes_text
from recorder_next.errors import ConflictError
from recorder_next.models import AsrResult, HermesResult, RouterDecision
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


def audio_manifest(turn_id, *, text=b"pcm-fixture"):
    return {
        "schema_version": 1,
        "user_id": "user-audio",
        "turn_id": turn_id,
        "origin_device_id": "watch-1",
        "client_created_at": "2026-08-25T00:00:00Z",
        "current_project_number": None,
        "prefer_current_project": False,
        "parts": [
            {
                "part_id": "audio-1",
                "kind": "audio",
                "mime": "audio/pcm",
                "declared_bytes": len(text),
                "declared_sha256": hashlib.sha256(text).hexdigest(),
                "relationship": None,
                "caption_hash": None,
                "streaming": True,
            }
        ],
    }


def make_audio_store(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890ad"):
    store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
    m = audio_manifest(turn_id)
    store.create_turn(m)
    store.put_chunk(turn_id, "audio-1", 0, b"pcm-")
    store.put_chunk(turn_id, "audio-1", 1, b"fixture")
    data = b"pcm-fixture"
    store.finish_part(turn_id, "audio-1", total_chunks=2, total_bytes=len(data), whole_stream_sha256=hashlib.sha256(data).hexdigest())
    store.accept_turn(turn_id)
    return store, turn_id


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class CanonicalResultTests(unittest.TestCase):
    def test_nfc_and_crlf_normalize_but_whitespace_is_preserved(self):
        self.assertEqual(normalize_hermes_text("e\u0301\r\nline\rnext"), "é\nline\nnext")
        self.assertEqual(hermes_content_hash("é\nline\nnext"), hermes_content_hash("e\u0301\r\nline\rnext"))
        self.assertNotEqual(hermes_content_hash("answer"), hermes_content_hash(" answer"))
        self.assertNotEqual(hermes_content_hash("a\n\nb"), hermes_content_hash("a\nb"))


class ASRArbitrationTests(unittest.TestCase):
    def test_fallback_generation_accepts_only_current_provider_and_deletes_audio_after_valid_transcript(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id = make_audio_store(tmp)
            first_generation = store.set_asr_stage(turn_id, expected_generation=0, stage="realtime")
            self.assertEqual(first_generation, 1)
            self.assertFalse(store.commit_asr_result(turn_id, expected_generation=0, stage="realtime", result=AsrResult.valid("stale")))
            self.assertTrue(store.commit_asr_result(turn_id, expected_generation=1, stage="realtime", result=AsrResult.valid("hello")))
            turn = store.get_turn(turn_id)
            self.assertEqual(turn["authoritative_asr_outcome"], "VALID_TRANSCRIPT")
            self.assertEqual(turn["transcript"], "hello")
            self.assertTrue(turn["source_deleted"])
            self.assertFalse(any(Path(part["source_path"]).exists() for part in turn["parts"] if part["kind"] == "audio"))

    def test_valid_asr_keeps_source_flag_unset_when_physical_deletion_fails(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id = make_audio_store(tmp, "018f5a2e-7b6e-7abc-8d11-1234567890af")
            first_generation = store.set_asr_stage(turn_id, expected_generation=0, stage="realtime")
            source_path = Path(store.get_turn(turn_id)["parts"][0]["source_path"])
            with patch.object(Path, "unlink", side_effect=PermissionError("fixture deletion failure")):
                self.assertTrue(store.commit_asr_result(turn_id, expected_generation=first_generation, stage="realtime", result=AsrResult.valid("hello")))
            self.assertFalse(store.get_turn(turn_id)["source_deleted"])
            self.assertTrue(source_path.exists())
            self.assertEqual(store.recover()["source_deletions_retried"], 1)
            self.assertTrue(store.get_turn(turn_id)["source_deleted"])
            self.assertFalse(source_path.exists())

    def test_service_falls_from_realtime_and_batch_to_local(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id = make_audio_store(tmp, "018f5a2e-7b6e-7abc-8d11-1234567890ae")
            service = RecorderService(
                store,
                asr_providers={
                    "realtime": StaticASRProvider("realtime", AsrResult.error("offline")),
                    "batch": StaticASRProvider("batch", AsrResult.error("offline")),
                    "local": StaticASRProvider("local", AsrResult.valid("fallback transcript")),
                },
            )
            result = service.run_asr(turn_id)
            self.assertEqual(result["transcript"], "fallback transcript")
            self.assertEqual(result["asr_generation"], 3)
            self.assertEqual(len(result["asr_attempts"]), 3)


class GraceAndArchiveTests(unittest.TestCase):
    def test_hermes_error_grace_recovers_with_late_success_and_duplicate_result_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            store.register_device("user-1", "phone-1", "phone")
            manifest = {
                "schema_version": 1,
                "user_id": "user-1",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890af",
                "origin_device_id": "phone-1",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": "P-001",
                "prefer_current_project": True,
                "parts": [{"part_id": "text-1", "kind": "text", "mime": "text/plain", "declared_bytes": 1, "declared_sha256": hashlib.sha256(b"x").hexdigest()}],
            }
            store.create_turn(manifest)
            store.put_chunk(manifest["turn_id"], "text-1", 0, b"x")
            store.finish_part(manifest["turn_id"], "text-1", total_chunks=1, total_bytes=1, whole_stream_sha256=hashlib.sha256(b"x").hexdigest())
            store.accept_turn(manifest["turn_id"])
            project = store.create_project("user-1", project_number="P-001", name="Fixture")
            store.commit_route(manifest["turn_id"], RouterDecision("route", project["stable_project_id"], project["default_session_key"], 1, "전달", "fixture"))
            route = store.pending_outbox("phone-1", user_id="user-1")[0]
            store.ack_event(manifest["turn_id"], route["event_id"], device_id="phone-1", event_version=1, payload_sha256=route["payload_sha256"])
            with store._read() as conn:
                submission = conn.execute("SELECT hermes_submission_id FROM session_ingress WHERE turn_id=?", (manifest["turn_id"],)).fetchone()[0]
            failed = store.commit_hermes_error(submission, grace_seconds=600)
            self.assertEqual(failed["state"], "LATE_RESULT_GRACE")
            recovered = store.commit_hermes_result(submission, HermesResult("late-1", "실제 결과"))
            self.assertEqual(recovered["final_event_version"], 2)
            self.assertIn("실제 결과", recovered["final_content"])
            again = store.commit_hermes_result(submission, HermesResult("late-1", "실제 결과"))
            self.assertEqual(again["final_event_version"], 2)

    def test_project_cas_and_archive_keep_data_but_hide_from_active_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            project = store.create_project("u", project_number="P-1", name="One")
            updated = store.update_project("u", project["stable_project_id"], expected_version=1, patch={"name": "Renamed"})
            self.assertEqual(updated["record_version"], 2)
            with self.assertRaises(ConflictError):
                store.update_project("u", project["stable_project_id"], expected_version=1, patch={"name": "Lost"})
            archived = store.archive_project("u", project["stable_project_id"], expected_version=2)
            self.assertEqual(archived["status"], "archived")
            self.assertEqual(store.list_projects("u"), [])
            self.assertEqual(store.get_project("u", project["stable_project_id"])["status"], "archived")

    def test_service_auto_creates_project_when_no_current_project_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            service = RecorderService(store, hermes=None)
            manifest = {
                "schema_version": 1,
                "user_id": "new-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890b3",
                "origin_device_id": "phone-new",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": None,
                "prefer_current_project": False,
                "text": "새 프로젝트로 정리해 줘",
            }
            service.accept_text_turn(manifest, manifest["text"])
            routed = service.route_next("new-user")
            self.assertEqual(routed["state"], "HERMES_PENDING")
            self.assertIsNotNone(routed["project_id"])
            self.assertEqual(len(store.list_projects("new-user")), 1)

    def test_router_exception_becomes_durable_routing_error_and_releases_lease(self):
        class BrokenRouter:
            def decide(self, turn, projects):
                raise RuntimeError("synthetic router down")

        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            service = RecorderService(store, router=BrokenRouter())
            manifest = {
                "schema_version": 1,
                "user_id": "router-error-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890d1",
                "origin_device_id": "device-1",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": None,
                "prefer_current_project": False,
            }
            service.accept_text_turn(manifest, "fixture")
            result = service.route_next("router-error-user", owner="router-test")
            self.assertEqual(result["final_error_kind"], "routing")
            self.assertEqual(result["state"], "FINAL_READY")

    def test_invalid_explicit_current_project_becomes_fixed_routing_error_without_routed_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            service = RecorderService(store)
            manifest = {
                "schema_version": 1,
                "user_id": "invalid-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890b4",
                "origin_device_id": "phone-invalid",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": "MISSING",
                "prefer_current_project": True,
                "text": "fixture",
            }
            service.accept_text_turn(manifest, manifest["text"])
            failed = service.route_next("invalid-user")
            self.assertEqual(failed["state"], "FINAL_READY")
            self.assertEqual([event["event_kind"] for event in failed["events"]], ["ACCEPTED", "FINAL"])
            self.assertEqual(failed["final_error_kind"], "routing")

    def test_service_routes_submits_hermes_and_generates_only_first_final_tts(self):
        from recorder_next.adapters import MemoryHermesGateway

        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            project = store.create_project("flow-user", project_number="P-1", name="Flow")
            gateway = MemoryHermesGateway()
            service = RecorderService(store, hermes=gateway, tts=StaticTTSProvider())
            manifest = {
                "schema_version": 1,
                "user_id": "flow-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890b5",
                "origin_device_id": "flow-phone",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": "P-1",
                "prefer_current_project": True,
                "text": "flow request",
            }
            service.accept_text_turn(manifest, manifest["text"])
            routed = service.route_next("flow-user")
            self.assertEqual(routed["project_id"], project["stable_project_id"])
            with store._read() as conn:
                submission_id = conn.execute("SELECT hermes_submission_id FROM session_ingress WHERE turn_id=?", (manifest["turn_id"],)).fetchone()[0]
            gateway.responses[submission_id] = HermesResult("flow-message", "flow final")
            final = service.process_next_hermes(project["stable_project_id"])
            self.assertEqual(final["final_event_version"], 1)
            ingress = store.get_ingress(submission_id)
            self.assertEqual(ingress["payload"]["request"]["input"], "flow request")
            generated = service.generate_pending_tts()
            self.assertEqual(len(generated), 2)
            self.assertEqual(len(store.get_turn(manifest["turn_id"])["tts_artifacts"]), 2)


class HTTPContractTests(unittest.TestCase):
    def test_versioned_api_accepts_text_turn_and_exposes_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            service = RecorderService(store)
            status, _, health = service.handle_http("GET", "/v1/health", {}, b"")
            self.assertEqual(status, 200)
            self.assertEqual(health["api_version"], "v1")
            payload = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890b0",
                "origin_device_id": "d",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": None,
                "prefer_current_project": False,
                "text": "fixture",
            }
            store.register_device("u", "d", "phone")
            status, _, created = service.handle_http("POST", "/v1/turns", {}, json_bytes(payload))
            self.assertEqual(status, 202)
            self.assertEqual(created["state"], "ACCEPTED")
            status, _, fetched = service.handle_http("GET", "/v1/turns/018f5a2e-7b6e-7abc-8d11-1234567890b0?user_id=u&device_id=d", {}, b"")
            self.assertEqual(status, 200)
            self.assertEqual(fetched["accepted_seq"], 1)

    def test_versioned_api_accept_route_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            service = RecorderService(store)
            payload = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890b1",
                "origin_device_id": "d",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": None,
                "prefer_current_project": False,
                "text": "fixture",
            }
            store.register_device("u", "d", "phone")
            status, _, created = service.handle_http("POST", "/v1/turns", {}, json_bytes(payload))
            self.assertEqual(status, 202)
            status, _, accepted = service.handle_http("POST", "/v1/turns/018f5a2e-7b6e-7abc-8d11-1234567890b1/accept", {}, json_bytes({"user_id": "u", "device_id": "d"}))
            self.assertEqual(status, 200)
            self.assertEqual(accepted["accepted_seq"], created["accepted_seq"])

    def test_http_event_ack_requires_exact_origin_device_and_hash(self):
        from tests.test_reliability_contract import setup_text_flow

        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, _ = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890b6")
            service = RecorderService(store)
            event = store.get_turn(turn_id)["events"][1]
            body = json_bytes({"user_id": "u", "device_id": "device-1", "event_version": 1, "payload_sha256": event["payload_sha256"]})
            status, _, result = service.handle_http("POST", f"/v1/turns/{turn_id}/events/{event['event_id']}/ack", {}, body)
            self.assertEqual(status, 200)
            self.assertEqual(result["outbox"][0]["state"], "ACKED")

    def test_tts_download_is_origin_bound_and_hashes_payload(self):
        import base64

        from tests.test_reliability_contract import setup_text_flow

        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, _ = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890cc")
            service = RecorderService(store)
            artifact = store.get_turn(turn_id)["tts_artifacts"][0]
            ready = store.set_tts_result(artifact["artifact_id"], {"audio": b"tts-bytes", "mode": "file"})
            status, _, downloaded = service.handle_http("GET", f"/v1/tts/{artifact['artifact_id']}?user_id=u&device_id=device-1", {}, b"")
            self.assertEqual(status, 200)
            self.assertEqual(base64.b64decode(downloaded["audio_base64"]), b"tts-bytes")
            status, _, denied = service.handle_http("GET", f"/v1/tts/{artifact['artifact_id']}?user_id=u&device_id=other", {}, b"")
            self.assertEqual(status, 401)

    def test_device_registration_and_revoke_are_versioned_api_seams(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RecorderService(RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data"))
            status, _, device = service.handle_http("POST", "/v1/devices", {}, json_bytes({"user_id": "u", "device_id": "phone-1", "kind": "phone"}))
            self.assertEqual(status, 201)
            self.assertEqual(device["status"], "active")
            status, _, revoked = service.handle_http("POST", "/v1/devices/phone-1/revoke", {}, json_bytes({"user_id": "u", "actor_device_id": "phone-1"}))
            self.assertEqual(status, 200)
            self.assertEqual(revoked["status"], "revoked")

    def test_standalone_http_server_binds_only_ephemeral_loopback_for_smoke(self):
        import threading
        import urllib.request

        from recorder_next.http import create_http_server

        with tempfile.TemporaryDirectory() as tmp:
            service = RecorderService(RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data"))
            service.store.register_device("u", "d", "phone")
            server = create_http_server(service, host="127.0.0.1", port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"
                with urllib.request.urlopen(base + "/v1/health", timeout=2) as response:
                    self.assertEqual(response.status, 200)
                payload = {
                    "schema_version": 1,
                    "user_id": "u",
                    "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890b2",
                    "origin_device_id": "d",
                    "client_created_at": "2026-08-25T00:00:00Z",
                    "current_project_number": None,
                    "prefer_current_project": False,
                    "text": "fixture",
                }
                request = urllib.request.Request(base + "/v1/turns", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(request, timeout=2) as response:
                    body = json.loads(response.read())
                    self.assertEqual(response.status, 202)
                    self.assertEqual(body["state"], "ACCEPTED")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
