import hashlib
import tempfile
import unittest
from pathlib import Path

from recorder_next.errors import LeaseConflict, MissingParts
from recorder_next.models import HermesResult, RouterDecision, TTSResult
from recorder_next.store import RecorderStore


def manifest(turn_id, *, user="user-1", device="phone-1", part_id="text-1", text=b"hello"):
    return {
        "schema_version": 1,
        "user_id": user,
        "turn_id": turn_id,
        "origin_device_id": device,
        "client_created_at": "2026-08-25T00:00:00Z",
        "current_project_number": "P-001",
        "prefer_current_project": True,
        "parts": [
            {
                "part_id": part_id,
                "kind": "text",
                "mime": "text/plain",
                "declared_bytes": len(text),
                "declared_sha256": hashlib.sha256(text).hexdigest(),
                "relationship": None,
                "caption_hash": None,
            }
        ],
    }


def accepted_store(tmp):
    store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
    store.register_device("user-1", "phone-1", "phone")
    m = manifest("018f5a2e-7b6e-7abc-8d11-1234567890ab")
    store.create_turn(m)
    payload = b"hello"
    store.put_chunk(m["turn_id"], "text-1", 0, payload)
    store.finish_part(m["turn_id"], "text-1", total_chunks=1, total_bytes=len(payload), whole_stream_sha256=hashlib.sha256(payload).hexdigest())
    store.accept_turn(m["turn_id"])
    return store, m["turn_id"]


class UploadAndAcceptanceTests(unittest.TestCase):
    def test_disk_free_admission_is_checked_before_acceptance(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data", min_free_bytes=10**30)
            with self.assertRaises(Exception):
                store.create_turn(manifest("018f5a2e-7b6e-7abc-8d11-1234567890d5", text=b"small"))

    def test_storage_component_rejects_path_traversal_in_part_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            payload = b"safe"
            manifest = {
                "schema_version": 1,
                "user_id": "safe-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890d2",
                "origin_device_id": "device-1",
                "client_created_at": "2026-08-25T00:00:00Z",
                "parts": [{"part_id": "part/../../escape", "kind": "text", "mime": "text/plain", "declared_bytes": len(payload), "declared_sha256": hashlib.sha256(payload).hexdigest()}],
            }
            with self.assertRaises(Exception):
                store.create_turn(manifest)

    def test_missing_chunk_cannot_be_accepted_and_finish_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            m = manifest("018f5a2e-7b6e-7abc-8d11-1234567890ac", text=b"hello world")
            store.create_turn(m)
            store.put_chunk(m["turn_id"], "text-1", 1, b"world")
            with self.assertRaises(MissingParts):
                store.finish_part(m["turn_id"], "text-1", total_chunks=2, total_bytes=11, whole_stream_sha256=hashlib.sha256(b"hello world").hexdigest())
            self.assertEqual(store.missing_sequences(m["turn_id"], "text-1", 2), [0])
            store.put_chunk(m["turn_id"], "text-1", 0, b"hello ")
            first = store.finish_part(m["turn_id"], "text-1", total_chunks=2, total_bytes=11, whole_stream_sha256=hashlib.sha256(b"hello world").hexdigest())
            same = store.finish_part(m["turn_id"], "text-1", total_chunks=2, total_bytes=11, whole_stream_sha256=hashlib.sha256(b"hello world").hexdigest())
            self.assertEqual(first["whole_stream_sha256"], same["whole_stream_sha256"])
            accepted = store.accept_turn(m["turn_id"])
            self.assertEqual(accepted["state"], "ACCEPTED")
            self.assertEqual(accepted["accepted_seq"], 1)


    def test_admission_rejects_over_limit_before_turn_bytes_are_stored(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data", max_turn_bytes=4, max_parts=1)
            m = manifest("018f5a2e-7b6e-7abc-8d11-1234567890c8", text=b"hello")
            with self.assertRaises(Exception):
                store.create_turn(m)
            self.assertEqual(store.db_snapshot()["turns"], 0)

    def test_router_lease_cas_transaction_and_ordered_final_outbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id = accepted_store(tmp)
            project = store.create_project("user-1", project_number="P-001", name="Fixture project")
            claim = store.claim_router("user-1", "router-a", lease_seconds=60)
            self.assertIsNotNone(claim)
            decision = RouterDecision(
                route_decision_id="route-1",
                project_id=project["stable_project_id"],
                session_key=project["default_session_key"],
                project_record_version=project["record_version"],
                routed_text="요청을 전달했습니다.",
                decision_reason_code="fixture_current_project",
            )
            routed = store.commit_route(turn_id, decision, owner="router-a")
            self.assertEqual(routed["state"], "HERMES_PENDING")
            pending = store.pending_outbox("phone-1", user_id="user-1")
            self.assertEqual([item["event_kind"] for item in pending], ["ROUTED"])
            route_event = pending[0]
            store.ack_event(turn_id, route_event["event_id"], device_id="phone-1", event_version=1, payload_sha256=route_event["payload_sha256"])
            ingress = store.get_ingress(store.get_turn(turn_id)["session_key"] and "" or "") if False else None
            with store._read() as conn:
                submission_id = conn.execute("SELECT hermes_submission_id FROM session_ingress WHERE turn_id=?", (turn_id,)).fetchone()[0]
            first = store.commit_hermes_result(submission_id, HermesResult("msg-1", "첫 답\r\n", True))
            self.assertEqual(first["final_event_version"], 1)
            self.assertEqual(first["state"], "FINAL_READY")
            final_pending = store.pending_outbox("phone-1", user_id="user-1")
            self.assertEqual([item["event_version"] for item in final_pending], [1])
            second = store.commit_hermes_result(submission_id, HermesResult("msg-2", "두 번째 답", True))
            self.assertEqual(second["final_event_version"], 2)
            self.assertEqual(second["final_content"], "첫 답\n\n두 번째 답")
            self.assertEqual(len(second["tts_artifacts"]), 2)  # ROUTED_TTS + FINAL_TTS(v1), no v2 TTS
            final_v1 = [item for item in store.pending_outbox("phone-1", user_id="user-1") if item["event_kind"] == "FINAL"][0]
            store.ack_event(turn_id, final_v1["event_id"], device_id="phone-1", event_version=1, payload_sha256=final_v1["payload_sha256"])
            pending_v2 = store.pending_outbox("phone-1", user_id="user-1")
            self.assertEqual([item["event_version"] for item in pending_v2], [2])

    def test_expired_router_lease_can_be_taken_over_but_cannot_commit_as_old_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id = accepted_store(tmp)
            claim = store.claim_router("user-1", "old", lease_seconds=1, now="2026-08-25T00:00:00+00:00")
            self.assertIsNotNone(claim)
            takeover = store.claim_router("user-1", "new", lease_seconds=30, now="2026-08-25T00:00:02+00:00")
            self.assertEqual(takeover["lease_owner"], "new")
            project = store.create_project("user-1", project_number="P-001", name="Fixture project")
            decision = RouterDecision("route-1", project["stable_project_id"], project["default_session_key"], 1, "전달", "fixture")
            with self.assertRaises(LeaseConflict):
                store.commit_route(turn_id, decision, owner="old", now="2026-08-25T00:00:02+00:00")


class TTSRetentionTests(unittest.TestCase):
    def test_playback_ack_is_origin_bound_and_deletes_only_after_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id = accepted_store(tmp)
            project = store.create_project("user-1", project_number="P-001", name="Fixture project")
            store.commit_route(turn_id, RouterDecision("route-1", project["stable_project_id"], project["default_session_key"], 1, "전달", "fixture"))
            artifact = store.get_turn(turn_id)["tts_artifacts"][0]
            store.set_tts_result(artifact["artifact_id"], TTSResult(b"fixture-audio"))
            ready = store.get_artifact(artifact["artifact_id"])
            self.assertTrue(Path(ready["storage_path"]).exists())
            with self.assertRaises(Exception):
                store.ack_playback(
                    artifact["artifact_id"],
                    device_id="other-device",
                    payload_sha256=ready["payload_sha256"],
                    turn_id=turn_id,
                    artifact_version=artifact["artifact_version"],
                )
            played = store.ack_playback(
                artifact["artifact_id"],
                device_id="phone-1",
                payload_sha256=ready["payload_sha256"],
                turn_id=turn_id,
                artifact_version=artifact["artifact_version"],
            )
            self.assertEqual(played["status"], "PLAYED")
            self.assertFalse(Path(ready["storage_path"]).exists())


if __name__ == "__main__":
    unittest.main()
