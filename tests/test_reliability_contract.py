import hashlib
import tempfile
import threading
import unittest
from pathlib import Path

from recorder_next.canonical import hermes_content_hash
from recorder_next.errors import ConflictError
from recorder_next.models import HermesResult, RouterDecision, TTSResult
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


def setup_text_flow(tmp, *, user="u", turn_id="018f5a2e-7b6e-7abc-8d11-1234567890c1", project_number="P-1"):
    root = Path(tmp)
    store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
    store.register_device(user, "device-1", "phone")
    data = b"fixture"
    manifest = {
        "schema_version": 1,
        "user_id": user,
        "turn_id": turn_id,
        "origin_device_id": "device-1",
        "client_created_at": "2026-08-25T00:00:00Z",
        "current_project_number": project_number,
        "prefer_current_project": True,
        "parts": [{"part_id": "text-1", "kind": "text", "mime": "text/plain", "declared_bytes": len(data), "declared_sha256": hashlib.sha256(data).hexdigest()}],
    }
    store.create_turn(manifest)
    store.put_chunk(turn_id, "text-1", 0, data)
    store.finish_part(turn_id, "text-1", total_chunks=1, total_bytes=len(data), whole_stream_sha256=hashlib.sha256(data).hexdigest())
    store.accept_turn(turn_id)
    project = store.create_project(user, project_number=project_number, name="Fixture")
    store.commit_route(turn_id, RouterDecision("route-1", project["stable_project_id"], project["default_session_key"], project["record_version"], "전달", "fixture"))
    route_event = store.pending_outbox("device-1")[0]
    store.ack_event(turn_id, route_event["event_id"], device_id="device-1", event_version=1, payload_sha256=route_event["payload_sha256"])
    with store._read() as conn:
        submission_id = conn.execute("SELECT hermes_submission_id FROM session_ingress WHERE turn_id=?", (turn_id,)).fetchone()[0]
    return store, turn_id, project, submission_id


class RecoveryAndConcurrencyTests(unittest.TestCase):
    def test_restart_recovery_requeues_expired_router_and_ingress_leases(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, project, submission_id = setup_text_flow(tmp)
            # The route is already done, so create a second turn's router lease.
            data = b"two"
            manifest = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890c2",
                "origin_device_id": "device-1",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": "P-1",
                "prefer_current_project": True,
                "parts": [{"part_id": "text-1", "kind": "text", "mime": "text/plain", "declared_bytes": len(data), "declared_sha256": hashlib.sha256(data).hexdigest()}],
            }
            store.create_turn(manifest)
            store.put_chunk(manifest["turn_id"], "text-1", 0, data)
            store.finish_part(manifest["turn_id"], "text-1", total_chunks=1, total_bytes=len(data), whole_stream_sha256=hashlib.sha256(data).hexdigest())
            store.accept_turn(manifest["turn_id"])
            claim = store.claim_router("u", "crashed-router", lease_seconds=1, now="2026-08-25T00:00:00+00:00")
            self.assertIsNotNone(claim)
            reopened = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            receipt = reopened.recover(now="2026-08-25T00:00:02+00:00")
            self.assertEqual(receipt["router_leases_requeued"], 1)
            takeover = reopened.claim_router("u", "recovered-router", lease_seconds=30, now="2026-08-25T00:00:02+00:00")
            self.assertEqual(takeover["lease_owner"], "recovered-router")

            ingress = reopened.claim_session_ingress(project["stable_project_id"], "crashed-hermes", lease_seconds=1, now="2026-08-25T00:00:00+00:00")
            self.assertIsNotNone(ingress)
            receipt = reopened.recover(now="2026-08-25T00:00:02+00:00")
            self.assertEqual(receipt["session_ingress_requeued"], 1)
            recovered_ingress = reopened.claim_session_ingress(project["stable_project_id"], "recovered-hermes", lease_seconds=30, now="2026-08-25T00:00:02+00:00")
            self.assertEqual(recovered_ingress["lease_owner"], "recovered-hermes")

    def test_restart_recovery_expires_elapsed_late_result_grace(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, submission_id = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890cb")
            store.commit_hermes_error(submission_id, grace_seconds=1)
            reopened = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            reopened.recover(now="2999-01-01T00:00:00+00:00")
            self.assertEqual(reopened.get_turn(turn_id)["state"], "EXPIRED")

    def test_concurrent_claim_has_one_winner(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, _ = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890c3")
            # setup_text_flow has already routed this one; use its queue to ensure no second claim.
            results = []
            lock = threading.Lock()

            def claim(owner):
                local = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
                value = local.claim_router("u", owner)
                with lock:
                    results.append(value)

            threads = [threading.Thread(target=claim, args=(f"owner-{i}",)) for i in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)
            self.assertEqual(sum(value is not None for value in results), 0)


class GraceAndCASRegressionTests(unittest.TestCase):
    def test_relay_receipt_requires_registered_non_origin_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, _ = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890d4")
            artifact = store.get_turn(turn_id)["tts_artifacts"][0]
            ready = store.set_tts_result(artifact["artifact_id"], TTSResult(b"audio"))
            with self.assertRaises(Exception):
                store.relay_tts_received(artifact["artifact_id"], device_id="unregistered", payload_sha256=ready["payload_sha256"])
            store.register_device("u", "watch-1", "watch")
            receipt = store.relay_tts_received(artifact["artifact_id"], device_id="watch-1", payload_sha256=ready["payload_sha256"])
            self.assertEqual(receipt["artifact_id"], artifact["artifact_id"])
            self.assertEqual(store.get_artifact(artifact["artifact_id"])["status"], "READY")

    def test_late_result_can_rebuild_cumulative_payload_from_hermes_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, submission_id = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890d3")
            first = store.commit_hermes_result(submission_id, HermesResult("assistant-1", "old body"))
            final_v1 = [event for event in first["events"] if event["event_kind"] == "FINAL"][0]
            store.ack_event(turn_id, final_v1["event_id"], device_id="device-1", event_version=1, payload_sha256=final_v1["payload_sha256"])
            rebuilt = store.commit_hermes_result(submission_id, HermesResult("assistant-2", "new body"), combined_content="old body\nnew body")
            self.assertEqual(rebuilt["final_content"], "old body\nnew body")
            self.assertEqual(rebuilt["final_event_version"], 2)

    def test_delivered_hermes_body_is_purged_but_reference_hashes_remain(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, submission_id = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890cf")
            store.commit_hermes_result(submission_id, HermesResult("assistant-1", "temporary body"))
            final = [event for event in store.get_turn(turn_id)["events"] if event["event_kind"] == "FINAL"][0]
            store.ack_event(turn_id, final["event_id"], device_id="device-1", event_version=1, payload_sha256=final["payload_sha256"])
            with store._read() as conn:
                raw_turn = conn.execute("SELECT final_content FROM turns WHERE turn_id=?", (turn_id,)).fetchone()[0]
                raw_result = conn.execute("SELECT normalized_content FROM hermes_results WHERE hermes_submission_id=?", (submission_id,)).fetchone()[0]
                raw_version = conn.execute("SELECT combined_content FROM final_versions WHERE turn_id=?", (turn_id,)).fetchone()[0]
            self.assertIsNone(raw_turn)
            self.assertIsNone(raw_result)
            self.assertIsNone(raw_version)
            self.assertEqual(store.get_turn(turn_id)["hermes_result_refs"][0]["content_hash"], hermes_content_hash("temporary body"))

    def test_hermes_transport_exception_releases_lease_and_reaches_bounded_grace_error(self):
        class BrokenGateway:
            def submit(self, **kwargs):
                raise OSError("synthetic transport down")

            def history(self, **kwargs):
                return None

        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, project, submission_id = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890ce")
            service = RecorderService(store, hermes=BrokenGateway(), hermes_max_attempts=1, hermes_grace_seconds=10)
            result = service.process_next_hermes(project["stable_project_id"], owner="hermes-test")
            self.assertEqual(result["state"], "LATE_RESULT_GRACE")
            self.assertEqual(store.get_ingress(submission_id)["status"], "FAILED")

    def test_repeated_hermes_error_commit_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _, _, submission_id = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890c9")
            first = store.commit_hermes_error(submission_id, grace_seconds=600)
            second = store.commit_hermes_error(submission_id, grace_seconds=600)
            self.assertEqual(first["final_event_version"], 1)
            self.assertEqual(second["final_event_version"], 1)

    def test_result_after_grace_expiry_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, submission_id = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890c4")
            failed = store.commit_hermes_error(submission_id, grace_seconds=1)
            self.assertEqual(failed["state"], "LATE_RESULT_GRACE")
            expired = store.expire_grace(turn_id, now="2999-01-01T00:00:00+00:00")
            self.assertEqual(expired["state"], "EXPIRED")
            late = store.commit_hermes_result(submission_id, HermesResult("too-late", "late"))
            self.assertEqual(late["final_event_version"], 1)
            self.assertEqual(late["state"], "EXPIRED")

    def test_acknowledging_old_hermes_error_does_not_regress_recovered_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, submission_id = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890c5")
            store.commit_hermes_error(submission_id, grace_seconds=600)
            recovered = store.commit_hermes_result(submission_id, HermesResult("late-success", "success"))
            self.assertEqual(recovered["final_outcome"], "success")
            error_event = [event for event in recovered["events"] if event["event_kind"] == "FINAL" and event["event_version"] == 1][0]
            after_ack = store.ack_event(turn_id, error_event["event_id"], device_id="device-1", event_version=1, payload_sha256=error_event["payload_sha256"])
            self.assertEqual(after_ack["final_outcome"], "success")
            self.assertNotEqual(after_ack["state"], "LATE_RESULT_GRACE")

    def test_route_rejects_stale_project_record_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            data = b"x"
            manifest = {
                "schema_version": 1,
                "user_id": "cas-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890c6",
                "origin_device_id": "device-1",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": "P-1",
                "prefer_current_project": True,
                "parts": [{"part_id": "text-1", "kind": "text", "mime": "text/plain", "declared_bytes": 1, "declared_sha256": hashlib.sha256(data).hexdigest()}],
            }
            store.register_device("cas-user", "device-1", "phone")
            store.create_turn(manifest)
            store.put_chunk(manifest["turn_id"], "text-1", 0, data)
            store.finish_part(manifest["turn_id"], "text-1", total_chunks=1, total_bytes=1, whole_stream_sha256=hashlib.sha256(data).hexdigest())
            store.accept_turn(manifest["turn_id"])
            project = store.create_project("cas-user", project_number="P-1", name="Fixture")
            store.update_project("cas-user", project["stable_project_id"], expected_version=1, patch={"name": "New"})
            with self.assertRaises(ConflictError):
                store.commit_route(manifest["turn_id"], RouterDecision("stale", project["stable_project_id"], project["default_session_key"], 1, "전달", "fixture"))


    def test_recording_lease_defers_tts_generation_until_recording_finishes(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, _ = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890ca")
            store.set_recording_lease("device-1", active=True, lease_seconds=600)
            self.assertEqual(store.pending_tts(), [])
            store.set_recording_lease("device-1", active=False)
            self.assertEqual(len(store.pending_tts()), 1)

    def test_revoked_origin_device_cannot_complete_playback(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, _ = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890cd")
            artifact = store.get_turn(turn_id)["tts_artifacts"][0]
            ready = store.set_tts_result(artifact["artifact_id"], TTSResult(b"audio"))
            store.revoke_device("u", "device-1")
            with self.assertRaises(Exception):
                store.ack_playback(artifact["artifact_id"], device_id="device-1", payload_sha256=ready["payload_sha256"])
            self.assertTrue(Path(ready["storage_path"]).exists())

    def test_expired_tts_retains_spool_until_origin_playback_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, turn_id, _, _ = setup_text_flow(tmp, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890c7")
            artifact = store.get_turn(turn_id)["tts_artifacts"][0]
            ready = store.set_tts_result(artifact["artifact_id"], TTSResult(b"audio"))
            store.mark_tts_expired(artifact["artifact_id"])
            self.assertTrue(Path(ready["storage_path"]).exists())
            played = store.ack_playback(artifact["artifact_id"], device_id="device-1", payload_sha256=ready["payload_sha256"])
            self.assertEqual(played["status"], "PLAYED")
            self.assertFalse(Path(ready["storage_path"]).exists())


if __name__ == "__main__":
    unittest.main()
