from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

from recorder_next.clock import DeterministicClock
from recorder_next.errors import ConflictError, NotReadyError, UnauthorizedError, ValidationError
from recorder_next.http import create_http_server
from recorder_next.models import TTSResult
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


PARENT_TURN = "018f5a2e-7b6e-7abc-8d11-1234567890e1"


def _manifest(
    turn_id: str = PARENT_TURN,
    *,
    user: str = "schedule-user",
    device: str = "watch-1",
    project_number: str = "P-1",
) -> dict:
    text = b"remind me"
    return {
        "schema_version": 1,
        "user_id": user,
        "turn_id": turn_id,
        "origin_device_id": device,
        "client_created_at": "2026-08-26T00:00:00+00:00",
        "current_project_number": project_number,
        "prefer_current_project": True,
        "parts": [
            {
                "part_id": "text-1",
                "kind": "text",
                "mime": "text/plain",
                "declared_bytes": len(text),
                "declared_sha256": hashlib.sha256(text).hexdigest(),
            }
        ],
    }


def _accepted_parent(
    root: Path,
    clock: DeterministicClock,
    *,
    device: str = "watch-1",
    project_number: str = "P-1",
    project_name: str = "Schedule fixture",
) -> tuple[RecorderStore, dict, dict]:
    store = RecorderStore(root / "db.sqlite3", storage_root=root / "data", clock=clock)
    store.register_device("schedule-user", "watch-1", "watch")
    store.register_device("schedule-user", "phone-1", "phone")
    manifest = _manifest(device=device, project_number=project_number)
    store.create_turn(manifest)
    payload = b"remind me"
    store.put_chunk(PARENT_TURN, "text-1", 0, payload)
    store.finish_part(
        PARENT_TURN,
        "text-1",
        total_chunks=1,
        total_bytes=len(payload),
        whole_stream_sha256=hashlib.sha256(payload).hexdigest(),
    )
    parent = store.accept_turn(PARENT_TURN)
    project = store.create_project("schedule-user", project_number=project_number, name=project_name)
    return store, parent, project


def _accepted_later_turn(store: RecorderStore, *, turn_id: str, device: str, project_number: str) -> dict:
    manifest = _manifest(turn_id, device=device, project_number=project_number)
    store.create_turn(manifest)
    payload = b"remind me"
    store.put_chunk(turn_id, "text-1", 0, payload)
    store.finish_part(
        turn_id,
        "text-1",
        total_chunks=1,
        total_bytes=len(payload),
        whole_stream_sha256=hashlib.sha256(payload).hexdigest(),
    )
    return store.accept_turn(turn_id)


def _schedule_command(
    project: dict,
    *,
    fire_at: str,
    origin: str = "watch-1",
    target: str = "watch-1",
    schedule_id: str = "schedule-1",
) -> dict:
    return {
        "schedule_id": schedule_id,
        "parent_turn_id": PARENT_TURN,
        "project_id": project["stable_project_id"],
        "session_key": project["default_session_key"],
        "origin_device_id": origin,
        "delivery_target_device_id": target,
        "fire_at_utc": fire_at,
        "timezone_offset": "+09:00",
        "reminder_text": "물 마실 시간입니다.",
        "confirmation_text": "30분 뒤에 알려드리도록 설정했습니다.",
    }


class _FlakyTTS:
    name = "flaky-fixture"

    def __init__(self) -> None:
        self.fail = True

    def synthesize(self, text: str, *, artifact_id: str) -> TTSResult:
        if self.fail:
            raise RuntimeError("fixture TTS failure")
        return TTSResult(b"retry-audio", mode="file", content_type="audio/mpeg")


class ScheduledFinalStoreTests(unittest.TestCase):
    def test_schedule_create_is_atomic_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, parent, project = _accepted_parent(Path(tmp), clock)
            command = _schedule_command(project, fire_at="2026-08-26T00:30:00+00:00")

            first = store.create_schedule(command)
            again = store.create_schedule(dict(command))

            self.assertEqual(first["schedule_id"], "schedule-1")
            self.assertEqual(first["state"], "SCHEDULED")
            self.assertEqual(first["trigger_instance_id"], again["trigger_instance_id"])
            self.assertEqual(first["confirmation_event_id"], again["confirmation_event_id"])
            confirmed = store.get_turn(PARENT_TURN)
            self.assertEqual(confirmed["final_event_version"], 1)
            self.assertEqual(confirmed["final_content"], command["confirmation_text"])
            self.assertEqual(confirmed["events"][1]["event_kind"], "FINAL")
            self.assertEqual(store.db_snapshot()["schedules"], 1)
            self.assertEqual(store.db_snapshot()["schedule_occurrences"], 1)
            self.assertEqual(store.db_snapshot()["outbox"], 1)

    def test_expiry_creates_distinct_server_turn_final_v1_and_targeted_tts(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:30+00:00"))
            clock.advance(seconds=30)

            fired = store.fire_due_schedules(owner="scheduler-a", lease_seconds=5)
            self.assertEqual(len(fired), 1)
            scheduled = fired[0]["turn"]
            self.assertNotEqual(scheduled["turn_id"], PARENT_TURN)
            self.assertEqual(scheduled["turn_source"], "server_schedule")
            self.assertEqual(scheduled["parent_turn_id"], PARENT_TURN)
            self.assertEqual(scheduled["schedule_id"], "schedule-1")
            self.assertEqual(scheduled["events"][0]["event_kind"], "FINAL")
            self.assertEqual(scheduled["final_event_version"], 1)
            self.assertEqual(scheduled["events"][0]["event_version"], 1)
            self.assertEqual(scheduled["tts_artifacts"][0]["output_kind"], "FINAL_TTS")
            self.assertEqual(scheduled["tts_artifacts"][0]["delivery_target_device_id"], "watch-1")
            self.assertEqual(store.get_turn(PARENT_TURN)["final_content"], "30분 뒤에 알려드리도록 설정했습니다.")
            self.assertEqual(store.db_snapshot()["turns"], 2)
            self.assertEqual(store.db_snapshot()["events"], 3)
            self.assertEqual(store.db_snapshot()["tts_artifacts"], 2)

            replay = store.fire_due_schedules(owner="scheduler-b")
            self.assertEqual(replay, [])
            schedule = store.get_schedule("schedule-1")
            self.assertEqual(schedule["state"], "FIRED")
            self.assertEqual(len(schedule["occurrences"]), 1)

    def test_preclaimed_scheduled_uuid_is_rejected_without_scheduled_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            schedule = store.create_schedule(
                _schedule_command(
                    project,
                    fire_at="2026-08-26T00:00:00+00:00",
                    origin="watch-1",
                    target="watch-1",
                    schedule_id="schedule-collision",
                )
            )
            scheduled_turn_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"recorder-next:scheduled-turn:{schedule['schedule_id']}:{schedule['trigger_instance_id']}",
                )
            )
            collision = _accepted_later_turn(
                store,
                turn_id=scheduled_turn_id,
                device="phone-1",
                project_number="P-client",
            )
            self.assertEqual(collision["turn_source"], "client")
            self.assertIsNone(collision["schedule_id"])
            self.assertIsNone(collision["trigger_instance_id"])

            claim = store.claim_due_occurrence(owner="scheduler")
            self.assertIsNotNone(claim)
            assert claim is not None
            claimed_snapshot = store.db_snapshot()
            with self.assertRaises(ConflictError):
                store.commit_scheduled_occurrence(
                    claim["schedule_id"],
                    claim["trigger_instance_id"],
                    owner="scheduler",
                )

            self.assertEqual(store.db_snapshot(), claimed_snapshot)
            preserved = store.get_turn(scheduled_turn_id)
            self.assertEqual(preserved["state"], "ACCEPTED")
            self.assertEqual(preserved["turn_source"], "client")
            self.assertIsNone(preserved["schedule_id"])
            self.assertIsNone(preserved["trigger_instance_id"])
            self.assertEqual(preserved["final_event_version"], 0)
            self.assertEqual(preserved["tts_artifacts"], [])
            self.assertEqual(preserved["outbox"], [])
            occurrence = store.get_schedule("schedule-collision")["occurrences"][0]
            self.assertEqual(occurrence["state"], "CLAIMED")
            self.assertIsNone(occurrence["turn_id"])
            self.assertIsNone(occurrence["event_id"])
            self.assertIsNone(occurrence["artifact_id"])

    def test_scheduled_occurrence_replay_returns_original_delivery_without_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            first = store.fire_due_schedules(owner="scheduler")[0]
            occurrence = store.get_schedule("schedule-1")["occurrences"][0]
            before_replay = store.db_snapshot()

            replay = store.commit_scheduled_occurrence(
                "schedule-1",
                occurrence["trigger_instance_id"],
                owner="scheduler-replay",
            )

            self.assertEqual(replay["turn_id"], first["turn_id"])
            self.assertEqual(replay["event_id"], first["event_id"])
            self.assertEqual(replay["artifact_id"], first["artifact_id"])
            self.assertEqual(store.db_snapshot(), before_replay)

    def test_explicit_schedule_target_wins_over_latest_phone_origin_for_scheduled_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(root, clock, device="phone-1", project_number="P-phone")
            schedule = store.create_schedule(
                _schedule_command(
                    project,
                    fire_at="2026-08-26T00:00:00+00:00",
                    origin="phone-1",
                    target="watch-1",
                    schedule_id="schedule-phone-to-watch",
                )
            )

            self.assertEqual(schedule["delivery_target_device_id"], "watch-1")
            self.assertEqual(schedule["occurrences"][0]["delivery_target_device_id"], "watch-1")

            fired = store.fire_due_schedules(owner="scheduler")
            self.assertEqual(len(fired), 1)
            scheduled = fired[0]["turn"]
            event = scheduled["events"][0]
            artifact = scheduled["tts_artifacts"][0]
            self.assertEqual(scheduled["delivery_target_device_id"], "watch-1")
            self.assertEqual(event["required_device_id"], "watch-1")
            self.assertEqual(artifact["delivery_target_device_id"], "watch-1")
            watch_outbox = store.pending_outbox("watch-1")
            self.assertIn(event["event_id"], [row["event_id"] for row in watch_outbox])
            self.assertNotIn(event["event_id"], [row["event_id"] for row in store.pending_outbox("phone-1")])
            self.assertEqual(store.get_schedule("schedule-phone-to-watch")["occurrences"][0]["delivery_target_device_id"], "watch-1")

    def test_explicit_target_stays_phone_across_latest_watch_turn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, phone_project = _accepted_parent(root, clock, device="phone-1", project_number="P-phone")
            wear_project = store.create_project("schedule-user", project_number="P-wear", name="Wear project")
            store.create_schedule(
                _schedule_command(
                    phone_project,
                    fire_at="2026-08-26T00:00:00+00:00",
                    origin="phone-1",
                    target="phone-1",
                )
            )
            later = _accepted_later_turn(
                store,
                turn_id="018f5a2e-7b6e-7abc-8d11-1234567890e2",
                device="watch-1",
                project_number="P-wear",
            )
            clock.advance(seconds=1)
            fired = store.fire_due_schedules(owner="scheduler")
            scheduled = fired[0]["turn"]
            self.assertEqual(scheduled["previous_turn_id"], later["turn_id"])
            self.assertEqual(scheduled["previous_turn_origin_device_id"], "watch-1")
            self.assertEqual(scheduled["delivery_target_device_id"], "phone-1")
            self.assertEqual(scheduled["events"][0]["required_device_id"], "phone-1")
            self.assertEqual(scheduled["tts_artifacts"][0]["delivery_target_device_id"], "phone-1")

            later_again = _accepted_later_turn(
                store,
                turn_id="018f5a2e-7b6e-7abc-8d11-1234567890e3",
                device="phone-1",
                project_number="P-phone",
            )
            replay = store.fire_due_schedules(owner="scheduler-replay")
            self.assertEqual(replay, [])
            persisted = store.get_turn(scheduled["turn_id"])
            self.assertEqual(persisted["previous_turn_id"], later["turn_id"])
            self.assertNotEqual(persisted["previous_turn_id"], later_again["turn_id"])

    def test_explicit_target_stays_watch_in_inverse_latest_phone_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, wear_project = _accepted_parent(root, clock, device="watch-1", project_number="P-wear")
            phone_project = store.create_project("schedule-user", project_number="P-phone", name="Phone project")
            store.create_schedule(
                _schedule_command(
                    wear_project,
                    fire_at="2026-08-26T00:00:00+00:00",
                    origin="watch-1",
                    target="watch-1",
                )
            )
            later = _accepted_later_turn(
                store,
                turn_id="018f5a2e-7b6e-7abc-8d11-1234567890e4",
                device="phone-1",
                project_number="P-phone",
            )
            fired = store.fire_due_schedules(owner="scheduler")
            scheduled = fired[0]["turn"]
            self.assertEqual(scheduled["previous_turn_id"], later["turn_id"])
            self.assertEqual(scheduled["previous_turn_origin_device_id"], "phone-1")
            self.assertEqual(scheduled["delivery_target_device_id"], "watch-1")

    def test_explicit_target_snapshot_is_atomic_between_claim_and_server_turn_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(root, clock, device="phone-1", project_number="P-phone")
            store.create_schedule(
                _schedule_command(
                    project,
                    fire_at="2026-08-26T00:00:00+00:00",
                    origin="phone-1",
                    target="phone-1",
                )
            )
            claim = store.claim_due_occurrence(owner="scheduler", lease_seconds=30)
            self.assertIsNotNone(claim)
            _accepted_later_turn(
                store,
                turn_id="018f5a2e-7b6e-7abc-8d11-1234567890e5",
                device="watch-1",
                project_number="P-later",
            )
            fired = store.commit_scheduled_occurrence(
                claim["schedule_id"],
                claim["trigger_instance_id"],
                owner="scheduler",
            )
            self.assertEqual(fired["turn"]["delivery_target_device_id"], "phone-1")

    def test_concurrent_workers_and_expired_lease_are_lossless(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(root, clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            results: list[dict] = []
            lock = threading.Lock()

            def worker(owner: str) -> None:
                local = RecorderStore(root / "db.sqlite3", storage_root=root / "data", clock=clock)
                value = local.fire_due_schedules(owner=owner, lease_seconds=30)
                with lock:
                    results.extend(value)

            threads = [threading.Thread(target=worker, args=(f"worker-{i}",)) for i in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertEqual(len(results), 1)
            self.assertEqual(store.db_snapshot()["schedule_occurrences"], 1)
            self.assertEqual(store.db_snapshot()["turns"], 2)
            self.assertEqual(store.db_snapshot()["events"], 3)
            self.assertEqual(store.db_snapshot()["tts_artifacts"], 2)

            second = RecorderStore(root / "db.sqlite3", storage_root=root / "data", clock=clock)
            command = second.get_schedule("schedule-1")
            self.assertEqual(command["occurrences"][0]["state"], "FIRED")

    def test_expired_claim_can_be_taken_over_without_duplicate_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(root, clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            claim = store.claim_due_occurrence(owner="crashed", lease_seconds=1)
            self.assertIsNotNone(claim)
            clock.advance(seconds=2)
            reopened = RecorderStore(root / "db.sqlite3", storage_root=root / "data", clock=clock)
            fired = reopened.fire_due_schedules(owner="takeover", lease_seconds=5)
            self.assertEqual(len(fired), 1)
            self.assertEqual(reopened.db_snapshot()["turns"], 2)
            self.assertEqual(reopened.db_snapshot()["schedule_occurrences"], 1)
            self.assertEqual(reopened.get_schedule("schedule-1")["occurrences"][0]["state"], "FIRED")

    def test_text_ack_is_not_tts_playback_and_only_target_can_finish(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            fired = store.fire_due_schedules(owner="scheduler") [0]
            turn = fired["turn"]
            artifact = turn["tts_artifacts"][0]
            service = RecorderService(store)
            ready = service.generate_tts(artifact["artifact_id"])
            self.assertEqual(ready["status"], "READY")
            event = next(event for event in turn["events"] if event["event_kind"] == "FINAL")
            store.ack_event(
                turn["turn_id"],
                event["event_id"],
                device_id="watch-1",
                event_version=1,
                payload_sha256=event["payload_sha256"],
            )
            self.assertEqual(store.get_artifact(artifact["artifact_id"])["status"], "READY")
            with self.assertRaises(UnauthorizedError):
                store.ack_playback(
                    artifact["artifact_id"],
                    device_id="phone-1",
                    payload_sha256=ready["payload_sha256"],
                    turn_id=turn["turn_id"],
                    artifact_version=artifact["artifact_version"],
                )
            store.relay_tts_received(artifact["artifact_id"], device_id="phone-1", payload_sha256=ready["payload_sha256"])
            self.assertEqual(store.get_artifact(artifact["artifact_id"])["status"], "READY")
            played = store.ack_playback(
                artifact["artifact_id"],
                device_id="watch-1",
                payload_sha256=ready["payload_sha256"],
                turn_id=turn["turn_id"],
                artifact_version=artifact["artifact_version"],
            )
            self.assertEqual(played["status"], "PLAYED")
            self.assertFalse(Path(ready["storage_path"]).exists())

    def test_registered_phone_bridge_reads_watch_tts_but_cannot_complete_playback(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            fired = store.fire_due_schedules(owner="scheduler")[0]
            turn = fired["turn"]
            artifact = turn["tts_artifacts"][0]
            ready = RecorderService(store).generate_tts(artifact["artifact_id"])

            metadata, audio = store.read_tts_for_bridge(artifact["artifact_id"], bridge_device_id="phone-1")
            self.assertEqual(metadata["delivery_target_device_id"], "watch-1")
            self.assertEqual(hashlib.sha256(audio).hexdigest(), ready["payload_sha256"])
            with self.assertRaises(UnauthorizedError):
                store.read_tts_for_bridge(artifact["artifact_id"], bridge_device_id="watch-1")
            with self.assertRaises(UnauthorizedError):
                store.ack_playback(
                    artifact["artifact_id"],
                    device_id="phone-1",
                    payload_sha256=ready["payload_sha256"],
                    turn_id=turn["turn_id"],
                    artifact_version=artifact["artifact_version"],
                )
            self.assertEqual(store.get_artifact(artifact["artifact_id"])["status"], "READY")
            store.relay_tts_received(artifact["artifact_id"], device_id="phone-1", payload_sha256=ready["payload_sha256"])
            played = store.ack_playback(
                artifact["artifact_id"],
                device_id="watch-1",
                payload_sha256=ready["payload_sha256"],
                turn_id=turn["turn_id"],
                artifact_version=artifact["artifact_version"],
            )
            self.assertEqual(played["status"], "PLAYED")
            replay = store.ack_playback(
                artifact["artifact_id"],
                device_id="watch-1",
                payload_sha256=ready["payload_sha256"],
                turn_id=turn["turn_id"],
                artifact_version=artifact["artifact_version"],
            )
            self.assertEqual(replay["status"], "PLAYED")
            with self.assertRaises(ConflictError):
                store.ack_playback(
                    artifact["artifact_id"],
                    device_id="watch-1",
                    payload_sha256="wrong-after-played",
                    turn_id=turn["turn_id"],
                    artifact_version=artifact["artifact_version"],
                )

    def test_playback_ack_requires_generated_artifact_exact_hash_turn_and_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            fired = store.fire_due_schedules(owner="scheduler")[0]
            turn = fired["turn"]
            artifact = turn["tts_artifacts"][0]
            ack = {
                "device_id": "watch-1",
                "payload_sha256": "",
                "turn_id": turn["turn_id"],
                "artifact_version": artifact["artifact_version"],
            }
            with self.assertRaises(ValidationError):
                store.ack_playback(artifact["artifact_id"], **ack)
            ack["payload_sha256"] = "not-generated"
            with self.assertRaises(NotReadyError):
                store.ack_playback(artifact["artifact_id"], **ack)
            ready = RecorderService(store).generate_tts(artifact["artifact_id"])
            with self.assertRaises(ConflictError):
                store.ack_playback(
                    artifact["artifact_id"],
                    device_id="watch-1",
                    payload_sha256="wrong-hash",
                    turn_id=turn["turn_id"],
                    artifact_version=artifact["artifact_version"],
                )
            with self.assertRaises(UnauthorizedError):
                store.ack_playback(
                    artifact["artifact_id"],
                    device_id="watch-1",
                    payload_sha256=ready["payload_sha256"],
                    turn_id=PARENT_TURN,
                    artifact_version=artifact["artifact_version"],
                )
            with self.assertRaises(UnauthorizedError):
                store.ack_playback(
                    artifact["artifact_id"],
                    device_id="watch-1",
                    payload_sha256=ready["payload_sha256"],
                    turn_id=turn["turn_id"],
                    artifact_version=artifact["artifact_version"] + 1,
                )
            self.assertEqual(
                store.ack_playback(
                    artifact["artifact_id"],
                    device_id="watch-1",
                    payload_sha256=ready["payload_sha256"],
                    turn_id=turn["turn_id"],
                    artifact_version=artifact["artifact_version"],
                )["status"],
                "PLAYED",
            )

    def test_expired_generated_tts_cannot_be_acknowledged_as_played(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            fired = store.fire_due_schedules(owner="scheduler")[0]
            turn = fired["turn"]
            artifact = turn["tts_artifacts"][0]
            ready = RecorderService(store).generate_tts(artifact["artifact_id"])
            expired = store.mark_tts_expired(artifact["artifact_id"])
            self.assertEqual(expired["status"], "EXPIRED")
            with self.assertRaises(NotReadyError):
                store.ack_playback(
                    artifact["artifact_id"],
                    device_id="watch-1",
                    payload_sha256=ready["payload_sha256"],
                    turn_id=turn["turn_id"],
                    artifact_version=artifact["artifact_version"],
                )
            self.assertTrue(Path(ready["storage_path"]).exists())

    def test_http_bridge_read_and_playback_ack_require_exact_wire_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            fired = store.fire_due_schedules(owner="scheduler")[0]
            turn = fired["turn"]
            artifact = turn["tts_artifacts"][0]
            ready = RecorderService(store).generate_tts(artifact["artifact_id"])
            service = RecorderService(store)

            for path in (
                f"/v1/tts/{artifact['artifact_id']}?device_id=phone-1",
                f"/v1/tts/{artifact['artifact_id']}/bridge-read?device_id=phone-1",
            ):
                status, _, body = service.handle_http("GET", path, {}, b"")
                self.assertEqual(status, 200)
                self.assertEqual(hashlib.sha256(base64.b64decode(body["audio_base64"])).hexdigest(), ready["payload_sha256"])

            missing_version = {
                "device_id": "watch-1",
                "turn_id": turn["turn_id"],
                "payload_sha256": ready["payload_sha256"],
            }
            status, _, body = service.handle_http(
                "POST",
                f"/v1/tts/{artifact['artifact_id']}/playback-ack",
                {},
                json.dumps(missing_version).encode(),
            )
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "VALIDATION_ERROR")

    def test_recording_lease_defers_scheduled_tts_and_release_replays(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            fired = store.fire_due_schedules(owner="scheduler")[0]
            artifact_id = fired["turn"]["tts_artifacts"][0]["artifact_id"]
            store.set_recording_lease("watch-1", active=True)
            self.assertEqual(store.pending_tts(), [])
            store.set_recording_lease("watch-1", active=False)
            self.assertIn(artifact_id, [row["artifact_id"] for row in store.pending_tts()])

    def test_tts_generation_failure_keeps_the_scheduled_artifact_retryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:00+00:00"))
            artifact_id = store.fire_due_schedules(owner="scheduler")[0]["artifact_id"]
            provider = _FlakyTTS()
            service = RecorderService(store, tts=provider)
            failed = service.generate_tts(artifact_id)
            self.assertEqual(failed["status"], "FAILED_GENERATION")
            self.assertIn(artifact_id, [row["artifact_id"] for row in store.pending_tts()])
            provider.fail = False
            retried = service.generate_pending_tts()
            self.assertEqual(store.get_artifact(artifact_id)["status"], "READY")
            self.assertTrue(all(row["status"] == "READY" for row in retried))

    def test_schedule_failure_rolls_back_without_false_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(Path(tmp), clock)
            original = store._commit_schedule_confirmation_tx

            def fail(*args, **kwargs):
                raise RuntimeError("fixture confirmation failure")

            store._commit_schedule_confirmation_tx = fail
            with self.assertRaises(RuntimeError):
                store.create_schedule(_schedule_command(project, fire_at="2026-08-26T00:00:30+00:00"))
            store._commit_schedule_confirmation_tx = original
            snapshot = store.db_snapshot()
            self.assertEqual(snapshot["schedules"], 0)
            self.assertEqual(snapshot["schedule_occurrences"], 0)
            self.assertEqual(snapshot["outbox"], 1)
            failed = store.get_turn(PARENT_TURN)
            self.assertEqual(failed["final_event_version"], 1)
            self.assertEqual(failed["final_outcome"], "error")
            self.assertEqual(failed["final_error_kind"], "schedule")


class ScheduledFinalHTTPAndMigrationTests(unittest.TestCase):
    def test_trusted_adapter_http_and_readback_surfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, _, project = _accepted_parent(root, clock)
            service = RecorderService(store)
            server = create_http_server(service, host="127.0.0.1", port=0)
            try:
                self.assertNotIn(server.server_address[1], {5000, 8642})
            finally:
                server.server_close()
            command = _schedule_command(project, fire_at="2026-08-26T00:00:10+00:00")
            status, _, body = service.handle_http(
                "POST",
                "/v1/internal/schedule_create",
                {"X-Recorder-Internal-Trusted": "1"},
                json.dumps(command).encode(),
            )
            self.assertEqual(status, 201)
            self.assertEqual(body["schedule_id"], "schedule-1")
            status, _, readback = service.handle_http("GET", "/v1/schedules/schedule-1", {}, b"")
            self.assertEqual(status, 200)
            self.assertEqual(readback["fire_at_utc"], "2026-08-26T00:00:10.000+00:00")
            clock.advance(seconds=10)
            status, _, fired = service.handle_http(
                "POST",
                "/v1/internal/scheduler/fire",
                {},
                json.dumps({"owner": "http-scheduler"}).encode(),
            )
            self.assertEqual(status, 200)
            self.assertEqual(len(fired["items"]), 1)

            denied, _, _ = service.handle_http(
                "POST",
                "/v1/internal/schedule_create",
                {},
                json.dumps({**command, "schedule_id": "schedule-denied"}).encode(),
            )
            self.assertEqual(denied, 401)

    def test_r4_database_upgrades_additively_to_scheduled_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "legacy.sqlite3"
            conn = sqlite3.connect(db)
            conn.executescript((Path(__file__).parents[1] / "migrations/001_initial.sql").read_text(encoding="utf-8"))
            conn.close()
            store = RecorderStore(db, storage_root=root / "data")
            with store._read() as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                columns = {row[1] for row in conn.execute("PRAGMA table_info(turns)")}
                self.assertTrue(
                    {
                        "turn_source",
                        "schedule_id",
                        "trigger_instance_id",
                        "parent_turn_id",
                        "previous_turn_id",
                        "previous_turn_origin_device_id",
                        "delivery_target_device_id",
                    }
                    <= columns
                )
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM schedules").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM schedule_occurrences").fetchone()[0], 0)

    def test_openapi_exposes_scheduled_protocol_and_migration_is_additive(self):
        from recorder_next.openapi import OPENAPI

        self.assertIn("/v1/internal/schedule_create", OPENAPI["paths"])
        self.assertIn("/v1/internal/scheduler/fire", OPENAPI["paths"])
        self.assertIn("/v1/schedules/{schedule_id}", OPENAPI["paths"])
        self.assertIn("/v1/tts/{artifact_id}/bridge-read", OPENAPI["paths"])
        ack_schema = OPENAPI["components"]["schemas"]["PlaybackAck"]
        self.assertEqual(
            set(ack_schema["required"]),
            {"device_id", "payload_sha256", "turn_id", "artifact_version"},
        )
        self.assertTrue(OPENAPI["paths"]["/v1/tts/{artifact_id}/playback-ack"]["post"]["requestBody"]["required"])
        migration = (Path(__file__).parents[1] / "migrations/002_scheduled_final.sql").read_text(encoding="utf-8").upper()
        self.assertNotIn("DROP TABLE", migration)
        self.assertNotIn("DELETE FROM", migration)
        self.assertNotIn("UPDATE TURNS", migration)


if __name__ == "__main__":
    unittest.main()
