from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from recorder_next.adapters import ChainFailure, HermesAudioTTSProvider, ProviderChain, ProviderFailure, ProviderTarget
from recorder_next.clock import DeterministicClock
from recorder_next.config import RecorderConfig
from recorder_next.models import TTSResult
from recorder_next.service import RecorderService, create_configured_service
from recorder_next.store import RecorderStore


PARENT_TURN = "018f5a2e-7b6e-7abc-8d11-1234567890e1"


class _TTSFixture:
    def __init__(self, *, route_available: bool = True) -> None:
        self.route_available = route_available
        self.authorization_seen = False
        self.authorization_valid = False
        self.session_token_seen = False
        self.session_token_valid = False
        self.valid_request_seen = False
        self.last_status = None
        self._server = _FixtureServer(("127.0.0.1", 0), _TTSHandler)
        self._server.fixture = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


class _FixtureServer(ThreadingHTTPServer):
    fixture: Any


class _TTSHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        cast(_FixtureServer, self.server).fixture.last_status = status

    def do_GET(self) -> None:
        # Readiness probes now flow through the shared chain dispatcher, so
        # the fixture must serve the bounded GET contract the real Hermes
        # dashboard exposes: an ok/ready health and a supported edge-relay
        # voice-config.  No synthesize endpoint is reachable via GET.
        fixture = cast(_FixtureServer, self.server).fixture
        parsed = urlsplit(self.path)
        authorization = self.headers.get("Authorization", "")
        session_token = self.headers.get("X-Hermes-Session-Token", "")
        fixture.authorization_seen = bool(authorization)
        fixture.authorization_valid = authorization == "Bearer fixture-secret"
        fixture.session_token_seen = bool(session_token)
        fixture.session_token_valid = session_token == "fixture-secret"
        if parsed.path == "/api/health":
            self._send(200, {"ok": True, "ready": True})
            return
        if parsed.path == "/api/audio/voice-config":
            if not fixture.authorization_valid or not fixture.session_token_valid:
                self._send(401, {"detail": "unauthorized"})
                return
            self._send(
                200,
                {
                    "ok": True,
                    "ready": True,
                    "audio_api": True,
                    "stt": {"mode": "relay", "reason": "provider 'edge' has no client wire"},
                    "tts": {"mode": "relay", "reason": "provider 'edge' has no client wire", "provider": "edge", "ok": True},
                },
            )
            return
        self._send(404, {"detail": "not found"})

    def do_POST(self) -> None:
        fixture = cast(_FixtureServer, self.server).fixture
        parsed = urlsplit(self.path)
        if parsed.path != "/api/audio/speak" or parse_qs(parsed.query).get("profile") != ["default"]:
            self._send(404, {"detail": "not found"})
            return
        if not fixture.route_available:
            self._send(404, {"detail": "audio API is not served by this listener"})
            return

        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(422, {"detail": "invalid JSON"})
            return
        authorization = self.headers.get("Authorization", "")
        session_token = self.headers.get("X-Hermes-Session-Token", "")
        fixture.authorization_seen = bool(authorization)
        fixture.authorization_valid = authorization == "Bearer fixture-secret"
        fixture.session_token_seen = bool(session_token)
        fixture.session_token_valid = session_token == "fixture-secret"
        if not fixture.authorization_valid or not fixture.session_token_valid:
            self._send(401, {"detail": "unauthorized"})
            return
        if not isinstance(payload, dict) or set(payload) != {"text"} or not isinstance(payload["text"], str) or not payload["text"].strip():
            self._send(422, {"detail": "text is required"})
            return

        fixture.valid_request_seen = True
        audio = b"fixture-hermes-audio"
        self._send(
            200,
            {
                "ok": True,
                "data_url": f"data:audio/mpeg;base64,{base64.b64encode(audio).decode('ascii')}",
                "mime_type": "audio/mpeg",
                "provider": "fixture-hermes",
            },
        )


class HermesTTSContractTests(unittest.TestCase):
    def _credential(self, root: Path) -> Path:
        path = root / "recorder_api_key.env"
        path.write_text("API_SERVER_KEY=fixture-secret\n", encoding="ascii")
        path.chmod(0o600)
        return path

    def _accepted_parent(self, root: Path, clock: DeterministicClock) -> tuple[RecorderStore, dict[str, object]]:
        store = RecorderStore(root / "db.sqlite3", storage_root=root / "data", clock=clock)
        store.register_device("schedule-user", "watch-1", "watch")
        store.register_device("schedule-user", "phone-1", "phone")
        text = b"remind me"
        manifest = {
            "schema_version": 1,
            "user_id": "schedule-user",
            "turn_id": PARENT_TURN,
            "origin_device_id": "watch-1",
            "client_created_at": "2026-08-26T00:00:00+00:00",
            "current_project_number": "P-1",
            "prefer_current_project": True,
            "parts": [{
                "part_id": "text-1",
                "kind": "text",
                "mime": "text/plain",
                "declared_bytes": len(text),
                "declared_sha256": hashlib.sha256(text).hexdigest(),
            }],
        }
        store.create_turn(manifest)
        store.put_chunk(PARENT_TURN, "text-1", 0, text)
        store.finish_part(
            PARENT_TURN,
            "text-1",
            total_chunks=1,
            total_bytes=len(text),
            whole_stream_sha256=hashlib.sha256(text).hexdigest(),
        )
        store.accept_turn(PARENT_TURN)
        project = store.create_project("schedule-user", project_number="P-1", name="Schedule fixture")
        return store, project

    def _schedule(self, project: dict[str, object]) -> dict[str, object]:
        return {
            "schedule_id": "schedule-1",
            "parent_turn_id": PARENT_TURN,
            "project_id": project["stable_project_id"],
            "session_key": project["default_session_key"],
            "origin_device_id": "watch-1",
            "delivery_target_device_id": "watch-1",
            "fire_at_utc": "2026-08-26T00:00:00+00:00",
            "timezone_offset": "+09:00",
            "reminder_text": "물 마실 시간입니다.",
            "confirmation_text": "30분 뒤에 알려드리도록 설정했습니다.",
        }


    def test_authenticated_hermes_tts_request_uses_real_audio_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture()
            try:
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
                result = provider.synthesize("안녕하세요", artifact_id="artifact-1")
                self.assertEqual(result.audio, b"fixture-hermes-audio")
                self.assertEqual(result.content_type, "audio/mpeg")
                self.assertEqual(result.metadata["endpoint_contract"], "/api/audio/speak?profile=default")
                self.assertTrue(fixture.authorization_seen)
                self.assertTrue(fixture.authorization_valid)
                self.assertTrue(fixture.session_token_seen)
                self.assertTrue(fixture.session_token_valid)
                self.assertTrue(fixture.valid_request_seen)
                self.assertNotIn("fixture-secret", repr(result))
            finally:
                fixture.close()

    def test_authenticated_fixture_distinguishes_unauthorized_4xx_from_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture()
            try:
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
                with self.assertRaises(ProviderFailure) as raised:
                    provider.synthesize("안녕하세요", artifact_id="artifact-unauthorized")
                self.assertEqual(raised.exception.kind, "auth")
                self.assertEqual(raised.exception.status_code, 401)
                self.assertTrue(fixture.authorization_seen is False)
                self.assertTrue(fixture.session_token_seen is False)
                self.assertNotIn("fixture-secret", str(raised.exception))
            finally:
                fixture.close()

    def test_api_only_listener_404_is_reported_as_unavailable_not_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture(route_available=False)
            try:
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
                with self.assertRaises(ProviderFailure) as raised:
                    provider.synthesize("안녕하세요", artifact_id="artifact-missing-route")
                self.assertEqual(raised.exception.kind, "provider_unavailable")
                self.assertEqual(raised.exception.status_code, 404)
                self.assertNotIn("fixture-secret", str(raised.exception))
            finally:
                fixture.close()

    def test_configured_chain_preserves_terminal_provider_unavailable_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture(route_available=False)
            try:
                clock = DeterministicClock("2026-08-26T00:00:00+00:00")
                store, project = self._accepted_parent(root, clock)
                store.create_schedule(self._schedule(project))
                fired = store.fire_due_schedules(owner="scheduler")
                artifact_id = fired[0]["turn"]["tts_artifacts"][0]["artifact_id"]
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
                chain = ProviderChain(
                    "tts",
                    [ProviderTarget("hermes-audio", "tts", "hermes", provider)],
                )
                service = RecorderService(store, tts_chain=chain)
                failed = service.generate_tts(artifact_id, frozen=chain.freeze())
                metadata = json.loads(failed["provider_metadata_json"])
                self.assertEqual(failed["status"], "FAILED_GENERATION")
                self.assertEqual(metadata["error_kind"], "provider_unavailable")
                self.assertEqual(metadata["status_code"], 404)
                with self.assertRaises(ChainFailure) as raised:
                    chain.execute_tts("hello", artifact_id="chain-404", frozen=chain.freeze())
                self.assertEqual(raised.exception.kind, "provider_unavailable")
                self.assertEqual(raised.exception.statuses[0]["status_code"], 404)
            finally:
                fixture.close()

    def test_scheduled_tts_receipt_preserves_unavailable_http_status_without_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture(route_available=False)
            try:
                clock = DeterministicClock("2026-08-26T00:00:00+00:00")
                store, project = self._accepted_parent(root, clock)
                store.create_schedule(self._schedule(project))
                fired = store.fire_due_schedules(owner="scheduler")
                artifact_id = fired[0]["turn"]["tts_artifacts"][0]["artifact_id"]
                service = RecorderService(
                    store,
                    tts=HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root)),
                )
                failed = service.generate_tts(artifact_id)
                metadata = json.loads(failed["provider_metadata_json"])
                self.assertEqual(failed["status"], "FAILED_GENERATION")
                self.assertEqual(metadata, {"error_kind": "provider_unavailable", "status_code": 404})
                self.assertNotIn("fixture-secret", failed["provider_metadata_json"])
            finally:
                fixture.close()

    def test_scheduler_replays_tts_enqueue_after_transient_worker_fault(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture()
            try:
                clock = DeterministicClock("2026-08-26T00:00:00+00:00")
                store, project = self._accepted_parent(root, clock)
                store.create_schedule(self._schedule(project))
                service = RecorderService(
                    store,
                    tts=HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root)),
                )
                store.enqueue_worker_job(
                    kind="scheduler",
                    stage="scheduler",
                    payload={"now": "2026-08-26T00:00:00+00:00"},
                    idempotency_key="scheduler:replay-fixture",
                    max_attempts=3,
                    now="2026-08-26T00:00:00+00:00",
                )
                original_enqueue = service._enqueue_stage_job
                fault = {"raised": False}

                def fail_once(stage: str, *args: Any, **kwargs: Any) -> Any:
                    if stage == "tts" and not fault["raised"]:
                        fault["raised"] = True
                        raise sqlite3.OperationalError("transient enqueue failure")
                    return original_enqueue(stage, *args, **kwargs)

                with patch.object(service, "_enqueue_stage_job", side_effect=fail_once):
                    first = service.run_background_worker_once(
                        owner="scheduler-worker",
                        now="2026-08-26T00:00:00+00:00",
                    )
                    self.assertIsNotNone(first)
                    assert first is not None
                    self.assertEqual(first["stage"], "scheduler")
                    self.assertEqual(first["status"], "RETRY_WAIT")
                    self.assertEqual(first["last_error_kind"], "transport")
                    schedule = store.get_schedule("schedule-1")
                    occurrence = schedule["occurrences"][0]
                    self.assertEqual(occurrence["state"], "FIRED")
                    scheduled = store.get_turn(occurrence["turn_id"])
                    self.assertEqual(scheduled["tts_artifacts"][0]["status"], "PENDING")
                    self.assertEqual([job for job in store.list_worker_jobs() if job["stage"] == "tts"], [])

                    second = service.run_background_worker_once(
                        owner="scheduler-worker",
                        now="2026-08-26T00:00:03+00:00",
                    )
                    self.assertIsNotNone(second)
                    assert second is not None
                    self.assertEqual(second["stage"], "scheduler")
                    self.assertEqual(second["status"], "SUCCEEDED")
                    self.assertEqual(len(store.list_worker_jobs()), 2)

                third = service.run_background_worker_once(
                    owner="tts-worker",
                    now="2026-08-26T00:00:03+00:00",
                )
                self.assertIsNotNone(third)
                assert third is not None
                self.assertEqual(third["stage"], "tts")
                self.assertEqual(third["status"], "SUCCEEDED")
                scheduled = store.get_turn(occurrence["turn_id"])
                self.assertEqual(scheduled["tts_artifacts"][0]["status"], "READY")
                self.assertTrue(fixture.valid_request_seen)
            finally:
                fixture.close()

    def test_scheduled_final_tts_reaches_ready_through_authenticated_hermes_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture()
            try:
                clock = DeterministicClock("2026-08-26T00:00:00+00:00")
                store, project = self._accepted_parent(root, clock)
                store.create_schedule(self._schedule(project))
                service = RecorderService(
                    store,
                    tts=HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root)),
                )
                fired = service.run_scheduler(owner="scheduler")
                self.assertEqual(len(fired), 1)
                jobs = store.list_worker_jobs()
                self.assertEqual(len(jobs), 1)
                self.assertEqual(jobs[0]["stage"], "tts")
                receipt = service.run_background_worker_once(owner="tts-worker")
                self.assertIsNotNone(receipt)
                assert receipt is not None
                self.assertEqual(receipt["status"], "SUCCEEDED")
                self.assertEqual(receipt["stage"], "tts")
                scheduled = store.get_turn(fired[0]["turn"]["turn_id"])
                ready = scheduled["tts_artifacts"][0]
                self.assertEqual(ready["status"], "READY")
                self.assertEqual(ready["content_type"], "audio/mpeg")
                self.assertEqual(ready["payload_sha256"], hashlib.sha256(b"fixture-hermes-audio").hexdigest())
                self.assertTrue(fixture.authorization_valid)
                self.assertTrue(fixture.session_token_valid)
                self.assertTrue(fixture.valid_request_seen)
            finally:
                fixture.close()

    def test_scheduler_reconciles_pending_tts_after_enqueue_fault_and_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture()
            try:
                clock = DeterministicClock("2026-08-26T00:00:00+00:00")
                store, project = self._accepted_parent(root, clock)
                store.create_schedule(self._schedule(project))
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
                service = RecorderService(store, tts=provider)
                original_enqueue = store.enqueue_worker_job
                enqueue_calls = 0

                def fail_first_enqueue(**kwargs):
                    nonlocal enqueue_calls
                    enqueue_calls += 1
                    if enqueue_calls == 1:
                        raise sqlite3.OperationalError("synthetic worker enqueue fault")
                    return original_enqueue(**kwargs)

                with patch.object(store, "enqueue_worker_job", side_effect=fail_first_enqueue):
                    with self.assertRaises(ProviderFailure) as raised:
                        service.run_scheduler(owner="scheduler")
                self.assertEqual(raised.exception.kind, "transport")
                occurrence = store.get_schedule("schedule-1")["occurrences"][0]
                pending = store.pending_tts()
                self.assertEqual(len(pending), 2)
                scheduled_pending = [item for item in pending if item["turn_id"] == occurrence["turn_id"]]
                self.assertEqual(len(scheduled_pending), 1)
                self.assertEqual(store.list_worker_jobs(), [])
                self.assertEqual(store.get_schedule("schedule-1")["state"], "FIRED")

                restarted = RecorderService(store, tts=provider)
                recovery = restarted.recover_scheduler(now="2026-08-26T00:00:03+00:00")
                self.assertEqual(recovery["tts_jobs_enqueued"], 1)
                jobs = store.list_worker_jobs()
                self.assertEqual(len(jobs), 1)
                receipts = [
                    restarted.run_background_worker_once(
                        owner="tts-recovery",
                        now="2026-08-26T00:00:03+00:00",
                    )
                    for _ in jobs
                ]
                self.assertTrue(all(receipt is not None for receipt in receipts))
                self.assertTrue(all(receipt["status"] == "SUCCEEDED" and receipt["stage"] == "tts" for receipt in receipts if receipt is not None))
                recovered = store.get_turn(occurrence["turn_id"])
                self.assertEqual(recovered["tts_artifacts"][0]["status"], "READY")
                self.assertTrue(fixture.valid_request_seen)
            finally:
                fixture.close()

    def test_configured_chain_worker_receipt_preserves_unavailable_http_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture(route_available=False)
            try:
                clock = DeterministicClock("2026-08-26T00:00:00+00:00")
                store, project = self._accepted_parent(root, clock)
                store.create_schedule(self._schedule(project))
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
                chain = ProviderChain.from_providers("tts", [("hermes-audio", provider)])
                service = RecorderService(store, tts_chain=chain)
                fired = service.run_scheduler(owner="scheduler")
                job = store.list_worker_jobs()[0]
                self.assertEqual(job["payload"]["artifact_id"], fired[0]["artifact_id"])

                failed = service.run_background_worker_once(owner="tts-worker")
                self.assertIsNotNone(failed)
                assert failed is not None
                self.assertEqual(failed["status"], "RETRY_WAIT")
                self.assertEqual(failed["last_error_kind"], "provider_unavailable")
                self.assertEqual(failed["last_error_status_code"], 404)
                attempts = store.list_worker_attempts(job["job_id"])
                self.assertEqual(len(attempts), 1)
                self.assertEqual(attempts[0]["error_kind"], "provider_unavailable")
                self.assertEqual(attempts[0]["error_status_code"], 404)
                self.assertNotIn("fixture-secret", json.dumps(failed))
                self.assertNotIn("fixture-secret", json.dumps(attempts))
            finally:
                fixture.close()

    def test_durable_scheduler_fault_replay_reconciles_pending_tts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture()
            try:
                clock = DeterministicClock("2026-08-26T00:00:00+00:00")
                store, project = self._accepted_parent(root, clock)
                store.create_schedule(self._schedule(project))
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
                service = RecorderService(store, tts=provider)
                now = "2026-08-26T00:00:00+00:00"
                store.enqueue_worker_job(
                    kind="scheduler",
                    stage="scheduler",
                    payload={"now": now},
                    idempotency_key="scheduler:fault-replay",
                    max_attempts=1,
                    now=now,
                )
                original_enqueue = store.enqueue_worker_job
                failed_tts_enqueue = False

                def fail_first_tts_enqueue(**kwargs):
                    nonlocal failed_tts_enqueue
                    if kwargs.get("stage") == "tts" and not failed_tts_enqueue:
                        failed_tts_enqueue = True
                        raise sqlite3.OperationalError("synthetic worker enqueue fault")
                    return original_enqueue(**kwargs)

                with patch.object(store, "enqueue_worker_job", side_effect=fail_first_tts_enqueue):
                    failed = service.run_background_worker_once(owner="scheduler-worker", now=now)
                assert failed is not None
                self.assertEqual(failed["stage"], "scheduler")
                self.assertEqual(failed["status"], "FAILED_PERMANENT")
                occurrence = store.get_schedule("schedule-1")["occurrences"][0]
                self.assertEqual(occurrence["state"], "FIRED")
                self.assertEqual(store.get_turn(occurrence["turn_id"])["tts_artifacts"][0]["status"], "PENDING")
                self.assertEqual(store.list_worker_jobs(), [failed])

                restarted = RecorderService(store, tts=provider)
                replayed = restarted.run_background_worker_once(owner="recovery-worker", now=now)
                assert replayed is not None
                self.assertEqual(replayed["stage"], "tts")
                self.assertEqual(replayed["status"], "SUCCEEDED")
                self.assertEqual(store.get_turn(occurrence["turn_id"])["tts_artifacts"][0]["status"], "READY")
                self.assertTrue(fixture.valid_request_seen)
            finally:
                fixture.close()

    def test_scheduled_reconciliation_pages_past_terminal_first_page_and_ignores_large_non_schedule_backlog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, project = self._accepted_parent(root, clock)
            now = "2026-08-26T00:00:00+00:00"
            with store._tx() as conn:
                for index in range(501):
                    event_kind = "FINAL"
                    event_version = index + 1
                    event = store._insert_event_tx(
                        conn,
                        turn_id=PARENT_TURN,
                        event_kind=event_kind,
                        event_version=event_version,
                        required_device_id="watch-1",
                        payload={"type": event_kind, "version": event_version},
                        outcome="success",
                        error_kind=None,
                        create_outbox=False,
                        created_at=now,
                    )
                    store._create_tts_tx(
                        conn,
                        turn_id=PARENT_TURN,
                        event_id=event["event_id"],
                        event_kind=event_kind,
                        artifact_version=event_version,
                        source_text=f"backlog-{index}",
                        output_kind="TEST_TTS",
                        created_at=now,
                    )

            store.create_schedule(self._schedule(project))
            service = RecorderService(store)
            fired = service.run_scheduler(owner="scheduler")
            self.assertEqual(len(fired), 1)
            jobs = store.list_worker_jobs()
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]["stage"], "tts")
            self.assertEqual(jobs[0]["payload"]["artifact_id"], fired[0]["artifact_id"])
            self.assertEqual(
                [row["turn_id"] for row in store.pending_tts(turn_source="server_schedule")],
                [fired[0]["turn_id"]],
            )

            fairness_root = root / "fairness"
            fairness_root.mkdir()
            fairness_store, _ = self._accepted_parent(fairness_root, clock)
            with fairness_store._tx() as conn:
                conn.execute("UPDATE turns SET turn_source='server_schedule' WHERE turn_id=?", (PARENT_TURN,))
                for index in range(501):
                    event_version = index + 1
                    event = fairness_store._insert_event_tx(
                        conn,
                        turn_id=PARENT_TURN,
                        event_kind="FINAL",
                        event_version=event_version,
                        required_device_id="watch-1",
                        payload={"type": "FINAL", "version": event_version},
                        outcome="success",
                        error_kind=None,
                        create_outbox=False,
                        created_at=now,
                    )
                    fairness_store._create_tts_tx(
                        conn,
                        turn_id=PARENT_TURN,
                        event_id=event["event_id"],
                        event_kind="FINAL",
                        artifact_version=event_version,
                        source_text=f"scheduled-{index}",
                        output_kind="FINAL_TTS",
                        created_at=now,
                    )

            fairness_service = RecorderService(fairness_store)
            first_page = fairness_service._enqueue_pending_tts_jobs(now=now, scheduled_only=True)
            self.assertEqual(len(first_page), 500)
            with fairness_store._tx() as conn:
                conn.execute(
                    "UPDATE worker_jobs SET status='FAILED_PERMANENT', owner=NULL, lease_expires_at=NULL, completed_at=?",
                    (now,),
                )

            eligible = fairness_store.pending_tts(limit=600, turn_source="server_schedule")
            second_page = fairness_service._enqueue_pending_tts_jobs(now=now, scheduled_only=True)
            self.assertEqual(len(second_page), 1)
            self.assertEqual(second_page[0]["payload"]["artifact_id"], eligible[500]["artifact_id"])
            self.assertEqual(fairness_service._enqueue_pending_tts_jobs(now=now, scheduled_only=True), [])
            self.assertEqual(fairness_store.worker_health()["counts"]["FAILED_PERMANENT"], 500)
            self.assertEqual(fairness_store.worker_health()["counts"]["PENDING"], 1)
            self.assertEqual(fairness_store.get_artifact(eligible[0]["artifact_id"])["status"], "EXPIRED")
            self.assertEqual(fairness_store.get_artifact(eligible[500]["artifact_id"])["status"], "PENDING")

    def test_expired_unclaimed_scheduled_tts_converges_artifact_to_terminal_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, project = self._accepted_parent(root, clock)
            store.create_schedule(self._schedule(project))
            service = RecorderService(store)

            fired = service.run_scheduler(owner="scheduler", now=clock.now())
            artifact_id = fired[0]["artifact_id"]
            job = store.list_worker_jobs()[0]
            self.assertEqual(store.get_artifact(artifact_id)["status"], "PENDING")

            # The worker is down past the enqueue-time deadline.  Claiming the
            # expired job must converge the linked artifact instead of leaving
            # a permanently unprocessable PENDING row.
            clock.advance(seconds=181)
            self.assertIsNone(service.run_background_worker_once(owner="recovery", now=clock.now()))

            terminal_job = store.get_worker_job(job["job_id"])
            terminal_artifact = store.get_artifact(artifact_id)
            self.assertEqual(terminal_job["status"], "FAILED_PERMANENT")
            self.assertEqual(terminal_job["last_error_kind"], "deadline")
            self.assertEqual(terminal_artifact["status"], "EXPIRED")
            self.assertEqual(terminal_artifact["relay_state"], "EXPIRED")
            self.assertEqual(terminal_artifact["retention_outcome"], "expired")
            self.assertEqual(service._enqueue_pending_tts_jobs(now=clock.now(), scheduled_only=True), [])
            self.assertIsNone(service.run_background_worker_once(owner="recovery", now=clock.now()))

    def test_terminal_tts_worker_failure_converges_pending_artifact_without_reenqueue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, project = self._accepted_parent(root, clock)
            store.create_schedule(self._schedule(project))
            service = RecorderService(store)
            fired = service.run_scheduler(owner="scheduler", now=clock.now())
            artifact_id = fired[0]["artifact_id"]
            job = store.list_worker_jobs()[0]

            claimed = store.claim_worker_job("terminal-worker", now=clock.now(), lease_seconds=30)
            self.assertIsNotNone(claimed)
            failed = store.fail_worker_job(
                job["job_id"],
                "terminal-worker",
                error_kind="no_handler",
                retryable=False,
                lease_token=claimed["lease_token"],
                now=clock.now(),
            )
            self.assertEqual(failed["status"], "FAILED_PERMANENT")
            self.assertEqual(store.get_artifact(artifact_id)["status"], "EXPIRED")
            self.assertEqual(service._enqueue_pending_tts_jobs(now=clock.now(), scheduled_only=True), [])
            self.assertEqual(len(store.list_worker_jobs()), 1)

    def test_tts_lease_recovery_reuses_one_job_and_generates_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-08-26T00:00:00+00:00")
            store, project = self._accepted_parent(root, clock)
            store.create_schedule(self._schedule(project))

            class CountingTTS:
                name = "counting"

                def __init__(self):
                    self.calls = 0

                def synthesize(self, text: str, *, artifact_id: str) -> TTSResult:
                    self.calls += 1
                    return TTSResult(f"recovered-{self.calls}".encode(), metadata={"artifact_id": artifact_id})

            provider = CountingTTS()
            service = RecorderService(store, tts=provider)
            fired = service.run_scheduler(owner="scheduler", now=clock.now())
            artifact_id = fired[0]["artifact_id"]
            job = store.list_worker_jobs()[0]
            claimed = store.claim_worker_job("crashed-worker", now=clock.now(), lease_seconds=1)
            self.assertIsNotNone(claimed)

            clock.advance(seconds=2)
            self.assertEqual(store.recover_worker_jobs(now=clock.now()), {"requeued": 1, "failed": 0})
            recovered = service.run_background_worker_once(owner="recovery-worker", now=clock.now())
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered["job_id"], job["job_id"])
            self.assertEqual(recovered["status"], "SUCCEEDED")
            self.assertEqual(provider.calls, 1)
            self.assertEqual(len(store.list_worker_jobs()), 1)
            self.assertEqual(store.get_artifact(artifact_id)["status"], "READY")

    def test_systemd_style_config_factory_uses_hermes_tts_and_worker_seam(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credential_dir = root / "systemd-credentials"
            credential_dir.mkdir()
            credential = credential_dir / "recorder_api_key"
            credential.write_text("API_SERVER_KEY=fixture-secret\n")
            credential.chmod(0o600)
            fixture = _TTSFixture()
            try:
                config_path = root / "recorder-next.toml"
                config_path.write_text(
                    "\n".join(
                        (
                            "[server]",
                            'host = "127.0.0.1"',
                            "port = 8653",
                            "",
                            "[storage]",
                            f'database = "{root / "db.sqlite3"}"',
                            f'root = "{root / "data"}"',
                            "",
                            "[providers]",
                            'tts_source = "hermes"',
                            'tts_chain = ["hermes-audio"]',
                            "",
                            "[[providers.tts_providers]]",
                            'name = "hermes-audio"',
                            'adapter = "hermes"',
                            f'endpoint = "{fixture.url}"',
                            'profile = "default"',
                            'credential_file = "$CREDENTIALS_DIRECTORY/recorder_api_key"',
                            "enabled = true",
                        )
                    )
                    + "\n"
                )
                with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(credential_dir)}, clear=False), patch(
                    "recorder_next.adapters._trusted_systemd_credential_path", return_value=None
                ):
                    service = create_configured_service(RecorderConfig.from_file(config_path).resolved())
                self.assertIsNotNone(service.tts_chain)
                assert service.tts_chain is not None
                provider = service.tts_chain.targets[0].provider
                self.assertIsInstance(provider, HermesAudioTTSProvider)
                self.assertEqual(provider.endpoint, f"{fixture.url}/api/audio/speak?profile=default")
                store, project = self._accepted_parent(root / "schedule", DeterministicClock("2026-08-26T00:00:00+00:00"))
                service = RecorderService(store, tts_chain=service.tts_chain)
                store.create_schedule(self._schedule(project))
                fired = service.run_scheduler(owner="scheduler")
                receipt = service.run_background_worker_once(owner="tts-worker")
                self.assertEqual(len(fired), 1)
                self.assertIsNotNone(receipt)
                assert receipt is not None
                self.assertEqual(receipt["status"], "SUCCEEDED")
                self.assertTrue(fixture.authorization_valid)
                self.assertTrue(fixture.session_token_valid)
            finally:
                fixture.close()

    def test_wrong_auth_fails_the_real_tts_worker_without_success_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture()
            try:
                clock = DeterministicClock("2026-08-26T00:00:00+00:00")
                store, project = self._accepted_parent(root, clock)
                store.create_schedule(self._schedule(project))
                service = RecorderService(
                    store,
                    tts=HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None),
                )
                fired = service.run_scheduler(owner="scheduler")
                receipt = service.run_background_worker_once(owner="tts-worker")
                self.assertIsNotNone(receipt)
                assert receipt is not None
                self.assertEqual(receipt["status"], "FAILED_PERMANENT")
                self.assertEqual(receipt["last_error_kind"], "auth")
                self.assertNotEqual(receipt["status"], "SUCCEEDED")
                self.assertNotIn("fixture-secret", json.dumps(receipt))
                scheduled = store.get_turn(fired[0]["turn"]["turn_id"])
                self.assertEqual(scheduled["tts_artifacts"][0]["status"], "FAILED_GENERATION")
                self.assertFalse(fixture.valid_request_seen)
                self.assertFalse(fixture.authorization_seen)
                self.assertFalse(fixture.session_token_seen)
            finally:
                fixture.close()


class HermesTTSReadyOnlyEnvelopeTests(unittest.TestCase):
    """B3 T4: the live ok-only edge shape through the authenticated fixture.

    The sealed dashboard capability envelope carries ok/stt/tts without a
    top-level ready; readiness must accept it while the malformed envelope
    variants keep failing closed — all through raw authenticated HTTP with
    zero synthesize POSTs.
    """

    def _credential(self, root: Path) -> Path:
        path = root / "recorder_api_key.env"
        path.write_text("API_SERVER_KEY=fixture-secret\n", encoding="ascii")
        path.chmod(0o600)
        return path

    def _ready_provider(self, root: Path):
        fixture = _TTSFixture()
        # Rebuild the readiness fixture contract on the live TTS fixture:
        # readiness probes use GET /api/health and GET /api/audio/voice-config.
        provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
        return fixture, provider

    def test_live_ready_fixture_admits_readiness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture()
            try:
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
                result = provider.readiness_check()
                self.assertEqual(set(result), {"health", "capability", "endpoint_contract"})
                self.assertEqual(result["endpoint_contract"], "/api/audio/speak?profile=default")
            finally:
                fixture.close()

    def test_capability_shape_matches_sealed_envelope_flags(self):
        # The projected capability of the sealed ok/ready fixture keeps the
        # boolean flags and the bounded tts semantics, never secrets.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _TTSFixture()
            try:
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
                capability = provider.capability_check()
                projected = capability.get("tts")
                self.assertIsInstance(projected, dict)
                self.assertEqual(projected.get("mode"), "relay")
                self.assertEqual(projected.get("reason"), "provider 'edge' has no client wire")
                self.assertIs(projected.get("ok"), True)
                self.assertNotIn("fixture-secret", repr(capability))
            finally:
                fixture.close()


if __name__ == "__main__":
    unittest.main()
