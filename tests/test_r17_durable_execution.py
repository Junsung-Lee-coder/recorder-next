from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from recorder_next.adapters import (
    HttpHermesGateway,
    MemoryHermesGateway,
    ProviderChain,
    ProviderFailure,
    StaticTTSProvider,
)
from recorder_next.config import RecorderConfig
from recorder_next.errors import ChunkConflict, LeaseConflict
from recorder_next.features import DurableProcessingWorker
from recorder_next.hermes_wire import SubmissionContext
from recorder_next.models import AsrResult, HermesResult, RouterDecision
from recorder_next.openapi import OPENAPI
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore, utc_now
from tests.r25_test_helpers import canonical_wav


BASE_TIME = "2026-09-06T00:00:00+00:00"


def _manifest(
    turn_id: str,
    payload: bytes,
    *,
    kind: str = "text",
    user_id: str = "r17-user",
    device_id: str = "r17-phone",
    project_number: str = "R17-PROJECT",
) -> dict:
    return {
        "schema_version": 1,
        "user_id": user_id,
        "turn_id": turn_id,
        "origin_device_id": device_id,
        "client_created_at": BASE_TIME,
        "current_project_number": project_number,
        "prefer_current_project": True,
        "parts": [
            {
                "part_id": "part-1",
                "kind": kind,
                "mime": "audio/wav" if kind == "audio" else "text/plain",
                "declared_bytes": len(payload),
                "declared_sha256": hashlib.sha256(payload).hexdigest(),
            }
        ],
    }


def _accept(store: RecorderStore, turn_id: str, payload: bytes, *, kind: str = "text") -> dict:
    if kind == "audio":
        payload = canonical_wav()
    store.create_turn(_manifest(turn_id, payload, kind=kind))
    store.put_chunk(turn_id, "part-1", 0, payload)
    store.finish_part(
        turn_id,
        "part-1",
        total_chunks=1,
        total_bytes=len(payload),
        whole_stream_sha256=hashlib.sha256(payload).hexdigest(),
    )
    return store.accept_turn(turn_id)


def _routed_pair(root: Path) -> tuple[RecorderStore, RecorderService, dict, list[dict]]:
    store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
    project = store.create_project("r17-user", project_number="R17-PROJECT", name="R17")
    gateway = MemoryHermesGateway()
    service = RecorderService(store, hermes=gateway, tts=StaticTTSProvider())
    for turn_id, text in (
        ("018f5a2e-7b6e-7abc-8d11-1234567890a1", b"first"),
        ("018f5a2e-7b6e-7abc-8d11-1234567890a2", b"second"),
    ):
        _accept(store, turn_id, text)
        service.route_next("r17-user")
    with store._read() as conn:
        ingress = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM session_ingress ORDER BY accepted_seq"
            ).fetchall()
        ]
    return store, service, project, ingress


class _AlwaysFinalGateway:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def submit(self, *, session_key: str, request: dict, submission_id: str, marker: str) -> HermesResult:
        del session_key, request, marker
        self.calls.append(submission_id)
        return HermesResult(f"assistant:{submission_id}", f"final:{submission_id}")

    def history(self, *, session_key: str, marker: str) -> None:
        del session_key, marker
        return None

    def history_messages(self, *, session_key: str, marker: str) -> list[HermesResult]:
        del session_key, marker
        return []


class _FlakyASR:
    name = "flaky-r17"

    def __init__(self) -> None:
        self.fail = True

    def transcribe(self, audio: bytes, *, turn_id: str, generation: int) -> AsrResult:
        del audio, turn_id, generation
        if self.fail:
            raise ProviderFailure("transport", retryable=True)
        return AsrResult.valid("recovered transcript")


class R17HermesBindingTests(unittest.TestCase):
    def test_reversed_same_session_submission_jobs_cannot_cross_bind(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, service, project, ingress = _routed_pair(Path(tmp))
            first, second = ingress
            gateway = service.hermes
            assert isinstance(gateway, MemoryHermesGateway)
            gateway.responses[first["hermes_submission_id"]] = HermesResult("first-msg", "first final")
            gateway.responses[second["hermes_submission_id"]] = HermesResult("second-msg", "second final")

            jobs = store.list_worker_jobs()
            hermes_jobs = [job for job in jobs if job["stage"] == "hermes"]
            self.assertEqual(
                [job["payload"]["hermes_submission_id"] for job in hermes_jobs],
                [item["hermes_submission_id"] for item in ingress],
            )

            blocked = service.process_next_hermes(
                project["stable_project_id"],
                owner="hermes-second",
                hermes_submission_id=second["hermes_submission_id"],
            )
            self.assertIsNone(blocked)
            self.assertEqual(gateway.calls, [])
            self.assertEqual(store.get_ingress(first["hermes_submission_id"])["status"], "QUEUED")
            self.assertEqual(store.get_ingress(second["hermes_submission_id"])["status"], "QUEUED")

            first_result = service.process_next_hermes(
                project["stable_project_id"],
                owner="hermes-first",
                hermes_submission_id=first["hermes_submission_id"],
            )
            self.assertEqual(first_result["final_content"], "first final")
            second_result = service.process_next_hermes(
                project["stable_project_id"],
                owner="hermes-second",
                hermes_submission_id=second["hermes_submission_id"],
            )
            self.assertEqual(second_result["final_content"], "second final")
            self.assertEqual(gateway.calls[0]["submission_id"], first["hermes_submission_id"])
            self.assertEqual(gateway.calls[1]["submission_id"], second["hermes_submission_id"])

    def test_logical_session_can_bind_a_distinct_canonical_gateway_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            project = store.create_project("r17-user", project_number="R17-PROJECT", name="R17")
            logical_session = project["default_session_key"]
            gateway_session = "existing-hermes-transcript"
            with store._tx() as conn:
                conn.execute(
                    "UPDATE sessions SET gateway_session_key=? WHERE project_id=? AND session_key=?",
                    (gateway_session, project["stable_project_id"], logical_session),
                )
            service = RecorderService(store, hermes=MemoryHermesGateway(), tts=StaticTTSProvider())
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890b1"
            _accept(store, turn_id, b"canonical target")

            routed = service.route_next("r17-user")
            ingress = store.get_ingress_for_turn(turn_id)
            assert routed is not None
            assert ingress is not None

            self.assertEqual(routed["session_key"], logical_session)
            self.assertEqual(ingress["target_session_id"], project["stable_project_id"])
            self.assertEqual(ingress["gateway_session_key"], gateway_session)
            self.assertEqual(store.submission_context(ingress["hermes_submission_id"]).gateway_session_key, gateway_session)

    def test_gateway_target_order_blocks_reverse_claim_across_misbound_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _service, project, ingress = _routed_pair(Path(tmp))
            first, second = ingress
            with store._tx() as conn:
                conn.execute(
                    "UPDATE session_ingress SET target_session_id=? WHERE hermes_submission_id=?",
                    ("misbound-project", second["hermes_submission_id"]),
                )

            blocked = store.claim_session_ingress(
                "misbound-project",
                "second-owner",
                hermes_submission_id=second["hermes_submission_id"],
            )
            self.assertIsNone(blocked)
            claimed = store.claim_session_ingress(
                project["stable_project_id"],
                "first-owner",
                hermes_submission_id=first["hermes_submission_id"],
            )
            assert claimed is not None
            self.assertEqual(claimed["hermes_submission_id"], first["hermes_submission_id"])

    def test_commit_route_rejects_known_cross_project_gateway_session_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            first = store.create_project("r17-user", project_number="R17-PROJECT", name="First")
            second = store.create_project("r17-user", project_number="R17-OTHER", name="Second")
            gateway_session = "shared-hermes-transcript"
            with store._tx() as conn:
                conn.execute(
                    "UPDATE sessions SET gateway_session_key=? WHERE project_id IN (?, ?)",
                    (gateway_session, first["stable_project_id"], second["stable_project_id"]),
                )
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890b2"
            _accept(store, turn_id, b"reject alias")
            decision = RouterDecision(
                "route-alias",
                first["stable_project_id"],
                first["default_session_key"],
                first["record_version"],
                "reject alias",
                "test",
            )

            with self.assertRaises(Exception):
                store.commit_route(turn_id, decision)


class R17HermesSessionPreflightTests(unittest.TestCase):
    @staticmethod
    def _context(session_key: str) -> SubmissionContext:
        return SubmissionContext(
            submission_id="submission-1",
            subject_kind="turn",
            marker="marker-1",
            gateway_session_key=session_key,
            canonical_request_sha256="a" * 64,
            wire_revision="test-v1",
            request={"input": "normalized"},
            turn_id="018f5a2e-7b6e-7abc-8d11-1234567890b3",
        )

    def test_preflight_failures_never_post_a_run(self):
        session_key = "existing-hermes-transcript"
        cases = {
            "missing": ProviderFailure("client_error", retryable=False, status_code=404),
            "archived": {"object": "hermes.session", "session": {"id": session_key, "archived": True, "ended_at": None}},
            "mismatch": {"object": "hermes.session", "session": {"id": "other-session", "archived": False, "ended_at": None}},
            "wrong_object": {"object": "list", "session": {"id": session_key, "archived": False, "ended_at": None}},
        }

        for name, response in cases.items():
            with self.subTest(name=name):
                class ProbeGateway(HttpHermesGateway):
                    def __init__(self):
                        super().__init__("http://127.0.0.1:9", poll_interval_seconds=0, require_existing_session=True)
                        self.calls = []

                    def _request(self, method, path, payload=None, *, extra_headers=None, timeout_seconds=None, deadline_at=None):
                        del payload, extra_headers, timeout_seconds, deadline_at
                        self.calls.append((method, path))
                        if isinstance(response, Exception):
                            raise response
                        return response

                gateway = ProbeGateway()
                with self.assertRaises(ProviderFailure):
                    gateway.submit(
                        session_key=session_key,
                        request={"input": "normalized"},
                        submission_id="submission-1",
                        marker="marker-1",
                        context=self._context(session_key),
                    )
                self.assertEqual([method for method, _path in gateway.calls], ["GET"])

    def test_matching_session_and_completed_run_status_produce_final(self):
        session_key = "existing-hermes-transcript"

        class ProbeGateway(HttpHermesGateway):
            def __init__(self):
                super().__init__("http://127.0.0.1:9", poll_interval_seconds=0, require_existing_session=True)
                self.calls = []

            def _request(self, method, path, payload=None, *, extra_headers=None, timeout_seconds=None, deadline_at=None):
                del payload, extra_headers, timeout_seconds, deadline_at
                self.calls.append((method, path))
                if path.startswith("/api/sessions/"):
                    return {"object": "hermes.session", "session": {"id": session_key, "archived": False, "ended_at": None}}
                if method == "POST":
                    return {"run_id": "run-1", "status": "queued"}
                return {"run_id": "run-1", "status": "completed", "session_id": session_key, "output": "actual final"}

        gateway = ProbeGateway()
        result = gateway.submit(
            session_key=session_key,
            request={"input": "normalized"},
            submission_id="submission-1",
            marker="marker-1",
            context=self._context(session_key),
        )

        assert result is not None
        self.assertEqual(result.content, "actual final")
        self.assertEqual([method for method, _path in gateway.calls], ["GET", "POST", "GET"])


class R17HermesTerminalityTests(unittest.TestCase):
    def test_progress_malformed_empty_and_history_events_are_not_terminal(self):
        progress = HttpHermesGateway._parse_result(
            {
                "object": "hermes.session.chat.completion",
                "status": "progress",
                "terminal": False,
                "message": {"role": "assistant", "content": "검색중입니다"},
            }
        )
        self.assertIsNotNone(progress)
        self.assertFalse(progress.terminal)
        self.assertIsNone(HttpHermesGateway._parse_result({"status": "unknown", "content": "ambiguous"}))
        self.assertIsNone(HttpHermesGateway._parse_result({"message": {"role": "assistant", "content": "   "}}))

        class HistoryGateway(HttpHermesGateway):
            def __init__(self) -> None:
                super().__init__("http://127.0.0.1:9")

            def _request(self, method, path, payload=None, *, extra_headers=None):
                del method, path, payload, extra_headers
                return {
                    "object": "list",
                    "data": [
                        {"id": "u", "role": "user", "content": "marker-r17"},
                        {
                            "id": "progress",
                            "role": "assistant",
                            "status": "progress",
                            "terminal": False,
                            "content": "중간 상태",
                        },
                        {"id": "final", "role": "assistant", "status": "completed", "content": "최종 상태"},
                    ],
                }

        history = HistoryGateway().history_messages(
            session_key="project:r17",
            marker="marker-r17",
        )
        self.assertEqual([item.content for item in history], ["최종 상태"])
        self.assertTrue(all(item.terminal for item in history))

    def test_progress_response_is_released_and_later_final_replaces_no_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            project = store.create_project("r17-user", project_number="R17-PROJECT", name="R17")
            gateway = MemoryHermesGateway()
            service = RecorderService(store, hermes=gateway, tts=StaticTTSProvider())
            turn = _accept(store, "018f5a2e-7b6e-7abc-8d11-1234567890a3", b"hello")
            routed = service.route_next("r17-user")
            with store._read() as conn:
                submission_id, marker = conn.execute(
                    "SELECT hermes_submission_id, marker FROM session_ingress WHERE turn_id=?",
                    (turn["turn_id"],),
                ).fetchone()
            gateway.responses[submission_id] = HermesResult("progress", "검색중입니다", terminal=False)

            pending = service.process_next_hermes(
                project["stable_project_id"],
                owner="progress-worker",
                hermes_submission_id=submission_id,
            )
            self.assertEqual(pending["turn_id"], routed["turn_id"])
            self.assertEqual(pending["final_event_version"], 0)
            self.assertEqual(store.get_ingress(submission_id)["status"], "QUEUED")
            self.assertEqual(store.get_turn(turn["turn_id"])["hermes_result_refs"], [])

            gateway.responses[submission_id] = HermesResult("final", "최종 답변")
            final = service.process_next_hermes(
                project["stable_project_id"],
                owner="progress-worker",
                hermes_submission_id=submission_id,
            )
            self.assertEqual(final["final_event_version"], 1)
            self.assertEqual(final["final_content"], "최종 답변")
            self.assertNotIn("검색중입니다", json.dumps(final, ensure_ascii=False))
            self.assertEqual(gateway.calls[-1]["marker"], marker)


class R17ASRRetryTests(unittest.TestCase):
    def test_retryable_chain_failure_survives_worker_budget_until_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            flaky = _FlakyASR()
            chain = ProviderChain.from_providers(
                "asr",
                [("flaky", flaky)],
                source="fixture-asr",
                overall_deadline_seconds=60,
            )
            service = RecorderService(store, asr_chain=chain, tts=StaticTTSProvider())
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890a4"
            accepted = _accept(store, turn_id, b"RIFF-r17-audio", kind="audio")
            service._enqueue_turn_stage(accepted)
            self.assertEqual(accepted["state"], "ACCEPTED")

            first = service.run_background_worker_once(owner="asr-worker")
            self.assertEqual(first["stage"], "asr")
            self.assertEqual(first["status"], "RETRY_WAIT")
            self.assertEqual(store.get_turn(turn_id)["final_event_version"], 0)
            self.assertIsNone(store.get_turn(turn_id)["authoritative_asr_outcome"])

            flaky.fail = False
            second = service.run_background_worker_once(owner="asr-worker", now=first["next_attempt_at"])
            self.assertEqual(second["stage"], "asr")
            self.assertEqual(second["status"], "SUCCEEDED")
            recovered = store.get_turn(turn_id)
            self.assertEqual(recovered["transcript"], "recovered transcript")
            self.assertEqual(recovered["authoritative_asr_outcome"], "VALID_TRANSCRIPT")
            self.assertEqual(recovered["final_event_version"], 0)


class R17LeaseHeartbeatTests(unittest.TestCase):
    def test_blocked_handler_lease_is_renewed_and_stale_token_cannot_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            store.enqueue_worker_job(kind="effect", stage="effect", payload={"id": "heartbeat"}, idempotency_key="heartbeat-job")
            entered = threading.Event()
            release = threading.Event()
            results: list[dict | None] = []

            def handler(job):
                del job
                entered.set()
                self.assertTrue(release.wait(4))
                return {"effect_id": "heartbeat-effect", "status": "succeeded"}

            worker = DurableProcessingWorker(store, owner="heartbeat-worker", handlers={"effect": handler})
            thread = threading.Thread(
                target=lambda: results.append(worker.run_once(lease_seconds=1)),
                daemon=True,
            )
            thread.start()
            self.assertTrue(entered.wait(2))
            time.sleep(1.4)
            self.assertIsNone(store.claim_worker_job("takeover", lease_seconds=1))
            release.set()
            thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertEqual(results[0]["status"], "SUCCEEDED")

            store.enqueue_worker_job(kind="effect", stage="effect", payload={"id": "death"}, idempotency_key="death-job")
            first = store.claim_worker_job("dead-worker", lease_seconds=1)
            self.assertIsNotNone(first)
            assert first is not None
            second = store.claim_worker_job("new-worker", now=first["lease_expires_at"], lease_seconds=1)
            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            self.assertNotEqual(first["lease_token"], second["lease_token"])
            with self.assertRaises(LeaseConflict):
                store.complete_worker_job(
                    first["job_id"],
                    "dead-worker",
                    {"effect_id": "stale-effect", "status": "succeeded"},
                    lease_token=first["lease_token"],
                    now="2026-09-06T00:00:02+00:00",
                )
            completed = store.complete_worker_job(
                second["job_id"],
                "new-worker",
                {"effect_id": "new-effect", "status": "succeeded"},
                lease_token=second["lease_token"],
                now="2026-09-06T00:00:02+00:00",
            )
            self.assertEqual(completed["status"], "SUCCEEDED")


class R17AutonomousRuntimeTests(unittest.TestCase):
    def test_service_loops_process_turn_and_due_schedule_without_internal_post(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            gateway = _AlwaysFinalGateway()
            service = RecorderService(store, hermes=gateway, tts=StaticTTSProvider())
            project = store.create_project("r17-user", project_number="R17-PROJECT", name="R17")
            store.register_device("r17-user", "r17-phone", "phone")
            parent_id = "018f5a2e-7b6e-7abc-8d11-1234567890a5"
            _accept(store, parent_id, b"parent")
            schedule = service.schedule_create(
                {
                    "schedule_id": "r17-schedule",
                    "parent_turn_id": parent_id,
                    "project_id": project["stable_project_id"],
                    "session_key": project["default_session_key"],
                    "origin_device_id": "r17-phone",
                    "delivery_target_device_id": "r17-phone",
                    "fire_at_utc": utc_now(),
                    "timezone_offset": "+09:00",
                    "reminder_text": "scheduled reminder",
                    "confirmation_text": "scheduled",
                }
            )
            live_turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890a6"
            service.start_background_workers(worker_poll_seconds=0.02, scheduler_poll_seconds=0.02)
            try:
                accepted = _accept(store, live_turn_id, b"live turn")
                service._enqueue_turn_stage(accepted)

                deadline = time.monotonic() + 6
                scheduled_turn_id = None
                while time.monotonic() < deadline:
                    live = store.get_turn(live_turn_id)
                    current_schedule = store.get_schedule(schedule["schedule_id"])
                    occurrence = current_schedule["occurrences"][0]
                    scheduled_turn_id = occurrence.get("turn_id")
                    if (
                        live["final_event_version"] == 1
                        and live["tts_artifacts"]
                        and live["tts_artifacts"][0]["status"] == "READY"
                        and occurrence["state"] == "FIRED"
                        and scheduled_turn_id
                    ):
                        scheduled = store.get_turn(scheduled_turn_id)
                        if scheduled["tts_artifacts"] and scheduled["tts_artifacts"][0]["status"] == "READY":
                            break
                    time.sleep(0.02)
                self.assertEqual(store.get_turn(live_turn_id)["final_event_version"], 1)
                self.assertIsNotNone(scheduled_turn_id)
                self.assertEqual(store.get_schedule(schedule["schedule_id"])["occurrences"][0]["state"], "FIRED")
                self.assertEqual(store.get_turn(scheduled_turn_id)["final_event_version"], 1)
                self.assertEqual(store.get_turn(scheduled_turn_id)["tts_artifacts"][0]["status"], "READY")
            finally:
                service.stop_background_workers()

    def test_worker_and_scheduler_controls_use_exact_http_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = RecorderService(RecorderStore(root / "db.sqlite3", storage_root=root / "data"))
            for path in (
                "/v1/internal/worker/claim",
                "/v1/internal/worker/recover",
                "/v1/internal/worker/complete",
                "/v1/internal/worker/fail",
                "/v1/internal/worker/run",
                "/v1/internal/scheduler/fire",
                "/v1/internal/scheduler/recover",
            ):
                self.assertNotEqual(service.handle_http("POST", path, {}, b"{}")[0], 404, path)
                self.assertIn(path, OPENAPI["paths"])
            for path in ("/v1/internal/router", "/v1/internal/hermes", "/v1/internal/tts"):
                self.assertEqual(service.handle_http("POST", path, {}, b"{}")[0], 404, path)
                self.assertNotIn(path, OPENAPI["paths"])


class R17ConfigAndChunkTests(unittest.TestCase):
    def test_cli_overrides_copy_loaded_config_without_dropping_provider_settings(self):
        from recorder_next.__main__ import apply_cli_overrides

        original = RecorderConfig(
            database="source.sqlite3",
            storage_root="source-data",
            host="source-host",
            port=8643,
            hermes_max_attempts=7,
            hermes_profile="r17-profile",
            asr_chain=("loaded-asr",),
            tts_chain=("loaded-tts",),
        )
        overridden = apply_cli_overrides(
            original,
            db="override.sqlite3",
            storage_root="override-data",
            host="override-host",
            port=9753,
        )
        self.assertEqual(original.database, "source.sqlite3")
        self.assertEqual(original.storage_root, "source-data")
        self.assertEqual(overridden.database, "override.sqlite3")
        self.assertEqual(overridden.storage_root, "override-data")
        self.assertEqual(overridden.host, "override-host")
        self.assertEqual(overridden.port, 9753)
        self.assertEqual(overridden.hermes_max_attempts, 7)
        self.assertEqual(overridden.hermes_profile, "r17-profile")
        self.assertEqual(overridden.asr_chain, ("loaded-asr",))
        self.assertEqual(overridden.tts_chain, ("loaded-tts",))

    def test_existing_chunk_is_resolved_before_cleanup_receipt_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890a7"
            _accept(store, turn_id, b"original")
            with store._read() as conn:
                before = conn.execute("SELECT COUNT(*) FROM storage_cleanup_receipts").fetchone()[0]
            with self.assertRaises(ChunkConflict):
                store.put_chunk(turn_id, "part-1", 0, b"different")
            with store._read() as conn:
                after = conn.execute("SELECT COUNT(*) FROM storage_cleanup_receipts").fetchone()[0]
            self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
