from __future__ import annotations

import base64
import hashlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from recorder_next import adapters
from recorder_next.adapters import HttpASRProvider, HttpHermesGateway, HttpTTSProvider, ProviderChain, ProviderFailure, ProviderTarget, StaticASRProvider
from recorder_next.clock import DeterministicClock
from recorder_next.config import ProviderConfig, RecorderConfig
from recorder_next.errors import ConflictError
from recorder_next.features import DurableProcessingWorker
from recorder_next.models import AsrResult, HermesResult
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore
from tests.test_feature_groups import complete_turn


class _Response(io.BytesIO):
    def __init__(self, payload: object, content_type: str = "application/json") -> None:
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        super().__init__(raw)
        self.headers = {"Content-Type": content_type}
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
        return None


class R23AdapterRepairTests(unittest.TestCase):
    def test_terminal_parser_rejects_failure_nested_conflict_and_correlation_conflict(self):
        payloads = [
            {"status": "failed", "content": "failure"},
            {"terminal": True, "message": {"terminal": False, "role": "assistant", "content": "progress"}},
            {"role": "assistant", "message": {"role": "user", "content": "wrong role"}},
            {"marker": "marker-A", "message": {"marker": "marker-B", "role": "assistant", "content": "wrong turn"}},
        ]
        for payload in payloads:
            with patch.object(adapters, "_urlopen_no_redirect", return_value=_Response(payload)):
                result = HttpHermesGateway("https://fixture.invalid").submit(
                    session_key="session", request={"input": "request"}, submission_id="submission", marker="marker-A"
                )
            self.assertIsNone(result, payload)

    def test_asr_failure_envelope_is_rejected_and_source_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            turn = complete_turn(store, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890d1", kind="audio", payload=b"wav")
            provider = HttpASRProvider("https://fixture.invalid", model="fixture", credential_file=None)
            service = RecorderService(store, asr_providers={"realtime": provider})
            with patch.object(adapters, "_urlopen_no_redirect", return_value=_Response({"status": "failed", "outcome": "ERROR", "text": "upstream failure"})):
                result = service.run_asr(turn["turn_id"])
            self.assertEqual(result["authoritative_asr_outcome"], "PROVIDER_ERROR")
            self.assertIsNone(result["transcript"])
            self.assertEqual(result["source_deleted"], 0)
            self.assertNotEqual(result["final_error_kind"], None)

    def test_asr_nested_failure_status_is_rejected_without_an_outcome(self):
        provider = HttpASRProvider("https://fixture.invalid", model="fixture", credential_file=None)
        payloads = [
            {"status": "failed", "text": "upstream diagnostic"},
            {"result": {"status": "error", "transcript": "upstream diagnostic"}},
            {"data": {"ok": False, "text": "upstream diagnostic"}},
        ]
        for payload in payloads:
            with patch.object(adapters, "_urlopen_no_redirect", return_value=_Response(payload)):
                with self.assertRaises(ProviderFailure) as caught:
                    provider.transcribe(b"wav", turn_id="turn", generation=1)
            self.assertIn(caught.exception.kind, {"provider_error", "malformed_success"})

    def test_hermes_asr_failure_status_is_rejected_without_an_outcome(self):
        provider = adapters.HermesAudioASRProvider("https://fixture.invalid", credential_file=None)
        with patch.object(adapters, "_urlopen_no_redirect", return_value=_Response({"result": {"status": "failed", "text": "diagnostic"}})):
            with self.assertRaises(ProviderFailure):
                provider.transcribe(b"wav", turn_id="turn", generation=1)

    def test_tts_reserved_options_are_rejected(self):
        with self.assertRaises(ValueError):
            ProviderConfig.from_spec(
                "voice", "tts", {"adapter": "http-tts", "endpoint": "https://fixture.invalid", "model": "m", "voice": "v", "options": {"text": "override"}}
            )
        with self.assertRaises(ValueError):
            HttpTTSProvider("https://fixture.invalid", model="m", voice="v", credential_file=None, options={"artifact_id": "override"})

    def test_tts_json_envelope_budget_is_separate_from_decoded_cap(self):
        audio = b"x" * 24
        provider = HttpTTSProvider("https://fixture.invalid", model="m", voice="v", credential_file=None, max_bytes=32)
        with patch.object(adapters, "_urlopen_no_redirect", return_value=_Response({"audio_base64": base64.b64encode(audio).decode()})):
            result = provider.synthesize("text", artifact_id="artifact")
        self.assertEqual(result.audio, audio)

    def test_provider_chain_passes_remaining_budget_to_http_transport(self):
        provider = HttpASRProvider("https://fixture.invalid", model="m", credential_file=None, timeout=300)
        chain = ProviderChain("asr", [ProviderTarget("one", "asr", "http-asr", provider, timeout_seconds=300)], overall_deadline_seconds=0.05)
        seen: list[float] = []

        def transport(_request, *, timeout):
            seen.append(timeout)
            time.sleep(0.06)
            return _Response({"text": "late"})

        with patch.object(adapters, "_urlopen_no_redirect", side_effect=transport):
            with self.assertRaises(adapters.ChainFailure) as caught:
                chain.execute_asr(b"audio", turn_id="turn")
        self.assertLessEqual(seen[0], 0.05)
        self.assertEqual(caught.exception.kind, "deadline")

    def test_query_base_and_legacy_timeouts_are_bound(self):
        with self.assertRaises(ValueError):
            RecorderConfig(hermes_base_url="https://fixture.invalid?profile=default").validate()
        config = RecorderConfig(
            hermes_base_url="https://fixture.invalid",
            hermes_api_key_file="fixture-reference",
            asr_provider_timeout_seconds=1,
            tts_timeout_seconds=29,
        )
        self.assertEqual(config.asr_providers[0].timeout_seconds, 1)
        self.assertEqual(config.tts_providers[0].timeout_seconds, 29)


class R23DurableFenceTests(unittest.TestCase):
    def test_late_asr_result_does_not_commit_or_delete_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-09-07T00:00:00Z")
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data", clock=clock)

            class LateProvider:
                name = "late"

                def transcribe(self, audio, *, turn_id, generation):
                    del audio, turn_id, generation
                    clock.advance(seconds=301)
                    return AsrResult.valid("late transcript")

            turn = complete_turn(store, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890d2", kind="audio", payload=b"wav")
            service = RecorderService(store, asr_chain=ProviderChain.from_providers("asr", [("late", LateProvider())], overall_deadline_seconds=60))
            service._enqueue_turn_stage(turn)
            result = service.run_background_worker_once(owner="late-worker")
            self.assertIsNotNone(result)
            current = store.get_turn(turn["turn_id"])
            self.assertIsNone(current["transcript"])
            self.assertEqual(current["source_deleted"], 0)
            with store._read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM worker_jobs WHERE stage='route' AND status='PENDING'").fetchone()[0], 0)


class R23FeatureBoundaryTests(unittest.TestCase):
    def test_stopped_expired_eavesdrop_is_not_forwarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-09-07T00:00:00Z")
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data", clock=clock)
            store.register_device("u", "phone", "phone")
            session = store.start_eavesdrop("u", "phone", session_id="expiry-r23", hermes_enabled=True, expires_seconds=1)
            store.activate_eavesdrop(session["session_id"], "u", "phone")
            store.append_eavesdrop_segment(session["session_id"], "u", "phone", sequence=0, client_segment_id="seg", audio=b"pcm", transcript="expired")
            store.stop_eavesdrop(session["session_id"], "u", "phone")
            clock.advance(seconds=2)
            calls: list[object] = []

            class Gateway:
                def submit(self, **kwargs):
                    calls.append(kwargs)
                    return HermesResult("message", "reply", True, "hermes")

                def history(self, **kwargs):
                    return None

                def history_messages(self, **kwargs):
                    return []

            service = RecorderService(store, hermes=Gateway())
            service.run_background_worker_once(owner="expiry-worker")
            self.assertEqual(calls, [])
            self.assertEqual(store.list_eavesdrop_decisions(session["session_id"])[0]["result_state"], "FAILED")

    def test_stopped_eavesdrop_is_not_forwarded_before_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-09-07T00:00:00Z")
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data", clock=clock)
            store.register_device("u", "phone", "phone")
            session = store.start_eavesdrop("u", "phone", session_id="stopped-r23", hermes_enabled=True, expires_seconds=100)
            store.activate_eavesdrop(session["session_id"], "u", "phone")
            store.append_eavesdrop_segment(session["session_id"], "u", "phone", sequence=0, client_segment_id="seg", audio=b"pcm", transcript="stopped")
            store.stop_eavesdrop(session["session_id"], "u", "phone")
            calls: list[object] = []

            class Gateway:
                def submit(self, **kwargs):
                    calls.append(kwargs)
                    return HermesResult("message", "reply", True, "hermes")

                def history(self, **kwargs):
                    return None

                def history_messages(self, **kwargs):
                    return []

            service = RecorderService(store, hermes=Gateway())
            service.run_background_worker_once(owner="stopped-worker")
            self.assertEqual(calls, [])
            decision = store.list_eavesdrop_decisions(session["session_id"])[0]
            self.assertEqual(decision["result_state"], "FAILED")
            self.assertEqual(decision["reason"], "session_inactive")
            with self.assertRaises(ConflictError):
                store.record_eavesdrop_reply(session["session_id"], segment_sequence=0, text="must not persist")

    def test_eavesdrop_reply_is_not_recorded_if_session_expires_during_forward(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = DeterministicClock("2026-09-07T00:00:00Z")
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data", clock=clock)
            store.register_device("u", "phone", "phone")
            session = store.start_eavesdrop("u", "phone", session_id="expiry-during-forward", hermes_enabled=True, expires_seconds=1)
            store.activate_eavesdrop(session["session_id"], "u", "phone")
            store.append_eavesdrop_segment(session["session_id"], "u", "phone", sequence=0, client_segment_id="seg", audio=b"pcm", transcript="request")

            class Gateway:
                def submit(self, **kwargs):
                    del kwargs
                    clock.advance(seconds=2)
                    return HermesResult("message", "late reply", True, "hermes")

                def history(self, **kwargs):
                    del kwargs
                    return None

                def history_messages(self, **kwargs):
                    del kwargs
                    return []

            service = RecorderService(store, hermes=Gateway())
            service.run_background_worker_once(owner="expiry-during-worker")
            self.assertEqual(store.list_eavesdrop_replies(session["session_id"]), [])
            self.assertEqual(store.list_eavesdrop_decisions(session["session_id"])[0]["result_state"], "FAILED")

    def test_diagnostics_export_is_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("u", "phone", "phone")
            store.record_diagnostics_opt_in("u", "phone", event_id="opt")
            for index in range(501):
                store.ingest_diagnostic_event("u", "phone", event_id=f"ev-{index}", idempotency_key=f"key-{index}", payload={"category": "fixture", "stage": "test"})
            exported = store.export_diagnostics("u", "phone")
            self.assertEqual(len(exported["items"]), 501)
            self.assertFalse(exported["truncated"])
            self.assertEqual(exported["next_cursor"], None)
            listed = store.list_diagnostics("u", "phone", limit=500)
            self.assertEqual(len(listed["items"]), 500)
            self.assertTrue(listed["has_more"])


if __name__ == "__main__":
    unittest.main()
