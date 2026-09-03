from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
import zlib
from pathlib import Path

from recorder_next.adapters import AsrResult, ChainFailure, CredentialError, HttpASRProvider, HttpHermesGateway, HttpTTSProvider, MemoryHermesGateway, ProviderChain, ProviderFailure, ProviderTarget, StaticASRProvider, StaticTTSProvider
from recorder_next.config import ProviderConfig, RecorderConfig
from recorder_next.errors import ConflictError, UnauthorizedError
from recorder_next.features import DurableProcessingWorker
from recorder_next.models import HermesResult
from recorder_next.service import RecorderService, create_configured_service
from recorder_next.store import RecorderStore


TURN_ID = "018f5a2e-7b6e-7abc-8d11-1234567890ab"


def complete_turn(store: RecorderStore, *, turn_id: str = TURN_ID, kind: str = "text", payload: bytes = b"hello") -> dict:
    manifest = {
        "schema_version": 1,
        "user_id": "feature-user",
        "turn_id": turn_id,
        "origin_device_id": "feature-phone",
        "client_created_at": "2026-09-03T00:00:00Z",
        "parts": [{
            "part_id": "part-1",
            "kind": kind,
            "mime": "text/plain" if kind == "text" else "application/octet-stream",
            "declared_bytes": len(payload),
            "declared_sha256": hashlib.sha256(payload).hexdigest(),
        }],
    }
    store.create_turn(manifest)
    store.put_chunk(turn_id, "part-1", 0, payload)
    store.finish_part(
        turn_id,
        "part-1",
        total_chunks=1,
        total_bytes=len(payload),
        whole_stream_sha256=hashlib.sha256(payload).hexdigest(),
    )
    return store.accept_turn(turn_id)


class DurableWorkerFeatureTests(unittest.TestCase):
    def test_worker_job_has_idempotency_lease_receipt_and_restart_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            job = store.enqueue_worker_job(
                kind="hermes",
                stage="submit",
                payload={"turn_id": TURN_ID},
                idempotency_key="feature-job-1",
                max_attempts=2,
                now="2026-09-03T00:00:00+00:00",
            )
            same = store.enqueue_worker_job(
                kind="hermes",
                stage="submit",
                payload={"turn_id": TURN_ID},
                idempotency_key="feature-job-1",
                max_attempts=2,
                now="2026-09-03T00:00:00+00:00",
            )
            self.assertEqual(job["job_id"], same["job_id"])
            with self.assertRaises(ConflictError):
                store.enqueue_worker_job(
                    kind="hermes",
                    stage="submit",
                    payload={"turn_id": "different"},
                    idempotency_key="feature-job-1",
                    max_attempts=2,
                    now="2026-09-03T00:00:00+00:00",
                )
            claim = store.claim_worker_job("worker-a", now="2026-09-03T00:00:00+00:00", lease_seconds=5)
            self.assertEqual(claim["status"], "CLAIMED")
            self.assertEqual(claim["attempt_count"], 1)
            recovered = store.recover_worker_jobs(now="2026-09-03T00:00:06+00:00")
            self.assertEqual(recovered["requeued"], 1)
            claim = store.claim_worker_job("worker-b", now="2026-09-03T00:00:06+00:00", lease_seconds=5)
            done = store.complete_worker_job(
                claim["job_id"],
                "worker-b",
                {"effect_id": "hermes-effect-1", "status": "accepted"},
                now="2026-09-03T00:00:07+00:00",
            )
            self.assertEqual(done["status"], "SUCCEEDED")
            self.assertRegex(done["effect_receipt_sha256"], r"^[0-9a-f]{64}$")

    def test_worker_completion_is_idempotent_and_binds_receipt_to_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            job = store.enqueue_worker_job(kind="hermes", stage="submit", payload={"turn_id": TURN_ID}, idempotency_key="receipt-binding", now="2026-09-03T00:00:00+00:00")
            claim = store.claim_worker_job("worker", now="2026-09-03T00:00:00+00:00")
            receipt = {"effect_id": "effect-1", "status": "accepted"}
            first = store.complete_worker_job(claim["job_id"], "worker", receipt, now="2026-09-03T00:00:01+00:00")
            second = store.complete_worker_job(claim["job_id"], "worker", receipt, now="2026-09-03T00:00:02+00:00")
            self.assertEqual(second["status"], "SUCCEEDED")
            self.assertEqual(second["effect_receipt"], first["effect_receipt"])
            self.assertEqual(second["effect_receipt"]["job_id"], job["job_id"])
            self.assertEqual(second["effect_receipt"]["idempotency_key"], "receipt-binding")

    def test_background_worker_runs_route_hermes_and_tts_stages(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            project = store.create_project("feature-user", project_number="P-1", name="Feature")
            complete_turn(store)
            gateway = MemoryHermesGateway()
            service = RecorderService(store, hermes=gateway, tts=StaticTTSProvider(name="injected-test"))
            service.accept_turn(TURN_ID)
            first = service.run_background_worker_once(owner="worker")
            self.assertEqual(first["status"], "SUCCEEDED")
            self.assertEqual(first["stage"], "route")
            with store._read() as conn:
                submission = conn.execute("SELECT hermes_submission_id FROM session_ingress WHERE turn_id=?", (TURN_ID,)).fetchone()[0]
            gateway.responses[submission] = __import__("recorder_next.models", fromlist=["HermesResult"]).HermesResult("assistant-1", "완료")
            second = service.run_background_worker_once(owner="worker")
            self.assertEqual(second["status"], "SUCCEEDED")
            self.assertEqual(second["stage"], "hermes")
            third = service.run_background_worker_once(owner="worker")
            self.assertEqual(third["status"], "SUCCEEDED")
            self.assertEqual(third["stage"], "tts")
            self.assertEqual(len([call for call in gateway.calls if call["kind"] == "submit"]), 1)
            self.assertEqual(store.worker_health()["counts"]["SUCCEEDED"], 3)


class ProviderFeatureTests(unittest.TestCase):
    def test_provider_failures_are_classified_without_exposing_secret(self):
        failure = ProviderFailure("auth", retryable=False, status_code=401)
        self.assertEqual(failure.kind, "auth")
        self.assertFalse(failure.retryable)
        self.assertNotIn("secret", str(failure).lower())

    def test_provider_chain_does_not_fallback_after_permanent_failure(self):
        class Permanent:
            name = "permanent"

            def transcribe(self, audio, *, turn_id, generation):
                raise ProviderFailure("server", retryable=False, status_code=500)

        class ShouldNotRun:
            name = "fallback"

            def __init__(self):
                self.calls = 0

            def transcribe(self, audio, *, turn_id, generation):
                self.calls += 1
                return AsrResult.valid("unexpected")

        fallback = ShouldNotRun()
        chain = ProviderChain("asr", [
            ProviderTarget("primary", "asr", "hermes", Permanent(), declared={"profile": "default"}),
            ProviderTarget("fallback", "asr", "nemotron", fallback, declared={"endpoint": "https://asr.example.invalid", "model": "m"}),
        ])
        with self.assertRaises(ChainFailure) as raised:
            chain.execute_asr(b"audio", turn_id="turn-1")
        self.assertEqual(raised.exception.kind, "server")
        self.assertEqual(fallback.calls, 0)

    def test_http_provider_constructors_are_real_and_not_fixture_adapters(self):
        asr = HttpASRProvider("https://example.invalid/asr", model="whisper-ko", credential_file=None)
        tts = HttpTTSProvider("https://example.invalid/tts", model="korean-tts", voice="ko-KR-1", credential_file=None)
        self.assertEqual(asr.name, "http-asr")
        self.assertEqual(tts.name, "http-tts")
        self.assertEqual(tts.language, "ko-KR")

    def test_configured_service_rejects_fixture_and_defaults_to_explicit_disabled_tts(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self.assertRaises(CredentialError):
                create_configured_service(RecorderConfig(database=str(base / "fixture.sqlite3"), storage_root=str(base / "fixture-data"), tts_provider="fixture"))
            service = create_configured_service(RecorderConfig(database=str(base / "disabled.sqlite3"), storage_root=str(base / "disabled-data")))
            self.assertEqual(service.tts.name, "disabled")

    def test_configured_service_builds_named_asr_and_tts_chains(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = RecorderConfig(
                database=str(base / "named.sqlite3"),
                storage_root=str(base / "named-data"),
                asr_providers=(ProviderConfig("nemotron", "asr", "nemotron", endpoint="https://asr.example.invalid", model="ko"),),
                tts_providers=(ProviderConfig("edge", "tts", "edge", endpoint="https://tts.example.invalid", model="edge", voice="ko-KR-SunHiNeural"),),
                asr_chain=("nemotron",),
                tts_chain=("edge",),
            )
            service = create_configured_service(config)
            self.assertEqual(service.asr_chain.freeze()["targets"][0]["alias"], "nemotron")
            self.assertEqual(service.asr_chain.targets[0].provider.name, "nemotron")
            self.assertEqual(service.tts_chain.targets[0].provider.name, "edge-tts")

    def test_durable_worker_requires_a_receipt_before_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            job = store.enqueue_worker_job(kind="effect", stage="submit", payload={"id": "1"}, idempotency_key="worker-receipt", now="2026-09-03T00:00:00+00:00")
            worker = DurableProcessingWorker(store, owner="worker", handlers={"effect": lambda _job: None})
            failed = worker.run_once(now="2026-09-03T00:00:00+00:00")
            self.assertEqual(failed["status"], "FAILED_PERMANENT")
            self.assertEqual(failed["last_error_kind"], "missing_effect_receipt")

    def test_asr_no_speech_is_authoritative_and_does_not_fallback(self):
        class CountingProvider:
            def __init__(self, result):
                self.result = result
                self.calls = 0

            def transcribe(self, audio, *, turn_id, generation):
                self.calls += 1
                return self.result

        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            complete_turn(store, kind="audio", payload=b"wav")
            realtime = CountingProvider(AsrResult.no_speech())
            batch = CountingProvider(AsrResult.valid("must-not-run"))
            service = RecorderService(store, asr_providers={"realtime": realtime, "batch": batch})
            result = service.run_asr(TURN_ID)
            self.assertEqual(result["authoritative_asr_outcome"], "NO_SPEECH")
            self.assertEqual(realtime.calls, 1)
            self.assertEqual(batch.calls, 0)

    def test_asr_permanent_provider_failure_does_not_fallback(self):
        class FailingProvider:
            def __init__(self):
                self.calls = 0

            def transcribe(self, audio, *, turn_id, generation):
                self.calls += 1
                raise ProviderFailure("auth", retryable=False, status_code=401)

        class CountingProvider:
            def __init__(self):
                self.calls = 0

            def transcribe(self, audio, *, turn_id, generation):
                self.calls += 1
                return AsrResult.valid("must-not-run")

        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            complete_turn(store, kind="audio", payload=b"wav")
            realtime = FailingProvider()
            batch = CountingProvider()
            result = RecorderService(store, asr_providers={"realtime": realtime, "batch": batch}).run_asr(TURN_ID)
            self.assertEqual(result["final_error_kind"], "asr")
            self.assertEqual(realtime.calls, 1)
            self.assertEqual(batch.calls, 0)

    def test_http_attachment_projection_validates_bytes_with_resolver(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self, resolver):
                super().__init__("http://127.0.0.1:9", attachment_resolver=resolver)
                self.seen = None

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.seen = payload
                return {"assistant_message_id": "attachment-check", "content": "ok"}

        digest = hashlib.sha256(b"bytes").hexdigest()
        reference = "recorder://v1/turns/turn-1/parts/part-1?sha256=" + digest
        calls = []

        def resolver(value):
            calls.append(value)
            return {"reference": value, "body": b"bytes", "byte_length": 5, "sha256": digest, "mime": "application/octet-stream"}

        result = ProbeGateway(resolver).submit(
            session_key="project:attachments:default",
            request={
                "input": "",
                "parts": [{
                    "part_id": "part-1",
                    "kind": "attachment",
                    "mime": "application/octet-stream",
                    "declared_bytes": 5,
                    "total_bytes": 5,
                    "whole_stream_sha256": digest,
                    "status": "COMPLETE",
                    "turn_id": "turn-1",
                }],
            },
            submission_id="attachment-check",
            marker="marker",
        )
        self.assertEqual(result.content, "ok")
        self.assertEqual(calls, [reference])

    def test_named_provider_registry_freezes_order_and_redacts_credentials(self):
        config_text = """
[providers]
asr_chain = ["asr:hermes-default", "nemotron"]
tts_chain = ["edge"]
asr_deadline_seconds = 42
tts_deadline_seconds = 21

[providers.asr.hermes-default]
adapter = "hermes"
profile = "default"
credential_file = "secrets/hermes.env"

[providers.asr.nemotron]
adapter = "nemotron"
endpoint = "https://asr.example.invalid/v1/transcribe"
model = "nemotron-ko"
credential_file = "secrets/nemotron.env"
retries = 2

[providers.tts.edge]
adapter = "edge"
endpoint = "https://tts.example.invalid/v1/speak"
model = "edge"
voice = "ko-KR-SunHiNeural"
credential_file = "secrets/edge.env"
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "providers.toml"
            path.write_text(config_text, encoding="utf-8")
            config = RecorderConfig.from_file(path)
            self.assertEqual(config.asr_chain, ("hermes-default", "nemotron"))
            self.assertEqual(config.tts_chain, ("edge",))
            self.assertEqual([item.name for item in config.asr_providers], ["hermes-default", "nemotron"])
            self.assertEqual(config.asr_providers[1].retries, 2)
            safe = config.safe_provider_config()
            self.assertNotIn("credential_file", json.dumps(safe))
            self.assertEqual(config.resolved(base_dir=tmp).tts_providers[0].credential_file, str(Path(tmp) / "secrets/edge.env"))
            self.assertRegex(config.provider_generation, r"^[0-9a-f]{64}$")


class UpdateAndHistoryFeatureTests(unittest.TestCase):
    def test_update_manifest_is_immutable_and_serves_hash_bound_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "candidate.apk"
            artifact.write_bytes(b"0123456789")
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            manifest = store.publish_update_manifest(
                channel="test",
                generation=1,
                platform="phone",
                version="1.2.3",
                version_code=12,
                artifact_name="recorder-phone.apk",
                artifact_path=artifact,
                signer_digest="a" * 64,
                changelog="feature",
                min_server_version="1.0.0",
                authorization_policy="test-only",
            )
            self.assertEqual(manifest["generation"], 1)
            self.assertEqual(manifest["size"], 10)
            served = store.read_update_artifact("test", 1, "recorder-phone.apk", range_header="bytes=2-5")
            self.assertEqual(served["status"], 206)
            self.assertEqual(served["body"], b"2345")
            self.assertEqual(served["headers"]["Content-Range"], "bytes 2-5/10")
            with self.assertRaises(ConflictError):
                store.publish_update_manifest(
                    channel="test",
                    generation=1,
                    platform="phone",
                    version="1.2.4",
                    version_code=13,
                    artifact_name="recorder-phone.apk",
                    artifact_path=artifact,
                    signer_digest="a" * 64,
                    changelog="changed",
                    min_server_version="1.0.0",
                    authorization_policy="test-only",
                )

    def test_history_is_project_scoped_cursor_bound_and_path_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            store.register_device("feature-user", "feature-phone", "phone")
            project = store.create_project("feature-user", project_number="P-1", name="Feature")
            accepted = complete_turn(store)
            history = store.history_read_model("feature-user", project_id=project["stable_project_id"], limit=10)
            self.assertEqual(history["items"], [])
            decision = {
                "route_decision_id": "route-1",
                "project_id": project["stable_project_id"],
                "session_key": project["default_session_key"],
                "project_record_version": 1,
                "routed_text": "hello",
                "decision_reason_code": "fixture",
            }
            store.commit_route(TURN_ID, decision)
            history = store.history_read_model("feature-user", project_id=project["stable_project_id"], limit=1)
            self.assertEqual(len(history["items"]), 1)
            self.assertNotIn("storage_path", json.dumps(history))
            self.assertNotIn("source_path", json.dumps(history))
            self.assertEqual(history["items"][0]["accepted_seq"], accepted["accepted_seq"])


class AttachmentEavesdropDiagnosticsFeatureTests(unittest.TestCase):
    def test_attachment_resolver_rechecks_hash_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            accepted = complete_turn(store, kind="attachment", payload=b"attachment-bytes")
            reference = store.attachment_reference(TURN_ID, "part-1")
            resolved = store.resolve_attachment_reference(reference)
            self.assertEqual(resolved["body"], b"attachment-bytes")
            part = store.get_turn(TURN_ID)["parts"][0]
            Path(part["source_path"]).unlink()
            Path(part["source_path"]).symlink_to(root / "outside")
            with self.assertRaises(UnauthorizedError):
                store.resolve_attachment_reference(reference)
            self.assertEqual(accepted["turn_id"], TURN_ID)

    def test_eavesdrop_states_segments_and_phone_mediated_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            store.register_device("feature-user", "feature-phone", "phone")
            store.register_device("feature-user", "feature-watch", "watch")
            session = store.start_eavesdrop("feature-user", "feature-phone", watch_device_id="feature-watch", response_enabled=True, tts_enabled=False)
            self.assertEqual(session["state"], "CREATED")
            store.activate_eavesdrop(session["session_id"], "feature-user", "feature-phone")
            segment = store.append_eavesdrop_segment(session["session_id"], "feature-user", "feature-phone", sequence=0, client_segment_id="seg-0", audio=b"pcm", transcript="안녕하세요")
            duplicate = store.append_eavesdrop_segment(session["session_id"], "feature-user", "feature-phone", sequence=0, client_segment_id="seg-0", audio=b"pcm", transcript="안녕하세요")
            self.assertFalse(segment["duplicate"])
            self.assertTrue(duplicate["duplicate"])
            current = store.get_eavesdrop_session(session["session_id"])
            self.assertEqual(current["provenance"], "phone_mediated_watch")
            self.assertEqual(current["accumulated_transcript"], "안녕하세요")
            store.pause_eavesdrop(session["session_id"], "feature-user", "feature-phone")
            self.assertEqual(store.get_eavesdrop_session(session["session_id"])["state"], "PAUSED")
            store.resume_eavesdrop(session["session_id"], "feature-user", "feature-phone")
            store.stop_eavesdrop(session["session_id"], "feature-user", "feature-phone")
            self.assertEqual(store.get_eavesdrop_session(session["session_id"])["state"], "STOPPED")

    def test_eavesdrop_queues_fixed_project_hermes_once_and_delivers_reply(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            store.register_device("feature-user", "feature-phone", "phone")
            project = store.create_project("feature-user", project_number="P-E", name="Eavesdrop")
            gateway = MemoryHermesGateway()
            service = RecorderService(store, hermes=gateway)
            session = store.start_eavesdrop("feature-user", "feature-phone", project_id=project["stable_project_id"], hermes_enabled=True, response_enabled=True)
            store.activate_eavesdrop(session["session_id"], "feature-user", "feature-phone")
            appended = store.append_eavesdrop_segment(session["session_id"], "feature-user", "feature-phone", sequence=0, client_segment_id="seg-e", audio=b"pcm", transcript="질문")
            decision = store.list_eavesdrop_decisions(session["session_id"])[0]
            self.assertEqual(decision["decision"], "FORWARD_DEFAULT")
            self.assertEqual(decision["result_state"], "QUEUED")
            gateway.responses[decision["hermes_submission_id"]] = HermesResult("eavesdrop-response", "답변", True, "hermes")
            receipt = service.run_background_worker_once(owner="eavesdrop-worker")
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt["status"], "SUCCEEDED")
            self.assertEqual(gateway.calls[0]["session_key"], f"recorder:eavesdrop:{session['session_id']}")
            self.assertEqual(gateway.calls[0]["request"], {"input": "질문"})
            delivered = store.list_eavesdrop_decisions(session["session_id"])[0]
            self.assertEqual(delivered["decision"], "FORWARD_DEFAULT")
            self.assertEqual(delivered["result_state"], "DELIVERED")
            self.assertEqual(len(store.list_eavesdrop_replies(session["session_id"])), 1)
            self.assertFalse(appended["duplicate"])

    def test_eavesdrop_store_silent_bypasses_router_and_has_zero_external_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            store.register_device("feature-user", "feature-phone", "phone")
            gateway = MemoryHermesGateway()
            service = RecorderService(store, hermes=gateway)
            session = store.start_eavesdrop("feature-user", "feature-phone", hermes_enabled=False, response_enabled=True, tts_enabled=True)
            store.activate_eavesdrop(session["session_id"], "feature-user", "feature-phone")
            store.append_eavesdrop_segment(session["session_id"], "feature-user", "feature-phone", sequence=0, client_segment_id="silent-0", audio=b"pcm", transcript="검색 가능한 참고")
            decision = store.list_eavesdrop_decisions(session["session_id"])[0]
            self.assertEqual(decision["decision"], "STORE_SILENT")
            self.assertEqual(decision["result_state"], "STORED_SILENT")
            self.assertEqual(store.list_worker_jobs(), [])
            self.assertIsNone(service.run_background_worker_once(owner="silent-worker"))
            self.assertEqual(gateway.calls, [])
            self.assertEqual(store.list_eavesdrop_replies(session["session_id"]), [])
            self.assertEqual(store.get_eavesdrop_session(session["session_id"])["accumulated_transcript"], "검색 가능한 참고")

    def test_configured_asr_chain_commits_once_and_replays_authoritative_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            complete_turn(store, turn_id="018f5a2e-7b6e-7abc-8d11-1234567890ac", kind="audio", payload=b"wav")
            provider = StaticASRProvider("static-test", AsrResult.valid("chain transcript"))
            chain = ProviderChain(
                "asr",
                [ProviderTarget("primary", "asr", "fixture", provider, declared={"name": "primary"})],
            )
            service = RecorderService(store, asr_chain=chain)
            first = service.run_asr("018f5a2e-7b6e-7abc-8d11-1234567890ac")
            second = service.run_asr("018f5a2e-7b6e-7abc-8d11-1234567890ac")
            self.assertEqual(first["transcript"], "chain transcript")
            self.assertEqual(second["transcript"], "chain transcript")
            with store._read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM asr_attempts WHERE turn_id=?", ("018f5a2e-7b6e-7abc-8d11-1234567890ac",)).fetchone()[0], 1)

    def test_diagnostics_require_opt_in_redact_and_leave_tombstone_on_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            store.register_device("feature-user", "feature-phone", "phone")
            opt_in = store.record_diagnostics_opt_in("feature-user", "feature-phone", event_id="opt-in-1")
            event = store.ingest_diagnostic_event(
                "feature-user",
                "feature-phone",
                event_id="diag-1",
                idempotency_key="diag-1",
                payload={"category": "voice", "stage": "upload", "duration_ms": 12, "token": "must-not-store"},
            )
            self.assertNotIn("token", json.dumps(event))
            raw = json.dumps({"events": [{"category": "voice", "stage": "upload", "status": "ok"}]}).encode()
            bundle = zlib.compress(raw)
            stored = store.ingest_diagnostic_bundle("feature-user", "feature-phone", "bundle-1", bundle, opt_in_event_id=opt_in["event_id"], expanded_size=len(raw))
            self.assertEqual(stored["expanded_size"], len(raw))
            secret_raw = json.dumps({"events": [{"category": "voice", "stage": "upload", "token": "super-secret", "transcript": "private words"}]}).encode()
            secret_bundle = store.ingest_diagnostic_bundle("feature-user", "feature-phone", "bundle-2", zlib.compress(secret_raw), opt_in_event_id=opt_in["event_id"], expanded_size=len(secret_raw))
            secret_path = next(Path(tmp).rglob("bundle-2.z"))
            stored_secret = zlib.decompress(secret_path.read_bytes())
            self.assertNotIn(b"super-secret", stored_secret)
            self.assertNotIn(b"private words", stored_secret)
            exported = store.export_diagnostics("feature-user", "feature-phone")
            self.assertNotIn("storage_path", json.dumps(exported))
            http_status, _, http_export = RecorderService(store).handle_http("GET", "/v1/diagnostics/export?user_id=feature-user&device_id=feature-phone", {}, b"")
            self.assertEqual(http_status, 200)
            self.assertEqual(http_export["schema_version"], 1)
            deleted = store.delete_diagnostics("feature-user", "feature-phone")
            self.assertEqual(deleted["tombstones"], 3)
            self.assertEqual(store.list_diagnostics("feature-user", "feature-phone")["items"], [])

    def test_diagnostics_latest_opt_out_revokes_older_consent(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            store.register_device("feature-user", "feature-phone", "phone")
            store.record_diagnostics_opt_in("feature-user", "feature-phone", event_id="opt-in-old", now="2026-09-03T00:00:00Z")
            store.record_diagnostics_opt_in("feature-user", "feature-phone", event_id="opt-out-new", enabled=False, now="2026-09-03T00:00:01Z")
            with self.assertRaises(UnauthorizedError):
                store.ingest_diagnostic_event("feature-user", "feature-phone", event_id="diag-revoked", idempotency_key="diag-revoked", payload={"category": "voice", "stage": "upload"}, now="2026-09-03T00:00:02Z")


if __name__ == "__main__":
    unittest.main()
