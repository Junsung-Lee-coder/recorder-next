from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from recorder_next.adapters import ChainFailure, HermesAudioASRProvider, HttpASRProvider, HttpHermesGateway, MemoryHermesGateway, ProviderChain, ProviderFailure, ProviderTarget, StaticASRProvider, StaticTTSProvider
from recorder_next.config import ProviderConfig, RecorderConfig
from recorder_next.errors import ConflictError, UnauthorizedError, ValidationError
from recorder_next.models import AsrResult, HermesResult, TTSResult
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


class OwnerCorrectionTests(unittest.TestCase):
    def test_restart_migrates_partial_eavesdrop_decision_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "legacy.sqlite3"
            conn = sqlite3.connect(db_path)
            try:
                conn.executescript(
                    """
                    CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO schema_meta(key, value) VALUES ('schema_version', '3');
                    CREATE TABLE eavesdrop_sessions (
                        session_id TEXT PRIMARY KEY,
                        state TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    );
                    CREATE TABLE eavesdrop_decisions (
                        decision_id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        segment_sequence INTEGER NOT NULL,
                        decision TEXT NOT NULL,
                        reason TEXT NOT NULL
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()
            store = RecorderStore(db_path, storage_root=root / "data")
            with store._read() as read_conn:
                columns = {row["name"] for row in read_conn.execute("PRAGMA table_info(eavesdrop_decisions)")}
                version = read_conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]
            self.assertTrue({"policy_version", "covered_start_sequence", "covered_end_sequence", "dedupe_key", "result_state", "effect_receipt_json"}.issubset(columns))
            self.assertEqual(version, "4")

    def test_config_defaults_to_declared_hermes_and_does_not_auto_discover_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_file = root / "hermes.env"
            config_file = root / "hermes.toml"
            config_file.write_text(
                """
[providers]
hermes_base_url = "http://127.0.0.1:8642"
hermes_api_key_file = "hermes.env"
""",
                encoding="utf-8",
            )
            config = RecorderConfig.from_file(config_file)
            self.assertEqual(config.asr_chain, ("hermes-default",))
            self.assertEqual(config.tts_chain, ("hermes-default",))
            self.assertEqual(config.asr_providers[0].profile, "default")
            self.assertEqual(config.tts_providers[0].adapter, "hermes")

            no_chain = root / "no-chain.toml"
            no_chain.write_text(
                """
[providers.asr.nemotron]
adapter = "nemotron"
endpoint = "http://127.0.0.1:5110/transcribe"
model = "nemotron"

[providers.tts.edge]
adapter = "edge"
endpoint = "http://127.0.0.1:5111/speak"
model = "edge"
voice = "ko-KR-SunHiNeural"
""",
                encoding="utf-8",
            )
            no_chain_config = RecorderConfig.from_file(no_chain)
            self.assertEqual(no_chain_config.asr_chain, ())
            self.assertEqual(no_chain_config.tts_chain, ())

    def test_scoped_provider_override_can_be_selected_without_leaking_secrets(self):
        config = RecorderConfig(
            asr_providers=(
                ProviderConfig("primary", "asr", "nemotron", endpoint="http://127.0.0.1:5110", model="n"),
                ProviderConfig("project", "asr", "whisper-compatible", endpoint="http://127.0.0.1:5111", model="w"),
            ),
            asr_chain=("primary",),
            asr_overrides=(("project:P-1", ("project",)),),
        )
        self.assertEqual(config.provider_chain_names("asr"), ("primary",))
        self.assertEqual(config.provider_chain_names("asr", "project:P-1"), ("project",))
        self.assertNotIn("127.0.0.1:5110", str(config.safe_provider_config().get("credential_file", "")))

    def test_provider_configuration_rejects_non_string_endpoint_and_bad_retry_types(self):
        with self.assertRaises(ValueError):
            ProviderConfig.from_spec("bad-endpoint", "asr", {"kind": "asr", "adapter": "hermes", "endpoint": 123})
        with self.assertRaises(ValueError):
            ProviderConfig("bad-retries", "asr", "hermes", retries=True).safe_dict()

    def test_provider_target_does_not_persist_secret_like_option_names(self):
        target = ProviderTarget(
            alias="target",
            kind="asr",
            source="hermes",
            provider=object(),
            declared={"options": {"api_key_hash": "opaque"}},
        )
        with self.assertRaises(ValueError):
            target.safe_config()

    def test_http_hermes_refuses_local_attachment_references_without_a_resolver(self):
        gateway = HttpHermesGateway("http://127.0.0.1:8642")
        gateway._request = lambda *args, **kwargs: {"content": "unexpected"}
        with self.assertRaises(ValueError):
            gateway.submit(
                session_key="recorder:project:P-1",
                request={
                    "request": {
                        "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890ab",
                        "input": "inspect",
                        "parts": [{
                            "part_id": "file-1",
                            "kind": "attachment",
                            "mime": "application/octet-stream",
                            "status": "COMPLETE",
                            "declared_bytes": 3,
                            "declared_sha256": "a" * 64,
                        }],
                    }
                },
                submission_id="submission-1",
                marker="marker-1",
            )

    def test_tts_ready_receipt_prevents_reinvocation_and_invalid_mime_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            project = store.create_project("user", project_number="P-1", name="Project")
            payload = b"hello"
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ad"
            manifest = {
                "schema_version": 1,
                "user_id": "user",
                "turn_id": turn_id,
                "origin_device_id": "phone",
                "current_project_number": "P-1",
                "client_created_at": "2026-09-03T00:00:00Z",
                "parts": [{
                    "part_id": "text-1",
                    "kind": "text",
                    "mime": "text/plain",
                    "declared_bytes": len(payload),
                    "declared_sha256": hashlib.sha256(payload).hexdigest(),
                }],
            }
            store.create_turn(manifest)
            store.put_chunk(turn_id, "text-1", 0, payload)
            store.finish_part(turn_id, "text-1", total_chunks=1, total_bytes=len(payload), whole_stream_sha256=hashlib.sha256(payload).hexdigest())
            gateway = MemoryHermesGateway()
            service = RecorderService(store, hermes=gateway)
            service.accept_turn(turn_id)
            routed = service.route_next("user")
            self.assertEqual(routed["project_id"], project["stable_project_id"])
            with store._read() as conn:
                ingress = conn.execute("SELECT * FROM session_ingress WHERE turn_id=?", (turn_id,)).fetchone()
            gateway.responses[ingress["hermes_submission_id"]] = HermesResult("msg", "답변")
            service.process_next_hermes(project["stable_project_id"])
            artifact = store.pending_tts(limit=1)[0]

            class CountingTTS(StaticTTSProvider):
                def __init__(self):
                    super().__init__(name="counting")
                    self.calls = 0

                def synthesize(self, text: str, *, artifact_id: str) -> TTSResult:
                    self.calls += 1
                    return super().synthesize(text, artifact_id=artifact_id)

            provider = CountingTTS()
            service = RecorderService(store, tts=provider)
            first = service.generate_tts(artifact["artifact_id"])
            second = service.generate_tts(artifact["artifact_id"])
            self.assertEqual(first["status"], "READY")
            self.assertEqual(second["status"], "READY")
            self.assertEqual(provider.calls, 1)
            with self.assertRaises(ValidationError):
                store.set_tts_result(artifact["artifact_id"], TTSResult(b"audio", content_type="text/plain"))

    def test_eavesdrop_agent_receives_accumulated_text_and_silent_reply_has_no_side_effect(self):
        class InspectingAgent:
            policy_version = "inspect-v1"

            def __init__(self):
                self.seen = []

            def decide(self, *, session, segment, accumulated_transcript):
                self.seen.append((segment["sequence"], accumulated_transcript))
                return {"outcome": "STORE_SILENT", "reason": "silent_policy", "policy_version": self.policy_version}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            agent = InspectingAgent()
            RecorderService(store, eavesdrop_agent=agent)
            session = store.start_eavesdrop("user", "phone", response_enabled=True, tts_enabled=True, hermes_enabled=True)
            store.activate_eavesdrop(session["session_id"], "user", "phone")
            store.append_eavesdrop_segment(
                session["session_id"], "user", "phone", sequence=0, client_segment_id="seg-0", audio=b"pcm", transcript="첫 문장", reply_text="fake reply"
            )
            self.assertEqual(agent.seen, [(0, "첫 문장")])
            decision = store.list_eavesdrop_decisions(session["session_id"])[0]
            self.assertEqual(decision["result_state"], "STORED_SILENT")
            self.assertEqual(decision["gateway_profile"], "default")
            self.assertEqual(store.list_eavesdrop_replies(session["session_id"]), [])

    def test_eavesdrop_forward_uses_accumulated_conversation_and_default_profile_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            gateway = MemoryHermesGateway()
            RecorderService(store, hermes=gateway)
            session = store.start_eavesdrop("user", "phone", hermes_enabled=True, response_enabled=False)
            store.activate_eavesdrop(session["session_id"], "user", "phone")
            store.append_eavesdrop_segment(session["session_id"], "user", "phone", sequence=0, client_segment_id="seg-0", audio=b"a", transcript="첫 문장")
            store.append_eavesdrop_segment(session["session_id"], "user", "phone", sequence=1, client_segment_id="seg-1", audio=b"b", transcript="둘째 문장")
            decisions = store.list_eavesdrop_decisions(session["session_id"])
            for decision in decisions:
                gateway.responses[decision["hermes_submission_id"]] = HermesResult("msg-" + str(decision["segment_sequence"]), "ok")
            service = RecorderService(store, hermes=gateway)
            service.run_background_worker_once(owner="worker")
            service.run_background_worker_once(owner="worker")
            self.assertEqual(gateway.calls[1]["request"], {"input": "첫 문장\n둘째 문장"})
            self.assertEqual(gateway.calls[1]["marker"], f"eavesdrop:default:{session['session_id']}:1")

    def test_eavesdrop_hermes_disabled_overrides_a_forwarding_agent(self):
        class UnsafeForwardingAgent:
            policy_version = "unsafe-forward-v1"

            def decide(self, *, session, segment, accumulated_transcript):
                return {"outcome": "FORWARD_DEFAULT", "reason": "agent_forward", "policy_version": self.policy_version}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            agent = UnsafeForwardingAgent()
            RecorderService(store, eavesdrop_agent=agent)
            session = store.start_eavesdrop("user", "phone", hermes_enabled=False)
            store.activate_eavesdrop(session["session_id"], "user", "phone")
            store.append_eavesdrop_segment(
                session["session_id"],
                "user",
                "phone",
                sequence=0,
                client_segment_id="silent-segment",
                audio=b"pcm",
                transcript="must remain local",
            )
            decision = store.list_eavesdrop_decisions(session["session_id"])[0]
            self.assertEqual(decision["decision"], "STORE_SILENT")
            self.assertEqual(decision["result_state"], "STORED_SILENT")
            self.assertEqual(store.worker_health()["counts"]["PENDING"], 0)

    def test_eavesdrop_idempotency_rejects_changed_owner_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            store.start_eavesdrop("user", "phone", idempotency_key="same-request", response_enabled=True)
            with self.assertRaises(ConflictError):
                store.start_eavesdrop("user", "phone", idempotency_key="same-request", response_enabled=False)

    def test_audio_worker_advances_to_router_after_committing_asr(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            store.create_project("user", project_number="P-1", name="Project")
            audio = b"wav-bytes"
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ae"
            manifest = {
                "schema_version": 1,
                "user_id": "user",
                "turn_id": turn_id,
                "origin_device_id": "phone",
                "current_project_number": "P-1",
                "client_created_at": "2026-09-03T00:00:00Z",
                "parts": [{
                    "part_id": "audio-1",
                    "kind": "audio",
                    "mime": "audio/wav",
                    "declared_bytes": len(audio),
                    "declared_sha256": hashlib.sha256(audio).hexdigest(),
                }],
            }
            store.create_turn(manifest)
            store.put_chunk(turn_id, "audio-1", 0, audio)
            store.finish_part(turn_id, "audio-1", total_chunks=1, total_bytes=len(audio), whole_stream_sha256=hashlib.sha256(audio).hexdigest())
            service = RecorderService(store, asr_providers={"realtime": StaticASRProvider("realtime", AsrResult.valid("transcribed"))})
            service.accept_turn(turn_id)
            completed = service.run_background_worker_once(owner="worker")
            self.assertEqual(completed["status"], "SUCCEEDED")
            next_job = store.claim_worker_job("router")
            self.assertIsNotNone(next_job)
            assert next_job is not None
            self.assertEqual(next_job["stage"], "route")

    def test_provider_unavailable_allows_the_next_declared_chain_target(self):
        class Unavailable:
            def __init__(self):
                self.calls = 0

            def transcribe(self, audio, *, turn_id, generation):
                self.calls += 1
                raise ProviderFailure("unavailable", retryable=False)

        first = Unavailable()
        second = StaticASRProvider("second", AsrResult.valid("fallback"))
        chain = ProviderChain(
            "asr",
            [
                ProviderTarget("first", "asr", "first", first, declared={"endpoint": "http://127.0.0.1:1", "model": "first"}),
                ProviderTarget("second", "asr", "second", second, declared={"endpoint": "http://127.0.0.1:2", "model": "second"}),
            ],
        )
        result = chain.execute_asr(b"audio", turn_id="turn")
        self.assertEqual(result.transcript, "fallback")
        self.assertEqual(first.calls, 1)

    def test_provider_chain_rejects_a_blank_transcript_as_malformed_success(self):
        blank = StaticASRProvider("blank", AsrResult("VALID_TRANSCRIPT", transcript=""))
        chain = ProviderChain(
            "asr",
            [ProviderTarget("blank", "asr", "blank", blank, declared={"endpoint": "http://127.0.0.1:1", "model": "blank"})],
        )
        with self.assertRaises(ChainFailure) as context:
            chain.execute_asr(b"audio", turn_id="turn")
        self.assertEqual(context.exception.kind, "malformed_success")

    def test_provider_chain_rejects_an_incomplete_audio_mime(self):
        bad = StaticTTSProvider()
        bad_result = TTSResult(b"audio", content_type="audio/")

        class BadTTS(StaticTTSProvider):
            def synthesize(self, text, *, artifact_id):
                return bad_result

        chain = ProviderChain(
            "tts",
            [ProviderTarget("bad", "tts", "bad", BadTTS(), declared={"endpoint": "http://127.0.0.1:1", "model": "m", "voice": "v"})],
        )
        with self.assertRaises(ChainFailure) as context:
            chain.execute_tts("text", artifact_id="artifact")
        self.assertEqual(context.exception.kind, "integrity_invalid")

    def test_eavesdrop_segment_route_path_accepts_the_openapi_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            service = RecorderService(store)
            session = store.start_eavesdrop("user", "phone", hermes_enabled=False)
            store.activate_eavesdrop(session["session_id"], "user", "phone")
            store.append_eavesdrop_segment(session["session_id"], "user", "phone", sequence=0, client_segment_id="seg", audio=b"pcm", transcript="text")
            status, _, payload = service.handle_http(
                "POST",
                f"/v1/eavesdrop/{session['session_id']}/segments/0/route",
                {"Content-Type": "application/json"},
                json.dumps({"user_id": "user", "phone_device_id": "phone"}).encode("utf-8"),
            )
            self.assertEqual(status, 200)
            self.assertEqual(payload["result_state"], "STORED_SILENT")

    def test_hermes_asr_projects_nested_provider_metadata(self):
        class ProbeHermesASR(HermesAudioASRProvider):
            def _request(self, payload, *, max_response_bytes=None):
                return "application/json", json.dumps({"result": {"text": "ok", "provider": "nested"}}).encode("utf-8")

        result = ProbeHermesASR("http://127.0.0.1:8642", credential_file=None).transcribe(b"audio", turn_id="turn", generation=1)
        self.assertEqual(result.metadata["provider"], "nested")

    def test_attachment_reference_rejects_unbound_query_parameters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            payload = b"document"
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890af"
            manifest = {
                "schema_version": 1,
                "user_id": "user",
                "turn_id": turn_id,
                "origin_device_id": "phone",
                "client_created_at": "2026-09-03T00:00:00Z",
                "parts": [{
                    "part_id": "document-1",
                    "kind": "document",
                    "mime": "application/pdf",
                    "declared_bytes": len(payload),
                    "declared_sha256": hashlib.sha256(payload).hexdigest(),
                }],
            }
            store.create_turn(manifest)
            store.put_chunk(turn_id, "document-1", 0, payload)
            store.finish_part(turn_id, "document-1", total_chunks=1, total_bytes=len(payload), whole_stream_sha256=hashlib.sha256(payload).hexdigest())
            reference = store.attachment_reference(turn_id, "document-1")
            with self.assertRaises(UnauthorizedError):
                store.resolve_attachment_reference(reference + "&extra=1")

    def test_update_manifest_hash_binds_channel_and_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            published = store.publish_update_manifest(
                channel="test",
                generation=1,
                platform="phone",
                version="1.0.0",
                version_code=1,
                artifact_name="candidate.apk",
                artifact_bytes=b"apk",
                signer_digest="a" * 64,
                changelog="change",
                min_server_version="1.0.0",
                authorization_policy="test-only",
            )
            with store._read() as conn:
                row = conn.execute("SELECT manifest_json, manifest_sha256 FROM update_manifests WHERE channel=? AND generation=?", ("test", 1)).fetchone()
            self.assertIsNotNone(row)
            assert row is not None
            stored = json.loads(row["manifest_json"])
            self.assertEqual(stored["channel"], "test")
            self.assertEqual(stored["generation"], 1)
            from recorder_next.canonical import sha256_json
            self.assertEqual(row["manifest_sha256"], sha256_json(stored))
            self.assertEqual(published["manifest_sha256"], row["manifest_sha256"])
            with self.assertRaises(ConflictError):
                store.publish_update_manifest(
                    channel="test",
                    generation=2,
                    platform="phone",
                    version="1.1.0",
                    version_code=2,
                    artifact_name="candidate.apk",
                    artifact_bytes=b"apk-2",
                    signer_digest="b" * 64,
                    changelog="change-2",
                    min_server_version="1.0.0",
                    authorization_policy="test-only",
                )

    def test_http_manifest_honors_if_none_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            published = store.publish_update_manifest(
                channel="test",
                generation=1,
                platform="phone",
                version="1.0.0",
                version_code=1,
                artifact_name="candidate.apk",
                artifact_bytes=b"apk",
                signer_digest="a" * 64,
                changelog="change",
                min_server_version="1.0.0",
                authorization_policy="test-only",
            )
            service = RecorderService(store)
            status, _, body = service.handle_http("GET", "/v1/updates/test/manifest", {"If-None-Match": published["etag"]}, b"")
            self.assertEqual(status, 304)
            self.assertEqual(body, b"")

    def test_http_diagnostics_delete_requires_owner_and_supports_delete_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            service = RecorderService(store)
            store.record_diagnostics_opt_in("user", "phone", event_id="opt-in")
            store.ingest_diagnostic_event("user", "phone", event_id="event", idempotency_key="event", payload={"category": "voice", "stage": "upload"})
            status, _, _ = service.handle_http("GET", "/v1/eavesdrop/missing", {}, b"")
            self.assertNotEqual(status, 200)
            status, _, deleted = service.handle_http(
                "DELETE", "/v1/diagnostics", {"Content-Type": "application/json"},
                b'{"user_id":"user","device_id":"phone"}',
            )
            self.assertEqual(status, 200)
            self.assertEqual(deleted["events"], 1)

    def test_http_missing_required_query_is_a_bounded_client_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            status, _, _ = service.handle_http("GET", "/v1/history", {}, b"")
            self.assertEqual(status, 400)

    def test_http_does_not_coerce_eavesdrop_identity_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            status, _, _ = service.handle_http(
                "POST", "/v1/eavesdrop", {"Content-Type": "application/json"},
                b'{"user_id":7,"phone_device_id":"phone"}',
            )
            self.assertEqual(status, 400)

    def test_worker_receipts_reject_private_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            job = store.enqueue_worker_job(
                kind="effect",
                stage="submit",
                payload={"id": "1"},
                idempotency_key="private-receipt",
                now="2026-09-03T00:00:00+00:00",
            )
            claim = store.claim_worker_job("worker", now="2026-09-03T00:00:01+00:00")
            self.assertIsNotNone(claim)
            with self.assertRaises(ValidationError):
                store.complete_worker_job(
                    job["job_id"],
                    "worker",
                    {"effect_id": "effect-1", "status": "accepted", "transcript": "private"},
                    now="2026-09-03T00:00:02+00:00",
                )

    def test_claim_takeover_closes_the_expired_attempt_before_reclaiming(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            job = store.enqueue_worker_job(kind="effect", stage="submit", payload={"id": "1"}, idempotency_key="takeover", now="2026-09-03T00:00:00+00:00")
            first = store.claim_worker_job("worker-a", now="2026-09-03T00:00:00+00:00", lease_seconds=1)
            self.assertIsNotNone(first)
            second = store.claim_worker_job("worker-b", now="2026-09-03T00:00:02+00:00", lease_seconds=1)
            self.assertIsNotNone(second)
            with store._read() as conn:
                attempts = conn.execute("SELECT attempt_number, outcome FROM worker_attempts WHERE job_id=? ORDER BY attempt_number", (job["job_id"],)).fetchall()
            self.assertEqual([(row["attempt_number"], row["outcome"]) for row in attempts], [(1, "RECLAIMED"), (2, "RUNNING")])

    def test_forward_branch_uses_remote_reply_not_client_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("u1", "phone-1", "phone")
            gateway = MemoryHermesGateway()
            service = RecorderService(store, hermes=gateway)
            store.start_eavesdrop("u1", "phone-1", session_id="es-forward", hermes_enabled=True, response_enabled=True, now="2026-09-03T00:00:00Z")
            store.activate_eavesdrop("es-forward", "u1", "phone-1", now="2026-09-03T00:00:00Z")
            store.append_eavesdrop_segment(
                "es-forward", "u1", "phone-1", sequence=0, client_segment_id="seg-1", audio=b"audio", transcript="질문", reply_text="forged", now="2026-09-03T00:00:01Z",
            )
            decision = store.list_eavesdrop_decisions("es-forward", user_id="u1", phone_device_id="phone-1")[0]
            gateway.responses[decision["hermes_submission_id"]] = HermesResult(assistant_message_id="assistant-1", content="real reply", terminal=True)
            service.run_background_worker_once(owner="worker-1", now="2026-09-03T00:00:01Z")
            replies = store.list_eavesdrop_replies("es-forward", user_id="u1", phone_device_id="phone-1")
            self.assertEqual([item["text"] for item in replies], ["real reply"])

    def test_expired_eavesdrop_queue_is_terminalized_without_forwarding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("user", "phone", "phone")
            gateway = MemoryHermesGateway()
            service = RecorderService(store, hermes=gateway)
            session = store.start_eavesdrop("user", "phone", session_id="expired-eavesdrop", hermes_enabled=True, now="2020-01-01T00:00:00Z")
            store.activate_eavesdrop("expired-eavesdrop", "user", "phone", now="2020-01-01T00:00:00Z")
            store.append_eavesdrop_segment("expired-eavesdrop", "user", "phone", sequence=0, client_segment_id="seg", audio=b"pcm", transcript="질문", now="2020-01-01T00:00:00Z")
            result = service.process_eavesdrop_segment("expired-eavesdrop", 0)
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result["state"], "FAILED")
            self.assertEqual(gateway.calls, [])

    def test_eavesdrop_receipts_reject_boolean_sequence_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            with self.assertRaises(ValidationError):
                store.record_eavesdrop_reply("session", segment_sequence=True, text="reply")
            with self.assertRaises(ValidationError):
                store.mark_eavesdrop_decision("session", True, result_state="FAILED", reason="test")

    def test_provider_exposes_safe_health_and_capability_probe_seams(self):
        provider = HttpASRProvider(
            "http://127.0.0.1:5110/transcribe",
            model="whisper",
            credential_file=None,
            health_path="/health",
            capability_path="/capabilities",
        )
        self.assertEqual(provider.health_path, "/health")
        self.assertEqual(provider.capability_path, "/capabilities")
        self.assertTrue(callable(provider.health_check))
        self.assertTrue(callable(provider.capability_check))


if __name__ == "__main__":
    unittest.main()
