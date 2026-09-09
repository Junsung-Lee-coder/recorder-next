from __future__ import annotations

import io
import json
import struct
import unittest
import wave
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from recorder_next.diagnostics_contract import MetadataValidationError, project_metadata
from recorder_next.hermes_wire import (
    GatewayRequestTooLarge,
    WirePolicy,
    estimate_run_body_upper_bound,
    serialize_json,
)
from recorder_next.ingress_contract import ManifestValidationError, validate_turn_manifest
from recorder_next.media import ASRInput, MediaValidationError, validate_wav
from recorder_next.errors import ConflictError, UnauthorizedError
from recorder_next.models import AsrResult, HermesResult
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore
from recorder_next.adapters import WhisperASRProvider


class R25IngressContractTests(unittest.TestCase):
    def test_manifest_is_closed_and_does_not_coerce_types(self):
        digest = "a" * 64
        manifest = {
            "schema_version": 1,
            "user_id": "fixture-user",
            "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890ab",
            "origin_device_id": "fixture-phone",
            "client_created_at": "2026-09-09T00:00:00Z",
            "parts": [
                {
                    "part_id": "image-1",
                    "kind": "image",
                    "mime": "image/png",
                    "declared_bytes": 3,
                    "declared_sha256": digest,
                }
            ],
        }
        validated = validate_turn_manifest(manifest)
        self.assertEqual(validated["prefer_current_project"], False)
        self.assertEqual(validated["parts"][0]["declared_bytes"], 3)
        for bad in (
            {**manifest, "schema_version": True},
            {**manifest, "unknown": 1},
            {**manifest, "parts": [{**manifest["parts"][0], "streaming": "false"}]},
            {**manifest, "parts": [{**manifest["parts"][0], "kind": "document", "mime": "application/pdf"}]},
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ManifestValidationError):
                    validate_turn_manifest(bad)

    def test_text_shortcut_is_validated_before_synthesis(self):
        validated = validate_turn_manifest(
            {
                "schema_version": 1,
                "user_id": "fixture-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890ac",
                "origin_device_id": "fixture-phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "text": "안녕하세요",
            }
        )
        self.assertEqual(validated["parts"][0]["kind"], "text")
        self.assertEqual(validated["parts"][0]["mime"], "text/plain")
        with self.assertRaises(ManifestValidationError):
            validate_turn_manifest(
                {
                    "schema_version": 1,
                    "user_id": "fixture-user",
                    "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890ad",
                    "origin_device_id": "fixture-phone",
                    "client_created_at": "2026-09-09T00:00:00Z",
                    "text": "ok",
                    "parts": [{"part_id": "x", "kind": "text", "mime": "text/plain"}],
                }
            )


class R25MediaContractTests(unittest.TestCase):
    @staticmethod
    def wav(*, samples: bytes = b"\x00\x00\x01\x00", list_chunk: bytes | None = b"fixture") -> bytes:
        output = io.BytesIO()
        with wave.open(output, "wb") as writer:
            writer.setnchannels(1)
            writer.setsampwidth(2)
            writer.setframerate(16000)
            writer.writeframes(samples)
        data = output.getvalue()
        if list_chunk is None:
            return data
        payload = b"LIST" + struct.pack("<I", len(list_chunk)) + list_chunk
        if len(list_chunk) & 1:
            payload += b"\x00"
        return data[:4] + struct.pack("<I", len(data) - 8 + len(payload)) + data[8:]

    def test_canonical_wav_returns_immutable_asr_input_and_rejects_concat(self):
        raw = self.wav(list_chunk=None)
        value = validate_wav(raw, part_id="audio-1", mime="audio/wav")
        self.assertIsInstance(value, ASRInput)
        self.assertEqual(value.sample_rate, 16000)
        self.assertEqual(value.channels, 1)
        self.assertEqual(value.sample_width, 2)
        self.assertEqual(value.frame_count, 2)
        with self.assertRaises(MediaValidationError):
            validate_wav(raw + raw, part_id="audio-1", mime="audio/wav")
        with self.assertRaises(MediaValidationError):
            validate_wav(raw, part_id="audio-1", mime="audio/mpeg")


class R25ProviderWireTests(unittest.TestCase):
    def test_whisper_alias_uses_real_multipart_transcription_wire(self):
        seen: dict[str, object] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                seen["path"] = self.path
                seen["content_type"] = self.headers.get("Content-Type")
                length = int(self.headers["Content-Length"])
                seen["body"] = self.rfile.read(length)
                payload = b'{"text":"wire-ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            raw = R25MediaContractTests.wav(list_chunk=None)
            value = validate_wav(raw, part_id="audio-1", mime="audio/wav")
            provider = WhisperASRProvider(f"http://127.0.0.1:{server.server_port}/v1/audio/transcriptions", model="fixture", credential_file=None)
            result = provider.transcribe(value, turn_id="turn", generation=1)
            self.assertEqual(result.transcript, "wire-ok")
            self.assertEqual(seen["path"], "/v1/audio/transcriptions")
            content_type = str(seen["content_type"])
            self.assertTrue(content_type.startswith("multipart/form-data; boundary="))
            body = bytes(seen["body"])
            self.assertIn(b'name="file"; filename="audio.wav"', body)
            self.assertIn(b'name="model"', body)
            self.assertNotIn(b"audio_base64", body)
            self.assertIn(raw, body)
        finally:
            server.shutdown()
            thread.join(timeout=2)


class R25WireContractTests(unittest.TestCase):
    def test_serializer_is_single_canonical_utf8_and_budget_is_conservative(self):
        body = {"input": [{"type": "input_text", "text": "따옴표 \\\""}], "session": "fixture"}
        encoded = serialize_json(body)
        self.assertEqual(encoded, json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
        policy = WirePolicy(gateway_max_request_bytes=512)
        bound = estimate_run_body_upper_bound(body, text_reserve=32, session_reserve=16)
        self.assertGreaterEqual(bound, len(encoded))
        with self.assertRaises(GatewayRequestTooLarge):
            policy.ensure_size(b"x" * 513)


class R25DiagnosticsContractTests(unittest.TestCase):
    def test_metadata_is_finite_flat_and_drops_sensitive_or_free_text_values(self):
        value = project_metadata(
            {
                "category": "voice",
                "stage": "asr",
                "status": "ok",
                "reason": "patient_Alice_diagnosis_cancer",
                "event_type": "completed",
                "source": "phone",
                "platform": "android",
                "code": 200,
                "duration_ms": 7,
                "count": True,
                "turn_id": "sentinel-turn",
                "metadata": {"name": "Alice"},
            }
        )
        self.assertEqual(value["reason"], "other")
        self.assertNotIn("turn_id", value)
        self.assertNotIn("metadata", value)
        self.assertNotIn("count", value)
        with self.assertRaises(MetadataValidationError):
            project_metadata({"category": "voice"})
        with self.assertRaises(MetadataValidationError):
            project_metadata({"category": "voice", "stage": "asr", "duration_ms": float("nan")})


class R25StoreAuthorityTests(unittest.TestCase):
    def test_revoked_identity_cannot_be_reactivated_by_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("fixture-user", "fixture-phone", "phone")
            store.revoke_device("fixture-user", "fixture-phone", actor_device_id="fixture-phone")
            before = store.get_device("fixture-user", "fixture-phone")
            with self.assertRaises(UnauthorizedError):
                store.register_device("fixture-user", "fixture-phone", "phone")
            self.assertEqual(before, store.get_device("fixture-user", "fixture-phone"))

    def test_direct_create_validates_before_any_turn_rows_and_accepts_corrected_same_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            bad = {
                "schema_version": 1,
                "user_id": "fixture-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890ae",
                "origin_device_id": "fixture-phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [{"part_id": "text-1", "kind": "text", "mime": "text/plain", "streaming": "false"}],
            }
            with self.assertRaises(Exception):
                store.create_turn(bad)
            with store._read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM turns").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM turn_parts").fetchone()[0], 0)
            good = dict(bad)
            good["parts"] = [{"part_id": "text-1", "kind": "text", "mime": "text/plain", "declared_bytes": 2}]
            created = store.create_turn(good)
            self.assertEqual(created["turn_id"], good["turn_id"])
            self.assertEqual(store.create_turn(dict(good))["initial_fingerprint"], created["initial_fingerprint"])

    def test_asr_cleanup_scopes_part_id_to_the_target_turn_and_reports_source_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("fixture-user", "fixture-phone", "phone")
            audio = R25MediaContractTests.wav(list_chunk=None)
            manifests = []
            for turn_id in ("018f5a2e-7b6e-7abc-8d11-1234567890af", "018f5a2e-7b6e-7abc-8d11-1234567890b0"):
                manifests.append({
                    "schema_version": 1,
                    "user_id": "fixture-user",
                    "turn_id": turn_id,
                    "origin_device_id": "fixture-phone",
                    "client_created_at": "2026-09-09T00:00:00Z",
                    "parts": [
                        {"part_id": "shared", "kind": "text", "mime": "text/plain", "declared_bytes": 5},
                        {"part_id": "audio", "kind": "audio", "mime": "audio/wav", "declared_bytes": len(audio)},
                    ],
                })
            for manifest in manifests:
                store.create_turn(manifest)
                store.put_chunk(manifest["turn_id"], "audio", 0, audio)
                store.finish_part(manifest["turn_id"], "audio", total_chunks=1, total_bytes=len(audio), whole_stream_sha256=__import__("hashlib").sha256(audio).hexdigest())
            first = manifests[0]["turn_id"]
            generation = store.set_asr_stage(first, expected_generation=0, stage="realtime")
            store.commit_asr_result(first, expected_generation=generation, stage="realtime", result=AsrResult.valid("hello"))
            target = store.get_turn(first)
            foreign = store.get_turn(manifests[1]["turn_id"])
            self.assertTrue(target["source_deleted"])
            target_audio = next(part for part in target["parts"] if part["kind"] == "audio")
            foreign_audio = next(part for part in foreign["parts"] if part["kind"] == "audio")
            self.assertFalse(target_audio["source_available"])
            self.assertTrue(foreign_audio["source_available"])
            self.assertEqual(store.missing_sequence_page(first, "audio", encoding="list")["missing"], [])
            with store._read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM turn_chunks WHERE turn_id=?", (first,)).fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM turn_chunks WHERE turn_id=?", (manifests[1]["turn_id"],)).fetchone()[0], 1)


class R25BindingAndBudgetTests(unittest.TestCase):
    def test_terminal_result_requires_the_complete_durable_binding(self):
        expected = dict(
            submission_id="sub-1",
            turn_id="018f5a2e-7b6e-7abc-8d11-1234567890aa",
            marker="marker-1",
            session_key="project:one:default",
            run_id="run-1",
            request_sha256="a" * 64,
            subject_kind="turn",
        )
        complete = HermesResult(
            "assistant-1",
            "answer",
            True,
            "hermes-run",
            submission_id=expected["submission_id"],
            turn_id=expected["turn_id"],
            marker=expected["marker"],
            session_key=expected["session_key"],
            run_id=expected["run_id"],
            request_sha256=expected["request_sha256"],
            subject_kind=expected["subject_kind"],
        )
        self.assertIs(RecorderService._valid_terminal_hermes_result(complete, expected=expected), complete)
        for field in expected:
            bad = dict(expected)
            bad[field] = "wrong" if field != "subject_kind" else "eavesdrop"
            with self.subTest(field=field):
                self.assertIsNone(RecorderService._valid_terminal_hermes_result(complete, expected=bad))
        self.assertIsNone(RecorderService._valid_terminal_hermes_result(HermesResult("assistant-1", "answer"), expected=expected))

    def test_audio_finish_rejects_non_wav_before_complete_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            manifest = {
                "schema_version": 1,
                "user_id": "fixture-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890bb",
                "origin_device_id": "fixture-phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [{"part_id": "audio-1", "kind": "audio", "mime": "audio/wav", "streaming": True}],
            }
            store.create_turn(manifest)
            store.put_chunk(manifest["turn_id"], "audio-1", 0, b"not-a-wav")
            with self.assertRaises(MediaValidationError):
                store.finish_part(
                    manifest["turn_id"],
                    "audio-1",
                    total_chunks=1,
                    total_bytes=9,
                    whole_stream_sha256=__import__("hashlib").sha256(b"not-a-wav").hexdigest(),
                )
            self.assertEqual(store.get_turn(manifest["turn_id"])["parts"][0]["status"], "RECEIVING")

    def test_mime_parameter_policy_only_allows_utf8_text(self):
        base = {
            "schema_version": 1,
            "user_id": "fixture-user",
            "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890bc",
            "origin_device_id": "fixture-phone",
            "client_created_at": "2026-09-09T00:00:00Z",
        }
        text = {**base, "parts": [{"part_id": "text-1", "kind": "text", "mime": "text/plain; charset=utf-8"}]}
        self.assertEqual(validate_turn_manifest(text)["parts"][0]["mime"], "text/plain; charset=utf-8")
        for mime in ("audio/wav; charset=binary", "image/png; charset=utf-8"):
            with self.subTest(mime=mime), self.assertRaises(ManifestValidationError):
                validate_turn_manifest({**base, "parts": [{"part_id": "p", "kind": "audio" if mime.startswith("audio") else "image", "mime": mime, "declared_bytes": 1}]})

    def test_image_estimator_counts_each_image_once(self):
        body = {"input": [{"role": "user", "content": [{"type": "input_image", "declared_bytes": 3, "image_url": "data:image/png;base64,AAAA"}]}]}
        explicit = estimate_run_body_upper_bound(body, text_reserve=0, session_reserve=0, image_declared_bytes=[3])
        discovered = estimate_run_body_upper_bound(body, text_reserve=0, session_reserve=0)
        self.assertEqual(discovered, explicit)


if __name__ == "__main__":
    unittest.main()
