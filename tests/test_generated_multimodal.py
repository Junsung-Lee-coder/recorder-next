from __future__ import annotations

import hashlib
import json
import math
import struct
import tempfile
import threading
import urllib.error
import urllib.request
import wave
from pathlib import Path
import unittest

from recorder_next.adapters import StaticASRProvider
from recorder_next.http import create_http_server
from recorder_next.models import AsrResult, HermesResult, TTSResult
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


ROOT = Path(__file__).parents[1]
FIXTURE_ROOT = ROOT / "fixtures" / "generated"
FIXTURE_MANIFEST = FIXTURE_ROOT / "manifest.json"


class EchoHermesGateway:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def submit(self, *, session_key, request, submission_id, marker):
        self.calls.append(
            {
                "session_key": session_key,
                "request": dict(request),
                "submission_id": submission_id,
                "marker": marker,
            }
        )
        return HermesResult("generated-hermes-message", "Synthetic generated final.")

    def history(self, *, session_key, marker):
        return None

    def history_messages(self, *, session_key, marker):
        return []


class FixtureTTSProvider:
    name = "generated-fixture-tts"

    def __init__(self, audio: bytes) -> None:
        self.audio = audio

    def synthesize(self, text: str, *, artifact_id: str) -> TTSResult:
        return TTSResult(
            audio=self.audio,
            mode="file",
            content_type="audio/wav",
            metadata={"fixture": True, "artifact_id": artifact_id},
        )


def _fixture_metadata() -> dict[str, object]:
    return json.loads(FIXTURE_MANIFEST.read_text(encoding="utf-8"))


def _fixture_bytes(metadata: dict[str, object], key: str) -> bytes:
    entry = metadata["files"][key]
    return (FIXTURE_ROOT / entry["path"]).read_bytes()


def _request(server, method: str, path: str, payload=None, *, raw: bytes | None = None, headers=None):
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}{path}"
    body = raw if raw is not None else (json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None)
    request_headers = {"Accept": "application/json"}
    if payload is not None or raw is not None:
        request_headers["Content-Type"] = "application/json" if raw is None else "application/octet-stream"
    request_headers.update(headers or {})
    request = urllib.request.Request(url, data=body, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response_body = response.read()
            return response.status, json.loads(response_body.decode("utf-8")) if response_body else None
    except urllib.error.HTTPError as exc:
        response_body = exc.read()
        return exc.code, json.loads(response_body.decode("utf-8")) if response_body else None


def _assert_status(test: unittest.TestCase, result, expected: int):
    test.assertEqual(result[0], expected, result[1])
    return result[1]


def _manifest_for(metadata: dict[str, object], key: str, turn_id: str, *, user: str, device: str) -> dict[str, object]:
    entry = metadata["files"][key]
    return {
        "schema_version": 1,
        "user_id": user,
        "turn_id": turn_id,
        "origin_device_id": device,
        "client_created_at": "2026-08-25T00:00:00Z",
        "current_project_number": "P-GENERATED",
        "prefer_current_project": True,
        "parts": [
            {
                "part_id": entry["part_id"],
                "kind": entry["kind"],
                "mime": entry["mime"],
                "declared_bytes": entry["bytes"],
                "declared_sha256": entry["sha256"],
                "relationship": entry.get("relationship"),
                "caption_hash": entry.get("caption_hash"),
                "streaming": bool(entry.get("streaming", False)),
            }
        ],
    }


def _start_isolated_server(tmp: str, metadata: dict[str, object], *, asr=None):
    root = Path(tmp)
    store = RecorderStore(root / "recorder.sqlite3", storage_root=root / "data")
    user = "generated-fixture-user"
    device = "generated-fixture-phone"
    store.register_device(user, device, "phone")
    project = store.create_project(user, project_number="P-GENERATED", name="Generated fixture project")
    gateway = EchoHermesGateway()
    audio = _fixture_bytes(metadata, "voice_ko")
    service = RecorderService(
        store,
        hermes=gateway,
        asr_providers=asr or {},
        tts=FixtureTTSProvider(audio),
    )
    server = create_http_server(service, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, store, project, gateway, user, device


def _upload_and_accept(test: unittest.TestCase, server, manifest: dict[str, object], payload: bytes, *, out_of_order=False):
    turn_id = manifest["turn_id"]
    part_id = manifest["parts"][0]["part_id"]
    _assert_status(test, _request(server, "POST", "/v1/turns", manifest), 201)
    midpoint = max(1, len(payload) // 2)
    chunks = [payload[:midpoint], payload[midpoint:]]
    order = [1, 0] if out_of_order else [0, 1]
    for sequence in order:
        result = _assert_status(
            test,
            _request(
                server,
                "PUT",
                f"/v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}",
                raw=chunks[sequence],
                headers={"X-Chunk-SHA256": hashlib.sha256(chunks[sequence]).hexdigest()},
            ),
            200,
        )
        test.assertFalse(result["duplicate"])
    duplicate = _assert_status(
        test,
        _request(
            server,
            "PUT",
            f"/v1/turns/{turn_id}/parts/{part_id}/chunks/0",
            raw=chunks[0],
        ),
        200,
    )
    test.assertTrue(duplicate["duplicate"])
    finished = _assert_status(
        test,
        _request(
            server,
            "POST",
            f"/v1/turns/{turn_id}/parts/{part_id}/finish",
            {
                "total_chunks": 2,
                "total_bytes": len(payload),
                "whole_stream_sha256": hashlib.sha256(payload).hexdigest(),
            },
        ),
        200,
    )
    test.assertEqual(finished["status"], "COMPLETE")
    accepted = _assert_status(test, _request(server, "POST", f"/v1/turns/{turn_id}/accept", {}), 200)
    test.assertEqual(accepted["state"], "ACCEPTED")
    return accepted


def _route_hermes_and_ack(test: unittest.TestCase, server, *, user: str, device: str, project_id: str, turn_id: str):
    routed = _assert_status(test, _request(server, "POST", "/v1/internal/router", {"user_id": user, "owner": "fixture-router"}), 200)
    test.assertEqual(routed["state"], "HERMES_PENDING")
    route_items = _assert_status(test, _request(server, "GET", f"/v1/outbox?device_id={device}"), 200)["items"]
    route_event = next(item for item in route_items if item["event_kind"] == "ROUTED")
    _assert_status(
        test,
        _request(
            server,
            "POST",
            f"/v1/turns/{turn_id}/events/{route_event['event_id']}/ack",
            {
                "device_id": device,
                "event_version": route_event["event_version"],
                "payload_sha256": route_event["payload_sha256"],
            },
        ),
        200,
    )
    final_ready = _assert_status(
        test,
        _request(server, "POST", "/v1/internal/hermes", {"session_id": project_id, "owner": "fixture-hermes"}),
        200,
    )
    test.assertEqual(final_ready["state"], "FINAL_READY")
    final_items = _assert_status(test, _request(server, "GET", f"/v1/outbox?device_id={device}"), 200)["items"]
    final_event = next(item for item in final_items if item["event_kind"] == "FINAL")
    delivered = _assert_status(
        test,
        _request(
            server,
            "POST",
            f"/v1/turns/{turn_id}/events/{final_event['event_id']}/ack",
            {
                "device_id": device,
                "event_version": final_event["event_version"],
                "payload_sha256": final_event["payload_sha256"],
            },
        ),
        200,
    )
    test.assertEqual(delivered["state"], "DELIVERED")
    generated = _assert_status(test, _request(server, "POST", "/v1/internal/tts", {"limit": 50}), 200)
    for artifact in generated:
        ready = _assert_status(test, _request(server, "GET", f"/v1/tts/{artifact['artifact_id']}?device_id={device}"), 200)
        test.assertEqual(ready["status"], "READY")
        playback = _assert_status(
            test,
            _request(
                server,
                "POST",
                f"/v1/tts/{artifact['artifact_id']}/playback-ack",
                {
                    "device_id": device,
                    "turn_id": turn_id,
                    "artifact_version": artifact["artifact_version"],
                    "payload_sha256": ready["payload_sha256"],
                },
            ),
            200,
        )
        test.assertEqual(playback["status"], "PLAYED")
    return delivered


class GeneratedFixtureInventoryTests(unittest.TestCase):
    def test_generated_fixture_manifest_is_deterministic_and_audio_is_real_speech(self):
        metadata = _fixture_metadata()
        self.assertEqual(metadata["privacy"], "synthetic-only")
        self.assertEqual(metadata["generator"]["tts_provider"], "espeak-ng")
        self.assertEqual(metadata["prompts"]["ko"], "합성 음성 입력 수용 시험입니다.")
        self.assertEqual(metadata["prompts"]["en"], "Synthetic English voice acceptance fixture.")
        for language in ("ko", "en"):
            self.assertEqual(
                metadata["prompts"]["sha256"][language],
                hashlib.sha256(metadata["prompts"][language].encode("utf-8")).hexdigest(),
            )
        self.assertEqual(metadata["files"]["voice_ko"]["prompt_sha256"], metadata["prompts"]["sha256"]["ko"])
        self.assertEqual(metadata["files"]["voice_en"]["prompt_sha256"], metadata["prompts"]["sha256"]["en"])
        self.assertNotIn("mixed", metadata["files"])
        for key, entry in metadata["files"].items():
            path = FIXTURE_ROOT / entry["path"]
            self.assertTrue(path.is_file(), key)
            payload = path.read_bytes()
            self.assertEqual(len(payload), entry["bytes"], key)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), entry["sha256"], key)

        for key in ("voice_ko", "voice_en"):
            with wave.open(str(FIXTURE_ROOT / metadata["files"][key]["path"]), "rb") as handle:
                self.assertEqual(handle.getnchannels(), 1)
                self.assertEqual(handle.getsampwidth(), 2)
                self.assertEqual(handle.getframerate(), 16000)
                self.assertGreater(handle.getnframes(), 8000)
                samples = struct.unpack("<" + "h" * handle.getnframes(), handle.readframes(handle.getnframes()))
            window = max(1, len(samples) // 20)
            rms_values = []
            for start in range(0, len(samples), window):
                values = samples[start : start + window]
                if values:
                    rms_values.append(math.sqrt(sum(value * value for value in values) / len(values)))
            self.assertGreater(max(rms_values), 200)
            self.assertGreater(len({round(value) for value in rms_values}), 5)
            self.assertGreater(sum(value != 0 for value in samples), len(samples) // 10)

    def test_generated_image_and_documents_have_valid_signatures_and_content(self):
        metadata = _fixture_metadata()
        png = _fixture_bytes(metadata, "image_png")
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(png[12:16], b"IHDR")
        width, height = struct.unpack(">II", png[16:24])
        self.assertEqual((width, height), (64, 48))
        pdf = _fixture_bytes(metadata, "document_pdf")
        self.assertTrue(pdf.startswith(b"%PDF-1.4\n"))
        self.assertIn(b"xref\n", pdf)
        self.assertIn(b"trailer\n", pdf)
        self.assertTrue(pdf.endswith(b"%%EOF\n"))
        self.assertIn(b"Synthetic PDF acceptance fixture", pdf)
        self.assertEqual(_fixture_bytes(metadata, "text_utf8").decode("utf-8"), "합성 텍스트 첨부입니다.\n두 번째 줄입니다.\n")
        self.assertEqual(_fixture_bytes(metadata, "data_csv").decode("utf-8"), "name,value\nsynthetic,42\n")
        generic = _fixture_bytes(metadata, "generic_binary")
        self.assertGreater(len(generic), 8)
        self.assertNotEqual(generic[:4], b"RIFF")


class GeneratedSingleInputHTTPTests(unittest.TestCase):
    def test_voice_public_flow_uses_real_audio_chunks_asr_hermes_final_and_tts(self):
        metadata = _fixture_metadata()
        audio = _fixture_bytes(metadata, "voice_ko")
        asr = {
            "realtime": StaticASRProvider("realtime", AsrResult.no_speech()),
            "batch": StaticASRProvider("batch", AsrResult.error("synthetic batch unavailable")),
            "local": StaticASRProvider("local", AsrResult.valid(metadata["prompts"]["ko"])),
        }
        with tempfile.TemporaryDirectory() as tmp:
            server, thread, store, project, gateway, user, device = _start_isolated_server(tmp, metadata, asr=asr)
            try:
                turn_id = "018f5a2e-7b6e-7abc-8d11-123456789101"
                manifest = _manifest_for(metadata, "voice_ko", turn_id, user=user, device=device)
                _assert_status(self, _request(server, "POST", "/v1/turns", manifest), 201)
                part_id = manifest["parts"][0]["part_id"]
                midpoint = len(audio) // 2
                chunks = [audio[:midpoint], audio[midpoint:]]
                first = _assert_status(self, _request(server, "PUT", f"/v1/turns/{turn_id}/parts/{part_id}/chunks/1", raw=chunks[1]), 200)
                self.assertFalse(first["duplicate"])
                missing = _assert_status(self, _request(server, "GET", f"/v1/turns/{turn_id}/parts/{part_id}/missing?total_chunks=2"), 200)
                self.assertEqual(missing["missing"], [0])
                duplicate = _assert_status(self, _request(server, "PUT", f"/v1/turns/{turn_id}/parts/{part_id}/chunks/1", raw=chunks[1]), 200)
                self.assertTrue(duplicate["duplicate"])
                conflict = _request(server, "PUT", f"/v1/turns/{turn_id}/parts/{part_id}/chunks/1", raw=b"conflicting-sequence")
                self.assertEqual(conflict[0], 409)
                _assert_status(self, _request(server, "PUT", f"/v1/turns/{turn_id}/parts/{part_id}/chunks/0", raw=chunks[0]), 200)
                _assert_status(
                    self,
                    _request(
                        server,
                        "POST",
                        f"/v1/turns/{turn_id}/parts/{part_id}/finish",
                        {"total_chunks": 2, "total_bytes": len(audio), "whole_stream_sha256": hashlib.sha256(audio).hexdigest()},
                    ),
                    200,
                )
                accepted = _assert_status(self, _request(server, "POST", f"/v1/turns/{turn_id}/accept", {}), 200)
                self.assertEqual(accepted["state"], "ACCEPTED")
                reopened = RecorderStore(Path(tmp) / "recorder.sqlite3", storage_root=Path(tmp) / "data")
                self.assertEqual(reopened.read_part(turn_id, part_id), audio)
                asr_result = RecorderService(reopened, asr_providers=asr).run_asr(turn_id)
                self.assertEqual(asr_result["transcript"], metadata["prompts"]["ko"])
                routed = _route_hermes_and_ack(self, server, user=user, device=device, project_id=project["stable_project_id"], turn_id=turn_id)
                self.assertEqual(routed["state"], "DELIVERED")
                self.assertEqual([call["request"]["request"]["input"] for call in gateway.calls], [metadata["prompts"]["ko"]])
                self.assertEqual(store.get_turn(turn_id)["parts"][0]["whole_stream_sha256"], hashlib.sha256(audio).hexdigest())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_each_supported_non_audio_fixture_is_a_separate_public_single_input_turn(self):
        metadata = _fixture_metadata()
        cases = ("image_png", "document_pdf", "text_utf8", "data_csv", "generic_binary")
        for index, key in enumerate(cases, start=2):
            with self.subTest(fixture=key), tempfile.TemporaryDirectory() as tmp:
                server, thread, store, project, gateway, user, device = _start_isolated_server(tmp, metadata)
                try:
                    turn_id = f"018f5a2e-7b6e-7abc-8d11-1234567891{index:02d}"
                    payload = _fixture_bytes(metadata, key)
                    manifest = _manifest_for(metadata, key, turn_id, user=user, device=device)
                    accepted = _upload_and_accept(self, server, manifest, payload, out_of_order=True)
                    part = accepted["parts"][0]
                    self.assertEqual(part["mime"], metadata["files"][key]["mime"])
                    self.assertEqual(part["declared_bytes"], len(payload))
                    self.assertEqual(part["whole_stream_sha256"], hashlib.sha256(payload).hexdigest())
                    self.assertEqual(part["status"], "COMPLETE")
                    routed = _route_hermes_and_ack(self, server, user=user, device=device, project_id=project["stable_project_id"], turn_id=turn_id)
                    self.assertEqual(routed["state"], "DELIVERED")
                    request = gateway.calls[0]["request"]["request"]
                    self.assertEqual(request["manifest"]["parts"][0]["relationship"], metadata["files"][key].get("relationship"))
                    self.assertEqual(request["manifest"]["parts"][0]["declared_sha256"], metadata["files"][key]["sha256"])
                    archived = _assert_status(self, _request(server, "POST", f"/v1/turns/{turn_id}/archive?user_id={user}", {"source": "generated-fixture-test"}), 200)
                    self.assertIsNotNone(archived["archived_at"])
                    self.assertEqual(store.read_part(turn_id, manifest["parts"][0]["part_id"]), payload)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

    def test_english_voice_fixture_is_supported_as_a_separate_public_voice_turn(self):
        metadata = _fixture_metadata()
        audio = _fixture_bytes(metadata, "voice_en")
        with tempfile.TemporaryDirectory() as tmp:
            asr = {"realtime": StaticASRProvider("realtime", AsrResult.valid(metadata["prompts"]["en"]))}
            server, thread, store, project, gateway, user, device = _start_isolated_server(tmp, metadata, asr=asr)
            try:
                turn_id = "018f5a2e-7b6e-7abc-8d11-1234567891ab"
                manifest = _manifest_for(metadata, "voice_en", turn_id, user=user, device=device)
                _upload_and_accept(self, server, manifest, audio, out_of_order=True)
                result = server.service.run_asr(turn_id)
                self.assertEqual(result["transcript"], metadata["prompts"]["en"])
                _route_hermes_and_ack(self, server, user=user, device=device, project_id=project["stable_project_id"], turn_id=turn_id)
                self.assertEqual(gateway.calls[0]["request"]["request"]["input"], metadata["prompts"]["en"])
                self.assertEqual(store.get_turn(turn_id)["state"], "DELIVERED")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_text_convenience_path_is_idempotent_and_rejects_changed_payload(self):
        metadata = _fixture_metadata()
        text = "첫 줄\r\n둘째 줄\r셋째 줄\n\n끝"
        with tempfile.TemporaryDirectory() as tmp:
            server, thread, store, project, gateway, user, device = _start_isolated_server(tmp, metadata)
            try:
                turn_id = "018f5a2e-7b6e-7abc-8d11-123456789199"
                body = {
                    "schema_version": 1,
                    "user_id": user,
                    "turn_id": turn_id,
                    "origin_device_id": device,
                    "client_created_at": "2026-08-25T00:00:00Z",
                    "current_project_number": "P-GENERATED",
                    "prefer_current_project": True,
                    "text": text,
                }
                first = _assert_status(self, _request(server, "POST", "/v1/turns", body), 202)
                second = _assert_status(self, _request(server, "POST", "/v1/turns", body), 202)
                self.assertEqual(first["accepted_seq"], second["accepted_seq"])
                changed = dict(body)
                changed["text"] = text + " changed"
                conflict = _request(server, "POST", "/v1/turns", changed)
                self.assertEqual(conflict[0], 409)
                _route_hermes_and_ack(self, server, user=user, device=device, project_id=project["stable_project_id"], turn_id=turn_id)
                self.assertEqual(gateway.calls[0]["request"]["request"]["input"], text)
                self.assertEqual(store.get_turn(turn_id)["state"], "DELIVERED")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_attachment_quota_is_rejected_before_bytes_are_stored(self):
        metadata = _fixture_metadata()
        payload = _fixture_bytes(metadata, "document_pdf")
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "recorder.sqlite3", storage_root=Path(tmp) / "data", max_attachment_bytes=len(payload) - 1)
            manifest = _manifest_for(metadata, "document_pdf", "018f5a2e-7b6e-7abc-8d11-1234567891aa", user="quota-user", device="quota-device")
            with self.assertRaises(Exception):
                store.create_turn(manifest)
            self.assertEqual(store.db_snapshot()["turns"], 0)


if __name__ == "__main__":
    unittest.main()
