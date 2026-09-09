from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from recorder_next.adapters import HermesAudioASRProvider
from recorder_next.config import RecorderConfig
from recorder_next.service import create_configured_service
from tests.r25_test_helpers import canonical_wav


class _ASRFixture:
    def __init__(self) -> None:
        self.authorization_valid = False
        self.valid_request_seen = False
        self.audio_bytes = b""
        self._server = _ASRServer(("127.0.0.1", 0), _ASRHandler)
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


class _ASRServer(ThreadingHTTPServer):
    fixture: Any


class _ASRHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        fixture = cast(_ASRFixture, self.server.fixture)
        parsed = urlsplit(self.path)
        if parsed.path != "/api/audio/transcribe" or parse_qs(parsed.query).get("profile") != ["default"]:
            self._send(404, {"detail": "not found"})
            return
        size = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(size)
        try:
            payload = json.loads(raw.decode("utf-8"))
            data_url = payload["data_url"]
            if payload.get("mime_type") != "audio/wav":
                raise ValueError("invalid audio MIME")
            encoded = data_url.split(",", 1)[1]
            fixture.audio_bytes = base64.b64decode(encoded, validate=True)
        except (KeyError, IndexError, ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            self._send(422, {"detail": "invalid audio payload"})
            return
        fixture.authorization_valid = self.headers.get("Authorization") == "Bearer fixture-secret"
        if not fixture.authorization_valid:
            self._send(401, {"detail": "unauthorized"})
            return
        fixture.valid_request_seen = True
        self._send(200, {"transcript": "configured public ASR"})


class ConfiguredASRContractTests(unittest.TestCase):
    def test_configured_service_exercises_hermes_asr_through_public_http_caller(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credential_dir = root / "credentials"
            credential_dir.mkdir()
            credential = credential_dir / "recorder_api_key"
            credential.write_text("API_SERVER_KEY=fixture-secret\n", encoding="utf-8")
            credential.chmod(0o600)
            fixture = _ASRFixture()
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
                            f'database = "{root / "recorder.sqlite3"}"',
                            f'root = "{root / "data"}"',
                            "",
                            "[providers]",
                            f'hermes_base_url = "{fixture.url}"',
                            f'hermes_audio_base_url = "{fixture.url}"',
                            'hermes_api_key_file = "$CREDENTIALS_DIRECTORY/recorder_api_key"',
                            'hermes_profile = "default"',
                            'asr_source = "hermes"',
                            'asr_chain = ["hermes-asr"]',
                            'tts_source = "disabled"',
                            "",
                            "[[providers.asr_providers]]",
                            'name = "hermes-asr"',
                            'adapter = "hermes"',
                            f'endpoint = "{fixture.url}"',
                            'profile = "default"',
                            'credential_file = "$CREDENTIALS_DIRECTORY/recorder_api_key"',
                            "enabled = true",
                        )
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with patch.dict("os.environ", {"CREDENTIALS_DIRECTORY": str(credential_dir)}, clear=False), patch(
                    "recorder_next.adapters._trusted_systemd_credential_path", return_value=None
                ):
                    config = RecorderConfig.from_file(config_path).resolved()
                    service = create_configured_service(config)
                self.assertIsNotNone(service.asr_chain)
                assert service.asr_chain is not None
                provider = service.asr_chain.targets[0].provider
                self.assertIsInstance(provider, HermesAudioASRProvider)
                self.assertEqual(provider.endpoint, f"{fixture.url}/api/audio/transcribe?profile=default")

                user_id = "configured-asr-user"
                device_id = "configured-asr-device"
                service.store.register_device(user_id, device_id, "phone")
                turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890b1"
                audio = canonical_wav()
                manifest = {
                    "schema_version": 1,
                    "user_id": user_id,
                    "turn_id": turn_id,
                    "origin_device_id": device_id,
                    "client_created_at": "2026-09-07T00:00:00Z",
                    "current_project_number": "ASR-PUBLIC",
                    "prefer_current_project": True,
                    "parts": [{
                        "part_id": "audio-1",
                        "kind": "audio",
                        "mime": "audio/wav",
                        "declared_bytes": len(audio),
                        "declared_sha256": hashlib.sha256(audio).hexdigest(),
                    }],
                }
                status, _, created = service.handle_http("POST", "/v1/turns", {"Content-Type": "application/json"}, json.dumps(manifest).encode())
                self.assertEqual(status, 201)
                self.assertEqual(created["turn_id"], turn_id)
                query = f"?user_id={user_id}&device_id={device_id}"
                status, _, _ = service.handle_http("PUT", f"/v1/turns/{turn_id}/parts/audio-1/chunks/0{query}", {"X-Chunk-SHA256": hashlib.sha256(audio).hexdigest()}, audio)
                self.assertEqual(status, 200)
                finish = {"total_chunks": 1, "total_bytes": len(audio), "whole_stream_sha256": hashlib.sha256(audio).hexdigest()}
                status, _, _ = service.handle_http("POST", f"/v1/turns/{turn_id}/parts/audio-1/finish{query}", {"Content-Type": "application/json"}, json.dumps(finish).encode())
                self.assertEqual(status, 200)
                status, _, accepted = service.handle_http("POST", f"/v1/turns/{turn_id}/accept", {"Content-Type": "application/json"}, json.dumps({"user_id": user_id, "device_id": device_id}).encode())
                self.assertEqual(status, 200)
                self.assertEqual(accepted["state"], "ACCEPTED")

                receipt = service.run_background_worker_once(owner="configured-asr-worker")
                self.assertIsNotNone(receipt)
                assert receipt is not None
                self.assertEqual(receipt["status"], "SUCCEEDED")
                turn = service.store.get_turn(turn_id)
                self.assertEqual(turn["authoritative_asr_outcome"], "VALID_TRANSCRIPT")
                self.assertEqual(turn["transcript"], "configured public ASR")
                self.assertEqual(fixture.audio_bytes, audio)
                self.assertTrue(fixture.authorization_valid)
                self.assertTrue(fixture.valid_request_seen)
            finally:
                fixture.close()


if __name__ == "__main__":
    unittest.main()
