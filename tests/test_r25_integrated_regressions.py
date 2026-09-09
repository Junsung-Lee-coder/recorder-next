from __future__ import annotations

import json
import tempfile
import unittest
import io
import wave
from pathlib import Path
from unittest.mock import patch

from recorder_next.errors import ConflictError, LeaseConflict, ValidationError
from recorder_next.store import RecorderStore


class R25IntegratedRegressionTests(unittest.TestCase):
    def test_terminal_worker_replay_requires_winning_attempt_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            job = store.enqueue_worker_job(
                kind="fixture",
                stage="fixture",
                payload={"turn_id": "turn-1"},
                idempotency_key="fixture-job",
            )
            claim = store.claim_worker_job("owner-1")
            self.assertIsNotNone(claim)
            assert claim is not None
            receipt = {"effect_id": "effect-1", "status": "succeeded"}
            store.complete_worker_job(
                job["job_id"],
                "owner-1",
                receipt,
                lease_token=claim["lease_token"],
            )
            with self.assertRaises(ValidationError):
                store.complete_worker_job(job["job_id"], "owner-1", receipt, lease_token="")
            with self.assertRaises(LeaseConflict):
                store.complete_worker_job(job["job_id"], "other-owner", receipt, lease_token="other-token")

    def test_audio_cleanup_does_not_unlink_replaced_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            manifest = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890aa",
                "origin_device_id": "phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [
                    {"part_id": "audio", "kind": "audio", "mime": "audio/wav", "streaming": True}
                ],
            }
            store.create_turn(manifest)
            wav_buffer = io.BytesIO()
            with wave.open(wav_buffer, "wb") as handle:
                handle.setnchannels(1)
                handle.setsampwidth(2)
                handle.setframerate(16000)
                handle.writeframes(b"\x00\x00" * 160)
            original = wav_buffer.getvalue()
            store.put_chunk(manifest["turn_id"], "audio", 0, original)
            import hashlib
            store.finish_part(
                manifest["turn_id"],
                "audio",
                total_chunks=1,
                total_bytes=len(original),
                whole_stream_sha256=hashlib.sha256(original).hexdigest(),
            )
            with store._read() as conn:
                source = Path(conn.execute("SELECT source_path FROM turn_parts WHERE turn_id=?", (manifest["turn_id"],)).fetchone()[0])
            source.write_bytes(b"replacement")
            generation = store.set_asr_stage(manifest["turn_id"], expected_generation=0, stage="realtime")
            assert generation is not None
            from recorder_next.models import AsrResult
            store.commit_asr_result(
                manifest["turn_id"],
                expected_generation=generation,
                stage="realtime",
                result=AsrResult.valid("transcript"),
            )
            self.assertEqual(source.read_bytes(), b"replacement")


if __name__ == "__main__":
    unittest.main()
