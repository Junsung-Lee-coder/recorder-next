import hashlib
import tempfile
import unittest
from pathlib import Path

from recorder_next.store import RecorderStore


class LimitContractTests(unittest.TestCase):
    def test_audio_limit_is_separate_from_attachment_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = b"123456789"
            manifest = {
                "schema_version": 1,
                "user_id": "limit-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890f1",
                "origin_device_id": "limit-watch",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": None,
                "prefer_current_project": False,
                "parts": [{"part_id": "audio-1", "kind": "audio", "mime": "audio/wav", "declared_bytes": len(data), "declared_sha256": hashlib.sha256(data).hexdigest(), "relationship": None, "caption_hash": None}],
            }
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data", max_audio_bytes=8, max_attachment_bytes=100)
            with self.assertRaises(Exception):
                store.create_turn(manifest)

    def test_audio_duration_limit_is_checked_when_declared(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = b"123"
            manifest = {
                "schema_version": 1,
                "user_id": "duration-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890f2",
                "origin_device_id": "duration-watch",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": None,
                "prefer_current_project": False,
                "parts": [{"part_id": "audio-1", "kind": "audio", "mime": "audio/wav", "declared_bytes": len(data), "declared_sha256": hashlib.sha256(data).hexdigest(), "duration_ms": 121 * 60 * 1000, "relationship": None, "caption_hash": None}],
            }
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data", max_audio_minutes=120)
            with self.assertRaises(Exception):
                store.create_turn(manifest)


if __name__ == "__main__":
    unittest.main()
