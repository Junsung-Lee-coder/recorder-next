import hashlib
import tempfile
import unittest
from pathlib import Path

from recorder_next.errors import TurnIdConflict
from recorder_next.store import RecorderStore


class InitialFingerprintContractTests(unittest.TestCase):
    def test_same_initial_envelope_rejoins_but_immutable_change_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "recorder.sqlite3", storage_root=Path(tmp) / "data")
            manifest = {
                "schema_version": 1,
                "user_id": "fixture-user",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890ab",
                "origin_device_id": "fixture-phone",
                "client_created_at": "2026-08-25T00:00:00Z",
                "current_project_number": "P-001",
                "prefer_current_project": True,
                "parts": [
                    {
                        "part_id": "text-1",
                        "kind": "text",
                        "mime": "text/plain",
                        "declared_bytes": 5,
                        "declared_sha256": hashlib.sha256(b"hello").hexdigest(),
                        "relationship": None,
                        "caption_hash": None,
                    }
                ],
            }

            first = store.create_turn(manifest)
            same = store.create_turn(dict(manifest))

            self.assertEqual(first["turn_id"], same["turn_id"])
            self.assertEqual(first["initial_fingerprint"], same["initial_fingerprint"])

            conflict = dict(manifest)
            conflict["origin_device_id"] = "fixture-watch"
            with self.assertRaises(TurnIdConflict):
                store.create_turn(conflict)


if __name__ == "__main__":
    unittest.main()
