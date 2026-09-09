from __future__ import annotations

import json
import hashlib
import shutil
import sqlite3
import tempfile
import unittest
import io
import wave
import uuid
import zlib
from pathlib import Path
from unittest.mock import patch

from recorder_next.errors import ConflictError, LeaseConflict, SourceUnavailableError, ValidationError
from recorder_next.features import FeatureGroups
from recorder_next.models import AsrResult
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

    def test_audio_cleanup_missing_parent_converges_across_restart_and_blocks_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ab"
            manifest = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": turn_id,
                "origin_device_id": "phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [{"part_id": "audio", "kind": "audio", "mime": "audio/wav", "streaming": True}],
            }
            store.create_turn(manifest)
            wav_buffer = io.BytesIO()
            with wave.open(wav_buffer, "wb") as handle:
                handle.setnchannels(1)
                handle.setsampwidth(2)
                handle.setframerate(16000)
                handle.writeframes(b"\x00\x00" * 160)
            audio = wav_buffer.getvalue()
            store.put_chunk(turn_id, "audio", 0, audio)
            store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=hashlib.sha256(audio).hexdigest(),
            )
            reference = store.attachment_reference(turn_id, "audio")
            with store._read() as conn:
                source = Path(conn.execute("SELECT source_path FROM turn_parts WHERE turn_id=?", (turn_id,)).fetchone()[0])
            shutil.rmtree(source.parent)
            generation = store.set_asr_stage(turn_id, expected_generation=0, stage="realtime")
            assert generation is not None
            # Leave the durable valid-transcript marker behind and simulate a
            # process loss before its first cleanup attempt.
            with patch.object(store, "_converge_audio_cleanup", return_value=False):
                self.assertTrue(
                    store.commit_asr_result(
                        turn_id,
                        expected_generation=generation,
                        stage="realtime",
                        result=AsrResult.valid("transcript"),
                    )
                )

            restarted = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            recovery = restarted.recover(now="2026-09-09T00:01:00+00:00")
            self.assertEqual(recovery["source_deletions_retried"], 1)
            with restarted._read() as conn:
                turn = conn.execute("SELECT source_deleted FROM turns WHERE turn_id=?", (turn_id,)).fetchone()
                part = conn.execute("SELECT source_path, source_deleted_at FROM turn_parts WHERE turn_id=?", (turn_id,)).fetchone()
                chunks = conn.execute("SELECT COUNT(*) FROM turn_chunks WHERE turn_id=?", (turn_id,)).fetchone()[0]
            self.assertEqual(turn["source_deleted"], 1)
            self.assertIsNone(part["source_path"])
            self.assertIsNotNone(part["source_deleted_at"])
            self.assertEqual(chunks, 0)
            with self.assertRaises(SourceUnavailableError) as issued:
                restarted.attachment_reference(turn_id, "audio")
            self.assertEqual((issued.exception.code, issued.exception.status), ("SOURCE_UNAVAILABLE", 410))
            with self.assertRaises(SourceUnavailableError) as resolved:
                restarted.resolve_attachment_reference(reference)
            self.assertEqual((resolved.exception.code, resolved.exception.status), ("SOURCE_UNAVAILABLE", 410))

    def test_schema4_diagnostics_reproject_handles_aliases_and_equal_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            storage_root = root / "data"
            RecorderStore(db_path, storage_root=storage_root)
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            for table in ("diagnostic_bundles", "diagnostic_events", "diagnostics_consents", "diagnostic_tombstones"):
                conn.execute(f"DROP TABLE {table}")
            conn.executescript(
                """
                CREATE TABLE diagnostics_consents (
                    user_id TEXT NOT NULL, device_id TEXT NOT NULL, event_id TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT
                );
                CREATE TABLE diagnostic_events (
                    event_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
                    user_id TEXT NOT NULL, device_id TEXT NOT NULL, category TEXT NOT NULL,
                    stage TEXT NOT NULL, metadata_json TEXT NOT NULL, occurred_at TEXT NOT NULL,
                    retention_deadline TEXT NOT NULL, deleted_at TEXT
                );
                CREATE TABLE diagnostic_bundles (
                    bundle_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL,
                    opt_in_event_id TEXT NOT NULL, compressed_size INTEGER NOT NULL,
                    expanded_size INTEGER NOT NULL, payload_sha256 TEXT NOT NULL,
                    storage_path TEXT NOT NULL, created_at TEXT NOT NULL,
                    retention_deadline TEXT NOT NULL, deleted_at TEXT,
                    UNIQUE(user_id, device_id, payload_sha256),
                    FOREIGN KEY(opt_in_event_id) REFERENCES diagnostics_consents(event_id) ON DELETE RESTRICT
                );
                CREATE TABLE diagnostic_tombstones (
                    tombstone_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL CHECK(entity_type IN ('event','bundle')),
                    entity_id TEXT NOT NULL, deleted_at TEXT NOT NULL,
                    UNIQUE(entity_type, entity_id)
                );
                """
            )
            conn.execute("UPDATE schema_meta SET value='4' WHERE key='schema_version'")
            conn.execute(
                "INSERT INTO devices(user_id, device_id, kind, created_at) VALUES (?, ?, ?, ?)",
                ("legacy-user", "legacy-phone", "phone", "2026-09-10T00:00:00+00:00"),
            )
            conn.execute(
                "INSERT INTO diagnostics_consents VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("legacy-user", "legacy-phone", "consent-old", 1, "2026-09-10T00:00:00+00:00", "2026-12-01T00:00:00+00:00", None),
            )
            conn.execute(
                "INSERT INTO diagnostic_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "event-old", "idem-old", "legacy-user", "legacy-phone", "voice", "asr",
                    json.dumps({"category": "voice", "stage": "asr", "status": "ok", "token": "private"}),
                    "2026-09-10T00:00:01+00:00", "2026-12-01T00:00:00+00:00", None,
                ),
            )
            legacy_payloads = []
            for index in range(2):
                raw = json.dumps(
                    {"events": [{"category": "voice", "stage": "asr", "status": "ok", "token": f"private-{index}"}]},
                    separators=(",", ":"),
                ).encode()
                compressed = zlib.compress(raw)
                path = storage_root / f"legacy-{index}.z"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(compressed)
                bundle_id = f"bundle-old-{index}"
                conn.execute(
                    "INSERT INTO diagnostic_bundles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        bundle_id, "legacy-user", "legacy-phone", "consent-old", len(compressed), len(raw),
                        hashlib.sha256(compressed).hexdigest(), str(path), f"2026-09-10T00:00:0{index + 2}+00:00",
                        "2026-12-01T00:00:00+00:00", None,
                    ),
                )
                legacy_payloads.append((bundle_id, raw))
            conn.execute(
                "INSERT INTO diagnostic_tombstones VALUES (?, ?, ?, ?, ?, ?)",
                ("tomb-old", "legacy-user", "legacy-phone", "event", "event-old", "2026-09-10T00:00:03+00:00"),
            )
            conn.commit()
            conn.close()

            with patch.object(FeatureGroups, "_unlink_managed_file", side_effect=OSError("deferred cleanup")):
                incomplete = RecorderStore(db_path, storage_root=storage_root)
            with incomplete._read() as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertEqual(conn.execute("SELECT migration_state FROM diagnostic_bundles").fetchone()[0], "MIGRATING")
                self.assertEqual(conn.execute("SELECT status FROM storage_cleanup_receipts WHERE operation LIKE 'diagnostic_migration_cleanup_%'").fetchone()[0], "PENDING")
            migrated = RecorderStore(db_path, storage_root=storage_root)
            with migrated._read() as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "5")
                consent = conn.execute("SELECT * FROM diagnostics_consents").fetchone()
                event = conn.execute("SELECT * FROM diagnostic_events").fetchone()
                bundles = conn.execute("SELECT * FROM diagnostic_bundles ORDER BY created_at").fetchall()
                tombstone = conn.execute("SELECT * FROM diagnostic_tombstones").fetchone()
                self.assertEqual(len(bundles), 2)
                self.assertTrue(all(row["migration_state"] == "READY" and row["privacy_version"] == 2 for row in bundles))
                self.assertTrue(all(uuid.UUID(row["bundle_id"]).version == 4 for row in bundles))
                self.assertEqual(bundles[0]["payload_sha256"], bundles[1]["payload_sha256"])
                self.assertEqual(bundles[0]["opt_in_event_id"], consent["event_id"])
                self.assertEqual(tombstone["entity_id"], event["event_id"])
                self.assertNotIn("event-old", json.dumps(dict(event)))
                self.assertNotIn("idem-old", json.dumps(dict(event)))
                for index in conn.execute("PRAGMA index_list(diagnostic_bundles)").fetchall():
                    if index["unique"]:
                        columns = [item["name"] for item in conn.execute(f"PRAGMA index_info({index['name']})").fetchall()]
                        self.assertNotEqual(columns, ["user_id", "device_id", "payload_sha256"])
            self.assertFalse(any((storage_root / f"legacy-{index}.z").exists() for index in range(2)))
            replay_event = migrated.ingest_diagnostic_event(
                "legacy-user", "legacy-phone", event_id="event-old", idempotency_key="idem-old",
                payload={"category": "voice", "stage": "asr", "status": "ok"},
            )
            self.assertEqual(replay_event["event_id"], event["event_id"])
            for bundle_id, raw in legacy_payloads:
                replay = migrated.ingest_diagnostic_bundle(
                    "legacy-user", "legacy-phone", bundle_id, zlib.compress(raw),
                    opt_in_event_id="consent-old", expanded_size=len(raw),
                )
                with migrated._read() as conn:
                    expected = conn.execute("SELECT bundle_id FROM diagnostic_bundles WHERE alias_digest=?", (migrated._features._alias_digest("bundle", "legacy-user", "legacy-phone", bundle_id),)).fetchone()[0]
                self.assertEqual(replay["bundle_id"], expected)
            restarted = RecorderStore(db_path, storage_root=storage_root)
            with restarted._read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM diagnostic_bundles").fetchone()[0], 2)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM diagnostic_bundles WHERE migration_state='READY'").fetchone()[0], 2)


if __name__ == "__main__":
    unittest.main()
