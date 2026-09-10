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

from recorder_next.adapters import HermesResult
from recorder_next.errors import ConflictError, LeaseConflict, SourceUnavailableError, ValidationError
from recorder_next.service import RecorderService
from recorder_next.features import FeatureGroups
from recorder_next.models import AsrResult
from recorder_next.store import RecorderStore

SCHEMA4_FIXTURE = Path(__file__).with_name("fixtures") / "schema4_public_preimage.sql"
SCHEMA4_FIXTURE_SHA256 = "73076556af3d41c46b45ef43049346ad750fd705bdc6bef5cc53ba12c1316d84"


def _seed_migration_fixture(db_path: Path, script_path: Path, *, version: int) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(script_path.read_text(encoding="utf-8"))
    conn.execute("UPDATE schema_meta SET value=? WHERE key='schema_version'", (str(version),))
    conn.execute(
        "INSERT INTO devices(user_id, device_id, kind, created_at) VALUES (?, ?, ?, ?)",
        ("sentinel-user", "sentinel-device", "phone", "2026-09-10T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()


def _logical_database_snapshot(db_path: Path) -> dict:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    objects = [
        tuple(row)
        for row in conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        )
    ]
    tables = [row[1] for row in objects if row[0] == "table"]
    rows = {}
    for table in tables:
        escaped = table.replace('"', '""')
        values = [tuple(row) for row in conn.execute(f'SELECT * FROM "{escaped}"')]
        rows[table] = sorted(values, key=repr)
    snapshot = {
        "objects": objects,
        "rows": rows,
        "foreign_key_check": [tuple(row) for row in conn.execute("PRAGMA foreign_key_check")],
        "integrity_check": conn.execute("PRAGMA integrity_check").fetchone()[0],
    }
    conn.close()
    return snapshot


class R25IntegratedRegressionTests(unittest.TestCase):
    def test_project_create_omitted_aliases_uses_empty_canonical_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("project-user", "project-phone", "phone")
            status, _headers, payload = RecorderService(store).handle_http(
                "POST",
                "/v1/projects",
                {"Content-Type": "application/json"},
                json.dumps(
                    {
                        "user_id": "project-user",
                        "device_id": "project-phone",
                        "project_number": "P-1",
                        "name": "Project one",
                    }
                ).encode(),
            )
            self.assertEqual(status, 201)
            self.assertEqual(payload["aliases"], [])

    def test_audio_duration_is_derived_and_frame_boundary_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data", max_audio_minutes=1)

            def create_audio_turn(turn_id: str, frames: int) -> bytes:
                manifest = {
                    "schema_version": 1,
                    "user_id": "audio-user",
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
                    handle.writeframes(b"\x00\x00" * frames)
                audio = wav_buffer.getvalue()
                starts = range(0, len(audio), store.max_chunk_bytes)
                for sequence, start in enumerate(starts):
                    store.put_chunk(turn_id, "audio", sequence, audio[start : start + store.max_chunk_bytes])
                return audio, (len(audio) + store.max_chunk_bytes - 1) // store.max_chunk_bytes

            audio, total_chunks = create_audio_turn("018f5a2e-7b6e-7abc-8d11-1234567890b1", 160)
            result = store.finish_part(
                "018f5a2e-7b6e-7abc-8d11-1234567890b1",
                "audio",
                total_chunks=total_chunks,
                total_bytes=len(audio),
                whole_stream_sha256=hashlib.sha256(audio).hexdigest(),
                duration_ms=11,
            )
            self.assertEqual(result["duration_ms"], 10)

            oversized, total_chunks = create_audio_turn("018f5a2e-7b6e-7abc-8d11-1234567890b2", 960001)
            with self.assertRaises(Exception) as raised:
                store.finish_part(
                    "018f5a2e-7b6e-7abc-8d11-1234567890b2",
                    "audio",
                    total_chunks=total_chunks,
                    total_bytes=len(oversized),
                    whole_stream_sha256=hashlib.sha256(oversized).hexdigest(),
                )
            self.assertEqual(getattr(raised.exception, "code", None), "QUOTA_EXCEEDED")

    def test_diagnostic_purge_removes_expired_content_rows_after_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(
                root / "db.sqlite3",
                storage_root=root / "data",
                diagnostics_retention_seconds=1,
                diagnostics_tombstone_retention_seconds=10,
            )
            store.register_device("diag-user", "diag-phone", "phone")
            opt_in = store.record_diagnostics_opt_in("diag-user", "diag-phone", event_id="diag-opt", now="2026-09-01T00:00:00Z")
            event = store.ingest_diagnostic_event(
                "diag-user",
                "diag-phone",
                event_id="diag-event",
                idempotency_key="diag-event",
                payload={"category": "voice", "stage": "upload"},
                now="2026-09-01T00:00:00Z",
            )
            bundle = store.ingest_diagnostic_bundle(
                "diag-user",
                "diag-phone",
                "diag-bundle",
                zlib.compress(b'{"category":"voice","stage":"upload"}'),
                opt_in_event_id=opt_in["event_id"],
                now="2026-09-01T00:00:00Z",
            )
            first = store.purge_diagnostics(now="2026-09-01T00:00:02Z")
            self.assertEqual((first["events"], first["bundles"]), (1, 1))
            with store._read() as conn:
                self.assertIsNotNone(conn.execute("SELECT 1 FROM diagnostic_events WHERE event_id=?", (event["event_id"],)).fetchone())
                self.assertIsNotNone(conn.execute("SELECT 1 FROM diagnostic_bundles WHERE bundle_id=?", (bundle["bundle_id"],)).fetchone())
            second = store.purge_diagnostics(now="2026-09-01T00:00:20Z")
            self.assertGreaterEqual(second.get("tombstones", 0), 2)
            with store._read() as conn:
                self.assertIsNone(conn.execute("SELECT 1 FROM diagnostic_events WHERE event_id=?", (event["event_id"],)).fetchone())
                self.assertIsNone(conn.execute("SELECT 1 FROM diagnostic_bundles WHERE bundle_id=?", (bundle["bundle_id"],)).fetchone())

    def test_diagnostic_tombstones_scrub_owner_and_event_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(
                root / "db.sqlite3",
                storage_root=root / "data",
                diagnostics_retention_seconds=1,
                diagnostics_tombstone_retention_seconds=10,
            )
            store.register_device("opaque-user", "opaque-phone", "phone")
            store.record_diagnostics_opt_in("opaque-user", "opaque-phone", event_id="opaque-opt", now="2026-09-01T00:00:00Z")
            event_result = store.ingest_diagnostic_event(
                "opaque-user",
                "opaque-phone",
                event_id="opaque-event",
                idempotency_key="opaque-event",
                payload={"category": "voice", "stage": "upload"},
                now="2026-09-01T00:00:00Z",
            )
            store.purge_diagnostics(now="2026-09-01T00:00:02Z", _recover_cleanup=False)
            with store._read() as conn:
                event = conn.execute("SELECT category, stage, metadata_json FROM diagnostic_events WHERE event_id=?", (event_result["event_id"],)).fetchone()
                tombstone = conn.execute("SELECT user_id, device_id, entity_id FROM diagnostic_tombstones WHERE entity_type='event' AND entity_id=?", (event_result["event_id"],)).fetchone()
            self.assertEqual((event["category"], event["stage"], event["metadata_json"]), ("other", "other", "{}"))
            self.assertIsNotNone(tombstone)
            self.assertNotIn("opaque-user", tombstone["user_id"])
            self.assertNotIn("opaque-phone", tombstone["device_id"])
            self.assertEqual(tombstone["entity_id"], event_result["event_id"])

    def test_cleanup_receipt_claim_is_single_owner_and_reclaims_after_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            target = root / "data" / "cleanup.bin"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"cleanup")
            receipt_id = store._prepare_cleanup_receipt(
                operation="integrated_claim_test",
                path=target,
                expected_sha256=hashlib.sha256(b"cleanup").hexdigest(),
                expected_size=7,
                now="2026-09-01T00:00:00Z",
            )
            first = store._features._claim_cleanup_receipt(receipt_id, now="2026-09-01T00:00:00Z")
            second = store._features._claim_cleanup_receipt(receipt_id, now="2026-09-01T00:00:01Z")
            reclaimed = store._features._claim_cleanup_receipt(receipt_id, now="2026-09-01T00:05:01Z")
            self.assertIsNotNone(first)
            self.assertIsNone(second)
            self.assertIsNotNone(reclaimed)
            self.assertNotEqual(first, reclaimed)

    def test_http_rejects_new_work_after_shutdown_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = RecorderService(RecorderStore(root / "db.sqlite3", storage_root=root / "data"))
            service.request_shutdown()
            status, _headers, payload = service.handle_http("GET", "/v1/health", {}, b"")
            self.assertEqual(status, 503)
            self.assertEqual(payload["error"]["code"], "SERVICE_STOPPING")

    def test_audio_finish_replay_without_duration_uses_trusted_derived_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ac"
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
            digest = hashlib.sha256(audio).hexdigest()
            store.put_chunk(turn_id, "audio", 0, audio)
            first = store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=digest,
            )
            replay = store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=digest,
            )
            self.assertEqual(first["duration_ms"], 10)
            self.assertEqual(replay["duration_ms"], first["duration_ms"])

    def test_audio_finish_legacy_missing_duration_is_repaired_or_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ad"
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
            digest = hashlib.sha256(audio).hexdigest()
            store.put_chunk(turn_id, "audio", 0, audio)
            first = store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=digest,
            )
            with store._tx() as conn:
                conn.execute("UPDATE turn_parts SET duration_ms=NULL WHERE turn_id=? AND part_id=?", (turn_id, "audio"))
            repaired = store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=digest,
            )
            self.assertEqual(repaired["duration_ms"], first["duration_ms"])

            with store._tx() as conn:
                conn.execute(
                    "UPDATE turn_parts SET duration_ms=NULL, source_deleted_at=? WHERE turn_id=? AND part_id=?",
                    ("2026-09-10T00:00:00+00:00", turn_id, "audio"),
                )
            with self.assertRaises(SourceUnavailableError):
                store.finish_part(
                    turn_id,
                    "audio",
                    total_chunks=1,
                    total_bytes=len(audio),
                    whole_stream_sha256=digest,
                )

    def test_audio_finish_publishes_with_cleanup_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ae"
            manifest = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": turn_id,
                "origin_device_id": "phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [{"part_id": "text", "kind": "text", "mime": "text/plain"}],
            }
            store.create_turn(manifest)
            payload = b"streamed finish"
            digest = hashlib.sha256(payload).hexdigest()
            store.put_chunk(turn_id, "text", 0, payload)
            real_link = store._features._link_staged

            def link_then_fail(*args, **kwargs):
                real_link(*args, **kwargs)
                raise RuntimeError("simulated post-publication failure")

            with patch.object(store._features, "_link_staged", side_effect=link_then_fail):
                with self.assertRaises(RuntimeError):
                    store.finish_part(
                        turn_id,
                        "text",
                        total_chunks=1,
                        total_bytes=len(payload),
                        whole_stream_sha256=digest,
                    )
            part_dir = next((root / "data" / "turns").glob("*/" + "*/parts/*"))
            self.assertFalse((part_dir / "part.bin").exists())
            with store._read() as conn:
                statuses = [row["status"] for row in conn.execute("SELECT status FROM storage_cleanup_receipts").fetchall()]
            self.assertTrue(statuses)
            self.assertTrue(all(status == "COMPLETE" for status in statuses))

    def test_schema4_fixture_is_the_pinned_public_preimage(self):
        content = SCHEMA4_FIXTURE.read_bytes()
        self.assertEqual(len(content), 19999)
        self.assertEqual(hashlib.sha256(content).hexdigest(), SCHEMA4_FIXTURE_SHA256)

    def test_sql_script_executor_preserves_transaction_and_sqlite_parsing(self):
        with sqlite3.connect(":memory:", isolation_level=None) as conn:
            conn.execute("BEGIN IMMEDIATE")
            RecorderStore._execute_sql_script(
                conn,
                "-- semicolon in a comment;\n"
                "CREATE TABLE parsed (value TEXT);\n"
                "INSERT INTO parsed VALUES ('quoted;semicolon');\n"
                "CREATE TABLE unterminated (value TEXT)\n"
                "/* final comment */",
            )
            self.assertEqual(conn.execute("SELECT value FROM parsed").fetchone()[0], "quoted;semicolon")
            self.assertEqual(
                [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")],
                ["parsed", "unterminated"],
            )
            conn.execute("ROLLBACK")
            with self.assertRaisesRegex(RuntimeError, "active transaction"):
                RecorderStore._execute_sql_script(conn, "CREATE TABLE inactive (value TEXT);")
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(sqlite3.OperationalError):
                RecorderStore._execute_sql_script(conn, "CREATE TABLE malformed (")
            conn.execute("ROLLBACK")

    def test_schema_preparation_failure_after_real_r25_rolls_back_pre_a_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            before = _logical_database_snapshot(db_path)
            original = RecorderStore._apply_r25_migration

            def fail_after_real_work(conn):
                original(conn)
                raise RuntimeError("injected-after-real-r25")

            with patch.object(RecorderStore, "_apply_r25_migration", staticmethod(fail_after_real_work)):
                with self.assertRaisesRegex(RuntimeError, "injected-after-real-r25"):
                    RecorderStore(db_path, storage_root=root / "data")

            self.assertEqual(_logical_database_snapshot(db_path), before)
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertEqual(conn.execute("SELECT device_id FROM devices WHERE device_id='sentinel-device'").fetchone()[0], "sentinel-device")
            migrated = RecorderStore(db_path, storage_root=root / "data")
            with migrated._read() as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "5")
                self.assertIsNotNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_run_bindings'").fetchone())
            restarted = RecorderStore(db_path, storage_root=root / "data")
            with restarted._read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices WHERE device_id='sentinel-device'").fetchone()[0], 1)

    def test_historical_migration_failure_rolls_back_script_and_alters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            initial = root / "initial.sql"
            initial.write_text(
                (Path(__file__).parents[1] / "migrations" / "001_initial.sql").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            _seed_migration_fixture(db_path, initial, version=1)
            before = _logical_database_snapshot(db_path)
            real_connect = sqlite3.connect
            created = []

            class FailingScheduleConnection(sqlite3.Connection):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.closed_for_test = False

                def execute(self, sql, parameters=()):
                    if "idx_schedule_occurrences_due" in str(sql):
                        raise RuntimeError("injected-mid-scheduled-script")
                    return super().execute(sql, parameters)

                def close(self):
                    self.closed_for_test = True
                    return super().close()

            def connect(*args, **kwargs):
                kwargs["factory"] = FailingScheduleConnection
                conn = real_connect(*args, **kwargs)
                created.append(conn)
                return conn

            with patch("recorder_next.store.sqlite3.connect", side_effect=connect):
                with self.assertRaisesRegex(RuntimeError, "injected-mid-scheduled-script"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertTrue(created[0].closed_for_test)
            self.assertEqual(_logical_database_snapshot(db_path), before)

    def test_schema_preparation_commit_refusal_restores_pre_a_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            before = _logical_database_snapshot(db_path)
            real_connect = sqlite3.connect
            created = []

            class FailingInitialCommitConnection(sqlite3.Connection):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.commit_attempts = 0
                    self.closed_for_test = False

                def execute(self, sql, parameters=()):
                    if str(sql).strip().upper() == "COMMIT":
                        self.commit_attempts += 1
                        if self.commit_attempts == 1:
                            raise RuntimeError("injected-initial-commit")
                    return super().execute(sql, parameters)

                def close(self):
                    self.closed_for_test = True
                    return super().close()

            def connect(*args, **kwargs):
                kwargs["factory"] = FailingInitialCommitConnection
                conn = real_connect(*args, **kwargs)
                created.append(conn)
                return conn

            with patch("recorder_next.store.sqlite3.connect", side_effect=connect):
                with self.assertRaisesRegex(RuntimeError, "injected-initial-commit"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertTrue(created[0].closed_for_test)
            self.assertEqual(_logical_database_snapshot(db_path), before)

    def test_final_marker_write_failure_leaves_committed_schema4_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            real_connect = sqlite3.connect
            created = []

            class FailingFinalMarkerConnection(sqlite3.Connection):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.closed_for_test = False

                def execute(self, sql, parameters=()):
                    if (
                        str(sql).strip().upper() == "UPDATE SCHEMA_META SET VALUE=? WHERE KEY='SCHEMA_VERSION'"
                        and tuple(parameters) == ("5",)
                    ):
                        raise RuntimeError("injected-final-marker-write")
                    return super().execute(sql, parameters)

                def close(self):
                    self.closed_for_test = True
                    return super().close()

            def connect(*args, **kwargs):
                kwargs["factory"] = FailingFinalMarkerConnection
                conn = real_connect(*args, **kwargs)
                created.append(conn)
                return conn

            with patch("recorder_next.store.sqlite3.connect", side_effect=connect), patch.object(
                RecorderStore, "_migrate_c7_diagnostics", return_value=True
            ):
                with self.assertRaisesRegex(RuntimeError, "injected-final-marker-write"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertTrue(created[0].closed_for_test)
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertIsNotNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_run_bindings'").fetchone())

    def test_unsupported_version_rejection_rolls_back_bootstrap_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=6)
            before = _logical_database_snapshot(db_path)
            with self.assertRaisesRegex(RuntimeError, "unsupported Recorder schema version 6"):
                RecorderStore(db_path, storage_root=root / "data")
            self.assertEqual(_logical_database_snapshot(db_path), before)

    def test_c7_starts_after_committed_schema_checkpoint_and_exception_preserves_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            observations = []

            def fail_c7(conn, *, force):
                observations.append((conn.in_transaction, force))
                raise RuntimeError("injected-c7-failure")

            with patch.object(RecorderStore, "_migrate_c7_diagnostics", side_effect=fail_c7):
                with self.assertRaisesRegex(RuntimeError, "injected-c7-failure"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertEqual(observations, [(False, True)])
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertIsNotNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_run_bindings'").fetchone())
            resumed = RecorderStore(db_path, storage_root=root / "data")
            with resumed._read() as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "5")

    def test_final_marker_commit_failure_rolls_back_to_schema4_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            real_connect = sqlite3.connect
            created = []

            class FailingFinalCommitConnection(sqlite3.Connection):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.commit_attempts = 0
                    self.closed_for_test = False

                def execute(self, sql, parameters=()):
                    if str(sql).strip().upper() == "COMMIT":
                        self.commit_attempts += 1
                        if self.commit_attempts == 2:
                            raise RuntimeError("injected-final-commit")
                    return super().execute(sql, parameters)

                def close(self):
                    self.closed_for_test = True
                    return super().close()

            def connect(*args, **kwargs):
                kwargs["factory"] = FailingFinalCommitConnection
                conn = real_connect(*args, **kwargs)
                created.append(conn)
                return conn

            with patch("recorder_next.store.sqlite3.connect", side_effect=connect), patch.object(
                RecorderStore, "_migrate_c7_diagnostics", return_value=True
            ):
                with self.assertRaisesRegex(RuntimeError, "injected-final-commit"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertTrue(created[0].closed_for_test)
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertIsNotNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_run_bindings'").fetchone())

    def test_connect_closes_acquired_connection_when_pragma_setup_fails(self):
        real_connect = sqlite3.connect

        class FailingPragmaConnection(sqlite3.Connection):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.closed_for_test = False

            def execute(self, sql, parameters=()):
                if str(sql).strip().upper() == "PRAGMA JOURNAL_MODE = WAL":
                    raise RuntimeError("injected-journal-mode")
                return super().execute(sql, parameters)

            def close(self):
                self.closed_for_test = True
                return super().close()

        conn = real_connect(":memory:", factory=FailingPragmaConnection, isolation_level=None)
        instance = RecorderStore.__new__(RecorderStore)
        instance.db_path = ":memory:"
        with patch("recorder_next.store.sqlite3.connect", return_value=conn):
            with self.assertRaisesRegex(RuntimeError, "injected-journal-mode"):
                instance._connect()
        self.assertTrue(conn.closed_for_test)

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

    def test_history_requery_uses_canonical_request_hash_not_ingress_envelope_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890a1"
            service.store.get_turn = lambda _turn_id: {
                "turn_id": turn_id,
                "final_event_version": 1,
                "final_content": None,
                "final_outcome": None,
            }

            first = HermesResult(
                "assistant-1", "first", True, "hermes-history", submission_id="submission-1",
                turn_id=turn_id, marker="marker-1", session_key="session-1", run_id="run-1",
                request_sha256="request-hash", subject_kind="turn",
            )
            second = HermesResult(
                "assistant-2", "second", True, "hermes-run", submission_id="submission-1",
                turn_id=turn_id, marker="marker-1", session_key="session-1", run_id="run-1",
                request_sha256="request-hash", subject_kind="turn",
            )

            class HistoryGateway:
                def history_messages(self, *, session_key, marker):
                    self.seen = (session_key, marker)
                    return [first]

            service.hermes = HistoryGateway()
            ingress = {
                "turn_id": turn_id,
                "hermes_submission_id": "submission-1",
                "marker": "marker-1",
                "gateway_session_key": "session-1",
                "run_id": "run-1",
                "payload_sha256": "envelope-hash",
            }
            self.assertEqual(service._requery_combined_content(ingress, second), "first\nsecond")

    def test_update_manifest_rejects_same_size_source_mutation_during_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "candidate.apk"
            source.write_bytes(b"original")
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            features = store._features
            publish_stream = features._publish_stream

            def mutate_source_then_publish(*args, **kwargs):
                source.write_bytes(b"mutated!")
                return publish_stream(*args, **kwargs)

            features._publish_stream = mutate_source_then_publish
            try:
                with self.assertRaises(ConflictError):
                    store.publish_update_manifest(
                        channel="mutation",
                        generation=1,
                        platform="phone",
                        version="1.0.0",
                        version_code=1,
                        artifact_name="candidate.apk",
                        artifact_path=source,
                        signer_digest="a" * 64,
                        changelog="change",
                        min_server_version="1.0.0",
                        authorization_policy="test-only",
                    )
            finally:
                features._publish_stream = publish_stream
            with store._read() as conn:
                self.assertIsNone(conn.execute("SELECT 1 FROM update_manifests WHERE channel=?", ("mutation",)).fetchone())


if __name__ == "__main__":
    unittest.main()
