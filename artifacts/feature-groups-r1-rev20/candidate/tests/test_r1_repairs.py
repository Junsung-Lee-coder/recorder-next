import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from recorder_next.models import RouterDecision, TTSResult
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


BASE_TURN = {
    "schema_version": 1,
    "user_id": "repair-user",
    "origin_device_id": "repair-phone",
    "client_created_at": "2026-08-25T00:00:00Z",
    "current_project_number": None,
    "prefer_current_project": False,
}


def manifest(turn_id, parts):
    return {**BASE_TURN, "turn_id": turn_id, "parts": parts}


def text_part(part_id="text-1", declared_bytes=1):
    return {
        "part_id": part_id,
        "kind": "text",
        "mime": "text/plain",
        "declared_bytes": declared_bytes,
        "declared_sha256": hashlib.sha256(b"x").hexdigest(),
        "relationship": None,
        "caption_hash": None,
    }


class RecorderR1RepairTests(unittest.TestCase):
    def test_late_non_origin_relay_preserves_played_journal_after_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            store.register_device("relay-user", "relay-phone", "phone")
            store.register_device("relay-user", "relay-watch", "watch")
            turn_id = "018f5a2e-7b6e-7abc-8d11-123456789901"
            service.accept_text_turn(
                {
                    "schema_version": 1,
                    "user_id": "relay-user",
                    "turn_id": turn_id,
                    "origin_device_id": "relay-phone",
                    "client_created_at": "2026-08-25T00:00:00Z",
                },
                "relay fixture",
            )
            project = store.create_project("relay-user", project_number="P-1", name="Relay")
            store.commit_route(
                turn_id,
                RouterDecision(
                    "route-1",
                    project["stable_project_id"],
                    project["default_session_key"],
                    project["record_version"],
                    "routed",
                    "test",
                ),
            )
            artifact = store.get_turn(turn_id)["tts_artifacts"][0]
            ready = store.set_tts_result(artifact["artifact_id"], TTSResult(b"audio"))
            store.ack_playback(
                artifact["artifact_id"],
                device_id="relay-phone",
                payload_sha256=ready["payload_sha256"],
                turn_id=turn_id,
                artifact_version=artifact["artifact_version"],
            )

            status, _, response = service.handle_http(
                "POST",
                f"/v1/tts/{artifact['artifact_id']}/relay-received",
                {},
                json.dumps(
                    {
                        "device_id": "relay-watch",
                        "payload_sha256": ready["payload_sha256"],
                    }
                ).encode("utf-8"),
            )
            self.assertEqual(status, 200)
            self.assertEqual(response["status"], "PLAYED")
            with store._read() as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT state FROM playback_journal WHERE artifact_id=?",
                        (artifact["artifact_id"],),
                    ).fetchone()[0],
                    "PLAYED",
                )

            reopened = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            with reopened._read() as conn:
                journal = conn.execute(
                    "SELECT state FROM playback_journal WHERE artifact_id=?",
                    (artifact["artifact_id"],),
                ).fetchone()
            self.assertIsNotNone(journal)
            self.assertEqual(journal["state"], "PLAYED")

    def test_missing_ranges_reject_oversized_total_chunks_with_bounded_4xx(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            turn_id = "018f5a2e-7b6e-7abc-8d11-123456789902"
            store.create_turn(manifest(turn_id, [text_part()]))

            status, _, response = service.handle_http(
                "GET",
                f"/v1/turns/{turn_id}/parts/text-1/missing?total_chunks=100000",
                {},
                b"",
            )
            self.assertEqual(status, 400)
            self.assertEqual(response["error"]["code"], "VALIDATION_ERROR")
            self.assertLess(len(json.dumps(response)), 1024)

    def test_default_audio_contract_accepts_7200_missing_query_with_bounded_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            turn_id = "018f5a2e-7b6e-7abc-8d11-123456789904"
            store.create_turn(
                manifest(
                    turn_id,
                    [
                        {
                            "part_id": "audio-1",
                            "kind": "audio",
                            "mime": "audio/pcm",
                            "declared_bytes": None,
                            "declared_sha256": None,
                            "streaming": True,
                        }
                    ],
                )
            )

            status, _, response = service.handle_http(
                "GET",
                f"/v1/turns/{turn_id}/parts/audio-1/missing?total_chunks=7200",
                {},
                b"",
            )
            self.assertEqual(status, 200)
            self.assertEqual(response["total_missing"], 7200)
            self.assertEqual(response["missing"], list(range(response["limit"])))
            self.assertIsNotNone(response["next_offset"])
            self.assertLess(len(json.dumps(response)), 20000)

    def test_missing_ranges_reconstruct_lossless_7200_chunks_and_paginate(self):
        def collect_ranges(store, turn_id, *, offset=0, limit=1024):
            reconstructed = []
            pages = 0
            while True:
                response = store.missing_sequence_page(
                    turn_id,
                    "audio-1",
                    total_chunks=7200,
                    offset=offset,
                    limit=limit,
                    encoding="ranges",
                )
                pages += 1
                for item in response["missing_ranges"]:
                    reconstructed.extend(range(item["start"], item["end"] + 1))
                if response["next_offset"] is None:
                    return response, reconstructed, pages
                self.assertEqual(response["next_offset"], offset + len(response["missing_ranges"]))
                offset = response["next_offset"]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            audio_part = {
                "part_id": "audio-1",
                "kind": "audio",
                "mime": "audio/pcm",
                "declared_bytes": None,
                "declared_sha256": None,
                "streaming": True,
            }
            all_missing_turn = "018f5a2e-7b6e-7abc-8d11-123456789905"
            store.create_turn(manifest(all_missing_turn, [audio_part]))
            response, reconstructed, pages = collect_ranges(store, all_missing_turn)
            self.assertEqual(response["total_missing"], 7200)
            self.assertEqual(reconstructed, list(range(7200)))
            self.assertEqual(pages, 1)

            paginated_turn = "018f5a2e-7b6e-7abc-8d11-123456789906"
            store.create_turn(manifest(paginated_turn, [audio_part]))
            present = set(range(2, 7200, 3))
            with store._tx() as conn:
                conn.executemany(
                    "INSERT INTO turn_chunks(turn_id, part_id, sequence, byte_length, sha256, storage_path, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [
                        (paginated_turn, "audio-1", sequence, 1, "a" * 64, f"fixture-{sequence}", "2026-08-25T00:00:00Z")
                        for sequence in sorted(present)
                    ],
                )
            response, reconstructed, pages = collect_ranges(store, paginated_turn)
            expected = [sequence for sequence in range(7200) if sequence not in present]
            self.assertEqual(response["total_missing"], len(expected))
            self.assertEqual(reconstructed, expected)
            self.assertGreater(pages, 1)

    def test_finish_http_rejects_non_native_integer_values_without_mutation(self):
        cases = [
            ("total_chunks", "1"),
            ("total_chunks", True),
            ("total_chunks", 1.5),
            ("total_bytes", "1"),
            ("duration_ms", "1000"),
            ("duration_ms", True),
            ("duration_ms", 1.5),
        ]
        for index, (field, value) in enumerate(cases):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
                service = RecorderService(store)
                turn_id = f"018f5a2e-7b6e-7abc-8d11-12345678994{index}"
                part_id = "audio-1" if field == "duration_ms" else "text-1"
                kind = "audio" if field == "duration_ms" else "text"
                store.create_turn(manifest(turn_id, [{"part_id": part_id, "kind": kind, "mime": "audio/pcm" if kind == "audio" else "text/plain", "declared_bytes": 1, "declared_sha256": hashlib.sha256(b"x").hexdigest()}]))
                store.put_chunk(turn_id, part_id, 0, b"x")
                finish = {"total_chunks": 1, "total_bytes": 1, "whole_stream_sha256": hashlib.sha256(b"x").hexdigest()}
                finish[field] = value
                status, _, response = service.handle_http("POST", f"/v1/turns/{turn_id}/parts/{part_id}/finish", {}, json.dumps(finish).encode("utf-8"))
                self.assertEqual(status, 400)
                self.assertEqual(response["error"]["code"], "VALIDATION_ERROR")
                part = store.get_turn(turn_id)["parts"][0]
                self.assertEqual(part["status"], "RECEIVING")
                self.assertIsNone(part["total_chunks"])

    def test_non_integer_descriptor_numbers_are_rejected_before_persistence(self):
        bad_values = ["10", True, 1.5]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            for index, bad_value in enumerate(bad_values):
                with self.subTest(field="declared_bytes", value=bad_value):
                    turn_id = f"018f5a2e-7b6e-7abc-8d11-12345678991{index}"
                    status, _, response = service.handle_http(
                        "POST",
                        "/v1/turns",
                        {},
                        json.dumps(manifest(turn_id, [text_part(declared_bytes=bad_value)])).encode("utf-8"),
                    )
                    self.assertEqual(status, 400)
                    self.assertEqual(response["error"]["code"], "VALIDATION_ERROR")
            self.assertEqual(store.db_snapshot()["turns"], 0)
            self.assertFalse((root / "data" / "turns").exists())

    def test_non_integer_audio_duration_is_rejected_before_persistence(self):
        bad_values = ["10", True, 1.5]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            for index, bad_value in enumerate(bad_values):
                with self.subTest(field="duration_ms", value=bad_value):
                    turn_id = f"018f5a2e-7b6e-7abc-8d11-12345678993{index}"
                    part = {
                        "part_id": "audio-1",
                        "kind": "audio",
                        "mime": "audio/wav",
                        "declared_bytes": 1,
                        "declared_sha256": "0" * 64,
                        "duration_ms": bad_value,
                    }
                    status, _, response = service.handle_http(
                        "POST",
                        "/v1/turns",
                        {},
                        json.dumps(manifest(turn_id, [part])).encode("utf-8"),
                    )
                    self.assertEqual(status, 400)
                    self.assertEqual(response["error"]["code"], "VALIDATION_ERROR")
            self.assertEqual(store.db_snapshot()["turns"], 0)

    def test_empty_regular_manifest_is_rejected_without_a_zombie_turn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            turn_id = "018f5a2e-7b6e-7abc-8d11-123456789903"
            status, _, response = service.handle_http(
                "POST",
                "/v1/turns",
                {},
                json.dumps(manifest(turn_id, [])).encode("utf-8"),
            )
            self.assertEqual(status, 400)
            self.assertEqual(response["error"]["code"], "VALIDATION_ERROR")
            self.assertEqual(store.db_snapshot()["turns"], 0)
            self.assertFalse((root / "data" / "turns").exists())

    def test_text_convenience_path_rejects_every_non_string_json_value(self):
        values = [None, {"unexpected": True}, ["unexpected"], 7, True]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            for index, value in enumerate(values):
                with self.subTest(value=value):
                    turn_id = f"018f5a2e-7b6e-7abc-8d11-12345678992{index}"
                    payload = {
                        "schema_version": 1,
                        "user_id": "text-user",
                        "turn_id": turn_id,
                        "origin_device_id": "text-phone",
                        "client_created_at": "2026-08-25T00:00:00Z",
                        "text": value,
                    }
                    status, _, response = service.handle_http(
                        "POST",
                        "/v1/turns",
                        {},
                        json.dumps(payload).encode("utf-8"),
                    )
                    self.assertEqual(status, 400)
                    self.assertEqual(response["error"]["code"], "VALIDATION_ERROR")
            self.assertEqual(store.db_snapshot()["turns"], 0)


if __name__ == "__main__":
    unittest.main()
