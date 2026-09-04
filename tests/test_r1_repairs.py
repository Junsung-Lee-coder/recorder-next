import hashlib
import http.client
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from recorder_next.adapters import HermesAudioASRProvider, HermesAudioTTSProvider, HttpASRProvider, HttpHermesGateway, HttpTTSProvider
from recorder_next.errors import UnauthorizedError
from recorder_next.http import create_http_server
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
                        "user_id": "relay-user",
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
            store.register_device("repair-user", "repair-phone", "phone")
            store.create_turn(manifest(turn_id, [text_part()]))

            status, _, response = service.handle_http(
                "GET",
                f"/v1/turns/{turn_id}/parts/text-1/missing?total_chunks=100000&user_id=repair-user&device_id=repair-phone",
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
            store.register_device("repair-user", "repair-phone", "phone")
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
                f"/v1/turns/{turn_id}/parts/audio-1/missing?total_chunks=7200&user_id=repair-user&device_id=repair-phone",
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
                store.register_device("repair-user", "repair-phone", "phone")
                turn_id = f"018f5a2e-7b6e-7abc-8d11-12345678994{index}"
                part_id = "audio-1" if field == "duration_ms" else "text-1"
                kind = "audio" if field == "duration_ms" else "text"
                store.create_turn(manifest(turn_id, [{"part_id": part_id, "kind": kind, "mime": "audio/pcm" if kind == "audio" else "text/plain", "declared_bytes": 1, "declared_sha256": hashlib.sha256(b"x").hexdigest()}]))
                store.put_chunk(turn_id, part_id, 0, b"x")
                finish = {"total_chunks": 1, "total_bytes": 1, "whole_stream_sha256": hashlib.sha256(b"x").hexdigest()}
                finish[field] = value
                status, _, response = service.handle_http("POST", f"/v1/turns/{turn_id}/parts/{part_id}/finish?user_id=repair-user&device_id=repair-phone", {}, json.dumps(finish).encode("utf-8"))
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

    def test_private_turn_and_outbox_routes_require_registered_exact_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            store.register_device("victim", "shared-phone", "phone")
            store.register_device("attacker", "shared-phone", "phone")
            turn_id = "018f5a2e-7b6e-7abc-8d11-123456789981"
            turn_manifest = {
                **manifest(turn_id, [text_part(declared_bytes=1)]),
                "user_id": "victim",
                "origin_device_id": "shared-phone",
            }
            store.create_turn(turn_manifest)
            store.put_chunk(turn_id, "text-1", 0, b"x")
            store.finish_part(
                turn_id,
                "text-1",
                total_chunks=1,
                total_bytes=1,
                whole_stream_sha256=hashlib.sha256(b"x").hexdigest(),
            )
            store.accept_turn(turn_id)

            with self.assertRaises(UnauthorizedError):
                store.pending_outbox("shared-phone")

            for target in (
                f"/v1/turns/{turn_id}",
                f"/v1/turns/{turn_id}/parts/text-1/missing",
                "/v1/outbox",
            ):
                status, _, response = service.handle_http("GET", target, {}, b"")
                with self.subTest(target=target, identity="missing"):
                    self.assertEqual(status, 401, response)
            status, _, _ = service.handle_http(
                "GET",
                f"/v1/turns/{turn_id}?user_id=attacker&device_id=shared-phone",
                {},
                b"",
            )
            self.assertEqual(status, 401)
            status, _, response = service.handle_http(
                "GET",
                f"/v1/outbox?user_id=attacker&device_id=shared-phone",
                {},
                b"",
            )
            self.assertEqual(status, 200, response)
            self.assertEqual(response["items"], [])
            status, _, response = service.handle_http(
                "GET",
                f"/v1/turns/{turn_id}?user_id=victim&device_id=shared-phone",
                {},
                b"",
            )
            self.assertEqual(status, 200, response)
            store.revoke_device("victim", "shared-phone")
            status, _, _ = service.handle_http(
                "GET",
                "/v1/outbox?user_id=victim&device_id=shared-phone",
                {},
                b"",
            )
            self.assertEqual(status, 401)

            unregistered_id = "018f5a2e-7b6e-7abc-8d11-123456789982"
            unregistered_manifest = {
                **manifest(unregistered_id, [text_part(declared_bytes=1)]),
                "user_id": "new-user",
                "origin_device_id": "new-device",
            }
            status, _, _ = service.handle_http("POST", "/v1/turns", {}, json.dumps(unregistered_manifest).encode())
            self.assertEqual(status, 401)

    def test_network_delete_diagnostics_forwards_and_returns_tombstone_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            store.register_device("diag-user", "diag-phone", "phone")
            store.record_diagnostics_opt_in("diag-user", "diag-phone", event_id="consent-g2")
            store.ingest_diagnostic_event(
                "diag-user",
                "diag-phone",
                event_id="diag-event-g2",
                idempotency_key="diag-idem-g2",
                payload={"category": "transport", "stage": "test", "status": "ok"},
            )
            server = create_http_server(service, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                host, port = server.server_address
                connection = http.client.HTTPConnection(host, port, timeout=2)
                connection.request("DELETE", "/v1/diagnostics?user_id=diag-user&device_id=diag-phone")
                response = connection.getresponse()
                payload = json.loads(response.read().decode())
                self.assertEqual(response.status, 200, payload)
                self.assertEqual(payload, {"events": 1, "bundles": 0, "tombstones": 1})
                connection.request("GET", "/v1/diagnostics/export?user_id=diag-user&device_id=diag-phone")
                readback = json.loads(connection.getresponse().read().decode())
                self.assertEqual(readback["items"], [])
                self.assertEqual(len(readback["tombstones"]), 1)
                self.assertEqual(readback["tombstones"][0]["entity_id"], "diag-event-g2")
                self.assertEqual(readback["tombstones"][0]["entity_type"], "event")
                connection.close()
            finally:
                server.shutdown()
                server.server_close()

    def test_device_revoke_requires_an_active_actor_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = RecorderService(RecorderStore(root / "db.sqlite3", storage_root=root / "data"))
            service.store.register_device("revoke-user", "target", "watch")
            status, _, _ = service.handle_http(
                "POST",
                "/v1/devices/target/revoke",
                {},
                json.dumps({"user_id": "revoke-user", "actor_device_id": "attacker"}).encode(),
            )
            self.assertEqual(status, 401)
            self.assertEqual(service.store.get_device("revoke-user", "target")["status"], "active")

    def test_openapi_declares_all_path_variables_and_exact_worker_run_contract(self):
        from recorder_next.openapi import OPENAPI, validate_openapi_contract

        validate_openapi_contract(OPENAPI)
        self.assertNotIn("/v1/internal/worker/{action}", OPENAPI["paths"])
        self.assertIn("/v1/internal/worker/run", OPENAPI["paths"])

    def test_raw_socket_rejects_ambiguous_content_length_and_closes_connection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = create_http_server(RecorderService(RecorderStore(root / "db.sqlite3", storage_root=root / "data")), port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                host, port = server.server_address
                cases = [
                    (b"Content-Length: nope\r\n", 400),
                    (b"Content-Length: -1\r\n", 400),
                    (b"Content-Length: 1, 1\r\n", 400),
                    (b"Content-Length: 1\r\nContent-Length: 1\r\n", 400),
                    (b"Content-Length: 16777217\r\n", 413),
                    (b"Content-Length: " + b"9" * 5000 + b"\r\n", 413),
                ]
                for index, (length_header, expected_status) in enumerate(cases):
                    with self.subTest(index=index, header=length_header):
                        sock = socket.create_connection((host, port), timeout=2)
                        sock.settimeout(1)
                        sock.sendall(
                            b"POST /v1/turns HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n"
                            + length_header
                            + b"\r\n{}GET /v1/healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
                        )
                        chunks = []
                        while True:
                            try:
                                part = sock.recv(4096)
                            except socket.timeout as exc:
                                self.fail(f"framing response did not close the connection: {exc}")
                            if not part:
                                break
                            chunks.append(part)
                        raw = b"".join(chunks)
                        self.assertIn(f"HTTP/1.1 {expected_status}".encode(), raw)
                        self.assertIn(b"Connection: close", raw)
                        self.assertNotIn(b"200 OK", raw)
                        sock.close()
            finally:
                server.shutdown()
                server.server_close()

    def test_update_publication_rejects_parent_symlink_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            source = outside / "candidate.apk"
            source.write_bytes(b"outside-bytes")
            source_parent = root / "source-link"
            source_parent.symlink_to(outside, target_is_directory=True)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            with self.assertRaises(UnauthorizedError):
                store.publish_update_manifest(
                    channel="test",
                    generation=1,
                    platform="phone",
                    version="1.0.0",
                    version_code=1,
                    artifact_name="app.apk",
                    signer_digest="a" * 64,
                    changelog="test",
                    min_server_version="1.0.0",
                    authorization_policy="test-only",
                    artifact_path=source_parent / source.name,
                    expected_generation=0,
                )
            self.assertEqual(store.db_snapshot().get("update_manifests", 0), 0)

            source_root = root / "source-root"
            source_root.mkdir()
            traversal = source_root / ".." / "outside" / source.name
            with self.assertRaises(UnauthorizedError):
                store.publish_update_manifest(
                    channel="test",
                    generation=1,
                    platform="phone",
                    version="1.0.0",
                    version_code=1,
                    artifact_name="traversal.apk",
                    signer_digest="a" * 64,
                    changelog="test",
                    min_server_version="1.0.0",
                    authorization_policy="test-only",
                    artifact_path=traversal,
                    expected_generation=0,
                )
            self.assertEqual(store.db_snapshot().get("update_manifests", 0), 0)

    def test_diagnostics_delete_rejects_non_string_identity_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            store.register_device("7", "diag-device", "phone")
            store.record_diagnostics_opt_in("7", "diag-device", event_id="consent-types-g2")
            store.ingest_diagnostic_event(
                "7",
                "diag-device",
                event_id="diag-types-g2",
                idempotency_key="diag-types-idem-g2",
                payload={"category": "transport", "stage": "test"},
            )
            for method, target, payload in (
                ("POST", "/v1/diagnostics/delete", {"user_id": 7, "device_id": "diag-device"}),
                ("DELETE", "/v1/diagnostics", {"user_id": True, "device_id": "diag-device"}),
                ("DELETE", "/v1/diagnostics", {"user_id": "7", "device_id": None}),
            ):
                with self.subTest(method=method, payload=payload):
                    status, _, response = service.handle_http(method, target, {}, json.dumps(payload).encode())
                    self.assertEqual(status, 400, response)
            status, _, remaining = service.handle_http(
                "GET",
                "/v1/diagnostics?user_id=7&device_id=diag-device",
                {},
                b"",
            )
            self.assertEqual(status, 200, remaining)
            self.assertEqual(len(remaining["items"]), 1)

    def test_credential_bearing_adapters_do_not_follow_cross_origin_redirects(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", self.server.target)
                self.end_headers()

            def do_POST(self):
                self.do_GET()

            def log_message(self, *_args):
                return

        class SinkHandler(BaseHTTPRequestHandler):
            seen = []

            def do_GET(self):
                self.__class__.seen.append(dict(self.headers))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def do_POST(self):
                self.do_GET()

            def log_message(self, *_args):
                return

        with tempfile.TemporaryDirectory() as tmp:
            credential = Path(tmp) / "credential"
            credential.write_text("API_SERVER_KEY=secret-g2\n", encoding="utf-8")
            os.chmod(credential, 0o600)
            sink = __import__("http.server", fromlist=["ThreadingHTTPServer"]).ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
            redirect = __import__("http.server", fromlist=["ThreadingHTTPServer"]).ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
            redirect.target = f"http://127.0.0.1:{sink.server_address[1]}/sink"
            sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
            redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
            sink_thread.start()
            redirect_thread.start()
            endpoint = f"http://127.0.0.1:{redirect.server_address[1]}/provider"
            try:
                adapters = [
                    HttpASRProvider(endpoint, model="asr", credential_file=credential),
                    HttpTTSProvider(endpoint, model="tts", voice="voice", credential_file=credential),
                    HermesAudioASRProvider(endpoint, profile="default", credential_file=credential),
                    HermesAudioTTSProvider(endpoint, profile="default", credential_file=credential),
                    HttpHermesGateway(endpoint, api_key_file=credential),
                ]
                for adapter in adapters:
                    with self.subTest(adapter=type(adapter).__name__):
                        try:
                            if isinstance(adapter, (HttpASRProvider, HermesAudioASRProvider)):
                                adapter.transcribe(b"audio", turn_id="turn-g2", generation=1)
                            elif isinstance(adapter, (HttpTTSProvider, HermesAudioTTSProvider)):
                                adapter.synthesize("text", artifact_id="artifact-g2")
                            else:
                                adapter.submit(session_key="session-g2", request={"input": "text"}, submission_id="submission-g2", marker="marker-g2")
                        except Exception:
                            pass
                self.assertEqual(SinkHandler.seen, [])
            finally:
                redirect.shutdown()
                sink.shutdown()
                redirect.server_close()
                sink.server_close()


if __name__ == "__main__":
    unittest.main()
