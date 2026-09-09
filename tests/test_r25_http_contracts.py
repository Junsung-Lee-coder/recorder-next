import copy
import hashlib
import hmac
import json
import tempfile
import unittest
import uuid
from pathlib import Path

from recorder_next.http_contract import match_operation, project_response, route_catalog, validate_request, validate_response
from recorder_next.openapi import OPENAPI, validate_openapi_contract
from recorder_next.errors import NotFoundError, ValidationError
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


class R25HttpContractTests(unittest.TestCase):
    def test_catalog_is_authoritative_and_checked_in_coverage_is_generated(self):
        source = Path(__file__).parents[1].joinpath("recorder_next/http_contract.py").read_text()
        self.assertNotIn("from .openapi import", source)
        catalog = route_catalog()
        self.assertGreaterEqual(len(catalog), 59)
        self.assertEqual(len({(item.method, item.path_template) for item in catalog}), len(catalog))
        self.assertNotIn("ApiResponse", json.dumps(OPENAPI, sort_keys=True))
        coverage_path = Path(__file__).parents[1].joinpath("api/operation-coverage.json")
        coverage = json.loads(coverage_path.read_text())
        self.assertEqual(
            [(item["method"], item["path"]) for item in coverage["operations"]],
            [(item.method, item.path_template) for item in catalog],
        )

    def test_duplicate_query_parameters_are_declared_as_400_for_public_get_and_head_routes(self):
        routes = ("/v1/health", "/v1/openapi.json", "/healthz")
        for path in routes:
            for method in ("GET", "HEAD"):
                with self.subTest(path=path, method=method):
                    operation = match_operation(path, method)
                    self.assertIn(400, [response.status for response in operation.responses])
                    if method == "GET":
                        self.assertEqual(operation.response(400).schema_name, "Error")
                        self.assertEqual(operation.response(400).media_type, "application/json")
                    else:
                        self.assertTrue(operation.response(400).no_body)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            before = store.db_snapshot()
            for path in routes:
                for method in ("GET", "HEAD"):
                    with self.subTest(path=path, method=method, behavior=True):
                        status, headers, payload = service.handle_http(
                            method,
                            f"{path}?probe=1&probe=1",
                            {},
                            b"",
                        )
                        self.assertEqual(status, 400)
                        self.assertEqual(headers["Content-Type"], "application/json")
                        if method == "GET":
                            self.assertEqual(
                                payload,
                                {"error": {"code": "VALIDATION_ERROR", "message": "duplicate query parameters are not permitted"}},
                            )
                        else:
                            self.assertEqual(payload, b"")
            self.assertEqual(store.db_snapshot(), before)

    def test_openapi_validation_is_mutation_sensitive_to_routes_and_responses(self):
        missing_route = copy.deepcopy(OPENAPI)
        del missing_route["paths"]["/v1/turns"]
        with self.assertRaises(ValueError):
            validate_openapi_contract(missing_route)

        changed_response = copy.deepcopy(OPENAPI)
        changed_response["paths"]["/v1/turns"]["post"]["responses"]["201"]["content"] = {
            "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
        }
        with self.assertRaises(ValueError):
            validate_openapi_contract(changed_response)

    def test_signed_request_rejects_undeclared_fields_before_eavesdrop_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("contract-user", "contract-phone", "phone")
            service = RecorderService(store, ingress_secret="test-secret")
            headers = self._principal_headers("contract-user", "contract-phone", "test-secret")
            payload = {
                "user_id": "contract-user",
                "phone_device_id": "contract-phone",
                "unexpected": "must-not-reach-store",
            }
            before = store.db_snapshot()
            status, _headers, response = service.handle_http(
                "POST",
                "/v1/eavesdrop",
                headers,
                json.dumps(payload).encode(),
                peer_addr=("127.0.0.1", 1),
            )
            self.assertEqual(status, 400, response)
            self.assertEqual(response["error"]["code"], "VALIDATION_ERROR")
            self.assertEqual(store.db_snapshot(), before)

    def test_update_binary_and_head_response_contracts_are_exact(self):
        update = OPENAPI["paths"]["/v1/updates/{channel}/{generation}/{artifact_name}"]
        self.assertEqual(
            set(update["get"]["responses"]["200"]["content"]),
            {"application/vnd.android.package-archive"},
        )
        self.assertEqual(
            set(update["get"]["responses"]["206"]["content"]),
            {"application/vnd.android.package-archive"},
        )
        self.assertNotIn("content", update["get"]["responses"]["304"])
        self.assertNotIn("content", update["head"]["responses"]["200"])
        self.assertIn("ETag", update["get"]["responses"]["206"]["headers"])
        self.assertIn("Content-Range", update["get"]["responses"]["206"]["headers"])
        self.assertIn("Accept-Ranges", update["head"]["responses"]["200"]["headers"])
        for status, response in update["head"]["responses"].items():
            self.assertNotIn("content", response, status)
            self.assertTrue(response.get("x-no-body"), status)

    def test_binary_update_responses_and_head_errors_follow_the_runtime_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "candidate.apk"
            artifact.write_bytes(b"0123456789")
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.publish_update_manifest(
                channel="test",
                generation=1,
                platform="phone",
                version="1.2.3",
                version_code=12,
                artifact_name="recorder-phone.apk",
                artifact_path=artifact,
                signer_digest="a" * 64,
                changelog="feature",
                min_server_version="1.0.0",
                authorization_policy="test-only",
            )
            service = RecorderService(store)

            status, headers, payload = service.handle_http("GET", "/v1/updates/test/1/recorder-phone.apk", {}, b"")
            self.assertEqual((status, headers["Content-Type"], payload), (200, "application/vnd.android.package-archive", b"0123456789"))
            status, headers, payload = service.handle_http("GET", "/v1/updates/test/1/recorder-phone.apk", {"Range": "bytes=2-5"}, b"")
            self.assertEqual((status, headers["Content-Range"], payload), (206, "bytes 2-5/10", b"2345"))
            status, headers, payload = service.handle_http("GET", "/v1/updates/test/1/recorder-phone.apk", {"If-None-Match": "*"}, b"")
            self.assertEqual((status, headers["Content-Length"], payload), (304, "0", b""))
            status, headers, payload = service.handle_http("GET", "/v1/updates/test/1/recorder-phone.apk", {"Range": "bytes=99-100"}, b"")
            self.assertEqual((status, headers["Content-Range"], payload), (416, "bytes */10", b""))
            status, headers, payload = service.handle_http("HEAD", "/v1/updates/test/1/recorder-phone.apk", {}, b"")
            self.assertEqual((status, headers["Content-Length"], payload), (200, "10", b""))
            status, _headers, payload = service.handle_http("HEAD", "/v1/updates/test/1/missing.apk", {}, b"")
            self.assertEqual((status, payload), (404, b""))

    def test_required_catalog_parameters_are_rejected_before_network_handlers(self):
        operation = match_operation("/v1/internal/schedule_create", "POST")
        headers = {
            "X-Recorder-Principal-User": "user-1",
            "X-Recorder-Principal-Device": "phone-1",
            "X-Recorder-Principal-Signature": "proof",
            "Content-Type": "application/json",
        }
        with self.assertRaises(ValidationError):
            validate_request(
                operation,
                path="/v1/internal/schedule_create",
                query={},
                headers=headers,
                body=json.dumps(
                    {
                        "schedule_id": "schedule-1",
                        "parent_turn_id": "turn-1",
                        "project_id": "project-1",
                        "session_key": "session-1",
                        "origin_device_id": "phone-1",
                        "delivery_target_device_id": "phone-1",
                        "fire_at_utc": "2026-08-25T00:00:00Z",
                        "timezone_offset": "+09:00",
                        "reminder_text": "reminder",
                        "confirmation_text": "confirmed",
                    }
                ).encode(),
                network=True,
            )

    def test_openapi_is_executable_and_static_projection_matches(self):
        validate_openapi_contract()
        checked_in = json.loads(Path(__file__).parents[1].joinpath("api/openapi.json").read_text())
        self.assertEqual(checked_in, OPENAPI)
        operation_ids = []
        for path, item in OPENAPI["paths"].items():
            for method, operation in item.items():
                if method not in {"get", "post", "put", "patch", "delete", "head"}:
                    continue
                operation_ids.append(operation["operationId"])
                for status, response in operation["responses"].items():
                    if status not in {"204", "304"}:
                        self.assertTrue(
                            "content" in response or response.get("x-no-body") is True,
                            (path, method, status),
                        )
        self.assertEqual(len(operation_ids), len(set(operation_ids)))
        self.assertNotIn("/v1/eavesdrop/{session_id}/{action}", OPENAPI["paths"])
        self.assertEqual(
            OPENAPI["components"]["parameters"]["PrincipalUserHeader"]["name"],
            "X-Recorder-Principal-User",
        )
        self.assertEqual(
            OPENAPI["components"]["parameters"]["PrincipalDeviceHeader"]["name"],
            "X-Recorder-Principal-Device",
        )

    def test_route_catalog_rejects_prefix_suffixes_and_generic_actions(self):
        self.assertEqual(match_operation("/v1/history", "GET").method, "GET")
        self.assertEqual(match_operation("/v1/history", "HEAD").method, "HEAD")
        self.assertEqual(match_operation("/v1/updates/beta/manifest.json", "GET").deprecated, True)
        for path in (
            "/v1/history/extra",
            "/v1/internal/worker/claim/extra",
            "/v1/eavesdrop/session/unknown",
            "/v1/diagnostics/opt-in/extra",
        ):
            with self.subTest(path=path), self.assertRaises(NotFoundError):
                match_operation(path, "GET" if path.endswith("extra") else "POST")

    def test_response_dtos_reject_extra_fields_and_projection_hides_storage_paths(self):
        operation = match_operation("/v1/turns/turn-1", "GET")
        with self.assertRaises(ValueError):
            validate_response(operation, 200, {}, {"unexpected": True})
        with self.assertRaises(ValueError):
            validate_response(operation, 200, {}, {"parts": [{"unexpected": True}]})
        projected = project_response(
            operation,
            200,
            {"turn_id": "turn-1", "parts": [{"part_id": "part-1", "source_path": "/private/file", "source_available": False}]},
        )
        self.assertNotIn("source_path", json.dumps(projected))

    def test_body_sequence_route_alias_is_catalogued(self):
        operation = match_operation("/v1/eavesdrop/session-1/segments/route", "POST")
        self.assertTrue(operation.deprecated)
        self.assertEqual(operation.request_model.name, "EavesdropRoute")

    def test_unknown_routes_are_non_mutating_http_404s(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            before = store.worker_health()
            before.pop("as_of", None)
            for method, path in (
                ("GET", "/v1/history/extra"),
                ("POST", "/v1/internal/worker/claim/extra"),
                ("POST", "/v1/diagnostics/opt-in/extra"),
            ):
                status, _headers, payload = service.handle_http(method, path, {}, b"{}")
                self.assertEqual(status, 404, (method, path, payload))
            after = store.worker_health()
            after.pop("as_of", None)
            self.assertEqual(after, before)

    @staticmethod
    def _principal_headers(user: str, device: str, secret: str) -> dict[str, str]:
        message = f"{user}\x00{device}".encode("utf-8")
        signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        return {
            "X-Recorder-Principal-User": user,
            "X-Recorder-Principal-Device": device,
            "X-Recorder-Principal-Signature": signature,
            "Content-Type": "application/json",
        }

    def test_worker_controls_require_active_signed_allowlisted_principal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("worker-user", "worker-device", "other")
            headers = self._principal_headers("worker-user", "worker-device", "test-secret")
            denied = RecorderService(store, ingress_secret="test-secret")
            status, _headers, payload = denied.handle_http(
                "POST", "/v1/internal/worker/recover", headers, b"{}", peer_addr=("127.0.0.1", 1)
            )
            self.assertEqual(status, 403)
            self.assertEqual(payload["error"]["code"], "FORBIDDEN")
            allowed = RecorderService(
                store,
                ingress_secret="test-secret",
                internal_worker_principals=(("worker-user", "worker-device"),),
            )
            status, _headers, payload = allowed.handle_http(
                "POST", "/v1/internal/worker/recover", headers, b"{}", peer_addr=("127.0.0.1", 1)
            )
            self.assertEqual(status, 200)
            self.assertEqual(set(payload), {"requeued", "failed"})

    def test_worker_claim_and_mutation_bodies_match_catalogued_dtos(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("worker-user", "worker-device", "other")
            store.enqueue_worker_job(
                kind="contract-test",
                stage="route",
                payload={"turn_id": "turn-1"},
                idempotency_key="contract-worker-job",
            )
            service = RecorderService(
                store,
                ingress_secret="test-secret",
                internal_worker_principals=(("worker-user", "worker-device"),),
            )
            headers = self._principal_headers("worker-user", "worker-device", "test-secret")
            status, _headers, payload = service.handle_http(
                "POST", "/v1/internal/worker/claim", headers, b"{}", peer_addr=("127.0.0.1", 1)
            )
            self.assertEqual(status, 200)
            self.assertEqual(set(payload), {"job"})
            job = payload["job"]
            self.assertEqual(job["status"], "CLAIMED")
            completion = {
                "job_id": job["job_id"],
                "owner": "worker-1",
                "lease_token": job["lease_token"],
                "receipt": {"effect_id": str(uuid.uuid4()), "status": "succeeded"},
            }
            status, _headers, payload = service.handle_http(
                "POST",
                "/v1/internal/worker/complete",
                headers,
                json.dumps(completion).encode("utf-8"),
                peer_addr=("127.0.0.1", 1),
            )
            self.assertEqual(status, 200)
            self.assertEqual(payload["status"], "SUCCEEDED")
            self.assertEqual(payload["effect_receipt"]["status"], "succeeded")

    def test_network_now_and_duplicate_json_keys_are_rejected_before_handlers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("worker-user", "worker-device", "other")
            service = RecorderService(
                store,
                ingress_secret="test-secret",
                internal_worker_principals=(("worker-user", "worker-device"),),
            )
            headers = self._principal_headers("worker-user", "worker-device", "test-secret")
            status, _headers, payload = service.handle_http(
                "POST", "/v1/internal/worker/recover", headers, b'{"now":"client","now":"again"}', peer_addr=("127.0.0.1", 1)
            )
            self.assertEqual(status, 400)
            self.assertEqual(payload["error"]["code"], "VALIDATION_ERROR")
            status, _headers, payload = service.handle_http(
                "POST", "/v1/internal/worker/recover?now=client", headers, b"{}", peer_addr=("127.0.0.1", 1)
            )
            self.assertEqual(status, 400)
            self.assertEqual(payload["error"]["code"], "VALIDATION_ERROR")


if __name__ == "__main__":
    unittest.main()
