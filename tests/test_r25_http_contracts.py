import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from recorder_next.http_contract import match_operation
from recorder_next.openapi import OPENAPI, validate_openapi_contract
from recorder_next.errors import NotFoundError
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


class R25HttpContractTests(unittest.TestCase):
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
                        self.assertIn("content", response, (path, method, status))
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
        self.assertEqual(match_operation("/v1/history", "HEAD").method, "GET")
        self.assertEqual(match_operation("/v1/updates/beta/manifest.json", "GET").deprecated, True)
        for path in (
            "/v1/history/extra",
            "/v1/internal/worker/claim/extra",
            "/v1/eavesdrop/session/unknown",
            "/v1/diagnostics/opt-in/extra",
        ):
            with self.subTest(path=path), self.assertRaises(NotFoundError):
                match_operation(path, "GET" if path.endswith("extra") else "POST")

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
