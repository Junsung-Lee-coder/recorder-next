import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recorder_next.adapters import CredentialError, HttpHermesGateway
from recorder_next.config import RecorderConfig
from recorder_next.service import create_configured_service


class BearerCredentialTests(unittest.TestCase):
    def _write_credential(self, root: Path, contents: bytes, *, mode: int = 0o600) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        path = root / "credential.env"
        path.write_bytes(contents)
        path.chmod(mode)
        return path

    def test_valid_credential_is_read_once_and_headers_preserve_session_key(self):
        class ProbeGateway(HttpHermesGateway):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.requests = []

            def _request(self, method, path, payload=None, *, extra_headers=None):
                self.requests.append(
                    {
                        "method": method,
                        "path": path,
                        "payload": payload,
                        "headers": dict(extra_headers or {}),
                    }
                )
                return {"assistant_message_id": "message-1", "content": "ok"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credential = self._write_credential(root, b"API_SERVER_KEY=fixture-value")
            gateway = ProbeGateway("http://127.0.0.1:9", api_key_file=credential)
            credential.write_bytes(b"API_SERVER_KEY=rotated-value")

            result = gateway.submit(
                session_key="project:fixture:default",
                request={"input": "normalized"},
                submission_id="submission-1",
                marker="marker-1",
            )
            gateway.history(session_key="project:fixture:default", marker="marker-1")

            self.assertEqual(result.content, "ok")
            self.assertEqual(gateway.requests[0]["headers"]["Authorization"], "Bearer fixture-value")
            self.assertEqual(gateway.requests[0]["headers"]["X-Hermes-Session-Key"], "project:fixture:default")
            self.assertEqual(gateway.requests[1]["headers"]["Authorization"], "Bearer fixture-value")
            self.assertNotIn("rotated-value", repr(gateway))

    def test_invalid_credential_files_fail_closed_without_echoing_file_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = {
                "empty": b"API_SERVER_KEY=\n",
                "duplicate": b"API_SERVER_KEY=one\nAPI_SERVER_KEY=two\n",
                "malformed": b"NOT_API_SERVER_KEY=value\n",
                "extra_key": b"API_SERVER_KEY=value\nOTHER=value\n",
                "bare_cr": b"API_SERVER_KEY=value\r",
                "extra_blank": b"API_SERVER_KEY=value\n\n",
                "whitespace": b"API_SERVER_KEY=bad value\n",
            }
            for name, contents in cases.items():
                with self.subTest(case=name):
                    path = self._write_credential(root / name, contents)
                    with self.assertRaises(CredentialError) as raised:
                        HttpHermesGateway("http://127.0.0.1:9", api_key_file=path)
                    self.assertNotIn("one", str(raised.exception))
                    self.assertNotIn("two", str(raised.exception))
                    self.assertNotIn("value", str(raised.exception))

            missing = root / "missing.env"
            with self.assertRaises(CredentialError):
                HttpHermesGateway("http://127.0.0.1:9", api_key_file=missing)

            directory = root / "directory.env"
            directory.mkdir()
            with self.assertRaises(CredentialError):
                HttpHermesGateway("http://127.0.0.1:9", api_key_file=directory)

            source = self._write_credential(root / "source.env", b"API_SERVER_KEY=symlink-value")
            link = root / "link.env"
            link.symlink_to(source)
            with self.assertRaises(CredentialError):
                HttpHermesGateway("http://127.0.0.1:9", api_key_file=link)

            unsafe = self._write_credential(root / "unsafe.env", b"API_SERVER_KEY=unsafe-value", mode=0o640)
            with self.assertRaises(CredentialError):
                HttpHermesGateway("http://127.0.0.1:9", api_key_file=unsafe)

            owner_mismatch = self._write_credential(root / "owner-mismatch.env", b"API_SERVER_KEY=owner-value")
            with patch("recorder_next.adapters.os.getuid", return_value=os.getuid() + 1):
                with self.assertRaises(CredentialError):
                    HttpHermesGateway("http://127.0.0.1:9", api_key_file=owner_mismatch)

    def test_config_resolves_only_the_credential_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "recorder.toml"
            config_path.write_text(
                "[providers]\nhermes_base_url = 'http://127.0.0.1:8642'\nhermes_api_key_file = './credential.env'\n",
                encoding="utf-8",
            )
            config = RecorderConfig.from_file(config_path).resolved(base_dir=root)
            self.assertEqual(config.hermes_base_url, "http://127.0.0.1:8642")
            self.assertEqual(config.hermes_api_key_file, str(root / "credential.env"))
            self.assertNotIn("API_SERVER_KEY", repr(config))

    def test_configured_hermes_fails_closed_without_a_credential_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = RecorderConfig(
                database=str(Path(tmp) / "db.sqlite3"),
                storage_root=str(Path(tmp) / "data"),
                hermes_base_url="http://127.0.0.1:8642",
            )
            with self.assertRaises(CredentialError):
                create_configured_service(config)
            self.assertFalse(Path(config.database).exists())
            self.assertFalse(Path(config.storage_root).exists())


if __name__ == "__main__":
    unittest.main()
