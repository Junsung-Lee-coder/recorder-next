"""Synthetic actual-consumer corpus; only the launcher's final executable is substituted."""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from recorder_next.adapters import CredentialError, HermesAudioTTSProvider, HttpHermesGateway, _read_api_key_file, _read_provider_credential

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "control/start-hermes-dashboard-tts.sh"
EXECUTABLE = "/home/rumi/.hermes/hermes-agent/venv/bin/hermes"


class CredentialGrammarTests(unittest.TestCase):
    def exercise(self, raw: bytes | None, accepted: bool, *, unsafe=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credential = root / "recorder_api_key"
            if raw is not None:
                credential.write_bytes(raw)
                credential.chmod(0 if unsafe else 0o600)
            home = root / "home"
            home.mkdir()
            (home / "config.yaml").write_text("{}\n")
            expected = raw.removeprefix(b"API_SERVER_KEY=").removesuffix(b"\n").decode("ascii") if accepted and raw is not None else "never-execute"
            with patch("urllib.request.urlopen", side_effect=AssertionError("request before validation")) as request:
                for consumer in (
                    lambda: HermesAudioTTSProvider("http://127.0.0.1:1", profile="default", credential_file=credential),
                    lambda: HttpHermesGateway("http://127.0.0.1:1", api_key_file=credential),
                ):
                    with self.subTest(consumer=consumer.__code__.co_firstlineno):
                        if accepted:
                            consumer()
                        else:
                            with self.assertRaises(CredentialError) as caught:
                                consumer()
                            self.assertNotIn("synthetic-secret", str(caught.exception))
                request.assert_not_called()
            stub = root / "hermes"
            stub.write_text("#!/usr/bin/env python3\nimport os, sys\nassert os.environ['HERMES_DASHBOARD_SESSION_TOKEN'] == os.environ['R19_EXPECTED_TOKEN']\nassert sys.argv[1:] == ['serve', '--isolated', '--skip-build', '--host', '127.0.0.1', '--port', '9120']\nprint('EXEC_ACCEPTED')\n")
            stub.chmod(0o700)
            source = LAUNCHER.read_text()
            self.assertEqual(source.count(EXECUTABLE), 1)
            launcher = root / "launcher.sh"
            launcher.write_text(source.replace(EXECUTABLE, str(stub)))
            result = subprocess.run(["/bin/sh", str(launcher)], env={"PATH": os.environ["PATH"], "CREDENTIALS_DIRECTORY": str(root), "HERMES_HOME": str(home), "R19_EXPECTED_TOKEN": expected}, capture_output=True, timeout=5)
            if accepted:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"EXEC_ACCEPTED\n")
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertFalse((home / "cron").exists())
            self.assertNotIn(b"synthetic-secret", result.stdout + result.stderr)

    def test_five_r18_mismatches(self):
        for name, raw in {
            "alternate_api_key": b"API_KEY=synthetic-secret\n",
            "alternate_token": b"TOKEN=synthetic-secret\n",
            "bare": b"synthetic-secret\n",
            "punctuation": b"API_SERVER_KEY=synthetic-secret!\n",
            "crlf": b"API_SERVER_KEY=synthetic-secret\r\n",
        }.items():
            with self.subTest(case=name):
                self.exercise(raw, False)

    def test_acceptance_boundaries(self):
        for size in (1, 4080, 4095, 4096):
            for ending in (b"", b"\n"):
                with self.subTest(size=size, lf=bool(ending)):
                    self.exercise(b"API_SERVER_KEY=" + b"a" * size + ending, True)
        self.exercise(b"API_SERVER_KEY=AZaz09._~+/=-\n", True)

    def test_rejections(self):
        cases = [b"", b"\n", b"API_SERVER_KEY=", b"API_SERVER_KEY=\n", b"API_SERVER_KEY=x\r", b"API_SERVER_KEY=x\x00\n", b"API_SERVER_KEY=x\xff\n", b'API_SERVER_KEY="x"\n', b"API_SERVER_KEY=x y\n", b"API_SERVER_KEY=x\t\n", b" API_SERVER_KEY=x\n", b"API_SERVER_KEY=x\n\n", b"API_SERVER_KEY=x\nTOKEN=y", b"API_SERVER_KEY=" + b"x" * 4097, b"API_SERVER_KEY=" + b"x" * 4097 + b"\n", b"API_SERVER_KEY=" + b"x" * 100000]
        for index, raw in enumerate(cases):
            with self.subTest(case=index):
                self.exercise(raw, False)

    def test_missing_and_unreadable(self):
        self.exercise(None, False)
        self.exercise(b"API_SERVER_KEY=synthetic-secret\n", False, unsafe=True)

    def test_actual_reads_are_bounded_before_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            credential = Path(tmp) / "recorder_api_key"
            credential.write_bytes(b"API_SERVER_KEY=x")
            credential.chmod(0o600)
            real_fdopen = os.fdopen
            for reader in (_read_api_key_file, _read_provider_credential):
                reads = []

                def tracked_fdopen(fd, mode):
                    handle = real_fdopen(fd, mode)
                    proxy = MagicMock()
                    proxy.__enter__.return_value = proxy
                    proxy.__exit__.side_effect = lambda *args: handle.close()
                    def read(size):
                        reads.append(size)
                        return handle.read(size)
                    proxy.read.side_effect = read
                    return proxy

                with patch("os.fdopen", side_effect=tracked_fdopen):
                    self.assertEqual(reader(credential), "x")
                self.assertEqual(reads, [4113])

            # Execute the exact inline parser, not a fixture implementation.
            inline = LAUNCHER.read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
            handle = MagicMock()
            handle.__enter__.return_value = handle
            handle.read.return_value = b"API_SERVER_KEY=x"
            with patch("builtins.open", return_value=handle), patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": tmp}), contextlib.redirect_stdout(io.StringIO()) as output:
                exec(compile(inline, str(LAUNCHER), "exec"), {})
            handle.read.assert_called_once_with(4113)
            self.assertEqual(output.getvalue(), "x")


if __name__ == "__main__":
    unittest.main()
