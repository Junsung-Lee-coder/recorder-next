from __future__ import annotations

import http.client
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from recorder_next.store import RecorderStore


REPO_ROOT = Path(__file__).resolve().parents[1]

# Fixture-only evidence boundary: these subprocesses deliberately substitute the
# configured-service factory child-locally, so an HTTP 200 from this listener is
# isolated lifecycle evidence only. It is NOT proof of real speech, provider
# readiness, exact existing-session continuity, or of the unmodified
# `python -m recorder_next` production admission path.
_CHILD_SOURCE = r'''
import sys
from pathlib import Path

candidate_root = Path(sys.argv.pop(1)).resolve()
sys.path.insert(0, str(candidate_root))

import recorder_next.__main__ as recorder_main

resolved = Path(recorder_main.__file__).resolve()
expected = candidate_root / "recorder_next" / "__main__.py"
if resolved != expected:
    raise SystemExit(
        f"child imported the wrong recorder_next module: {resolved} != {expected}"
    )

from unittest.mock import patch

from recorder_next.adapters import MemoryHermesGateway, StaticTTSProvider
from recorder_next.service import RecorderService, RecorderStore


def factory(config, *, ingress_secret, require_production):
    if require_production is not True:
        raise AssertionError("fixture factory requires require_production=True")
    if ingress_secret is not None:
        raise AssertionError("fixture factory requires ingress_secret=None")
    store = RecorderStore(config.database, storage_root=config.storage_root)
    return RecorderService(store, hermes=MemoryHermesGateway(), tts=StaticTTSProvider())


with patch.object(
    recorder_main,
    "create_configured_service",
    side_effect=factory,
) as replaced:
    code = recorder_main.main(sys.argv[1:])
if replaced.call_count != 1:
    raise SystemExit(
        f"configured-service factory was called {replaced.call_count} times"
    )
raise SystemExit(code)
'''


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_for_health(port: int, process: subprocess.Popen[str], *, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(
                f"Recorder Next exited before health: rc={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
            )
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
            connection.request("GET", "/v1/health")
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status == 200:
                return
            last_error = AssertionError(f"health returned HTTP {response.status}")
        except OSError as exc:
            last_error = exc
        time.sleep(0.05)
    raise AssertionError(f"Recorder Next did not become healthy: {last_error!r}")


class RecorderNextR18ShutdownTests(unittest.TestCase):
    def _run_signal_cycle(self, signum: signal.Signals) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "recorder.sqlite3"
            storage = root / "storage"
            port = _free_port()
            config_path = root / "recorder-next.toml"
            config_path.write_text(
                "\n".join(
                    (
                        "[server]",
                        'host = "127.0.0.1"',
                        f"port = {port}",
                        "",
                        "[storage]",
                        'database = "recorder.sqlite3"',
                        'root = "storage"',
                        "",
                    )
                ),
                encoding="utf-8",
            )
            home = root / "home"
            tmpdir = root / "tmp"
            home.mkdir()
            tmpdir.mkdir()
            child_environment = {
                "HOME": str(home),
                "PATH": os.defpath,
                "LC_ALL": "C.UTF-8",
                "TMPDIR": str(tmpdir),
            }
            command = [
                sys.executable,
                "-I",
                "-B",
                "-c",
                _CHILD_SOURCE,
                str(REPO_ROOT),
                "--config",
                str(config_path),
                "--db",
                str(db),
                "--storage-root",
                str(storage),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ]

            # Persistence sentinel: an inert registered device written exactly
            # once before the first child, then re-read through the real store
            # after each shutdown to prove durable storage reuse across the
            # restart cycles. No session/project/turn work is enqueued.
            sentinel_store = RecorderStore(db, storage_root=storage)
            sentinel = sentinel_store.register_device(
                "r18-shutdown-user", "r18-shutdown-device", "phone"
            )
            del sentinel_store

            for cycle in range(2):
                process = subprocess.Popen(
                    command,
                    cwd=REPO_ROOT,
                    env=child_environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    _wait_for_health(port, process)
                    os.kill(process.pid, signum)
                    stdout, stderr = process.communicate(timeout=8)
                    self.assertEqual(
                        process.returncode,
                        0,
                        f"cycle {cycle} signal {signum.name} did not cleanly exit; stdout={stdout!r}, stderr={stderr!r}",
                    )
                    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    probe.settimeout(0.5)
                    try:
                        probe.connect(("127.0.0.1", port))
                        probe.close()
                        self.fail(
                            f"cycle {cycle} port {port} still accepts connections after clean exit"
                        )
                    except ConnectionRefusedError:
                        pass
                    finally:
                        probe.close()
                    self.assertTrue(db.is_file(), f"cycle {cycle} database missing after shutdown")
                    self.assertTrue(storage.is_dir(), f"cycle {cycle} storage root missing after shutdown")
                    reader = RecorderStore(db, storage_root=storage)
                    try:
                        self.assertEqual(
                            reader.get_device("r18-shutdown-user", "r18-shutdown-device"),
                            sentinel,
                        )
                    finally:
                        del reader
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=3)

    def test_sigterm_uses_bounded_clean_shutdown_and_restart_recovery(self):
        self._run_signal_cycle(signal.SIGTERM)

    def test_sigint_uses_the_same_bounded_clean_shutdown_and_restart_recovery(self):
        self._run_signal_cycle(signal.SIGINT)


if __name__ == "__main__":
    unittest.main()
