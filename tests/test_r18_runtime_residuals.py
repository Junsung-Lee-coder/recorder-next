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


REPO_ROOT = Path(__file__).resolve().parents[1]


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
            command = [
                sys.executable,
                "-m",
                "recorder_next",
                "--db",
                str(db),
                "--storage-root",
                str(storage),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ]

            for cycle in range(2):
                process = subprocess.Popen(
                    command,
                    cwd=REPO_ROOT,
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
