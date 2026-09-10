from __future__ import annotations

import argparse
import os
import signal
import stat
import threading
import time
from dataclasses import replace
from types import FrameType
from typing import Callable

from .config import RecorderConfig
from .http import create_http_server
from .service import create_configured_service, create_service


SignalHandler = Callable[[int, FrameType | None], object] | int | None
APPLICATION_MAX_SECONDS = 3900.0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recorder Next standalone server")
    parser.add_argument("--config", default=os.environ.get("RECORDER_NEXT_CONFIG"))
    parser.add_argument("--db", default=os.environ.get("RECORDER_NEXT_DB"))
    parser.add_argument("--storage-root", default=os.environ.get("RECORDER_NEXT_STORAGE_ROOT"))
    parser.add_argument("--host", default=os.environ.get("RECORDER_NEXT_HOST"))
    parser.add_argument("--port", type=int, default=os.environ.get("RECORDER_NEXT_PORT"))
    return parser


def apply_cli_overrides(
    config: RecorderConfig,
    *,
    db: str | None = None,
    storage_root: str | None = None,
    host: str | None = None,
    port: int | str | None = None,
) -> RecorderConfig:
    """Copy a loaded config while applying only explicit CLI overrides."""

    if not isinstance(config, RecorderConfig):
        raise TypeError("config must be RecorderConfig")
    values: dict[str, object] = {}
    if db is not None:
        values["database"] = db
    if storage_root is not None:
        values["storage_root"] = storage_root
    if host is not None:
        values["host"] = host
    if port is not None:
        values["port"] = int(port)
    return replace(config, **values)


class _ShutdownBridge:
    """Translate process signals into bounded server and worker shutdown."""

    def __init__(self, service, server, *, server_join_timeout: float = 1.0):
        self.service = service
        self.server = server
        self.server_join_timeout = server_join_timeout
        self.requested = threading.Event()
        self.requested_at: float | None = None
        self._previous_handlers: dict[int, SignalHandler] = {}
        self._server_thread = threading.Thread(
            target=self._shutdown_server,
            name="recorder-shutdown",
            daemon=True,
        )

    def install(self) -> None:
        for signum in (signal.SIGTERM, signal.SIGINT):
            self._previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle_signal)
        self._server_thread.start()

    def _handle_signal(self, signum: int, frame: FrameType | None) -> None:
        del signum, frame
        self.request()

    def request(self) -> None:
        if self.requested.is_set():
            return
        self.requested_at = time.monotonic()
        self.requested.set()
        self.service.request_shutdown()

    def _shutdown_server(self) -> None:
        self.requested.wait()
        self.server.shutdown()

    def close(self) -> None:
        self.request()
        self._server_thread.join(timeout=self.server_join_timeout)
        for signum, previous in self._previous_handlers.items():
            signal.signal(signum, previous)


def _credential_value(name: str) -> str | None:
    """Read a systemd-delivered secret without placing it in argv or logs."""
    explicit = os.environ.get("RECORDER_INGRESS_SECRET_FILE")
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    path = explicit or (os.path.join(directory, name) if directory else None)
    if not path:
        return None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise RuntimeError("ingress credential file is unavailable") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in {0o400, 0o440, 0o600}:
            raise RuntimeError("ingress credential file custody is unsafe")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = handle.read().strip()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not value:
        raise RuntimeError("ingress credential is empty")
    return value


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.config:
        config_path = os.path.abspath(args.config)
        config = RecorderConfig.from_file(config_path).resolved(base_dir=os.path.dirname(config_path))
    else:
        config = RecorderConfig()
    config = apply_cli_overrides(
        config,
        db=args.db,
        storage_root=args.storage_root,
        host=args.host,
        port=args.port,
    )
    ingress_secret = _credential_value("recorder_ingress_secret")
    if args.config:
        service = create_configured_service(config, ingress_secret=ingress_secret)
    else:
        service = create_service(
            config.database,
            config.storage_root,
            hermes_max_attempts=config.hermes_max_attempts,
            hermes_grace_seconds=config.hermes_grace_seconds,
            ingress_secret=ingress_secret,
        )
    service.store.recover()
    server = create_http_server(service, host=config.host, port=config.port)
    shutdown = _ShutdownBridge(service, server)
    try:
        shutdown.install()
        service.start_background_workers()
        server.serve_forever()
    finally:
        shutdown.close()
        deadline = (shutdown.requested_at or time.monotonic()) + APPLICATION_MAX_SECONDS
        remaining = max(0.0, deadline - time.monotonic())
        background_stopped = service.stop_background_workers(timeout=remaining)
        remaining = max(0.0, deadline - time.monotonic())
        drained = service.wait_for_drain(timeout=remaining)
        server.server_close()
        if not background_stopped or not drained:
            raise RuntimeError("Recorder service did not stop within the configured drain deadline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
