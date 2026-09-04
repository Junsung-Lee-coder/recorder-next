from __future__ import annotations

import argparse
import os

from .config import RecorderConfig
from .http import create_http_server
from .service import create_configured_service, create_service


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recorder Next standalone server")
    parser.add_argument("--config", default=os.environ.get("RECORDER_NEXT_CONFIG"))
    parser.add_argument("--db", default=os.environ.get("RECORDER_NEXT_DB"))
    parser.add_argument("--storage-root", default=os.environ.get("RECORDER_NEXT_STORAGE_ROOT"))
    parser.add_argument("--host", default=os.environ.get("RECORDER_NEXT_HOST"))
    parser.add_argument("--port", type=int, default=os.environ.get("RECORDER_NEXT_PORT"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.config:
        config_path = os.path.abspath(args.config)
        config = RecorderConfig.from_file(config_path).resolved(base_dir=os.path.dirname(config_path))
    else:
        config = RecorderConfig()
    db = args.db or config.database
    storage_root = args.storage_root or config.storage_root
    host = args.host or config.host
    port = int(args.port or config.port)
    if args.config and not any((args.db, args.storage_root)):
        service = create_configured_service(config)
    else:
        service = create_service(
            db,
            storage_root,
            hermes_max_attempts=config.hermes_max_attempts,
            hermes_grace_seconds=config.hermes_grace_seconds,
        )
    service.store.recover()
    server = create_http_server(service, host=host, port=port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
