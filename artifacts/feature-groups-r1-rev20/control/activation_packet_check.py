#!/usr/bin/env python3
"""Read-only exact activation-packet checker for Recorder Next."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from control_contract import ContractError, expected_packet_report, load_json, validate_generation, validate_packet


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.read_only:
        print("HOLD: packet checker requires --read-only", file=sys.stderr)
        return 2
    try:
        packet_path = args.packet.absolute()
        packet, _, _ = load_json(packet_path, "activation packet")
        if not isinstance(packet, dict) or not isinstance(packet.get("transaction_manifest"), dict):
            raise ContractError("activation packet has no bound transaction manifest")
        transaction_path = Path(packet["transaction_manifest"].get("path", "")).absolute()
        generation = transaction_path.parent.parent.absolute()
        manifest, transaction, _ = validate_generation(generation)
        validate_packet(generation, packet_path, manifest, transaction)
        print(json.dumps(expected_packet_report(generation, manifest, transaction), indent=2, sort_keys=True))
        return 0
    except (ContractError, OSError, ValueError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
