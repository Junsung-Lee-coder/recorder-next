#!/usr/bin/env python3
"""Read-only exact candidate verifier for a frozen Recorder Next generation."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from control_contract import ContractError, expected_candidate_report, validate_generation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generation", type=Path, required=True)
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.read_only:
        print("HOLD: candidate verifier requires --read-only", file=sys.stderr)
        return 2
    try:
        generation = args.generation.absolute()
        manifest, _, _ = validate_generation(generation)
        print(json.dumps(expected_candidate_report(manifest), indent=2, sort_keys=True))
        return 0
    except (ContractError, OSError, ValueError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
