"""Shared exact-byte contract checks for the Recorder Next rev19 packet.

This module is copied into each frozen generation.  The candidate, packet,
preflight, and stage checks all consume the same closed schemas and canonical
projections so that a single relaxed validator cannot certify a different
candidate or operator packet.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


HEX64 = __import__("re").compile(r"^[0-9a-f]{64}$")
MODE = __import__("re").compile(r"^[0-7]{4}$")

MANIFEST_SCHEMA = "recorder-next-r7-rev19-manifest/v5"
PACKET_SCHEMA = "recorder-next-activation-packet/v2"
PREFLIGHT_SCHEMA = "recorder-next-preflight/v3"
CANDIDATE_VERIFIER_SCHEMA = "recorder-next-candidate-verifier/v2"
STAGE_VERIFIER_SCHEMA = "recorder-next-stage-verifier/v2"
PACKET_CHECK_SCHEMA = "recorder-next-activation-packet-check/v2"
PRODUCER_SCHEMA = "recorder-next-producer-report/v3"
FREEZE_SCHEMA = "recorder-next-freeze-vector/v2"
TRANSACTION_SCHEMA = "recorder-next-transaction/v1"

CANDIDATE_HASH_PREFIX = "recorder-next-r7-candidate/v3"
CANDIDATE_HASH_ALGORITHM = 'sha256(\\"recorder-next-r7-candidate/v3\\"\\0generation\\0product_sha256\\0)'
PRODUCT_IDENTITY = "recorder-next-plus-local-single-recorder-runtime"
EXPECTED_PRODUCT_FILE_COUNT = 44
EXPECTED_PRODUCT_SHA = "5e7f78d85e9ba94f62ed2be719b0a8840c4e9e9f41d1ae9013e33be4f5ff7a87"
PRODUCT_BYTES_CHANGED_FROM_FAILED_CANDIDATE = True
CHANGED_PRODUCT_PATHS_FROM_FAILED_CANDIDATE = ["recorder_next/store.py", "tests/test_generation_contract.py", "tests/test_scheduled_final.py"]
ARCHIVE_NAME = "candidate-source-r7-rev19.tar"
PREDECESSOR = {
    "disposition": "preserved_failed_predecessor",
    "candidate_id": "recorder-next-bearer-r7-rev18-affa9cfdbcd5c74c",
    "candidate_sha256": "affa9cfdbcd5c74c298dc5dc39f66deab6a0f9430d65556fbc3e81f1881e19f9",
    "product_sha256": "5b317a65106498ae84591eecfd6000525339e702380da47dc7802ab22482e384",
    "archive_sha256": "9a70826230f91558dda1f22cea04deb36e41ca580147fabd21c0a970c5265fe3",
    "declared_source_bundle_sha256": "9a70826230f91558dda1f22cea04deb36e41ca580147fabd21c0a970c5265fe3",
}
MUTATION_COUNTER_KEYS = (
    "installation",
    "rollback",
    "live_service",
    "systemd",
    "gateway",
    "app_device",
    "publication",
    "secret_output",
)
CONTROL_ROLE_PATHS = {
    "operator": "control/release_op.py",
    "candidate_verifier": "control/verify_candidate.py",
    "packet_checker": "control/activation_packet_check.py",
    "preflight": "control/preflight_rev14.py",
    "control_contract": "control/control_contract.py",
    "config": "control/recorder-next.toml",
    "operator_matrix": "control/test_operator_matrix.py",
    "provenance_tests": "control/test_activation_provenance_regressions.py",
    "candidate_builder": "control/build_candidate.py",
    "repair_tests": "control/test_rev17_repairs.py",
}
EVIDENCE_PATHS = (
    "evidence/product-full-suite.log",
    "evidence/control-suite.log",
    "evidence/candidate-verifier-final.json",
    "evidence/operator-stage-verifier-final.json",
    "evidence/preflight-final.json",
    "evidence/packet-check-final.json",
)
FREEZE_DYNAMIC_PATHS = {"candidate-manifest.json", "control/activation-packet.json", "opening-vector.json", "closing-vector.json", "freeze-vector.json"}


class ContractError(RuntimeError):
    """A controlled provenance or packet contract failure."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def strict_load_bytes(data: bytes) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ContractError(f"non-finite JSON constant: {value}")

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON: {exc}") from None


def regular(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ContractError(f"{label} is missing or unreadable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ContractError(f"{label} must be a regular non-symlink file")
    return info


def directory(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ContractError(f"{label} is missing or unreadable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ContractError(f"{label} must be a real directory")
    return info


def canonical_absolute(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or not os.path.isabs(value):
        raise ContractError(f"{label} must be an absolute path")
    path = Path(value)
    if path != path.resolve() or path.is_symlink():
        raise ContractError(f"{label} must be canonical and symlink-free")
    return path


def relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value or "\x00" in value:
        raise ContractError(f"{label} must be a relative POSIX path")
    parts = PurePosixPath(value).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ContractError(f"{label} contains an unsafe path component")
    return "/".join(parts)


def leaf(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or PurePosixPath(value).name != value or value in {".", ".."} or "/" in value or "\\" in value:
        raise ContractError(f"{label} must be one direct leaf")
    return value


def hash_text(value: Any, label: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise ContractError(f"{label} must be a lowercase SHA-256")
    return value


def mode_text(value: Any, label: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or MODE.fullmatch(value) is None:
        raise ContractError(f"{label} must be a four-digit octal mode")
    return value


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (positive and value <= 0) or (not positive and value < 0):
        raise ContractError(f"{label} must be a {'positive' if positive else 'non-negative'} integer")
    return value


def descriptor(value: Any, label: str, *, relative: bool = True, mode: bool = False) -> dict[str, Any]:
    expected = {"path", "sha256", "size"} | ({"mode"} if mode else set())
    if not isinstance(value, dict) or set(value) != expected:
        raise ContractError(f"{label} descriptor keys differ")
    if relative:
        relative_path(value["path"], f"{label}.path")
    else:
        canonical_absolute(value["path"], f"{label}.path")
    hash_text(value["sha256"], f"{label}.sha256")
    _integer(value["size"], f"{label}.size")
    if mode:
        mode_text(value["mode"], f"{label}.mode")
    return value


def load_json(path: Path, label: str) -> tuple[Any, bytes, os.stat_result]:
    info = regular(path, label)
    raw = path.read_bytes()
    return strict_load_bytes(raw), raw, info


def tree_rows(root: Path, label: str, *, expected_mode: str | None = None) -> list[dict[str, Any]]:
    directory(root, label)
    result: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ContractError(f"{label} contains a symlink: {path}")
        if not path.is_file():
            continue
        info = regular(path, f"{label} file {path}")
        mode = f"{stat.S_IMODE(info.st_mode):04o}"
        if expected_mode is not None and mode != expected_mode:
            raise ContractError(f"{label} file mode drift: {path}")
        data = path.read_bytes()
        result.append({"path": path.relative_to(root).as_posix(), "size": len(data), "sha256": sha256_bytes(data), "mode": mode})
    return result


def product_sha(rows: Sequence[Mapping[str, Any]]) -> str:
    payload = "".join(f"{row['path']}\0{row['size']}\0{row['sha256']}\0" for row in rows).encode("utf-8")
    return sha256_bytes(payload)


def freeze_projection_digest(rows: Sequence[Mapping[str, Any]]) -> str:
    stable = [row for row in rows if row["path"] not in FREEZE_DYNAMIC_PATHS]
    payload = "".join(f"{row['path']}\0{row['size']}\0{row['sha256']}\0{row['mode']}\n" for row in stable).encode("utf-8")
    return sha256_bytes(payload)


def candidate_sha(generation: str, product_sha256: str) -> str:
    return sha256_bytes(f"{CANDIDATE_HASH_PREFIX}\0{generation}\0{product_sha256}\0".encode("utf-8"))


def candidate_id(generation: str, product_sha256: str) -> str:
    return f"recorder-next-{generation}-{candidate_sha(generation, product_sha256)[:16]}"


def expected_sidecar(generation: Path) -> Path:
    return generation.parent / f"{generation.name}.freeze-vector.sha256"


def expected_receipts(generation_name: str) -> dict[str, str]:
    return {
        "apply": f"apply-{generation_name}.json",
        "rollback": f"rollback-{generation_name}.json",
        "journal": f"transaction-{generation_name}.json",
        "lock": "operator.lock",
    }


def _expected_control_rows(generation: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for role, relative in CONTROL_ROLE_PATHS.items():
        path = generation / relative
        info = regular(path, f"control role {role}")
        data = path.read_bytes()
        result[role] = {"path": relative, "sha256": sha256_bytes(data), "size": len(data), "mode": f"{stat.S_IMODE(info.st_mode):04o}"}
    return result


def _expected_mutation_counters() -> dict[str, int]:
    return {key: 0 for key in MUTATION_COUNTER_KEYS}


def _candidate_member_rows(generation: Path) -> list[dict[str, Any]]:
    rows = tree_rows(generation / "candidate", "candidate", expected_mode="0444")
    if len(rows) != EXPECTED_PRODUCT_FILE_COUNT:
        raise ContractError(f"candidate file count is {len(rows)}, expected {EXPECTED_PRODUCT_FILE_COUNT}")
    return rows


def _archive_rows(path: Path) -> list[dict[str, Any]]:
    regular(path, "candidate archive")
    result: list[dict[str, Any]] = []
    try:
        with tarfile.open(path, "r:") as archive:
            for member in archive.getmembers():
                if not member.isfile() or member.name.startswith("/") or any(part in {"", ".", ".."} for part in PurePosixPath(member.name).parts):
                    raise ContractError("candidate archive contains an unsafe or non-regular member")
                extracted = archive.extractfile(member)
                data = extracted.read() if extracted is not None else b""
                result.append({"path": member.name, "size": len(data), "sha256": sha256_bytes(data), "mode": f"{member.mode & 0o7777:04o}"})
    except (OSError, tarfile.TarError) as exc:
        raise ContractError(f"candidate archive is unreadable: {exc}") from exc
    return sorted(result, key=lambda row: row["path"])


def _test_ids(candidate: Path) -> tuple[list[str], str]:
    old_cwd = Path.cwd()
    old_path = list(sys.path)
    old_flag = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(candidate))
    try:
        import unittest

        os.chdir(candidate)
        suite = unittest.defaultTestLoader.discover("tests", pattern="test_*.py")
        discovered: list[str] = []

        def flatten(value: unittest.TestSuite | unittest.TestCase) -> None:
            if isinstance(value, unittest.TestSuite):
                for item in value:
                    flatten(item)
            else:
                discovered.append(value.id())

        flatten(suite)
    except Exception as exc:
        raise ContractError(f"candidate test discovery failed: {exc}") from exc
    finally:
        os.chdir(old_cwd)
        sys.path[:] = old_path
        sys.dont_write_bytecode = old_flag
    if len(set(discovered)) != len(discovered):
        raise ContractError("candidate test IDs contain duplicates")
    ids = sorted(discovered)
    return ids, sha256_bytes(("\n".join(ids) + "\n").encode("utf-8"))


def _validate_test_matrix(generation: Path, data: Mapping[str, Any], members: list[dict[str, Any]]) -> None:
    matrix = data["test_matrix"]
    expected_keys = {"schema", "status", "discovered_count", "unique_count", "duplicate_count", "sorted_test_id_sha256", "ids", "test_source_file_count", "test_source_sha256", "test_source_rows", "status_code"}
    if not isinstance(matrix, dict) or set(matrix) != expected_keys:
        raise ContractError("test matrix schema is not closed")
    if matrix["schema"] != "recorder-next-test-matrix/v2" or matrix["status"] != "PASS" or matrix["status_code"] != 0:
        raise ContractError("test matrix status is not PASS")
    ids, ids_sha = _test_ids(generation / "candidate")
    if matrix["ids"] != ids or matrix["sorted_test_id_sha256"] != ids_sha:
        raise ContractError("candidate test IDs or digest drifted")
    if matrix["discovered_count"] != len(ids) or matrix["unique_count"] != len(ids) or matrix["duplicate_count"] != 0:
        raise ContractError("candidate test count is not closed")
    test_rows = [row for row in members if row["path"].startswith("tests/") and row["path"].endswith(".py")]
    test_payload = "".join(f"{row['path']}\0{row['size']}\0{row['sha256']}\n" for row in test_rows).encode("utf-8")
    if matrix["test_source_rows"] != test_rows or matrix["test_source_file_count"] != len(test_rows) or matrix["test_source_sha256"] != sha256_bytes(test_payload):
        raise ContractError("candidate test source provenance drifted")
    if len(ids) != 87:
        raise ContractError(f"candidate product test count is {len(ids)}, expected 87")


def _validate_manifest_shape(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ContractError("candidate manifest must be an object")
    expected = {
        "schema", "status", "generation", "candidate_id", "candidate_sha256", "candidate_hash_algorithm",
        "candidate_file_count", "candidate_total_bytes", "candidate_members", "candidate_archive", "source_archive", "product_identity",
        "product_sha256", "product_bytes_changed_from_failed_candidate", "changed_product_paths_from_failed_candidate",
        "predecessor", "candidate_only_not_applied", "approved_for_live_change", "live_authorized", "commands_executed",
        "mutation_counters", "transaction", "packet", "control_roles", "test_matrix", "evidence", "producer_report",
        "freeze_vector",
    }
    if set(data) != expected:
        raise ContractError("candidate manifest top-level keys differ")
    if data["schema"] != MANIFEST_SCHEMA or data["status"] != "FROZEN":
        raise ContractError("candidate manifest is not a frozen rev17 manifest")
    if not isinstance(data["generation"], str) or not data["generation"] or "/" in data["generation"] or "\\" in data["generation"]:
        raise ContractError("generation is unsafe")
    hash_text(data["candidate_sha256"], "candidate_sha256")
    if data["candidate_hash_algorithm"] != CANDIDATE_HASH_ALGORITHM:
        raise ContractError("candidate hash algorithm drifted")
    if data["candidate_file_count"] != EXPECTED_PRODUCT_FILE_COUNT or data["product_identity"] != PRODUCT_IDENTITY:
        raise ContractError("candidate product cardinality or identity drifted")
    hash_text(data["product_sha256"], "product_sha256")
    if data["product_bytes_changed_from_failed_candidate"] is not PRODUCT_BYTES_CHANGED_FROM_FAILED_CANDIDATE or data["changed_product_paths_from_failed_candidate"] != CHANGED_PRODUCT_PATHS_FROM_FAILED_CANDIDATE:
        raise ContractError("rev18 product change projection drifted")
    if data["predecessor"] != PREDECESSOR:
        raise ContractError("predecessor provenance drifted")
    for key in ("candidate_only_not_applied",):
        if data[key] is not True:
            raise ContractError("candidate-only gate is not closed")
    for key in ("approved_for_live_change", "live_authorized"):
        if data[key] is not False:
            raise ContractError("live authorization gate is open")
    if data["commands_executed"] != 0:
        raise ContractError("manifest command counter is nonzero")
    if data["mutation_counters"] != _expected_mutation_counters():
        raise ContractError("manifest mutation counter schema or value drifted")
    return data


def _validate_manifest_content(generation: Path, data: dict[str, Any]) -> None:
    members = _candidate_member_rows(generation)
    if data["candidate_members"] != members:
        raise ContractError("candidate member rows are not an exact projection")
    if data["candidate_total_bytes"] != sum(row["size"] for row in members):
        raise ContractError("candidate byte total drifted")
    product_digest = product_sha(members)
    if data["product_sha256"] != product_digest or product_digest != EXPECTED_PRODUCT_SHA:
        raise ContractError("accepted product SHA drifted")
    expected_sha = candidate_sha(data["generation"], product_digest)
    expected_id = candidate_id(data["generation"], product_digest)
    if data["candidate_sha256"] != expected_sha or data["candidate_id"] != expected_id:
        raise ContractError("candidate identity is not derived from the exact product")

    archive = data["candidate_archive"]
    if not isinstance(archive, dict) or set(archive) != {"path", "sha256", "size", "role"}:
        raise ContractError("candidate archive descriptor schema differs")
    descriptor({key: archive[key] for key in ("path", "sha256", "size")}, "candidate_archive", relative=False)
    expected_archive = (generation.parent / ARCHIVE_NAME).resolve()
    archive_path = canonical_absolute(archive["path"], "candidate_archive.path")
    if archive_path != expected_archive or archive["role"] != "candidate_archive":
        raise ContractError("candidate archive path or role drifted")
    if sha256_file(archive_path) != archive["sha256"] or archive_path.stat().st_size != archive["size"]:
        raise ContractError("candidate archive digest or size drifted")
    source_archive = data["source_archive"]
    if source_archive != archive:
        raise ContractError("source archive identity is not the candidate archive identity")
    archive_rows = _archive_rows(archive_path)
    expected_archive_rows = [{**row, "path": row["path"]} for row in members]
    if archive_rows != expected_archive_rows:
        raise ContractError("candidate archive members do not equal candidate rows")
    _validate_test_matrix(generation, data, members)

    roles = data["control_roles"]
    if not isinstance(roles, dict) or set(roles) != set(CONTROL_ROLE_PATHS):
        raise ContractError("control role map is not closed")
    expected_roles = _expected_control_rows(generation)
    if roles != expected_roles:
        raise ContractError("control role referents are not exact")

    tx_descriptor = data["transaction"]
    if not isinstance(tx_descriptor, dict) or set(tx_descriptor) != {"path", "sha256", "roots", "receipts", "operator_sha256"}:
        raise ContractError("transaction descriptor schema differs")
    tx_path = canonical_absolute(tx_descriptor["path"], "transaction.path")
    if tx_path != generation / "control/transaction-manifest.json":
        raise ContractError("transaction path drifted")
    if sha256_file(tx_path) != tx_descriptor["sha256"]:
        raise ContractError("transaction descriptor hash drifted")
    if tx_descriptor["operator_sha256"] != roles["operator"]["sha256"]:
        raise ContractError("transaction operator projection drifted")
    tx = validate_transaction(tx_path, generation, data)
    if tx_descriptor["roots"] != tx["roots"] or tx_descriptor["receipts"] != tx["receipts"]:
        raise ContractError("transaction roots or receipt projection drifted")

    packet_descriptor = data["packet"]
    descriptor(packet_descriptor, "packet", relative=True)
    if packet_descriptor["path"] != "control/activation-packet.json":
        raise ContractError("activation packet path drifted")
    packet_path = generation / packet_descriptor["path"]
    if sha256_file(packet_path) != packet_descriptor["sha256"] or packet_path.stat().st_size != packet_descriptor["size"]:
        raise ContractError("activation packet digest or size drifted")

    evidence = data["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != set(EVIDENCE_PATHS):
        raise ContractError("evidence role map is not closed")
    for relative, item in evidence.items():
        descriptor(item, f"evidence.{relative}", relative=True)
        if item["path"] != relative:
            raise ContractError(f"evidence path projection drifted: {relative}")
        path = generation / relative
        if sha256_file(path) != item["sha256"] or path.stat().st_size != item["size"]:
            raise ContractError(f"evidence digest drifted: {relative}")

    producer = data["producer_report"]
    descriptor(producer, "producer_report", relative=True)
    if producer["path"] != "producer-report.json":
        raise ContractError("producer report path drifted")
    producer_path = generation / producer["path"]
    if sha256_file(producer_path) != producer["sha256"] or producer_path.stat().st_size != producer["size"]:
        raise ContractError("producer report digest drifted")

    freeze = data["freeze_vector"]
    if not isinstance(freeze, dict) or set(freeze) != {"path", "sidecar", "excluded", "sha256", "entry_count"}:
        raise ContractError("freeze-vector descriptor schema differs")
    if freeze["path"] != "freeze-vector.json" or freeze["excluded"] != ["freeze-vector.json"]:
        raise ContractError("freeze-vector path or exclusion drifted")
    sidecar = canonical_absolute(freeze["sidecar"], "freeze_vector.sidecar")
    if sidecar != expected_sidecar(generation):
        raise ContractError("freeze-vector sidecar path drifted")
    hash_text(freeze["sha256"], "freeze_vector.sha256")
    _integer(freeze["entry_count"], "freeze_vector.entry_count", positive=True)
    validate_freeze(generation, freeze)


def validate_manifest(generation: Path) -> dict[str, Any]:
    generation = generation.absolute()
    directory(generation, "generation")
    if generation != generation.resolve() or generation.is_symlink():
        raise ContractError("generation path is not canonical")
    value, _, _ = load_json(generation / "candidate-manifest.json", "candidate manifest")
    data = _validate_manifest_shape(value)
    _validate_manifest_content(generation, data)
    return data


def validate_transaction(path: Path, generation: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    value, _, _ = load_json(path, "transaction manifest")
    if not isinstance(value, dict) or set(value) != {"schema", "generation", "candidate", "operator_sha256", "runtime", "roots", "receipts", "targets"}:
        raise ContractError("transaction manifest schema is not closed")
    if value["schema"] != TRANSACTION_SCHEMA or value["generation"] != manifest["generation"]:
        raise ContractError("transaction identity drifted")
    candidate = value["candidate"]
    if not isinstance(candidate, dict) or set(candidate) != {"id", "sha256", "product_sha256"}:
        raise ContractError("transaction candidate schema differs")
    if candidate != {"id": manifest["candidate_id"], "sha256": manifest["candidate_sha256"], "product_sha256": manifest["product_sha256"]}:
        raise ContractError("transaction candidate projection drifted")
    if value["operator_sha256"] != manifest["control_roles"]["operator"]["sha256"]:
        raise ContractError("transaction operator digest drifted")
    runtime = value["runtime"]
    expected_runtime = {
        "python": "/usr/bin/python3",
        "module": "recorder_next",
        "unit": "recorder-next.service",
        "exec_start": "/usr/bin/python3 -m recorder_next --config /etc/recorder-next/recorder-next.toml",
    }
    if runtime != expected_runtime:
        raise ContractError("transaction runtime projection drifted")
    roots = value["roots"]
    expected_roots = {
        "stage": str(generation),
        "live": str(generation / "fixture/live"),
        "receipts": str(generation / "fixture/receipts"),
        "state": str(generation / "fixture/state"),
    }
    if roots != expected_roots:
        raise ContractError("transaction roots drifted")
    receipts = value["receipts"]
    if receipts != expected_receipts(manifest["generation"]):
        raise ContractError("transaction receipt leaves drifted")
    expected_targets = [
        {
            "target": "etc/recorder-next/recorder-next.toml",
            "source": "control/recorder-next.toml",
            "preimage": {"exists": True, "mode": "0444", "sha256": sha256_file(generation / "fixture/live/etc/recorder-next/recorder-next.toml")},
            "postimage": {"mode": "0444", "sha256": manifest["control_roles"]["config"]["sha256"]},
        },
        {
            "target": "etc/systemd/system/recorder-next.service",
            "source": "candidate/systemd/recorder-next.service",
            "preimage": {"exists": False, "mode": None, "sha256": None},
            "postimage": {"mode": "0444", "sha256": sha256_file(generation / "candidate/systemd/recorder-next.service")},
        },
        {
            "target": "usr/local/libexec/recorder-next-release-op.py",
            "source": "control/release_op.py",
            "preimage": {"exists": False, "mode": None, "sha256": None},
            "postimage": {"mode": "0444", "sha256": manifest["control_roles"]["operator"]["sha256"]},
        },
    ]
    if value["targets"] != expected_targets:
        raise ContractError("transaction target cohort is not exact")
    return value


def _command(command: list[str], *, read_only: bool, executed: bool = False) -> dict[str, Any]:
    return {"argv": command, "read_only": read_only, "executed": executed}


def canonical_commands(generation: Path, manifest: Mapping[str, Any], transaction: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    generation = generation.absolute()
    control = generation / "control"
    operator = control / "release_op.py"
    tx_path = control / "transaction-manifest.json"
    manifest_path = generation / "candidate-manifest.json"
    archive = generation.parent / ARCHIVE_NAME
    tx_sha = sha256_file(tx_path)
    op_sha = manifest["control_roles"]["operator"]["sha256"]
    common = [
        "--manifest", str(tx_path),
        "--manifest-sha256", tx_sha,
        "--operator-sha256", op_sha,
        "--stage-root", str(generation),
        "--live-root", str(generation / "fixture/live"),
        "--receipt-root", str(generation / "fixture/receipts"),
        "--state-root", str(generation / "fixture/state"),
        "--candidate-manifest", str(manifest_path),
    ]
    py = "/usr/bin/python3"
    commands: dict[str, dict[str, Any]] = {
        "candidate_verifier": _command([py, "-B", str(control / "verify_candidate.py"), "--generation", str(generation), "--read-only"], read_only=True),
        "operator_stage_verifier": _command([py, "-B", str(operator), "verify-stage", *common, "--candidate-id", manifest["candidate_id"], "--candidate-sha256", manifest["candidate_sha256"], "--archive", str(archive), "--archive-sha256", manifest["candidate_archive"]["sha256"], "--read-only"], read_only=True),
        "preflight": _command([py, "-B", str(control / "preflight_rev14.py"), "--generation", str(generation), "--read-only"], read_only=True),
        "packet_checker": _command([py, "-B", str(control / "activation_packet_check.py"), "--packet", str(control / "activation-packet.json"), "--read-only"], read_only=True),
        "apply": _command([py, "-B", str(operator), "apply", *common], read_only=False),
        "rollback": _command([py, "-B", str(operator), "rollback", *common, "--apply-receipt", transaction["receipts"]["apply"]], read_only=False),
        "rollback_authorization": _command([py, "-B", str(operator), "authorize-rollback", *common, "--apply-receipt", transaction["receipts"]["apply"], "--rollback-receipt", transaction["receipts"]["rollback"], "--read-only"], read_only=True),
        "rollback_readback": _command([py, "-B", str(operator), "readback-rollback", *common, "--rollback-receipt", transaction["receipts"]["rollback"], "--protected-ports", "127.0.0.1:8642,127.0.0.1:8653", "--read-only"], read_only=True),
        "restore_legacy": _command([py, "-B", str(operator), "restore-legacy", *common, "--apply-receipt", transaction["receipts"]["apply"], "--rollback-receipt", transaction["receipts"]["rollback"], "--restore-manifest", str(tx_path), "--restore-only-bound-preimages"], read_only=False),
    }
    return commands


def _expected_managed_cohort(generation: Path, manifest: Mapping[str, Any], transaction: Mapping[str, Any]) -> list[dict[str, Any]]:
    roles = manifest["control_roles"]
    return [
        {"source": str(generation / "control/recorder-next.toml"), "target": "/etc/recorder-next/recorder-next.toml", "sha256": roles["config"]["sha256"], "mode": "0444", "via": "journaled_operator"},
        {"source": str(generation / "candidate/systemd/recorder-next.service"), "target": "/etc/systemd/system/recorder-next.service", "sha256": sha256_file(generation / "candidate/systemd/recorder-next.service"), "mode": "0444", "via": "journaled_operator"},
        {"source": str(generation / "control/release_op.py"), "target": "/usr/local/libexec/recorder-next-release-op.py", "sha256": roles["operator"]["sha256"], "mode": "0444", "via": "journaled_operator"},
    ]


def expected_preflight_report(generation: Path, manifest: Mapping[str, Any], transaction: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": PREFLIGHT_SCHEMA,
        "status": "PASS",
        "ready_to_begin": True,
        "live_authorized": False,
        "approved_for_live_change": False,
        "candidate_only": True,
        "commands_executed": 0,
        "read_only": True,
        "errors": [],
        "generation": manifest["generation"],
        "candidate_id": manifest["candidate_id"],
        "candidate_sha256": manifest["candidate_sha256"],
        "product_sha256": manifest["product_sha256"],
        "transaction_manifest_sha256": sha256_file(generation / "control/transaction-manifest.json"),
        "operator_sha256": manifest["control_roles"]["operator"]["sha256"],
        "freeze_vector_path": "freeze-vector.json",
        "freeze_vector_sidecar": str(expected_sidecar(generation)),
        "control_role_count": len(CONTROL_ROLE_PATHS),
        "required_live_gate": "independent review PASS plus explicit live authorization; no live mutation in this generation",
    }


def expected_candidate_report(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": CANDIDATE_VERIFIER_SCHEMA,
        "status": "PASS",
        "generation": manifest["generation"],
        "candidate_id": manifest["candidate_id"],
        "candidate_sha256": manifest["candidate_sha256"],
        "product_sha256": manifest["product_sha256"],
        "candidate_file_count": manifest["candidate_file_count"],
        "test_count": manifest["test_matrix"]["discovered_count"],
        "test_id_sha256": manifest["test_matrix"]["sorted_test_id_sha256"],
        "read_only": True,
        "commands_executed": 0,
    }


def expected_packet_report(generation: Path, manifest: Mapping[str, Any], transaction: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": PACKET_CHECK_SCHEMA,
        "status": "PASS",
        "generation": manifest["generation"],
        "candidate_id": manifest["candidate_id"],
        "candidate_sha256": manifest["candidate_sha256"],
        "read_only": True,
        "commands_executed": 0,
        "receipt_root": transaction["roots"]["receipts"],
        "freeze_vector_path": "freeze-vector.json",
    }


def _validate_preflight_evidence(generation: Path, manifest: Mapping[str, Any], transaction: Mapping[str, Any]) -> None:
    packet, _, _ = load_json(generation / "control/activation-packet.json", "activation packet")
    evidence = packet.get("preflight_evidence") if isinstance(packet, dict) else None
    if not isinstance(evidence, dict) or set(evidence) != {"path", "sha256", "schema"}:
        raise ContractError("preflight evidence descriptor is not closed")
    if evidence["path"] != "evidence/preflight-final.json" or evidence["schema"] != PREFLIGHT_SCHEMA:
        raise ContractError("preflight evidence path/schema drifted")
    hash_text(evidence["sha256"], "preflight evidence.sha256")
    path = generation / evidence["path"]
    if sha256_file(path) != evidence["sha256"]:
        raise ContractError("preflight evidence hash drifted")
    value, _, _ = load_json(path, "preflight evidence")
    if value != expected_preflight_report(generation, manifest, transaction):
        raise ContractError("fresh preflight evidence does not equal the bound report")


def _validate_producer_report(generation: Path, manifest: Mapping[str, Any], preflight: Mapping[str, Any]) -> None:
    value, _, _ = load_json(generation / "producer-report.json", "producer report")
    expected_keys = {"schema", "status", "generation", "candidate_id", "candidate_sha256", "product_sha256", "candidate_file_count", "product_bytes_changed_from_failed_candidate", "source_archive", "test_matrix", "control_matrix", "preflight", "mutation_counters"}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ContractError("producer report schema is not closed")
    if value["schema"] != PRODUCER_SCHEMA or value["status"] != "PASS":
        raise ContractError("producer report status/schema drifted")
    if value["generation"] != manifest["generation"] or value["candidate_id"] != manifest["candidate_id"] or value["candidate_sha256"] != manifest["candidate_sha256"] or value["product_sha256"] != manifest["product_sha256"] or value["candidate_file_count"] != EXPECTED_PRODUCT_FILE_COUNT or value["product_bytes_changed_from_failed_candidate"] is not PRODUCT_BYTES_CHANGED_FROM_FAILED_CANDIDATE or value["source_archive"] != manifest["source_archive"]:
        raise ContractError("producer product projection drifted")
    matrix = value["test_matrix"]
    if matrix != {"count": manifest["test_matrix"]["discovered_count"], "sorted_test_id_sha256": manifest["test_matrix"]["sorted_test_id_sha256"], "status": "PASS"}:
        raise ContractError("producer test projection drifted")
    controls = value["control_matrix"]
    if not isinstance(controls, dict) or set(controls) != {"status", "operator", "test_count"} or controls["status"] != "PASS" or controls["operator"] != manifest["control_roles"]["operator"]["sha256"] or controls["test_count"] <= 0:
        raise ContractError("producer control projection drifted")
    if value["preflight"] != preflight or value["mutation_counters"] != _expected_mutation_counters():
        raise ContractError("producer preflight or mutation projection drifted")


def validate_freeze(generation: Path, descriptor_value: Mapping[str, Any] | None = None) -> dict[str, Any]:
    vector_path = generation / "freeze-vector.json"
    value, _, _ = load_json(vector_path, "freeze vector")
    expected_keys = {"schema", "status", "entry_count", "actual_entry_count", "duplicate_count", "path_set_exact", "rows", "opening_closing_equal", "non_writable", "excluded", "projection_sha256", "projection_entry_count"}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ContractError("freeze vector schema is not closed")
    if value["schema"] != FREEZE_SCHEMA or value["status"] != "SEALED" or value["excluded"] != ["freeze-vector.json"]:
        raise ContractError("freeze vector status/schema drifted")
    rows = tree_rows(generation, "generation")
    rows = [row for row in rows if row["path"] != "freeze-vector.json"]
    if len({row["path"] for row in rows}) != len(rows):
        raise ContractError("freeze vector contains duplicate paths")
    projection_digest = freeze_projection_digest(rows)
    if value["rows"] != rows or value["entry_count"] != len(rows) or value["actual_entry_count"] != len(rows) or value["duplicate_count"] != 0 or value["path_set_exact"] is not True or value["opening_closing_equal"] is not True or value["non_writable"] is not True or value["projection_sha256"] != projection_digest or value["projection_entry_count"] != len(rows):
        raise ContractError("freeze vector does not equal the current generation")
    bookend_expected = [row for row in rows if row["path"] not in {"opening-vector.json", "closing-vector.json"}]
    for name, phase in (("opening-vector.json", "OPENING"), ("closing-vector.json", "CLOSING")):
        bookend, _, _ = load_json(generation / name, f"{phase.lower()} vector")
        if not isinstance(bookend, dict) or set(bookend) != {"schema", "phase", "entry_count", "rows"} or bookend["schema"] != "recorder-next-bookend-vector/v1" or bookend["phase"] != phase or bookend["entry_count"] != len(bookend_expected) or bookend["rows"] != bookend_expected:
            raise ContractError(f"{phase.lower()} vector is not an exact bookend")
    if descriptor_value is not None and (descriptor_value.get("sha256") != projection_digest or descriptor_value.get("entry_count") != len(rows)):
        raise ContractError("packet/manifest freeze projection hash or count drifted")
    if descriptor_value is not None:
        sidecar = canonical_absolute(descriptor_value["sidecar"], "freeze_vector.sidecar")
    else:
        sidecar = expected_sidecar(generation)
    regular(sidecar, "freeze vector sidecar")
    expected_line = f"{sha256_file(vector_path)}  {generation.name}/freeze-vector.json\n"
    if sidecar.read_text(encoding="utf-8") != expected_line:
        raise ContractError("freeze vector sidecar digest or referent drifted")
    root_info = generation.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) & 0o222:
        raise ContractError("frozen generation root is writable")
    for path in sorted(generation.rglob("*"), key=lambda item: len(item.parts)):
        if path.is_symlink():
            raise ContractError("frozen generation contains a symlink")
        if path.is_dir():
            if stat.S_IMODE(path.stat().st_mode) & 0o222:
                raise ContractError(f"frozen directory is writable: {path}")
        elif path.is_file() and stat.S_IMODE(path.stat().st_mode) & 0o222:
            raise ContractError(f"frozen file is writable: {path}")
    return value


def validate_packet(generation: Path, packet_path: Path, manifest: Mapping[str, Any] | None = None, transaction: Mapping[str, Any] | None = None) -> dict[str, Any]:
    generation = generation.absolute()
    expected_packet_path = generation / "control/activation-packet.json"
    packet_path = packet_path.absolute()
    if packet_path != expected_packet_path or packet_path != packet_path.resolve() or packet_path.is_symlink():
        raise ContractError("activation packet path is not canonical; receipt referents are untrusted")
    if manifest is None:
        manifest = validate_manifest(generation)
    if transaction is None:
        transaction = validate_transaction(generation / "control/transaction-manifest.json", generation, manifest)
    value, _, _ = load_json(packet_path, "activation packet")
    expected_keys = {"schema", "status", "execution_policy", "generation", "candidate_id", "candidate_sha256", "product_sha256", "operator", "transaction_manifest", "freeze_vector", "preflight_evidence", "apply", "rollback", "install", "install_plan", "managed_cohort", "commands", "activation_sequence", "rollback_sequence", "mutation_counters"}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ContractError("activation packet top-level keys differ")
    if value["schema"] != PACKET_SCHEMA or value["status"] != "CANDIDATE_ONLY" or value["execution_policy"] != "read_only_smokes_only":
        raise ContractError("activation packet is not candidate-only")
    if value["generation"] != manifest["generation"] or value["candidate_id"] != manifest["candidate_id"] or value["candidate_sha256"] != manifest["candidate_sha256"] or value["product_sha256"] != manifest["product_sha256"]:
        raise ContractError("activation packet candidate projection drifted")
    operator = value["operator"]
    if not isinstance(operator, dict) or set(operator) != {"path", "sha256", "runtime_python", "module", "unit"}:
        raise ContractError("activation packet operator schema differs")
    if operator != {"path": str(generation / "control/release_op.py"), "sha256": manifest["control_roles"]["operator"]["sha256"], "runtime_python": "/usr/bin/python3", "module": "recorder_next", "unit": "recorder-next.service"}:
        raise ContractError("activation packet operator projection drifted")
    tx_descriptor = value["transaction_manifest"]
    if not isinstance(tx_descriptor, dict) or set(tx_descriptor) != {"path", "sha256"} or tx_descriptor["path"] != str(generation / "control/transaction-manifest.json") or tx_descriptor["sha256"] != sha256_file(generation / "control/transaction-manifest.json"):
        raise ContractError("activation packet transaction projection drifted")
    if value["freeze_vector"] != manifest["freeze_vector"]:
        raise ContractError("activation packet freeze-vector projection drifted")
    evidence = value["preflight_evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {"path", "sha256", "schema"}:
        raise ContractError("activation packet preflight evidence schema differs")
    if evidence["path"] != "evidence/preflight-final.json" or evidence["sha256"] != manifest["evidence"]["evidence/preflight-final.json"]["sha256"] or evidence["schema"] != PREFLIGHT_SCHEMA:
        raise ContractError("activation packet preflight evidence projection drifted")
    if value["mutation_counters"] != _expected_mutation_counters():
        raise ContractError("activation packet mutation counter drifted")

    commands = canonical_commands(generation, manifest, transaction)
    command_keys = {"candidate_verifier", "operator_stage_verifier", "preflight", "packet_checker", "apply", "rollback", "rollback_authorization", "rollback_readback", "restore_legacy"}
    packet_commands = value["commands"]
    if not isinstance(packet_commands, dict) or set(packet_commands) != command_keys:
        raise ContractError("activation packet command role map is not closed")
    if packet_commands != commands:
        raise ContractError("activation packet contains a non-canonical command vector")

    apply = value["apply"]
    rollback = value["rollback"]
    section_keys = {"receipt_root", "apply_receipt", "rollback_receipt", "journal", "argv", "executed", "mutation"}
    for label, section in (("apply", apply), ("rollback", rollback)):
        if not isinstance(section, dict) or set(section) != section_keys:
            raise ContractError(f"{label} section schema differs")
        if section["receipt_root"] != transaction["roots"]["receipts"] or section["apply_receipt"] != transaction["receipts"]["apply"] or section["rollback_receipt"] != transaction["receipts"]["rollback"] or section["journal"] != transaction["receipts"]["journal"] or section["argv"] != commands[label]["argv"] or section["executed"] is not False or section["mutation"] is not True:
            raise ContractError(f"{label} section projection drifted")
        for key in ("apply_receipt", "rollback_receipt", "journal"):
            leaf(section[key], f"{label}.{key}")

    install = value["install"]
    if install != {"argv": ["/usr/bin/sha256sum", str(generation / "control/release_op.py")], "executed": False, "mutation": False, "identity": {"path": "/usr/local/libexec/recorder-next-release-op.py", "sha256": manifest["control_roles"]["operator"]["sha256"], "mode": "0444"}}:
        raise ContractError("operator install identity projection drifted")
    install_plan = value["install_plan"]
    expected_plan = {"argv": ["install", "-D", "-o", "root", "-g", "root", "-m", "0444", str(generation / "control/release_op.py"), "/usr/local/libexec/recorder-next-release-op.py"], "executed": False, "mutation": True, "via": "journaled_operator_target", "reason": "The direct install plan is retained for identity review only; the activation packet never dispatches an unjournaled install. The journaled operator apply owns this target."}
    if install_plan != expected_plan:
        raise ContractError("operator install plan drifted")
    if value["managed_cohort"] != _expected_managed_cohort(generation, manifest, transaction):
        raise ContractError("managed cohort projection drifted")

    freeze = value["freeze_vector"]
    if not isinstance(freeze, dict) or set(freeze) != {"path", "sidecar", "excluded", "sha256", "entry_count"}:
        raise ContractError("packet freeze-vector schema differs")
    validate_freeze(generation, freeze)
    expected_activation = [
        {"step": 1, "name": "bind_candidate_and_preimages", "mutation": False, "commands": [commands["candidate_verifier"]["argv"], commands["operator_stage_verifier"]["argv"], commands["preflight"]["argv"]], "gate": "all candidate rows, stage referents, and read-only preflight predicates pass"},
        {"step": 2, "name": "install_operator_and_apply_exact_cohort", "mutation": True, "commands": [install["argv"], commands["apply"]["argv"]], "executed": False, "gate": "independent review PASS and exact live preimages are revalidated before journaled apply"},
    ]
    expected_rollback = [
        {"step": 1, "name": "authorize_exact_apply_receipt", "mutation": False, "commands": [commands["rollback_authorization"]["argv"], commands["preflight"]["argv"]], "gate": "inode-bound apply receipt and journal are exact"},
        {"step": 2, "name": "restore_legacy_preimages", "mutation": True, "commands": [commands["restore_legacy"]["argv"]], "executed": False, "gate": "only receipt-bound preimages are restored"},
        {"step": 3, "name": "rollback_readback", "mutation": False, "commands": [commands["rollback_readback"]["argv"]], "gate": "rollback receipt, target vector, and protected surfaces read back exactly"},
    ]
    if value["activation_sequence"] != expected_activation or value["rollback_sequence"] != expected_rollback:
        raise ContractError("activation or rollback sequence drifted")
    return value


def validate_generation(generation: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest = validate_manifest(generation)
    transaction = validate_transaction(generation / "control/transaction-manifest.json", generation, manifest)
    packet = validate_packet(generation, generation / "control/activation-packet.json", manifest, transaction)
    preflight = expected_preflight_report(generation, manifest, transaction)
    _validate_preflight_evidence(generation, manifest, transaction)
    _validate_producer_report(generation, manifest, preflight)
    return manifest, transaction, packet


def stage_report(manifest: Mapping[str, Any], archive_sha256: str, source_count: int = 3) -> dict[str, Any]:
    return {
        "schema": STAGE_VERIFIER_SCHEMA,
        "status": "PASS",
        "generation": manifest["generation"],
        "candidate_id": manifest["candidate_id"],
        "candidate_sha256": manifest["candidate_sha256"],
        "operator_sha256": manifest["control_roles"]["operator"]["sha256"],
        "source_count": source_count,
        "archive_sha256": archive_sha256,
        "source_archive": manifest["source_archive"],
        "read_only": True,
        "commands_executed": 0,
    }