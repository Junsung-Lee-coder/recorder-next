#!/usr/bin/env python3
"""Build one deterministic, candidate-only Recorder Next feature generation."""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

from control_contract import (
    ARCHIVE_NAME,
    CANDIDATE_HASH_ALGORITHM,
    CANDIDATE_VERIFIER_SCHEMA,
    CHANGED_PRODUCT_PATHS_FROM_FAILED_CANDIDATE,
    EVIDENCE_PATHS,
    EXPECTED_PRODUCT_FILE_COUNT,
    EXPECTED_PRODUCT_SHA,
    FREEZE_SCHEMA,
    MANIFEST_SCHEMA,
    PACKET_CHECK_SCHEMA,
    PACKET_SCHEMA,
    PREFLIGHT_SCHEMA,
    PREDECESSOR,
    PRODUCT_IDENTITY,
    PRODUCT_BYTES_CHANGED_FROM_FAILED_CANDIDATE,
    PRODUCER_SCHEMA,
    STAGE_VERIFIER_SCHEMA,
    TRANSACTION_SCHEMA,
    _expected_control_rows,
    _expected_mutation_counters,
    _test_ids,
    canonical_commands,
    candidate_id,
    candidate_sha,
    expected_packet_report,
    expected_preflight_report,
    expected_receipts,
    expected_sidecar,
    freeze_projection_digest,
    json_bytes,
    product_sha,
    sha256_bytes,
    sha256_file,
    stage_report,
    tree_rows,
    write_json,
)

GENERATION = "feature-groups-r2-rev33"
CONTROL_TEST_SOURCES = {
    "tests/test_activation_controls.py",
    "tests/test_generation_contract.py",
    "tests/test_activation_provenance_regressions.py",
    "tests/test_rev16_repairs.py",
    "tests/test_rev17_repairs.py",
    # Owner-correction tests validate the producer contract but are not part
    # of the 50-file product payload.  Keeping them control-only preserves
    # the frozen product cardinality while the full workspace still runs
    # them during producer verification.
    "tests/test_owner_corrections.py",
}


class BuildError(RuntimeError):
    pass


def product_paths(repo: Path) -> list[Path]:
    result: list[Path] = []
    for path in sorted((p for p in repo.rglob("*") if p.is_file()), key=lambda p: p.relative_to(repo).as_posix()):
        relative = path.relative_to(repo)
        rel = relative.as_posix()
        if ".git" in relative.parts or rel in CONTROL_TEST_SOURCES or rel.startswith("release/") or rel.startswith("artifacts/"):
            continue
        if "__pycache__" in path.parts or ".pytest_cache" in path.parts or path.suffix == ".pyc":
            continue
        result.append(path)
    return result


def copy_product(repo: Path, candidate: Path) -> list[dict[str, Any]]:
    for source in product_paths(repo):
        relative = source.relative_to(repo)
        target = candidate / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        os.chmod(target, 0o444)
    rows = tree_rows(candidate, "candidate", expected_mode="0444")
    if len(rows) != EXPECTED_PRODUCT_FILE_COUNT:
        raise BuildError(f"product candidate has {len(rows)} files, expected {EXPECTED_PRODUCT_FILE_COUNT}")
    return rows


def make_archive(candidate: Path, archive: Path) -> None:
    with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as output:
        for source in sorted((p for p in candidate.rglob("*") if p.is_file()), key=lambda p: p.relative_to(candidate).as_posix()):
            data = source.read_bytes()
            info = tarfile.TarInfo(source.relative_to(candidate).as_posix())
            info.size = len(data)
            info.mode = 0o444
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            output.addfile(info, io.BytesIO(data))
    os.chmod(archive, 0o444)


def run(argv: list[str], *, cwd: Path, log: Path, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    log.parent.mkdir(parents=True, exist_ok=True)
    rendered = result.stdout
    if result.stderr:
        rendered += "\n--- stderr ---\n" + result.stderr
    rendered = re.sub(r"(Ran \d+ tests in) [0-9.]+s", r"\1 <sealed-duration>", rendered)
    log.write_text(rendered, encoding="utf-8")
    return result


def run_capture(argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True, check=False)


def copy_controls(repo: Path, generation: Path) -> None:
    control = generation / "control"
    control.mkdir(parents=True, exist_ok=True)
    for name in ("control_contract.py", "release_op.py", "verify_candidate.py", "activation_packet_check.py", "preflight_rev14.py", "recorder-next.toml", "build_candidate.py"):
        target = control / name
        shutil.copyfile(repo / "release" / name, target)
        os.chmod(target, 0o444)
    operator_tests = (repo / "tests/test_activation_controls.py").read_text(encoding="utf-8")
    operator_tests = operator_tests.replace('OPERATOR = ROOT / "release" / "release_op.py"', 'OPERATOR = ROOT / "control" / "release_op.py"')
    operator_tests = operator_tests.replace('CONFIG = ROOT / "release" / "recorder-next.toml"', 'CONFIG = ROOT / "control" / "recorder-next.toml"')
    operator_matrix = control / "test_operator_matrix.py"
    operator_matrix.write_text(operator_tests, encoding="utf-8")
    os.chmod(operator_matrix, 0o444)
    provenance_tests = control / "test_activation_provenance_regressions.py"
    shutil.copyfile(repo / "tests/test_activation_provenance_regressions.py", provenance_tests)
    os.chmod(provenance_tests, 0o444)
    repair_tests = control / "test_rev17_repairs.py"
    shutil.copyfile(repo / "tests/test_rev17_repairs.py", repair_tests)
    os.chmod(repair_tests, 0o444)


def make_transaction(generation: Path, candidate_id_value: str, candidate_sha256: str, operator_sha256: str) -> tuple[Path, dict[str, Any]]:
    fixture = generation / "fixture"
    live = fixture / "live"
    receipts = fixture / "receipts"
    state = fixture / "state"
    for path in (live / "etc/recorder-next", live / "etc/systemd/system", live / "usr/local/libexec", receipts, state):
        path.mkdir(parents=True, exist_ok=True)
    lock = receipts / "operator.lock"
    lock.touch()
    os.chmod(lock, 0o444)
    old_config = live / "etc/recorder-next/recorder-next.toml"
    old_config.write_text("[server]\nport = 8643\n", encoding="utf-8")
    os.chmod(old_config, 0o444)
    data = {
        "schema": TRANSACTION_SCHEMA,
        "generation": GENERATION,
        "candidate": {"id": candidate_id_value, "sha256": candidate_sha256, "product_sha256": EXPECTED_PRODUCT_SHA},
        "operator_sha256": operator_sha256,
        "runtime": {"python": "/usr/bin/python3", "module": "recorder_next", "unit": "recorder-next.service", "exec_start": "/usr/bin/python3 -m recorder_next --config /etc/recorder-next/recorder-next.toml"},
        "roots": {"stage": str(generation.resolve()), "live": str(live.resolve()), "receipts": str(receipts.resolve()), "state": str(state.resolve())},
        "receipts": expected_receipts(GENERATION),
        "targets": [
            {
                "target": "etc/recorder-next/recorder-next.toml",
                "source": "control/recorder-next.toml",
                "preimage": {"exists": True, "mode": "0444", "sha256": sha256_file(old_config)},
                "postimage": {"mode": "0444", "sha256": sha256_file(generation / "control/recorder-next.toml")},
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
                "postimage": {"mode": "0444", "sha256": operator_sha256},
            },
        ],
    }
    path = generation / "control/transaction-manifest.json"
    write_json(path, data)
    return path, data


def make_packet(generation: Path, manifest: dict[str, Any], transaction: dict[str, Any]) -> Path:
    control = generation / "control"
    transaction_path = control / "transaction-manifest.json"
    tx_sha = sha256_file(transaction_path)
    commands = canonical_commands(generation, manifest, transaction)
    operator = {"path": str(control / "release_op.py"), "sha256": manifest["control_roles"]["operator"]["sha256"], "runtime_python": "/usr/bin/python3", "module": "recorder_next", "unit": "recorder-next.service"}
    freeze = manifest["freeze_vector"]
    evidence_path = "evidence/preflight-final.json"
    packet = {
        "schema": PACKET_SCHEMA,
        "status": "CANDIDATE_ONLY",
        "execution_policy": "read_only_smokes_only",
        "generation": GENERATION,
        "candidate_id": manifest["candidate_id"],
        "candidate_sha256": manifest["candidate_sha256"],
        "product_sha256": manifest["product_sha256"],
        "operator": operator,
        "transaction_manifest": {"path": str(transaction_path), "sha256": tx_sha},
        "freeze_vector": freeze,
        "preflight_evidence": {"path": evidence_path, "sha256": manifest["evidence"][evidence_path]["sha256"], "schema": PREFLIGHT_SCHEMA},
        "apply": {"receipt_root": transaction["roots"]["receipts"], "apply_receipt": transaction["receipts"]["apply"], "rollback_receipt": transaction["receipts"]["rollback"], "journal": transaction["receipts"]["journal"], "argv": commands["apply"]["argv"], "executed": False, "mutation": True},
        "rollback": {"receipt_root": transaction["roots"]["receipts"], "apply_receipt": transaction["receipts"]["apply"], "rollback_receipt": transaction["receipts"]["rollback"], "journal": transaction["receipts"]["journal"], "argv": commands["rollback"]["argv"], "executed": False, "mutation": True},
        "install": {"argv": ["/usr/bin/sha256sum", str(control / "release_op.py")], "executed": False, "mutation": False, "identity": {"path": "/usr/local/libexec/recorder-next-release-op.py", "sha256": manifest["control_roles"]["operator"]["sha256"], "mode": "0444"}},
        "install_plan": {"argv": ["install", "-D", "-o", "root", "-g", "root", "-m", "0444", str(control / "release_op.py"), "/usr/local/libexec/recorder-next-release-op.py"], "executed": False, "mutation": True, "via": "journaled_operator_target", "reason": "The direct install plan is retained for identity review only; the activation packet never dispatches an unjournaled install. The journaled operator apply owns this target."},
        "managed_cohort": [
            {"source": str(control / "recorder-next.toml"), "target": "/etc/recorder-next/recorder-next.toml", "sha256": manifest["control_roles"]["config"]["sha256"], "mode": "0444", "via": "journaled_operator"},
            {"source": str(generation / "candidate/systemd/recorder-next.service"), "target": "/etc/systemd/system/recorder-next.service", "sha256": sha256_file(generation / "candidate/systemd/recorder-next.service"), "mode": "0444", "via": "journaled_operator"},
            {"source": str(control / "release_op.py"), "target": "/usr/local/libexec/recorder-next-release-op.py", "sha256": manifest["control_roles"]["operator"]["sha256"], "mode": "0444", "via": "journaled_operator"},
        ],
        "commands": commands,
        "activation_sequence": [
            {"step": 1, "name": "bind_candidate_and_preimages", "mutation": False, "commands": [commands["candidate_verifier"]["argv"], commands["operator_stage_verifier"]["argv"], commands["preflight"]["argv"]], "gate": "all candidate rows, stage referents, and read-only preflight predicates pass"},
            {"step": 2, "name": "install_operator_and_apply_exact_cohort", "mutation": True, "commands": [["/usr/bin/sha256sum", str(control / "release_op.py")], commands["apply"]["argv"]], "executed": False, "gate": "independent review PASS and exact live preimages are revalidated before journaled apply"},
        ],
        "rollback_sequence": [
            {"step": 1, "name": "authorize_exact_apply_receipt", "mutation": False, "commands": [commands["rollback_authorization"]["argv"], commands["preflight"]["argv"]], "gate": "inode-bound apply receipt and journal are exact"},
            {"step": 2, "name": "restore_legacy_preimages", "mutation": True, "commands": [commands["restore_legacy"]["argv"]], "executed": False, "gate": "only receipt-bound preimages are restored"},
            {"step": 3, "name": "rollback_readback", "mutation": False, "commands": [commands["rollback_readback"]["argv"]], "gate": "rollback receipt, target vector, and protected surfaces read back exactly"},
        ],
        "mutation_counters": _expected_mutation_counters(),
    }
    path = control / "activation-packet.json"
    write_json(path, packet)
    return path


def evidence_descriptor(generation: Path, relative: str) -> dict[str, Any]:
    path = generation / relative
    data = path.read_bytes()
    return {"path": relative, "sha256": sha256_bytes(data), "size": len(data)}


def manifest_template(generation: Path, members: list[dict[str, Any]], product_digest: str, archive: Path, roles: dict[str, dict[str, Any]], transaction_path: Path, transaction: dict[str, Any], candidate_sha256: str, candidate_id_value: str) -> dict[str, Any]:
    candidate_archive = {"path": str(archive.resolve()), "sha256": sha256_file(archive), "size": archive.stat().st_size, "role": "candidate_archive"}
    test_ids, id_sha = _test_ids(generation / "candidate")
    test_rows = [row for row in members if row["path"].startswith("tests/") and row["path"].endswith(".py")]
    test_payload = "".join(f"{row['path']}\0{row['size']}\0{row['sha256']}\n" for row in test_rows).encode("utf-8")
    placeholder = {"path": "pending", "sha256": "0" * 64, "size": 0}
    evidence = {relative: placeholder.copy() for relative in EVIDENCE_PATHS}
    return {
        "schema": MANIFEST_SCHEMA,
        "status": "FROZEN",
        "generation": GENERATION,
        "candidate_id": candidate_id_value,
        "candidate_sha256": candidate_sha256,
        "candidate_hash_algorithm": CANDIDATE_HASH_ALGORITHM,
        "candidate_file_count": len(members),
        "candidate_total_bytes": sum(row["size"] for row in members),
        "candidate_members": members,
        "candidate_archive": candidate_archive,
        "source_archive": candidate_archive.copy(),
        "product_identity": PRODUCT_IDENTITY,
        "product_sha256": product_digest,
        "product_bytes_changed_from_failed_candidate": PRODUCT_BYTES_CHANGED_FROM_FAILED_CANDIDATE,
        "changed_product_paths_from_failed_candidate": CHANGED_PRODUCT_PATHS_FROM_FAILED_CANDIDATE,
        "predecessor": PREDECESSOR,
        "candidate_only_not_applied": True,
        "approved_for_live_change": False,
        "live_authorized": False,
        "commands_executed": 0,
        "mutation_counters": _expected_mutation_counters(),
        "transaction": {"path": str(transaction_path.resolve()), "sha256": sha256_file(transaction_path), "roots": transaction["roots"], "receipts": transaction["receipts"], "operator_sha256": roles["operator"]["sha256"]},
        "packet": {"path": "control/activation-packet.json", "sha256": "0" * 64, "size": 0},
        "control_roles": roles,
        "test_matrix": {"schema": "recorder-next-test-matrix/v2", "status": "PASS", "discovered_count": len(test_ids), "unique_count": len(test_ids), "duplicate_count": 0, "sorted_test_id_sha256": id_sha, "ids": test_ids, "test_source_file_count": len(test_rows), "test_source_sha256": sha256_bytes(test_payload), "test_source_rows": test_rows, "status_code": 0},
        "evidence": evidence,
        "producer_report": {"path": "producer-report.json", "sha256": "0" * 64, "size": 0},
        "freeze_vector": {"path": "freeze-vector.json", "sidecar": str(expected_sidecar(generation)), "excluded": ["freeze-vector.json"], "sha256": "0" * 64, "entry_count": 0},
    }


def snapshot_rows(generation: Path, excluded: set[str]) -> list[dict[str, Any]]:
    rows = tree_rows(generation, "generation")
    return [row for row in rows if row["path"] not in excluded]


def seal_vectors(generation: Path) -> None:
    # All generation bytes are final before the bookends are taken.
    for path in sorted(generation.rglob("*"), key=lambda item: len(item.parts)):
        if path.is_symlink():
            raise BuildError(f"symlink in generation: {path}")
        if path.is_dir():
            os.chmod(path, 0o555)
        elif path.is_file():
            os.chmod(path, 0o444)
    excluded = {"opening-vector.json", "closing-vector.json", "freeze-vector.json"}
    rows = snapshot_rows(generation, excluded)
    bookend = {"schema": "recorder-next-bookend-vector/v1", "phase": "OPENING", "entry_count": len(rows), "rows": rows}
    write_json(generation / "opening-vector.json", bookend)
    bookend["phase"] = "CLOSING"
    write_json(generation / "closing-vector.json", bookend)
    os.chmod(generation / "opening-vector.json", 0o444)
    os.chmod(generation / "closing-vector.json", 0o444)
    freeze_rows = snapshot_rows(generation, {"freeze-vector.json"})
    descriptor = json.loads((generation / "candidate-manifest.json").read_text(encoding="utf-8"))["freeze_vector"]
    freeze = {"schema": FREEZE_SCHEMA, "status": "SEALED", "entry_count": len(freeze_rows), "actual_entry_count": len(freeze_rows), "duplicate_count": 0, "path_set_exact": True, "rows": freeze_rows, "opening_closing_equal": True, "non_writable": True, "excluded": ["freeze-vector.json"], "projection_sha256": freeze_projection_digest(freeze_rows), "projection_entry_count": len(freeze_rows)}
    if descriptor["sha256"] != freeze["projection_sha256"] or descriptor["entry_count"] != freeze["projection_entry_count"]:
        raise BuildError("freeze projection descriptor changed while sealing")
    write_json(generation / "freeze-vector.json", freeze)
    os.chmod(generation / "freeze-vector.json", 0o444)
    sidecar = expected_sidecar(generation)
    sidecar.write_text(f"{sha256_file(generation / 'freeze-vector.json')}  {generation.name}/freeze-vector.json\n", encoding="utf-8")
    os.chmod(sidecar, 0o444)
    os.chmod(generation, 0o555)


def parse_test_count(log: Path) -> int:
    match = re.search(r"Ran (\d+) tests?", log.read_text(encoding="utf-8"))
    if match is None:
        raise BuildError(f"test count missing from {log}")
    return int(match.group(1))


def build(repo: Path, output: Path) -> Path:
    if output.exists() or output.is_symlink():
        if output.is_symlink() or not output.is_dir():
            raise BuildError("output must be a disposable directory")
        old_sidecar = expected_sidecar(output)
        if old_sidecar.exists():
            os.chmod(old_sidecar, 0o644)
        old_archive = output.parent / ARCHIVE_NAME
        if old_archive.exists():
            os.chmod(old_archive, 0o644)
        for path in sorted(output.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_symlink():
                raise BuildError("refusing to remove a symlink from the prior output")
            if path.is_dir():
                os.chmod(path, 0o755)
            elif path.is_file():
                os.chmod(path, 0o644)
        os.chmod(output, 0o755)
        shutil.rmtree(output)
    output.mkdir(parents=True)
    generation = output.resolve()
    (generation / "candidate").mkdir()
    copy_controls(repo, generation)
    members = copy_product(repo, generation / "candidate")
    digest = product_sha(members)
    if digest != EXPECTED_PRODUCT_SHA:
        raise BuildError(f"accepted product SHA changed: {digest}")
    candidate_sha256 = candidate_sha(GENERATION, digest)
    candidate_id_value = candidate_id(GENERATION, digest)
    archive = output.parent / ARCHIVE_NAME
    make_archive(generation / "candidate", archive)
    roles = _expected_control_rows(generation)
    transaction_path, transaction = make_transaction(generation, candidate_id_value, candidate_sha256, roles["operator"]["sha256"])

    product_log = generation / "evidence/product-full-suite.log"
    product_result = run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "candidate/tests", "-p", "test_*.py"], cwd=generation, log=product_log, extra_env={"PYTHONPATH": str(generation / "candidate")})
    if product_result.returncode != 0:
        raise BuildError(f"product suite failed: {product_result.stderr}")
    product_test_count = parse_test_count(product_log)
    if product_test_count != 117:
        raise BuildError(f"product suite ran {product_test_count}, expected 117")

    manifest = manifest_template(generation, members, digest, archive, roles, transaction_path, transaction, candidate_sha256, candidate_id_value)
    # The preflight report is deterministic and does not bind later evidence hashes.
    write_json(generation / "candidate-manifest.json", manifest)
    preflight = expected_preflight_report(generation, manifest, transaction)
    write_json(generation / "evidence/preflight-final.json", preflight)
    manifest["evidence"]["evidence/preflight-final.json"] = evidence_descriptor(generation, "evidence/preflight-final.json")
    make_packet(generation, manifest, transaction)
    manifest["packet"] = evidence_descriptor(generation, "control/activation-packet.json")

    candidate_report = {
        "schema": CANDIDATE_VERIFIER_SCHEMA,
        "status": "PASS",
        "generation": GENERATION,
        "candidate_id": candidate_id_value,
        "candidate_sha256": candidate_sha256,
        "product_sha256": digest,
        "candidate_file_count": len(members),
        "test_count": product_test_count,
        "test_id_sha256": manifest["test_matrix"]["sorted_test_id_sha256"],
        "read_only": True,
        "commands_executed": 0,
    }
    write_json(generation / "evidence/candidate-verifier-final.json", candidate_report)
    write_json(generation / "evidence/operator-stage-verifier-final.json", stage_report(manifest, archive_sha256=archive and sha256_file(archive)))
    packet = json.loads((generation / "control/activation-packet.json").read_text(encoding="utf-8"))
    write_json(generation / "evidence/packet-check-final.json", expected_packet_report(generation, manifest, transaction))

    # Give the copied control suite its final manifest projection before it runs.
    write_json(generation / "candidate-manifest.json", manifest)
    control_log = generation / "evidence/control-suite.log"
    control_result = run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "control", "-p", "test_*.py"],
        cwd=generation,
        log=control_log,
        extra_env={
            "PYTHONPATH": os.pathsep.join((str(generation / "control"), str(generation / "candidate"))),
            "RECORDER_NEXT_BUILDER": str(generation / "control/build_candidate.py"),
        },
    )
    if control_result.returncode != 0:
        raise BuildError(f"control suite failed: {control_result.stderr}")
    control_test_count = parse_test_count(control_log)

    for relative in EVIDENCE_PATHS:
        if relative == "evidence/control-suite.log":
            continue
        manifest["evidence"][relative] = evidence_descriptor(generation, relative)
    manifest["evidence"]["evidence/control-suite.log"] = evidence_descriptor(generation, "evidence/control-suite.log")
    producer = {
        "schema": PRODUCER_SCHEMA,
        "status": "PASS",
        "generation": GENERATION,
        "candidate_id": candidate_id_value,
        "candidate_sha256": candidate_sha256,
        "product_sha256": digest,
        "candidate_file_count": len(members),
        "product_bytes_changed_from_failed_candidate": PRODUCT_BYTES_CHANGED_FROM_FAILED_CANDIDATE,
        "source_archive": manifest["source_archive"],
        "test_matrix": {"count": product_test_count, "sorted_test_id_sha256": manifest["test_matrix"]["sorted_test_id_sha256"], "status": "PASS"},
        "control_matrix": {"status": "PASS", "operator": roles["operator"]["sha256"], "test_count": control_test_count},
        "preflight": preflight,
        "mutation_counters": _expected_mutation_counters(),
    }
    write_json(generation / "producer-report.json", producer)
    manifest["producer_report"] = evidence_descriptor(generation, "producer-report.json")
    for path in sorted(generation.rglob("*"), key=lambda item: len(item.parts)):
        if path.is_symlink():
            raise BuildError(f"symlink in generation: {path}")
        if path.is_dir():
            os.chmod(path, 0o555)
        elif path.is_file():
            os.chmod(path, 0o444)
    base_rows = snapshot_rows(generation, {"opening-vector.json", "closing-vector.json", "freeze-vector.json"})
    manifest["freeze_vector"] = {"path": "freeze-vector.json", "sidecar": str(expected_sidecar(generation)), "excluded": ["freeze-vector.json"], "sha256": freeze_projection_digest(base_rows), "entry_count": len(base_rows) + 2}
    os.chmod(generation / "candidate-manifest.json", 0o644)
    write_json(generation / "candidate-manifest.json", manifest)
    os.chmod(generation / "candidate-manifest.json", 0o444)
    os.chmod(generation / "control/activation-packet.json", 0o644)
    make_packet(generation, manifest, transaction)
    os.chmod(generation / "control/activation-packet.json", 0o444)
    manifest["packet"] = evidence_descriptor(generation, "control/activation-packet.json")
    os.chmod(generation / "candidate-manifest.json", 0o644)
    write_json(generation / "candidate-manifest.json", manifest)
    os.chmod(generation / "candidate-manifest.json", 0o444)
    seal_vectors(generation)

    # Final read-only smokes are the only commands after sealing.
    final_packet = json.loads((generation / "control/activation-packet.json").read_text(encoding="utf-8"))
    expected_outputs = {
        "candidate_verifier": candidate_report,
        "operator_stage_verifier": stage_report(manifest, sha256_file(archive)),
        "preflight": preflight,
        "packet_checker": expected_packet_report(generation, manifest, transaction),
    }
    for name in ("candidate_verifier", "operator_stage_verifier", "preflight", "packet_checker"):
        result = run_capture(final_packet["commands"][name]["argv"], cwd=generation)
        if result.returncode != 0:
            raise BuildError(f"final {name} failed: {result.stderr}")
        try:
            observed = json.loads(result.stdout)
        except ValueError as exc:
            raise BuildError(f"final {name} did not emit JSON") from exc
        if observed != expected_outputs[name]:
            raise BuildError(f"final {name} output drifted")
    return generation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        generation = build(args.repo_root.resolve(), args.output.resolve())
        manifest = json.loads((generation / "candidate-manifest.json").read_text(encoding="utf-8"))
        print(json.dumps({"status": "PASS", "generation": str(generation), "candidate_id": manifest["candidate_id"], "candidate_sha256": manifest["candidate_sha256"], "product_sha256": manifest["product_sha256"], "control_suite_tests": json.loads((generation / "producer-report.json").read_text(encoding="utf-8"))["control_matrix"]["test_count"]}, sort_keys=True))
        return 0
    except (BuildError, OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
