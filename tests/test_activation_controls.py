from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
OPERATOR = ROOT / "release" / "release_op.py"
CONFIG = ROOT / "release" / "recorder-next.toml"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_operator(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged["PYTHONPATH"] = str(ROOT) + os.pathsep + merged.get("PYTHONPATH", "")
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, "-B", str(OPERATOR), *args],
        cwd=ROOT,
        env=merged,
        capture_output=True,
        text=True,
        check=False,
    )


def make_manifest(root: Path, operator_sha256: str) -> tuple[Path, dict[str, object]]:
    stage = root / "stage"
    live = root / "live"
    receipts = root / "receipts"
    state = root / "state"
    for path in (stage / "config", stage / "unit", live / "etc/recorder-next", live / "etc/systemd/system", live / "opt/recorder-next", receipts, state):
        path.mkdir(parents=True, exist_ok=True)
    (receipts / "operator.lock").touch(mode=0o600)
    os.chmod(receipts / "operator.lock", 0o600)
    (stage / "config/recorder-next.toml").write_text("[server]\nport = 8653\n", encoding="utf-8")
    (stage / "unit/recorder-next.service").write_text("[Service]\nExecStart=/usr/bin/python3 -m recorder_next\n", encoding="utf-8")
    (stage / "runtime.txt").write_text("candidate-runtime\n", encoding="utf-8")
    old_config = live / "etc/recorder-next/recorder-next.toml"
    old_config.write_text("[server]\nport = 8643\n", encoding="utf-8")
    os.chmod(old_config, 0o640)
    targets = [
        {
            "target": "etc/recorder-next/recorder-next.toml",
            "source": "config/recorder-next.toml",
            "preimage": {"exists": True, "mode": "0640", "sha256": digest(old_config)},
            "postimage": {"mode": "0444", "sha256": digest(stage / "config/recorder-next.toml")},
        },
        {
            "target": "etc/systemd/system/recorder-next.service",
            "source": "unit/recorder-next.service",
            "preimage": {"exists": False, "mode": None, "sha256": None},
            "postimage": {"mode": "0444", "sha256": digest(stage / "unit/recorder-next.service")},
        },
        {
            "target": "opt/recorder-next/runtime.txt",
            "source": "runtime.txt",
            "preimage": {"exists": False, "mode": None, "sha256": None},
            "postimage": {"mode": "0444", "sha256": digest(stage / "runtime.txt")},
        },
    ]
    manifest = {
        "schema": "recorder-next-transaction/v1",
        "generation": "fixture-rev14",
        "candidate": {
            "id": "recorder-next-fixture-rev14-0123456789abcdef",
            "sha256": "1" * 64,
            "product_sha256": "2" * 64,
        },
        "operator_sha256": operator_sha256,
        "runtime": {
            "python": "/usr/bin/python3",
            "module": "recorder_next",
            "unit": "recorder-next.service",
            "exec_start": "/usr/bin/python3 -m recorder_next --config /etc/recorder-next/recorder-next.toml",
        },
        "roots": {
            "stage": str(stage.resolve()),
            "live": str(live.resolve()),
            "receipts": str(receipts.resolve()),
            "state": str(state.resolve()),
        },
        "receipts": {
            "apply": "apply-fixture-rev14.json",
            "rollback": "rollback-fixture-rev14.json",
            "journal": "transaction-fixture-rev14.json",
            "lock": "operator.lock",
        },
        "targets": targets,
    }
    manifest_path = root / "transaction-manifest.json"
    write_json(manifest_path, manifest)
    write_json(root / "stage/candidate-manifest.json", {})
    return manifest_path, manifest


def exact_common(root: Path, manifest_path: Path) -> tuple[str, ...]:
    return (
        "--manifest", str(manifest_path.resolve()),
        "--manifest-sha256", digest(manifest_path),
        "--operator-sha256", digest(OPERATOR),
        "--stage-root", str((root / "stage").resolve()),
        "--live-root", str((root / "live").resolve()),
        "--receipt-root", str((root / "receipts").resolve()),
        "--state-root", str((root / "state").resolve()),
        "--candidate-manifest", str((root / "stage/candidate-manifest.json").resolve()),
    )


class TransactionalOperatorTests(unittest.TestCase):
    def test_apply_rollback_reentry_and_readback_are_receipt_authoritative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path, manifest = make_manifest(root, digest(OPERATOR))
            common = exact_common(root, manifest_path)

            applied = run_operator("apply", *common)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            apply_result = json.loads(applied.stdout)
            self.assertEqual(apply_result["status"], "APPLIED")
            apply_receipt = root / "receipts" / manifest["receipts"]["apply"]
            journal = root / "state" / manifest["receipts"]["journal"]
            self.assertTrue(apply_receipt.is_file())
            self.assertEqual(json.loads(journal.read_text(encoding="utf-8"))["phase"], "APPLY_COMMITTED")

            replay = run_operator("apply", *common)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertEqual(json.loads(replay.stdout)["status"], "APPLY_REPLAY")

            authorization = run_operator(
                "authorize-rollback",
                *common,
                "--apply-receipt",
                manifest["receipts"]["apply"],
                "--rollback-receipt",
                manifest["receipts"]["rollback"],
                "--read-only",
            )
            self.assertEqual(authorization.returncode, 0, authorization.stderr)

            before_verify = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
            verified = run_operator(
                "verify-apply",
                *common,
                "--read-only",
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(json.loads(verified.stdout)["status"], "PASS")
            after_verify = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
            self.assertEqual(before_verify, after_verify)

            rollback = run_operator(
                "rollback",
                *common,
                "--apply-receipt",
                manifest["receipts"]["apply"],
            )
            self.assertEqual(rollback.returncode, 0, rollback.stderr)
            self.assertEqual(json.loads(rollback.stdout)["status"], "ROLLED_BACK")
            old_config = root / "live/etc/recorder-next/recorder-next.toml"
            self.assertEqual(old_config.read_text(encoding="utf-8"), "[server]\nport = 8643\n")
            self.assertFalse((root / "live/etc/systemd/system/recorder-next.service").exists())
            self.assertFalse((root / "live/opt/recorder-next/runtime.txt").exists())

            rollback_replay = run_operator(
                "rollback",
                *common,
                "--apply-receipt",
                manifest["receipts"]["apply"],
            )
            self.assertEqual(rollback_replay.returncode, 0, rollback_replay.stderr)
            self.assertEqual(json.loads(rollback_replay.stdout)["status"], "ROLLBACK_REPLAY")

            restore_replay = run_operator(
                "restore-legacy",
                *common,
                "--apply-receipt",
                manifest["receipts"]["apply"],
                "--rollback-receipt",
                manifest["receipts"]["rollback"],
                "--restore-manifest",
                str(manifest_path),
                "--restore-only-bound-preimages",
            )
            self.assertEqual(restore_replay.returncode, 0, restore_replay.stderr)
            self.assertEqual(json.loads(restore_replay.stdout)["status"], "ROLLBACK_REPLAY")

            readback = run_operator(
                "readback",
                *common,
                "--receipt",
                manifest["receipts"]["rollback"],
                "--action",
                "rollback",
                "--read-only",
            )
            self.assertEqual(readback.returncode, 0, readback.stderr)
            self.assertEqual(json.loads(readback.stdout)["status"], "PASS")

            rollback_readback = run_operator(
                "readback-rollback",
                *common,
                "--rollback-receipt",
                manifest["receipts"]["rollback"],
                "--protected-ports",
                "127.0.0.1:8642,127.0.0.1:8653",
                "--read-only",
            )
            self.assertEqual(rollback_readback.returncode, 0, rollback_readback.stderr)

    def test_missing_or_substituted_stage_referent_fails_before_first_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path, manifest = make_manifest(root, digest(OPERATOR))
            common = exact_common(root, manifest_path)
            (root / "stage/config/recorder-next.toml").unlink()
            failed = run_operator("apply", *common)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("source", failed.stderr)
            self.assertEqual((root / "live/etc/recorder-next/recorder-next.toml").read_text(encoding="utf-8"), "[server]\nport = 8643\n")
            self.assertFalse((root / "receipts" / manifest["receipts"]["apply"]).exists())
            self.assertFalse((root / "state" / manifest["receipts"]["journal"]).exists())

            manifest_path, manifest = make_manifest(root / "substituted", digest(OPERATOR))
            common = exact_common(root / "substituted", manifest_path)
            (root / "substituted/stage/config/recorder-next.toml").write_text("substituted\n", encoding="utf-8")
            substituted = run_operator("apply", *common)
            self.assertNotEqual(substituted.returncode, 0)
            self.assertIn("postimage", substituted.stderr)
            self.assertEqual(
                (root / "substituted/live/etc/recorder-next/recorder-next.toml").read_text(encoding="utf-8"),
                "[server]\nport = 8643\n",
            )

    def test_foreign_same_byte_receipt_and_missing_lock_are_holds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path, manifest = make_manifest(root, digest(OPERATOR))
            common = exact_common(root, manifest_path)
            (root / "receipts/operator.lock").unlink()
            missing_lock = run_operator("apply", *common)
            self.assertNotEqual(missing_lock.returncode, 0)
            self.assertIn("lock", missing_lock.stderr)
            self.assertEqual((root / "live/etc/recorder-next/recorder-next.toml").read_text(encoding="utf-8"), "[server]\nport = 8643\n")

            manifest_path, manifest = make_manifest(root / "foreign", digest(OPERATOR))
            common = exact_common(root / "foreign", manifest_path)
            applied = run_operator("apply", *common)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            receipt = root / "foreign/receipts" / manifest["receipts"]["apply"]
            replacement = receipt.with_name("replacement.json")
            replacement.write_bytes(receipt.read_bytes())
            os.replace(replacement, receipt)
            foreign = run_operator("apply", *common)
            self.assertNotEqual(foreign.returncode, 0)
            self.assertIn("same-byte/different-inode", foreign.stderr)

    def test_rollback_fault_leaves_a_reenterable_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path, manifest = make_manifest(root, digest(OPERATOR))
            common = exact_common(root, manifest_path)
            applied = run_operator("apply", *common)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            fault = run_operator(
                "rollback",
                *common,
                "--apply-receipt",
                manifest["receipts"]["apply"],
                env={"RECORDER_OP_FAULT": "rollback_after_replace:1"},
            )
            self.assertNotEqual(fault.returncode, 0)
            journal = json.loads((root / "state" / manifest["receipts"]["journal"]).read_text(encoding="utf-8"))
            self.assertEqual(journal["phase"], "ROLLBACKING")
            retry = run_operator(
                "rollback",
                *common,
                "--apply-receipt",
                manifest["receipts"]["apply"],
            )
            self.assertEqual(retry.returncode, 0, retry.stderr)
            self.assertEqual(json.loads(retry.stdout)["status"], "ROLLED_BACK")

    def test_fault_after_replace_is_compensated_and_receipt_publication_gap_holds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path, manifest = make_manifest(root, digest(OPERATOR))
            common = exact_common(root, manifest_path)
            failed = run_operator("apply", *common, env={"RECORDER_OP_FAULT": "after_replace:1"})
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual((root / "live/etc/recorder-next/recorder-next.toml").read_text(encoding="utf-8"), "[server]\nport = 8643\n")
            self.assertFalse((root / "receipts" / manifest["receipts"]["apply"]).exists())

            gap = run_operator("apply", *common, env={"RECORDER_OP_FAULT": "after_receipt:1"})
            self.assertNotEqual(gap.returncode, 0)
            receipt = root / "receipts" / manifest["receipts"]["apply"]
            self.assertTrue(receipt.is_file())
            retry = run_operator("apply", *common)
            self.assertNotEqual(retry.returncode, 0)
            self.assertIn("HOLD", retry.stderr)
            self.assertEqual(
                (root / "live/etc/recorder-next/recorder-next.toml").read_text(encoding="utf-8"),
                "[server]\nport = 8653\n",
            )
            self.assertTrue((root / "state" / manifest["receipts"]["journal"]).is_file())

    def test_sigkill_reentry_holds_unbound_postimage_without_recovery_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path, manifest = make_manifest(root, digest(OPERATOR))
            common = exact_common(root, manifest_path)
            killed = run_operator("apply", *common, env={"RECORDER_OP_FAULT": "kill_after_replace:1"})
            self.assertEqual(killed.returncode, -9)
            target = root / "live/etc/recorder-next/recorder-next.toml"
            self.assertEqual(target.read_text(encoding="utf-8"), "[server]\nport = 8653\n")
            journal = root / "state" / manifest["receipts"]["journal"]
            self.assertTrue(journal.is_file())
            before = target.stat()
            reentry = run_operator("apply", *common)
            self.assertNotEqual(reentry.returncode, 0)
            self.assertIn("HOLD", reentry.stderr)
            after = target.stat()
            self.assertEqual((before.st_dev, before.st_ino, before.st_size), (after.st_dev, after.st_ino, after.st_size))
            self.assertFalse((root / "receipts" / manifest["receipts"]["apply"]).exists())

    def test_sigint_and_sigterm_reentry_holds_unbound_postimage(self):
        for signal_name, signal_number in (("sigint", signal.SIGINT), ("sigterm", signal.SIGTERM)):
            with self.subTest(signal=signal_name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                manifest_path, _ = make_manifest(root, digest(OPERATOR))
                common = exact_common(root, manifest_path)
                env = os.environ.copy()
                env["RECORDER_OP_FAULT"] = f"{signal_name}_after_replace:1"
                process = subprocess.Popen(
                    [sys.executable, "-B", str(OPERATOR), "apply", *common],
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                stdout, stderr = process.communicate()
                self.assertEqual(process.returncode, -signal_number, (stdout, stderr))
                verify = run_operator("verify-apply", *common, "--read-only")
                self.assertNotEqual(verify.returncode, 0, verify.stdout)
                self.assertIn("HOLD", verify.stderr)

    def test_foreign_same_byte_journal_is_a_hold_for_every_authority_entrypoint(self):
        commands: tuple[tuple[str, ...], ...] = (
            ("apply",),
            (
                "authorize-rollback",
                "--apply-receipt",
                "apply-fixture-rev14.json",
                "--rollback-receipt",
                "rollback-fixture-rev14.json",
                "--read-only",
            ),
            ("rollback", "--apply-receipt", "apply-fixture-rev14.json"),
            ("restore-legacy", "--apply-receipt", "apply-fixture-rev14.json", "--rollback-receipt", "rollback-fixture-rev14.json", "--restore-only-bound-preimages"),
            ("verify-apply", "--read-only"),
            ("readback", "--receipt", "apply-fixture-rev14.json", "--action", "apply", "--read-only"),
        )
        for command in commands:
            with self.subTest(command=command[0]), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                manifest_path, manifest = make_manifest(root, digest(OPERATOR))
                common = exact_common(root, manifest_path)
                applied = run_operator("apply", *common)
                self.assertEqual(applied.returncode, 0, applied.stderr)
                journal = root / "state" / manifest["receipts"]["journal"]
                replacement = journal.with_name("foreign-journal.json")
                replacement.write_bytes(journal.read_bytes())
                os.replace(replacement, journal)
                if command[0] == "restore-legacy":
                    command_args = [command[0], *common, *command[1:5], "--restore-manifest", str(manifest_path), *command[5:]]
                else:
                    command_args = [command[0], *common, *command[1:]]
                result = run_operator(*command_args)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("HOLD", result.stderr)

    def test_deployment_config_is_path_only_and_manifestable(self):
        self.assertTrue(CONFIG.is_file())
        text = CONFIG.read_text(encoding="utf-8")
        self.assertIn("hermes_api_key_file = \"$CREDENTIALS_DIRECTORY/recorder_api_key\"", text)
        self.assertNotIn("API_SERVER_KEY=", text)
        self.assertNotIn("Bearer ", text)


if __name__ == "__main__":
    unittest.main()
