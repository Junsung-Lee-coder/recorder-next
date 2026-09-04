from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
BUILDER = ROOT / "release" / "build_candidate.py"
FAILED_PRODUCT_SHA = "def267f5fa28891a481da41ecf12d314ba4c09066e8fcade389b124116e99fba"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FrozenGenerationTests(unittest.TestCase):
    def _build(self, root: Path) -> Path:
        output = root / "generation"
        result = subprocess.run(
            [sys.executable, "-B", str(BUILDER), "--repo-root", str(ROOT), "--output", str(output)],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def test_successor_preserves_product_and_seals_operator_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            generation = self._build(Path(tmp))
            manifest = json.loads((generation / "candidate-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "FROZEN")
            self.assertEqual(manifest["candidate_file_count"], 50)
            self.assertRegex(manifest["product_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotEqual(manifest["product_sha256"], FAILED_PRODUCT_SHA)
            self.assertEqual(manifest["product_bytes_changed_from_failed_candidate"], True)
            self.assertEqual(
                manifest["changed_product_paths_from_failed_candidate"],
                [
                    "api/openapi.json",
                    "recorder_next/adapters.py",
                    "recorder_next/features.py",
                    "recorder_next/http.py",
                    "recorder_next/openapi.py",
                    "recorder_next/service.py",
                    "recorder_next/store.py",
                    "tests/test_extended_contract.py",
                    "tests/test_generated_multimodal.py",
                    "tests/test_r1_repairs.py",
                    "tests/test_scheduled_final.py",
                ],
            )
            self.assertEqual(manifest["approved_for_live_change"], False)
            self.assertEqual(manifest["mutation_counters"]["installation"], 0)
            self.assertEqual(manifest["mutation_counters"]["rollback"], 0)

            packet = json.loads((generation / "control/activation-packet.json").read_text(encoding="utf-8"))
            self.assertEqual(packet["status"], "CANDIDATE_ONLY")
            self.assertEqual(packet["execution_policy"], "read_only_smokes_only")
            self.assertEqual(packet["apply"]["receipt_root"], packet["rollback"]["receipt_root"])
            self.assertNotIn("/", Path(packet["apply"]["apply_receipt"]).parts)
            self.assertNotIn("/", Path(packet["rollback"]["rollback_receipt"]).parts)
            self.assertEqual(packet["apply"]["receipt_root"], manifest["transaction"]["roots"]["receipts"])

            verifier = subprocess.run(
                packet["commands"]["candidate_verifier"]["argv"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verifier.returncode, 0, verifier.stderr)
            stage = subprocess.run(
                packet["commands"]["operator_stage_verifier"]["argv"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(stage.returncode, 0, stage.stderr)
            preflight = subprocess.run(
                packet["commands"]["preflight"]["argv"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(preflight.returncode, 0, preflight.stderr)
            self.assertEqual(json.loads(preflight.stdout)["commands_executed"], 0)

            freeze = json.loads((generation / "freeze-vector.json").read_text(encoding="utf-8"))
            self.assertEqual(freeze["opening_closing_equal"], True)
            self.assertEqual(freeze["entry_count"], freeze["actual_entry_count"])
            self.assertEqual(freeze["duplicate_count"], 0)
            self.assertEqual(freeze["non_writable"], True)

    def test_packet_checker_rejects_receipt_parent_substitution(self):
        with tempfile.TemporaryDirectory() as tmp:
            generation = self._build(Path(tmp))
            packet_path = generation / "control/activation-packet.json"
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            packet["rollback"]["rollback_receipt"] = "foreign/rollback.json"
            altered_packet = Path(tmp) / "altered-packet.json"
            shutil.copyfile(packet_path, altered_packet)
            altered_packet.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            checker_argv = list(packet["commands"]["packet_checker"]["argv"])
            checker_argv[checker_argv.index(str(packet_path.absolute()))] = str(altered_packet)
            result = subprocess.run(
                checker_argv,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("receipt", result.stderr.lower())

    def test_packet_checker_rejects_mutating_argv_variants(self):
        with tempfile.TemporaryDirectory() as tmp:
            generation = self._build(Path(tmp))
            packet_path = generation / "control/activation-packet.json"
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            checker = packet["commands"]["packet_checker"]["argv"]
            original = packet_path.read_bytes()
            variants = {}

            append = json.loads(original)
            append["apply"]["argv"] = [*append["apply"]["argv"], "--unexpected"]
            variants["append"] = append

            omit = json.loads(original)
            omit_argv = omit["apply"]["argv"]
            state_index = omit_argv.index("--state-root")
            del omit_argv[state_index : state_index + 2]
            variants["omit"] = omit

            reorder = json.loads(original)
            reorder_argv = reorder["apply"]["argv"]
            live_index = reorder_argv.index("--live-root")
            receipt_index = reorder_argv.index("--receipt-root")
            reorder_argv[live_index : live_index + 2], reorder_argv[receipt_index : receipt_index + 2] = (
                reorder_argv[receipt_index : receipt_index + 2],
                reorder_argv[live_index : live_index + 2],
            )
            variants["reorder"] = reorder

            duplicate = json.loads(original)
            duplicate_argv = duplicate["apply"]["argv"]
            receipt_index = duplicate_argv.index("--receipt-root")
            duplicate_argv[receipt_index:receipt_index] = duplicate_argv[receipt_index : receipt_index + 2]
            variants["duplicate"] = duplicate

            alias = json.loads(original)
            alias["apply"]["argv"][0] = "/usr/local/bin/python3"
            variants["executable_alias"] = alias

            for label, altered in variants.items():
                with self.subTest(variant=label):
                    os.chmod(packet_path, 0o644)
                    packet_path.write_text(json.dumps(altered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    result = subprocess.run(checker, cwd=ROOT, capture_output=True, text=True, check=False)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
            packet_path.write_bytes(original)

    def test_stage_verifier_rejects_a_stale_archive_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            generation = self._build(Path(tmp))
            packet = json.loads((generation / "control/activation-packet.json").read_text(encoding="utf-8"))
            argv = list(packet["commands"]["operator_stage_verifier"]["argv"])
            archive_index = argv.index("--archive-sha256") + 1
            argv[archive_index] = "0" * 64
            result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_generation_packet_binds_closed_provenance_and_fresh_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            generation = self._build(Path(tmp))
            manifest = json.loads((generation / "candidate-manifest.json").read_text(encoding="utf-8"))
            packet = json.loads((generation / "control/activation-packet.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["candidate_file_count"], 50)
            self.assertIn("control_roles", manifest)
            self.assertIn("freeze_vector", manifest)
            self.assertIn("preflight_evidence", packet)
            evidence = generation / packet["preflight_evidence"]["path"]
            self.assertTrue(evidence.is_file())
            self.assertEqual(packet["preflight_evidence"]["sha256"], digest(evidence))

    def test_provenance_and_freeze_drift_are_rejected_by_fresh_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            generation = self._build(Path(tmp))
            manifest_path = generation / "candidate-manifest.json"
            packet_path = generation / "control/activation-packet.json"
            original_manifest = manifest_path.read_bytes()
            original_packet = packet_path.read_bytes()
            packet = json.loads(original_packet)
            guards = [
                packet["commands"]["candidate_verifier"]["argv"],
                packet["commands"]["preflight"]["argv"],
                packet["commands"]["packet_checker"]["argv"],
            ]
            mutations = {}

            unknown = json.loads(original_manifest)
            unknown["unexpected"] = True
            mutations["manifest_unknown_field"] = unknown

            candidate_id = json.loads(original_manifest)
            candidate_id["candidate_id"] = "recorder-next-bearer-r7-rev15-drifted"
            mutations["candidate_id_drift"] = candidate_id

            test_digest = json.loads(original_manifest)
            test_digest["test_matrix"]["sorted_test_id_sha256"] = "f" * 64
            mutations["test_id_sha_drift"] = test_digest

            control_extra = json.loads(original_manifest)
            control_extra["control_roles"]["unexpected"] = {"path": "control/nope", "sha256": "0" * 64, "size": 0}
            mutations["control_extra_referent"] = control_extra

            freeze_drift = json.loads(original_manifest)
            freeze_drift["freeze_vector"]["sha256"] = "0" * 64
            mutations["freeze_vector_drift"] = freeze_drift

            for label, altered in mutations.items():
                with self.subTest(variant=label):
                    os.chmod(manifest_path, 0o644)
                    manifest_path.write_text(json.dumps(altered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    for guard in guards:
                        result = subprocess.run(guard, cwd=ROOT, capture_output=True, text=True, check=False)
                        self.assertNotEqual(result.returncode, 0, f"{label}: {guard}")
            manifest_path.write_bytes(original_manifest)
            os.chmod(packet_path, 0o644)
            packet_path.write_bytes(original_packet)


if __name__ == "__main__":
    unittest.main()
