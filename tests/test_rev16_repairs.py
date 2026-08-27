from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
BUILDER = ROOT / "release" / "build_candidate.py"
OPERATOR = ROOT / "release" / "release_op.py"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_generation(root: Path) -> Path:
    output = root / "generation"
    result = subprocess.run(
        [sys.executable, "-B", str(BUILDER), "--repo-root", str(ROOT), "--output", str(output)],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return output


def load_activation_helpers():
    path = ROOT / "tests" / "test_activation_controls.py"
    spec = importlib.util.spec_from_file_location("activation_controls_fixture", path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load activation fixture helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Rev16RepairRedTests(unittest.TestCase):
    def test_source_archive_identity_is_explicitly_bound_to_every_sealed_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            generation = build_generation(Path(tmp))
            manifest = json.loads((generation / "candidate-manifest.json").read_text(encoding="utf-8"))
            producer = json.loads((generation / "producer-report.json").read_text(encoding="utf-8"))
            self.assertIn("source_archive", manifest)
            source_archive = manifest["source_archive"]
            archive = manifest["candidate_archive"]
            self.assertEqual(source_archive, archive)
            self.assertEqual(source_archive, producer["source_archive"])
            self.assertEqual(
                manifest["predecessor"]["archive_sha256"],
                manifest["predecessor"]["declared_source_bundle_sha256"],
            )
            self.assertNotEqual(manifest["predecessor"]["archive_sha256"], source_archive["sha256"])
            archive_path = Path(source_archive["path"])
            self.assertEqual(source_archive["sha256"], digest(archive_path))
            self.assertEqual(source_archive["size"], archive_path.stat().st_size)

    def test_frozen_generation_root_is_non_writable(self):
        with tempfile.TemporaryDirectory() as tmp:
            generation = build_generation(Path(tmp))
            mode = stat.S_IMODE(generation.stat().st_mode)
            self.assertEqual(mode, 0o555)

    def test_direct_operator_rejects_noncanonical_stage_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            generation = build_generation(Path(tmp))
            packet = json.loads((generation / "control/activation-packet.json").read_text(encoding="utf-8"))
            canonical = list(packet["commands"]["operator_stage_verifier"]["argv"])
            baseline = subprocess.run(canonical, cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(baseline.returncode, 0, baseline.stderr)

            variants: dict[str, list[str]] = {}
            variants["duplicate_read_only"] = [*canonical, "--read-only"]

            reordered = list(canonical)
            live_index = reordered.index("--live-root")
            state_index = reordered.index("--state-root")
            reordered[live_index : live_index + 2], reordered[state_index : state_index + 2] = (
                reordered[state_index : state_index + 2],
                reordered[live_index : live_index + 2],
            )
            variants["reordered_pairs"] = reordered

            aliased = list(canonical)
            stage_index = aliased.index("--stage-root")
            stage_path = aliased[stage_index + 1]
            del aliased[stage_index : stage_index + 2]
            aliased.insert(stage_index, f"--stage-root={stage_path}")
            variants["equals_alias"] = aliased

            path_form = list(canonical)
            stage_index = path_form.index("--stage-root") + 1
            path_form[stage_index] = f"{path_form[stage_index]}/."
            variants["normalized_path"] = path_form

            for label, argv in variants.items():
                with self.subTest(label=label):
                    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("argv", result.stderr.lower())

    def test_apply_can_deliberately_reenter_after_completed_rollback(self):
        helpers = load_activation_helpers()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path, manifest = helpers.make_manifest(root, helpers.digest(OPERATOR))
            candidate_manifest = root / "stage" / "candidate-manifest.json"
            candidate_manifest.write_text("{}\n", encoding="utf-8")
            common = (
                "--manifest",
                str(manifest_path),
                "--manifest-sha256",
                digest(manifest_path),
                "--operator-sha256",
                digest(OPERATOR),
                "--stage-root",
                str((root / "stage").resolve()),
                "--live-root",
                str((root / "live").resolve()),
                "--receipt-root",
                str((root / "receipts").resolve()),
                "--state-root",
                str((root / "state").resolve()),
                "--candidate-manifest",
                str(candidate_manifest.resolve()),
            )

            applied = helpers.run_operator("apply", *common)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            rollback = helpers.run_operator(
                "rollback",
                *common,
                "--apply-receipt",
                manifest["receipts"]["apply"],
            )
            self.assertEqual(rollback.returncode, 0, rollback.stderr)
            reapply = helpers.run_operator("apply", *common)
            self.assertEqual(reapply.returncode, 0, reapply.stderr)
            self.assertIn(json.loads(reapply.stdout)["status"], {"APPLIED", "APPLY_REAPPLY"})


if __name__ == "__main__":
    unittest.main()
