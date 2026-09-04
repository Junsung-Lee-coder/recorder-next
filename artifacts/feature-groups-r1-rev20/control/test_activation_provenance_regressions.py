from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FrozenProvenanceProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        if not (ROOT / "candidate-manifest.json").is_file():
            self.skipTest("the provenance control module runs only inside a frozen generation")
        self.manifest = json.loads((ROOT / "candidate-manifest.json").read_text(encoding="utf-8"))
        self.packet = json.loads((ROOT / "control/activation-packet.json").read_text(encoding="utf-8"))

    def test_control_roles_are_closed_and_refer_to_existing_files(self):
        expected = {
            "operator", "candidate_verifier", "packet_checker", "preflight",
            "control_contract", "config", "operator_matrix", "provenance_tests",
            "candidate_builder", "repair_tests",
        }
        self.assertEqual(set(self.manifest["control_roles"]), expected)
        for row in self.manifest["control_roles"].values():
            self.assertTrue((ROOT / row["path"]).is_file(), row)
            self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")

    def test_packet_projects_fresh_preflight_and_freeze_authority(self):
        self.assertEqual(self.packet["freeze_vector"], self.manifest["freeze_vector"])
        evidence = self.packet["preflight_evidence"]
        self.assertEqual(evidence["path"], "evidence/preflight-final.json")
        self.assertEqual(evidence["schema"], "recorder-next-preflight/v3")
        self.assertEqual(evidence["sha256"], self.manifest["evidence"][evidence["path"]]["sha256"])
        self.assertTrue((ROOT / evidence["path"]).is_file())

    def test_every_packet_command_has_explicit_read_only_policy(self):
        expected = {
            "candidate_verifier", "operator_stage_verifier", "preflight", "packet_checker",
            "apply", "rollback", "rollback_authorization", "rollback_readback", "restore_legacy",
        }
        self.assertEqual(set(self.packet["commands"]), expected)
        for name, command in self.packet["commands"].items():
            self.assertIsInstance(command["argv"], list, name)
            self.assertEqual(command["executed"], False, name)
            self.assertEqual(command["read_only"], name not in {"apply", "rollback", "restore_legacy"}, name)


if __name__ == "__main__":
    unittest.main()
