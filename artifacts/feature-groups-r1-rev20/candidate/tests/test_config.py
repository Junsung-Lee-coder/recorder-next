import unittest
from pathlib import Path

from recorder_next.config import RecorderConfig


class ConfigContractTests(unittest.TestCase):
    def test_example_config_is_machine_loaded_without_live_mutation(self):
        config = RecorderConfig.from_file(Path(__file__).parents[1] / "config.example.toml")
        self.assertEqual(config.port, 8643)
        self.assertEqual(config.max_chunk_bytes, 1048576)
        self.assertEqual(config.max_parts, 20)
        self.assertEqual(config.hermes_max_attempts, 2)


if __name__ == "__main__":
    unittest.main()
