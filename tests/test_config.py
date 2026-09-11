import unittest
from pathlib import Path

from recorder_next.config import ProviderConfig, RecorderConfig


class ConfigContractTests(unittest.TestCase):
    def test_example_config_is_machine_loaded_without_live_mutation(self):
        config = RecorderConfig.from_file(Path(__file__).parents[1] / "config.example.toml")
        self.assertEqual(config.port, 8643)
        self.assertEqual(config.max_chunk_bytes, 1048576)
        self.assertEqual(config.max_parts, 20)
        self.assertEqual(config.hermes_max_attempts, 2)

    def test_resolved_preserves_named_provider_and_hermes_routing_fields(self):
        asr = ProviderConfig(
            name="voice-asr",
            kind="asr",
            adapter="hermes-audio",
            endpoint="http://127.0.0.1:9119",
            profile="voice",
            health_path="/api/health",
            capability_path="/api/audio/voice-config",
        )
        tts = ProviderConfig(
            name="voice-tts",
            kind="tts",
            adapter="hermes-audio",
            endpoint="http://127.0.0.1:9119",
            profile="voice",
            health_path="/api/health",
            capability_path="/api/audio/voice-config",
        )
        config = RecorderConfig(
            asr_providers=(asr,),
            tts_providers=(tts,),
            asr_chain=("voice-asr",),
            tts_chain=("voice-tts",),
            asr_overrides=(("project:alpha", ("voice-asr",)),),
            tts_overrides=(("project:alpha", ("voice-tts",)),),
            hermes_profile="voice",
            hermes_audio_base_url="http://127.0.0.1:9119",
        )

        resolved = config.resolved()

        self.assertEqual(resolved.asr_providers, config.asr_providers)
        self.assertEqual(resolved.tts_providers, config.tts_providers)
        self.assertEqual(resolved.asr_chain, config.asr_chain)
        self.assertEqual(resolved.tts_chain, config.tts_chain)
        self.assertEqual(resolved.asr_overrides, config.asr_overrides)
        self.assertEqual(resolved.tts_overrides, config.tts_overrides)
        self.assertEqual(resolved.hermes_profile, "voice")
        self.assertEqual(resolved.hermes_audio_base_url, "http://127.0.0.1:9119")


if __name__ == "__main__":
    unittest.main()
