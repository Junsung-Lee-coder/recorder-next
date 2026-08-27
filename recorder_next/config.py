from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RecorderConfig:
    host: str = "127.0.0.1"
    port: int = 8643
    database: str = "./state/recorder-next.sqlite3"
    storage_root: str = "./state/data"
    min_free_bytes: int = 0
    max_audio_minutes: int = 120
    max_audio_bytes: int = 1024 * 1024 * 1024
    max_chunk_bytes: int = 1024 * 1024
    max_text_bytes: int = 10 * 1024 * 1024
    max_attachment_bytes: int = 250 * 1024 * 1024
    max_turn_bytes: int = 1024 * 1024 * 1024
    max_parts: int = 20
    hermes_max_attempts: int = 2
    hermes_grace_seconds: int = 30
    asr_provider_timeout_seconds: int = 10
    tts_retry_seconds: int = 10
    hermes_base_url: str | None = None
    hermes_api_key_file: str | None = None
    tts_provider: str = "fixture"

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "RecorderConfig":
        path = Path(path)
        with path.open("rb") as handle:
            data: dict[str, Any] = tomllib.load(handle)
        server = data.get("server", {})
        storage = data.get("storage", {})
        limits = data.get("limits", {})
        retries = data.get("retries", {})
        providers = data.get("providers", {})
        return cls(
            host=str(server.get("host", cls.host)),
            port=int(server.get("port", cls.port)),
            database=str(storage.get("database", cls.database)),
            storage_root=str(storage.get("root", cls.storage_root)),
            min_free_bytes=int(storage.get("min_free_bytes", cls.min_free_bytes)),
            max_audio_minutes=int(limits.get("max_audio_minutes", cls.max_audio_minutes)),
            max_audio_bytes=int(limits.get("max_audio_bytes", cls.max_audio_bytes)),
            max_chunk_bytes=int(limits.get("max_chunk_bytes", cls.max_chunk_bytes)),
            max_text_bytes=int(limits.get("max_text_bytes", cls.max_text_bytes)),
            max_attachment_bytes=int(limits.get("max_attachment_bytes", cls.max_attachment_bytes)),
            max_turn_bytes=int(limits.get("max_turn_bytes", cls.max_turn_bytes)),
            max_parts=int(limits.get("max_parts", cls.max_parts)),
            hermes_max_attempts=int(retries.get("hermes_max_attempts", cls.hermes_max_attempts)),
            hermes_grace_seconds=int(retries.get("hermes_late_result_grace_seconds", cls.hermes_grace_seconds)),
            asr_provider_timeout_seconds=int(retries.get("asr_provider_timeout_seconds", cls.asr_provider_timeout_seconds)),
            tts_retry_seconds=int(retries.get("tts_retry_seconds", cls.tts_retry_seconds)),
            hermes_base_url=providers.get("hermes_base_url"),
            hermes_api_key_file=providers.get(
                "hermes_api_key_file", os.environ.get("RECORDER_NEXT_HERMES_API_KEY_FILE")
            ),
            tts_provider=str(providers.get("tts", cls.tts_provider)),
        )

    def resolved(self, *, base_dir: str | os.PathLike[str] = ".") -> "RecorderConfig":
        base = Path(base_dir)
        db = Path(self.database)
        root = Path(self.storage_root)
        credential = self.hermes_api_key_file
        if credential is not None:
            credential_path = Path(os.path.expanduser(os.path.expandvars(str(credential))))
            credential = str(credential_path if credential_path.is_absolute() else base / credential_path)
        return RecorderConfig(
            host=self.host,
            port=self.port,
            database=str(db if db.is_absolute() else base / db),
            storage_root=str(root if root.is_absolute() else base / root),
            min_free_bytes=self.min_free_bytes,
            max_audio_minutes=self.max_audio_minutes,
            max_audio_bytes=self.max_audio_bytes,
            max_chunk_bytes=self.max_chunk_bytes,
            max_text_bytes=self.max_text_bytes,
            max_attachment_bytes=self.max_attachment_bytes,
            max_turn_bytes=self.max_turn_bytes,
            max_parts=self.max_parts,
            hermes_max_attempts=self.hermes_max_attempts,
            hermes_grace_seconds=self.hermes_grace_seconds,
            asr_provider_timeout_seconds=self.asr_provider_timeout_seconds,
            tts_retry_seconds=self.tts_retry_seconds,
            hermes_base_url=self.hermes_base_url,
            hermes_api_key_file=credential,
            tts_provider=self.tts_provider,
        )
