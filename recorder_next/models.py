from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RouterDecision:
    route_decision_id: str
    project_id: str
    session_key: str
    project_record_version: int
    routed_text: str
    decision_reason_code: str


@dataclass(frozen=True)
class HermesResult:
    assistant_message_id: str
    content: str
    terminal: bool = True
    source: str = "hermes"


@dataclass(frozen=True)
class AsrResult:
    outcome: str
    transcript: str = ""
    detail: str = ""

    @classmethod
    def valid(cls, transcript: str) -> "AsrResult":
        return cls("VALID_TRANSCRIPT", transcript=transcript)

    @classmethod
    def no_speech(cls) -> "AsrResult":
        return cls("NO_SPEECH")

    @classmethod
    def error(cls, detail: str = "provider error") -> "AsrResult":
        return cls("PROVIDER_ERROR", detail=detail)


@dataclass(frozen=True)
class TTSResult:
    audio: bytes
    mode: str = "file"
    content_type: str = "audio/mpeg"
    metadata: dict[str, Any] = field(default_factory=dict)
