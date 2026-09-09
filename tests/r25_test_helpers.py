from __future__ import annotations

import io
import wave


def canonical_wav(frame_count: int = 160) -> bytes:
    """Return a minimal Recorder-accepted mono PCM16/16 kHz WAV."""
    if frame_count < 1:
        raise ValueError("frame_count must be positive")
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as writer:
        writer.setnchannels(1)
        writer.setsampwidth(2)
        writer.setframerate(16_000)
        writer.writeframes(b"\x00\x00" * frame_count)
    return buffer.getvalue()
