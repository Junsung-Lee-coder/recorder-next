from __future__ import annotations

import hashlib
import os
import stat
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


class MediaValidationError(ValueError):
    """Raised when uploaded audio is not the canonical Recorder WAV profile."""


@dataclass(frozen=True, slots=True)
class ASRInput:
    data: bytes
    source_mime: str
    canonical_mime: str
    part_id: str
    sha256: str
    byte_count: int
    codec: str
    sample_rate: int
    channels: int
    sample_width: int
    frame_count: int
    duration: float

    @property
    def bytes(self) -> bytes:
        return self.data

    @property
    def mime(self) -> str:
        return self.canonical_mime

    @property
    def duration_ms(self) -> int:
        return (self.frame_count * 1000) // self.sample_rate

    @property
    def metadata(self) -> MappingProxyType:
        return MappingProxyType(
            {
                "source_mime": self.source_mime,
                "transport_mime": self.canonical_mime,
                "codec": self.codec,
                "sample_rate": self.sample_rate,
                "channels": self.channels,
                "sample_width": self.sample_width,
                "frame_count": self.frame_count,
                "duration_ms": self.duration_ms,
                "sha256": self.sha256,
                "byte_count": self.byte_count,
            }
        )


_ALLOWED_MIME = {"audio/wav", "audio/x-wav"}
_MAX_ANCILLARY_CHUNKS = 32
_MAX_ANCILLARY_BYTES = 64 * 1024
_MEDIA_SLAB = 65_536


@dataclass(frozen=True, slots=True)
class WavMetadata:
    """Hash and format metadata for an authenticated WAV file."""

    codec: str
    sample_rate: int
    channels: int
    sample_width: int
    frame_count: int
    duration_ms: int
    byte_count: int
    sha256: str


def _fail(message: str) -> None:
    raise MediaValidationError(message)


def validate_wav(
    data: bytes,
    *,
    part_id: str,
    mime: str,
    duration_ms: int | None = None,
) -> ASRInput:
    if not isinstance(data, bytes) or not data:
        _fail("audio must be non-empty bytes")
    if not isinstance(part_id, str) or not part_id:
        _fail("audio part_id is invalid")
    if not isinstance(mime, str) or mime.split(";", 1)[0].strip().lower() not in _ALLOWED_MIME:
        _fail("audio MIME must be audio/wav or audio/x-wav")
    if ";" in mime:
        _fail("audio MIME parameters are not supported")
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        _fail("audio must be a RIFF/WAVE container")
    riff_size = struct.unpack_from("<I", data, 4)[0]
    if riff_size != len(data) - 8:
        _fail("RIFF size does not match the file length")
    pos = 12
    fmt_payload: bytes | None = None
    data_payload: bytes | None = None
    ancillary_chunks = 0
    ancillary_bytes = 0
    while pos < len(data):
        if len(data) - pos < 8:
            _fail("WAV chunk header is truncated")
        chunk_id = data[pos : pos + 4]
        chunk_size = struct.unpack_from("<I", data, pos + 4)[0]
        payload_start = pos + 8
        payload_end = payload_start + chunk_size
        padded_end = payload_end + (chunk_size & 1)
        if payload_end > len(data) or padded_end > len(data):
            _fail("WAV chunk extends beyond EOF")
        payload = data[payload_start:payload_end]
        if chunk_size & 1 and data[payload_end] != 0:
            _fail("WAV odd-sized chunk has invalid padding")
        if chunk_id == b"fmt ":
            if fmt_payload is not None:
                _fail("WAV contains duplicate fmt chunks")
            fmt_payload = payload
        elif chunk_id == b"data":
            if data_payload is not None:
                _fail("WAV contains duplicate data chunks")
            if not payload:
                _fail("WAV data chunk is empty")
            data_payload = payload
        elif chunk_id in {b"LIST", b"JUNK"}:
            ancillary_chunks += 1
            ancillary_bytes += chunk_size
            if ancillary_chunks > _MAX_ANCILLARY_CHUNKS or ancillary_bytes > _MAX_ANCILLARY_BYTES:
                _fail("WAV ancillary chunks exceed the bounded limit")
        else:
            _fail("WAV contains an unsupported chunk")
        pos = padded_end
    if pos != len(data) or fmt_payload is None or data_payload is None:
        _fail("WAV requires one fmt and one non-empty data chunk")
    if len(fmt_payload) not in {16, 18}:
        _fail("PCM fmt chunk must be 16 or 18 bytes")
    audio_format, channels, rate, byte_rate, block_align, bits = struct.unpack_from("<HHIIHH", fmt_payload, 0)
    if len(fmt_payload) == 18 and struct.unpack_from("<H", fmt_payload, 16)[0] != 0:
        _fail("WAV fmt extension is not empty")
    if audio_format != 1 or channels != 1 or rate != 16000 or bits != 16 or block_align != 2 or byte_rate != 32000:
        _fail("WAV is not canonical mono 16-bit 16 kHz PCM")
    if len(data_payload) % block_align:
        _fail("WAV data is not frame aligned")
    frame_count = len(data_payload) // block_align
    if frame_count <= 0:
        _fail("WAV contains no samples")
    actual_duration_ms = (frame_count * 1000) // rate
    if duration_ms is not None:
        if not isinstance(duration_ms, int) or isinstance(duration_ms, bool) or duration_ms < 0 or abs(duration_ms - actual_duration_ms) > 1:
            _fail("declared audio duration does not match the WAV")
    raw = bytes(data)
    return ASRInput(
        data=raw,
        source_mime=mime,
        canonical_mime="audio/wav",
        part_id=part_id,
        sha256=hashlib.sha256(raw).hexdigest(),
        byte_count=len(raw),
        codec="pcm_s16le",
        sample_rate=rate,
        channels=channels,
        sample_width=bits // 8,
        frame_count=frame_count,
        duration=frame_count / rate,
    )


def inspect_wav_file(
    handle: Any,
    expected_size: int,
    *,
    part_id: str,
    mime: str,
    asserted_duration_ms: int | None = None,
) -> WavMetadata:
    """Inspect an open regular WAV FD without materialising its PCM payload."""

    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 12:
        _fail("WAV file size is invalid")
    if not isinstance(part_id, str) or not part_id:
        _fail("audio part_id is invalid")
    if not isinstance(mime, str) or ";" in mime or mime.strip().lower() not in _ALLOWED_MIME:
        _fail("audio MIME must be audio/wav or audio/x-wav")
    if asserted_duration_ms is not None and (
        not isinstance(asserted_duration_ms, int) or isinstance(asserted_duration_ms, bool) or asserted_duration_ms < 0
    ):
        _fail("declared audio duration is invalid")
    descriptor: int | None = None
    original_offset: int | None = None
    try:
        descriptor = handle if isinstance(handle, int) else handle.fileno()
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            _fail("WAV file size does not match its immutable receipt")
        identity = (before.st_dev, before.st_ino, before.st_size)
        original_offset = os.lseek(descriptor, 0, os.SEEK_CUR)
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        consumed = 0

        def take(count: int) -> bytes:
            nonlocal consumed
            if count < 0 or consumed + count > expected_size:
                _fail("WAV chunk extends beyond EOF")
            parts: list[bytes] = []
            remaining = count
            while remaining:
                chunk = os.read(descriptor, min(_MEDIA_SLAB, remaining))
                if not chunk:
                    _fail("WAV file ended before its declared length")
                consumed += len(chunk)
                digest.update(chunk)
                parts.append(chunk)
                remaining -= len(chunk)
            return b"".join(parts)

        def discard(count: int) -> None:
            nonlocal consumed
            if count < 0 or consumed + count > expected_size:
                _fail("WAV chunk extends beyond EOF")
            remaining = count
            while remaining:
                chunk = os.read(descriptor, min(_MEDIA_SLAB, remaining))
                if not chunk:
                    _fail("WAV file ended before its declared length")
                consumed += len(chunk)
                digest.update(chunk)
                remaining -= len(chunk)

        header = take(12)
        if header[:4] != b"RIFF" or header[8:12] != b"WAVE":
            _fail("audio must be a RIFF/WAVE container")
        if struct.unpack_from("<I", header, 4)[0] != expected_size - 8:
            _fail("RIFF size does not match the file length")
        fmt_payload: bytes | None = None
        data_bytes = 0
        ancillary_chunks = 0
        ancillary_bytes = 0
        while consumed < expected_size:
            chunk_header = take(8)
            chunk_id = chunk_header[:4]
            chunk_size = struct.unpack_from("<I", chunk_header, 4)[0]
            padded_size = chunk_size + (chunk_size & 1)
            if consumed + padded_size > expected_size:
                _fail("WAV chunk extends beyond EOF")
            if chunk_id == b"fmt ":
                if fmt_payload is not None:
                    _fail("WAV contains duplicate fmt chunks")
                if chunk_size not in {16, 18}:
                    _fail("PCM fmt chunk must be 16 or 18 bytes")
                fmt_payload = take(chunk_size)
            elif chunk_id == b"data":
                if data_bytes:
                    _fail("WAV contains duplicate data chunks")
                if not chunk_size:
                    _fail("WAV data chunk is empty")
                data_bytes = chunk_size
                discard(chunk_size)
            elif chunk_id in {b"LIST", b"JUNK"}:
                ancillary_chunks += 1
                ancillary_bytes += chunk_size
                if ancillary_chunks > _MAX_ANCILLARY_CHUNKS or ancillary_bytes > _MAX_ANCILLARY_BYTES:
                    _fail("WAV ancillary chunks exceed the bounded limit")
                discard(chunk_size)
            else:
                _fail("WAV contains an unsupported chunk")
            if chunk_size & 1 and take(1) != b"\x00":
                _fail("WAV odd-sized chunk has invalid padding")
        if consumed != expected_size or fmt_payload is None or not data_bytes:
            _fail("WAV requires one fmt and one non-empty data chunk")
        if len(fmt_payload) == 18 and struct.unpack_from("<H", fmt_payload, 16)[0] != 0:
            _fail("WAV fmt extension is not empty")
        audio_format, channels, rate, byte_rate, block_align, bits = struct.unpack_from("<HHIIHH", fmt_payload, 0)
        if audio_format != 1 or channels != 1 or rate != 16000 or bits != 16 or block_align != 2 or byte_rate != 32000:
            _fail("WAV is not canonical mono 16-bit 16 kHz PCM")
        if data_bytes % block_align:
            _fail("WAV data is not frame aligned")
        frame_count = data_bytes // block_align
        if frame_count <= 0:
            _fail("WAV contains no samples")
        duration_ms = (frame_count * 1000) // rate
        if asserted_duration_ms is not None and abs(asserted_duration_ms - duration_ms) > 1:
            _fail("declared audio duration does not match the WAV")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != identity:
            _fail("WAV file changed while being inspected")
        return WavMetadata(
            codec="pcm_s16le",
            sample_rate=rate,
            channels=channels,
            sample_width=bits // 8,
            frame_count=frame_count,
            duration_ms=duration_ms,
            byte_count=expected_size,
            sha256=digest.hexdigest(),
        )
    except (OSError, ValueError) as exc:
        if isinstance(exc, MediaValidationError):
            raise
        raise MediaValidationError("WAV file could not be inspected") from exc
    finally:
        try:
            if descriptor is not None and original_offset is not None:
                os.lseek(descriptor, original_offset, os.SEEK_SET)
        except OSError:
            pass


parse_wav = validate_wav

__all__ = ["ASRInput", "MediaValidationError", "WavMetadata", "inspect_wav_file", "validate_wav", "parse_wav"]
