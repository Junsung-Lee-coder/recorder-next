#!/usr/bin/env python3
"""Generate deterministic, synthetic multimodal acceptance fixtures.

The fixture set is deliberately source-controlled data, not a runtime dependency.
Voice fixtures use a local espeak-ng binary and are resampled to the Recorder
canonical 16 kHz mono PCM16 WAV form with ffmpeg.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path


KO_PROMPT = "합성 음성 입력 수용 시험입니다."
EN_PROMPT = "Synthetic English voice acceptance fixture."


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def make_png() -> bytes:
    width, height = 64, 48
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            rows.extend(((x * 4 + y * 3) % 256, (x * 2 + y * 5) % 256, (x * 7 + y) % 256, 255))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", header) + png_chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + png_chunk(b"IEND", b"")


def make_pdf() -> bytes:
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 240 120] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    stream = b"BT /F1 12 Tf 20 80 Td (Synthetic PDF acceptance fixture) Tj ET\n"
    objects.append(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"endstream")
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def run_checked(command: list[str], *, stdin: bytes | None = None) -> bytes:
    completed = subprocess.run(command, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return completed.stdout


def version_line(command: list[str], version_flag: str) -> str:
    output = run_checked(command + [version_flag]).decode("utf-8", errors="replace").splitlines()
    return output[0] if output else "unknown"


def generate_voice(espeak: str, ffmpeg: str, data_root: Path, voice: str, prompt: str, destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="recorder-next-tts-") as temp:
        source = Path(temp) / "source.wav"
        run_checked(
            [
                espeak,
                "--path=" + str(data_root),
                "-v",
                voice,
                "-s",
                "145",
                "-a",
                "100",
                "-p",
                "50",
                "-P",
                "50",
                "-D",
                "-w",
                str(source),
            ],
            stdin=prompt.encode("utf-8"),
        )
        completed = subprocess.run(
            [
                ffmpeg,
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-i",
                str(source),
                "-ar",
                "16000",
                "-ac",
                "1",
                "-sample_fmt",
                "s16",
                "-map_metadata",
                "-1",
                str(destination),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        if completed.stderr:
            raise RuntimeError(completed.stderr.decode("utf-8", errors="replace"))


def file_entry(root: Path, filename: str, *, part_id: str, kind: str, mime: str, relationship: str, caption: str | None = None) -> dict[str, object]:
    payload = (root / filename).read_bytes()
    return {
        "path": filename,
        "part_id": part_id,
        "kind": kind,
        "mime": mime,
        "relationship": relationship,
        "caption_hash": sha256_bytes(caption.encode("utf-8")) if caption is not None else None,
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def generate(output_root: Path, *, espeak: str, ffmpeg: str, espeak_data: Path) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    voice_ko = output_root / "voice_ko.wav"
    voice_en = output_root / "voice_en.wav"
    generate_voice(espeak, ffmpeg, espeak_data, "Korean", KO_PROMPT, voice_ko)
    generate_voice(espeak, ffmpeg, espeak_data, "en-us", EN_PROMPT, voice_en)

    (output_root / "image.png").write_bytes(make_png())
    (output_root / "document.pdf").write_bytes(make_pdf())
    (output_root / "text.txt").write_text("합성 텍스트 첨부입니다.\n두 번째 줄입니다.\n", encoding="utf-8", newline="")
    (output_root / "data.csv").write_text("name,value\nsynthetic,42\n", encoding="utf-8", newline="")
    (output_root / "generic.bin").write_bytes(bytes.fromhex("0001020305070b0d1113171d23293137414b535d67717b85919da7b3c1"))

    prompts = {
        "ko": KO_PROMPT,
        "en": EN_PROMPT,
    }
    entries = {
        "voice_ko": {
            **file_entry(output_root, "voice_ko.wav", part_id="voice-ko-1", kind="audio", mime="audio/wav", relationship="primary_input"),
            "prompt_sha256": sha256_bytes(KO_PROMPT.encode("utf-8")),
        },
        "voice_en": {
            **file_entry(output_root, "voice_en.wav", part_id="voice-en-1", kind="audio", mime="audio/wav", relationship="primary_input"),
            "prompt_sha256": sha256_bytes(EN_PROMPT.encode("utf-8")),
        },
        "image_png": file_entry(output_root, "image.png", part_id="image-1", kind="attachment", mime="image/png", relationship="standalone_attachment", caption="synthetic image"),
        "document_pdf": file_entry(output_root, "document.pdf", part_id="document-1", kind="attachment", mime="application/pdf", relationship="standalone_attachment", caption="synthetic document"),
        "text_utf8": file_entry(output_root, "text.txt", part_id="text-1", kind="text", mime="text/plain; charset=utf-8", relationship="standalone_text"),
        "data_csv": file_entry(output_root, "data.csv", part_id="csv-1", kind="attachment", mime="text/csv; charset=utf-8", relationship="standalone_attachment", caption="synthetic csv"),
        "generic_binary": file_entry(output_root, "generic.bin", part_id="binary-1", kind="attachment", mime="application/octet-stream", relationship="standalone_attachment", caption="synthetic binary"),
    }
    metadata = {
        "schema_version": 1,
        "fixture_id": "recorder-next-v1-generated-multimodal-r1",
        "privacy": "synthetic-only",
        "scope": "separate single-input turns; mixed turns intentionally excluded",
        "generator": {
            "name": "fixtures/generate_multimodal_fixtures.py",
            "tts_provider": "espeak-ng",
            "espeak_ng_version": version_line([espeak], "--version"),
            "ffmpeg_version": version_line([ffmpeg], "-version"),
            "espeak_voice_ko": "Korean",
            "espeak_voice_en": "en-us",
            "canonical_audio": {"sample_rate": 16000, "channels": 1, "sample_width_bytes": 2, "container": "WAV"},
            "determinism": "fixed prompts, fixed voice parameters, -D deterministic mode, metadata stripped on resample",
        },
        "prompts": {**prompts, "sha256": {key: sha256_bytes(value.encode("utf-8")) for key, value in prompts.items()}},
        "files": entries,
    }
    (output_root / "manifest.json").write_text(json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--espeak", required=True)
    parser.add_argument("--ffmpeg", required=True)
    parser.add_argument("--espeak-data", type=Path, required=True)
    args = parser.parse_args()
    generate(args.output_root, espeak=args.espeak, ffmpeg=args.ffmpeg, espeak_data=args.espeak_data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
