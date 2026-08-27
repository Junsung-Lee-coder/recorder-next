from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .canonical import canonical_json, hermes_content_hash, normalize_hermes_text, sha256_bytes, sha256_json
from .errors import (
    ChunkConflict,
    ConflictError,
    LeaseConflict,
    MissingParts,
    NotFoundError,
    NotReadyError,
    QuotaExceeded,
    TurnIdConflict,
    UnauthorizedError,
    ValidationError,
)
from .models import AsrResult, HermesResult, RouterDecision, TTSResult

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
UUIDISH = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SCHEDULE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MAX_CHUNK_BYTES = 1024 * 1024
DEFAULT_MISSING_PAGE_SIZE = 1024
MAX_MISSING_PAGE_SIZE = 1024

TERMINAL_TURN_STATES = {"DELIVERED", "FAILED_PERMANENT", "EXPIRED"}
FINAL_ERROR_MESSAGES = {
    "routing": "요청을 처리할 프로젝트를 결정하지 못했습니다.",
    "asr": "음성을 인식하지 못했습니다. 원본은 보존되어 다시 시도할 수 있습니다.",
    "hermes": "요청 처리가 지연되고 있습니다. 잠시 후 프로젝트 세션에서 다시 확인해 주세요.",
    "schedule": "예약을 저장하지 못했습니다. 성공으로 처리하지 않고 다시 시도할 수 있도록 보존했습니다.",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value: str | None, default: Any = None) -> Any:
    if value is None:
        return default
    return json.loads(value)


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


class RecorderStore:
    """The one authoritative SQLite database and its private durable spool."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        storage_root: str | os.PathLike[str],
        clock: Callable[[], str] | Any | None = None,
        max_chunk_bytes: int = MAX_CHUNK_BYTES,
        max_turn_bytes: int = 1024 * 1024 * 1024,
        max_audio_bytes: int = 1024 * 1024 * 1024,
        max_audio_minutes: int = 120,
        max_text_bytes: int = 10 * 1024 * 1024,
        max_attachment_bytes: int = 250 * 1024 * 1024,
        max_parts: int = 20,
        max_user_storage_bytes: int | None = None,
        min_free_bytes: int = 0,
    ):
        self.db_path = Path(db_path)
        self.storage_root = Path(storage_root)
        self.max_chunk_bytes = max_chunk_bytes
        self.max_turn_bytes = max_turn_bytes
        self.max_audio_bytes = max_audio_bytes
        self.max_audio_minutes = max_audio_minutes
        self.max_text_bytes = max_text_bytes
        self.max_attachment_bytes = max_attachment_bytes
        self.max_parts = max_parts
        self.max_user_storage_bytes = max_user_storage_bytes
        self.min_free_bytes = max(0, min_free_bytes)
        self._clock = clock
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_root.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _initialize(self) -> None:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        conn = self._connect()
        try:
            conn.executescript(schema)
            version_row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
            version = int(version_row["value"]) if version_row is not None else 1
            if version > 2:
                raise RuntimeError(f"unsupported Recorder schema version {version}")
            if version < 2:
                self._apply_scheduled_migration(conn)
                conn.execute("UPDATE schema_meta SET value='2' WHERE key='schema_version'")
            conn.execute("INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('schema_version', '2')")
        finally:
            conn.close()

    @staticmethod
    def _apply_scheduled_migration(conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(turns)").fetchall()}
        for name, definition in (
            ("turn_source", "TEXT NOT NULL DEFAULT 'client'"),
            ("schedule_id", "TEXT"),
            ("trigger_instance_id", "TEXT"),
            ("parent_turn_id", "TEXT"),
            ("previous_turn_id", "TEXT"),
            ("previous_turn_origin_device_id", "TEXT"),
            ("scheduled_for", "TEXT"),
            ("fired_at", "TEXT"),
            ("delivery_target_device_id", "TEXT"),
        ):
            if name not in columns:
                conn.execute(f"ALTER TABLE turns ADD COLUMN {name} {definition}")
        artifact_columns = {row["name"] for row in conn.execute("PRAGMA table_info(tts_artifacts)").fetchall()}
        if "delivery_target_device_id" not in artifact_columns:
            conn.execute("ALTER TABLE tts_artifacts ADD COLUMN delivery_target_device_id TEXT")
        conn.execute("UPDATE tts_artifacts SET delivery_target_device_id=origin_device_id WHERE delivery_target_device_id IS NULL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schedules (
                schedule_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                parent_turn_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                session_key TEXT NOT NULL,
                origin_device_id TEXT NOT NULL,
                delivery_target_device_id TEXT NOT NULL,
                fire_at_utc TEXT NOT NULL,
                timezone_offset TEXT NOT NULL,
                reminder_text TEXT NOT NULL,
                generation_instruction TEXT,
                confirmation_text TEXT NOT NULL,
                request_sha256 TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL DEFAULT 'SCHEDULED' CHECK(state IN ('SCHEDULED','CLAIMED','FIRED','FAILED','CANCELLED')),
                version INTEGER NOT NULL DEFAULT 1,
                lease_owner TEXT,
                lease_expires_at TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                trigger_instance_id TEXT NOT NULL,
                confirmation_event_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                fired_at TEXT,
                FOREIGN KEY(parent_turn_id) REFERENCES turns(turn_id) ON DELETE RESTRICT
            );
            CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules(state, fire_at_utc);
            CREATE TABLE IF NOT EXISTS schedule_occurrences (
                schedule_id TEXT NOT NULL,
                trigger_instance_id TEXT NOT NULL,
                scheduled_for TEXT NOT NULL,
                previous_turn_id TEXT,
                previous_turn_origin_device_id TEXT,
                delivery_target_device_id TEXT,
                state TEXT NOT NULL DEFAULT 'PENDING' CHECK(state IN ('PENDING','CLAIMED','FIRED','FAILED')),
                version INTEGER NOT NULL DEFAULT 1,
                lease_owner TEXT,
                lease_expires_at TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                turn_id TEXT,
                event_id TEXT,
                artifact_id TEXT,
                fired_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(schedule_id, trigger_instance_id),
                UNIQUE(turn_id),
                FOREIGN KEY(schedule_id) REFERENCES schedules(schedule_id) ON DELETE CASCADE,
                FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE RESTRICT
            );
            CREATE INDEX IF NOT EXISTS idx_schedule_occurrences_due ON schedule_occurrences(state, scheduled_for);
            """
        )

    def _now(self) -> str:
        if self._clock is None:
            return utc_now()
        value = self._clock.now() if hasattr(self._clock, "now") else self._clock()
        if not isinstance(value, str):
            raise TypeError("clock must return an RFC3339 string")
        return value

    @contextlib.contextmanager
    def _tx(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
                yield conn
                conn.execute("COMMIT")
            except Exception:
                with contextlib.suppress(Exception):
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    @contextlib.contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _turn_dir(self, user_id: str, turn_id: str) -> Path:
        return self.storage_root / "turns" / self._storage_component(user_id) / self._storage_component(turn_id)

    def _part_dir(self, user_id: str, turn_id: str, part_id: str) -> Path:
        return self._turn_dir(user_id, turn_id) / "parts" / self._storage_component(part_id)

    @staticmethod
    def _storage_component(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _safe_write(self, path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        with tmp.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _validate_turn_id(self, value: Any) -> str:
        if not isinstance(value, str) or not UUIDISH.fullmatch(value):
            raise ValidationError("turn_id must be a UUID string")
        return value

    def _manifest_fingerprint(self, manifest: Mapping[str, Any]) -> str:
        required = ("schema_version", "user_id", "turn_id", "origin_device_id", "client_created_at")
        for key in required:
            if key not in manifest:
                raise ValidationError(f"manifest missing {key}")
        self._validate_turn_id(manifest["turn_id"])
        if not isinstance(manifest["user_id"], str) or not manifest["user_id"]:
            raise ValidationError("user_id must be non-empty")
        if not isinstance(manifest["origin_device_id"], str) or not manifest["origin_device_id"]:
            raise ValidationError("origin_device_id must be non-empty")
        parts = []
        for part in manifest.get("parts", []):
            if not isinstance(part, Mapping):
                raise ValidationError("part descriptor must be an object")
            if not part.get("part_id") or not part.get("kind") or not part.get("mime"):
                raise ValidationError("part descriptor requires part_id, kind, and mime")
            if not isinstance(part["part_id"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", part["part_id"]):
                raise ValidationError("part_id contains unsupported path characters")
            parts.append(
                {
                    "part_id": part["part_id"],
                    "kind": part["kind"],
                    "mime": part["mime"],
                    "declared_bytes": part.get("declared_bytes"),
                    "declared_sha256": part.get("declared_sha256"),
                    "relationship": part.get("relationship"),
                    "caption_hash": part.get("caption_hash"),
                    "duration_ms": part.get("duration_ms"),
                    "streaming": bool(part.get("streaming", False)),
                }
            )
        envelope = {
            "schema_version": manifest["schema_version"],
            "user_id": manifest["user_id"],
            "turn_id": manifest["turn_id"],
            "origin_device_id": manifest["origin_device_id"],
            "client_created_at": manifest["client_created_at"],
            "current_project_number": manifest.get("current_project_number"),
            "prefer_current_project": bool(manifest.get("prefer_current_project", False)),
            "parts": sorted(parts, key=lambda part: part["part_id"]),
        }
        return sha256_bytes(canonical_json(envelope))

    def _turn_row(self, conn: sqlite3.Connection, turn_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM turns WHERE turn_id = ?", (turn_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"turn {turn_id} not found")
        return row

    def _turn_payload(self, conn: sqlite3.Connection, turn_id: str) -> dict[str, Any]:
        turn = _row(self._turn_row(conn, turn_id)) or {}
        parts = [
            _row(part)
            for part in conn.execute(
                "SELECT * FROM turn_parts WHERE turn_id = ? ORDER BY part_id", (turn_id,)
            ).fetchall()
        ]
        for part in parts:
            part["archived_at"] = part.get("archived_at")
        turn["manifest"] = _loads(turn.pop("manifest_json"), {})
        turn["parts"] = parts
        turn["events"] = [
            _row(event)
            for event in conn.execute(
                "SELECT event_id, event_kind, event_version, turn_event_seq, payload_sha256, required_device_id, outcome, error_kind, created_at FROM events WHERE turn_id = ? ORDER BY turn_event_seq",
                (turn_id,),
            ).fetchall()
        ]
        turn["outbox"] = [
            _row(outbox)
            for outbox in conn.execute(
                "SELECT outbox_id, event_id, event_kind, event_version, turn_event_seq, required_device_id, payload_sha256, state, created_at, acknowledged_at FROM outbox WHERE turn_id = ? ORDER BY turn_event_seq",
                (turn_id,),
            ).fetchall()
        ]
        turn["tts_artifacts"] = [
            _row(artifact)
            for artifact in conn.execute(
                "SELECT artifact_id, event_id, event_kind, artifact_version, output_kind, origin_device_id, delivery_target_device_id, payload_sha256, status, mode, delivery_seq, created_at, updated_at, played_at FROM tts_artifacts WHERE turn_id = ? ORDER BY delivery_seq",
                (turn_id,),
            ).fetchall()
        ]
        turn["asr_attempts"] = [
            _row(attempt)
            for attempt in conn.execute(
                "SELECT attempt_id, generation, stage, outcome, detail, transcript, committed_at FROM asr_attempts WHERE turn_id=? ORDER BY generation, committed_at",
                (turn_id,),
            ).fetchall()
        ]
        turn["hermes_result_refs"] = [
            _row(result)
            for result in conn.execute(
                "SELECT attempt_seq, assistant_message_id, content_hash, source, committed_at FROM hermes_results WHERE hermes_submission_id IN (SELECT hermes_submission_id FROM session_ingress WHERE turn_id=?) ORDER BY attempt_seq, committed_at",
                (turn_id,),
            ).fetchall()
        ]
        turn["final_version_refs"] = [
            _row(version)
            for version in conn.execute(
                "SELECT event_version, source, outcome, error_kind, source_ref, content_hash, combined_content_hash, committed_at FROM final_versions WHERE turn_id=? ORDER BY event_version",
                (turn_id,),
            ).fetchall()
        ]
        return turn

    def get_turn(self, turn_id: str) -> dict[str, Any]:
        with self._read() as conn:
            return self._turn_payload(conn, turn_id)

    def create_turn(self, manifest: Mapping[str, Any]) -> dict[str, Any]:
        manifest = dict(manifest)
        parts = manifest.get("parts")
        if not isinstance(parts, list):
            raise ValidationError("parts must be an array")
        if not parts:
            raise ValidationError("turn manifest must declare at least one part")
        fingerprint = self._manifest_fingerprint(manifest)
        turn_id = manifest["turn_id"]
        if len(parts) > self.max_parts:
            raise QuotaExceeded("turn exceeds configured part count")
        known_total = 0
        for part in parts:
            declared = part.get("declared_bytes")
            kind = part.get("kind")
            if declared is not None and (not isinstance(declared, int) or isinstance(declared, bool) or declared < 0):
                raise ValidationError("declared_bytes must be a non-negative integer or null")
            duration_value = part.get("duration_ms")
            if duration_value is not None and (
                not isinstance(duration_value, int) or isinstance(duration_value, bool) or duration_value < 0
            ):
                raise ValidationError("duration_ms must be a non-negative integer or null")
            if kind == "audio" and part.get("duration_ms") is not None:
                duration_ms = duration_value
                if duration_ms < 0 or duration_ms > self.max_audio_minutes * 60 * 1000:
                    raise QuotaExceeded("audio duration exceeds configured minute limit")
            if declared is None:
                continue
            known_total += declared
            per_part_limit = self.max_text_bytes if kind == "text" else self.max_audio_bytes if kind == "audio" else self.max_attachment_bytes
            if declared > per_part_limit:
                raise QuotaExceeded(f"part {part.get('part_id')} exceeds its configured size limit")
        if known_total > self.max_turn_bytes:
            raise QuotaExceeded("turn exceeds configured byte limit")
        if self.min_free_bytes and shutil.disk_usage(self.storage_root).free < self.min_free_bytes + known_total:
            raise QuotaExceeded("configured minimum free disk space is not available")
        now = utc_now()
        with self._tx() as conn:
            existing = conn.execute("SELECT * FROM turns WHERE turn_id = ?", (turn_id,)).fetchone()
            if existing is not None:
                if existing["initial_fingerprint"] != fingerprint:
                    raise TurnIdConflict(f"turn_id {turn_id} already has a different immutable envelope")
                return self._turn_payload(conn, turn_id)
            if len({part.get("part_id") for part in parts}) != len(parts):
                raise ValidationError("part_id values must be unique")
            if self.max_user_storage_bytes is not None:
                existing = conn.execute(
                    "SELECT COALESCE(SUM(COALESCE(total_bytes, declared_bytes, 0)), 0) FROM turn_parts WHERE turn_id IN (SELECT turn_id FROM turns WHERE user_id=? AND archived_at IS NULL)",
                    (manifest["user_id"],),
                ).fetchone()[0]
                if int(existing) + known_total > self.max_user_storage_bytes:
                    raise QuotaExceeded("user storage quota would be exceeded")
            conn.execute(
                "INSERT INTO turns(turn_id, user_id, origin_device_id, client_created_at, current_project_number, prefer_current_project, initial_fingerprint, manifest_json, state, turn_source, delivery_target_device_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'RECEIVING', 'client', ?, ?, ?)",
                (
                    turn_id,
                    manifest["user_id"],
                    manifest["origin_device_id"],
                    manifest["client_created_at"],
                    manifest.get("current_project_number"),
                    int(bool(manifest.get("prefer_current_project", False))),
                    fingerprint,
                    _json(manifest),
                    manifest["origin_device_id"],
                    now,
                    now,
                ),
            )
            for part in parts:
                declared_bytes = part.get("declared_bytes")
                conn.execute(
                    "INSERT INTO turn_parts(turn_id, part_id, kind, mime, declared_bytes, declared_sha256, relationship, caption_hash, streaming, source_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        turn_id,
                        part["part_id"],
                        part["kind"],
                        part["mime"],
                        declared_bytes,
                        part.get("declared_sha256"),
                        part.get("relationship"),
                        part.get("caption_hash"),
                        int(bool(part.get("streaming", False))),
                        str(self._part_dir(manifest["user_id"], turn_id, part["part_id"]) / "part.bin"),
                    ),
                )
            return self._turn_payload(conn, turn_id)

    def register_device(self, user_id: str, device_id: str, kind: str) -> dict[str, Any]:
        if not user_id or not device_id or kind not in {"phone", "watch", "other"}:
            raise ValidationError("user_id, device_id, and supported device kind are required")
        now = utc_now()
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO devices(user_id, device_id, kind, status, created_at) VALUES (?, ?, ?, 'active', ?) ON CONFLICT(user_id, device_id) DO UPDATE SET kind=excluded.kind, status='active', revoked_at=NULL",
                (user_id, device_id, kind, now),
            )
        return self.get_device(user_id, device_id)

    def get_device(self, user_id: str, device_id: str) -> dict[str, Any]:
        with self._read() as conn:
            row = conn.execute("SELECT * FROM devices WHERE user_id = ? AND device_id = ?", (user_id, device_id)).fetchone()
            if row is None:
                raise NotFoundError("device is not registered")
            return _row(row) or {}

    def revoke_device(self, user_id: str, device_id: str) -> None:
        with self._tx() as conn:
            updated = conn.execute(
                "UPDATE devices SET status='revoked', revoked_at=? WHERE user_id=? AND device_id=? AND status='active'",
                (utc_now(), user_id, device_id),
            ).rowcount
            if not updated:
                raise NotFoundError("active device not found")

    def _assert_device(self, conn: sqlite3.Connection, user_id: str, device_id: str) -> None:
        row = conn.execute(
            "SELECT status FROM devices WHERE user_id = ? AND device_id = ?", (user_id, device_id)
        ).fetchone()
        if row is None or row["status"] != "active":
            raise UnauthorizedError("device is not registered or has been revoked")

    def put_chunk(
        self,
        turn_id: str,
        part_id: str,
        sequence: int,
        payload: bytes,
        *,
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(sequence, int) or sequence < 0:
            raise ValidationError("sequence must be a non-negative integer")
        if len(payload) > self.max_chunk_bytes:
            raise ValidationError("chunk exceeds configured chunk limit")
        digest = sha256_bytes(payload)
        if expected_sha256 is not None and expected_sha256 != digest:
            raise ConflictError("chunk sha256 does not match payload")
        now = utc_now()
        path: Path | None = None
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            part = conn.execute(
                "SELECT * FROM turn_parts WHERE turn_id = ? AND part_id = ?", (turn_id, part_id)
            ).fetchone()
            if part is None:
                raise NotFoundError("part not found")
            existing = conn.execute(
                "SELECT * FROM turn_chunks WHERE turn_id=? AND part_id=? AND sequence=?",
                (turn_id, part_id, sequence),
            ).fetchone()
            if existing is not None:
                if existing["sha256"] == digest and existing["byte_length"] == len(payload):
                    return {"duplicate": True, **(_row(existing) or {})}
                raise ChunkConflict("same chunk sequence has a different hash")
            previous_bytes = conn.execute(
                "SELECT COALESCE(SUM(byte_length), 0) FROM turn_chunks WHERE turn_id=? AND part_id=?",
                (turn_id, part_id),
            ).fetchone()[0]
            kind = part["kind"]
            per_part_limit = self.max_text_bytes if kind == "text" else self.max_audio_bytes if kind == "audio" else self.max_attachment_bytes
            if int(previous_bytes) + len(payload) > per_part_limit:
                raise QuotaExceeded("part exceeds configured size limit")
            turn_bytes = conn.execute(
                "SELECT COALESCE(SUM(byte_length), 0) FROM turn_chunks WHERE turn_id=?",
                (turn_id,),
            ).fetchone()[0]
            if int(turn_bytes) + len(payload) > self.max_turn_bytes:
                raise QuotaExceeded("turn exceeds configured byte limit")
            if part["declared_bytes"] is not None and int(previous_bytes) + len(payload) > int(part["declared_bytes"]):
                raise ConflictError("chunk payload exceeds declared part size")
            if self.max_user_storage_bytes is not None:
                user_bytes = conn.execute(
                    "SELECT COALESCE(SUM(c.byte_length), 0) FROM turn_chunks c JOIN turns t ON t.turn_id=c.turn_id WHERE t.user_id=? AND t.archived_at IS NULL",
                    (turn["user_id"],),
                ).fetchone()[0]
                if int(user_bytes) + len(payload) > self.max_user_storage_bytes:
                    raise QuotaExceeded("user storage quota would be exceeded")
            path = self._part_dir(turn["user_id"], turn_id, part_id) / f"{sequence:08d}.chunk"
            self._safe_write(path, payload)
            try:
                conn.execute(
                    "INSERT INTO turn_chunks(turn_id, part_id, sequence, byte_length, sha256, storage_path, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (turn_id, part_id, sequence, len(payload), digest, str(path), now),
                )
            except Exception:
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
                raise
            return {
                "duplicate": False,
                "turn_id": turn_id,
                "part_id": part_id,
                "sequence": sequence,
                "byte_length": len(payload),
                "sha256": digest,
                "storage_path": str(path),
            }

    def _validate_total_chunks(self, value: Any, *, kind: str | None = None) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError("total_chunks must be a non-negative integer")
        if value < 0:
            raise ValidationError("total_chunks must be non-negative")
        if kind is None:
            return value
        if kind == "audio":
            # Audio is chunked at approximately one second, so the supported
            # duration—not max bytes / max chunk size—sets the count bound.
            maximum = max(0, self.max_audio_minutes * 60)
        else:
            if self.max_chunk_bytes <= 0:
                raise ValidationError("configured chunk limit is invalid")
            maximum = (self.max_turn_bytes + self.max_chunk_bytes - 1) // self.max_chunk_bytes
        if value > maximum:
            raise ValidationError(f"total_chunks exceeds configured maximum of {maximum}")
        return value

    def missing_sequences(self, turn_id: str, part_id: str, total_chunks: int | None = None) -> list[int]:
        with self._read() as conn:
            part = conn.execute(
                "SELECT total_chunks, kind FROM turn_parts WHERE turn_id=? AND part_id=?", (turn_id, part_id)
            ).fetchone()
            if part is None:
                raise NotFoundError("part not found")
            expected = total_chunks if total_chunks is not None else part["total_chunks"]
            if expected is None:
                return []
            expected = self._validate_total_chunks(expected, kind=part["kind"])
            rows = conn.execute(
                "SELECT sequence FROM turn_chunks WHERE turn_id=? AND part_id=? AND sequence < ? ORDER BY sequence",
                (turn_id, part_id, expected),
            ).fetchall()
            have = {row["sequence"] for row in rows}
            return [seq for seq in range(expected) if seq not in have]

    def missing_sequence_page(
        self,
        turn_id: str,
        part_id: str,
        total_chunks: int | None = None,
        *,
        offset: int = 0,
        limit: int = DEFAULT_MISSING_PAGE_SIZE,
        encoding: str = "list",
    ) -> dict[str, Any]:
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValidationError("missing offset must be a non-negative integer")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_MISSING_PAGE_SIZE:
            raise ValidationError(f"missing limit must be an integer from 1 to {MAX_MISSING_PAGE_SIZE}")
        if encoding not in {"list", "ranges"}:
            raise ValidationError("missing encoding must be list or ranges")
        with self._read() as conn:
            part = conn.execute(
                "SELECT total_chunks, kind FROM turn_parts WHERE turn_id=? AND part_id=?", (turn_id, part_id)
            ).fetchone()
            if part is None:
                raise NotFoundError("part not found")
            expected = total_chunks if total_chunks is not None else part["total_chunks"]
            if expected is None:
                return {
                    "encoding": encoding,
                    "offset": offset,
                    "limit": limit,
                    "missing": [] if encoding == "list" else [],
                    "missing_ranges": [] if encoding == "ranges" else None,
                    "total_missing": 0,
                    "next_offset": None,
                    "complete": True,
                }
            expected = self._validate_total_chunks(expected, kind=part["kind"])
            rows = conn.execute(
                "SELECT sequence FROM turn_chunks WHERE turn_id=? AND part_id=? AND sequence < ? ORDER BY sequence",
                (turn_id, part_id, expected),
            ).fetchall()
            have = {row["sequence"] for row in rows}
            total_missing = expected - len(have)
            if encoding == "list":
                missing: list[int] = []
                skipped = 0
                for sequence in range(expected):
                    if sequence in have:
                        continue
                    if skipped < offset:
                        skipped += 1
                        continue
                    if len(missing) >= limit:
                        break
                    missing.append(sequence)
                consumed = offset + len(missing)
                return {
                    "encoding": "list",
                    "offset": offset,
                    "limit": limit,
                    "missing": missing,
                    "total_missing": total_missing,
                    "next_offset": consumed if consumed < total_missing else None,
                    "complete": consumed >= total_missing,
                }

            ranges: list[dict[str, int]] = []
            range_offset = 0
            start: int | None = None
            for sequence in range(expected + 1):
                is_missing = sequence < expected and sequence not in have
                if is_missing:
                    if start is None:
                        start = sequence
                    continue
                if start is None:
                    continue
                end = sequence - 1
                if range_offset >= offset and len(ranges) < limit:
                    ranges.append({"start": start, "end": end})
                range_offset += 1
                start = None
            total_ranges = range_offset
            consumed = offset + len(ranges)
            return {
                "encoding": "ranges",
                "offset": offset,
                "limit": limit,
                "missing": [],
                "missing_ranges": ranges,
                "total_missing": total_missing,
                "total_ranges": total_ranges,
                "next_offset": consumed if consumed < total_ranges else None,
                "complete": consumed >= total_ranges,
            }

    def finish_part(
        self,
        turn_id: str,
        part_id: str,
        *,
        total_chunks: int,
        total_bytes: int,
        whole_stream_sha256: str,
        duration_ms: int | None = None,
    ) -> dict[str, Any]:
        total_chunks = self._validate_total_chunks(total_chunks)
        if not isinstance(total_bytes, int) or isinstance(total_bytes, bool) or total_bytes < 0:
            raise ValidationError("total_bytes must be a non-negative integer")
        if duration_ms is not None and (
            not isinstance(duration_ms, int) or isinstance(duration_ms, bool) or duration_ms < 0
        ):
            raise ValidationError("duration_ms must be a non-negative integer or null")
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            part = conn.execute(
                "SELECT * FROM turn_parts WHERE turn_id=? AND part_id=?", (turn_id, part_id)
            ).fetchone()
            if part is None:
                raise NotFoundError("part not found")
            total_chunks = self._validate_total_chunks(total_chunks, kind=part["kind"])
            if part["kind"] == "audio" and duration_ms is not None:
                if duration_ms > self.max_audio_minutes * 60 * 1000:
                    raise QuotaExceeded("audio duration exceeds configured minute limit")
            if part["status"] == "COMPLETE":
                if part["whole_stream_sha256"] == whole_stream_sha256 and part["total_chunks"] == total_chunks:
                    return _row(part) or {}
                raise ChunkConflict("completed part was finished with a different manifest")
            rows = conn.execute(
                "SELECT * FROM turn_chunks WHERE turn_id=? AND part_id=? ORDER BY sequence", (turn_id, part_id)
            ).fetchall()
            have = {row["sequence"] for row in rows}
            missing = [seq for seq in range(total_chunks) if seq not in have]
            if missing:
                raise MissingParts(f"missing chunk sequences: {missing}")
            if len(rows) != total_chunks:
                extra = sorted(have.difference(range(total_chunks)))
                raise MissingParts(f"unexpected chunk sequences: {extra}")
            if sum(row["byte_length"] for row in rows) != total_bytes:
                raise ConflictError("total_bytes does not match stored chunks")
            digest = hashlib.sha256()
            assembled = bytearray()
            for row in rows:
                content = Path(row["storage_path"]).read_bytes()
                if sha256_bytes(content) != row["sha256"]:
                    raise ConflictError("stored chunk failed its durable hash check")
                digest.update(content)
                assembled.extend(content)
            actual = digest.hexdigest()
            if actual != whole_stream_sha256:
                raise ConflictError("whole_stream_sha256 does not match stored chunks")
            if part["declared_bytes"] is not None and part["declared_bytes"] != total_bytes:
                raise ConflictError("declared_bytes does not match completed part")
            if part["declared_sha256"] is not None and part["declared_sha256"] != actual:
                raise ConflictError("declared_sha256 does not match completed part")
            assembled_path = self._part_dir(turn["user_id"], turn_id, part_id) / "part.bin"
            self._safe_write(assembled_path, bytes(assembled))
            conn.execute(
                "UPDATE turn_parts SET total_chunks=?, total_bytes=?, whole_stream_sha256=?, status='COMPLETE', source_path=? WHERE turn_id=? AND part_id=?",
                (total_chunks, total_bytes, actual, str(assembled_path), turn_id, part_id),
            )
            return _row(
                conn.execute(
                    "SELECT * FROM turn_parts WHERE turn_id=? AND part_id=?", (turn_id, part_id)
                ).fetchone()
            ) or {}

    def read_part(self, turn_id: str, part_id: str) -> bytes:
        with self._read() as conn:
            part = conn.execute(
                "SELECT source_path FROM turn_parts WHERE turn_id=? AND part_id=?", (turn_id, part_id)
            ).fetchone()
            if part is None:
                raise NotFoundError("part not found")
            if not part["source_path"] or not Path(part["source_path"]).exists():
                raise NotReadyError("part source is not assembled")
            return Path(part["source_path"]).read_bytes()

    def _all_parts_complete(self, conn: sqlite3.Connection, turn_id: str) -> bool:
        row = conn.execute(
            "SELECT COUNT(*) AS total, SUM(CASE WHEN status='COMPLETE' THEN 1 ELSE 0 END) AS complete FROM turn_parts WHERE turn_id=?",
            (turn_id,),
        ).fetchone()
        return bool(row["total"] and row["total"] == row["complete"])

    def accept_turn(self, turn_id: str) -> dict[str, Any]:
        now = utc_now()
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            if turn["state"] != "RECEIVING":
                return self._turn_payload(conn, turn_id)
            if not self._all_parts_complete(conn, turn_id):
                raise MissingParts("all declared parts must be complete before ACCEPTED")
            counter = conn.execute("SELECT accepted_seq FROM user_counters WHERE user_id=?", (turn["user_id"],)).fetchone()
            accepted_seq = (counter["accepted_seq"] if counter else 0) + 1
            conn.execute(
                "INSERT INTO user_counters(user_id, accepted_seq) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET accepted_seq=excluded.accepted_seq",
                (turn["user_id"], accepted_seq),
            )
            conn.execute(
                "UPDATE turns SET state='ACCEPTED', accepted_seq=?, updated_at=? WHERE turn_id=? AND state='RECEIVING'",
                (accepted_seq, now, turn_id),
            )
            accepted_payload = {
                "type": "ACCEPTED",
                "turn_id": turn_id,
                "accepted_seq": accepted_seq,
                "initial_fingerprint": turn["initial_fingerprint"],
            }
            self._insert_event_tx(
                conn,
                turn_id=turn_id,
                event_kind="ACCEPTED",
                event_version=1,
                required_device_id=turn["origin_device_id"],
                payload=accepted_payload,
                outcome="success",
                error_kind=None,
                create_outbox=False,
            )
            conn.execute(
                "INSERT INTO router_queue(turn_id, user_id, accepted_seq, state, updated_at) VALUES (?, ?, ?, 'QUEUED', ?)",
                (turn_id, turn["user_id"], accepted_seq, now),
            )
            return self._turn_payload(conn, turn_id)

    def _insert_event_tx(
        self,
        conn: sqlite3.Connection,
        *,
        turn_id: str,
        event_kind: str,
        event_version: int,
        required_device_id: str,
        payload: Mapping[str, Any],
        outcome: str | None,
        error_kind: str | None,
        create_outbox: bool,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        existing = conn.execute(
            "SELECT * FROM events WHERE turn_id=? AND event_kind=? AND event_version=?",
            (turn_id, event_kind, event_version),
        ).fetchone()
        if existing is not None:
            return _row(existing) or {}
        if event_kind == "ACCEPTED":
            turn_event_seq = 0
        else:
            current = conn.execute("SELECT turn_event_seq FROM turns WHERE turn_id=?", (turn_id,)).fetchone()
            turn_event_seq = int(current["turn_event_seq"]) + 1
            conn.execute("UPDATE turns SET turn_event_seq=? WHERE turn_id=?", (turn_event_seq, turn_id))
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:event:{turn_id}:{event_kind}:{event_version}"))
        payload_json = _json(dict(payload))
        payload_sha = sha256_bytes(canonical_json(dict(payload)))
        now = created_at or utc_now()
        conn.execute(
            "INSERT INTO events(event_id, turn_id, event_kind, event_version, turn_event_seq, payload_sha256, required_device_id, outcome, error_kind, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, turn_id, event_kind, event_version, turn_event_seq, payload_sha, required_device_id, outcome, error_kind, payload_json, now),
        )
        event = _row(conn.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()) or {}
        if create_outbox:
            turn = self._turn_row(conn, turn_id)
            idem = f"{turn['user_id']}:{turn_id}:delivery:{event_id}"
            outbox_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:outbox:{event_id}"))
            conn.execute(
                "INSERT INTO outbox(outbox_id, event_id, turn_id, event_kind, event_version, turn_event_seq, required_device_id, payload_sha256, payload_json, idempotency_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (outbox_id, event_id, turn_id, event_kind, event_version, turn_event_seq, required_device_id, payload_sha, payload_json, idem, now),
            )
        return event

    def _next_delivery_seq_tx(self, conn: sqlite3.Connection, device_id: str) -> int:
        row = conn.execute("SELECT delivery_seq FROM device_counters WHERE device_id=?", (device_id,)).fetchone()
        seq = (row["delivery_seq"] if row else 0) + 1
        conn.execute(
            "INSERT INTO device_counters(device_id, delivery_seq) VALUES (?, ?) ON CONFLICT(device_id) DO UPDATE SET delivery_seq=excluded.delivery_seq",
            (device_id, seq),
        )
        return seq

    def _create_tts_tx(
        self,
        conn: sqlite3.Connection,
        *,
        turn_id: str,
        event_id: str,
        event_kind: str,
        artifact_version: int,
        source_text: str,
        output_kind: str,
        delivery_target_device_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        existing = conn.execute(
            "SELECT * FROM tts_artifacts WHERE turn_id=? AND event_kind=? AND artifact_version=?",
            (turn_id, event_kind, artifact_version),
        ).fetchone()
        if existing is not None:
            return _row(existing) or {}
        turn = self._turn_row(conn, turn_id)
        artifact_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:tts:{turn_id}:{event_kind}:{artifact_version}"))
        now = created_at or utc_now()
        target = delivery_target_device_id or turn["delivery_target_device_id"] or turn["origin_device_id"]
        seq = self._next_delivery_seq_tx(conn, target)
        conn.execute(
            "INSERT INTO tts_artifacts(artifact_id, turn_id, event_id, event_kind, artifact_version, output_kind, origin_device_id, delivery_target_device_id, source_text, status, delivery_seq, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)",
            (artifact_id, turn_id, event_id, event_kind, artifact_version, output_kind, turn["origin_device_id"], target, source_text, seq, now, now),
        )
        return _row(conn.execute("SELECT * FROM tts_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()) or {}

    def _payload_for_turn_tx(self, conn: sqlite3.Connection, turn_id: str) -> dict[str, Any]:
        turn = self._turn_row(conn, turn_id)
        manifest = _loads(turn["manifest_json"], {})
        parts: list[dict[str, Any]] = []
        for part in conn.execute(
            "SELECT part_id, kind, mime, declared_bytes, total_bytes, whole_stream_sha256, status FROM turn_parts WHERE turn_id=? ORDER BY part_id",
            (turn_id,),
        ).fetchall():
            item = _row(part) or {}
            if item["kind"] == "text" and item["status"] == "COMPLETE":
                try:
                    item["text"] = self.read_part(turn_id, item["part_id"]).decode("utf-8")
                except UnicodeDecodeError:
                    item["text"] = ""
            parts.append(item)
        text_values = [item["text"] for item in parts if item.get("kind") == "text" and item.get("text") is not None]
        input_text = turn["transcript"] or "\n".join(text_values)
        return {
            "turn_id": turn_id,
            "user_id": turn["user_id"],
            "origin_device_id": turn["origin_device_id"],
            "current_project_number": turn["current_project_number"],
            "prefer_current_project": bool(turn["prefer_current_project"]),
            "transcript": turn["transcript"],
            "authoritative_asr_outcome": turn["authoritative_asr_outcome"],
            "input": input_text,
            "parts": parts,
            "manifest": manifest,
        }

    def claim_router(self, user_id: str, owner: str, *, lease_seconds: int = 30, now: str | None = None) -> dict[str, Any] | None:
        now = now or utc_now()
        expires = (dt.datetime.fromisoformat(now) + dt.timedelta(seconds=lease_seconds)).isoformat(timespec="milliseconds")
        with self._tx() as conn:
            row = conn.execute(
                "SELECT q.* FROM router_queue q WHERE q.user_id=? AND q.state IN ('QUEUED','IN_PROGRESS') AND (q.state='QUEUED' OR q.lease_expires_at <= ?) ORDER BY q.accepted_seq LIMIT 1",
                (user_id, now),
            ).fetchone()
            if row is None:
                return None
            # A lower sequence still pending blocks the candidate. DONE/FAILED rows are complete.
            earlier = conn.execute(
                "SELECT 1 FROM router_queue WHERE user_id=? AND accepted_seq < ? AND state NOT IN ('DONE','FAILED') LIMIT 1",
                (user_id, row["accepted_seq"]),
            ).fetchone()
            if earlier is not None:
                return None
            updated = conn.execute(
                "UPDATE router_queue SET state='IN_PROGRESS', lease_owner=?, lease_expires_at=?, attempt_count=attempt_count+1, updated_at=? WHERE turn_id=? AND (state='QUEUED' OR (state='IN_PROGRESS' AND lease_expires_at <= ?))",
                (owner, expires, now, row["turn_id"], now),
            ).rowcount
            if updated != 1:
                return None
            result = _row(conn.execute("SELECT * FROM router_queue WHERE turn_id=?", (row["turn_id"],)).fetchone()) or {}
            result["turn"] = self._turn_payload(conn, row["turn_id"])
            return result

    def renew_router_lease(self, turn_id: str, owner: str, *, lease_seconds: int = 30, now: str | None = None) -> bool:
        now = now or utc_now()
        expires = (dt.datetime.fromisoformat(now) + dt.timedelta(seconds=lease_seconds)).isoformat(timespec="milliseconds")
        with self._tx() as conn:
            return bool(
                conn.execute(
                    "UPDATE router_queue SET lease_expires_at=?, updated_at=? WHERE turn_id=? AND state='IN_PROGRESS' AND lease_owner=? AND lease_expires_at > ?",
                    (expires, now, turn_id, owner, now),
                ).rowcount
            )

    def _assert_router_lease_tx(self, conn: sqlite3.Connection, turn_id: str, owner: str | None, now: str) -> None:
        if owner is None:
            return
        row = conn.execute("SELECT * FROM router_queue WHERE turn_id=?", (turn_id,)).fetchone()
        if row is None or row["state"] != "IN_PROGRESS" or row["lease_owner"] != owner or row["lease_expires_at"] <= now:
            raise LeaseConflict("router lease is not owned or has expired")

    def commit_route(self, turn_id: str, decision: RouterDecision | Mapping[str, Any], *, owner: str | None = None, now: str | None = None) -> dict[str, Any]:
        if not isinstance(decision, RouterDecision):
            decision = RouterDecision(**dict(decision))
        now = now or utc_now()
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            existing = conn.execute("SELECT * FROM route_receipts WHERE turn_id=?", (turn_id,)).fetchone()
            if existing is not None:
                return self._turn_payload(conn, turn_id)
            self._assert_router_lease_tx(conn, turn_id, owner, now)
            if turn["state"] not in {"ACCEPTED", "ROUTING", "RETRY_WAIT"}:
                if turn["state"] in {"ROUTED", "HERMES_PENDING", "FINAL_READY", "DELIVERED"}:
                    return self._turn_payload(conn, turn_id)
                raise ConflictError(f"turn cannot be routed from {turn['state']}")
            project = conn.execute(
                "SELECT * FROM projects WHERE stable_project_id=? AND user_id=? AND status='active'",
                (decision.project_id, turn["user_id"]),
            ).fetchone()
            if project is None:
                raise ConflictError("router returned an unknown or inactive project")
            if int(project["record_version"]) != int(decision.project_record_version):
                raise ConflictError("router project_record_version is stale")
            if decision.session_key != project["default_session_key"]:
                raise ConflictError("router session key does not match the project registry")
            payload = self._payload_for_turn_tx(conn, turn_id)
            route_payload = {
                "type": "ROUTED",
                "turn_id": turn_id,
                "route_decision_id": decision.route_decision_id,
                "project_id": decision.project_id,
                "session_key": decision.session_key,
                "project_record_version": decision.project_record_version,
                "text": decision.routed_text,
                "decision_reason_code": decision.decision_reason_code,
            }
            event = self._insert_event_tx(
                conn,
                turn_id=turn_id,
                event_kind="ROUTED",
                event_version=1,
                required_device_id=turn["origin_device_id"],
                payload=route_payload,
                outcome="success",
                error_kind=None,
                create_outbox=True,
            )
            conn.execute(
                "INSERT INTO route_receipts(turn_id, route_decision_id, project_id, session_key, project_record_version, routed_text, decision_reason_code, committed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (turn_id, decision.route_decision_id, decision.project_id, decision.session_key, decision.project_record_version, decision.routed_text, decision.decision_reason_code, now),
            )
            submission_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:submission:{turn_id}"))
            marker = f"recorder-next:{submission_id}"
            ingress_payload = {
                "submission_id": submission_id,
                "marker": marker,
                "request": payload,
                "route": route_payload,
            }
            ingress_hash = sha256_json(ingress_payload)
            gateway_key = decision.session_key
            conn.execute(
                "INSERT INTO session_ingress(hermes_submission_id, turn_id, user_id, target_session_id, gateway_session_key, accepted_seq, payload_sha256, payload_json, marker, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (submission_id, turn_id, turn["user_id"], decision.project_id, gateway_key, turn["accepted_seq"], ingress_hash, _json(ingress_payload), marker, now, now),
            )
            self._create_tts_tx(
                conn,
                turn_id=turn_id,
                event_id=event["event_id"],
                event_kind="ROUTED",
                artifact_version=1,
                source_text=decision.routed_text,
                output_kind="ROUTED_TTS",
            )
            conn.execute(
                "UPDATE turns SET state='HERMES_PENDING', route_decision_id=?, project_id=?, session_key=?, updated_at=? WHERE turn_id=?",
                (decision.route_decision_id, decision.project_id, decision.session_key, now, turn_id),
            )
            if owner is not None:
                conn.execute(
                    "UPDATE router_queue SET state='DONE', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE turn_id=? AND state='IN_PROGRESS' AND lease_owner=?",
                    (now, turn_id, owner),
                )
            else:
                conn.execute(
                    "UPDATE router_queue SET state='DONE', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE turn_id=?",
                    (now, turn_id),
                )
            return self._turn_payload(conn, turn_id)

    def commit_routing_error(self, turn_id: str, *, owner: str | None = None, now: str | None = None) -> dict[str, Any]:
        now = now or utc_now()
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            self._assert_router_lease_tx(conn, turn_id, owner, now)
            if turn["final_event_version"]:
                return self._turn_payload(conn, turn_id)
            self._commit_protocol_final_tx(
                conn,
                turn_id=turn_id,
                error_kind="routing",
                message=FINAL_ERROR_MESSAGES["routing"],
                grace_seconds=0,
                source_ref="recorder_protocol:routing",
            )
            conn.execute(
                "UPDATE router_queue SET state='FAILED', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE turn_id=?",
                (now, turn_id),
            )
            return self._turn_payload(conn, turn_id)

    def _commit_protocol_final_tx(
        self,
        conn: sqlite3.Connection,
        *,
        turn_id: str,
        error_kind: str,
        message: str,
        grace_seconds: int,
        source_ref: str,
    ) -> dict[str, Any]:
        turn = self._turn_row(conn, turn_id)
        version = int(turn["final_event_version"]) + 1
        normalized = normalize_hermes_text(message)
        previous = turn["final_content"]
        if not previous and turn["final_outcome"] == "error" and turn["final_error_kind"] == "hermes":
            previous = FINAL_ERROR_MESSAGES["hermes"]
        combined = normalized if not previous else f"{previous}\n{normalized}"
        content_hash = hermes_content_hash(normalized)
        combined_hash = hermes_content_hash(combined)
        final_ref = source_ref
        conn.execute(
            "INSERT INTO final_versions(turn_id, event_version, source, outcome, error_kind, source_ref, content_hash, combined_content_hash, combined_content, committed_at) VALUES (?, ?, 'recorder_protocol', 'error', ?, ?, ?, ?, ?, ?)",
            (turn_id, version, error_kind, final_ref, content_hash, combined_hash, None, utc_now()),
        )
        payload = {
            "type": "FINAL",
            "turn_id": turn_id,
            "event_version": version,
            "text": combined,
            "outcome": "error",
            "error_kind": error_kind,
            "source": "recorder_protocol",
        }
        event = self._insert_event_tx(
            conn,
            turn_id=turn_id,
            event_kind="FINAL",
            event_version=version,
            required_device_id=turn["origin_device_id"],
            payload=payload,
            outcome="error",
            error_kind=error_kind,
            create_outbox=True,
        )
        self._create_tts_tx(
            conn,
            turn_id=turn_id,
            event_id=event["event_id"],
            event_kind="FINAL",
            artifact_version=version,
            source_text=combined,
            output_kind="FINAL_TTS",
        )
        grace_until = None
        state = "FINAL_READY"
        if grace_seconds:
            grace_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=grace_seconds)).isoformat(timespec="milliseconds")
            state = "LATE_RESULT_GRACE"
        conn.execute(
            "UPDATE turns SET final_event_version=?, final_combined_hash=?, final_content=?, final_outcome='error', final_error_kind=?, grace_until=?, state=?, updated_at=? WHERE turn_id=?",
            (version, combined_hash, combined, error_kind, grace_until, state, utc_now(), turn_id),
        )
        return self._turn_payload(conn, turn_id)

    def commit_protocol_error(self, turn_id: str, error_kind: str, *, grace_seconds: int = 0, message: str | None = None) -> dict[str, Any]:
        if error_kind not in FINAL_ERROR_MESSAGES:
            raise ValidationError("unsupported protocol error kind")
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            if turn["final_event_version"] and error_kind != "hermes":
                return self._turn_payload(conn, turn_id)
            return self._commit_protocol_final_tx(
                conn,
                turn_id=turn_id,
                error_kind=error_kind,
                message=message or FINAL_ERROR_MESSAGES[error_kind],
                grace_seconds=grace_seconds,
                source_ref=f"recorder_protocol:{error_kind}",
            )

    def claim_session_ingress(self, target_session_id: str, owner: str, *, lease_seconds: int = 30, now: str | None = None) -> dict[str, Any] | None:
        now = now or utc_now()
        expires = (dt.datetime.fromisoformat(now) + dt.timedelta(seconds=lease_seconds)).isoformat(timespec="milliseconds")
        with self._tx() as conn:
            row = conn.execute(
                "SELECT * FROM session_ingress WHERE target_session_id=? AND status IN ('QUEUED','IN_PROGRESS') AND (status='QUEUED' OR lease_expires_at <= ?) ORDER BY accepted_seq LIMIT 1",
                (target_session_id, now),
            ).fetchone()
            if row is None:
                return None
            earlier = conn.execute(
                "SELECT 1 FROM session_ingress WHERE target_session_id=? AND accepted_seq < ? AND status NOT IN ('SUBMITTED','FAILED') LIMIT 1",
                (target_session_id, row["accepted_seq"]),
            ).fetchone()
            if earlier is not None:
                return None
            updated = conn.execute(
                "UPDATE session_ingress SET status='IN_PROGRESS', lease_owner=?, lease_expires_at=?, attempt_count=attempt_count+1, updated_at=? WHERE hermes_submission_id=? AND (status='QUEUED' OR (status='IN_PROGRESS' AND lease_expires_at <= ?))",
                (owner, expires, now, row["hermes_submission_id"], now),
            ).rowcount
            if not updated:
                return None
            result = _row(conn.execute("SELECT * FROM session_ingress WHERE hermes_submission_id=?", (row["hermes_submission_id"],)).fetchone()) or {}
            result["payload"] = _loads(result.pop("payload_json"), {})
            return result

    def get_ingress(self, submission_id: str) -> dict[str, Any]:
        with self._read() as conn:
            row = conn.execute("SELECT * FROM session_ingress WHERE hermes_submission_id=?", (submission_id,)).fetchone()
            if row is None:
                raise NotFoundError("session ingress not found")
            result = _row(row) or {}
            result["payload"] = _loads(result.pop("payload_json"), {})
            return result

    def _get_submission_tx(self, conn: sqlite3.Connection, submission_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM session_ingress WHERE hermes_submission_id=?", (submission_id,)).fetchone()
        if row is None:
            raise NotFoundError("session ingress not found")
        return row

    def commit_hermes_result(self, submission_id: str, result: HermesResult | Mapping[str, Any], *, combined_content: str | None = None) -> dict[str, Any]:
        if not isinstance(result, HermesResult):
            result = HermesResult(**dict(result))
        if not result.terminal or not result.content:
            raise ValidationError("only non-empty terminal Hermes assistant results are accepted")
        with self._tx() as conn:
            ingress = self._get_submission_tx(conn, submission_id)
            return self._commit_hermes_result_tx(conn, ingress, result, combined_content=combined_content)

    def _commit_hermes_result_tx(self, conn: sqlite3.Connection, ingress: sqlite3.Row, result: HermesResult, *, combined_content: str | None = None) -> dict[str, Any]:
        turn = self._turn_row(conn, ingress["turn_id"])
        normalized = normalize_hermes_text(result.content)
        content_hash = hermes_content_hash(normalized)
        if turn["final_error_kind"] == "hermes" and turn["state"] in {"EXPIRED", "FAILED_PERMANENT"}:
            conn.execute(
                "INSERT INTO audit_events(audit_id, user_id, turn_id, kind, details_json, created_at) VALUES (?, ?, ?, 'late_hermes_result_ignored', ?, ?)",
                (str(uuid.uuid4()), turn["user_id"], turn["turn_id"], _json({"assistant_message_id": result.assistant_message_id, "content_hash": content_hash}), utc_now()),
            )
            return self._turn_payload(conn, turn["turn_id"])
        existing_result = conn.execute(
            "SELECT * FROM hermes_results WHERE hermes_submission_id=? AND content_hash=?",
            (ingress["hermes_submission_id"], content_hash),
        ).fetchone()
        if existing_result is not None:
            return self._turn_payload(conn, turn["turn_id"])
        attempt_seq = int(ingress["attempt_count"])
        result_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:hermes-result:{ingress['hermes_submission_id']}:{content_hash}"))
        conn.execute(
            "INSERT INTO hermes_results(result_id, hermes_submission_id, attempt_seq, assistant_message_id, content_hash, normalized_content, source, committed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (result_id, ingress["hermes_submission_id"], attempt_seq, result.assistant_message_id, content_hash, None, result.source, utc_now()),
        )
        version = int(turn["final_event_version"]) + 1
        if combined_content is not None:
            combined = normalize_hermes_text(combined_content)
            if combined != normalized and not combined.endswith("\n" + normalized):
                raise ValidationError("combined Hermes content must end with the committed result")
        else:
            previous = turn["final_content"]
            if not previous and turn["final_outcome"] == "error" and turn["final_error_kind"] == "hermes":
                previous = FINAL_ERROR_MESSAGES["hermes"]
            combined = normalized if not previous else f"{previous}\n{normalized}"
        combined_hash = hermes_content_hash(combined)
        recovered = turn["final_outcome"] == "error" and turn["final_error_kind"] == "hermes"
        conn.execute(
            "INSERT INTO final_versions(turn_id, event_version, source, outcome, error_kind, source_ref, content_hash, combined_content_hash, combined_content, committed_at) VALUES (?, ?, ?, 'success', NULL, ?, ?, ?, ?, ?)",
            (turn["turn_id"], version, result.source, result.assistant_message_id, content_hash, combined_hash, None, utc_now()),
        )
        payload = {
            "type": "FINAL",
            "turn_id": turn["turn_id"],
            "event_version": version,
            "text": combined,
            "outcome": "success",
            "error_kind": None,
            "source": result.source,
            "source_ref": result.assistant_message_id,
            "recovered_from_error": recovered,
        }
        event = self._insert_event_tx(
            conn,
            turn_id=turn["turn_id"],
            event_kind="FINAL",
            event_version=version,
            required_device_id=turn["origin_device_id"],
            payload=payload,
            outcome="success",
            error_kind=None,
            create_outbox=True,
        )
        if version == 1:
            self._create_tts_tx(
                conn,
                turn_id=turn["turn_id"],
                event_id=event["event_id"],
                event_kind="FINAL",
                artifact_version=version,
                source_text=combined,
                output_kind="FINAL_TTS",
            )
        state = turn["state"] if turn["state"] == "DELIVERED" else "FINAL_READY"
        conn.execute(
            "UPDATE turns SET final_event_version=?, final_combined_hash=?, final_content=?, final_outcome='success', final_error_kind=NULL, state=?, grace_until=NULL, updated_at=? WHERE turn_id=?",
            (version, combined_hash, combined, state, utc_now(), turn["turn_id"]),
        )
        conn.execute(
            "UPDATE session_ingress SET status='SUBMITTED', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE hermes_submission_id=?",
            (utc_now(), ingress["hermes_submission_id"]),
        )
        return self._turn_payload(conn, turn["turn_id"])

    def commit_hermes_error(self, submission_id: str, *, grace_seconds: int = 30) -> dict[str, Any]:
        with self._tx() as conn:
            ingress = self._get_submission_tx(conn, submission_id)
            turn = self._turn_row(conn, ingress["turn_id"])
            if turn["final_outcome"] == "success":
                return self._turn_payload(conn, turn["turn_id"])
            if turn["final_outcome"] == "error" and turn["final_error_kind"] == "hermes":
                return self._turn_payload(conn, turn["turn_id"])
            result = self._commit_protocol_final_tx(
                conn,
                turn_id=turn["turn_id"],
                error_kind="hermes",
                message=FINAL_ERROR_MESSAGES["hermes"],
                grace_seconds=grace_seconds,
                source_ref=f"recorder_protocol:hermes:{submission_id}",
            )
            conn.execute(
                "UPDATE session_ingress SET status='FAILED', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE hermes_submission_id=?",
                (utc_now(), submission_id),
            )
            return result

    def expire_grace(self, turn_id: str, *, now: str | None = None) -> dict[str, Any]:
        now = now or utc_now()
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            if turn["state"] != "LATE_RESULT_GRACE" or not turn["grace_until"] or turn["grace_until"] > now:
                return self._turn_payload(conn, turn_id)
            latest = conn.execute(
                "SELECT * FROM events WHERE turn_id=? AND event_kind='FINAL' ORDER BY event_version DESC LIMIT 1", (turn_id,)
            ).fetchone()
            acked = False
            if latest:
                outbox = conn.execute("SELECT state FROM outbox WHERE event_id=?", (latest["event_id"],)).fetchone()
                acked = bool(outbox and outbox["state"] == "ACKED")
            state = "FAILED_PERMANENT" if acked else "EXPIRED"
            conn.execute("UPDATE turns SET state=?, updated_at=? WHERE turn_id=?", (state, now, turn_id))
            return self._turn_payload(conn, turn_id)

    def late_result_ignored(self, submission_id: str, result: HermesResult) -> bool:
        with self._read() as conn:
            ingress = self._get_submission_tx(conn, submission_id)
            turn = self._turn_row(conn, ingress["turn_id"])
            return bool(turn["grace_until"] and turn["grace_until"] < utc_now() and turn["final_outcome"] == "error")

    def ack_event(
        self,
        turn_id: str,
        event_id: str,
        *,
        device_id: str,
        event_version: int,
        payload_sha256: str,
        now: str | None = None,
    ) -> dict[str, Any]:
        now = now or utc_now()
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            self._assert_device(conn, turn["user_id"], device_id)
            event = conn.execute("SELECT * FROM events WHERE event_id=? AND turn_id=?", (event_id, turn_id)).fetchone()
            if event is None:
                raise NotFoundError("event not found")
            if event["required_device_id"] != device_id or event["event_version"] != event_version:
                raise UnauthorizedError("event ACK is not bound to the origin device and exact version")
            if event["payload_sha256"] != payload_sha256:
                raise ConflictError("event ACK payload hash does not match")
            outbox = conn.execute("SELECT * FROM outbox WHERE event_id=?", (event_id,)).fetchone()
            if outbox is None:
                raise ConflictError("event is not a deliverable text outbox row")
            if outbox["state"] != "ACKED":
                conn.execute("UPDATE outbox SET state='ACKED', acknowledged_at=? WHERE event_id=?", (now, event_id))
            if event["event_kind"] == "FINAL":
                if event["outcome"] == "success":
                    if turn["state"] != "DELIVERED":
                        conn.execute("UPDATE turns SET state='DELIVERED', updated_at=? WHERE turn_id=?", (now, turn_id))
                elif event["error_kind"] in {"routing", "asr"}:
                    conn.execute("UPDATE turns SET state='FAILED_PERMANENT', updated_at=? WHERE turn_id=?", (now, turn_id))
                elif event["error_kind"] == "hermes" and turn["final_outcome"] == "error" and turn["state"] not in TERMINAL_TURN_STATES:
                    conn.execute("UPDATE turns SET state='LATE_RESULT_GRACE', updated_at=? WHERE turn_id=?", (now, turn_id))
                newer_pending = conn.execute(
                    "SELECT 1 FROM outbox WHERE turn_id=? AND event_kind='FINAL' AND event_version>? AND state='PENDING' LIMIT 1",
                    (turn_id, event["event_version"]),
                ).fetchone()
                if newer_pending is None:
                    conn.execute("UPDATE turns SET final_content=NULL WHERE turn_id=?", (turn_id,))
                    conn.execute(
                        "UPDATE hermes_results SET normalized_content=NULL WHERE hermes_submission_id IN (SELECT hermes_submission_id FROM session_ingress WHERE turn_id=?)",
                        (turn_id,),
                    )
                    conn.execute("UPDATE final_versions SET combined_content=NULL WHERE turn_id=?", (turn_id,))
                    conn.execute("UPDATE events SET payload_json='{}' WHERE event_id=?", (event_id,))
                    conn.execute("UPDATE outbox SET payload_json='{}' WHERE event_id=?", (event_id,))
            return self._turn_payload(conn, turn_id)

    def pending_outbox(self, device_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._read() as conn:
            rows = conn.execute(
                "SELECT * FROM outbox WHERE required_device_id=? AND state='PENDING' ORDER BY turn_event_seq, created_at LIMIT ?",
                (device_id, limit * 4),
            ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                blocked = conn.execute(
                    "SELECT 1 FROM outbox WHERE required_device_id=? AND turn_id=? AND turn_event_seq < ? AND state='PENDING' LIMIT 1",
                    (device_id, row["turn_id"], row["turn_event_seq"]),
                ).fetchone()
                if blocked:
                    continue
                item = _row(row) or {}
                item["payload"] = _loads(item.pop("payload_json"), {})
                result.append(item)
                if len(result) >= limit:
                    break
            return result

    def get_event(self, event_id: str) -> dict[str, Any]:
        with self._read() as conn:
            row = conn.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
            if row is None:
                raise NotFoundError("event not found")
            result = _row(row) or {}
            result["payload"] = _loads(result.pop("payload_json"), {})
            return result

    def get_artifact(self, artifact_id: str) -> dict[str, Any]:
        with self._read() as conn:
            row = conn.execute("SELECT * FROM tts_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
            if row is None:
                raise NotFoundError("TTS artifact not found")
            return _row(row) or {}

    def _read_tts(
        self,
        artifact_id: str,
        *,
        device_id: str,
        allow_phone_bridge: bool,
        require_phone_bridge: bool = False,
    ) -> tuple[dict[str, Any], bytes]:
        with self._read() as conn:
            row = conn.execute(
                "SELECT a.*, t.user_id FROM tts_artifacts a JOIN turns t ON t.turn_id=a.turn_id WHERE a.artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("TTS artifact not found")
            self._assert_device(conn, row["user_id"], device_id)
            bridge = None
            if allow_phone_bridge:
                bridge = conn.execute(
                    "SELECT kind FROM devices WHERE user_id=? AND device_id=? AND status='active'",
                    (row["user_id"], device_id),
                ).fetchone()
                if require_phone_bridge and (bridge is None or bridge["kind"] != "phone"):
                    raise UnauthorizedError("an active registered Phone is required for TTS bridge reads")
            target = row["delivery_target_device_id"] or row["origin_device_id"]
            if target != device_id:
                if not allow_phone_bridge or bridge is None or bridge["kind"] != "phone":
                    raise UnauthorizedError("TTS payload is bound to its delivery target or an authenticated Phone bridge")
            if row["status"] not in {"READY", "DELIVERY_PENDING", "EXPIRED"} or not row["storage_path"]:
                raise NotReadyError("TTS artifact is not ready")
            path = Path(row["storage_path"])
            if not path.exists():
                raise NotReadyError("TTS spool is no longer available")
            metadata = _row(row) or {}
            metadata.pop("source_text", None)
            metadata.pop("user_id", None)
            return metadata, path.read_bytes()

    def read_tts(self, artifact_id: str, *, device_id: str) -> tuple[dict[str, Any], bytes]:
        """Read target audio or allow an active registered Phone to bridge it."""
        return self._read_tts(artifact_id, device_id=device_id, allow_phone_bridge=True)

    def read_tts_for_bridge(self, artifact_id: str, *, bridge_device_id: str) -> tuple[dict[str, Any], bytes]:
        """Read target audio through the authenticated registered Phone bridge."""
        return self._read_tts(artifact_id, device_id=bridge_device_id, allow_phone_bridge=True, require_phone_bridge=True)

    def set_tts_result(self, artifact_id: str, result: TTSResult | Mapping[str, Any] | None, *, error: str | None = None) -> dict[str, Any]:
        if result is not None and not isinstance(result, TTSResult):
            result = TTSResult(**dict(result))
        path: Path | None = None
        with self._tx() as conn:
            artifact = conn.execute("SELECT * FROM tts_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
            if artifact is None:
                raise NotFoundError("TTS artifact not found")
            if error is not None or result is None or not result.audio:
                conn.execute("UPDATE tts_artifacts SET status='FAILED_GENERATION', updated_at=? WHERE artifact_id=?", (utc_now(), artifact_id))
                return _row(conn.execute("SELECT * FROM tts_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()) or {}
            digest = sha256_bytes(result.audio)
            turn = self._turn_row(conn, artifact["turn_id"])
            path = self._turn_dir(turn["user_id"], turn["turn_id"]) / "tts" / f"{artifact_id}.audio"
            self._safe_write(path, result.audio)
            conn.execute(
                "UPDATE tts_artifacts SET payload_sha256=?, storage_path=?, source_text=NULL, status='READY', mode=?, updated_at=? WHERE artifact_id=?",
                (digest, str(path), result.mode, utc_now(), artifact_id),
            )
            return _row(conn.execute("SELECT * FROM tts_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()) or {}

    def mark_tts_expired(self, artifact_id: str) -> dict[str, Any]:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM tts_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
            if row is None:
                raise NotFoundError("TTS artifact not found")
            conn.execute("UPDATE tts_artifacts SET source_text=NULL, status='EXPIRED', updated_at=? WHERE artifact_id=? AND status != 'PLAYED'", (utc_now(), artifact_id))
            return _row(conn.execute("SELECT * FROM tts_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()) or {}

    def relay_tts_received(self, artifact_id: str, *, device_id: str, payload_sha256: str) -> dict[str, Any]:
        with self._tx() as conn:
            artifact = conn.execute(
                "SELECT a.*, t.user_id FROM tts_artifacts a JOIN turns t ON t.turn_id=a.turn_id WHERE a.artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if artifact is None:
                raise NotFoundError("TTS artifact not found")
            self._assert_device(conn, artifact["user_id"], device_id)
            target = artifact["delivery_target_device_id"] or artifact["origin_device_id"]
            if target == device_id:
                raise ConflictError("target playback requires playback-complete ACK, not relay receipt")
            if artifact["payload_sha256"] and artifact["payload_sha256"] != payload_sha256:
                raise ConflictError("relay payload hash does not match")
            journal = conn.execute(
                "SELECT state FROM playback_journal WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
            if artifact["status"] == "PLAYED" or (journal is not None and journal["state"] == "PLAYED"):
                return _row(artifact) or {}
            conn.execute(
                "INSERT OR REPLACE INTO playback_journal(artifact_id, device_id, payload_sha256, state, recorded_at) VALUES (?, ?, ?, 'RELAY_RECEIVED', ?)",
                (artifact_id, device_id, payload_sha256, utc_now()),
            )
            return _row(artifact) or {}

    def ack_playback(
        self,
        artifact_id: str,
        *,
        device_id: str,
        payload_sha256: str,
        turn_id: str | None = None,
        artifact_version: int | None = None,
    ) -> dict[str, Any]:
        if not isinstance(turn_id, str) or not turn_id:
            raise ValidationError("turn_id is required for playback completion")
        if not isinstance(artifact_version, int) or isinstance(artifact_version, bool) or artifact_version < 1:
            raise ValidationError("artifact_version must be a positive native JSON integer")
        if not isinstance(payload_sha256, str) or not payload_sha256:
            raise ValidationError("payload_sha256 is required for playback completion")
        path: Path | None = None
        with self._tx() as conn:
            artifact = conn.execute(
                "SELECT a.*, t.user_id FROM tts_artifacts a JOIN turns t ON t.turn_id=a.turn_id WHERE a.artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if artifact is None:
                raise NotFoundError("TTS artifact not found")
            self._assert_device(conn, artifact["user_id"], device_id)
            if artifact["turn_id"] != turn_id:
                raise UnauthorizedError("artifact does not belong to turn")
            if artifact["artifact_version"] != artifact_version:
                raise UnauthorizedError("artifact version does not match playback receipt")
            target = artifact["delivery_target_device_id"] or artifact["origin_device_id"]
            if target != device_id:
                raise UnauthorizedError("only the delivery target device may complete playback")
            if artifact["status"] == "PLAYED":
                if not artifact["payload_sha256"]:
                    raise NotReadyError("played TTS artifact has no generated payload hash")
                if artifact["payload_sha256"] != payload_sha256:
                    raise ConflictError("playback payload hash does not match")
                return _row(conn.execute("SELECT * FROM tts_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()) or {}
            if artifact["status"] not in {"READY", "DELIVERY_PENDING"}:
                raise NotReadyError("TTS artifact is not ready for playback completion")
            if not artifact["payload_sha256"]:
                raise NotReadyError("TTS artifact has no generated payload hash")
            if artifact["payload_sha256"] != payload_sha256:
                raise ConflictError("playback payload hash does not match")
            conn.execute(
                "INSERT OR REPLACE INTO playback_journal(artifact_id, device_id, payload_sha256, state, recorded_at) VALUES (?, ?, ?, 'PLAYED', ?)",
                (artifact_id, device_id, payload_sha256, utc_now()),
            )
            conn.execute("UPDATE tts_artifacts SET status='PLAYED', played_at=?, updated_at=? WHERE artifact_id=?", (utc_now(), utc_now(), artifact_id))
            path = Path(artifact["storage_path"]) if artifact["storage_path"] else None
            result = _row(conn.execute("SELECT * FROM tts_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()) or {}
        if path:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        return result

    @staticmethod
    def _schedule_identifier(value: Any, field: str) -> str:
        if not isinstance(value, str) or not SCHEDULE_ID.fullmatch(value):
            raise ValidationError(f"{field} must be a non-empty bounded identifier")
        return value

    @staticmethod
    def _schedule_timestamp(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValidationError(f"{field} must be an RFC3339 timestamp")
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} must be an RFC3339 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValidationError(f"{field} must include a timezone")
        return parsed.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds")

    def _schedule_payload(self, conn: sqlite3.Connection, schedule_id: str) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM schedules WHERE schedule_id=?", (schedule_id,)).fetchone()
        if row is None:
            raise NotFoundError("schedule not found")
        result = _row(row) or {}
        result["occurrences"] = [
            _row(item) or {}
            for item in conn.execute(
                "SELECT * FROM schedule_occurrences WHERE schedule_id=? ORDER BY scheduled_for, trigger_instance_id",
                (schedule_id,),
            ).fetchall()
        ]
        if result.get("parent_turn_id"):
            result["parent_turn"] = self._turn_payload(conn, result["parent_turn_id"])
        return result

    def get_schedule(self, schedule_id: str) -> dict[str, Any]:
        schedule_id = self._schedule_identifier(schedule_id, "schedule_id")
        with self._read() as conn:
            return self._schedule_payload(conn, schedule_id)

    def _commit_schedule_confirmation_tx(
        self,
        conn: sqlite3.Connection,
        *,
        parent: sqlite3.Row,
        schedule_id: str,
        trigger_instance_id: str,
        project_id: str,
        session_key: str,
        origin_device_id: str,
        delivery_target_device_id: str,
        confirmation_text: str,
        now: str,
    ) -> dict[str, Any]:
        normalized = normalize_hermes_text(confirmation_text)
        content_hash = hermes_content_hash(normalized)
        combined_hash = hermes_content_hash(normalized)
        conn.execute(
            "INSERT INTO final_versions(turn_id, event_version, source, outcome, error_kind, source_ref, content_hash, combined_content_hash, combined_content, committed_at) VALUES (?, 1, 'schedule_confirmation', 'success', NULL, ?, ?, ?, NULL, ?)",
            (parent["turn_id"], schedule_id, content_hash, combined_hash, now),
        )
        payload = {
            "type": "FINAL",
            "turn_id": parent["turn_id"],
            "event_version": 1,
            "text": normalized,
            "outcome": "success",
            "error_kind": None,
            "source": "schedule_confirmation",
            "schedule_id": schedule_id,
            "trigger_instance_id": trigger_instance_id,
        }
        event = self._insert_event_tx(
            conn,
            turn_id=parent["turn_id"],
            event_kind="FINAL",
            event_version=1,
            required_device_id=delivery_target_device_id,
            payload=payload,
            outcome="success",
            error_kind=None,
            create_outbox=True,
            created_at=now,
        )
        self._create_tts_tx(
            conn,
            turn_id=parent["turn_id"],
            event_id=event["event_id"],
            event_kind="FINAL",
            artifact_version=1,
            source_text=normalized,
            output_kind="FINAL_TTS",
            delivery_target_device_id=delivery_target_device_id,
            created_at=now,
        )
        conn.execute(
            "UPDATE turns SET final_event_version=1, final_combined_hash=?, final_content=?, final_outcome='success', final_error_kind=NULL, state='FINAL_READY', project_id=COALESCE(project_id, ?), session_key=COALESCE(session_key, ?), delivery_target_device_id=?, updated_at=? WHERE turn_id=? AND final_event_version=0",
            (combined_hash, normalized, project_id, session_key, delivery_target_device_id, now, parent["turn_id"]),
        )
        if conn.execute("SELECT changes()").fetchone()[0] != 1:
            raise ConflictError("parent turn already has a FINAL")
        return event

    def _record_schedule_failure(self, parent_turn_id: str) -> dict[str, Any] | None:
        try:
            with self._tx() as conn:
                turn = self._turn_row(conn, parent_turn_id)
                if turn["final_event_version"]:
                    return self._turn_payload(conn, parent_turn_id)
                return self._commit_protocol_final_tx(
                    conn,
                    turn_id=parent_turn_id,
                    error_kind="schedule",
                    message=FINAL_ERROR_MESSAGES["schedule"],
                    grace_seconds=0,
                    source_ref=f"recorder_protocol:schedule:{parent_turn_id}",
                )
        except Exception:
            return None

    def create_schedule(self, command: Mapping[str, Any]) -> dict[str, Any]:
        parent_value = command.get("parent_turn_id") if isinstance(command, Mapping) else None
        try:
            parent_turn_id = self._validate_turn_id(parent_value)
        except Exception:
            return self._create_schedule_tx(command)
        try:
            return self._create_schedule_tx(command)
        except Exception:
            self._record_schedule_failure(parent_turn_id)
            raise

    def _create_schedule_tx(self, command: Mapping[str, Any]) -> dict[str, Any]:
        command = dict(command)
        parent_turn_id = self._validate_turn_id(command.get("parent_turn_id"))
        schedule_id = self._schedule_identifier(
            command.get("schedule_id")
            or str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:schedule:{parent_turn_id}:{command.get('fire_at_utc')}:{command.get('reminder_text', command.get('text', ''))}")),
            "schedule_id",
        )
        fire_at = self._schedule_timestamp(command.get("fire_at_utc"), "fire_at_utc")
        reminder_text = command.get("reminder_text", command.get("text"))
        confirmation_text = command.get("confirmation_text", "타이머를 설정했습니다.")
        if not isinstance(reminder_text, str) or not reminder_text:
            raise ValidationError("reminder_text must be a non-empty string")
        if not isinstance(confirmation_text, str) or not confirmation_text:
            raise ValidationError("confirmation_text must be a non-empty string")
        timezone_offset = command.get("timezone_offset", command.get("timezone", "UTC"))
        if not isinstance(timezone_offset, str) or not timezone_offset:
            raise ValidationError("timezone_offset must be a non-empty string")
        trigger_instance_id = self._schedule_identifier(
            command.get("trigger_instance_id")
            or str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:trigger:{schedule_id}:{fire_at}")),
            "trigger_instance_id",
        )
        now = self._now()
        request = {
            "schedule_id": schedule_id,
            "parent_turn_id": parent_turn_id,
            "project_id": command.get("project_id"),
            "session_key": command.get("session_key"),
            "origin_device_id": command.get("origin_device_id"),
            "delivery_target_device_id": command.get("delivery_target_device_id"),
            "fire_at_utc": fire_at,
            "timezone_offset": timezone_offset,
            "reminder_text": reminder_text,
            "generation_instruction": command.get("generation_instruction"),
            "confirmation_text": confirmation_text,
            "trigger_instance_id": trigger_instance_id,
        }
        request_sha = sha256_json(request)
        with self._tx() as conn:
            existing = conn.execute("SELECT request_sha256 FROM schedules WHERE schedule_id=?", (schedule_id,)).fetchone()
            if existing is not None:
                if existing["request_sha256"] != request_sha:
                    raise ConflictError("schedule_id already has a different immutable definition")
                return self._schedule_payload(conn, schedule_id)
            by_request = conn.execute("SELECT schedule_id FROM schedules WHERE request_sha256=?", (request_sha,)).fetchone()
            if by_request is not None:
                return self._schedule_payload(conn, by_request["schedule_id"])
            parent = self._turn_row(conn, parent_turn_id)
            if parent["state"] in TERMINAL_TURN_STATES or parent["final_event_version"]:
                raise ConflictError("schedule confirmation requires a parent turn without a FINAL")
            origin_device_id = command.get("origin_device_id") or parent["origin_device_id"]
            if origin_device_id != parent["origin_device_id"]:
                raise UnauthorizedError("schedule origin device must match the parent turn")
            delivery_target = command.get("delivery_target_device_id") or origin_device_id
            if not isinstance(delivery_target, str) or not delivery_target:
                raise ValidationError("delivery_target_device_id must be non-empty")
            self._assert_device(conn, parent["user_id"], origin_device_id)
            self._assert_device(conn, parent["user_id"], delivery_target)
            project_id = command.get("project_id") or parent["project_id"]
            session_key = command.get("session_key") or parent["session_key"]
            if not project_id or not session_key:
                raise ValidationError("project_id and session_key are required for a schedule")
            project = conn.execute(
                "SELECT * FROM projects WHERE stable_project_id=? AND user_id=? AND status='active'",
                (project_id, parent["user_id"]),
            ).fetchone()
            if project is None or project["default_session_key"] != session_key:
                raise ConflictError("schedule project/session reference is not active")
            conn.execute(
                "INSERT INTO schedules(schedule_id, user_id, parent_turn_id, project_id, session_key, origin_device_id, delivery_target_device_id, fire_at_utc, timezone_offset, reminder_text, generation_instruction, confirmation_text, request_sha256, trigger_instance_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    schedule_id,
                    parent["user_id"],
                    parent_turn_id,
                    project_id,
                    session_key,
                    origin_device_id,
                    delivery_target,
                    fire_at,
                    timezone_offset,
                    reminder_text,
                    command.get("generation_instruction"),
                    normalize_hermes_text(confirmation_text),
                    request_sha,
                    trigger_instance_id,
                    now,
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO schedule_occurrences(schedule_id, trigger_instance_id, scheduled_for, delivery_target_device_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (schedule_id, trigger_instance_id, fire_at, delivery_target, now, now),
            )
            confirmation = self._commit_schedule_confirmation_tx(
                conn,
                parent=parent,
                schedule_id=schedule_id,
                trigger_instance_id=trigger_instance_id,
                project_id=project_id,
                session_key=session_key,
                origin_device_id=origin_device_id,
                delivery_target_device_id=delivery_target,
                confirmation_text=confirmation_text,
                now=now,
            )
            conn.execute(
                "UPDATE schedules SET confirmation_event_id=?, updated_at=? WHERE schedule_id=?",
                (confirmation["event_id"], now, schedule_id),
            )
            return self._schedule_payload(conn, schedule_id)

    def _scheduled_delivery_payload(self, conn: sqlite3.Connection, occurrence: sqlite3.Row) -> dict[str, Any]:
        turn_id = occurrence["turn_id"]
        result = {
            "schedule_id": occurrence["schedule_id"],
            "trigger_instance_id": occurrence["trigger_instance_id"],
            "turn_id": turn_id,
            "event_id": occurrence["event_id"],
            "artifact_id": occurrence["artifact_id"],
            "turn": self._turn_payload(conn, turn_id) if turn_id else None,
        }
        return result

    def claim_due_occurrence(
        self,
        *,
        owner: str,
        lease_seconds: int = 30,
        now: str | None = None,
    ) -> dict[str, Any] | None:
        if not owner:
            raise ValidationError("scheduler owner is required")
        if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool) or lease_seconds <= 0:
            raise ValidationError("lease_seconds must be a positive integer")
        now = self._schedule_timestamp(now or self._now(), "now")
        expires = (dt.datetime.fromisoformat(now) + dt.timedelta(seconds=lease_seconds)).isoformat(timespec="milliseconds")
        with self._tx() as conn:
            row = conn.execute(
                "SELECT o.*, s.state AS schedule_state, s.version AS schedule_version FROM schedule_occurrences o JOIN schedules s ON s.schedule_id=o.schedule_id WHERE o.scheduled_for <= ? AND o.state IN ('PENDING','CLAIMED') AND (o.state='PENDING' OR o.lease_expires_at <= ?) AND s.state IN ('SCHEDULED','CLAIMED') ORDER BY o.scheduled_for, o.schedule_id, o.trigger_instance_id LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            old_version = int(row["version"])
            changed = conn.execute(
                "UPDATE schedule_occurrences SET state='CLAIMED', version=?, lease_owner=?, lease_expires_at=?, attempt_count=attempt_count+1, updated_at=? WHERE schedule_id=? AND trigger_instance_id=? AND version=? AND (state='PENDING' OR (state='CLAIMED' AND lease_expires_at <= ?))",
                (old_version + 1, owner, expires, now, row["schedule_id"], row["trigger_instance_id"], old_version, now),
            ).rowcount
            if changed != 1:
                return None
            schedule_changed = conn.execute(
                "UPDATE schedules SET state='CLAIMED', version=version+1, lease_owner=?, lease_expires_at=?, attempt_count=attempt_count+1, updated_at=? WHERE schedule_id=? AND version=? AND state IN ('SCHEDULED','CLAIMED')",
                (owner, expires, now, row["schedule_id"], row["schedule_version"]),
            ).rowcount
            if schedule_changed != 1:
                raise LeaseConflict("schedule version compare-and-set failed")
            claimed = conn.execute(
                "SELECT * FROM schedule_occurrences WHERE schedule_id=? AND trigger_instance_id=?",
                (row["schedule_id"], row["trigger_instance_id"]),
            ).fetchone()
            return _row(claimed) if claimed is not None else None

    def commit_scheduled_occurrence(
        self,
        schedule_id: str,
        trigger_instance_id: str,
        *,
        owner: str,
        now: str | None = None,
    ) -> dict[str, Any]:
        schedule_id = self._schedule_identifier(schedule_id, "schedule_id")
        trigger_instance_id = self._schedule_identifier(trigger_instance_id, "trigger_instance_id")
        now = self._schedule_timestamp(now or self._now(), "now")
        with self._tx() as conn:
            occurrence = conn.execute(
                "SELECT o.*, s.user_id, s.parent_turn_id, s.project_id, s.session_key, s.origin_device_id, s.delivery_target_device_id AS schedule_delivery_target_device_id, s.reminder_text, s.generation_instruction, s.fire_at_utc, s.state AS schedule_state FROM schedule_occurrences o JOIN schedules s ON s.schedule_id=o.schedule_id WHERE o.schedule_id=? AND o.trigger_instance_id=?",
                (schedule_id, trigger_instance_id),
            ).fetchone()
            if occurrence is None:
                raise NotFoundError("scheduled occurrence not found")
            if occurrence["state"] == "FIRED" and occurrence["turn_id"]:
                return self._scheduled_delivery_payload(conn, occurrence)
            if occurrence["state"] != "CLAIMED" or occurrence["lease_owner"] != owner or not occurrence["lease_expires_at"] or occurrence["lease_expires_at"] <= now:
                raise LeaseConflict("scheduled occurrence lease is not owned or has expired")
            turn_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:scheduled-turn:{schedule_id}:{trigger_instance_id}"))
            existing_turn = conn.execute("SELECT * FROM turns WHERE turn_id=?", (turn_id,)).fetchone()
            durable_target_device_id = occurrence["delivery_target_device_id"] or occurrence["schedule_delivery_target_device_id"]
            if existing_turn is not None:
                previous = conn.execute("SELECT * FROM turns WHERE turn_id=?", (existing_turn["previous_turn_id"],)).fetchone()
                if previous is None:
                    previous = {
                        "turn_id": existing_turn["previous_turn_id"],
                        "origin_device_id": existing_turn["previous_turn_origin_device_id"],
                    }
                target_device_id = durable_target_device_id or existing_turn["delivery_target_device_id"] or existing_turn["origin_device_id"]
            else:
                previous = conn.execute(
                    "SELECT * FROM turns WHERE user_id=? AND turn_source='client' AND accepted_seq IS NOT NULL ORDER BY accepted_seq DESC, updated_at DESC, turn_id DESC LIMIT 1",
                    (occurrence["user_id"],),
                ).fetchone()
                if previous is None:
                    raise ConflictError("server schedule has no durable client-originated target turn")
                target_device_id = durable_target_device_id or previous["origin_device_id"]
            if existing_turn is None:
                manifest = {
                    "schema_version": 1,
                    "user_id": occurrence["user_id"],
                    "turn_id": turn_id,
                    "origin_device_id": occurrence["origin_device_id"],
                    "client_created_at": occurrence["scheduled_for"],
                    "parts": [],
                    "turn_source": "server_schedule",
                    "schedule_id": schedule_id,
                    "trigger_instance_id": trigger_instance_id,
                    "parent_turn_id": occurrence["parent_turn_id"],
                    "previous_turn_id": previous["turn_id"],
                    "previous_turn_origin_device_id": previous["origin_device_id"],
                    "project_id": occurrence["project_id"],
                    "session_key": occurrence["session_key"],
                }
                initial_fingerprint = sha256_json(manifest)
                conn.execute(
                    "INSERT INTO turns(turn_id, user_id, origin_device_id, client_created_at, initial_fingerprint, manifest_json, state, turn_source, schedule_id, trigger_instance_id, parent_turn_id, previous_turn_id, previous_turn_origin_device_id, scheduled_for, fired_at, project_id, session_key, delivery_target_device_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'FINAL_READY', 'server_schedule', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        turn_id,
                        occurrence["user_id"],
                        occurrence["origin_device_id"],
                        occurrence["scheduled_for"],
                        initial_fingerprint,
                        _json(manifest),
                        schedule_id,
                        trigger_instance_id,
                        occurrence["parent_turn_id"],
                        previous["turn_id"],
                        previous["origin_device_id"],
                        occurrence["scheduled_for"],
                        now,
                        occurrence["project_id"],
                        occurrence["session_key"],
                        target_device_id,
                        now,
                        now,
                    ),
                )
            text = normalize_hermes_text(occurrence["reminder_text"])
            content_hash = hermes_content_hash(text)
            conn.execute(
                "INSERT OR IGNORE INTO final_versions(turn_id, event_version, source, outcome, error_kind, source_ref, content_hash, combined_content_hash, combined_content, committed_at) VALUES (?, 1, 'server_schedule', 'success', NULL, ?, ?, ?, NULL, ?)",
                (turn_id, f"{schedule_id}:{trigger_instance_id}", content_hash, content_hash, now),
            )
            payload = {
                "type": "FINAL",
                "turn_id": turn_id,
                "turn_source": "server_schedule",
                "schedule_id": schedule_id,
                "trigger_instance_id": trigger_instance_id,
                "parent_turn_id": occurrence["parent_turn_id"],
                "project_id": occurrence["project_id"],
                "session_key": occurrence["session_key"],
                "origin_device_id": occurrence["origin_device_id"],
                "previous_turn_id": previous["turn_id"],
                "previous_turn_origin_device_id": previous["origin_device_id"],
                "delivery_target_device_id": target_device_id,
                "scheduled_for": occurrence["scheduled_for"],
                "fired_at": now,
                "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:event:{turn_id}:FINAL:1")),
                "event_kind": "FINAL",
                "event_version": 1,
                "outcome": "success",
                "text": text,
                "tts_expected": True,
                "created_at": now,
            }
            event = self._insert_event_tx(
                conn,
                turn_id=turn_id,
                event_kind="FINAL",
                event_version=1,
                required_device_id=target_device_id,
                payload=payload,
                outcome="success",
                error_kind=None,
                create_outbox=True,
                created_at=now,
            )
            artifact = self._create_tts_tx(
                conn,
                turn_id=turn_id,
                event_id=event["event_id"],
                event_kind="FINAL",
                artifact_version=1,
                source_text=text,
                output_kind="FINAL_TTS",
                delivery_target_device_id=target_device_id,
                created_at=now,
            )
            conn.execute(
                "UPDATE turns SET final_event_version=1, final_combined_hash=?, final_content=?, final_outcome='success', final_error_kind=NULL, updated_at=? WHERE turn_id=? AND final_event_version=0",
                (content_hash, text, now, turn_id),
            )
            conn.execute(
                "UPDATE schedule_occurrences SET state='FIRED', version=version+1, lease_owner=NULL, lease_expires_at=NULL, previous_turn_id=?, previous_turn_origin_device_id=?, delivery_target_device_id=?, turn_id=?, event_id=?, artifact_id=?, fired_at=?, updated_at=? WHERE schedule_id=? AND trigger_instance_id=? AND state='CLAIMED' AND lease_owner=?",
                (previous["turn_id"], previous["origin_device_id"], target_device_id, turn_id, event["event_id"], artifact["artifact_id"], now, now, schedule_id, trigger_instance_id, owner),
            )
            if conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise LeaseConflict("scheduled occurrence completion compare-and-set failed")
            conn.execute(
                "UPDATE schedules SET state='FIRED', version=version+1, lease_owner=NULL, lease_expires_at=NULL, delivery_target_device_id=?, confirmation_event_id=confirmation_event_id, fired_at=?, updated_at=? WHERE schedule_id=? AND state='CLAIMED' AND lease_owner=?",
                (target_device_id, now, now, schedule_id, owner),
            )
            return self._scheduled_delivery_payload(
                conn,
                conn.execute(
                    "SELECT * FROM schedule_occurrences WHERE schedule_id=? AND trigger_instance_id=?",
                    (schedule_id, trigger_instance_id),
                ).fetchone(),
            )

    def fire_due_schedules(
        self,
        *,
        owner: str = "scheduler-1",
        lease_seconds: int = 30,
        limit: int = 50,
        now: str | None = None,
    ) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValidationError("scheduler limit must be an integer from 1 to 1000")
        effective_now = self._schedule_timestamp(now or self._now(), "now")
        results: list[dict[str, Any]] = []
        for _ in range(limit):
            claim = self.claim_due_occurrence(owner=owner, lease_seconds=lease_seconds, now=effective_now)
            if claim is None:
                break
            results.append(
                self.commit_scheduled_occurrence(
                    claim["schedule_id"],
                    claim["trigger_instance_id"],
                    owner=owner,
                    now=effective_now,
                )
            )
        return results

    def set_recording_lease(self, device_id: str, *, active: bool, lease_seconds: int = 60) -> None:
        now = self._now()
        expires = (dt.datetime.fromisoformat(now.replace("Z", "+00:00")) + dt.timedelta(seconds=lease_seconds)).isoformat(timespec="milliseconds") if active else None
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO recording_leases(device_id, active, lease_expires_at, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(device_id) DO UPDATE SET active=excluded.active, lease_expires_at=excluded.lease_expires_at, updated_at=excluded.updated_at",
                (device_id, int(active), expires, now),
            )
            detail = {"device_id": device_id, "active": active, "lease_expires_at": expires}
            conn.execute(
                "INSERT INTO audit_events(audit_id, kind, details_json, created_at) VALUES (?, 'recording_lease', ?, ?)",
                (str(uuid.uuid4()), _json(detail), now),
            )

    def set_asr_stage(self, turn_id: str, *, expected_generation: int, stage: str) -> int | None:
        if stage not in {"realtime", "batch", "local"}:
            raise ValidationError("unsupported ASR stage")
        with self._tx() as conn:
            self._turn_row(conn, turn_id)
            new_generation = expected_generation + 1
            changed = conn.execute(
                "UPDATE turns SET asr_stage=?, asr_generation=?, state=CASE WHEN state IN ('ACCEPTED','RETRY_WAIT') THEN 'PREPROCESSING' ELSE state END, updated_at=? WHERE turn_id=? AND asr_generation=? AND authoritative_asr_outcome IS NULL",
                (stage, new_generation, utc_now(), turn_id, expected_generation),
            ).rowcount
            return new_generation if changed else None

    def commit_asr_result(
        self,
        turn_id: str,
        *,
        expected_generation: int,
        stage: str,
        result: AsrResult,
        authoritative: bool = True,
    ) -> bool:
        paths: list[Path] = []
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            if turn["asr_generation"] != expected_generation or turn["asr_stage"] != stage:
                return False
            conn.execute(
                "INSERT INTO asr_attempts(attempt_id, turn_id, generation, stage, outcome, detail, transcript, committed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), turn_id, expected_generation, stage, result.outcome, result.detail, result.transcript, utc_now()),
            )
            if not authoritative:
                return True
            if result.outcome == "VALID_TRANSCRIPT":
                for part in conn.execute("SELECT source_path FROM turn_parts WHERE turn_id=? AND kind='audio'", (turn_id,)).fetchall():
                    if part["source_path"]:
                        paths.append(Path(part["source_path"]))
                for chunk in conn.execute("SELECT storage_path FROM turn_chunks WHERE turn_id=? AND part_id IN (SELECT part_id FROM turn_parts WHERE kind='audio')", (turn_id,)).fetchall():
                    paths.append(Path(chunk["storage_path"]))
                conn.execute(
                    "UPDATE turns SET transcript=?, authoritative_asr_outcome='VALID_TRANSCRIPT', source_deleted=0, state=CASE WHEN state IN ('ACCEPTED','PREPROCESSING','RETRY_WAIT') THEN 'ACCEPTED' ELSE state END, updated_at=? WHERE turn_id=?",
                    (result.transcript, utc_now(), turn_id),
                )
            elif result.outcome in {"NO_SPEECH", "PROVIDER_ERROR"}:
                conn.execute(
                    "UPDATE turns SET authoritative_asr_outcome=?, state=CASE WHEN ?='NO_SPEECH' THEN 'FINAL_READY' ELSE 'RETRY_WAIT' END, updated_at=? WHERE turn_id=?",
                    (result.outcome, result.outcome, utc_now(), turn_id),
                )
        if result.outcome == "VALID_TRANSCRIPT":
            deletion_complete = True
            for path in paths:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    deletion_complete = False
            if deletion_complete:
                with self._tx() as conn:
                    conn.execute("UPDATE turns SET source_deleted=1, updated_at=? WHERE turn_id=? AND authoritative_asr_outcome='VALID_TRANSCRIPT'", (utc_now(), turn_id))
        return True

    def retry_source_deletion(self, turn_id: str) -> bool:
        with self._read() as conn:
            turn = conn.execute("SELECT source_deleted, authoritative_asr_outcome FROM turns WHERE turn_id=?", (turn_id,)).fetchone()
            if turn is None or turn["source_deleted"] or turn["authoritative_asr_outcome"] != "VALID_TRANSCRIPT":
                return bool(turn and turn["source_deleted"])
            paths = [Path(row["storage_path"]) for row in conn.execute("SELECT storage_path FROM turn_chunks WHERE turn_id=? AND part_id IN (SELECT part_id FROM turn_parts WHERE kind='audio')", (turn_id,)).fetchall()]
            paths.extend(Path(row["source_path"]) for row in conn.execute("SELECT source_path FROM turn_parts WHERE turn_id=? AND kind='audio' AND source_path IS NOT NULL", (turn_id,)).fetchall())
        complete = True
        for path in paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                complete = False
        if complete:
            with self._tx() as conn:
                conn.execute("UPDATE turns SET source_deleted=1, updated_at=? WHERE turn_id=? AND authoritative_asr_outcome='VALID_TRANSCRIPT'", (utc_now(), turn_id))
        return complete

    def recover(self, *, now: str | None = None) -> dict[str, int]:
        now = now or self._now()
        with self._tx() as conn:
            source_pending = [row["turn_id"] for row in conn.execute("SELECT turn_id FROM turns WHERE source_deleted=0 AND authoritative_asr_outcome='VALID_TRANSCRIPT'").fetchall()]
            router_count = conn.execute(
                "UPDATE router_queue SET state='QUEUED', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE state='IN_PROGRESS' AND lease_expires_at <= ?",
                (now, now),
            ).rowcount
            ingress_count = conn.execute(
                "UPDATE session_ingress SET status='QUEUED', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE status='IN_PROGRESS' AND lease_expires_at <= ?",
                (now, now),
            ).rowcount
            grace_failed = conn.execute(
                "UPDATE turns SET state='FAILED_PERMANENT', updated_at=? WHERE state='LATE_RESULT_GRACE' AND final_error_kind='hermes' AND grace_until <= ? AND EXISTS (SELECT 1 FROM events e JOIN outbox o ON o.event_id=e.event_id WHERE e.turn_id=turns.turn_id AND e.event_kind='FINAL' AND e.event_version=turns.final_event_version AND o.state='ACKED')",
                (now, now),
            ).rowcount
            grace_expired = conn.execute(
                "UPDATE turns SET state='EXPIRED', updated_at=? WHERE state='LATE_RESULT_GRACE' AND final_error_kind='hermes' AND grace_until <= ?",
                (now, now),
            ).rowcount
            schedule_occurrences_requeued = conn.execute(
                "UPDATE schedule_occurrences SET state='PENDING', version=version+1, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE state='CLAIMED' AND lease_expires_at <= ?",
                (now, now),
            ).rowcount
            schedules_requeued = conn.execute(
                "UPDATE schedules SET state='SCHEDULED', version=version+1, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE state='CLAIMED' AND lease_expires_at <= ?",
                (now, now),
            ).rowcount
            result = {
                "router_leases_requeued": router_count,
                "session_ingress_requeued": ingress_count,
                "grace_failed": grace_failed,
                "grace_expired": grace_expired,
                "schedule_occurrences_requeued": schedule_occurrences_requeued,
                "schedules_requeued": schedules_requeued,
                "source_deletions_retried": 0,
            }
        for pending_turn_id in source_pending:
            if self.retry_source_deletion(pending_turn_id):
                result["source_deletions_retried"] += 1
        return result

    def release_session_ingress(self, submission_id: str, *, owner: str) -> bool:
        with self._tx() as conn:
            updated = conn.execute(
                "UPDATE session_ingress SET status='QUEUED', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE hermes_submission_id=? AND status='IN_PROGRESS' AND lease_owner=?",
                (utc_now(), submission_id, owner),
            ).rowcount
            return bool(updated)

    def pending_tts(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._read() as conn:
            rows = conn.execute(
                "SELECT t.* FROM tts_artifacts t LEFT JOIN recording_leases r ON r.device_id=COALESCE(t.delivery_target_device_id, t.origin_device_id) WHERE t.status IN ('PENDING','DELIVERY_PENDING','FAILED_GENERATION') AND (r.device_id IS NULL OR r.active=0 OR r.lease_expires_at <= ?) ORDER BY COALESCE(t.delivery_target_device_id, t.origin_device_id), t.delivery_seq LIMIT ?",
                (self._now(), limit),
            ).fetchall()
            return [_row(row) or {} for row in rows]

    # ---- Project registry -------------------------------------------------

    def _project_payload(self, row: sqlite3.Row) -> dict[str, Any]:
        result = _row(row) or {}
        result["aliases"] = _loads(result.pop("aliases_json"), [])
        return result

    def create_project(
        self,
        user_id: str,
        *,
        project_number: str,
        name: str,
        aliases: list[str] | None = None,
        description: str = "",
        idempotency_key: str | None = None,
        stable_project_id: str | None = None,
    ) -> dict[str, Any]:
        if not user_id or not project_number or not name:
            raise ValidationError("project_number and name are required")
        stable_project_id = stable_project_id or str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:project:{user_id}:{idempotency_key or project_number}"))
        session_key = f"project:{stable_project_id}:default"
        now = utc_now()
        with self._tx() as conn:
            existing = conn.execute("SELECT * FROM projects WHERE stable_project_id=?", (stable_project_id,)).fetchone()
            if existing:
                if existing["user_id"] != user_id:
                    raise ConflictError("project id belongs to another user")
                return self._project_payload(existing)
            by_number = conn.execute("SELECT * FROM projects WHERE user_id=? AND project_number=?", (user_id, project_number)).fetchone()
            if by_number:
                return self._project_payload(by_number)
            conn.execute(
                "INSERT INTO projects(stable_project_id, user_id, project_number, name, aliases_json, description, status, default_session_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
                (stable_project_id, user_id, project_number, name, _json(aliases or []), description, session_key, now, now),
            )
            conn.execute(
                "INSERT INTO sessions(session_key, project_id, gateway_session_key, created_at) VALUES (?, ?, ?, ?)",
                (session_key, stable_project_id, session_key, now),
            )
            return self._project_payload(conn.execute("SELECT * FROM projects WHERE stable_project_id=?", (stable_project_id,)).fetchone())

    def list_projects(self, user_id: str, *, include_archived: bool = False) -> list[dict[str, Any]]:
        with self._read() as conn:
            sql = "SELECT * FROM projects WHERE user_id=?"
            args: list[Any] = [user_id]
            if not include_archived:
                sql += " AND status='active'"
            sql += " ORDER BY project_number"
            return [self._project_payload(row) for row in conn.execute(sql, args).fetchall()]

    def search_projects(self, user_id: str, query: str, *, include_archived: bool = False) -> list[dict[str, Any]]:
        q = f"%{query.lower()}%"
        with self._read() as conn:
            sql = "SELECT * FROM projects WHERE user_id=? AND (lower(project_number) LIKE ? OR lower(name) LIKE ? OR lower(description) LIKE ? OR lower(aliases_json) LIKE ?)"
            args: list[Any] = [user_id, q, q, q, q]
            if not include_archived:
                sql += " AND status='active'"
            sql += " ORDER BY project_number"
            return [self._project_payload(row) for row in conn.execute(sql, args).fetchall()]

    def get_project(self, user_id: str, project_id: str, *, include_archived: bool = True) -> dict[str, Any]:
        with self._read() as conn:
            row = conn.execute("SELECT * FROM projects WHERE stable_project_id=? AND user_id=?", (project_id, user_id)).fetchone()
            if row is None or (not include_archived and row["status"] != "active"):
                raise NotFoundError("project not found")
            return self._project_payload(row)

    def update_project(self, user_id: str, project_id: str, *, expected_version: int, patch: Mapping[str, Any]) -> dict[str, Any]:
        allowed = {"name", "aliases", "description"}
        if set(patch) - allowed:
            raise ValidationError("project update may change only name, aliases, and description")
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM projects WHERE stable_project_id=? AND user_id=?", (project_id, user_id)).fetchone()
            if row is None:
                raise NotFoundError("project not found")
            fields = {"name": row["name"], "aliases_json": row["aliases_json"], "description": row["description"]}
            if "name" in patch:
                fields["name"] = patch["name"]
            if "aliases" in patch:
                fields["aliases_json"] = _json(patch["aliases"])
            if "description" in patch:
                fields["description"] = patch["description"]
            now = utc_now()
            updated = conn.execute(
                "UPDATE projects SET name=?, aliases_json=?, description=?, record_version=record_version+1, updated_at=? WHERE stable_project_id=? AND user_id=? AND record_version=?",
                (fields["name"], fields["aliases_json"], fields["description"], now, project_id, user_id, expected_version),
            ).rowcount
            if not updated:
                raise ConflictError("project record_version compare-and-set failed")
            return self._project_payload(conn.execute("SELECT * FROM projects WHERE stable_project_id=?", (project_id,)).fetchone())

    def archive_project(self, user_id: str, project_id: str, *, expected_version: int) -> dict[str, Any]:
        with self._tx() as conn:
            now = utc_now()
            updated = conn.execute(
                "UPDATE projects SET status='archived', archived_at=?, record_version=record_version+1, updated_at=? WHERE stable_project_id=? AND user_id=? AND status='active' AND record_version=?",
                (now, now, project_id, user_id, expected_version),
            ).rowcount
            if not updated:
                raise ConflictError("project archive compare-and-set failed")
            return self._project_payload(conn.execute("SELECT * FROM projects WHERE stable_project_id=?", (project_id,)).fetchone())

    def archive_turn(self, user_id: str, turn_id: str, *, source: str) -> dict[str, Any]:
        with self._tx() as conn:
            turn = self._turn_row(conn, turn_id)
            if turn["user_id"] != user_id:
                raise UnauthorizedError("turn belongs to another user")
            now = utc_now()
            conn.execute("UPDATE turns SET archived_at=?, updated_at=? WHERE turn_id=?", (now, now, turn_id))
            conn.execute(
                "INSERT INTO audit_events(audit_id, user_id, turn_id, kind, details_json, created_at) VALUES (?, ?, ?, 'archive_turn', ?, ?)",
                (str(uuid.uuid4()), user_id, turn_id, _json({"source": source}), now),
            )
            return self._turn_payload(conn, turn_id)

    def db_snapshot(self) -> dict[str, int]:
        tables = ["turns", "turn_parts", "turn_chunks", "events", "outbox", "router_queue", "projects", "session_ingress", "hermes_results", "final_versions", "tts_artifacts", "asr_attempts", "schedules", "schedule_occurrences"]
        with self._read() as conn:
            return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables}
