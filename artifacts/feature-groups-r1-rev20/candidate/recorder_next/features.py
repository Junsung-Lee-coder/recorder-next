"""Recorder Next feature groups 1-8.

This module keeps the new protocol surfaces behind a small coordinator while
RecorderStore remains the sole SQLite authority.  It intentionally contains no
network clients or service-starting code; providers live in ``adapters.py`` and
HTTP routing remains in ``service.py``.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import re
import stat
import uuid
import zlib
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .canonical import canonical_json, normalize_hermes_text, sha256_bytes, sha256_json
from .errors import ConflictError, LeaseConflict, NotFoundError, NotReadyError, RangeNotSatisfiable, RecorderError, UnauthorizedError, ValidationError


DIGEST_RE = re.compile(r"^[0-9a-fA-F]{64}$")
FEATURE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
CHANNEL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
APK_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.apk$")
SAFE_ERROR_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

WORKER_ACTIVE = {"PENDING", "CLAIMED", "RETRY_WAIT"}
WORKER_TERMINAL = {"SUCCEEDED", "FAILED_PERMANENT"}
EAVESDROP_STATES = {"CREATED", "ACTIVE", "PAUSED", "STOPPING", "STOPPED", "EXPIRED", "FAILED"}


class EavesdropRoutingAgent:
    """Small policy boundary for the separate eavesdrop routing decision."""

    policy_version = "eavesdrop-router-v1"

    def decide(self, *, session: Mapping[str, Any], segment: Mapping[str, Any], accumulated_transcript: str) -> dict[str, Any]:
        del segment
        has_transcript = isinstance(accumulated_transcript, str) and bool(accumulated_transcript.strip())
        if bool(session.get("hermes_enabled")) and has_transcript:
            return {"outcome": "FORWARD_DEFAULT", "reason": "explicit_forward_policy", "policy_version": self.policy_version}
        if bool(session.get("hermes_enabled")):
            return {"outcome": "STORE_SILENT", "reason": "no_transcript", "policy_version": self.policy_version}
        return {"outcome": "STORE_SILENT", "reason": "silent_policy", "policy_version": self.policy_version}


class FeatureGroups:
    """Durable implementations for Recorder Next feature groups 1 through 8."""

    def __init__(self, store: Any, eavesdrop_agent: Any | None = None):
        self.store = store
        self.eavesdrop_agent = eavesdrop_agent or EavesdropRoutingAgent()

    # ---- Shared validation and no-follow file helpers ---------------------

    @staticmethod
    def _time(value: str | None, store: Any) -> str:
        if value is None:
            return store._now()
        if not isinstance(value, str) or not value:
            raise ValidationError("timestamp must be an RFC3339 string")
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("timestamp must be an RFC3339 string") from exc
        if parsed.tzinfo is None:
            raise ValidationError("timestamp must include a timezone")
        return parsed.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds")

    @staticmethod
    def _plus_seconds(value: str, seconds: int) -> str:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (parsed + dt.timedelta(seconds=seconds)).isoformat(timespec="milliseconds")

    @staticmethod
    def _identifier(value: Any, field: str = "identifier") -> str:
        if not isinstance(value, str) or not FEATURE_ID_RE.fullmatch(value):
            raise ValidationError(f"{field} must be a bounded identifier")
        return value

    @staticmethod
    def _digest(value: Any, field: str) -> str:
        if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
            raise ValidationError(f"{field} must be a SHA-256 digest")
        return value.lower()

    @staticmethod
    def _safe_error_kind(value: str) -> str:
        if not isinstance(value, str) or not SAFE_ERROR_RE.fullmatch(value):
            raise ValidationError("error_kind must be a bounded code")
        return value

    @staticmethod
    def _row(row: Any) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    @classmethod
    def _safe_eavesdrop_receipt(cls, receipt: Mapping[str, Any]) -> dict[str, Any]:
        allowed = {
            "submission_id",
            "session_id",
            "segment_sequence",
            "segment_sha256",
            "gateway_profile",
            "input_sha256",
            "content_hash",
            "reply_id",
            "assistant_message_id",
            "provider",
        }
        if any(not isinstance(key, str) or key not in allowed for key in receipt):
            raise ValidationError("eavesdrop effect receipt contains unsupported data")
        required = {"submission_id", "session_id", "segment_sequence", "segment_sha256", "gateway_profile", "input_sha256", "content_hash", "provider"}
        if not required.issubset(receipt):
            raise ValidationError("eavesdrop effect receipt is incomplete")
        result: dict[str, Any] = {}
        for key, value in receipt.items():
            if key.endswith("_sha256") or key == "content_hash":
                result[key] = None if value is None else cls._digest(value, key)
            elif key == "segment_sequence":
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValidationError("eavesdrop receipt sequence is invalid")
                result[key] = value
            elif key == "gateway_profile":
                if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
                    raise ValidationError("eavesdrop receipt profile is invalid")
                result[key] = value
            elif key in {"submission_id", "session_id", "reply_id", "assistant_message_id", "provider"}:
                result[key] = cls._identifier(value, key) if value is not None else None
            else:
                raise ValidationError("eavesdrop effect receipt is invalid")
        return result

    @classmethod
    def _eavesdrop_decision_payload(cls, row: Any) -> dict[str, Any]:
        result = cls._row(row) or {}
        raw = result.get("effect_receipt_json")
        if isinstance(raw, str) and raw:
            try:
                parsed = json.loads(raw)
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValidationError("stored eavesdrop receipt is malformed") from exc
            if not isinstance(parsed, Mapping):
                raise ValidationError("stored eavesdrop receipt is malformed")
            result["effect_receipt_json"] = cls._safe_eavesdrop_receipt(parsed)
        result["gateway_profile"] = "default"
        return result

    @staticmethod
    def _ensure_no_symlink_path(root: Path, path: Path, *, allow_missing_leaf: bool = True) -> None:
        """Reject symlinked path components without resolving them."""

        root = root.absolute()
        path = path.absolute()
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise UnauthorizedError("managed path escapes the storage root") from exc
        current = root
        try:
            root_info = os.lstat(current)
        except FileNotFoundError as exc:
            raise NotReadyError("managed storage root is unavailable") from exc
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise UnauthorizedError("managed storage root is not a regular directory")
        for index, component in enumerate(relative.parts):
            current = current / component
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                if allow_missing_leaf and index == len(relative.parts) - 1:
                    return
                raise NotReadyError("managed path is incomplete")
            if stat.S_ISLNK(info.st_mode):
                raise UnauthorizedError("managed path contains a symlink")
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
                raise UnauthorizedError("managed path contains a non-directory component")

    @classmethod
    def _mkdir_managed_path(cls, root: Path, path: Path) -> None:
        """Create a managed directory tree without following existing links."""

        root = root.absolute()
        path = path.absolute()
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise UnauthorizedError("managed directory escapes the storage root") from exc
        cls._ensure_no_symlink_path(root, root, allow_missing_leaf=False)
        current = root
        for component in relative.parts:
            current = current / component
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                current.mkdir()
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise UnauthorizedError("managed directory contains an unsafe component")

    @classmethod
    def _read_managed_bytes(
        cls,
        root: Path,
        path: Path,
        *,
        expected_size: int | None = None,
        expected_sha256: str | None = None,
    ) -> bytes:
        cls._ensure_no_symlink_path(root, path, allow_missing_leaf=False)
        root = root.absolute()
        path = path.absolute()
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise UnauthorizedError("managed path escapes the storage root") from exc
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_descriptor: int | None = None
        directory_descriptor: int | None = None
        descriptor: int | None = None
        try:
            root_descriptor = os.open(root, directory_flags)
            directory_descriptor = root_descriptor
            components = relative.parts
            if not components:
                raise UnauthorizedError("managed path must name a file")
            for component in components[:-1]:
                next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
                if directory_descriptor != root_descriptor:
                    os.close(directory_descriptor)
                directory_descriptor = next_descriptor
            descriptor = os.open(components[-1], file_flags, dir_fd=directory_descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise UnauthorizedError("managed artifact is not a regular file")
            if expected_size is not None and info.st_size != expected_size:
                raise ConflictError("managed artifact size does not match its receipt")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            content = b"".join(chunks)
        except OSError as exc:
            raise NotReadyError("managed artifact is unavailable") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory_descriptor is not None and directory_descriptor != root_descriptor:
                os.close(directory_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)
        if expected_size is not None and len(content) != expected_size:
            raise ConflictError("managed artifact size changed while reading")
        if expected_sha256 is not None and sha256_bytes(content) != expected_sha256.lower():
            raise ConflictError("managed artifact hash does not match its receipt")
        return content

    @staticmethod
    def _read_source_bytes(path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise NotReadyError("update artifact source is unavailable") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise UnauthorizedError("update artifact source must be a regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    @classmethod
    def _unlink_managed_file(cls, root: Path, path: Path) -> None:
        """Unlink a managed leaf without following a swapped parent."""

        cls._ensure_no_symlink_path(root, path, allow_missing_leaf=True)
        root = root.absolute()
        path = path.absolute()
        relative = path.relative_to(root)
        if not relative.parts:
            raise UnauthorizedError("managed storage root cannot be removed")
        root_descriptor = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        directory_descriptor = root_descriptor
        try:
            for component in relative.parts[:-1]:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_descriptor,
                )
                if directory_descriptor != root_descriptor:
                    os.close(directory_descriptor)
                directory_descriptor = next_descriptor
            try:
                # Keep the unlink anchored to the already opened directory
                # descriptor.  Going through its procfs handle also leaves a
                # Path.unlink seam for callers that need to surface a
                # physical deletion failure without weakening containment or
                # symlink checks.
                (Path("/proc/self/fd") / str(directory_descriptor) / relative.parts[-1]).unlink()
            except FileNotFoundError:
                return
        finally:
            if directory_descriptor != root_descriptor:
                os.close(directory_descriptor)
            os.close(root_descriptor)

    # ---- Group 1: durable autonomous processing worker --------------------

    def _job_payload(self, row: Any) -> dict[str, Any]:
        result = self._row(row) or {}
        raw = result.pop("payload_json", "{}")
        result["payload"] = json.loads(raw)
        if result.get("effect_receipt_json"):
            result["effect_receipt"] = json.loads(result["effect_receipt_json"])
        else:
            result["effect_receipt"] = None
        result.pop("effect_receipt_json", None)
        if result.get("chain_json"):
            result["provider_chain"] = json.loads(result["chain_json"])
        else:
            result["provider_chain"] = None
        result.pop("chain_json", None)
        return result

    def _enqueue_worker_job_tx(
        self,
        conn: Any,
        *,
        kind: str,
        stage: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        max_attempts: int,
        now: str,
        next_attempt_at: str,
        provider_chain: Mapping[str, Any] | None = None,
        overall_deadline_at: str | None = None,
    ) -> dict[str, Any]:
        payload_json = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        payload_sha = sha256_bytes(canonical_json(dict(payload)))
        chain_json = json.dumps(dict(provider_chain), ensure_ascii=False, sort_keys=True, separators=(",", ":")) if provider_chain is not None else None
        chain_generation = str(provider_chain.get("generation")) if provider_chain is not None and provider_chain.get("generation") is not None else None
        chain_fingerprint = str(provider_chain.get("fingerprint")) if provider_chain is not None and provider_chain.get("fingerprint") is not None else None
        existing = conn.execute("SELECT * FROM worker_jobs WHERE idempotency_key=?", (idempotency_key,)).fetchone()
        if existing is not None:
            if existing["payload_sha256"] != payload_sha or existing["kind"] != kind or existing["stage"] != stage or existing["chain_fingerprint"] != chain_fingerprint or existing["chain_json"] != chain_json:
                raise ConflictError("worker idempotency key has a different immutable payload")
            return self._job_payload(existing)
        job_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:worker:{idempotency_key}"))
        conn.execute(
            "INSERT INTO worker_jobs(job_id, idempotency_key, kind, stage, payload_json, payload_sha256, chain_generation, chain_fingerprint, chain_json, overall_deadline_at, status, next_attempt_at, max_attempts, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?)",
            (job_id, idempotency_key, kind, stage, payload_json, payload_sha, chain_generation, chain_fingerprint, chain_json, overall_deadline_at, next_attempt_at, max_attempts, now, now),
        )
        return self._job_payload(conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone())

    def enqueue_worker_job(
        self,
        *,
        kind: str,
        stage: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        max_attempts: int = 3,
        now: str | None = None,
        next_attempt_at: str | None = None,
        provider_chain: Any | None = None,
        deadline_seconds: int | None = None,
    ) -> dict[str, Any]:
        self._identifier(kind, "kind")
        self._identifier(stage, "stage")
        self._identifier(idempotency_key, "idempotency_key")
        if not isinstance(payload, Mapping):
            raise ValidationError("worker payload must be a JSON object")
        try:
            canonical_json(dict(payload))
        except (TypeError, ValueError) as exc:
            raise ValidationError("worker payload must be JSON serializable") from exc
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or not 1 <= max_attempts <= 100:
            raise ValidationError("max_attempts must be between 1 and 100")
        timestamp = self._time(now, self.store)
        due = self._time(next_attempt_at, self.store) if next_attempt_at is not None else timestamp
        frozen: Mapping[str, Any] | None = None
        if provider_chain is not None:
            if hasattr(provider_chain, "freeze"):
                frozen = provider_chain.freeze()
            elif isinstance(provider_chain, Mapping):
                frozen = dict(provider_chain)
            else:
                raise ValidationError("provider_chain must be a frozen mapping or ProviderChain")
            if frozen.get("version") != 1 or frozen.get("kind") not in {"asr", "tts"} or not isinstance(frozen.get("fingerprint"), str) or not isinstance(frozen.get("generation"), str) or not isinstance(frozen.get("targets"), list) or not frozen["targets"]:
                raise ValidationError("provider_chain freeze is invalid")
            if frozen["kind"] != stage and stage in {"asr", "tts"}:
                raise ValidationError("provider_chain type does not match worker stage")
        if deadline_seconds is not None:
            if not isinstance(deadline_seconds, int) or isinstance(deadline_seconds, bool) or not 1 <= deadline_seconds <= 1800:
                raise ValidationError("deadline_seconds must be between 1 and 1800")
            deadline_at = self._plus_seconds(timestamp, deadline_seconds)
        else:
            deadline_at = None
        with self.store._tx() as conn:
            return self._enqueue_worker_job_tx(
                conn,
                kind=kind,
                stage=stage,
                payload=payload,
                idempotency_key=idempotency_key,
                max_attempts=max_attempts,
                now=timestamp,
                next_attempt_at=due,
                provider_chain=frozen,
                overall_deadline_at=deadline_at,
            )

    def get_worker_job(self, job_id: str) -> dict[str, Any]:
        self._identifier(job_id, "job_id")
        with self.store._read() as conn:
            row = conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None:
                raise NotFoundError("worker job not found")
            return self._job_payload(row)

    def list_worker_jobs(self, *, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if status is not None and status not in WORKER_ACTIVE | WORKER_TERMINAL:
            raise ValidationError("unsupported worker job status")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValidationError("worker job limit must be between 1 and 500")
        with self.store._read() as conn:
            if status is None:
                rows = conn.execute("SELECT * FROM worker_jobs ORDER BY created_at, job_id LIMIT ?", (limit,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM worker_jobs WHERE status=? ORDER BY created_at, job_id LIMIT ?", (status, limit)).fetchall()
            return [self._job_payload(row) for row in rows]

    def worker_health(self, *, now: str | None = None) -> dict[str, Any]:
        """Return bounded queue state without returning job payloads."""
        timestamp = self._time(now, self.store)
        with self.store._read() as conn:
            counts = {
                status: int(conn.execute("SELECT COUNT(*) FROM worker_jobs WHERE status=?", (status,)).fetchone()[0])
                for status in sorted(WORKER_ACTIVE | WORKER_TERMINAL)
            }
            due = int(conn.execute("SELECT COUNT(*) FROM worker_jobs WHERE status IN ('PENDING','RETRY_WAIT') AND next_attempt_at <= ? AND (overall_deadline_at IS NULL OR overall_deadline_at > ?)", (timestamp, timestamp)).fetchone()[0])
            leased = int(conn.execute("SELECT COUNT(*) FROM worker_jobs WHERE status='CLAIMED' AND lease_expires_at > ?", (timestamp,)).fetchone()[0])
            expired = int(conn.execute("SELECT COUNT(*) FROM worker_jobs WHERE status='CLAIMED' AND lease_expires_at <= ?", (timestamp,)).fetchone()[0])
            deadline_expired = int(conn.execute("SELECT COUNT(*) FROM worker_jobs WHERE status IN ('PENDING','RETRY_WAIT','CLAIMED') AND overall_deadline_at IS NOT NULL AND overall_deadline_at <= ?", (timestamp,)).fetchone()[0])
            return {"as_of": timestamp, "counts": counts, "due": due, "leased": leased, "expired_leases": expired, "expired_deadlines": deadline_expired, "bounded": True}

    def claim_worker_job(self, owner: str, *, now: str | None = None, lease_seconds: int = 30) -> dict[str, Any] | None:
        self._identifier(owner, "owner")
        if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 86400:
            raise ValidationError("worker lease_seconds must be between 1 and 86400")
        timestamp = self._time(now, self.store)
        expires = self._plus_seconds(timestamp, lease_seconds)
        with self.store._tx() as conn:
            conn.execute(
                "UPDATE worker_jobs SET status='FAILED_PERMANENT', owner=NULL, lease_expires_at=NULL, last_error_kind='deadline', updated_at=?, completed_at=? WHERE status IN ('PENDING','RETRY_WAIT','CLAIMED') AND overall_deadline_at IS NOT NULL AND overall_deadline_at <= ?",
                (timestamp, timestamp, timestamp),
            )
            row = conn.execute(
                "SELECT * FROM worker_jobs WHERE ((status IN ('PENDING','RETRY_WAIT') AND next_attempt_at <= ?) OR (status='CLAIMED' AND lease_expires_at <= ?)) AND (overall_deadline_at IS NULL OR overall_deadline_at > ?) ORDER BY next_attempt_at, created_at, job_id LIMIT 1",
                (timestamp, timestamp, timestamp),
            ).fetchone()
            if row is None:
                return None
            attempt = int(row["attempt_count"]) + 1
            changed = conn.execute(
                "UPDATE worker_jobs SET status='CLAIMED', owner=?, lease_expires_at=?, attempt_count=?, updated_at=? WHERE job_id=? AND ((status IN ('PENDING','RETRY_WAIT') AND next_attempt_at <= ?) OR (status='CLAIMED' AND lease_expires_at <= ?)) AND (overall_deadline_at IS NULL OR overall_deadline_at > ?)",
                (owner, expires, attempt, timestamp, row["job_id"], timestamp, timestamp, timestamp),
            ).rowcount
            if changed != 1:
                return None
            if row["status"] == "CLAIMED":
                conn.execute(
                    "UPDATE worker_attempts SET outcome='RECLAIMED', finished_at=? WHERE job_id=? AND outcome='RUNNING'",
                    (timestamp, row["job_id"]),
                )
            attempt_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:worker-attempt:{row['job_id']}:{attempt}"))
            conn.execute(
                "INSERT OR REPLACE INTO worker_attempts(attempt_id, job_id, attempt_number, owner, stage, started_at, outcome) VALUES (?, ?, ?, ?, ?, ?, 'RUNNING')",
                (attempt_id, row["job_id"], attempt, owner, row["stage"], timestamp),
            )
            return self._job_payload(conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (row["job_id"],)).fetchone())

    def renew_worker_lease(self, job_id: str, owner: str, *, now: str | None = None, lease_seconds: int = 30) -> bool:
        self._identifier(job_id, "job_id")
        self._identifier(owner, "owner")
        if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 86400:
            raise ValidationError("worker lease_seconds must be between 1 and 86400")
        timestamp = self._time(now, self.store)
        expires = self._plus_seconds(timestamp, lease_seconds)
        with self.store._tx() as conn:
            return bool(
                conn.execute(
                    "UPDATE worker_jobs SET lease_expires_at=?, updated_at=? WHERE job_id=? AND status='CLAIMED' AND owner=? AND lease_expires_at > ?",
                    (expires, timestamp, job_id, owner, timestamp),
                ).rowcount
            )

    def _assert_worker_claim(self, conn: Any, job_id: str, owner: str, now: str) -> Any:
        row = conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise NotFoundError("worker job not found")
        if row["status"] != "CLAIMED" or row["owner"] != owner or not row["lease_expires_at"] or row["lease_expires_at"] <= now:
            raise LeaseConflict("worker job lease is not owned or has expired")
        return row

    @staticmethod
    def _receipt(receipt: Mapping[str, Any]) -> tuple[str, str]:
        if not isinstance(receipt, Mapping):
            raise ValidationError("effect receipt must be a JSON object")
        allowed = {"effect_id", "status", "job_id", "idempotency_key", "stage", "outcome", "state", "count"}
        if any(not isinstance(key, str) or key not in allowed for key in receipt):
            raise ValidationError("effect receipt contains unsupported data")
        effect_id = receipt.get("effect_id")
        status = receipt.get("status")
        if not isinstance(effect_id, str) or not FEATURE_ID_RE.fullmatch(effect_id):
            raise ValidationError("effect receipt requires a bounded effect_id")
        if status not in {"accepted", "succeeded", "not_required"}:
            raise ValidationError("effect receipt status is unsupported")
        for key in {"job_id", "idempotency_key", "stage"} & set(receipt):
            value = receipt[key]
            if not isinstance(value, str) or not FEATURE_ID_RE.fullmatch(value):
                raise ValidationError(f"effect receipt {key} is invalid")
        if "count" in receipt and (not isinstance(receipt["count"], int) or isinstance(receipt["count"], bool) or receipt["count"] < 0):
            raise ValidationError("effect receipt count is invalid")
        for key in {"outcome", "state"} & set(receipt):
            value = receipt[key]
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", value):
                raise ValidationError(f"effect receipt {key} is invalid")
        try:
            encoded = canonical_json(dict(receipt))
        except (TypeError, ValueError) as exc:
            raise ValidationError("effect receipt must be JSON serializable") from exc
        return json.dumps(dict(receipt), ensure_ascii=False, sort_keys=True, separators=(",", ":")), sha256_bytes(encoded)

    def complete_worker_job(self, job_id: str, owner: str, receipt: Mapping[str, Any], *, now: str | None = None) -> dict[str, Any]:
        self._identifier(job_id, "job_id")
        self._identifier(owner, "owner")
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            existing = conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone()
            if existing is None:
                raise NotFoundError("worker job not found")
            if existing["status"] == "SUCCEEDED":
                candidate = dict(receipt)
                if "job_id" in candidate and candidate["job_id"] != existing["job_id"]:
                    raise ConflictError("effect receipt job binding does not match worker job")
                if "idempotency_key" in candidate and candidate["idempotency_key"] != existing["idempotency_key"]:
                    raise ConflictError("effect receipt idempotency binding does not match worker job")
                candidate.setdefault("job_id", existing["job_id"])
                candidate.setdefault("idempotency_key", existing["idempotency_key"])
                candidate.setdefault("stage", existing["stage"])
                _candidate_json, candidate_sha = self._receipt(candidate)
                if candidate_sha != existing["effect_receipt_sha256"]:
                    raise ConflictError("worker job already succeeded with a different effect receipt")
                return self._job_payload(existing)
            row = self._assert_worker_claim(conn, job_id, owner, timestamp)
            bound_receipt = dict(receipt)
            if "job_id" in bound_receipt and bound_receipt["job_id"] != row["job_id"]:
                raise ConflictError("effect receipt job binding does not match worker job")
            if "idempotency_key" in bound_receipt and bound_receipt["idempotency_key"] != row["idempotency_key"]:
                raise ConflictError("effect receipt idempotency binding does not match worker job")
            bound_receipt.setdefault("job_id", row["job_id"])
            bound_receipt.setdefault("idempotency_key", row["idempotency_key"])
            bound_receipt.setdefault("stage", row["stage"])
            receipt_json, receipt_sha = self._receipt(bound_receipt)
            conn.execute(
                "UPDATE worker_jobs SET status='SUCCEEDED', owner=NULL, lease_expires_at=NULL, effect_receipt_json=?, effect_receipt_sha256=?, updated_at=?, completed_at=? WHERE job_id=?",
                (receipt_json, receipt_sha, timestamp, timestamp, job_id),
            )
            conn.execute(
                "UPDATE worker_attempts SET outcome='SUCCEEDED', finished_at=?, effect_receipt_sha256=? WHERE job_id=? AND attempt_number=? AND outcome='RUNNING'",
                (timestamp, receipt_sha, job_id, row["attempt_count"]),
            )
            return self._job_payload(conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone())

    def fail_worker_job(
        self,
        job_id: str,
        owner: str,
        *,
        error_kind: str,
        retryable: bool,
        now: str | None = None,
        retry_after_seconds: int | None = None,
    ) -> dict[str, Any]:
        self._identifier(job_id, "job_id")
        self._identifier(owner, "owner")
        error_kind = self._safe_error_kind(error_kind)
        if not isinstance(retryable, bool):
            raise ValidationError("retryable must be boolean")
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            row = self._assert_worker_claim(conn, job_id, owner, timestamp)
            attempt_count = int(row["attempt_count"])
            can_retry = retryable and attempt_count < int(row["max_attempts"]) and (row["overall_deadline_at"] is None or row["overall_deadline_at"] > timestamp)
            if can_retry:
                delay = retry_after_seconds if retry_after_seconds is not None else min(300, 2 ** min(attempt_count, 8))
                if not isinstance(delay, int) or isinstance(delay, bool) or delay < 0 or delay > 86400:
                    raise ValidationError("retry_after_seconds is out of bounds")
                state = "RETRY_WAIT"
                next_attempt_at = self._plus_seconds(timestamp, delay)
                outcome = "RETRY_WAIT"
            else:
                state = "FAILED_PERMANENT"
                next_attempt_at = timestamp
                outcome = "FAILED_PERMANENT"
            conn.execute(
                "UPDATE worker_jobs SET status=?, owner=NULL, lease_expires_at=NULL, next_attempt_at=?, last_error_kind=?, updated_at=?, completed_at=? WHERE job_id=?",
                (state, next_attempt_at, error_kind, timestamp, timestamp if state == "FAILED_PERMANENT" else None, job_id),
            )
            conn.execute(
                "UPDATE worker_attempts SET outcome=?, error_kind=?, finished_at=? WHERE job_id=? AND attempt_number=? AND outcome='RUNNING'",
                (outcome, error_kind, timestamp, job_id, attempt_count),
            )
            return self._job_payload(conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone())

    def recover_worker_jobs(self, *, now: str | None = None) -> dict[str, int]:
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            rows = conn.execute("SELECT job_id, attempt_count, max_attempts, overall_deadline_at FROM worker_jobs WHERE status='CLAIMED' AND lease_expires_at <= ?", (timestamp,)).fetchall()
            requeued = 0
            failed = 0
            for row in rows:
                deadline_expired = row["overall_deadline_at"] is not None and row["overall_deadline_at"] <= timestamp
                terminal = deadline_expired or int(row["attempt_count"]) >= int(row["max_attempts"])
                conn.execute(
                    "UPDATE worker_attempts SET outcome=?, finished_at=? WHERE job_id=? AND attempt_number=? AND outcome='RUNNING'",
                    ("FAILED_PERMANENT" if terminal else "RECLAIMED", timestamp, row["job_id"], row["attempt_count"]),
                )
                if terminal:
                    conn.execute("UPDATE worker_jobs SET status='FAILED_PERMANENT', owner=NULL, lease_expires_at=NULL, last_error_kind=?, updated_at=?, completed_at=? WHERE job_id=?", ("deadline" if deadline_expired else "lease_expired", timestamp, timestamp, row["job_id"]))
                    failed += 1
                else:
                    conn.execute("UPDATE worker_jobs SET status='RETRY_WAIT', owner=NULL, lease_expires_at=NULL, next_attempt_at=?, updated_at=? WHERE job_id=?", (timestamp, timestamp, row["job_id"]))
                    requeued += 1
            return {"requeued": requeued, "failed": failed}

    def list_worker_attempts(self, job_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        self._identifier(job_id, "job_id")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValidationError("worker attempt limit must be between 1 and 500")
        with self.store._read() as conn:
            if conn.execute("SELECT 1 FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone() is None:
                raise NotFoundError("worker job not found")
            return [dict(row) for row in conn.execute("SELECT attempt_id, job_id, attempt_number, owner, stage, started_at, finished_at, outcome, error_kind, effect_receipt_sha256 FROM worker_attempts WHERE job_id=? ORDER BY attempt_number LIMIT ?", (job_id, limit)).fetchall()]

    # ---- Group 4: update manifest and managed APK delivery ----------------

    @staticmethod
    def _channel(value: Any) -> str:
        if not isinstance(value, str) or not CHANNEL_RE.fullmatch(value):
            raise ValidationError("channel must be a bounded identifier")
        return value

    @staticmethod
    def _apk_name(value: Any) -> str:
        if not isinstance(value, str) or not APK_NAME_RE.fullmatch(value) or "/" in value or "\\" in value:
            raise ValidationError("artifact_name must be a single allowlisted APK filename")
        return value

    def _update_payload(self, row: Any, *, current_generation: int | None = None) -> dict[str, Any]:
        try:
            result = json.loads(row["manifest_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ConflictError("stored update manifest is malformed") from exc
        if not isinstance(result, Mapping) or sha256_json(result) != row["manifest_sha256"]:
            raise ConflictError("stored update manifest hash is invalid")
        result = dict(result)
        if (
            result.get("sha256") != row["artifact_sha256"]
            or result.get("size") != row["size"]
            or result.get("artifact_name") != row["artifact_name"]
            or result.get("channel") not in {None, row["channel"]}
            or result.get("generation") not in {None, row["generation"]}
            or result.get("etag", row["etag"]) != row["etag"]
        ):
            raise ConflictError("stored update manifest does not match its receipt")
        result["manifest_sha256"] = row["manifest_sha256"]
        result["etag"] = row["etag"]
        result["channel"] = row["channel"]
        result["generation"] = row["generation"]
        if current_generation is None:
            with self.store._read() as conn:
                current = conn.execute("SELECT current_generation FROM update_channels WHERE channel=?", (row["channel"],)).fetchone()
            current_generation = int(current["current_generation"]) if current else None
        result["current"] = current_generation == int(row["generation"])
        return result

    def publish_update_manifest(
        self,
        *,
        channel: str,
        generation: int,
        platform: str,
        version: str,
        version_code: int,
        artifact_name: str,
        signer_digest: str,
        changelog: str,
        min_server_version: str,
        authorization_policy: str,
        artifact_path: str | os.PathLike[str] | None = None,
        artifact_bytes: bytes | None = None,
        etag: str | None = None,
        expected_generation: int | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        channel = self._channel(channel)
        self._apk_name(artifact_name)
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            raise ValidationError("generation must be a positive integer")
        if platform not in {"phone", "wear"} or not isinstance(version, str) or not version:
            raise ValidationError("platform and version are required")
        if not isinstance(version_code, int) or isinstance(version_code, bool) or version_code < 1:
            raise ValidationError("version_code must be positive")
        if expected_generation is not None and (not isinstance(expected_generation, int) or isinstance(expected_generation, bool) or expected_generation < 0):
            raise ValidationError("expected_generation must be a non-negative integer")
        signer_digest = self._digest(signer_digest, "signer_digest")
        for name, value in (("changelog", changelog), ("min_server_version", min_server_version), ("authorization_policy", authorization_policy)):
            if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > 1024 * 1024:
                raise ValidationError(f"{name} is invalid")
        if (artifact_path is None) == (artifact_bytes is None):
            raise ValidationError("provide exactly one artifact_path or artifact_bytes")
        if artifact_bytes is not None and not isinstance(artifact_bytes, bytes):
            raise ValidationError("artifact_bytes must be bytes")
        if artifact_path is not None:
            source = Path(artifact_path)
            try:
                info = os.lstat(source)
            except OSError as exc:
                raise NotReadyError("update artifact source is unavailable") from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise UnauthorizedError("update artifact source must be a regular non-symlink file")
            content = self._read_source_bytes(source)
        else:
            content = artifact_bytes or b""
        if not content:
            raise ValidationError("update artifact must be non-empty")
        digest = sha256_bytes(content)
        timestamp = self._time(now, self.store)
        requested_etag = etag or f'"{digest}"'
        if not isinstance(requested_etag, str) or not requested_etag or "\r" in requested_etag or "\n" in requested_etag or len(requested_etag) > 256:
            raise ValidationError("etag is invalid")
        manifest = {
            "schema_version": 1,
            "channel": channel,
            "generation": generation,
            "platform": platform,
            "version": version,
            "version_code": version_code,
            "artifact_name": artifact_name,
            "sha256": digest,
            "signer_digest": signer_digest,
            "size": len(content),
            "changelog": changelog,
            "min_server_version": min_server_version,
            "authorization_policy": authorization_policy,
            "content_type": "application/vnd.android.package-archive",
            "download_path": f"/v1/updates/{channel}/{generation}/{artifact_name}",
        }
        manifest["etag"] = requested_etag
        manifest_sha = sha256_json(manifest)
        relpath = Path("updates") / channel / str(generation) / artifact_name
        target = self.store.storage_root / relpath
        self._mkdir_managed_path(self.store.storage_root, target.parent)
        self._ensure_no_symlink_path(self.store.storage_root, target)
        target_existed = target.exists()
        if target_existed:
            existing_bytes = self._read_managed_bytes(self.store.storage_root, target)
            if sha256_bytes(existing_bytes) != digest:
                raise ConflictError("update artifact path already contains different bytes")
        wrote_target = False
        try:
            with self.store._tx() as conn:
                existing = conn.execute("SELECT * FROM update_manifests WHERE channel=? AND generation=?", (channel, generation)).fetchone()
                if existing is not None:
                    if existing["manifest_sha256"] != manifest_sha or existing["artifact_sha256"] != digest:
                        raise ConflictError("update generation is immutable")
                    existing_bytes = self._read_managed_bytes(self.store.storage_root, target)
                    if sha256_bytes(existing_bytes) != existing["artifact_sha256"]:
                        raise ConflictError("immutable update artifact does not match its manifest")
                    current = conn.execute("SELECT current_generation FROM update_channels WHERE channel=?", (channel,)).fetchone()
                    return self._update_payload(existing, current_generation=int(current["current_generation"]) if current else None)
                current = conn.execute("SELECT * FROM update_channels WHERE channel=?", (channel,)).fetchone()
                if current is not None and expected_generation is None:
                    raise ConflictError("update publication requires an expected current generation")
                if expected_generation is not None and ((current is None and expected_generation != 0) or (current is not None and current["current_generation"] != expected_generation)):
                    raise ConflictError("update compare-and-swap generation failed")
                if current is not None and generation <= int(current["current_generation"]):
                    raise ConflictError("update generation must increase monotonically")
                prior_version = conn.execute("SELECT 1 FROM update_manifests WHERE channel=? AND version_code=?", (channel, version_code)).fetchone()
                if prior_version is not None:
                    raise ConflictError("update version_code is already used in this channel")
                if not target_existed:
                    self.store._safe_write(target, content)
                    wrote_target = True
                conn.execute(
                    "INSERT INTO update_manifests(channel, generation, platform, version, version_code, artifact_name, artifact_relpath, artifact_sha256, signer_digest, size, changelog, min_server_version, authorization_policy, etag, manifest_json, manifest_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (channel, generation, platform, version, version_code, artifact_name, relpath.as_posix(), digest, signer_digest, len(content), changelog, min_server_version, authorization_policy, requested_etag, json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")), manifest_sha, timestamp),
                )
                conn.execute(
                    "INSERT INTO update_channels(channel, current_generation, current_manifest_sha256, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(channel) DO UPDATE SET current_generation=excluded.current_generation, current_manifest_sha256=excluded.current_manifest_sha256, updated_at=excluded.updated_at",
                    (channel, generation, manifest_sha, timestamp),
                )
                return self._update_payload(conn.execute("SELECT * FROM update_manifests WHERE channel=? AND generation=?", (channel, generation)).fetchone(), current_generation=generation)
        except Exception:
            if wrote_target:
                try:
                    self._unlink_managed_file(self.store.storage_root, target)
                except (OSError, RecorderError):
                    pass
            raise

    def get_update_manifest(self, channel: str, generation: int | None = None) -> dict[str, Any]:
        channel = self._channel(channel)
        if generation is not None and (not isinstance(generation, int) or isinstance(generation, bool) or generation < 1):
            raise ValidationError("generation must be positive")
        with self.store._read() as conn:
            if generation is None:
                row = conn.execute("SELECT m.* FROM update_manifests m JOIN update_channels c ON c.channel=m.channel AND c.current_generation=m.generation WHERE m.channel=?", (channel,)).fetchone()
            else:
                row = conn.execute("SELECT * FROM update_manifests WHERE channel=? AND generation=?", (channel, generation)).fetchone()
            if row is None:
                raise NotFoundError("update manifest not found")
            current = conn.execute("SELECT current_generation FROM update_channels WHERE channel=?", (channel,)).fetchone()
            return self._update_payload(row, current_generation=int(current["current_generation"]) if current else None)

    @staticmethod
    def _range(value: str, size: int) -> tuple[int, int] | None:
        if not isinstance(value, str) or not value.startswith("bytes=") or "," in value:
            raise ValidationError("only one bytes range is supported")
        spec = value[6:].strip()
        if "-" not in spec:
            raise ValidationError("invalid byte range")
        start_raw, end_raw = spec.split("-", 1)
        try:
            if start_raw == "":
                if not re.fullmatch(r"[0-9]+", end_raw):
                    raise ValueError
                length = int(end_raw)
                if length <= 0:
                    raise ValueError
                start, end = max(0, size - length), size - 1
            else:
                if not re.fullmatch(r"[0-9]+", start_raw) or (end_raw and not re.fullmatch(r"[0-9]+", end_raw)):
                    raise ValueError
                start = int(start_raw)
                end = int(end_raw) if end_raw else size - 1
        except ValueError as exc:
            raise ValidationError("invalid byte range") from exc
        if start < 0 or end < start or start >= size:
            raise RangeNotSatisfiable("requested byte range is unsatisfiable")
        return start, min(end, size - 1)

    def read_update_artifact(
        self,
        channel: str,
        generation: int,
        artifact_name: str,
        *,
        range_header: str | None = None,
        if_range: str | None = None,
        if_none_match: str | None = None,
    ) -> dict[str, Any]:
        channel = self._channel(channel)
        self._apk_name(artifact_name)
        manifest = self.get_update_manifest(channel, generation)
        if manifest["artifact_name"] != artifact_name:
            raise NotFoundError("update artifact is not the manifest artifact")
        with self.store._read() as conn:
            row = conn.execute("SELECT * FROM update_manifests WHERE channel=? AND generation=?", (channel, generation)).fetchone()
            if row is None:
                raise NotFoundError("update manifest not found")
            path = self.store.storage_root / row["artifact_relpath"]
            content = self._read_managed_bytes(self.store.storage_root, path, expected_size=row["size"], expected_sha256=row["artifact_sha256"])
        headers = {
            "Content-Type": "application/vnd.android.package-archive",
            "Content-Length": str(len(content)),
            "ETag": row["etag"],
            "Accept-Ranges": "bytes",
            "Cache-Control": "no-store",
        }
        if if_none_match is not None and (if_none_match.strip() == "*" or row["etag"] in {item.strip() for item in if_none_match.split(",")}):
            headers["Content-Length"] = "0"
            return {"status": 304, "headers": headers, "body": b"", "manifest": manifest}
        selected_range: tuple[int, int] | None = None
        if range_header is not None and (if_range is None or if_range == row["etag"]):
            try:
                selected_range = self._range(range_header, len(content))
            except RangeNotSatisfiable:
                headers["Content-Range"] = f"bytes */{len(content)}"
                headers["Content-Length"] = "0"
                return {"status": 416, "headers": headers, "body": b"", "manifest": manifest}
        if selected_range is None:
            return {"status": 200, "headers": headers, "body": content, "manifest": manifest}
        start, end = selected_range
        body = content[start : end + 1]
        headers["Content-Length"] = str(len(body))
        headers["Content-Range"] = f"bytes {start}-{end}/{len(content)}"
        return {"status": 206, "headers": headers, "body": body, "manifest": manifest}

    # ---- Group 5: project history read model ------------------------------

    @staticmethod
    def _cursor(filters: Mapping[str, Any], accepted_seq: int, turn_id: str) -> str:
        payload = {"v": 1, "filters_sha256": sha256_json(dict(filters)), "accepted_seq": accepted_seq, "turn_id": turn_id}
        return base64.urlsafe_b64encode(canonical_json(payload)).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_cursor(value: str) -> dict[str, Any]:
        if not isinstance(value, str) or len(value) > 4096 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValidationError("cursor is invalid")
        try:
            padded = value + "=" * (-len(value) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        except (ValueError, UnicodeError, binascii.Error, json.JSONDecodeError) as exc:
            raise ValidationError("cursor is invalid") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("v") != 1
            or not isinstance(payload.get("filters_sha256"), str)
            or not DIGEST_RE.fullmatch(payload["filters_sha256"])
            or not isinstance(payload.get("accepted_seq"), int)
            or isinstance(payload.get("accepted_seq"), bool)
            or payload["accepted_seq"] < 0
            or not isinstance(payload.get("turn_id"), str)
            or not FEATURE_ID_RE.fullmatch(payload["turn_id"])
        ):
            raise ValidationError("cursor is invalid")
        return payload

    def _history_item(self, conn: Any, row: Any) -> dict[str, Any]:
        parts: list[dict[str, Any]] = []
        text_values: list[str] = []
        for part in conn.execute(
            "SELECT part_id, kind, mime, declared_bytes, total_bytes, whole_stream_sha256, status, source_path FROM turn_parts WHERE turn_id=? ORDER BY part_id",
            (row["turn_id"],),
        ).fetchall():
            item = {
                "part_id": part["part_id"],
                "kind": part["kind"],
                "mime": part["mime"],
                "byte_length": part["total_bytes"] if part["total_bytes"] is not None else part["declared_bytes"],
                "sha256": part["whole_stream_sha256"],
                "status": part["status"],
            }
            parts.append(item)
            if part["kind"] == "text" and part["status"] == "COMPLETE" and part["source_path"]:
                try:
                    raw = self._read_managed_bytes(self.store.storage_root, Path(part["source_path"]), expected_size=item["byte_length"], expected_sha256=item["sha256"])
                    text_values.append(raw.decode("utf-8"))
                except (UnicodeDecodeError, ConflictError, NotReadyError, UnauthorizedError):
                    pass
        if row["transcript"]:
            input_text = row["transcript"]
            input_type = "audio"
        elif text_values:
            input_text = "\n".join(text_values)
            input_type = "text"
        elif any(part["kind"] == "audio" for part in parts):
            input_text = ""
            input_type = "audio"
        elif parts:
            input_text = ""
            input_type = "attachment" if len(parts) == 1 else "mixed"
        else:
            input_text = ""
            input_type = "unknown"
        assistant = None
        if row["final_content"] is not None or row["final_outcome"] is not None:
            assistant = {
                "role": "assistant",
                "content": row["final_content"],
                "outcome": row["final_outcome"],
                "state": row["state"],
                "event_version": row["final_event_version"],
            }
        user_message = {"role": "user", "content": input_text, "input_type": input_type, "attachments": parts}
        return {
            "turn_id": row["turn_id"],
            "project_id": row["project_id"],
            "accepted_seq": row["accepted_seq"],
            "turn_source": row["turn_source"],
            "archived": row["archived_at"] is not None,
            "state": row["state"],
            "user": user_message,
            "assistant": assistant,
            "messages": [user_message] + ([assistant] if assistant is not None else []),
        }

    def history_read_model(
        self,
        user_id: str,
        *,
        project_id: str | None = None,
        include_archived: bool = False,
        input_type: str | None = None,
        since_seq: int | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        if not isinstance(user_id, str) or not user_id:
            raise ValidationError("user_id is required")
        if project_id is not None:
            self._identifier(project_id, "project_id")
        if not isinstance(include_archived, bool):
            raise ValidationError("include_archived must be boolean")
        if input_type is not None and input_type not in {"audio", "text", "attachment", "mixed", "unknown"}:
            raise ValidationError("unsupported input_type filter")
        if since_seq is not None and (not isinstance(since_seq, int) or isinstance(since_seq, bool) or since_seq < 0):
            raise ValidationError("since_seq must be non-negative")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
            raise ValidationError("history limit must be between 1 and 200")
        filters = {"user_id": user_id, "project_id": project_id, "include_archived": include_archived, "input_type": input_type, "since_seq": since_seq}
        after: tuple[int, str] | None = None
        if cursor is not None:
            decoded = self._decode_cursor(cursor)
            if decoded.get("filters_sha256") != sha256_json(filters):
                raise ConflictError("cursor filters do not match the requested history")
            after = (decoded["accepted_seq"], decoded["turn_id"])
        with self.store._read() as conn:
            scan_after = after
            items: list[dict[str, Any]] = []
            exhausted = False
            while len(items) <= limit and not exhausted:
                clauses = ["user_id=?", "accepted_seq IS NOT NULL"]
                args: list[Any] = [user_id]
                if not include_archived:
                    clauses.append("archived_at IS NULL")
                if project_id is not None:
                    clauses.append("project_id=?")
                    args.append(project_id)
                if since_seq is not None:
                    clauses.append("accepted_seq > ?")
                    args.append(since_seq)
                if scan_after is not None:
                    clauses.append("(accepted_seq > ? OR (accepted_seq=? AND turn_id>?))")
                    args.extend([scan_after[0], scan_after[0], scan_after[1]])
                sql = "SELECT * FROM turns WHERE " + " AND ".join(clauses) + " ORDER BY accepted_seq, turn_id LIMIT ?"
                rows = conn.execute(sql, (*args, max(200, limit + 1))).fetchall()
                if not rows:
                    exhausted = True
                    break
                for row in rows:
                    item = self._history_item(conn, row)
                    if input_type is None or item["user"]["input_type"] == input_type:
                        items.append(item)
                        if len(items) > limit:
                            break
                scan_after = (int(rows[-1]["accepted_seq"]), rows[-1]["turn_id"])
                if len(rows) < max(200, limit + 1) or len(items) > limit:
                    exhausted = True
            has_more = len(items) > limit
            items = items[:limit]
            next_cursor = None
            if has_more and items:
                last = items[-1]
                next_cursor = self._cursor(filters, int(last["accepted_seq"]), last["turn_id"])
            return {"items": items, "next_cursor": next_cursor, "has_more": has_more, "filters_version": 1}

    # ---- Group 6: hash-bound attachment delivery --------------------------

    def attachment_reference(self, turn_id: str, part_id: str) -> str:
        self._identifier(turn_id, "turn_id")
        self._identifier(part_id, "part_id")
        with self.store._read() as conn:
            row = conn.execute("SELECT * FROM turn_parts WHERE turn_id=? AND part_id=?", (turn_id, part_id)).fetchone()
            if row is None:
                raise NotFoundError("attachment part not found")
            if row["status"] != "COMPLETE" or not row["whole_stream_sha256"]:
                raise NotReadyError("attachment part is not complete")
            digest = self._digest(row["whole_stream_sha256"], "attachment hash")
            return f"recorder://v1/turns/{quote(turn_id, safe='')}/parts/{quote(part_id, safe='')}?sha256={digest}"

    def resolve_attachment_reference(self, reference: str) -> dict[str, Any]:
        if not isinstance(reference, str) or len(reference) > 4096:
            raise ValidationError("attachment reference is invalid")
        parsed = urlsplit(reference)
        if parsed.scheme != "recorder" or parsed.netloc != "v1":
            raise UnauthorizedError("attachment reference scheme is not accepted")
        segments = [unquote(value) for value in parsed.path.split("/") if value]
        if len(segments) != 4 or segments[0] != "turns" or segments[2] != "parts":
            raise UnauthorizedError("attachment reference path is invalid")
        turn_id, part_id = segments[1], segments[3]
        query = parse_qs(parsed.query, keep_blank_values=True)
        if set(query) != {"sha256"}:
            raise UnauthorizedError("attachment reference query is not accepted")
        values = query.get("sha256")
        if not values or len(values) != 1:
            raise UnauthorizedError("attachment reference hash is required")
        expected_hash = self._digest(values[0], "attachment hash")
        with self.store._read() as conn:
            row = conn.execute(
                "SELECT t.user_id, p.* FROM turn_parts p JOIN turns t ON t.turn_id=p.turn_id WHERE p.turn_id=? AND p.part_id=?",
                (turn_id, part_id),
            ).fetchone()
            if row is None:
                raise NotFoundError("attachment part not found")
            if row["status"] != "COMPLETE" or not row["source_path"]:
                raise NotReadyError("attachment part is not complete")
            if row["whole_stream_sha256"] != expected_hash:
                raise ConflictError("attachment reference hash does not match the stored receipt")
            body = self._read_managed_bytes(
                self.store.storage_root,
                Path(row["source_path"]),
                expected_size=row["total_bytes"],
                expected_sha256=expected_hash,
            )
            return {
                "reference": reference,
                "turn_id": turn_id,
                "part_id": part_id,
                "mime": row["mime"],
                "byte_length": len(body),
                "sha256": expected_hash,
                "body": body,
            }

    # ---- Group 7: eavesdrop session state machine -------------------------

    def _assert_phone_tx(self, conn: Any, user_id: str, device_id: str) -> None:
        row = conn.execute("SELECT kind, status FROM devices WHERE user_id=? AND device_id=?", (user_id, device_id)).fetchone()
        if row is None or row["status"] != "active" or row["kind"] != "phone":
            raise UnauthorizedError("an active registered Phone is required")

    def _eavesdrop_payload(self, conn: Any, session_id: str) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            raise NotFoundError("eavesdrop session not found")
        result = self._row(row) or {}
        result["response_enabled"] = bool(result["response_enabled"])
        result["tts_enabled"] = bool(result["tts_enabled"])
        result["hermes_enabled"] = bool(result["hermes_enabled"])
        result["routing_mode"] = "FORWARD_DEFAULT" if result["hermes_enabled"] else "STORE_SILENT"
        result["provenance"] = "phone_mediated_watch" if result.get("watch_device_id") else "phone"
        result["segments"] = [
            {"sequence": item["sequence"], "client_segment_id": item["client_segment_id"], "sha256": item["audio_sha256"], "byte_length": item["byte_length"], "transcript": item["transcript"], "status": item["status"], "created_at": item["created_at"]}
            for item in conn.execute("SELECT * FROM eavesdrop_segments WHERE session_id=? ORDER BY sequence", (session_id,)).fetchall()
        ]
        result["replies"] = [
            {"reply_id": item["reply_id"], "segment_sequence": item["segment_sequence"], "text_hash": item["text_hash"], "text": item["reply_text"], "tts_requested": bool(item["tts_requested"]), "hermes_requested": bool(item["hermes_requested"]), "created_at": item["created_at"]}
            for item in conn.execute("SELECT * FROM eavesdrop_replies WHERE session_id=? ORDER BY segment_sequence", (session_id,)).fetchall()
        ]
        result["routing_decisions"] = [
            self._eavesdrop_decision_payload(item)
            for item in conn.execute("SELECT * FROM eavesdrop_decisions WHERE session_id=? ORDER BY segment_sequence", (session_id,)).fetchall()
        ]
        return result

    def start_eavesdrop(
        self,
        user_id: str,
        phone_device_id: str,
        *,
        session_id: str | None = None,
        idempotency_key: str | None = None,
        watch_device_id: str | None = None,
        project_id: str | None = None,
        response_enabled: bool = True,
        tts_enabled: bool = False,
        hermes_enabled: bool = False,
        mode: str | None = None,
        expires_seconds: int = 300,
        now: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(user_id, str) or not user_id:
            raise ValidationError("user_id is required")
        self._identifier(phone_device_id, "phone_device_id")
        if session_id is not None:
            self._identifier(session_id, "session_id")
        if idempotency_key is not None:
            self._identifier(idempotency_key, "idempotency_key")
        if watch_device_id is not None:
            self._identifier(watch_device_id, "watch_device_id")
        if project_id is not None:
            self._identifier(project_id, "project_id")
        if mode is not None:
            if mode not in {"forward_default", "store_silent", "FORWARD_DEFAULT", "STORE_SILENT"}:
                raise ValidationError("eavesdrop mode is invalid")
            hermes_enabled = mode in {"forward_default", "FORWARD_DEFAULT"}
        if not all(isinstance(value, bool) for value in (response_enabled, tts_enabled, hermes_enabled)):
            raise ValidationError("eavesdrop toggles must be boolean")
        if not isinstance(expires_seconds, int) or isinstance(expires_seconds, bool) or not 1 <= expires_seconds <= 86400:
            raise ValidationError("expires_seconds must be between 1 and 86400")
        timestamp = self._time(now, self.store)
        expires = self._plus_seconds(timestamp, expires_seconds)
        if session_id is None:
            session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:eavesdrop:{user_id}:{idempotency_key}")) if idempotency_key else str(uuid.uuid4())
        with self.store._tx() as conn:
            self._assert_phone_tx(conn, user_id, phone_device_id)
            if watch_device_id is not None:
                watch = conn.execute("SELECT kind, status FROM devices WHERE user_id=? AND device_id=?", (user_id, watch_device_id)).fetchone()
                if watch is None or watch["status"] != "active" or watch["kind"] != "watch":
                    raise UnauthorizedError("watch provenance must be an active registered Watch")
            if project_id is not None:
                project = conn.execute("SELECT 1 FROM projects WHERE stable_project_id=? AND user_id=? AND status='active'", (project_id, user_id)).fetchone()
                if project is None:
                    raise NotFoundError("eavesdrop project not found")
            existing = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if existing is not None:
                if existing["user_id"] != user_id or existing["phone_device_id"] != phone_device_id:
                    raise ConflictError("eavesdrop session belongs to another owner")
                immutable_request = (
                    ("watch_device_id", watch_device_id),
                    ("project_id", project_id),
                    ("response_enabled", int(response_enabled)),
                    ("tts_enabled", int(tts_enabled)),
                    ("hermes_enabled", int(hermes_enabled)),
                )
                if any(existing[column] != expected for column, expected in immutable_request):
                    raise ConflictError("eavesdrop session request is immutable")
                if idempotency_key is not None and existing["idempotency_key"] != idempotency_key:
                    raise ConflictError("eavesdrop session idempotency key is immutable")
                return self._eavesdrop_payload(conn, session_id)
            if idempotency_key is not None:
                existing = conn.execute("SELECT * FROM eavesdrop_sessions WHERE idempotency_key=?", (idempotency_key,)).fetchone()
                if existing is not None:
                    immutable_request = (
                        ("user_id", user_id),
                        ("phone_device_id", phone_device_id),
                        ("watch_device_id", watch_device_id),
                        ("project_id", project_id),
                        ("response_enabled", int(response_enabled)),
                        ("tts_enabled", int(tts_enabled)),
                        ("hermes_enabled", int(hermes_enabled)),
                    )
                    if any(existing[column] != expected for column, expected in immutable_request):
                        raise ConflictError("eavesdrop idempotency request is immutable")
                    return self._eavesdrop_payload(conn, existing["session_id"])
            conn.execute(
                "INSERT INTO eavesdrop_sessions(session_id, idempotency_key, user_id, phone_device_id, watch_device_id, project_id, state, response_enabled, tts_enabled, hermes_enabled, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'CREATED', ?, ?, ?, ?, ?, ?)",
                (session_id, idempotency_key, user_id, phone_device_id, watch_device_id, project_id, int(response_enabled), int(tts_enabled), int(hermes_enabled), expires, timestamp, timestamp),
            )
            return self._eavesdrop_payload(conn, session_id)

    def get_eavesdrop_session(self, session_id: str, *, user_id: str | None = None, phone_device_id: str | None = None, now: str | None = None) -> dict[str, Any]:
        self._identifier(session_id, "session_id")
        if (user_id is None) != (phone_device_id is None):
            raise UnauthorizedError("eavesdrop read requires both user and phone owner")
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            row = conn.execute("SELECT state, expires_at FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                raise NotFoundError("eavesdrop session not found")
            if user_id is not None:
                assert phone_device_id is not None
                self._assert_phone_tx(conn, user_id, phone_device_id)
                owner = conn.execute("SELECT user_id, phone_device_id FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
                if owner is None or owner["user_id"] != user_id or owner["phone_device_id"] != phone_device_id:
                    raise UnauthorizedError("eavesdrop session owner mismatch")
            if row["state"] in {"CREATED", "ACTIVE", "PAUSED", "STOPPING"} and row["expires_at"] <= timestamp:
                conn.execute("UPDATE eavesdrop_sessions SET state='EXPIRED', updated_at=?, stopped_at=? WHERE session_id=?", (timestamp, timestamp, session_id))
            return self._eavesdrop_payload(conn, session_id)

    def _transition_eavesdrop(self, session_id: str, user_id: str, phone_device_id: str, allowed: set[str], target: str, *, now: str | None = None) -> dict[str, Any]:
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            self._assert_phone_tx(conn, user_id, phone_device_id)
            row = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                raise NotFoundError("eavesdrop session not found")
            if row["user_id"] != user_id or row["phone_device_id"] != phone_device_id:
                raise UnauthorizedError("eavesdrop session owner mismatch")
            if row["state"] in {"CREATED", "ACTIVE", "PAUSED", "STOPPING"} and row["expires_at"] <= timestamp:
                conn.execute("UPDATE eavesdrop_sessions SET state='EXPIRED', updated_at=?, stopped_at=? WHERE session_id=?", (timestamp, timestamp, session_id))
                return self._eavesdrop_payload(conn, session_id)
            if row["state"] not in allowed and row["state"] != target:
                raise ConflictError(f"eavesdrop state {row['state']} cannot transition to {target}")
            stopped_at = timestamp if target in {"STOPPED", "EXPIRED", "FAILED"} else row["stopped_at"]
            conn.execute("UPDATE eavesdrop_sessions SET state=?, stopped_at=?, updated_at=? WHERE session_id=?", (target, stopped_at, timestamp, session_id))
            return self._eavesdrop_payload(conn, session_id)

    def activate_eavesdrop(self, session_id: str, user_id: str, phone_device_id: str, *, now: str | None = None) -> dict[str, Any]:
        return self._transition_eavesdrop(session_id, user_id, phone_device_id, {"CREATED"}, "ACTIVE", now=now)

    def pause_eavesdrop(self, session_id: str, user_id: str, phone_device_id: str, *, now: str | None = None) -> dict[str, Any]:
        return self._transition_eavesdrop(session_id, user_id, phone_device_id, {"ACTIVE"}, "PAUSED", now=now)

    def resume_eavesdrop(self, session_id: str, user_id: str, phone_device_id: str, *, now: str | None = None) -> dict[str, Any]:
        return self._transition_eavesdrop(session_id, user_id, phone_device_id, {"PAUSED"}, "ACTIVE", now=now)

    def begin_stop_eavesdrop(self, session_id: str, user_id: str, phone_device_id: str, *, now: str | None = None) -> dict[str, Any]:
        return self._transition_eavesdrop(session_id, user_id, phone_device_id, {"CREATED", "ACTIVE", "PAUSED"}, "STOPPING", now=now)

    def stop_eavesdrop(self, session_id: str, user_id: str, phone_device_id: str, *, now: str | None = None) -> dict[str, Any]:
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            self._assert_phone_tx(conn, user_id, phone_device_id)
            row = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                raise NotFoundError("eavesdrop session not found")
            if row["user_id"] != user_id or row["phone_device_id"] != phone_device_id:
                raise UnauthorizedError("eavesdrop session owner mismatch")
            if row["state"] not in {"STOPPED", "EXPIRED", "FAILED"}:
                conn.execute("UPDATE eavesdrop_sessions SET state='STOPPED', stopped_at=?, updated_at=? WHERE session_id=?", (timestamp, timestamp, session_id))
            return self._eavesdrop_payload(conn, session_id)

    def _route_eavesdrop_segment_tx(self, conn: Any, session: Any, segment: Any, *, now: str) -> dict[str, Any]:
        existing = conn.execute("SELECT * FROM eavesdrop_decisions WHERE session_id=? AND segment_sequence=?", (session["session_id"], segment["sequence"])).fetchone()
        if existing is not None:
            return self._eavesdrop_decision_payload(existing)
        project_id = session["project_id"]
        if not bool(session["hermes_enabled"]):
            # The owner-controlled toggle is an authority boundary, not a
            # hint to the policy agent.  A stale or compromised agent must
            # never turn a silent session into an external Hermes effect.
            selection = {
                "outcome": "STORE_SILENT",
                "reason": "hermes_disabled",
                "policy_version": getattr(self.eavesdrop_agent, "policy_version", "eavesdrop-router-v1"),
            }
        else:
            try:
                selection = self.eavesdrop_agent.decide(
                    session=self._row(session) or {},
                    segment=self._row(segment) or {},
                    accumulated_transcript=str(session["accumulated_transcript"] or ""),
                )
            except Exception as exc:
                raise ValidationError("eavesdrop routing decision failed closed") from exc
        if not isinstance(selection, Mapping):
            raise ValidationError("eavesdrop routing decision must be an object")
        decision = selection.get("outcome")
        if decision not in {"FORWARD_DEFAULT", "STORE_SILENT"}:
            raise ValidationError("eavesdrop routing outcome is invalid")
        reason = selection.get("reason", "policy_decision")
        policy_version = selection.get("policy_version", getattr(self.eavesdrop_agent, "policy_version", "eavesdrop-router-v1"))
        if not isinstance(reason, str) or not SAFE_ERROR_RE.fullmatch(reason):
            raise ValidationError("eavesdrop routing reason is invalid")
        if not isinstance(policy_version, str) or not FEATURE_ID_RE.fullmatch(policy_version):
            raise ValidationError("eavesdrop policy version is invalid")
        dedupe_key = f"eavesdrop:{session['session_id']}:{segment['sequence']}"
        result_state = "QUEUED" if decision == "FORWARD_DEFAULT" else "STORED_SILENT"
        if decision == "STORE_SILENT":
            gateway_session_key = submission_id = None
        else:
            gateway_session_key = f"recorder:eavesdrop:{session['session_id']}"
            submission_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:eavesdrop-hermes:{session['session_id']}:{segment['sequence']}"))
            self._enqueue_worker_job_tx(
                conn,
                kind="eavesdrop",
                stage="hermes",
                payload={"session_id": session["session_id"], "segment_sequence": segment["sequence"], "segment_sha256": segment["audio_sha256"]},
                idempotency_key=f"eavesdrop:{session['session_id']}:{segment['sequence']}:hermes",
                max_attempts=3,
                now=now,
                next_attempt_at=now,
                overall_deadline_at=self._plus_seconds(now, 300),
            )
        decision_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:eavesdrop-decision:{session['session_id']}:{segment['sequence']}"))
        conn.execute(
            "INSERT INTO eavesdrop_decisions(decision_id, session_id, segment_sequence, decision, reason, project_id, gateway_session_key, hermes_submission_id, policy_version, covered_start_sequence, covered_end_sequence, dedupe_key, result_state, effect_receipt_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (decision_id, session["session_id"], segment["sequence"], decision, reason, project_id, gateway_session_key, submission_id, policy_version, 0, segment["sequence"], dedupe_key, result_state, None, now),
        )
        return self._eavesdrop_decision_payload(conn.execute("SELECT * FROM eavesdrop_decisions WHERE decision_id=?", (decision_id,)).fetchone())

    def route_eavesdrop_segment(self, session_id: str, user_id: str, phone_device_id: str, *, segment_sequence: int, now: str | None = None) -> dict[str, Any]:
        self._identifier(session_id, "session_id")
        if not isinstance(segment_sequence, int) or isinstance(segment_sequence, bool) or segment_sequence < 0:
            raise ValidationError("segment_sequence must be non-negative")
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            self._assert_phone_tx(conn, user_id, phone_device_id)
            session = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if session is None:
                raise NotFoundError("eavesdrop session not found")
            if session["user_id"] != user_id or session["phone_device_id"] != phone_device_id:
                raise UnauthorizedError("eavesdrop session owner mismatch")
            segment = conn.execute("SELECT * FROM eavesdrop_segments WHERE session_id=? AND sequence=?", (session_id, segment_sequence)).fetchone()
            if segment is None:
                raise NotFoundError("eavesdrop segment not found")
            return self._route_eavesdrop_segment_tx(conn, session, segment, now=timestamp)

    def list_eavesdrop_decisions(self, session_id: str, *, user_id: str | None = None, phone_device_id: str | None = None) -> list[dict[str, Any]]:
        self._identifier(session_id, "session_id")
        if (user_id is None) != (phone_device_id is None):
            raise UnauthorizedError("eavesdrop read requires both user and phone owner")
        with self.store._read() as conn:
            if user_id is not None:
                assert phone_device_id is not None
                self._assert_phone_tx(conn, user_id, phone_device_id)
                owner = conn.execute("SELECT user_id, phone_device_id FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
                if owner is None:
                    raise NotFoundError("eavesdrop session not found")
                if owner["user_id"] != user_id or owner["phone_device_id"] != phone_device_id:
                    raise UnauthorizedError("eavesdrop session owner mismatch")
            return [self._eavesdrop_decision_payload(item) for item in conn.execute("SELECT * FROM eavesdrop_decisions WHERE session_id=? ORDER BY segment_sequence", (session_id,)).fetchall()]

    def mark_eavesdrop_decision(
        self,
        session_id: str,
        segment_sequence: int,
        *,
        decision: str | None = None,
        result_state: str | None = None,
        reason: str,
        effect_receipt: Mapping[str, Any] | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        self._identifier(session_id, "session_id")
        if not isinstance(segment_sequence, int) or isinstance(segment_sequence, bool) or segment_sequence < 0:
            raise ValidationError("eavesdrop segment sequence is invalid")
        legacy_states = {"NO_SPEECH", "DELIVERED", "FAILED"}
        if decision in legacy_states and result_state is None:
            result_state = decision
            decision = None
        if decision is not None and decision not in {"FORWARD_DEFAULT", "STORE_SILENT"}:
            raise ValidationError("eavesdrop outcome is immutable")
        if result_state not in {"QUEUED", "STORED_SILENT", "DELIVERED", "NO_SPEECH", "FAILED"}:
            raise ValidationError("unsupported eavesdrop result state")
        if result_state == "DELIVERED" and effect_receipt is None:
            raise ValidationError("delivered eavesdrop effects require a receipt")
        if not isinstance(reason, str) or not SAFE_ERROR_RE.fullmatch(reason):
            raise ValidationError("eavesdrop decision reason is invalid")
        timestamp = self._time(now, self.store)
        receipt_json = None
        if effect_receipt is not None:
            if not isinstance(effect_receipt, Mapping):
                raise ValidationError("eavesdrop effect receipt must be an object")
            receipt_json = canonical_json(self._safe_eavesdrop_receipt(effect_receipt)).decode("utf-8")
            if len(receipt_json.encode("utf-8")) > 4096:
                raise ValidationError("eavesdrop effect receipt is too large")
        with self.store._tx() as conn:
            row = conn.execute("SELECT * FROM eavesdrop_decisions WHERE session_id=? AND segment_sequence=?", (session_id, segment_sequence)).fetchone()
            if row is None:
                raise NotFoundError("eavesdrop routing decision not found")
            if decision is not None and row["decision"] != decision:
                raise ConflictError("eavesdrop routing outcome is immutable")
            current_state = row["result_state"] if "result_state" in row.keys() else "PENDING"
            if current_state in {"DELIVERED", "NO_SPEECH", "FAILED", "STORED_SILENT"}:
                if current_state != result_state and result_state != "QUEUED":
                    raise ConflictError("eavesdrop result state is immutable")
                return self._eavesdrop_decision_payload(row)
            conn.execute(
                "UPDATE eavesdrop_decisions SET reason=?, result_state=?, effect_receipt_json=? WHERE session_id=? AND segment_sequence=?",
                (reason, result_state, receipt_json, session_id, segment_sequence),
            )
            return self._eavesdrop_decision_payload(conn.execute("SELECT * FROM eavesdrop_decisions WHERE session_id=? AND segment_sequence=?", (session_id, segment_sequence)).fetchone())

    def append_eavesdrop_segment(
        self,
        session_id: str,
        user_id: str,
        phone_device_id: str,
        *,
        sequence: int,
        client_segment_id: str,
        audio: bytes,
        transcript: str | None = None,
        reply_text: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        self._identifier(session_id, "session_id")
        self._identifier(client_segment_id, "client_segment_id")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise ValidationError("segment sequence must be non-negative")
        if not isinstance(audio, bytes) or not audio:
            raise ValidationError("segment audio must be non-empty bytes")
        if len(audio) > getattr(self.store, "max_attachment_bytes", 250 * 1024 * 1024):
            raise ValidationError("segment audio exceeds configured limit")
        if transcript is not None and (not isinstance(transcript, str) or len(transcript) > 100_000):
            raise ValidationError("segment transcript is invalid")
        if reply_text is not None and (not isinstance(reply_text, str) or not reply_text or len(reply_text) > 100_000):
            raise ValidationError("reply_text is invalid")
        timestamp = self._time(now, self.store)
        digest = sha256_bytes(audio)
        with self.store._tx() as conn:
            self._assert_phone_tx(conn, user_id, phone_device_id)
            session = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if session is None:
                raise NotFoundError("eavesdrop session not found")
            if session["user_id"] != user_id or session["phone_device_id"] != phone_device_id:
                raise UnauthorizedError("eavesdrop session owner mismatch")
            if session["state"] in {"CREATED", "PAUSED", "STOPPING", "STOPPED", "EXPIRED", "FAILED"}:
                raise ConflictError("eavesdrop session is not ACTIVE")
            if session["expires_at"] <= timestamp:
                conn.execute("UPDATE eavesdrop_sessions SET state='EXPIRED', stopped_at=?, updated_at=? WHERE session_id=?", (timestamp, timestamp, session_id))
                raise ConflictError("eavesdrop session has expired")
            existing = conn.execute("SELECT * FROM eavesdrop_segments WHERE session_id=? AND (sequence=? OR client_segment_id=?)", (session_id, sequence, client_segment_id)).fetchone()
            if existing is not None:
                if existing["audio_sha256"] != digest or existing["byte_length"] != len(audio):
                    raise ConflictError("eavesdrop segment idempotency key has different bytes")
                if transcript is not None and existing["transcript"] != transcript:
                    raise ConflictError("eavesdrop segment idempotency key has different transcript")
                result = {"duplicate": True, "sequence": existing["sequence"], "sha256": existing["audio_sha256"], "byte_length": existing["byte_length"]}
                return result
            if sequence != session["next_sequence"]:
                raise ConflictError("eavesdrop segments must be submitted in order")
            path = self.store.storage_root / "eavesdrop" / hashlib.sha256(session_id.encode("utf-8")).hexdigest() / f"{sequence:08d}.pcm"
            self._mkdir_managed_path(self.store.storage_root, path.parent)
            self.store._safe_write(path, audio)
            conn.execute(
                "INSERT INTO eavesdrop_segments(session_id, sequence, client_segment_id, audio_sha256, byte_length, storage_path, transcript, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (session_id, sequence, client_segment_id, digest, len(audio), str(path), transcript, timestamp),
            )
            stored_segment = conn.execute("SELECT * FROM eavesdrop_segments WHERE session_id=? AND sequence=?", (session_id, sequence)).fetchone()
            combined = session["accumulated_transcript"]
            if transcript:
                combined = transcript if not combined else f"{combined}\n{transcript}"
            conn.execute("UPDATE eavesdrop_sessions SET accumulated_transcript=?, next_sequence=?, updated_at=? WHERE session_id=?", (combined, sequence + 1, timestamp, session_id))
            updated_session = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if updated_session is None or stored_segment is None:
                raise NotReadyError("eavesdrop session update could not be read back")
            decision = self._route_eavesdrop_segment_tx(conn, updated_session, stored_segment, now=timestamp)

            # Reply text is produced only by the durable Hermes effect.  The
            # legacy argument is accepted for wire compatibility but is never
            # allowed to forge a user-visible assistant response.
            del reply_text
            return {"duplicate": False, "sequence": sequence, "sha256": digest, "byte_length": len(audio), "session_id": session_id}

    def record_eavesdrop_reply(self, session_id: str, *, segment_sequence: int, text: str, now: str | None = None) -> dict[str, Any]:
        self._identifier(session_id, "session_id")
        if not isinstance(segment_sequence, int) or isinstance(segment_sequence, bool) or segment_sequence < 0 or not isinstance(text, str) or not text:
            raise ValidationError("reply sequence and text are required")
        normalized = normalize_hermes_text(text)
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            session = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if session is None:
                raise NotFoundError("eavesdrop session not found")
            if not session["response_enabled"]:
                raise ConflictError("eavesdrop responses are disabled")
            existing = conn.execute("SELECT * FROM eavesdrop_replies WHERE session_id=? AND segment_sequence=?", (session_id, segment_sequence)).fetchone()
            text_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            if existing is not None:
                if existing["text_hash"] != text_hash:
                    raise ConflictError("eavesdrop reply is immutable")
                return self._row(existing) or {}
            reply_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:eavesdrop-reply:{session_id}:{segment_sequence}"))
            conn.execute(
                "INSERT INTO eavesdrop_replies(reply_id, session_id, segment_sequence, text_hash, reply_text, tts_requested, hermes_requested, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (reply_id, session_id, segment_sequence, text_hash, normalized, int(bool(session["tts_enabled"])), int(bool(session["hermes_enabled"])), timestamp),
            )
            return self._row(conn.execute("SELECT * FROM eavesdrop_replies WHERE reply_id=?", (reply_id,)).fetchone()) or {}

    def list_eavesdrop_replies(self, session_id: str, *, user_id: str | None = None, phone_device_id: str | None = None) -> list[dict[str, Any]]:
        self._identifier(session_id, "session_id")
        if (user_id is None) != (phone_device_id is None):
            raise UnauthorizedError("eavesdrop read requires both user and phone owner")
        with self.store._read() as conn:
            if user_id is not None:
                assert phone_device_id is not None
                self._assert_phone_tx(conn, user_id, phone_device_id)
                owner = conn.execute("SELECT user_id, phone_device_id FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
                if owner is None:
                    raise NotFoundError("eavesdrop session not found")
                if owner["user_id"] != user_id or owner["phone_device_id"] != phone_device_id:
                    raise UnauthorizedError("eavesdrop session owner mismatch")
            return [
                {"reply_id": row["reply_id"], "session_id": row["session_id"], "segment_sequence": row["segment_sequence"], "text_hash": row["text_hash"], "text": row["reply_text"], "tts_requested": bool(row["tts_requested"]), "hermes_requested": bool(row["hermes_requested"]), "created_at": row["created_at"]}
                for row in conn.execute("SELECT * FROM eavesdrop_replies WHERE session_id=? ORDER BY segment_sequence", (session_id,)).fetchall()
            ]

    def recover_eavesdrop(self, *, now: str | None = None) -> dict[str, int]:
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            expired = conn.execute("UPDATE eavesdrop_sessions SET state='EXPIRED', stopped_at=?, updated_at=? WHERE state IN ('CREATED','ACTIVE','PAUSED','STOPPING') AND expires_at <= ?", (timestamp, timestamp, timestamp)).rowcount
            return {"expired": expired}

    # ---- Group 8: opt-in redacted diagnostics -----------------------------

    DIAGNOSTIC_KEYS = {
        "category", "stage", "status", "code", "duration_ms", "count", "size_bytes", "hash", "client_version", "turn_id", "project_id", "source", "created_at", "platform", "version", "reason", "event_type"
    }
    DIAGNOSTIC_BANNED = re.compile(r"(?:secret|token|password|authorization|credential|transcript|audio|attachment|private|storage|source_path|file_path|bearer|api[_-]?key)", re.I)

    @classmethod
    def _sanitize_diagnostic_value(cls, key: str, value: Any) -> Any:
        if cls.DIAGNOSTIC_BANNED.search(key):
            return None
        if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
            if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
                return None
            return value
        if isinstance(value, str):
            if len(value) > 1024 or cls.DIAGNOSTIC_BANNED.search(value) or re.search(r"(^|[\s])(?:/|~[/\\]|[A-Za-z]:[\\/])", value):
                return "[REDACTED]"
            return value
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for child_key, child_value in value.items():
                if not isinstance(child_key, str) or cls.DIAGNOSTIC_BANNED.search(child_key):
                    continue
                cleaned = cls._sanitize_diagnostic_value(child_key, child_value)
                if cleaned is not None:
                    result[child_key] = cleaned
            return result
        if isinstance(value, list):
            return [cleaned for item in value[:64] if (cleaned := cls._sanitize_diagnostic_value(key, item)) is not None]
        return None

    @classmethod
    def _sanitize_diagnostic(cls, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ValidationError("diagnostic metadata must be an object")
        result: dict[str, Any] = {}
        for key, value in list(payload.items())[:64]:
            if not isinstance(key, str) or cls.DIAGNOSTIC_BANNED.search(key) or key not in cls.DIAGNOSTIC_KEYS:
                continue
            cleaned = cls._sanitize_diagnostic_value(key, value)
            if cleaned is not None:
                result[key] = cleaned
        encoded = canonical_json(result)
        if len(encoded) > 16 * 1024:
            raise ValidationError("diagnostic metadata exceeds the bounded limit")
        return result

    def _diagnostics_enabled_tx(self, conn: Any, user_id: str, device_id: str, now: str, event_id: str | None = None) -> bool:
        if event_id is not None:
            row = conn.execute("SELECT * FROM diagnostics_consents WHERE event_id=? AND user_id=? AND device_id=?", (event_id, user_id, device_id)).fetchone()
            if row is None or not row["enabled"] or row["revoked_at"] is not None or (row["expires_at"] and row["expires_at"] <= now):
                return False
            return True
        row = conn.execute("SELECT * FROM diagnostics_consents WHERE user_id=? AND device_id=? AND revoked_at IS NULL ORDER BY created_at DESC, event_id DESC LIMIT 1", (user_id, device_id)).fetchone()
        return bool(row is not None and row["enabled"] and (row["expires_at"] is None or row["expires_at"] > now))

    def record_diagnostics_opt_in(
        self,
        user_id: str,
        device_id: str,
        *,
        event_id: str | None = None,
        enabled: bool = True,
        expires_at: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        self._identifier(device_id, "device_id")
        if not isinstance(enabled, bool):
            raise ValidationError("enabled must be boolean")
        event_id = event_id or str(uuid.uuid4())
        self._identifier(event_id, "event_id")
        timestamp = self._time(now, self.store)
        expiry = self._time(expires_at, self.store) if expires_at is not None else None
        with self.store._tx() as conn:
            self.store._assert_device(conn, user_id, device_id)
            existing = conn.execute("SELECT * FROM diagnostics_consents WHERE event_id=?", (event_id,)).fetchone()
            if existing is not None:
                if existing["user_id"] != user_id or existing["device_id"] != device_id or bool(existing["enabled"]) != enabled or existing["expires_at"] != expiry:
                    raise ConflictError("diagnostics consent event is immutable")
                return {"event_id": event_id, "user_id": user_id, "device_id": device_id, "enabled": bool(existing["enabled"]), "created_at": existing["created_at"], "expires_at": existing["expires_at"]}
            conn.execute("INSERT INTO diagnostics_consents(user_id, device_id, event_id, enabled, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)", (user_id, device_id, event_id, int(enabled), timestamp, expiry))
            return {"event_id": event_id, "user_id": user_id, "device_id": device_id, "enabled": enabled, "created_at": timestamp, "expires_at": expiry}

    def ingest_diagnostic_event(
        self,
        user_id: str,
        device_id: str,
        *,
        event_id: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
        occurred_at: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        self._identifier(event_id, "event_id")
        self._identifier(idempotency_key, "idempotency_key")
        metadata = self._sanitize_diagnostic(payload)
        category = metadata.get("category")
        stage = metadata.get("stage")
        if not isinstance(category, str) or not category or not isinstance(stage, str) or not stage:
            raise ValidationError("diagnostic category and stage are required")
        timestamp = self._time(now, self.store)
        occurred = self._time(occurred_at, self.store) if occurred_at is not None else timestamp
        deadline = self._plus_seconds(timestamp, int(getattr(self.store, "diagnostics_retention_seconds", 7 * 86400)))
        metadata_json = json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self.store._tx() as conn:
            self.store._assert_device(conn, user_id, device_id)
            if not self._diagnostics_enabled_tx(conn, user_id, device_id, timestamp):
                raise UnauthorizedError("diagnostics requires an active opt-in")
            existing = conn.execute("SELECT * FROM diagnostic_events WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            if existing is not None:
                if existing["metadata_json"] != metadata_json or existing["user_id"] != user_id or existing["device_id"] != device_id:
                    raise ConflictError("diagnostic event idempotency key has a different payload")
                return {"event_id": existing["event_id"], "category": existing["category"], "stage": existing["stage"], "metadata": json.loads(existing["metadata_json"]), "occurred_at": existing["occurred_at"], "retention_deadline": existing["retention_deadline"]}
            if conn.execute("SELECT 1 FROM diagnostic_events WHERE event_id=?", (event_id,)).fetchone() is not None:
                raise ConflictError("diagnostic event_id is already used")
            conn.execute("INSERT INTO diagnostic_events(event_id, idempotency_key, user_id, device_id, category, stage, metadata_json, occurred_at, retention_deadline) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (event_id, idempotency_key, user_id, device_id, category, stage, metadata_json, occurred, deadline))
            return {"event_id": event_id, "category": category, "stage": stage, "metadata": metadata, "occurred_at": occurred, "retention_deadline": deadline}

    def ingest_diagnostic_bundle(
        self,
        user_id: str,
        device_id: str,
        bundle_id: str,
        compressed: bytes,
        *,
        opt_in_event_id: str,
        expanded_size: int | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        self._identifier(bundle_id, "bundle_id")
        self._identifier(opt_in_event_id, "opt_in_event_id")
        if not isinstance(compressed, bytes) or not compressed:
            raise ValidationError("diagnostic bundle must be non-empty bytes")
        max_compressed = int(getattr(self.store, "diagnostics_max_compressed_bytes", 2 * 1024 * 1024))
        max_expanded = int(getattr(self.store, "diagnostics_max_expanded_bytes", 16 * 1024 * 1024))
        if len(compressed) > max_compressed:
            raise ValidationError("diagnostic compressed size exceeds the bounded limit")
        try:
            decompressor = zlib.decompressobj()
            expanded = decompressor.decompress(compressed, max_expanded + 1)
            expanded += decompressor.flush(max_expanded + 1 - len(expanded))
        except zlib.error as exc:
            raise ValidationError("diagnostic bundle compression is invalid") from exc
        if len(expanded) > max_expanded or decompressor.unconsumed_tail or decompressor.unused_data or not decompressor.eof:
            raise ValidationError("diagnostic expanded size exceeds the bounded limit")
        if expanded_size is not None and (not isinstance(expanded_size, int) or isinstance(expanded_size, bool) or expanded_size != len(expanded)):
            raise ConflictError("diagnostic expanded size does not match the payload")
        try:
            decoded = json.loads(expanded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("diagnostic bundle must contain structured JSON") from exc
        if isinstance(decoded, Mapping):
            if isinstance(decoded.get("events"), list):
                redacted: Any = {"events": [self._sanitize_diagnostic(item) for item in decoded["events"][:64] if isinstance(item, Mapping)]}
            else:
                redacted = self._sanitize_diagnostic(decoded)
        elif isinstance(decoded, list):
            redacted = [self._sanitize_diagnostic(item) for item in decoded[:64] if isinstance(item, Mapping)]
        else:
            raise ValidationError("diagnostic bundle must contain an object or array")
        redacted_expanded = canonical_json(redacted)
        if len(redacted_expanded) > max_expanded:
            raise ValidationError("redacted diagnostic bundle exceeds the bounded limit")
        redacted_compressed = zlib.compress(redacted_expanded, level=6)
        digest = sha256_bytes(redacted_compressed)
        timestamp = self._time(now, self.store)
        deadline = self._plus_seconds(timestamp, int(getattr(self.store, "diagnostics_retention_seconds", 7 * 86400)))
        path = self.store.storage_root / "diagnostics" / hashlib.sha256(user_id.encode("utf-8")).hexdigest() / f"{bundle_id}.z"
        with self.store._tx() as conn:
            self.store._assert_device(conn, user_id, device_id)
            if not self._diagnostics_enabled_tx(conn, user_id, device_id, timestamp, opt_in_event_id):
                raise UnauthorizedError("diagnostic bundle requires the exact active opt-in event")
            existing = conn.execute("SELECT * FROM diagnostic_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
            if existing is not None:
                if existing["payload_sha256"] != digest or existing["user_id"] != user_id or existing["device_id"] != device_id:
                    raise ConflictError("diagnostic bundle is immutable")
                return {"bundle_id": bundle_id, "compressed_size": existing["compressed_size"], "expanded_size": existing["expanded_size"], "payload_sha256": existing["payload_sha256"], "created_at": existing["created_at"], "retention_deadline": existing["retention_deadline"]}
            same_payload = conn.execute("SELECT * FROM diagnostic_bundles WHERE user_id=? AND device_id=? AND payload_sha256=?", (user_id, device_id, digest)).fetchone()
            if same_payload is not None:
                return {"bundle_id": same_payload["bundle_id"], "compressed_size": same_payload["compressed_size"], "expanded_size": same_payload["expanded_size"], "payload_sha256": same_payload["payload_sha256"], "created_at": same_payload["created_at"], "retention_deadline": same_payload["retention_deadline"]}
            self._mkdir_managed_path(self.store.storage_root, path.parent)
            path_existed = path.exists()
            if path_existed and self._read_managed_bytes(self.store.storage_root, path) != redacted_compressed:
                raise ConflictError("diagnostic bundle path already contains different bytes")
            try:
                if not path_existed:
                    self.store._safe_write(path, redacted_compressed)
                conn.execute("INSERT INTO diagnostic_bundles(bundle_id, user_id, device_id, opt_in_event_id, compressed_size, expanded_size, payload_sha256, storage_path, created_at, retention_deadline) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (bundle_id, user_id, device_id, opt_in_event_id, len(redacted_compressed), len(expanded), digest, str(path), timestamp, deadline))
            except Exception:
                if not path_existed and path.exists():
                    try:
                        self._unlink_managed_file(self.store.storage_root, path)
                    except (OSError, RecorderError):
                        pass
                raise
            return {"bundle_id": bundle_id, "compressed_size": len(redacted_compressed), "expanded_size": len(expanded), "payload_sha256": digest, "created_at": timestamp, "retention_deadline": deadline}

    def list_diagnostics(self, user_id: str, device_id: str, *, category: str | None = None, stage: str | None = None, limit: int = 100) -> dict[str, Any]:
        self._identifier(device_id, "device_id")
        if not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValidationError("diagnostic limit must be between 1 and 500")
        with self.store._read() as conn:
            self.store._assert_device(conn, user_id, device_id)
            clauses = ["user_id=?", "device_id=?", "deleted_at IS NULL"]
            args: list[Any] = [user_id, device_id]
            if category is not None:
                clauses.append("category=?")
                args.append(category)
            if stage is not None:
                clauses.append("stage=?")
                args.append(stage)
            events = conn.execute("SELECT * FROM diagnostic_events WHERE " + " AND ".join(clauses) + " ORDER BY occurred_at, event_id LIMIT ?", (*args, limit)).fetchall()
            bundles = conn.execute("SELECT * FROM diagnostic_bundles WHERE user_id=? AND device_id=? AND deleted_at IS NULL ORDER BY created_at, bundle_id LIMIT ?", (user_id, device_id, limit)).fetchall()
            items = [
                {"type": "event", "event_id": row["event_id"], "category": row["category"], "stage": row["stage"], "metadata": json.loads(row["metadata_json"]), "occurred_at": row["occurred_at"], "retention_deadline": row["retention_deadline"]}
                for row in events
            ] + [
                {"type": "bundle", "bundle_id": row["bundle_id"], "compressed_size": row["compressed_size"], "expanded_size": row["expanded_size"], "payload_sha256": row["payload_sha256"], "created_at": row["created_at"], "retention_deadline": row["retention_deadline"]}
                for row in bundles
            ]
            items.sort(key=lambda item: (item.get("occurred_at") or item.get("created_at") or "", item.get("event_id") or item.get("bundle_id") or ""))
            return {"items": items[:limit], "has_more": len(items) > limit or len(events) >= limit or len(bundles) >= limit}

    def export_diagnostics(self, user_id: str, device_id: str) -> dict[str, Any]:
        listing = self.list_diagnostics(user_id, device_id, limit=500)
        with self.store._read() as conn:
            tombstones = [
                {"entity_type": row["entity_type"], "entity_id": row["entity_id"], "deleted_at": row["deleted_at"]}
                for row in conn.execute("SELECT entity_type, entity_id, deleted_at FROM diagnostic_tombstones WHERE user_id=? AND device_id=? ORDER BY deleted_at, entity_id", (user_id, device_id)).fetchall()
            ]
        return {"schema_version": 1, "items": listing["items"], "tombstones": tombstones}

    def delete_diagnostics(self, user_id: str, device_id: str, *, now: str | None = None) -> dict[str, int]:
        self._identifier(device_id, "device_id")
        timestamp = self._time(now, self.store)
        paths: list[Path] = []
        with self.store._tx() as conn:
            self.store._assert_device(conn, user_id, device_id)
            events = conn.execute("SELECT event_id FROM diagnostic_events WHERE user_id=? AND device_id=? AND deleted_at IS NULL", (user_id, device_id)).fetchall()
            bundles = conn.execute("SELECT bundle_id, storage_path FROM diagnostic_bundles WHERE user_id=? AND device_id=? AND deleted_at IS NULL", (user_id, device_id)).fetchall()
            for row in events:
                conn.execute("UPDATE diagnostic_events SET deleted_at=? WHERE event_id=?", (timestamp, row["event_id"]))
                conn.execute("INSERT OR IGNORE INTO diagnostic_tombstones(tombstone_id, user_id, device_id, entity_type, entity_id, deleted_at) VALUES (?, ?, ?, 'event', ?, ?)", (str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:diagnostic-tombstone:event:{row['event_id']}")), user_id, device_id, row["event_id"], timestamp))
            for row in bundles:
                conn.execute("UPDATE diagnostic_bundles SET deleted_at=? WHERE bundle_id=?", (timestamp, row["bundle_id"]))
                conn.execute("INSERT OR IGNORE INTO diagnostic_tombstones(tombstone_id, user_id, device_id, entity_type, entity_id, deleted_at) VALUES (?, ?, ?, 'bundle', ?, ?)", (str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:diagnostic-tombstone:bundle:{row['bundle_id']}")), user_id, device_id, row["bundle_id"], timestamp))
                paths.append(Path(row["storage_path"]))
            conn.execute("UPDATE diagnostics_consents SET revoked_at=? WHERE user_id=? AND device_id=? AND revoked_at IS NULL", (timestamp, user_id, device_id))
        for path in paths:
            try:
                self._unlink_managed_file(self.store.storage_root, path)
            except FileNotFoundError:
                pass
            except (OSError, RecorderError):
                pass
        return {"events": len(events), "bundles": len(bundles), "tombstones": len(events) + len(bundles)}

    def purge_diagnostics(self, *, now: str | None = None) -> dict[str, int]:
        timestamp = self._time(now, self.store)
        paths: list[Path] = []
        with self.store._tx() as conn:
            expired_events = conn.execute("SELECT event_id FROM diagnostic_events WHERE deleted_at IS NULL AND retention_deadline <= ?", (timestamp,)).fetchall()
            expired_bundles = conn.execute("SELECT bundle_id, storage_path FROM diagnostic_bundles WHERE deleted_at IS NULL AND retention_deadline <= ?", (timestamp,)).fetchall()
            for row in expired_events:
                conn.execute("UPDATE diagnostic_events SET deleted_at=? WHERE event_id=?", (timestamp, row["event_id"]))
                conn.execute("INSERT OR IGNORE INTO diagnostic_tombstones(tombstone_id, user_id, device_id, entity_type, entity_id, deleted_at) SELECT ?, user_id, device_id, 'event', event_id, ? FROM diagnostic_events WHERE event_id=?", (str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:diagnostic-tombstone:event:{row['event_id']}")), timestamp, row["event_id"]))
            for row in expired_bundles:
                conn.execute("UPDATE diagnostic_bundles SET deleted_at=? WHERE bundle_id=?", (timestamp, row["bundle_id"]))
                conn.execute("INSERT OR IGNORE INTO diagnostic_tombstones(tombstone_id, user_id, device_id, entity_type, entity_id, deleted_at) SELECT ?, user_id, device_id, 'bundle', bundle_id, ? FROM diagnostic_bundles WHERE bundle_id=?", (str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:diagnostic-tombstone:bundle:{row['bundle_id']}")), timestamp, row["bundle_id"]))
                paths.append(Path(row["storage_path"]))
        for path in paths:
            try:
                self._unlink_managed_file(self.store.storage_root, path)
            except (OSError, RecorderError):
                pass
        return {"events": len(expired_events), "bundles": len(expired_bundles)}


class DurableWorker:
    """Restart-safe worker loop whose handlers must return effect receipts."""

    def __init__(self, store: Any, *, owner: str, handlers: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]]):
        self.store = store
        self.owner = owner
        self.handlers = dict(handlers)

    def run_once(self, *, now: str | None = None, lease_seconds: int = 30) -> dict[str, Any] | None:
        job = self.store.claim_worker_job(self.owner, now=now, lease_seconds=lease_seconds)
        if job is None:
            return None
        handler = self.handlers.get(job["kind"]) or self.handlers.get(job["stage"])
        if handler is None:
            return self.store.fail_worker_job(job["job_id"], self.owner, error_kind="no_handler", retryable=False, now=now)
        try:
            handler_job = dict(job)
            if now is not None:
                handler_job["_worker_now"] = now
            receipt = handler(handler_job)
        except Exception as exc:
            retryable = bool(getattr(exc, "retryable", False))
            kind = str(getattr(exc, "kind", "handler_error"))
            if not SAFE_ERROR_RE.fullmatch(kind):
                kind = "handler_error"
            return self.store.fail_worker_job(job["job_id"], self.owner, error_kind=kind, retryable=retryable, now=now)
        if not isinstance(receipt, Mapping):
            return self.store.fail_worker_job(job["job_id"], self.owner, error_kind="missing_effect_receipt", retryable=False, now=now)
        try:
            return self.store.complete_worker_job(job["job_id"], self.owner, receipt, now=now)
        except (ValidationError, ConflictError):
            return self.store.fail_worker_job(job["job_id"], self.owner, error_kind="invalid_effect_receipt", retryable=False, now=now)

    def run_until_idle(self, *, limit: int = 100, now: str | None = None, lease_seconds: int = 30) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValidationError("worker limit must be between 1 and 500")
        results: list[dict[str, Any]] = []
        for _ in range(limit):
            result = self.run_once(now=now, lease_seconds=lease_seconds)
            if result is None:
                break
            results.append(result)
        return results


# Public aliases make the architecture discoverable without exposing private
# database connection helpers as an API contract.
DurableProcessingWorker = DurableWorker
UpdateManager = FeatureGroups
HistoryReadModel = FeatureGroups
EavesdropManager = FeatureGroups
DiagnosticsManager = FeatureGroups
