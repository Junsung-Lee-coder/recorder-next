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
import errno
import hashlib
import json
import os
import re
import stat
import threading
import uuid
import zlib
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .canonical import canonical_json, hermes_content_hash, normalize_hermes_text, sha256_bytes, sha256_json
from .diagnostics_contract import MetadataValidationError, project_bundle, project_metadata
from .errors import CleanupIncompleteError, ConflictError, LeaseConflict, NotFoundError, NotReadyError, RangeNotSatisfiable, RecorderError, SourceUnavailableError, UnauthorizedError, ValidationError


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
    def _lexical_absolute(path: Path, *, reject_parent: bool = False) -> Path:
        """Normalize lexical dots without resolving symlink components."""

        raw = Path(os.fspath(path))
        if reject_parent and ".." in raw.parts:
            raise UnauthorizedError("managed path contains parent traversal")
        return Path(os.path.abspath(os.fspath(path)))

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
    def _alias_digest(namespace: str, user_id: str, device_id: str, alias: str) -> str:
        parts = (namespace, user_id, device_id, alias)
        payload = b"".join(len(part.encode("utf-8")).to_bytes(8, "big") + part.encode("utf-8") for part in parts)
        return hashlib.sha256(payload).hexdigest()

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

        root = FeatureGroups._lexical_absolute(root)
        path = FeatureGroups._lexical_absolute(path, reject_parent=True)
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
        """Create a managed directory tree with anchored no-follow traversal."""

        root = cls._lexical_absolute(root)
        path = cls._lexical_absolute(path, reject_parent=True)
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise UnauthorizedError("managed directory escapes the storage root") from exc
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_descriptor: int | None = None
        directory_descriptor: int | None = None
        try:
            root_descriptor = os.open(root, directory_flags)
            directory_descriptor = root_descriptor
            for component in relative.parts:
                try:
                    next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
                except FileNotFoundError:
                    try:
                        os.mkdir(component, mode=0o755, dir_fd=directory_descriptor)
                    except FileExistsError:
                        pass
                    next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
                if directory_descriptor != root_descriptor:
                    os.close(directory_descriptor)
                directory_descriptor = next_descriptor
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise UnauthorizedError("managed directory contains a symlink") from exc
            raise NotReadyError("managed directory is unavailable") from exc
        finally:
            if directory_descriptor is not None and directory_descriptor != root_descriptor:
                os.close(directory_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)

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
        root = cls._lexical_absolute(root)
        path = cls._lexical_absolute(path, reject_parent=True)
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

    @classmethod
    def _read_managed_range(
        cls,
        root: Path,
        path: Path,
        *,
        expected_size: int,
        start: int,
        end: int,
    ) -> bytes:
        if any(isinstance(value, bool) or not isinstance(value, int) for value in (expected_size, start, end)) or expected_size < 0 or start < 0 or end < start:
            raise ValidationError("managed artifact range is invalid")
        cls._ensure_no_symlink_path(root, path, allow_missing_leaf=False)
        root = cls._lexical_absolute(root)
        path = cls._lexical_absolute(path, reject_parent=True)
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise UnauthorizedError("managed path escapes the storage root") from exc
        if not relative.parts or end >= expected_size:
            raise ConflictError("managed artifact range is outside its immutable receipt")
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_descriptor: int | None = None
        directory_descriptor: int | None = None
        descriptor: int | None = None
        try:
            root_descriptor = os.open(root, directory_flags)
            directory_descriptor = root_descriptor
            for component in relative.parts[:-1]:
                next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
                if directory_descriptor != root_descriptor:
                    os.close(directory_descriptor)
                directory_descriptor = next_descriptor
            descriptor = os.open(relative.parts[-1], file_flags, dir_fd=directory_descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
                raise ConflictError("managed artifact size does not match its immutable receipt")
            remaining = end - start + 1
            chunks: list[bytes] = []
            offset = start
            while remaining:
                chunk = os.pread(descriptor, min(1024 * 1024, remaining), offset)
                if not chunk:
                    raise ConflictError("managed artifact changed while reading its range")
                chunks.append(chunk)
                offset += len(chunk)
                remaining -= len(chunk)
            if os.fstat(descriptor).st_size != expected_size:
                raise ConflictError("managed artifact changed while reading its range")
            return b"".join(chunks)
        except OSError as exc:
            raise NotReadyError("managed artifact is unavailable") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory_descriptor is not None and directory_descriptor != root_descriptor:
                os.close(directory_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)

    @staticmethod
    def _read_source_bytes(path: Path) -> bytes:
        path = FeatureGroups._lexical_absolute(path, reject_parent=True)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_descriptor: int | None = None
        directory_descriptor: int | None = None
        descriptor: int | None = None
        try:
            root_descriptor = os.open(Path(path.anchor or "/"), directory_flags)
            directory_descriptor = root_descriptor
            for component in path.parent.parts[1:]:
                next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
                if directory_descriptor != root_descriptor:
                    os.close(directory_descriptor)
                directory_descriptor = next_descriptor
            descriptor = os.open(path.name, file_flags, dir_fd=directory_descriptor)
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            if directory_descriptor is not None and directory_descriptor != root_descriptor:
                os.close(directory_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise UnauthorizedError("update artifact source contains a symlink") from exc
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
            if descriptor is not None:
                os.close(descriptor)
            if directory_descriptor is not None and directory_descriptor != root_descriptor:
                os.close(directory_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)

    @classmethod
    def _unlink_managed_file(cls, root: Path, path: Path) -> None:
        """Unlink a managed leaf without following a swapped parent."""

        cls._ensure_no_symlink_path(root, path, allow_missing_leaf=True)
        root = cls._lexical_absolute(root)
        path = cls._lexical_absolute(path, reject_parent=True)
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

    @classmethod
    def _managed_file_state(cls, root: Path, path: Path) -> tuple[str, str | None]:
        """Inspect a managed path without following symlink components."""

        root = cls._lexical_absolute(root)
        path = cls._lexical_absolute(path, reject_parent=True)
        try:
            relative = path.relative_to(root)
        except ValueError:
            return "blocked", "cleanup path escapes the storage root"
        if not relative.parts:
            return "blocked", "cleanup path names the storage root"
        current = root
        for index, component in enumerate(relative.parts):
            current = current / component
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                return "missing", None
            except OSError as exc:
                return "error", f"{type(exc).__name__}: {str(exc)[:160]}"
            if stat.S_ISLNK(info.st_mode):
                return "blocked", "cleanup path contains a symlink"
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
                return "blocked", "cleanup path contains a non-directory component"
            if index == len(relative.parts) - 1 and not stat.S_ISREG(info.st_mode):
                return "blocked", "cleanup target is not a regular file"
        return "present", None

    def _cleanup_reference_state(self, receipt: Mapping[str, Any]) -> str:
        """Return whether a rollback receipt now owns a durable row."""

        if not str(receipt["operation"]).endswith("_rollback"):
            return "unowned"
        target = self._lexical_absolute(Path(receipt["storage_path"]), reject_parent=True)
        expected_digest = str(receipt["expected_sha256"]).lower()
        expected_size = int(receipt["expected_size"])
        references: list[tuple[str, str, str, int | None]] = []

        def canonical_reference(value: Any, *, relative: bool = False) -> Path | None:
            try:
                raw = self.store.storage_root / str(value) if relative else Path(str(value))
                return self._lexical_absolute(raw, reject_parent=True)
            except (TypeError, UnauthorizedError, ValueError):
                return None

        with self.store._read() as conn:
            for row in conn.execute("SELECT storage_path, sha256, byte_length FROM turn_chunks").fetchall():
                if canonical_reference(row["storage_path"]) == target:
                    references.append((str(row["storage_path"]), str(row["sha256"]), "turn_chunk", row["byte_length"]))
            for row in conn.execute("SELECT storage_path, payload_sha256, compressed_size FROM diagnostic_bundles").fetchall():
                if canonical_reference(row["storage_path"]) == target:
                    references.append((str(row["storage_path"]), str(row["payload_sha256"]), "diagnostic_bundle", row["compressed_size"]))
            for row in conn.execute("SELECT artifact_relpath, artifact_sha256, size FROM update_manifests").fetchall():
                candidate = canonical_reference(row["artifact_relpath"], relative=True)
                if candidate is not None and candidate == target:
                    references.append((str(candidate), str(row["artifact_sha256"]), "update_manifest", row["size"]))
            for row in conn.execute("SELECT source_path, whole_stream_sha256, total_bytes FROM turn_parts WHERE source_path IS NOT NULL").fetchall():
                if canonical_reference(row["source_path"]) == target:
                    references.append((str(row["source_path"]), str(row["whole_stream_sha256"]), "turn_part", row["total_bytes"]))
            tts_rows = conn.execute("SELECT artifact_id, storage_path, payload_sha256, byte_size FROM tts_artifacts WHERE storage_path IS NOT NULL").fetchall()
            for row in tts_rows:
                if receipt.get("entity_type") == "tts_artifact" and receipt.get("entity_id") == row["artifact_id"]:
                    continue
                if canonical_reference(row["storage_path"]) == target:
                    references.append((str(row["storage_path"]), str(row["payload_sha256"]), "tts_artifact", row["byte_size"]))
            for row in conn.execute("SELECT storage_path, audio_sha256, byte_length FROM eavesdrop_segments").fetchall():
                if canonical_reference(row["storage_path"]) == target:
                    references.append((str(row["storage_path"]), str(row["audio_sha256"]), "eavesdrop_segment", row["byte_length"]))
        for _path, digest, _kind, size in references:
            if digest.lower() == expected_digest and size is not None and int(size) == expected_size:
                return "owned"
            return "conflict"
        return "unowned"

    @staticmethod
    def _cleanup_error(exc: BaseException) -> str:
        detail = str(exc).replace("\n", " ")[:160]
        return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__

    def _mark_cleanup_receipt_attempt(self, receipt_id: str, *, status: str, error: str, now: str) -> None:
        with self.store._tx() as conn:
            conn.execute(
                "UPDATE storage_cleanup_receipts SET status=?, attempt_count=attempt_count+1, last_error=?, updated_at=?, completed_at=NULL WHERE receipt_id=? AND status IN ('PENDING', 'BLOCKED')",
                (status, error, now, receipt_id),
            )

    def recover_cleanup_receipts(
        self,
        *,
        receipt_ids: list[str] | None = None,
        now: str | None = None,
    ) -> dict[str, int]:
        timestamp = self._time(now, self.store)
        if receipt_ids is not None and not receipt_ids:
            return {"attempted": 0, "completed": 0, "pending": 0, "blocked": 0}
        with self.store._read() as conn:
            if receipt_ids is None:
                rows = conn.execute("SELECT * FROM storage_cleanup_receipts WHERE status IN ('PENDING', 'BLOCKED') ORDER BY created_at, receipt_id").fetchall()
            else:
                placeholders = ",".join("?" for _ in receipt_ids)
                rows = conn.execute(
                    f"SELECT * FROM storage_cleanup_receipts WHERE status IN ('PENDING', 'BLOCKED') AND receipt_id IN ({placeholders}) ORDER BY created_at, receipt_id",
                    tuple(receipt_ids),
                ).fetchall()
        attempted = completed = blocked = 0
        for row in rows:
            attempted += 1
            reference_state = self._cleanup_reference_state(row)
            if reference_state == "owned":
                self.store._complete_cleanup_receipt(row["receipt_id"], now=timestamp)
                completed += 1
                continue
            if reference_state == "conflict":
                self._mark_cleanup_receipt_attempt(row["receipt_id"], status="BLOCKED", error="cleanup target is referenced by a different durable artifact", now=timestamp)
                blocked += 1
                continue
            path = Path(row["storage_path"])
            state, detail = self._managed_file_state(self.store.storage_root, path)
            if state == "missing":
                self.store._complete_cleanup_receipt(row["receipt_id"], now=timestamp)
                completed += 1
                continue
            if state == "blocked":
                self._mark_cleanup_receipt_attempt(row["receipt_id"], status="BLOCKED", error=detail or "cleanup target is unsafe", now=timestamp)
                blocked += 1
                continue
            if state == "error":
                self._mark_cleanup_receipt_attempt(row["receipt_id"], status="PENDING", error=detail or "cleanup target cannot be inspected", now=timestamp)
                continue
            try:
                self._read_managed_bytes(
                    self.store.storage_root,
                    path,
                    expected_size=int(row["expected_size"]),
                    expected_sha256=str(row["expected_sha256"]),
                )
            except ConflictError as exc:
                self._mark_cleanup_receipt_attempt(row["receipt_id"], status="BLOCKED", error=self._cleanup_error(exc), now=timestamp)
                blocked += 1
                continue
            except (OSError, RecorderError) as exc:
                self._mark_cleanup_receipt_attempt(row["receipt_id"], status="PENDING", error=self._cleanup_error(exc), now=timestamp)
                continue
            try:
                self._unlink_managed_file(self.store.storage_root, path)
            except FileNotFoundError:
                self.store._complete_cleanup_receipt(row["receipt_id"], now=timestamp)
                completed += 1
            except (OSError, RecorderError) as exc:
                self._mark_cleanup_receipt_attempt(row["receipt_id"], status="PENDING", error=self._cleanup_error(exc), now=timestamp)
            else:
                self.store._complete_cleanup_receipt(row["receipt_id"], now=timestamp)
                completed += 1
        with self.store._read() as conn:
            if receipt_ids is None:
                pending_row = conn.execute("SELECT COUNT(*) AS count FROM storage_cleanup_receipts WHERE status='PENDING'").fetchone()
                blocked_row = conn.execute("SELECT COUNT(*) AS count FROM storage_cleanup_receipts WHERE status='BLOCKED'").fetchone()
            else:
                placeholders = ",".join("?" for _ in receipt_ids)
                pending_row = conn.execute(f"SELECT COUNT(*) AS count FROM storage_cleanup_receipts WHERE status='PENDING' AND receipt_id IN ({placeholders})", tuple(receipt_ids)).fetchone()
                blocked_row = conn.execute(f"SELECT COUNT(*) AS count FROM storage_cleanup_receipts WHERE status='BLOCKED' AND receipt_id IN ({placeholders})", tuple(receipt_ids)).fetchone()
        return {
            "attempted": attempted,
            "completed": completed,
            "pending": int(pending_row["count"]),
            "blocked": int(blocked_row["count"]),
        }

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

    def _project_terminal_tts_artifact_tx(self, conn: Any, job: Any, *, error_kind: str, now: str) -> bool:
        """Terminalize an unstarted TTS artifact with its worker job."""
        if job["stage"] != "tts":
            return False
        try:
            payload = json.loads(job["payload_json"])
        except (TypeError, json.JSONDecodeError):
            return False
        if not isinstance(payload, Mapping):
            return False
        artifact_id = payload.get("artifact_id")
        turn_id = payload.get("turn_id")
        if not isinstance(artifact_id, str) or not FEATURE_ID_RE.fullmatch(artifact_id):
            return False
        if turn_id is not None and not isinstance(turn_id, str):
            return False
        artifact = conn.execute(
            "SELECT turn_id, status FROM tts_artifacts WHERE artifact_id=?",
            (artifact_id,),
        ).fetchone()
        if artifact is None or artifact["status"] != "PENDING":
            return False
        if turn_id is not None and artifact["turn_id"] != turn_id:
            return False
        safe_error = error_kind if isinstance(error_kind, str) and SAFE_ERROR_RE.fullmatch(error_kind) else "worker_terminal"
        changed = conn.execute(
            "UPDATE tts_artifacts SET source_text=NULL, status='EXPIRED', relay_state='EXPIRED', retention_outcome='expired', provider_metadata_json=?, updated_at=? WHERE artifact_id=? AND status='PENDING'",
            (json.dumps({"error_kind": safe_error}, separators=(",", ":")), now, artifact_id),
        ).rowcount
        return bool(changed)

    def _project_terminal_job_tx(self, conn: Any, job: Any, *, error_kind: str, now: str) -> bool:
        """Project terminal worker state into its owning protocol queue."""
        if job["stage"] == "tts":
            return self._project_terminal_tts_artifact_tx(conn, job, error_kind=error_kind, now=now)
        try:
            payload = json.loads(job["payload_json"])
        except (TypeError, json.JSONDecodeError):
            return False
        if not isinstance(payload, Mapping):
            return False
        if job["kind"] == "eavesdrop" or ("segment_sequence" in payload and "session_id" in payload):
            changed = conn.execute(
                "UPDATE eavesdrop_decisions SET result_state='FAILED', reason=?, effect_receipt_json=NULL WHERE session_id=? AND segment_sequence=? AND result_state IN ('QUEUED','IN_PROGRESS','PENDING')",
                ("worker_terminal", payload.get("session_id"), payload.get("segment_sequence")),
            ).rowcount
            return bool(changed)
        turn_id = payload.get("turn_id")
        if not isinstance(turn_id, str):
            return False
        turn = conn.execute("SELECT * FROM turns WHERE turn_id=?", (turn_id,)).fetchone()
        if turn is None or turn["final_outcome"] is not None or job["kind"] == "hermes_history":
            return False
        if job["stage"] == "hermes":
            self.store._commit_protocol_final_tx(
                conn,
                turn_id=turn_id,
                error_kind="hermes",
                message="요청 처리가 지연되고 있습니다. 잠시 후 프로젝트 세션에서 다시 확인해 주세요.",
                grace_seconds=30,
                source_ref=f"recorder_protocol:hermes:worker:{job['job_id']}",
            )
            ingress = conn.execute("SELECT hermes_submission_id, target_session_id FROM session_ingress WHERE turn_id=?", (turn_id,)).fetchone()
            if ingress is not None:
                conn.execute(
                    "UPDATE session_ingress SET status='FAILED', lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL, updated_at=? WHERE hermes_submission_id=?",
                    (now, ingress["hermes_submission_id"]),
                )
                self._enqueue_worker_job_tx(
                    conn,
                    kind="hermes_history",
                    stage="hermes",
                    payload={"session_id": ingress["target_session_id"], "turn_id": turn_id, "hermes_submission_id": ingress["hermes_submission_id"]},
                    idempotency_key=f"hermes-history:{ingress['hermes_submission_id']}",
                    max_attempts=100,
                    now=now,
                    next_attempt_at=now,
                    overall_deadline_at=self._plus_seconds(now, 30),
                )
            return True
        protocol_kind = "asr" if job["stage"] == "asr" else "routing"
        self.store._commit_protocol_final_tx(
            conn,
            turn_id=turn_id,
            error_kind=protocol_kind,
            message=("음성을 인식하지 못했습니다. 원본은 보존되어 다시 시도할 수 있습니다." if protocol_kind == "asr" else "요청을 처리할 프로젝트를 결정하지 못했습니다."),
            grace_seconds=0,
            source_ref=f"recorder_protocol:{protocol_kind}:worker:{job['job_id']}",
        )
        if protocol_kind == "asr":
            conn.execute("UPDATE turns SET authoritative_asr_outcome='PROVIDER_ERROR', state='FINAL_READY', updated_at=? WHERE turn_id=?", (now, turn_id))
        conn.execute(
            "UPDATE router_queue SET state='FAILED', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE turn_id=? AND state IN ('QUEUED','IN_PROGRESS')",
            (now, turn_id),
        )
        return True

    def reconcile_terminal_tts_jobs(self, *, now: str | None = None, limit: int = 500) -> dict[str, int]:
        """Repair terminal TTS worker rows left by an older worker version."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValidationError("terminal TTS reconciliation limit must be between 1 and 1000")
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            rows = conn.execute(
                "SELECT j.* FROM worker_jobs j WHERE j.stage='tts' AND j.status='FAILED_PERMANENT' AND EXISTS (SELECT 1 FROM tts_artifacts a WHERE a.status='PENDING' AND a.artifact_id=json_extract(CASE WHEN json_valid(j.payload_json) THEN j.payload_json ELSE '{}' END, '$.artifact_id')) ORDER BY j.completed_at, j.created_at, j.job_id LIMIT ?",
                (limit,),
            ).fetchall()
            expired = 0
            for row in rows:
                error_kind = row["last_error_kind"] or "worker_terminal"
                if self._project_terminal_tts_artifact_tx(conn, row, error_kind=error_kind, now=timestamp):
                    expired += 1
            return {"jobs_scanned": len(rows), "artifacts_expired": expired}

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
        worker_claim: Mapping[str, Any] | None = None,
        worker_stage: str | None = None,
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
            if worker_claim is not None:
                claim_turn_id = payload.get("turn_id") if isinstance(payload, Mapping) else None
                claim_stage = worker_stage or stage
                if not self._assert_worker_effect_tx(conn, worker_claim, now=timestamp, stage=claim_stage, turn_id=claim_turn_id if isinstance(claim_turn_id, str) else None):
                    raise LeaseConflict("worker enqueue effect deadline has expired")
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
            expired_jobs = conn.execute(
                "SELECT * FROM worker_jobs WHERE status IN ('PENDING','RETRY_WAIT','CLAIMED') AND overall_deadline_at IS NOT NULL AND overall_deadline_at <= ? ORDER BY overall_deadline_at, created_at, job_id",
                (timestamp,),
            ).fetchall()
            for expired_job in expired_jobs:
                changed = conn.execute(
                    "UPDATE worker_jobs SET status='FAILED_PERMANENT', owner=NULL, lease_token=NULL, lease_expires_at=NULL, last_error_kind='deadline', updated_at=?, completed_at=? WHERE job_id=? AND status IN ('PENDING','RETRY_WAIT','CLAIMED') AND overall_deadline_at IS NOT NULL AND overall_deadline_at <= ?",
                    (timestamp, timestamp, expired_job["job_id"], timestamp),
                ).rowcount
                if changed:
                    conn.execute(
                        "UPDATE worker_attempts SET outcome='FAILED_PERMANENT', error_kind='deadline', finished_at=? WHERE job_id=? AND outcome='RUNNING'",
                        (timestamp, expired_job["job_id"]),
                    )
                    self._project_terminal_job_tx(conn, expired_job, error_kind="deadline", now=timestamp)
            expired_tts = conn.execute(
                "SELECT j.* FROM worker_jobs j WHERE j.stage='tts' AND j.status IN ('PENDING','RETRY_WAIT','CLAIMED') AND EXISTS (SELECT 1 FROM tts_artifacts a WHERE a.artifact_id=json_extract(CASE WHEN json_valid(j.payload_json) THEN j.payload_json ELSE '{}' END, '$.artifact_id') AND (a.status='EXPIRED' OR (a.expires_at IS NOT NULL AND a.expires_at <= ?)))",
                (timestamp,),
            ).fetchall()
            for expired_job in expired_tts:
                changed = conn.execute(
                    "UPDATE worker_jobs SET status='FAILED_PERMANENT', owner=NULL, lease_token=NULL, lease_expires_at=NULL, last_error_kind='deadline', updated_at=?, completed_at=? WHERE job_id=? AND status IN ('PENDING','RETRY_WAIT','CLAIMED')",
                    (timestamp, timestamp, expired_job["job_id"]),
                ).rowcount
                if changed:
                    conn.execute(
                        "UPDATE worker_attempts SET outcome='FAILED_PERMANENT', error_kind='deadline', finished_at=? WHERE job_id=? AND outcome='RUNNING'",
                        (timestamp, expired_job["job_id"]),
                    )
                    self._project_terminal_job_tx(conn, expired_job, error_kind="deadline", now=timestamp)
            exhausted_jobs = conn.execute(
                "SELECT * FROM worker_jobs WHERE ((status IN ('PENDING','RETRY_WAIT') AND next_attempt_at <= ?) OR (status='CLAIMED' AND lease_expires_at <= ?)) AND (overall_deadline_at IS NULL OR overall_deadline_at > ?) AND attempt_count >= max_attempts ORDER BY next_attempt_at, created_at, job_id",
                (timestamp, timestamp, timestamp),
            ).fetchall()
            for exhausted_job in exhausted_jobs:
                changed = conn.execute(
                    "UPDATE worker_jobs SET status='FAILED_PERMANENT', owner=NULL, lease_token=NULL, lease_expires_at=NULL, last_error_kind='max_attempts', updated_at=?, completed_at=? WHERE job_id=? AND status IN ('PENDING','RETRY_WAIT','CLAIMED') AND attempt_count >= max_attempts",
                    (timestamp, timestamp, exhausted_job["job_id"]),
                ).rowcount
                if changed:
                    conn.execute(
                        "UPDATE worker_attempts SET outcome='FAILED_PERMANENT', error_kind='max_attempts', finished_at=? WHERE job_id=? AND outcome='RUNNING'",
                        (timestamp, exhausted_job["job_id"]),
                    )
                    self._project_terminal_job_tx(conn, exhausted_job, error_kind="max_attempts", now=timestamp)
            row = conn.execute(
                "SELECT * FROM worker_jobs WHERE ((status IN ('PENDING','RETRY_WAIT') AND next_attempt_at <= ?) OR (status='CLAIMED' AND lease_expires_at <= ?)) AND (overall_deadline_at IS NULL OR overall_deadline_at > ?) AND attempt_count < max_attempts ORDER BY next_attempt_at, created_at, job_id LIMIT 1",
                (timestamp, timestamp, timestamp),
            ).fetchone()
            if row is None:
                return None
            attempt = int(row["attempt_count"]) + 1
            attempt_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:worker-attempt:{row['job_id']}:{attempt}"))
            lease_token = attempt_id
            changed = conn.execute(
                "UPDATE worker_jobs SET status='CLAIMED', owner=?, lease_token=?, lease_expires_at=?, attempt_count=?, updated_at=? WHERE job_id=? AND ((status IN ('PENDING','RETRY_WAIT') AND next_attempt_at <= ?) OR (status='CLAIMED' AND lease_expires_at <= ?)) AND (overall_deadline_at IS NULL OR overall_deadline_at > ?) AND attempt_count < max_attempts",
                (owner, attempt_id, expires, attempt, timestamp, row["job_id"], timestamp, timestamp, timestamp),
            ).rowcount
            if changed != 1:
                return None
            if row["status"] == "CLAIMED":
                conn.execute(
                    "UPDATE worker_attempts SET outcome='RECLAIMED', finished_at=? WHERE job_id=? AND outcome='RUNNING'",
                    (timestamp, row["job_id"]),
                )
            conn.execute(
                "INSERT OR REPLACE INTO worker_attempts(attempt_id, job_id, attempt_number, owner, lease_token, stage, started_at, outcome) VALUES (?, ?, ?, ?, ?, ?, ?, 'RUNNING')",
                (attempt_id, row["job_id"], attempt, owner, lease_token, row["stage"], timestamp),
            )
            return self._job_payload(conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (row["job_id"],)).fetchone())

    def renew_worker_lease(self, job_id: str, owner: str, *, lease_token: str, now: str | None = None, lease_seconds: int = 30) -> bool:
        self._identifier(job_id, "job_id")
        self._identifier(owner, "owner")
        self._identifier(lease_token, "lease_token")
        if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 86400:
            raise ValidationError("worker lease_seconds must be between 1 and 86400")
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            row = conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None or row["status"] != "CLAIMED" or row["owner"] != owner or row["lease_token"] != lease_token:
                return False
            if row["overall_deadline_at"] is not None and row["overall_deadline_at"] <= timestamp:
                self._terminalize_claimed_deadline_tx(conn, row, timestamp)
                return False
            if not row["lease_expires_at"] or row["lease_expires_at"] <= timestamp:
                return False
            expires = self._plus_seconds(timestamp, lease_seconds)
            if row["overall_deadline_at"] is not None and expires > row["overall_deadline_at"]:
                expires = row["overall_deadline_at"]
            return bool(conn.execute("UPDATE worker_jobs SET lease_expires_at=?, updated_at=? WHERE job_id=? AND status='CLAIMED' AND owner=? AND lease_token=? AND lease_expires_at > ? AND (overall_deadline_at IS NULL OR overall_deadline_at > ?)", (expires, timestamp, job_id, owner, lease_token, timestamp, timestamp)).rowcount)

    def _terminalize_claimed_deadline_tx(self, conn: Any, row: Any, timestamp: str) -> None:
        changed = conn.execute(
            "UPDATE worker_jobs SET status='FAILED_PERMANENT', owner=NULL, lease_token=NULL, lease_expires_at=NULL, last_error_kind='deadline', updated_at=?, completed_at=? WHERE job_id=? AND status='CLAIMED' AND owner IS NOT NULL",
            (timestamp, timestamp, row["job_id"]),
        ).rowcount
        if changed:
            conn.execute("UPDATE worker_attempts SET outcome='FAILED_PERMANENT', error_kind='deadline', finished_at=? WHERE job_id=? AND outcome='RUNNING'", (timestamp, row["job_id"]))
            self._project_terminal_job_tx(conn, row, error_kind="deadline", now=timestamp)

    def _assert_worker_claim(self, conn: Any, job_id: str, owner: str, lease_token: str, now: str) -> Any:
        self._identifier(lease_token, "lease_token")
        row = conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise NotFoundError("worker job not found")
        if row["status"] != "CLAIMED" or row["owner"] != owner or row["lease_token"] != lease_token or not row["lease_expires_at"] or row["lease_expires_at"] <= now:
            raise LeaseConflict("worker job lease is not owned or has expired")
        return row

    def _assert_worker_effect_tx(self, conn: Any, claim: Mapping[str, Any], *, now: str, stage: str | None = None, turn_id: str | None = None) -> bool:
        """Fence every durable worker effect with the live claim and deadline."""
        if not isinstance(claim, Mapping):
            raise LeaseConflict("worker effect claim is missing")
        job_id = claim.get("job_id")
        owner = claim.get("_worker_owner", claim.get("owner"))
        lease_token = claim.get("lease_token")
        if not all(isinstance(value, str) and value for value in (job_id, owner, lease_token)):
            raise LeaseConflict("worker effect claim is incomplete")
        row = self._assert_worker_claim(conn, job_id, owner, lease_token, now)
        if stage is not None and row["stage"] != stage:
            raise LeaseConflict("worker effect stage does not match the claim")
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError):
            raise LeaseConflict("worker effect payload is invalid") from None
        if turn_id is not None and (not isinstance(payload, Mapping) or payload.get("turn_id") != turn_id):
            raise LeaseConflict("worker effect turn does not match the claim")
        if row["overall_deadline_at"] is not None and row["overall_deadline_at"] <= now:
            self._terminalize_claimed_deadline_tx(conn, row, now)
            return False
        return True

    def assert_worker_effect_authority(self, claim: Mapping[str, Any], *, stage: str | None = None, turn_id: str | None = None, now: str | None = None) -> bool:
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            return self._assert_worker_effect_tx(conn, claim, now=timestamp, stage=stage, turn_id=turn_id)

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
        if "count" in receipt and (not isinstance(receipt["count"], int) or isinstance(receipt["count"], bool) or not 0 <= receipt["count"] <= 1_000_000):
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

    def complete_worker_job(self, job_id: str, owner: str, receipt: Mapping[str, Any], *, lease_token: str, now: str | None = None) -> dict[str, Any]:
        self._identifier(job_id, "job_id")
        self._identifier(owner, "owner")
        self._identifier(lease_token, "lease_token")
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            existing = conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone()
            if existing is None:
                raise NotFoundError("worker job not found")
            bound_receipt = dict(receipt)
            if "job_id" in bound_receipt and bound_receipt["job_id"] != existing["job_id"]:
                raise ConflictError("effect receipt job binding does not match worker job")
            if "idempotency_key" in bound_receipt and bound_receipt["idempotency_key"] != existing["idempotency_key"]:
                raise ConflictError("effect receipt idempotency binding does not match worker job")
            bound_receipt.setdefault("job_id", existing["job_id"])
            bound_receipt.setdefault("idempotency_key", existing["idempotency_key"])
            bound_receipt.setdefault("stage", existing["stage"])
            receipt_json, receipt_sha = self._receipt(bound_receipt)
            winning = conn.execute(
                "SELECT owner, lease_token, outcome, effect_receipt_sha256 FROM worker_attempts "
                "WHERE job_id=? AND outcome IN ('SUCCEEDED','FAILED_PERMANENT') ORDER BY attempt_number DESC LIMIT 1",
                (job_id,),
            ).fetchone()
            if existing["status"] == "SUCCEEDED":
                if winning is None or winning["owner"] != owner or winning["lease_token"] != lease_token:
                    raise LeaseConflict("worker job winning attempt is not owned by this token")
                if receipt_sha != existing["effect_receipt_sha256"]:
                    raise ConflictError("worker job already succeeded with a different effect receipt")
                return self._job_payload(existing)
            if existing["status"] == "FAILED_PERMANENT" and existing["last_error_kind"] in {"deadline", "max_attempts"}:
                if winning is None or winning["owner"] != owner or winning["lease_token"] != lease_token:
                    raise LeaseConflict("worker job terminal attempt is not owned by this token")
                return self._job_payload(existing)
            if existing["status"] == "CLAIMED" and existing["owner"] == owner and existing["lease_token"] == lease_token and existing["overall_deadline_at"] is not None and existing["overall_deadline_at"] <= timestamp:
                self._terminalize_claimed_deadline_tx(conn, existing, timestamp)
                return self._job_payload(conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone())
            row = self._assert_worker_claim(conn, job_id, owner, lease_token, timestamp)
            # The receipt was validated and bound before the live-claim check;
            # retain this exact canonical digest for the winning attempt.
            conn.execute(
                "UPDATE worker_jobs SET status='SUCCEEDED', owner=NULL, lease_token=NULL, lease_expires_at=NULL, effect_receipt_json=?, effect_receipt_sha256=?, updated_at=?, completed_at=? WHERE job_id=?",
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
        lease_token: str,
        status_code: int | None = None,
        now: str | None = None,
        retry_after_seconds: int | None = None,
    ) -> dict[str, Any]:
        self._identifier(job_id, "job_id")
        self._identifier(owner, "owner")
        error_kind = self._safe_error_kind(error_kind)
        if not isinstance(retryable, bool):
            raise ValidationError("retryable must be boolean")
        if status_code is not None and (not isinstance(status_code, int) or isinstance(status_code, bool) or not 100 <= status_code <= 599):
            raise ValidationError("status_code must be an HTTP status integer")
        if retry_after_seconds is not None and (not isinstance(retry_after_seconds, int) or isinstance(retry_after_seconds, bool) or not 0 <= retry_after_seconds <= 86400):
            raise ValidationError("retry_after_seconds is out of bounds")
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            current = conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone()
            if current is not None and current["status"] == "CLAIMED" and current["owner"] == owner and current["lease_token"] == lease_token and current["overall_deadline_at"] is not None and current["overall_deadline_at"] <= timestamp:
                self._terminalize_claimed_deadline_tx(conn, current, timestamp)
                return self._job_payload(conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone())
            row = self._assert_worker_claim(conn, job_id, owner, lease_token, timestamp)
            attempt_count = int(row["attempt_count"])
            can_retry = retryable and attempt_count < int(row["max_attempts"]) and (row["overall_deadline_at"] is None or row["overall_deadline_at"] > timestamp)
            if can_retry:
                delay = retry_after_seconds if retry_after_seconds is not None else min(300, 2 ** min(attempt_count, 8))
                state = "RETRY_WAIT"
                next_attempt_at = self._plus_seconds(timestamp, delay)
                outcome = "RETRY_WAIT"
            else:
                state = "FAILED_PERMANENT"
                next_attempt_at = timestamp
                outcome = "FAILED_PERMANENT"
            conn.execute(
                "UPDATE worker_jobs SET status=?, owner=NULL, lease_token=NULL, lease_expires_at=NULL, next_attempt_at=?, last_error_kind=?, last_error_status_code=?, updated_at=?, completed_at=? WHERE job_id=?",
                (state, next_attempt_at, error_kind, status_code, timestamp, timestamp if state == "FAILED_PERMANENT" else None, job_id),
            )
            conn.execute(
                "UPDATE worker_attempts SET outcome=?, error_kind=?, error_status_code=?, finished_at=? WHERE job_id=? AND attempt_number=? AND outcome='RUNNING'",
                (outcome, error_kind, status_code, timestamp, job_id, attempt_count),
            )
            if state == "FAILED_PERMANENT":
                self._project_terminal_job_tx(conn, row, error_kind=error_kind, now=timestamp)
            return self._job_payload(conn.execute("SELECT * FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone())

    def recover_worker_jobs(self, *, now: str | None = None) -> dict[str, int]:
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            rows = conn.execute("SELECT * FROM worker_jobs WHERE status='CLAIMED' AND lease_expires_at <= ?", (timestamp,)).fetchall()
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
                    error_kind = "deadline" if deadline_expired else "lease_expired"
                    conn.execute("UPDATE worker_jobs SET status='FAILED_PERMANENT', owner=NULL, lease_token=NULL, lease_expires_at=NULL, last_error_kind=?, updated_at=?, completed_at=? WHERE job_id=?", (error_kind, timestamp, timestamp, row["job_id"]))
                    self._project_terminal_job_tx(conn, row, error_kind=error_kind, now=timestamp)
                    failed += 1
                else:
                    conn.execute("UPDATE worker_jobs SET status='RETRY_WAIT', owner=NULL, lease_token=NULL, lease_expires_at=NULL, next_attempt_at=?, updated_at=? WHERE job_id=?", (timestamp, timestamp, row["job_id"]))
                    requeued += 1
            return {"requeued": requeued, "failed": failed}

    def list_worker_attempts(self, job_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        self._identifier(job_id, "job_id")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValidationError("worker attempt limit must be between 1 and 500")
        with self.store._read() as conn:
            if conn.execute("SELECT 1 FROM worker_jobs WHERE job_id=?", (job_id,)).fetchone() is None:
                raise NotFoundError("worker job not found")
            return [dict(row) for row in conn.execute("SELECT attempt_id, job_id, attempt_number, owner, stage, started_at, finished_at, outcome, error_kind, error_status_code, effect_receipt_sha256 FROM worker_attempts WHERE job_id=? ORDER BY attempt_number LIMIT ?", (job_id, limit)).fetchall()]

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
        # A rollback receipt is durable before the artifact write so a crash
        # can recover it.  Serialize that receipt/write/manifest sequence
        # against cleanup recovery so it cannot unlink an in-flight artifact.
        with self.store._write_lock:
            return self._publish_update_manifest(
                channel=channel,
                generation=generation,
                platform=platform,
                version=version,
                version_code=version_code,
                artifact_name=artifact_name,
                signer_digest=signer_digest,
                changelog=changelog,
                min_server_version=min_server_version,
                authorization_policy=authorization_policy,
                artifact_path=artifact_path,
                artifact_bytes=artifact_bytes,
                etag=etag,
                expected_generation=expected_generation,
                now=now,
            )

    def _publish_update_manifest(
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
        receipt_id = None
        if not target_existed:
            receipt_id = self.store._prepare_cleanup_receipt(
                operation="update_manifest_rollback",
                path=target,
                expected_sha256=digest,
                expected_size=len(content),
                entity_type="update_manifest",
                entity_id=f"{channel}:{generation}",
                now=timestamp,
            )
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
                conn.execute(
                    "INSERT INTO update_manifests(channel, generation, platform, version, version_code, artifact_name, artifact_relpath, artifact_sha256, signer_digest, size, changelog, min_server_version, authorization_policy, etag, manifest_json, manifest_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (channel, generation, platform, version, version_code, artifact_name, relpath.as_posix(), digest, signer_digest, len(content), changelog, min_server_version, authorization_policy, requested_etag, json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")), manifest_sha, timestamp),
                )
                conn.execute(
                    "INSERT INTO update_channels(channel, current_generation, current_manifest_sha256, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(channel) DO UPDATE SET current_generation=excluded.current_generation, current_manifest_sha256=excluded.current_manifest_sha256, updated_at=excluded.updated_at",
                    (channel, generation, manifest_sha, timestamp),
                )
                if receipt_id is not None:
                    self.store._complete_cleanup_receipt_tx(conn, receipt_id, now=timestamp)
                return self._update_payload(conn.execute("SELECT * FROM update_manifests WHERE channel=? AND generation=?", (channel, generation)).fetchone(), current_generation=generation)
        except Exception as exc:
            if receipt_id is not None:
                cleanup = self.store.recover_cleanup_receipts(receipt_ids=[receipt_id], now=timestamp)
                if cleanup["pending"] or cleanup["blocked"]:
                    raise CleanupIncompleteError("update artifact rollback cleanup is incomplete") from exc
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
        size = int(row["size"])
        headers = {
            "Content-Type": "application/vnd.android.package-archive",
            "Content-Length": str(size),
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
                selected_range = self._range(range_header, size)
            except RangeNotSatisfiable:
                headers["Content-Range"] = f"bytes */{size}"
                headers["Content-Length"] = "0"
                return {"status": 416, "headers": headers, "body": b"", "manifest": manifest}
        if selected_range is None:
            content = self._read_managed_bytes(self.store.storage_root, path, expected_size=size, expected_sha256=row["artifact_sha256"])
            return {"status": 200, "headers": headers, "body": content, "manifest": manifest}
        start, end = selected_range
        body = self._read_managed_range(self.store.storage_root, path, expected_size=size, start=start, end=end)
        headers["Content-Length"] = str(len(body))
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"
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
            if row["source_deleted_at"] is not None:
                raise SourceUnavailableError("attachment source is unavailable")
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
            if row["source_deleted_at"] is not None:
                raise SourceUnavailableError("attachment source is unavailable")
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
            if row["state"] in {"CREATED", "ACTIVE", "PAUSED", "STOPPING", "STOPPED"} and row["expires_at"] <= timestamp:
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
            if row["state"] in {"CREATED", "ACTIVE", "PAUSED", "STOPPING", "STOPPED"} and row["expires_at"] <= timestamp:
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
            history = conn.execute(
                "SELECT transcript FROM eavesdrop_segments WHERE session_id=? AND sequence<=? ORDER BY sequence",
                (session["session_id"], segment["sequence"]),
            ).fetchall()
            conversation = "\n".join(
                str(item["transcript"]).strip()
                for item in history
                if isinstance(item["transcript"], str) and item["transcript"].strip()
            )
            request_snapshot = {"input": conversation}
            marker = f"eavesdrop:default:{session['session_id']}:{segment['sequence']}"
            conn.execute(
                "INSERT INTO hermes_run_bindings(submission_id, subject_kind, eavesdrop_session_id, segment_sequence, segment_sha256, marker, gateway_session_key, gateway_identity, canonical_request_sha256, wire_revision, request_json, created_at) VALUES (?, 'eavesdrop', ?, ?, ?, ?, ?, 'default', ?, 'hermes-runs-v1', ?, ?)",
                (submission_id, session["session_id"], segment["sequence"], segment["audio_sha256"], marker, gateway_session_key, sha256_json(request_snapshot), canonical_json(request_snapshot).decode("utf-8"), now),
            )
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

    def commit_eavesdrop_result(
        self,
        submission_id: str,
        result: Any,
        *,
        worker_claim: Mapping[str, Any] | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        """Atomically bind, validate, reply, and deliver one eavesdrop run."""
        if not isinstance(submission_id, str) or not submission_id:
            raise ValidationError("eavesdrop submission_id is required")
        timestamp = self._time(now, self.store)
        values = result if isinstance(result, Mapping) else getattr(result, "__dict__", None)
        if not isinstance(values, Mapping):
            raise ValidationError("eavesdrop Hermes result is malformed")
        content = values.get("content")
        assistant_message_id = values.get("assistant_message_id")
        run_id = values.get("run_id")
        if values.get("terminal") is not True or not isinstance(content, str) or not content.strip() or not isinstance(assistant_message_id, str) or not assistant_message_id or not isinstance(run_id, str) or not run_id:
            raise ValidationError("only a bound terminal eavesdrop result is accepted")
        with self.store._tx() as conn:
            if worker_claim is None or not self._assert_worker_effect_tx(conn, worker_claim, now=timestamp, stage="hermes"):
                raise LeaseConflict("worker eavesdrop result authority has expired")
            binding = conn.execute("SELECT * FROM hermes_run_bindings WHERE submission_id=?", (submission_id,)).fetchone()
            if binding is None or binding["subject_kind"] != "eavesdrop":
                raise ConflictError("eavesdrop result has no matching durable binding")
            expected = {
                "submission_id": submission_id,
                "eavesdrop_session_id": binding["eavesdrop_session_id"],
                "segment_sequence": binding["segment_sequence"],
                "segment_sha256": binding["segment_sha256"],
                "marker": binding["marker"],
                "session_key": binding["gateway_session_key"],
                "run_id": binding["run_id"],
                "request_sha256": binding["canonical_request_sha256"],
                "subject_kind": "eavesdrop",
            }
            if expected["run_id"] != run_id or any(values.get(key) is not None and values.get(key) != value for key, value in expected.items() if key in values):
                raise ConflictError("eavesdrop result provenance does not match the durable binding")
            if binding["run_id"] is None:
                raise ConflictError("eavesdrop result arrived before its run was bound")
            session = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (binding["eavesdrop_session_id"],)).fetchone()
            segment = conn.execute("SELECT * FROM eavesdrop_segments WHERE session_id=? AND sequence=?", (binding["eavesdrop_session_id"], binding["segment_sequence"])).fetchone()
            decision = conn.execute("SELECT * FROM eavesdrop_decisions WHERE session_id=? AND segment_sequence=?", (binding["eavesdrop_session_id"], binding["segment_sequence"])).fetchone()
            if session is None or segment is None or decision is None:
                raise NotFoundError("eavesdrop result subject is missing")
            if segment["audio_sha256"] != binding["segment_sha256"]:
                raise ConflictError("eavesdrop segment identity changed")
            if session["state"] not in {"ACTIVE", "PAUSED", "STOPPING"} or session["expires_at"] <= timestamp:
                raise ConflictError("eavesdrop session is no longer active")
            if decision["decision"] != "FORWARD_DEFAULT":
                raise ConflictError("eavesdrop result is not authorized for forwarding")
            content_hash = hermes_content_hash(content)
            receipt = {
                "submission_id": submission_id,
                "session_id": binding["eavesdrop_session_id"],
                "segment_sequence": binding["segment_sequence"],
                "segment_sha256": binding["segment_sha256"],
                "gateway_profile": binding["gateway_identity"],
                "input_sha256": binding["canonical_request_sha256"],
                "content_hash": content_hash,
                "assistant_message_id": assistant_message_id,
                "provider": values.get("source") or "hermes-run",
            }
            if decision["result_state"] == "DELIVERED":
                previous = json.loads(decision["effect_receipt_json"] or "{}")
                if previous.get("content_hash") != content_hash or previous.get("assistant_message_id") != assistant_message_id or previous.get("submission_id") != submission_id:
                    raise ConflictError("eavesdrop result conflicts with the delivered receipt")
                return self._eavesdrop_decision_payload(decision)
            if decision["result_state"] != "QUEUED":
                raise ConflictError("eavesdrop decision is not awaiting a Hermes result")
            if session["response_enabled"]:
                reply_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:eavesdrop-reply:{binding['eavesdrop_session_id']}:{binding['segment_sequence']}:{content_hash}"))
                existing_reply = conn.execute("SELECT * FROM eavesdrop_replies WHERE session_id=? AND segment_sequence=?", (binding["eavesdrop_session_id"], binding["segment_sequence"])).fetchone()
                if existing_reply is not None and (existing_reply["text_hash"] != content_hash or existing_reply["reply_text"] != content):
                    raise ConflictError("eavesdrop reply conflicts with the delivered result")
                if existing_reply is None:
                    conn.execute(
                        "INSERT INTO eavesdrop_replies(reply_id, session_id, segment_sequence, text_hash, reply_text, tts_requested, hermes_requested, created_at) VALUES (?, ?, ?, ?, ?, 0, 1, ?)",
                        (reply_id, binding["eavesdrop_session_id"], binding["segment_sequence"], content_hash, content, timestamp),
                    )
                receipt["reply_id"] = existing_reply["reply_id"] if existing_reply is not None else reply_id
            receipt_json = canonical_json(self._safe_eavesdrop_receipt(receipt)).decode("utf-8")
            conn.execute(
                "UPDATE eavesdrop_decisions SET result_state='DELIVERED', reason='hermes_response_available', effect_receipt_json=? WHERE session_id=? AND segment_sequence=? AND result_state='QUEUED'",
                (receipt_json, binding["eavesdrop_session_id"], binding["segment_sequence"]),
            )
            return self._eavesdrop_decision_payload(conn.execute("SELECT * FROM eavesdrop_decisions WHERE session_id=? AND segment_sequence=?", (binding["eavesdrop_session_id"], binding["segment_sequence"])).fetchone())

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
        worker_claim: Mapping[str, Any] | None = None,
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
            if worker_claim is not None and not self._assert_worker_effect_tx(conn, worker_claim, now=timestamp, stage="hermes"):
                raise LeaseConflict("worker eavesdrop effect deadline has expired")
            session = conn.execute("SELECT state, expires_at FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if session is None:
                raise NotFoundError("eavesdrop session not found")
            if session["state"] in {"CREATED", "ACTIVE", "PAUSED", "STOPPING", "STOPPED"} and session["expires_at"] <= timestamp:
                conn.execute("UPDATE eavesdrop_sessions SET state='EXPIRED', updated_at=?, stopped_at=? WHERE session_id=?", (timestamp, timestamp, session_id))
                if result_state in {"QUEUED", "DELIVERED"}:
                    result_state = "FAILED"
                    reason = "session_expired"
                    receipt_json = None
            elif session["state"] == "EXPIRED" and result_state in {"QUEUED", "DELIVERED"}:
                result_state = "FAILED"
                reason = "session_expired"
                receipt_json = None
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

    def record_eavesdrop_reply(self, session_id: str, *, segment_sequence: int, text: str, now: str | None = None, worker_claim: Mapping[str, Any] | None = None) -> dict[str, Any]:
        self._identifier(session_id, "session_id")
        if not isinstance(segment_sequence, int) or isinstance(segment_sequence, bool) or segment_sequence < 0 or not isinstance(text, str) or not text:
            raise ValidationError("reply sequence and text are required")
        normalized = normalize_hermes_text(text)
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            if worker_claim is not None and not self._assert_worker_effect_tx(conn, worker_claim, now=timestamp, stage="hermes"):
                raise LeaseConflict("worker eavesdrop reply effect deadline has expired")
            session = conn.execute("SELECT * FROM eavesdrop_sessions WHERE session_id=?", (session_id,)).fetchone()
            if session is None:
                raise NotFoundError("eavesdrop session not found")
            if not session["response_enabled"]:
                raise ConflictError("eavesdrop responses are disabled")
            if session["state"] in {"CREATED", "ACTIVE", "PAUSED", "STOPPING", "STOPPED"} and session["expires_at"] <= timestamp:
                conn.execute("UPDATE eavesdrop_sessions SET state='EXPIRED', updated_at=?, stopped_at=? WHERE session_id=?", (timestamp, timestamp, session_id))
                raise ConflictError("eavesdrop session has expired")
            if session["state"] == "EXPIRED":
                raise ConflictError("eavesdrop session has expired")
            if session["state"] != "ACTIVE":
                raise ConflictError("eavesdrop session is not active")
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
    DIAGNOSTIC_SENSITIVE_VALUE = re.compile(
        r"(?:-----BEGIN|\bBearer\s+\S+|\b(?:sk|ghp|xox[baprs])-[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
        re.I,
    )
    DIAGNOSTIC_SCALAR = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
    DIAGNOSTIC_HASH = re.compile(r"^[0-9a-fA-F]{64}$")

    @classmethod
    def _sanitize_diagnostic_value(cls, key: str, value: Any) -> Any:
        if cls.DIAGNOSTIC_BANNED.search(key):
            return None
        if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
            if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
                return None
            return value
        if isinstance(value, str):
            looks_like_high_entropy = len(value) >= 40 and bool(re.search(r"[A-Z]", value) and re.search(r"[a-z]", value) and re.search(r"\d", value))
            if len(value) > 1024 or cls.DIAGNOSTIC_BANNED.search(value) or cls.DIAGNOSTIC_SENSITIVE_VALUE.search(value) or looks_like_high_entropy or re.search(r"(^|[\s])(?:/|~[/\\]|[A-Za-z]:[\\/])", value):
                return "[REDACTED]"
            if key == "hash":
                return value if cls.DIAGNOSTIC_HASH.fullmatch(value) else "[REDACTED]"
            return value if cls.DIAGNOSTIC_SCALAR.fullmatch(value) else "[REDACTED]"
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for child_key, child_value in value.items():
                if not isinstance(child_key, str) or child_key not in cls.DIAGNOSTIC_KEYS or cls.DIAGNOSTIC_BANNED.search(child_key):
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
        try:
            result = project_metadata(payload)
        except MetadataValidationError as exc:
            raise ValidationError("diagnostic metadata is invalid") from exc
        if len(canonical_json(result)) > 16 * 1024:
            raise ValidationError("diagnostic metadata exceeds the bounded limit")
        return result

    def _diagnostics_enabled_tx(self, conn: Any, user_id: str, device_id: str, now: str, event_id: str | None = None) -> bool:
        row = conn.execute(
            "SELECT * FROM diagnostics_consents "
            "WHERE user_id=? AND device_id=? AND revoked_at IS NULL "
            "ORDER BY created_at DESC, event_id DESC LIMIT 1",
            (user_id, device_id),
        ).fetchone()
        if row is None or not row["enabled"] or (row["expires_at"] and row["expires_at"] <= now):
            return False
        # A bundle carries the consent event that authorized it.  It must be
        # the one current row, not merely any historically enabled row.  The
        # enclosing transaction serializes this read with opt-out revocation.
        if event_id is None or row["event_id"] == event_id:
            return True
        alias_digest = self._alias_digest("consent", user_id, device_id, event_id)
        return row["alias_digest"] == alias_digest

    def _resolve_consent_event_id_tx(self, conn: Any, user_id: str, device_id: str, event_id: str) -> str | None:
        alias_digest = self._alias_digest("consent", user_id, device_id, event_id)
        row = conn.execute(
            "SELECT event_id FROM diagnostics_consents WHERE user_id=? AND device_id=? "
            "AND (event_id=? OR alias_digest=?) ORDER BY created_at DESC, event_id DESC LIMIT 1",
            (user_id, device_id, event_id, alias_digest),
        ).fetchone()
        return str(row["event_id"]) if row is not None else None

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
        alias_digest = None
        if event_id is not None:
            self._identifier(event_id, "event_id")
            alias_digest = self._alias_digest("consent", user_id, device_id, event_id)
        handle = str(uuid.uuid4())
        timestamp = self._time(now, self.store)
        expiry = self._time(expires_at, self.store) if expires_at is not None else None
        with self.store._tx() as conn:
            self.store._assert_device(conn, user_id, device_id)
            if alias_digest:
                existing = conn.execute(
                    "SELECT * FROM diagnostics_consents WHERE user_id=? AND device_id=? AND (event_id=? OR alias_digest=?)",
                    (user_id, device_id, event_id, alias_digest),
                ).fetchone()
            else:
                existing = None
            if existing is not None:
                if existing["user_id"] != user_id or existing["device_id"] != device_id or bool(existing["enabled"]) != enabled or existing["expires_at"] != expiry:
                    raise ConflictError("diagnostics consent event is immutable")
                return {"event_id": existing["event_id"], "user_id": user_id, "device_id": device_id, "enabled": bool(existing["enabled"]), "created_at": existing["created_at"], "expires_at": existing["expires_at"]}
            # Consent is a single current authority.  Revoke every older
            # event before publishing either a new opt-in or an opt-out so a
            # caller cannot reuse a historical authorization after a later
            # decision.  This runs in the same transaction as the new event.
            conn.execute(
                "UPDATE diagnostics_consents SET revoked_at=? "
                "WHERE user_id=? AND device_id=? AND revoked_at IS NULL",
                (timestamp, user_id, device_id),
            )
            conn.execute("INSERT INTO diagnostics_consents(user_id, device_id, event_id, alias_digest, enabled, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (user_id, device_id, handle, alias_digest, int(enabled), timestamp, expiry))
            return {"event_id": handle, "user_id": user_id, "device_id": device_id, "enabled": enabled, "created_at": timestamp, "expires_at": expiry}

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
        event_alias_digest = self._alias_digest("event", user_id, device_id, event_id)
        idempotency_digest = self._alias_digest("idempotency", user_id, device_id, idempotency_key)
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
            existing = conn.execute(
                "SELECT * FROM diagnostic_events WHERE user_id=? AND device_id=? "
                "AND (idempotency_key=? OR alias_digest=?)",
                (user_id, device_id, idempotency_digest, event_alias_digest),
            ).fetchone()
            if existing is not None:
                if existing["deleted_at"] is not None or existing["retention_deadline"] <= timestamp or existing["privacy_version"] != 2 or existing["migration_state"] != "READY":
                    raise ConflictError("diagnostic event is expired or deleted")
                if existing["metadata_json"] != metadata_json or existing["user_id"] != user_id or existing["device_id"] != device_id:
                    raise ConflictError("diagnostic event idempotency key has a different payload")
                if existing["idempotency_key"] != idempotency_digest:
                    raise ConflictError("diagnostic event alias has a different idempotency key")
                return {"event_id": existing["event_id"], "category": existing["category"], "stage": existing["stage"], "metadata": json.loads(existing["metadata_json"]), "occurred_at": existing["occurred_at"], "retention_deadline": existing["retention_deadline"]}
            handle = str(uuid.uuid4())
            conn.execute("INSERT INTO diagnostic_events(event_id, idempotency_key, alias_digest, user_id, device_id, category, stage, metadata_json, occurred_at, retention_deadline, privacy_version, migration_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, 'READY')", (handle, idempotency_digest, event_alias_digest, user_id, device_id, category, stage, metadata_json, occurred, deadline))
            return {"event_id": handle, "category": category, "stage": stage, "metadata": metadata, "occurred_at": occurred, "retention_deadline": deadline}

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
        # Keep the durable rollback receipt, managed bundle, and DB row
        # serialized with cleanup recovery for the same reason as chunk
        # ingestion: the receipt precedes the physical write by design.
        with self.store._write_lock:
            return self._ingest_diagnostic_bundle(
                user_id,
                device_id,
                bundle_id,
                compressed,
                opt_in_event_id=opt_in_event_id,
                expanded_size=expanded_size,
                now=now,
            )

    def _ingest_diagnostic_bundle(
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
        alias_digest = self._alias_digest("bundle", user_id, device_id, bundle_id)
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
        try:
            redacted: Any = project_bundle(decoded)
        except MetadataValidationError as exc:
            raise ValidationError("diagnostic bundle must contain an object or array")
        redacted_expanded = canonical_json(redacted)
        if len(redacted_expanded) > max_expanded:
            raise ValidationError("redacted diagnostic bundle exceeds the bounded limit")
        redacted_compressed = zlib.compress(redacted_expanded, level=6)
        digest = sha256_bytes(redacted_compressed)
        timestamp = self._time(now, self.store)
        deadline = self._plus_seconds(timestamp, int(getattr(self.store, "diagnostics_retention_seconds", 7 * 86400)))
        handle = str(uuid.uuid4())
        path = self.store.storage_root / "diagnostics" / hashlib.sha256(user_id.encode("utf-8")).hexdigest() / f"{handle}.z"
        with self.store._read() as conn:
            self.store._assert_device(conn, user_id, device_id)
            resolved_opt_in_event_id = self._resolve_consent_event_id_tx(conn, user_id, device_id, opt_in_event_id)
            if resolved_opt_in_event_id is None or not self._diagnostics_enabled_tx(conn, user_id, device_id, timestamp, resolved_opt_in_event_id):
                raise UnauthorizedError("diagnostic bundle requires the exact active opt-in event")
        self._mkdir_managed_path(self.store.storage_root, path.parent)
        receipt_id = self.store._prepare_cleanup_receipt(
            operation="diagnostic_bundle_ingest_rollback",
            path=path,
            expected_sha256=digest,
            expected_size=len(redacted_compressed),
            user_id=user_id,
            device_id=device_id,
            entity_type="diagnostic_bundle",
            entity_id=handle,
            now=timestamp,
        )
        try:
            with self.store._tx() as conn:
                self.store._assert_device(conn, user_id, device_id)
                resolved_opt_in_event_id = self._resolve_consent_event_id_tx(conn, user_id, device_id, opt_in_event_id)
                if resolved_opt_in_event_id is None or not self._diagnostics_enabled_tx(conn, user_id, device_id, timestamp, resolved_opt_in_event_id):
                    raise UnauthorizedError("diagnostic bundle requires the exact active opt-in event")
                existing = conn.execute("SELECT * FROM diagnostic_bundles WHERE user_id=? AND device_id=? AND (alias_digest=? OR bundle_id=?)", (user_id, device_id, alias_digest, bundle_id)).fetchone()
                if existing is not None:
                    if existing["deleted_at"] is not None or existing["retention_deadline"] <= timestamp or existing["privacy_version"] != 2 or existing["migration_state"] != "READY":
                        raise ConflictError("diagnostic bundle is expired or deleted")
                    if existing["payload_sha256"] != digest or existing["user_id"] != user_id or existing["device_id"] != device_id:
                        raise ConflictError("diagnostic bundle is immutable")
                    self.store._complete_cleanup_receipt_tx(conn, receipt_id, now=timestamp)
                    return {"bundle_id": existing["bundle_id"], "compressed_size": existing["compressed_size"], "expanded_size": existing["expanded_size"], "created_at": existing["created_at"], "retention_deadline": existing["retention_deadline"]}
                path_existed = path.exists()
                if path_existed and self._read_managed_bytes(self.store.storage_root, path) != redacted_compressed:
                    raise ConflictError("diagnostic bundle path already contains different bytes")
                if not path_existed:
                    self.store._safe_write(path, redacted_compressed)
                conn.execute("INSERT INTO diagnostic_bundles(bundle_id, alias_digest, user_id, device_id, opt_in_event_id, compressed_size, expanded_size, payload_sha256, storage_path, created_at, retention_deadline, privacy_version, migration_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, 'READY')", (handle, alias_digest, user_id, device_id, resolved_opt_in_event_id, len(redacted_compressed), len(redacted_expanded), digest, str(path), timestamp, deadline))
                self.store._complete_cleanup_receipt_tx(conn, receipt_id, now=timestamp)
                return {"bundle_id": handle, "compressed_size": len(redacted_compressed), "expanded_size": len(redacted_expanded), "created_at": timestamp, "retention_deadline": deadline}
        except Exception as exc:
            cleanup = self.store.recover_cleanup_receipts(receipt_ids=[receipt_id], now=timestamp)
            if cleanup["pending"] or cleanup["blocked"]:
                raise CleanupIncompleteError("diagnostic bundle rollback cleanup is incomplete") from exc
            raise

    def _expire_diagnostics_tx(self, conn: Any, *, user_id: str | None, device_id: str | None, as_of: str) -> dict[str, int]:
        scope_sql = ""
        scope_args: tuple[Any, ...] = ()
        if user_id is not None and device_id is not None:
            scope_sql = " AND user_id=? AND device_id=?"
            scope_args = (user_id, device_id)
        events = conn.execute("SELECT event_id, user_id, device_id, retention_deadline FROM diagnostic_events WHERE deleted_at IS NULL AND retention_deadline <= ? AND privacy_version=2 AND migration_state='READY'" + scope_sql, (as_of, *scope_args)).fetchall()
        bundles = conn.execute("SELECT bundle_id, user_id, device_id, storage_path, payload_sha256, compressed_size, retention_deadline FROM diagnostic_bundles WHERE deleted_at IS NULL AND retention_deadline <= ? AND privacy_version=2 AND migration_state='READY'" + scope_sql, (as_of, *scope_args)).fetchall()
        tombstone_seconds = int(self.store.diagnostics_tombstone_retention_seconds)
        for row in events:
            expires_at = self._plus_seconds(row["retention_deadline"], tombstone_seconds)
            conn.execute("UPDATE diagnostic_events SET metadata_json='{}', deleted_at=? WHERE event_id=?", (as_of, row["event_id"]))
            conn.execute("INSERT OR IGNORE INTO diagnostic_tombstones(tombstone_id, user_id, device_id, entity_type, entity_id, deleted_at, expires_at) VALUES (?, ?, ?, 'event', ?, ?, ?)", (str(uuid.uuid4()), row["user_id"], row["device_id"], row["event_id"], as_of, expires_at))
        for row in bundles:
            expires_at = self._plus_seconds(row["retention_deadline"], tombstone_seconds)
            conn.execute("UPDATE diagnostic_bundles SET compressed_size=0, expanded_size=0, storage_path='', deleted_at=? WHERE bundle_id=?", (as_of, row["bundle_id"]))
            conn.execute("INSERT OR IGNORE INTO diagnostic_tombstones(tombstone_id, user_id, device_id, entity_type, entity_id, deleted_at, expires_at) VALUES (?, ?, ?, 'bundle', ?, ?, ?)", (str(uuid.uuid4()), row["user_id"], row["device_id"], row["bundle_id"], as_of, expires_at))
            self.store._prepare_cleanup_receipt_tx(conn, operation="diagnostic_purge", path=Path(row["storage_path"]), expected_sha256=row["payload_sha256"], expected_size=int(row["compressed_size"]), user_id=row["user_id"], device_id=row["device_id"], entity_type="diagnostic_bundle", entity_id=row["bundle_id"], now=as_of)
        return {"events": len(events), "bundles": len(bundles)}

    def _diagnostic_listing_items(self, conn: Any, user_id: str, device_id: str, *, category: str | None = None, stage: str | None = None, limit: int | None = 100, as_of: str | None = None) -> list[dict[str, Any]]:
        clauses = ["user_id=?", "device_id=?", "deleted_at IS NULL", "retention_deadline > ?", "privacy_version=2", "migration_state='READY'"]
        args: list[Any] = [user_id, device_id]
        as_of = as_of or self.store._now()
        args.append(as_of)
        if category is not None:
            clauses.append("category=?")
            args.append(category)
        if stage is not None:
            clauses.append("stage=?")
            args.append(stage)
        event_query = "SELECT * FROM diagnostic_events WHERE " + " AND ".join(clauses) + " ORDER BY occurred_at, event_id"
        bundle_query = "SELECT * FROM diagnostic_bundles WHERE user_id=? AND device_id=? AND deleted_at IS NULL AND retention_deadline > ? AND privacy_version=2 AND migration_state='READY' ORDER BY created_at, bundle_id"
        if limit is not None:
            event_query += " LIMIT ?"
            bundle_query += " LIMIT ?"
            # Fetch one sentinel row from each source so ``has_more`` remains
            # truthful when one source alone reaches the page boundary.
            fetch_limit = limit + 1
            events = conn.execute(event_query, (*args, fetch_limit)).fetchall()
            bundles = conn.execute(bundle_query, (user_id, device_id, as_of, fetch_limit)).fetchall()
        else:
            events = conn.execute(event_query, args).fetchall()
            bundles = conn.execute(bundle_query, (user_id, device_id, as_of)).fetchall()
        items = [
            {"type": "event", "event_id": row["event_id"], "category": row["category"], "stage": row["stage"], "metadata": json.loads(row["metadata_json"]), "occurred_at": row["occurred_at"], "retention_deadline": row["retention_deadline"]}
            for row in events
        ] + [
            {"type": "bundle", "bundle_id": row["bundle_id"], "compressed_size": row["compressed_size"], "expanded_size": row["expanded_size"], "created_at": row["created_at"], "retention_deadline": row["retention_deadline"]}
            for row in bundles
        ]
        items.sort(key=lambda item: (item.get("occurred_at") or item.get("created_at") or "", item.get("event_id") or item.get("bundle_id") or ""))
        return items

    def list_diagnostics(self, user_id: str, device_id: str, *, category: str | None = None, stage: str | None = None, limit: int = 100) -> dict[str, Any]:
        self._identifier(device_id, "device_id")
        if not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValidationError("diagnostic limit must be between 1 and 500")
        with self.store._tx() as conn:
            self.store._assert_device(conn, user_id, device_id)
            as_of = self.store._now()
            self._expire_diagnostics_tx(conn, user_id=user_id, device_id=device_id, as_of=as_of)
            items = self._diagnostic_listing_items(conn, user_id, device_id, category=category, stage=stage, limit=limit, as_of=as_of)
            return {"items": items[:limit], "has_more": len(items) > limit}

    @staticmethod
    def _decode_diagnostics_cursor(cursor: str | None, *, scope: str) -> tuple[str, int, str] | None:
        if cursor is None:
            return None
        if not isinstance(cursor, str) or not cursor or len(cursor) > 512:
            raise ValidationError("diagnostic cursor is invalid")
        try:
            encoded = cursor.encode("ascii")
            encoded += b"=" * (-len(encoded) % 4)
            payload = json.loads(base64.b64decode(encoded, altchars=b"-_", validate=True).decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError, binascii.Error) as exc:
            raise ValidationError("diagnostic cursor is invalid") from exc
        if not isinstance(payload, dict) or set(payload) != {"version", "scope", "sort_at", "sort_type", "entity_id"} or payload.get("version") != 2 or payload.get("scope") != scope:
            raise ValidationError("diagnostic cursor is invalid")
        sort_at = payload["sort_at"]
        sort_type = payload["sort_type"]
        entity_id = payload["entity_id"]
        if (
            not isinstance(sort_at, str)
            or not sort_at
            or isinstance(sort_type, bool)
            or not isinstance(sort_type, int)
            or sort_type not in {0, 1, 2}
            or not isinstance(entity_id, str)
            or not entity_id
        ):
            raise ValidationError("diagnostic cursor is invalid")
        return sort_at, sort_type, entity_id

    @staticmethod
    def _encode_diagnostics_cursor(sort_at: str, sort_type: int, entity_id: str, *, scope: str) -> str:
        payload = {"entity_id": entity_id, "scope": scope, "sort_at": sort_at, "sort_type": sort_type, "version": 2}
        return base64.urlsafe_b64encode(canonical_json(payload)).decode("ascii").rstrip("=")

    @staticmethod
    def _diagnostic_row_item(row: Any) -> dict[str, Any]:
        if row["entity_type"] == "event":
            return {
                "type": "event",
                "event_id": row["entity_id"],
                "category": row["category"],
                "stage": row["stage"],
                "metadata": json.loads(row["metadata_json"]),
                "occurred_at": row["sort_at"],
                "retention_deadline": row["retention_deadline"],
            }
        return {
            "type": "bundle",
            "bundle_id": row["entity_id"],
            "compressed_size": row["compressed_size"],
            "expanded_size": row["expanded_size"],
            "created_at": row["sort_at"],
            "retention_deadline": row["retention_deadline"],
        }

    def export_diagnostics(
        self,
        user_id: str,
        device_id: str,
        *,
        category: str | None = None,
        stage: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        self._identifier(device_id, "device_id")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValidationError("diagnostic export limit must be between 1 and 500")
        byte_limit = self.store.diagnostics_export_max_bytes if max_bytes is None else max_bytes
        if not isinstance(byte_limit, int) or isinstance(byte_limit, bool) or not 1024 <= byte_limit <= 64 * 1024 * 1024:
            raise ValidationError("diagnostic export byte limit is invalid")
        scope = self._alias_digest("cursor", user_id, device_id, f"{category or ''}\x00{stage or ''}")
        decoded_cursor = self._decode_diagnostics_cursor(cursor, scope=scope)
        with self.store._tx() as conn:
            self.store._assert_device(conn, user_id, device_id)
            as_of = self.store._now()
            self._expire_diagnostics_tx(conn, user_id=user_id, device_id=device_id, as_of=as_of)
            event_clauses = ["e.user_id=?", "e.device_id=?", "e.deleted_at IS NULL", "e.retention_deadline > ?", "e.privacy_version=2", "e.migration_state='READY'"]
            event_args: list[Any] = [user_id, device_id, as_of]
            if category is not None:
                event_clauses.append("e.category=?")
                event_args.append(category)
            if stage is not None:
                event_clauses.append("e.stage=?")
                event_args.append(stage)
            bundle_clauses = ["b.user_id=?", "b.device_id=?", "b.deleted_at IS NULL", "b.retention_deadline > ?", "b.privacy_version=2", "b.migration_state='READY'"]
            bundle_args: list[Any] = [user_id, device_id, as_of]
            tombstone_clauses = ["t.user_id=?", "t.device_id=?", "t.expires_at > ?"]
            tombstone_args: list[Any] = [user_id, device_id, as_of]
            union_sql = (
                "SELECT 'event' AS entity_type, 0 AS sort_type, e.event_id AS entity_id, e.occurred_at AS sort_at, "
                "e.category AS category, e.stage AS stage, e.metadata_json AS metadata_json, "
                "NULL AS compressed_size, NULL AS expanded_size, NULL AS payload_sha256, e.retention_deadline AS retention_deadline "
                "FROM diagnostic_events e WHERE " + " AND ".join(event_clauses) + " UNION ALL "
                "SELECT 'bundle' AS entity_type, 1 AS sort_type, b.bundle_id AS entity_id, b.created_at AS sort_at, "
                "NULL AS category, NULL AS stage, NULL AS metadata_json, b.compressed_size AS compressed_size, "
                "b.expanded_size AS expanded_size, b.payload_sha256 AS payload_sha256, b.retention_deadline AS retention_deadline "
                "FROM diagnostic_bundles b WHERE " + " AND ".join(bundle_clauses) + " UNION ALL "
                "SELECT 'tombstone' AS entity_type, 2 AS sort_type, t.entity_id AS entity_id, t.deleted_at AS sort_at, "
                "t.entity_type AS category, NULL AS stage, NULL AS metadata_json, NULL AS compressed_size, "
                "NULL AS expanded_size, NULL AS payload_sha256, t.expires_at AS retention_deadline "
                "FROM diagnostic_tombstones t WHERE " + " AND ".join(tombstone_clauses)
            )
            args = [*event_args, *bundle_args, *tombstone_args]
            cursor_clause = ""
            if decoded_cursor is not None:
                sort_at, sort_type, entity_id = decoded_cursor
                cursor_clause = (
                    " WHERE (sort_at > ? OR (sort_at = ? AND sort_type > ?) "
                    "OR (sort_at = ? AND sort_type = ? AND entity_id > ?))"
                )
                args.extend([sort_at, sort_at, sort_type, sort_at, sort_type, entity_id])
            rows = conn.execute(
                "SELECT * FROM (" + union_sql + ")" + cursor_clause + " ORDER BY sort_at, sort_type, entity_id LIMIT ?",
                (*args, limit + 1),
            ).fetchall()

        accepted: list[dict[str, Any]] = []
        accepted_tombstones: list[dict[str, Any]] = []
        next_cursor: str | None = None
        truncated = False
        last_key: tuple[str, int, str] | None = None

        def render() -> dict[str, Any]:
            return {
                "schema_version": 1,
                "items": accepted,
                "tombstones": accepted_tombstones,
                "next_cursor": next_cursor,
                "truncated": truncated,
            }

        for index, row in enumerate(rows):
            if index >= limit:
                truncated = True
                if last_key is not None:
                    next_cursor = self._encode_diagnostics_cursor(*last_key, scope=scope)
                break
            if row["entity_type"] == "tombstone":
                item = {"entity_type": row["category"], "entity_id": row["entity_id"], "deleted_at": row["sort_at"]}
            else:
                item = self._diagnostic_row_item(row)
            if row["entity_type"] == "tombstone":
                accepted_tombstones.append(item)
            else:
                accepted.append(item)
            previous_key = last_key
            last_key = (row["sort_at"], int(row["sort_type"]), row["entity_id"])
            if len(canonical_json(render())) > byte_limit:
                if row["entity_type"] == "tombstone":
                    accepted_tombstones.pop()
                else:
                    accepted.pop()
                if not accepted and not accepted_tombstones:
                    raise ValidationError("diagnostic export item exceeds byte limit")
                truncated = True
                if previous_key is not None:
                    next_cursor = self._encode_diagnostics_cursor(*previous_key, scope=scope)
                last_key = previous_key
                break

        response = render()
        if len(canonical_json(response)) > byte_limit:
            raise ValidationError("diagnostic export envelope exceeds byte limit")
        return response


    def delete_diagnostics(self, user_id: str, device_id: str, *, now: str | None = None) -> dict[str, int]:
        self._identifier(device_id, "device_id")
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            self.store._assert_device(conn, user_id, device_id)
            as_of = timestamp
            self._expire_diagnostics_tx(conn, user_id=user_id, device_id=device_id, as_of=as_of)
            events = conn.execute("SELECT event_id, retention_deadline FROM diagnostic_events WHERE user_id=? AND device_id=? AND deleted_at IS NULL AND retention_deadline > ? AND privacy_version=2 AND migration_state='READY'", (user_id, device_id, as_of)).fetchall()
            bundles = conn.execute("SELECT bundle_id, storage_path, payload_sha256, compressed_size, retention_deadline FROM diagnostic_bundles WHERE user_id=? AND device_id=? AND deleted_at IS NULL AND retention_deadline > ? AND privacy_version=2 AND migration_state='READY'", (user_id, device_id, as_of)).fetchall()
            tombstone_expiry = self._plus_seconds(timestamp, self.store.diagnostics_tombstone_retention_seconds)
            for row in events:
                conn.execute("UPDATE diagnostic_events SET category='other', stage='other', metadata_json='{}', deleted_at=? WHERE event_id=?", (timestamp, row["event_id"]))
                conn.execute("INSERT OR IGNORE INTO diagnostic_tombstones(tombstone_id, user_id, device_id, entity_type, entity_id, deleted_at, expires_at) VALUES (?, ?, ?, 'event', ?, ?, ?)", (str(uuid.uuid4()), user_id, device_id, row["event_id"], timestamp, tombstone_expiry))
            for row in bundles:
                conn.execute("UPDATE diagnostic_bundles SET compressed_size=0, expanded_size=0, storage_path='', deleted_at=? WHERE bundle_id=?", (timestamp, row["bundle_id"]))
                conn.execute("INSERT OR IGNORE INTO diagnostic_tombstones(tombstone_id, user_id, device_id, entity_type, entity_id, deleted_at, expires_at) VALUES (?, ?, ?, 'bundle', ?, ?, ?)", (str(uuid.uuid4()), user_id, device_id, row["bundle_id"], timestamp, tombstone_expiry))
                self.store._prepare_cleanup_receipt_tx(
                    conn,
                    operation="diagnostic_delete",
                    path=Path(row["storage_path"]),
                    expected_sha256=row["payload_sha256"],
                    expected_size=int(row["compressed_size"]),
                    user_id=user_id,
                    device_id=device_id,
                    entity_type="diagnostic_bundle",
                    entity_id=row["bundle_id"],
                    now=timestamp,
                )
            conn.execute("UPDATE diagnostics_consents SET revoked_at=? WHERE user_id=? AND device_id=? AND revoked_at IS NULL", (timestamp, user_id, device_id))
        self.store.recover_cleanup_receipts(now=timestamp)
        with self.store._read() as conn:
            pending = conn.execute(
                "SELECT COUNT(*) FROM storage_cleanup_receipts WHERE user_id=? AND device_id=? AND operation IN ('diagnostic_delete', 'diagnostic_purge') AND status IN ('PENDING', 'BLOCKED')",
                (user_id, device_id),
            ).fetchone()[0]
        if pending:
            raise CleanupIncompleteError("diagnostic deletion cleanup is incomplete")
        return {"events": len(events), "bundles": len(bundles), "tombstones": len(events) + len(bundles)}

    def purge_diagnostics(self, *, now: str | None = None, _recover_cleanup: bool = True) -> dict[str, int]:
        timestamp = self._time(now, self.store)
        with self.store._tx() as conn:
            expired = self._expire_diagnostics_tx(conn, user_id=None, device_id=None, as_of=timestamp)
            expired_tombstones = conn.execute("SELECT tombstone_id FROM diagnostic_tombstones WHERE expires_at <= ?", (timestamp,)).fetchall()
            if expired_tombstones:
                conn.executemany(
                    "DELETE FROM diagnostic_tombstones WHERE tombstone_id=?",
                    [(row["tombstone_id"],) for row in expired_tombstones],
                )
        if _recover_cleanup:
            self.store.recover_cleanup_receipts(now=timestamp)
        if not _recover_cleanup:
            return {"events": expired["events"], "bundles": expired["bundles"], "tombstones": len(expired_tombstones)}
        with self.store._read() as conn:
            pending = conn.execute(
                "SELECT COUNT(*) FROM storage_cleanup_receipts WHERE operation IN ('diagnostic_delete', 'diagnostic_purge') AND status IN ('PENDING', 'BLOCKED')",
            ).fetchone()[0]
        if pending:
            raise CleanupIncompleteError("diagnostic purge cleanup is incomplete")
        result = {"events": expired["events"], "bundles": expired["bundles"]}
        if expired_tombstones:
            result["tombstones"] = len(expired_tombstones)
        return result


class DurableWorker:
    """Restart-safe worker loop whose handlers must return effect receipts."""

    def __init__(self, store: Any, *, owner: str, handlers: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]]):
        self.store = store
        self.owner = owner
        self.handlers = dict(handlers)

    def _start_heartbeat(
        self,
        *,
        job_id: str,
        lease_token: str,
        lease_seconds: int,
        stop: threading.Event,
        lost: threading.Event,
    ) -> threading.Thread:
        interval = max(0.05, min(float(lease_seconds) / 3.0, 5.0))

        def heartbeat() -> None:
            while not stop.wait(interval):
                try:
                    renewed = self.store.renew_worker_lease(
                        job_id,
                        self.owner,
                        lease_token=lease_token,
                        lease_seconds=lease_seconds,
                    )
                except Exception:
                    renewed = False
                if not renewed:
                    lost.set()
                    return

        thread = threading.Thread(target=heartbeat, name=f"recorder-worker-heartbeat-{job_id[:12]}", daemon=True)
        thread.start()
        return thread

    def run_once(self, *, now: str | None = None, lease_seconds: int = 30) -> dict[str, Any] | None:
        job = self.store.claim_worker_job(self.owner, now=now, lease_seconds=lease_seconds)
        if job is None:
            return None
        lease_token = job.get("lease_token")
        if not isinstance(lease_token, str) or not lease_token:
            return self.store.fail_worker_job(
                job["job_id"],
                self.owner,
                lease_token=lease_token or "missing-lease-token",
                error_kind="lease_token_missing",
                retryable=False,
                now=now,
            )
        handler = self.handlers.get(job["kind"]) or self.handlers.get(job["stage"])
        if handler is None:
            return self.store.fail_worker_job(job["job_id"], self.owner, lease_token=lease_token, error_kind="no_handler", retryable=False, now=now)
        stop = threading.Event()
        lease_lost = threading.Event()
        heartbeat = self._start_heartbeat(
            job_id=job["job_id"],
            lease_token=lease_token,
            lease_seconds=lease_seconds,
            stop=stop,
            lost=lease_lost,
        )

        def fail(
            *,
            error_kind: str,
            retryable: bool,
            status_code: int | None = None,
        ) -> dict[str, Any]:
            try:
                return self.store.fail_worker_job(
                    job["job_id"],
                    self.owner,
                    lease_token=lease_token,
                    error_kind=error_kind,
                    retryable=retryable,
                    status_code=status_code,
                    now=now,
                )
            except LeaseConflict:
                return self.store.get_worker_job(job["job_id"])

        try:
            handler_job = dict(job)
            handler_job["_worker_owner"] = self.owner
            if now is not None:
                handler_job["_worker_now"] = now
            receipt = handler(handler_job)
        except LeaseConflict:
            return self.store.get_worker_job(job["job_id"])
        except Exception as exc:
            retryable = bool(getattr(exc, "retryable", False))
            kind = str(getattr(exc, "kind", "handler_error"))
            status_code = getattr(exc, "status_code", None)
            if not isinstance(status_code, int) or isinstance(status_code, bool) or not 100 <= status_code <= 599:
                status_code = None
            if not SAFE_ERROR_RE.fullmatch(kind):
                kind = "handler_error"
            return fail(error_kind=kind, retryable=retryable, status_code=status_code)
        finally:
            stop.set()
            heartbeat.join(timeout=max(1.0, min(float(lease_seconds), 5.0)))
        if not isinstance(receipt, Mapping):
            return fail(error_kind="missing_effect_receipt", retryable=False)
        try:
            return self.store.complete_worker_job(job["job_id"], self.owner, receipt, lease_token=lease_token, now=now)
        except LeaseConflict:
            return self.store.get_worker_job(job["job_id"])
        except (ValidationError, ConflictError):
            return fail(error_kind="invalid_effect_receipt", retryable=False)

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
