#!/usr/bin/env python3
"""Fail-closed, receipt-authoritative Recorder Next file release operator.

The operator is deliberately a non-stdlib name.  It owns only the exact file
cohort described by a frozen transaction manifest.  All state-changing paths
use held directory descriptors after the manifest and opening vector have
been validated.  No live invocation is performed by the repository tests;
fixture roots are used instead.
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping


SCHEMA = "recorder-next-transaction/v1"
RECEIPT_SCHEMA = "recorder-next-transaction-receipt/v1"
JOURNAL_SCHEMA = "recorder-next-transaction-journal/v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
MODE = re.compile(r"^[0-7]{4}$")


class OperatorError(RuntimeError):
    """A controlled fail-closed operator error."""


class InjectedFault(OperatorError):
    """A deterministic fixture fault used by the regression matrix."""

    def __init__(self, point: str, index: int):
        self.point = point
        self.index = index
        super().__init__(f"injected fault at {point}:{index}")


@dataclass(frozen=True)
class Context:
    manifest_path: Path
    manifest_sha256: str
    manifest: dict[str, Any]
    stage_root: Path
    live_root: Path
    receipts_root: Path
    state_root: Path
    apply_leaf: str
    rollback_leaf: str
    journal_leaf: str
    lock_leaf: str
    operator_sha256: str


@dataclass
class OpenRoots:
    stage: int
    live: int
    receipts: int
    state: int
    lock: int | None = None

    def close(self) -> None:
        for fd in (self.lock, self.state, self.receipts, self.live, self.stage):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.lock = None


_TEMP_COUNTER = 0


def _next_temp(prefix: str) -> str:
    global _TEMP_COUNTER
    _TEMP_COUNTER += 1
    return f".{prefix}.{os.getpid()}.{_TEMP_COUNTER}"


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _strict_load_bytes(data: bytes) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OperatorError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise OperatorError(f"non-finite JSON constant: {value}")

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except OperatorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorError(f"invalid JSON: {exc}") from None


def _strict_load_path(path: Path) -> Any:
    _require_regular(path, "manifest")
    return _strict_load_bytes(path.read_bytes())


def _require_regular(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise OperatorError(f"{label} is missing or unreadable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OperatorError(f"{label} must be a regular non-symlink file")
    return info


def _require_directory(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise OperatorError(f"{label} is missing or unreadable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OperatorError(f"{label} must be a real directory")
    return info


def _absolute_clean(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or not os.path.isabs(value):
        raise OperatorError(f"{label} must be an absolute path")
    path = Path(value)
    if path != path.resolve():
        raise OperatorError(f"{label} must be canonical and symlink-free")
    return path


def _safe_leaf(value: Any, label: str) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value) or value in {".", ".."}:
        raise OperatorError(f"{label} must be one bounded leaf name")
    return value


def _safe_relative(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value or "\x00" in value:
        raise OperatorError(f"{label} must be a relative POSIX path")
    pure = PurePosixPath(value)
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise OperatorError(f"{label} contains an unsafe path component")
    if any("\x00" in part for part in parts):
        raise OperatorError(f"{label} contains NUL")
    return tuple(parts)


def _mode_text(value: Any, label: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not MODE.fullmatch(value):
        raise OperatorError(f"{label} must be a four-digit octal mode")
    return value


def _hash_text(value: Any, label: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise OperatorError(f"{label} must be a lowercase SHA-256")
    return value


def _identity_keys(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"exists", "mode", "size", "sha256", "dev", "ino"}:
        raise OperatorError(f"{label} identity schema mismatch")
    if not isinstance(value["exists"], bool):
        raise OperatorError(f"{label}.exists must be boolean")
    if value["exists"]:
        _mode_text(value["mode"], f"{label}.mode")
        _hash_text(value["sha256"], f"{label}.sha256")
        if not isinstance(value["size"], int) or value["size"] < 0:
            raise OperatorError(f"{label}.size must be non-negative integer")
        if not isinstance(value["dev"], int) or value["dev"] < 0 or not isinstance(value["ino"], int) or value["ino"] < 0:
            raise OperatorError(f"{label} device/inode must be non-negative integers")
    else:
        if any(value[key] is not None for key in ("mode", "size", "sha256", "dev", "ino")):
            raise OperatorError(f"{label} absent identity must contain null fields")
    return value


def _spec_keys(value: Any, label: str, *, preimage: bool) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OperatorError(f"{label} must be an object")
    expected = {"exists", "mode", "sha256"} if preimage else {"mode", "sha256"}
    if set(value) != expected:
        raise OperatorError(f"{label} keys differ")
    if preimage:
        if not isinstance(value["exists"], bool):
            raise OperatorError(f"{label}.exists must be boolean")
        _mode_text(value["mode"], f"{label}.mode", allow_none=not value["exists"])
        _hash_text(value["sha256"], f"{label}.sha256", allow_none=not value["exists"])
        if not value["exists"] and (value["mode"] is not None or value["sha256"] is not None):
            raise OperatorError(f"{label} absent spec must contain null fields")
    else:
        _mode_text(value["mode"], f"{label}.mode")
        _hash_text(value["sha256"], f"{label}.sha256")
    return value


def _validate_manifest_shape(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise OperatorError("manifest must be an object")
    expected = {"schema", "generation", "candidate", "operator_sha256", "runtime", "roots", "receipts", "targets"}
    if set(data) != expected:
        raise OperatorError("manifest top-level keys differ")
    if data["schema"] != SCHEMA or not isinstance(data["generation"], str) or not NAME.fullmatch(data["generation"]):
        raise OperatorError("manifest schema or generation mismatch")
    candidate = data["candidate"]
    if not isinstance(candidate, dict) or set(candidate) != {"id", "sha256", "product_sha256"}:
        raise OperatorError("candidate identity keys differ")
    if not isinstance(candidate["id"], str) or not candidate["id"] or "/" in candidate["id"] or "\\" in candidate["id"]:
        raise OperatorError("candidate id is unsafe")
    _hash_text(candidate["sha256"], "candidate.sha256")
    _hash_text(candidate["product_sha256"], "candidate.product_sha256")
    operator_sha256 = _hash_text(data["operator_sha256"], "operator_sha256")
    assert operator_sha256 is not None

    runtime = data["runtime"]
    if not isinstance(runtime, dict) or set(runtime) != {"python", "module", "unit", "exec_start"}:
        raise OperatorError("runtime identity keys differ")
    runtime_python = runtime["python"]
    if not isinstance(runtime_python, str) or not runtime_python or not os.path.isabs(runtime_python):
        raise OperatorError("runtime.python must be an absolute path")
    resolved_python = Path(runtime_python).resolve()
    if not resolved_python.is_file() or not os.access(resolved_python, os.X_OK):
        raise OperatorError("runtime.python must resolve to an executable")
    for key in ("module", "unit", "exec_start"):
        if not isinstance(runtime[key], str) or not runtime[key] or "\x00" in runtime[key]:
            raise OperatorError(f"runtime.{key} is invalid")
    if not NAME.fullmatch(runtime["module"]):
        raise OperatorError("runtime.module is invalid")

    roots = data["roots"]
    if not isinstance(roots, dict) or set(roots) != {"stage", "live", "receipts", "state"}:
        raise OperatorError("root keys differ")
    root_paths = {key: _absolute_clean(roots[key], f"roots.{key}") for key in roots}
    if len(set(root_paths.values())) != 4:
        raise OperatorError("manifest roots must be distinct")

    receipts = data["receipts"]
    if not isinstance(receipts, dict) or set(receipts) != {"apply", "rollback", "journal", "lock"}:
        raise OperatorError("receipt keys differ")
    for key in receipts:
        _safe_leaf(receipts[key], f"receipts.{key}")
    if len(set(receipts.values())) != 4:
        raise OperatorError("receipt leaves must be distinct")

    targets = data["targets"]
    if not isinstance(targets, list) or not targets:
        raise OperatorError("targets must be a non-empty list")
    previous_target = ""
    seen_targets: set[str] = set()
    seen_sources: set[str] = set()
    for index, row in enumerate(targets):
        label = f"targets[{index}]"
        if not isinstance(row, dict) or set(row) != {"target", "source", "preimage", "postimage"}:
            raise OperatorError(f"{label} keys differ")
        _safe_relative(row["target"], f"{label}.target")
        _safe_relative(row["source"], f"{label}.source")
        if row["target"] in seen_targets or row["source"] in seen_sources:
            raise OperatorError("target/source duplicates are forbidden")
        seen_targets.add(row["target"])
        seen_sources.add(row["source"])
        if row["target"] <= previous_target:
            raise OperatorError("targets must be in strict lexical order")
        previous_target = row["target"]
        _spec_keys(row["preimage"], f"{label}.preimage", preimage=True)
        _spec_keys(row["postimage"], f"{label}.postimage", preimage=False)
    return data


def load_context(
    manifest_path: Path,
    expected_manifest_sha256: str,
    *,
    operator_sha256: str | None = None,
    overrides: Mapping[str, Path] | None = None,
) -> Context:
    if not HEX64.fullmatch(expected_manifest_sha256):
        raise OperatorError("manifest SHA-256 argument is invalid")
    manifest_path = manifest_path.absolute()
    manifest_info = _require_regular(manifest_path, "manifest")
    data_bytes = manifest_path.read_bytes()
    actual_manifest_sha256 = digest_bytes(data_bytes)
    if actual_manifest_sha256 != expected_manifest_sha256:
        raise OperatorError("manifest SHA-256 mismatch")
    data = _validate_manifest_shape(_strict_load_bytes(data_bytes))
    actual_operator_sha256 = digest(Path(__file__).resolve())
    declared_operator_sha256 = data["operator_sha256"]
    if declared_operator_sha256 != actual_operator_sha256:
        raise OperatorError("operator identity mismatch")
    if operator_sha256 is not None and operator_sha256 != actual_operator_sha256:
        raise OperatorError("operator SHA-256 argument mismatch")
    roots = {key: Path(data["roots"][key]) for key in ("stage", "live", "receipts", "state")}
    if overrides:
        for key, value in overrides.items():
            if key not in roots:
                raise OperatorError(f"unknown root override: {key}")
            value = value.absolute()
            if value != roots[key]:
                raise OperatorError(f"{key} root override differs from manifest")
    for key, path in roots.items():
        _require_directory(path, f"{key} root")
    receipts = data["receipts"]
    # Keep the actual manifest inode authoritative through this call.  The
    # path is only used for the manifest itself; target authority is dirfd based.
    if manifest_info.st_ino <= 0:
        raise OperatorError("manifest identity is invalid")
    return Context(
        manifest_path=manifest_path,
        manifest_sha256=actual_manifest_sha256,
        manifest=data,
        stage_root=roots["stage"],
        live_root=roots["live"],
        receipts_root=roots["receipts"],
        state_root=roots["state"],
        apply_leaf=receipts["apply"],
        rollback_leaf=receipts["rollback"],
        journal_leaf=receipts["journal"],
        lock_leaf=receipts["lock"],
        operator_sha256=actual_operator_sha256,
    )


def _open_root(path: Path, label: str) -> int:
    before = _require_directory(path, label)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise OperatorError(f"{label} could not be opened safely") from exc
    try:
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise OperatorError(f"{label} changed during open")
        os.set_inheritable(fd, False)
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_parent(root_fd: int, relative: str, label: str) -> tuple[int, str]:
    parts = _safe_relative(relative, label)
    fd = os.dup(root_fd)
    os.set_inheritable(fd, False)
    try:
        for component in parts[:-1]:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                child = os.open(component, flags, dir_fd=fd)
            except OSError as exc:
                raise OperatorError(f"{label} parent is missing or unsafe") from exc
            os.close(fd)
            fd = child
            os.set_inheritable(fd, False)
        return fd, parts[-1]
    except Exception:
        os.close(fd)
        raise


def _stat_at(parent_fd: int, leaf: str) -> os.stat_result | None:
    try:
        return os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OperatorError(f"cannot inspect bounded leaf {leaf}") from exc


def _read_at(parent_fd: int, leaf: str, label: str) -> tuple[bytes, os.stat_result]:
    info = _stat_at(parent_fd, leaf)
    if info is None:
        raise OperatorError(f"{label} is missing")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OperatorError(f"{label} is not a regular non-symlink file")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(leaf, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise OperatorError(f"{label} could not be opened") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise OperatorError(f"{label} changed during open")
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks), opened
    except OSError as exc:
        raise OperatorError(f"{label} could not be read") from exc
    finally:
        os.close(fd)


def _image_at(parent_fd: int, leaf: str, label: str) -> dict[str, Any]:
    info = _stat_at(parent_fd, leaf)
    if info is None:
        return {"exists": False, "mode": None, "size": None, "sha256": None, "dev": None, "ino": None}
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OperatorError(f"{label} is a foreign or unsafe non-regular object")
    data, opened = _read_at(parent_fd, leaf, label)
    return {
        "exists": True,
        "mode": f"{stat.S_IMODE(opened.st_mode):04o}",
        "size": opened.st_size,
        "sha256": digest_bytes(data),
        "dev": opened.st_dev,
        "ino": opened.st_ino,
    }


def _spec_matches(image: Mapping[str, Any], spec: Mapping[str, Any]) -> bool:
    if bool(spec.get("exists", True)) != bool(image.get("exists")):
        return False
    if not image.get("exists"):
        return True
    return image.get("mode") == spec.get("mode") and image.get("sha256") == spec.get("sha256")


def _identity_matches(image: Mapping[str, Any], expected: Mapping[str, Any], *, include_inode: bool = True) -> bool:
    if image.get("exists") != expected.get("exists"):
        return False
    if not image.get("exists"):
        return True
    fields = ("mode", "size", "sha256", "dev", "ino") if include_inode else ("mode", "size", "sha256")
    return all(image.get(key) == expected.get(key) for key in fields)


def _opening_identity(image: Mapping[str, Any]) -> dict[str, Any]:
    return {key: image.get(key) for key in ("exists", "mode", "size", "sha256", "dev", "ino")}


def _validate_source_rows(ctx: Context, roots: OpenRoots) -> list[bytes]:
    sources: list[bytes] = []
    for index, row in enumerate(ctx.manifest["targets"]):
        parent_fd, leaf = _open_parent(roots.stage, row["source"], f"source[{index}]")
        try:
            data, _ = _read_at(parent_fd, leaf, f"source[{index}]")
        finally:
            os.close(parent_fd)
        if digest_bytes(data) != row["postimage"]["sha256"]:
            raise OperatorError(f"source[{index}] hash does not match frozen postimage")
        sources.append(data)
    return sources


def _validate_opening_rows(ctx: Context, roots: OpenRoots) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(ctx.manifest["targets"]):
        parent_fd, leaf = _open_parent(roots.live, row["target"], f"target[{index}]")
        try:
            image = _image_at(parent_fd, leaf, f"target[{index}]")
        finally:
            os.close(parent_fd)
        if not _spec_matches(image, row["preimage"]):
            raise OperatorError(f"target[{index}] opening preimage mismatch")
        rows.append(_opening_identity(image))
    return rows


def _assert_target_image(ctx: Context, roots: OpenRoots, row: Mapping[str, Any], index: int, expected: Mapping[str, Any], label: str, *, include_inode: bool = True) -> dict[str, Any]:
    parent_fd, leaf = _open_parent(roots.live, str(row["target"]), f"{label}[{index}]")
    try:
        image = _image_at(parent_fd, leaf, f"{label}[{index}]")
    finally:
        os.close(parent_fd)
    if not _identity_matches(image, expected, include_inode=include_inode):
        raise OperatorError(f"{label}[{index}] identity drift")
    return image


def _fault(point: str, index: int) -> None:
    wanted = os.environ.get("RECORDER_OP_FAULT", "")
    if wanted == f"sigint_{point}:{index}":
        os.kill(os.getpid(), signal.SIGINT)
    if wanted == f"sigterm_{point}:{index}":
        os.kill(os.getpid(), signal.SIGTERM)
    if wanted == f"kill_{point}:{index}":
        os.kill(os.getpid(), signal.SIGKILL)
    if wanted == f"{point}:{index}":
        raise InjectedFault(point, index)


def _write_temp_at(parent_fd: int, data: bytes, mode: int, prefix: str) -> tuple[str, os.stat_result]:
    leaf = _next_temp(prefix)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(leaf, flags, mode, dir_fd=parent_fd)
    except OSError as exc:
        raise OperatorError(f"cannot create bounded temporary {prefix}") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OperatorError(f"short write for {prefix}")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
        info = os.fstat(fd)
        return leaf, info
    except OSError as exc:
        raise OperatorError(f"cannot write bounded temporary {prefix}") from exc
    finally:
        os.close(fd)


def _replace_file_at(
    parent_fd: int,
    leaf: str,
    data: bytes,
    mode: int,
    expected: Mapping[str, Any],
    *,
    fault_index: int,
    fault_point: str,
) -> dict[str, Any]:
    before = _image_at(parent_fd, leaf, f"target {leaf}")
    if not _identity_matches(before, expected, include_inode=True):
        raise OperatorError(f"target {leaf} changed before replacement")
    temp_leaf = ""
    try:
        temp_leaf, _ = _write_temp_at(parent_fd, data, mode, leaf)
        try:
            os.replace(temp_leaf, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except OSError as exc:
            raise OperatorError(f"cannot atomically replace target {leaf}") from exc
        _fault(fault_point, fault_index)
        os.fsync(parent_fd)
    finally:
        if temp_leaf:
            try:
                os.unlink(temp_leaf, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
    return _image_at(parent_fd, leaf, f"target {leaf}")


def _unlink_at(parent_fd: int, leaf: str, expected: Mapping[str, Any], index: int) -> None:
    before = _image_at(parent_fd, leaf, f"target {leaf}")
    if not _identity_matches(before, expected, include_inode=True):
        raise OperatorError(f"target {leaf} changed before removal")
    try:
        os.unlink(leaf, dir_fd=parent_fd)
        _fault("rollback_after_unlink", index)
        os.fsync(parent_fd)
    except FileNotFoundError as exc:
        raise OperatorError(f"target {leaf} disappeared during removal") from exc
    except OSError as exc:
        raise OperatorError(f"cannot remove target {leaf}") from exc


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _read_json_at(parent_fd: int, leaf: str, label: str) -> tuple[dict[str, Any], os.stat_result, bytes]:
    raw, info = _read_at(parent_fd, leaf, label)
    value = _strict_load_bytes(raw)
    if not isinstance(value, dict):
        raise OperatorError(f"{label} must contain an object")
    return value, info, raw


def _write_json_replace_at(parent_fd: int, leaf: str, value: dict[str, Any], label: str) -> os.stat_result:
    existing = _stat_at(parent_fd, leaf)
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
            raise OperatorError(f"{label} is foreign")
    temp_leaf = ""
    try:
        temp_leaf, _ = _write_temp_at(parent_fd, _json_bytes(value), 0o600, leaf)
        os.replace(temp_leaf, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise OperatorError(f"cannot update {label}") from exc
    finally:
        if temp_leaf:
            try:
                os.unlink(temp_leaf, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
    info = _stat_at(parent_fd, leaf)
    if info is None:
        raise OperatorError(f"{label} disappeared after update")
    return info


def _write_json_exclusive_at(parent_fd: int, leaf: str, value: dict[str, Any], label: str) -> os.stat_result:
    if _stat_at(parent_fd, leaf) is not None:
        raise OperatorError(f"{label} already exists")
    temp_leaf = ""
    try:
        temp_leaf, _ = _write_temp_at(parent_fd, _json_bytes(value), 0o600, leaf)
        try:
            os.link(temp_leaf, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        except FileExistsError as exc:
            raise OperatorError(f"{label} collision") from exc
        os.unlink(temp_leaf, dir_fd=parent_fd)
        temp_leaf = ""
        os.fsync(parent_fd)
    except OSError as exc:
        raise OperatorError(f"cannot publish {label}") from exc
    finally:
        if temp_leaf:
            try:
                os.unlink(temp_leaf, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
    info = _stat_at(parent_fd, leaf)
    if info is None:
        raise OperatorError(f"{label} disappeared after publication")
    return info


def _delete_at(parent_fd: int, leaf: str, label: str) -> None:
    try:
        os.unlink(leaf, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OperatorError(f"cannot remove {label}") from exc


def _history_leaf(leaf: str, transaction_id: str) -> str:
    stem, suffix = leaf.rsplit(".", 1)
    return _safe_leaf(f"{stem}.history-{transaction_id[:24]}.{suffix}", "terminal history leaf")


def _archive_owned_leaf(
    parent_fd: int,
    leaf: str,
    expected_identity: Mapping[str, Any],
    transaction_id: str,
    label: str,
) -> str:
    current = _stat_at(parent_fd, leaf)
    if current is None or not _same_receipt_identity(current, expected_identity):
        raise OperatorError(f"HOLD: foreign or same-byte/different-inode {label}")
    history_leaf = _history_leaf(leaf, transaction_id)
    history = _stat_at(parent_fd, history_leaf)
    if history is None:
        try:
            os.link(leaf, history_leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        except FileExistsError:
            history = _stat_at(parent_fd, history_leaf)
        except OSError as exc:
            raise OperatorError(f"cannot archive {label}") from exc
        if history is None:
            history = _stat_at(parent_fd, history_leaf)
    if history is None or not _same_receipt_identity(history, expected_identity):
        raise OperatorError(f"HOLD: terminal history collision for {label}")
    try:
        os.unlink(leaf, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileNotFoundError as exc:
        raise OperatorError(f"HOLD: {label} disappeared during archival") from exc
    except OSError as exc:
        raise OperatorError(f"cannot retire {label}") from exc
    return history_leaf


def _receipt_identity(info: os.stat_result) -> dict[str, int]:
    return {"dev": int(info.st_dev), "ino": int(info.st_ino)}


def _same_receipt_identity(info: os.stat_result, identity: Mapping[str, Any] | None) -> bool:
    return isinstance(identity, Mapping) and info.st_dev == identity.get("dev") and info.st_ino == identity.get("ino")


def _transaction_id(ctx: Context, reapply_index: int = 0) -> str:
    material = "\0".join((ctx.manifest["generation"], ctx.manifest["candidate"]["id"], ctx.manifest_sha256)).encode()
    base = hashlib.sha256(material).hexdigest()
    if reapply_index == 0:
        return base
    if reapply_index < 0:
        raise OperatorError("reapply transaction index is invalid")
    return hashlib.sha256(f"{base}\0reapply\0{reapply_index}\0".encode()).hexdigest()


def _journal_authority_leaf(ctx: Context) -> str:
    return _safe_leaf(f"{ctx.journal_leaf}.authority", "transaction journal authority")


def _journal_rows(ctx: Context, opening: list[dict[str, Any]], transaction_id: str | None = None) -> list[dict[str, Any]]:
    txid = transaction_id or _transaction_id(ctx)
    result: list[dict[str, Any]] = []
    for index, (row, identity) in enumerate(zip(ctx.manifest["targets"], opening, strict=True)):
        result.append(
            {
                "target": row["target"],
                "source": row["source"],
                "preimage": row["preimage"],
                "postimage": row["postimage"],
                "opening_identity": identity,
                "applied_identity": None,
                "restored_identity": None,
                "backup": f"backup-{txid[:24]}-{index:04d}.bin" if row["preimage"]["exists"] else None,
            }
        )
    return result


def _new_journal(
    ctx: Context,
    action: str,
    rows: list[dict[str, Any]],
    phase: str,
    *,
    transaction_id: str | None = None,
    reapply_index: int = 0,
) -> dict[str, Any]:
    if transaction_id is None:
        transaction_id = _transaction_id(ctx, reapply_index)
    return {
        "schema": JOURNAL_SCHEMA,
        "action": action,
        "phase": phase,
        "transaction_id": transaction_id,
        "reapply_index": reapply_index,
        "generation": ctx.manifest["generation"],
        "candidate_id": ctx.manifest["candidate"]["id"],
        "candidate_sha256": ctx.manifest["candidate"]["sha256"],
        "manifest_sha256": ctx.manifest_sha256,
        "operator_sha256": ctx.operator_sha256,
        "journal_leaf": ctx.journal_leaf,
        "apply_leaf": ctx.apply_leaf,
        "rollback_leaf": ctx.rollback_leaf,
        "rows": rows,
        "applied_indices": [],
        "rollback_indices": [],
        "receipt_identity": None,
        "receipt_sha256": None,
        "rollback_receipt_identity": None,
        "rollback_receipt_sha256": None,
    }


def _validate_journal(ctx: Context, value: Any) -> dict[str, Any]:
    expected_keys = {
        "schema", "action", "phase", "transaction_id", "reapply_index", "generation", "candidate_id", "candidate_sha256",
        "manifest_sha256", "operator_sha256", "journal_leaf", "apply_leaf", "rollback_leaf", "rows",
        "applied_indices", "rollback_indices", "receipt_identity", "receipt_sha256", "rollback_receipt_identity",
        "rollback_receipt_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise OperatorError("transaction journal schema mismatch")
    if value["schema"] != JOURNAL_SCHEMA or value["generation"] != ctx.manifest["generation"]:
        raise OperatorError("transaction journal identity mismatch")
    if value["candidate_id"] != ctx.manifest["candidate"]["id"] or value["candidate_sha256"] != ctx.manifest["candidate"]["sha256"]:
        raise OperatorError("transaction journal candidate mismatch")
    if value["manifest_sha256"] != ctx.manifest_sha256 or value["operator_sha256"] != ctx.operator_sha256:
        raise OperatorError("transaction journal authority mismatch")
    if value["journal_leaf"] != ctx.journal_leaf or value["apply_leaf"] != ctx.apply_leaf or value["rollback_leaf"] != ctx.rollback_leaf:
        raise OperatorError("transaction journal receipt leaves mismatch")
    if value["action"] not in {"apply", "rollback"} or value["phase"] not in {
        "PREPARED", "BACKUPS_READY", "APPLYING", "TARGETS_APPLIED", "RECEIPT_PUBLISHED", "APPLY_COMMITTED", "ROLLBACKING", "ROLLBACK_COMMITTED",
    }:
        raise OperatorError("transaction journal phase is invalid")
    reapply_index = value["reapply_index"]
    if not isinstance(reapply_index, int) or isinstance(reapply_index, bool) or reapply_index < 0:
        raise OperatorError("transaction journal reapply index is invalid")
    txid = _transaction_id(ctx, reapply_index)
    if value["transaction_id"] != txid:
        raise OperatorError("transaction journal transaction id mismatch")
    rows = value["rows"]
    if not isinstance(rows, list) or len(rows) != len(ctx.manifest["targets"]):
        raise OperatorError("transaction journal row count mismatch")
    for index, (actual, expected) in enumerate(zip(rows, ctx.manifest["targets"], strict=True)):
        required = {"target", "source", "preimage", "postimage", "opening_identity", "applied_identity", "restored_identity", "backup"}
        if not isinstance(actual, dict) or set(actual) != required:
            raise OperatorError(f"transaction journal row {index} schema mismatch")
        for key in ("target", "source", "preimage", "postimage"):
            if actual[key] != expected[key]:
                raise OperatorError(f"transaction journal row {index} authority mismatch")
        _identity_keys(actual["opening_identity"], f"journal row {index}.opening_identity")
        for key in ("applied_identity", "restored_identity"):
            if actual[key] is not None:
                _identity_keys(actual[key], f"journal row {index}.{key}")
        if actual["backup"] is not None:
            _safe_leaf(actual["backup"], f"journal row {index}.backup")
        if expected["preimage"]["exists"] != (actual["backup"] is not None):
            raise OperatorError(f"transaction journal row {index} backup authority mismatch")
    for key in ("applied_indices", "rollback_indices"):
        values = value[key]
        if not isinstance(values, list) or any(not isinstance(item, int) or item < 0 or item >= len(rows) for item in values) or len(set(values)) != len(values):
            raise OperatorError(f"transaction journal {key} is invalid")
    for key in ("receipt_sha256", "rollback_receipt_sha256"):
        if value[key] is not None:
            _hash_text(value[key], f"journal.{key}")
    for key in ("receipt_identity", "rollback_receipt_identity"):
        identity = value[key]
        if identity is not None and (not isinstance(identity, dict) or set(identity) != {"dev", "ino"} or not all(isinstance(identity[k], int) and identity[k] >= 0 for k in identity)):
            raise OperatorError(f"journal.{key} is invalid")
    return value


def _journal_read(ctx: Context, roots: OpenRoots) -> tuple[dict[str, Any], os.stat_result, bytes] | None:
    parent_fd, leaf = _open_parent(roots.state, ctx.journal_leaf, "transaction journal")
    try:
        info = _stat_at(parent_fd, leaf)
        if info is None:
            return None
        value, info, raw = _read_json_at(parent_fd, leaf, "transaction journal")
        authority_leaf = _journal_authority_leaf(ctx)
        authority_info = _stat_at(parent_fd, authority_leaf)
        if authority_info is None or stat.S_ISLNK(authority_info.st_mode) or not stat.S_ISREG(authority_info.st_mode):
            raise OperatorError("HOLD: transaction journal inode authority is missing")
        if (authority_info.st_dev, authority_info.st_ino) != (info.st_dev, info.st_ino):
            raise OperatorError("HOLD: foreign or same-byte/different-inode transaction journal")
        return _validate_journal(ctx, value), info, raw
    finally:
        os.close(parent_fd)


def _write_json_in_place_at(parent_fd: int, leaf: str, value: dict[str, Any], label: str) -> os.stat_result:
    """Update an owned journal without changing its inode.

    The companion hard link is the durable inode authority.  Replacing the
    primary name with a same-byte file must therefore be distinguishable after
    a crash or a fresh-process re-entry.
    """
    expected = _stat_at(parent_fd, leaf)
    if expected is None or stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
        raise OperatorError(f"HOLD: {label} is missing or foreign")
    raw = _json_bytes(value)
    try:
        fd = os.open(leaf, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as exc:
        raise OperatorError(f"cannot open owned {label}") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise OperatorError(f"HOLD: {label} changed during update")
        view = memoryview(raw)
        os.ftruncate(fd, 0)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OperatorError(f"short write for {label}")
            view = view[written:]
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        result = os.fstat(fd)
    except OSError as exc:
        raise OperatorError(f"cannot update owned {label}") from exc
    finally:
        os.close(fd)
    os.fsync(parent_fd)
    return result


def _journal_write(ctx: Context, roots: OpenRoots, journal: dict[str, Any], *, exclusive: bool = False) -> os.stat_result:
    _validate_journal(ctx, journal)
    parent_fd, leaf = _open_parent(roots.state, ctx.journal_leaf, "transaction journal")
    try:
        if exclusive:
            info = _write_json_exclusive_at(parent_fd, leaf, journal, "transaction journal")
            authority_leaf = _journal_authority_leaf(ctx)
            try:
                os.link(leaf, authority_leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            except FileExistsError as exc:
                raise OperatorError("HOLD: transaction journal authority collision") from exc
            except OSError as exc:
                raise OperatorError("cannot publish transaction journal authority") from exc
            os.fsync(parent_fd)
            return info
        authority_leaf = _journal_authority_leaf(ctx)
        current = _stat_at(parent_fd, leaf)
        authority = _stat_at(parent_fd, authority_leaf)
        if current is None or authority is None or (current.st_dev, current.st_ino) != (authority.st_dev, authority.st_ino):
            raise OperatorError("HOLD: foreign or same-byte/different-inode transaction journal")
        return _write_json_in_place_at(parent_fd, leaf, journal, "transaction journal")
    finally:
        os.close(parent_fd)


def _read_receipt(ctx: Context, roots: OpenRoots, leaf: str, label: str) -> tuple[dict[str, Any], os.stat_result, bytes] | None:
    parent_fd, actual_leaf = _open_parent(roots.receipts, leaf, label)
    try:
        info = _stat_at(parent_fd, actual_leaf)
        if info is None:
            return None
        return (*_read_json_at(parent_fd, actual_leaf, label),)
    finally:
        os.close(parent_fd)


def _receipt_rows(ctx: Context, journal: Mapping[str, Any], *, action: str) -> list[dict[str, Any]]:
    return [
        {
            "target": row["target"],
            "source": row["source"],
            "preimage": row["preimage"],
            "postimage": row["postimage"],
            "opening_identity": row["opening_identity"],
            "applied_identity": row["applied_identity"],
            "restored_identity": row["restored_identity"] if action == "rollback" else None,
            "backup": row["backup"],
        }
        for row in journal["rows"]
    ]


def _new_apply_receipt(ctx: Context, journal: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "action": "apply",
        "status": "COMMITTED",
        "generation": ctx.manifest["generation"],
        "candidate_id": ctx.manifest["candidate"]["id"],
        "candidate_sha256": ctx.manifest["candidate"]["sha256"],
        "manifest_sha256": ctx.manifest_sha256,
        "operator_sha256": ctx.operator_sha256,
        "transaction_id": journal["transaction_id"],
        "receipt_leaf": ctx.apply_leaf,
        "journal_leaf": ctx.journal_leaf,
        "rows": _receipt_rows(ctx, journal, action="apply"),
    }


def _new_rollback_receipt(ctx: Context, journal: Mapping[str, Any], apply_receipt_sha256: str) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "action": "rollback",
        "status": "COMMITTED",
        "generation": ctx.manifest["generation"],
        "candidate_id": ctx.manifest["candidate"]["id"],
        "candidate_sha256": ctx.manifest["candidate"]["sha256"],
        "manifest_sha256": ctx.manifest_sha256,
        "operator_sha256": ctx.operator_sha256,
        "transaction_id": journal["transaction_id"],
        "receipt_leaf": ctx.rollback_leaf,
        "journal_leaf": ctx.journal_leaf,
        "apply_receipt_sha256": apply_receipt_sha256,
        "rows": _receipt_rows(ctx, journal, action="rollback"),
    }


def _validate_receipt(ctx: Context, value: Any, *, action: str, leaf: str, journal: Mapping[str, Any], apply_receipt_sha256: str | None = None) -> dict[str, Any]:
    expected = {
        "schema", "action", "status", "generation", "candidate_id", "candidate_sha256", "manifest_sha256", "operator_sha256",
        "transaction_id", "receipt_leaf", "journal_leaf", "rows",
    }
    if action == "rollback":
        expected.add("apply_receipt_sha256")
    if not isinstance(value, dict) or set(value) != expected:
        raise OperatorError(f"{action} receipt schema mismatch")
    if value["schema"] != RECEIPT_SCHEMA or value["action"] != action or value["status"] != "COMMITTED":
        raise OperatorError(f"{action} receipt status mismatch")
    if value["generation"] != ctx.manifest["generation"] or value["candidate_id"] != ctx.manifest["candidate"]["id"] or value["candidate_sha256"] != ctx.manifest["candidate"]["sha256"]:
        raise OperatorError(f"{action} receipt candidate mismatch")
    if value["manifest_sha256"] != ctx.manifest_sha256 or value["operator_sha256"] != ctx.operator_sha256:
        raise OperatorError(f"{action} receipt authority mismatch")
    if value["transaction_id"] != journal["transaction_id"] or value["receipt_leaf"] != leaf or value["journal_leaf"] != ctx.journal_leaf:
        raise OperatorError(f"{action} receipt lineage mismatch")
    if action == "rollback" and value["apply_receipt_sha256"] != apply_receipt_sha256:
        raise OperatorError("rollback receipt apply lineage mismatch")
    if value["rows"] != _receipt_rows(ctx, journal, action=action):
        raise OperatorError(f"{action} receipt row vector mismatch")
    return value


def _publish_receipt(ctx: Context, roots: OpenRoots, leaf: str, value: dict[str, Any], label: str, journal_identity: Mapping[str, Any] | None) -> tuple[str, dict[str, int]]:
    raw = _json_bytes(value)
    parent_fd, actual_leaf = _open_parent(roots.receipts, leaf, label)
    try:
        existing = _stat_at(parent_fd, actual_leaf)
        if existing is not None:
            existing_raw, info = _read_at(parent_fd, actual_leaf, label)
            if existing_raw != raw or not _same_receipt_identity(info, journal_identity):
                raise OperatorError(f"HOLD: foreign or same-byte/different-inode {label}")
            return digest_bytes(existing_raw), _receipt_identity(info)
        info = _write_json_exclusive_at(parent_fd, actual_leaf, value, label)
        return digest_bytes(raw), _receipt_identity(info)
    finally:
        os.close(parent_fd)


def _read_owned_receipt(ctx: Context, roots: OpenRoots, leaf: str, label: str, journal: Mapping[str, Any], *, action: str, apply_receipt_sha256: str | None = None, identity_key: str) -> tuple[dict[str, Any], str]:
    parent_fd, actual_leaf = _open_parent(roots.receipts, leaf, label)
    try:
        value, info, raw = _read_json_at(parent_fd, actual_leaf, label)
        expected_identity = journal[identity_key]
        if not _same_receipt_identity(info, expected_identity):
            raise OperatorError(f"HOLD: foreign or same-byte/different-inode {label}")
        parsed = _validate_receipt(ctx, value, action=action, leaf=leaf, journal=journal, apply_receipt_sha256=apply_receipt_sha256)
        return parsed, digest_bytes(raw)
    finally:
        os.close(parent_fd)


def _archive_terminal_transaction(ctx: Context, roots: OpenRoots, journal: Mapping[str, Any]) -> int:
    """Retire a completed rollback before starting a fresh apply transaction.

    The fixed receipt and journal leaves are the current transaction namespace
    used by the sealed packet.  A reapply must not overwrite those leaves in
    place: first validate both terminal receipts, hard-link each owned inode to
    a transaction-specific history leaf, and then remove only the old primary
    names.  The new journal therefore starts with fresh inode authorities while
    the prior terminal evidence remains inspectable.
    """
    if journal["phase"] != "ROLLBACK_COMMITTED":
        raise OperatorError("HOLD: only a committed rollback may be re-applied")
    apply_receipt, apply_sha = _read_owned_receipt(
        ctx,
        roots,
        ctx.apply_leaf,
        "apply receipt",
        journal,
        action="apply",
        identity_key="receipt_identity",
    )
    _read_owned_receipt(
        ctx,
        roots,
        ctx.rollback_leaf,
        "rollback receipt",
        journal,
        action="rollback",
        apply_receipt_sha256=apply_sha,
        identity_key="rollback_receipt_identity",
    )
    _assert_all_pre(ctx, roots, journal)
    next_index = journal["reapply_index"] + 1
    next_transaction_id = _transaction_id(ctx, next_index)

    journal_parent_fd, journal_leaf = _open_parent(roots.state, ctx.journal_leaf, "transaction journal")
    try:
        journal_info = _stat_at(journal_parent_fd, journal_leaf)
        if journal_info is None:
            raise OperatorError("HOLD: transaction journal disappeared before reapply")
        _archive_owned_leaf(
            journal_parent_fd,
            journal_leaf,
            _receipt_identity(journal_info),
            next_transaction_id,
            "transaction journal",
        )
        authority_leaf = _journal_authority_leaf(ctx)
        _archive_owned_leaf(
            journal_parent_fd,
            authority_leaf,
            _receipt_identity(journal_info),
            next_transaction_id,
            "transaction journal authority",
        )
    finally:
        os.close(journal_parent_fd)

    receipt_parent_fd, _ = _open_parent(roots.receipts, ctx.apply_leaf, "apply receipt")
    try:
        _archive_owned_leaf(
            receipt_parent_fd,
            ctx.apply_leaf,
            journal["receipt_identity"],
            next_transaction_id,
            "apply receipt",
        )
        _archive_owned_leaf(
            receipt_parent_fd,
            ctx.rollback_leaf,
            journal["rollback_receipt_identity"],
            next_transaction_id,
            "rollback receipt",
        )
    finally:
        os.close(receipt_parent_fd)
    return next_index


def _lock_roots(ctx: Context) -> OpenRoots:
    stage_fd = _open_root(ctx.stage_root, "stage root")
    try:
        live_fd = _open_root(ctx.live_root, "live root")
        try:
            receipts_fd = _open_root(ctx.receipts_root, "receipt root")
            try:
                state_fd = _open_root(ctx.state_root, "state root")
            except Exception:
                os.close(receipts_fd)
                raise
        except Exception:
            os.close(live_fd)
            raise
    except Exception:
        os.close(stage_fd)
        raise
    roots = OpenRoots(stage=stage_fd, live=live_fd, receipts=receipts_fd, state=state_fd)
    parent_fd, leaf = _open_parent(roots.receipts, ctx.lock_leaf, "operator lock")
    try:
        info = _stat_at(parent_fd, leaf)
        if info is None or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise OperatorError("operator lock must be pre-provisioned as a regular file")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise OperatorError("operator lock mode must be 0600")
        fd = os.open(leaf, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        os.set_inheritable(fd, False)
    finally:
        os.close(parent_fd)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError as exc:
        os.close(fd)
        roots.close()
        raise OperatorError("operator lock acquisition failed") from exc
    roots.lock = fd
    return roots


def _read_only_roots(ctx: Context) -> OpenRoots:
    return OpenRoots(
        stage=_open_root(ctx.stage_root, "stage root"),
        live=_open_root(ctx.live_root, "live root"),
        receipts=_open_root(ctx.receipts_root, "receipt root"),
        state=_open_root(ctx.state_root, "state root"),
    )


@contextmanager
def _mutation_roots(ctx: Context) -> Iterator[OpenRoots]:
    roots = _lock_roots(ctx)
    try:
        yield roots
    finally:
        if roots.lock is not None:
            try:
                fcntl.flock(roots.lock, fcntl.LOCK_UN)
            except OSError:
                pass
        roots.close()


@contextmanager
def _verification_roots(ctx: Context) -> Iterator[OpenRoots]:
    roots = _read_only_roots(ctx)
    try:
        yield roots
    finally:
        roots.close()


def _backup_preimages(ctx: Context, roots: OpenRoots, journal: dict[str, Any]) -> None:
    for index, row in enumerate(journal["rows"]):
        backup = row["backup"]
        if backup is None:
            continue
        target_parent, target_leaf = _open_parent(roots.live, row["target"], f"target[{index}]")
        try:
            data, info = _read_at(target_parent, target_leaf, f"target[{index}]")
            if digest_bytes(data) != row["preimage"]["sha256"] or f"{stat.S_IMODE(info.st_mode):04o}" != row["preimage"]["mode"]:
                raise OperatorError(f"target[{index}] preimage changed before backup")
        finally:
            os.close(target_parent)
        state_parent, state_leaf = _open_parent(roots.state, backup, f"backup[{index}]")
        try:
            existing = _stat_at(state_parent, state_leaf)
            if existing is None:
                _write_json_or_bytes_exclusive(state_parent, state_leaf, data, 0o600, f"backup[{index}]")
            else:
                existing_data, existing_info = _read_at(state_parent, state_leaf, f"backup[{index}]")
                if existing_data != data or stat.S_IMODE(existing_info.st_mode) != 0o600:
                    raise OperatorError(f"HOLD: foreign backup[{index}]")
        finally:
            os.close(state_parent)


def _write_json_or_bytes_exclusive(parent_fd: int, leaf: str, data: bytes, mode: int, label: str) -> os.stat_result:
    if _stat_at(parent_fd, leaf) is not None:
        raise OperatorError(f"{label} collision")
    temp_leaf = ""
    try:
        temp_leaf, _ = _write_temp_at(parent_fd, data, mode, leaf)
        os.link(temp_leaf, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        os.unlink(temp_leaf, dir_fd=parent_fd)
        temp_leaf = ""
        os.fsync(parent_fd)
    except OSError as exc:
        raise OperatorError(f"cannot publish {label}") from exc
    finally:
        if temp_leaf:
            try:
                os.unlink(temp_leaf, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
    info = _stat_at(parent_fd, leaf)
    if info is None:
        raise OperatorError(f"{label} disappeared")
    return info


def _backup_bytes(ctx: Context, roots: OpenRoots, row: Mapping[str, Any], index: int) -> bytes:
    backup = row["backup"]
    if backup is None:
        raise OperatorError(f"backup missing for target[{index}]")
    parent_fd, leaf = _open_parent(roots.state, backup, f"backup[{index}]")
    try:
        data, info = _read_at(parent_fd, leaf, f"backup[{index}]")
    finally:
        os.close(parent_fd)
    if stat.S_IMODE(info.st_mode) != 0o600 or digest_bytes(data) != row["preimage"]["sha256"]:
        raise OperatorError(f"backup[{index}] integrity mismatch")
    return data


def _restore_apply_in_process(ctx: Context, roots: OpenRoots, journal: dict[str, Any], *, allow_unbound_post: bool) -> None:
    for index in reversed(range(len(journal["rows"]))):
        row = journal["rows"][index]
        target_parent, target_leaf = _open_parent(roots.live, row["target"], f"target[{index}]")
        try:
            current = _image_at(target_parent, target_leaf, f"target[{index}]")
            post = row["postimage"]
            if _spec_matches(current, post):
                if row["applied_identity"] is not None and not _identity_matches(current, row["applied_identity"], include_inode=True):
                    raise OperatorError(f"HOLD: target[{index}] postimage inode drift during recovery")
                if row["applied_identity"] is None and not allow_unbound_post:
                    raise OperatorError(f"HOLD: target[{index}] postimage ownership is unbound")
                if row["preimage"]["exists"]:
                    data = _backup_bytes(ctx, roots, row, index)
                    _replace_file_at(target_parent, target_leaf, data, int(row["preimage"]["mode"], 8), current, fault_index=index + 1, fault_point="recovery_after_replace")
                else:
                    _unlink_at(target_parent, target_leaf, current, index + 1)
            elif not _spec_matches(current, row["preimage"]):
                raise OperatorError(f"HOLD: target[{index}] is neither frozen preimage nor candidate postimage")
        finally:
            os.close(target_parent)
    journal["phase"] = "PREPARED"
    journal["applied_indices"] = []
    journal["rollback_indices"] = []
    for row in journal["rows"]:
        row["applied_identity"] = None
        row["restored_identity"] = None
    _journal_write(ctx, roots, journal)
    # Active journals are removed only after fresh readback proves the whole
    # opening vector.  This is a local compensation, not blind cleanup.
    _validate_opening_rows(ctx, roots)
    state_parent, state_leaf = _open_parent(roots.state, ctx.journal_leaf, "transaction journal")
    try:
        _delete_at(state_parent, state_leaf, "transaction journal")
        _delete_at(state_parent, _journal_authority_leaf(ctx), "transaction journal authority")
    finally:
        os.close(state_parent)
    for row in journal["rows"]:
        if row["backup"] is not None:
            parent_fd, leaf = _open_parent(roots.state, row["backup"], "backup cleanup")
            try:
                _delete_at(parent_fd, leaf, "backup")
            finally:
                os.close(parent_fd)


def _recover_active_apply(ctx: Context, roots: OpenRoots, journal: dict[str, Any]) -> None:
    if journal["phase"] == "RECEIPT_PUBLISHED":
        if journal["receipt_identity"] is None or journal["receipt_sha256"] is None:
            raise OperatorError("HOLD: receipt publication lacks durable inode authority")
        receipt, receipt_sha = _read_owned_receipt(ctx, roots, ctx.apply_leaf, "apply receipt", journal, action="apply", identity_key="receipt_identity")
        if receipt_sha != journal["receipt_sha256"]:
            raise OperatorError("HOLD: apply receipt hash drift")
        _assert_all_post(ctx, roots, journal)
        journal["phase"] = "APPLY_COMMITTED"
        _journal_write(ctx, roots, journal)
        return
    if journal["phase"] in {"APPLY_COMMITTED", "ROLLBACK_COMMITTED"}:
        return
    pending_receipt = _read_receipt(ctx, roots, ctx.apply_leaf, "apply receipt")
    if pending_receipt is not None:
        raise OperatorError("HOLD: apply receipt exists before durable journal authority")
    _restore_apply_in_process(ctx, roots, journal, allow_unbound_post=False)


def _assert_all_post(ctx: Context, roots: OpenRoots, journal: Mapping[str, Any]) -> None:
    for index, row in enumerate(journal["rows"]):
        expected = row["applied_identity"]
        if expected is None:
            raise OperatorError(f"target[{index}] has no applied identity")
        _assert_target_image(ctx, roots, row, index, expected, "candidate", include_inode=True)


def _assert_all_pre(ctx: Context, roots: OpenRoots, journal: Mapping[str, Any], *, strict_inode: bool = False) -> None:
    for index, row in enumerate(journal["rows"]):
        parent_fd, leaf = _open_parent(roots.live, row["target"], f"target[{index}]")
        try:
            current = _image_at(parent_fd, leaf, f"target[{index}]")
        finally:
            os.close(parent_fd)
        if not _spec_matches(current, row["preimage"]):
            raise OperatorError(f"target[{index}] rollback readback mismatch")
        if strict_inode and row["opening_identity"]["exists"] and not _identity_matches(current, row["opening_identity"], include_inode=True):
            # A restored file necessarily receives a new inode.  strict_inode
            # is reserved for an already-captured no-write opening vector.
            raise OperatorError(f"target[{index}] opening inode changed unexpectedly")


def _apply_locked(ctx: Context, roots: OpenRoots) -> dict[str, Any]:
    existing = _journal_read(ctx, roots)
    reapply_index = 0
    if existing is not None:
        journal, _, _ = existing
        if journal["phase"] == "APPLY_COMMITTED":
            receipt, receipt_sha = _read_owned_receipt(ctx, roots, ctx.apply_leaf, "apply receipt", journal, action="apply", identity_key="receipt_identity")
            if receipt_sha != journal["receipt_sha256"]:
                raise OperatorError("HOLD: apply receipt hash drift")
            _assert_all_post(ctx, roots, journal)
            return {"status": "APPLY_REPLAY", "receipt_sha256": receipt_sha, "transaction_id": journal["transaction_id"], "read_only": False}
        if journal["phase"] == "ROLLBACK_COMMITTED":
            reapply_index = _archive_terminal_transaction(ctx, roots, journal)
        elif journal["action"] != "apply":
            raise OperatorError("HOLD: rollback transaction is active")
        else:
            _recover_active_apply(ctx, roots, journal)
            if _journal_read(ctx, roots) is not None:
                raise OperatorError("HOLD: predecessor transaction did not close")

    sources = _validate_source_rows(ctx, roots)
    opening = _validate_opening_rows(ctx, roots)
    transaction_id = _transaction_id(ctx, reapply_index)
    journal = _new_journal(
        ctx,
        "apply",
        _journal_rows(ctx, opening, transaction_id),
        "PREPARED",
        transaction_id=transaction_id,
        reapply_index=reapply_index,
    )
    _journal_write(ctx, roots, journal, exclusive=True)
    try:
        _backup_preimages(ctx, roots, journal)
        journal["phase"] = "BACKUPS_READY"
        _journal_write(ctx, roots, journal)
        for index, (row, data) in enumerate(zip(ctx.manifest["targets"], sources, strict=True)):
            target_parent, target_leaf = _open_parent(roots.live, row["target"], f"target[{index}]")
            try:
                current = _image_at(target_parent, target_leaf, f"target[{index}]")
                if not _identity_matches(current, journal["rows"][index]["opening_identity"], include_inode=True):
                    raise OperatorError(f"target[{index}] changed after opening validation")
                image = _replace_file_at(
                    target_parent,
                    target_leaf,
                    data,
                    int(row["postimage"]["mode"], 8),
                    current,
                    fault_index=index + 1,
                    fault_point="after_replace",
                )
            finally:
                os.close(target_parent)
            journal["phase"] = "APPLYING"
            journal["applied_indices"].append(index)
            journal["rows"][index]["applied_identity"] = _opening_identity(image)
            _journal_write(ctx, roots, journal)
        journal["phase"] = "TARGETS_APPLIED"
        _assert_all_post(ctx, roots, journal)
        _journal_write(ctx, roots, journal)
        receipt_value = _new_apply_receipt(ctx, journal)
        receipt_sha, receipt_identity = _publish_receipt(ctx, roots, ctx.apply_leaf, receipt_value, "apply receipt", journal.get("receipt_identity"))
        _fault("after_receipt", 1)
        journal["receipt_identity"] = receipt_identity
        journal["receipt_sha256"] = receipt_sha
        journal["phase"] = "RECEIPT_PUBLISHED"
        _journal_write(ctx, roots, journal)
        journal["phase"] = "APPLY_COMMITTED"
        _journal_write(ctx, roots, journal)
        return {"status": "APPLIED", "receipt_sha256": receipt_sha, "transaction_id": journal["transaction_id"], "read_only": False}
    except InjectedFault as exc:
        if exc.point == "after_receipt":
            raise
        try:
            _restore_apply_in_process(ctx, roots, journal, allow_unbound_post=True)
        except Exception as recovery_exc:
            raise OperatorError(f"HOLD: apply fault recovery failed: {recovery_exc}") from recovery_exc
        raise
    except Exception as exc:
        # A normal exception after the journal exists must either compensate
        # completely or leave an explicit HOLD; never claim clean failure with
        # a mixed target vector.
        try:
            _restore_apply_in_process(ctx, roots, journal, allow_unbound_post=False)
        except Exception as recovery_exc:
            raise OperatorError(f"HOLD: apply recovery failed: {recovery_exc}") from recovery_exc
        raise exc


def _prepare_rollback_journal(ctx: Context, roots: OpenRoots, journal: dict[str, Any], apply_receipt: dict[str, Any], apply_receipt_sha: str) -> None:
    if journal["phase"] == "ROLLBACK_COMMITTED":
        return
    if journal["phase"] != "APPLY_COMMITTED":
        if journal["phase"] == "ROLLBACKING":
            return
        raise OperatorError("HOLD: apply transaction is not committed")
    _assert_all_post(ctx, roots, journal)
    journal["action"] = "rollback"
    journal["phase"] = "ROLLBACKING"
    journal["rollback_indices"] = []
    journal["rollback_receipt_identity"] = None
    journal["rollback_receipt_sha256"] = None
    _journal_write(ctx, roots, journal)


def _recover_active_rollback(ctx: Context, roots: OpenRoots, journal: dict[str, Any]) -> None:
    if journal["phase"] != "ROLLBACKING":
        return
    for index in reversed(range(len(journal["rows"]))):
        row = journal["rows"][index]
        parent_fd, leaf = _open_parent(roots.live, row["target"], f"target[{index}]")
        try:
            current = _image_at(parent_fd, leaf, f"target[{index}]")
            if _spec_matches(current, row["preimage"]):
                continue
            expected_post = row["applied_identity"]
            if expected_post is None or not _identity_matches(current, expected_post, include_inode=True):
                raise OperatorError(f"HOLD: rollback target[{index}] is foreign or ambiguous")
            if row["preimage"]["exists"]:
                data = _backup_bytes(ctx, roots, row, index)
                image = _replace_file_at(parent_fd, leaf, data, int(row["preimage"]["mode"], 8), current, fault_index=index + 1, fault_point="recovery_rollback_after_replace")
            else:
                _unlink_at(parent_fd, leaf, current, index + 1)
                image = _image_at(parent_fd, leaf, f"target[{index}]")
            row["restored_identity"] = _opening_identity(image)
        finally:
            os.close(parent_fd)
    _assert_all_pre(ctx, roots, journal)


def _rollback_locked(ctx: Context, roots: OpenRoots, apply_receipt_leaf: str) -> dict[str, Any]:
    apply_receipt_leaf = _safe_leaf(apply_receipt_leaf, "apply receipt argument")
    if apply_receipt_leaf != ctx.apply_leaf:
        raise OperatorError("apply receipt argument is not the frozen direct child")
    existing_journal = _journal_read(ctx, roots)
    if existing_journal is None:
        raise OperatorError("HOLD: transaction journal is missing")
    journal, _, _ = existing_journal
    if journal["action"] not in {"apply", "rollback"}:
        raise OperatorError("HOLD: journal action is invalid")
    if journal["phase"] == "ROLLBACK_COMMITTED":
        apply_receipt, apply_sha = _read_owned_receipt(ctx, roots, ctx.apply_leaf, "apply receipt", journal, action="apply", identity_key="receipt_identity")
        rollback_receipt, rollback_sha = _read_owned_receipt(ctx, roots, ctx.rollback_leaf, "rollback receipt", journal, action="rollback", apply_receipt_sha256=apply_sha, identity_key="rollback_receipt_identity")
        _assert_all_pre(ctx, roots, journal)
        return {"status": "ROLLBACK_REPLAY", "receipt_sha256": rollback_sha, "apply_receipt_sha256": apply_sha, "transaction_id": journal["transaction_id"], "read_only": False}

    apply_receipt, apply_info, apply_raw = _read_receipt(ctx, roots, ctx.apply_leaf, "apply receipt") or (None, None, None)
    if apply_receipt is None or apply_info is None or apply_raw is None:
        raise OperatorError("HOLD: exact apply receipt is missing")
    apply_sha = digest_bytes(apply_raw)
    # The journal binds the receipt inode before rollback is admitted.  A
    # same-byte receipt on another inode is intentionally preserved as HOLD.
    if journal["receipt_identity"] is None or not _same_receipt_identity(apply_info, journal["receipt_identity"]):
        raise OperatorError("HOLD: apply receipt inode authority mismatch")
    _validate_receipt(ctx, apply_receipt, action="apply", leaf=ctx.apply_leaf, journal=journal)
    if journal["receipt_sha256"] != apply_sha:
        raise OperatorError("HOLD: apply receipt hash authority mismatch")
    rollback_was_active = journal["phase"] == "ROLLBACKING"
    _prepare_rollback_journal(ctx, roots, journal, apply_receipt, apply_sha)
    if rollback_was_active:
        _recover_active_rollback(ctx, roots, journal)
    try:
        for index in reversed(range(len(journal["rows"]))):
            row = journal["rows"][index]
            target_parent, target_leaf = _open_parent(roots.live, row["target"], f"target[{index}]")
            try:
                current = _image_at(target_parent, target_leaf, f"target[{index}]")
                if _spec_matches(current, row["preimage"]):
                    if index not in journal["rollback_indices"]:
                        journal["rollback_indices"].append(index)
                    journal["rows"][index]["restored_identity"] = _opening_identity(current)
                    _journal_write(ctx, roots, journal)
                    continue
                if row["preimage"]["exists"]:
                    if not _identity_matches(current, row["applied_identity"], include_inode=True):
                        raise OperatorError(f"HOLD: target[{index}] candidate identity drift")
                    data = _backup_bytes(ctx, roots, row, index)
                    image = _replace_file_at(
                        target_parent,
                        target_leaf,
                        data,
                        int(row["preimage"]["mode"], 8),
                        current,
                        fault_index=index + 1,
                        fault_point="rollback_after_replace",
                    )
                else:
                    if not _identity_matches(current, row["applied_identity"], include_inode=True):
                        raise OperatorError(f"HOLD: target[{index}] candidate identity drift")
                    _unlink_at(target_parent, target_leaf, current, index + 1)
                    image = _image_at(target_parent, target_leaf, f"target[{index}]")
            finally:
                os.close(target_parent)
            if index not in journal["rollback_indices"]:
                journal["rollback_indices"].append(index)
            journal["rows"][index]["restored_identity"] = _opening_identity(image)
            _journal_write(ctx, roots, journal)
        _assert_all_pre(ctx, roots, journal)
        journal["action"] = "rollback"
        rollback_value = _new_rollback_receipt(ctx, journal, apply_sha)
        rollback_sha, rollback_identity = _publish_receipt(ctx, roots, ctx.rollback_leaf, rollback_value, "rollback receipt", journal.get("rollback_receipt_identity"))
        _fault("after_rollback_receipt", 1)
        journal["rollback_receipt_identity"] = rollback_identity
        journal["rollback_receipt_sha256"] = rollback_sha
        journal["phase"] = "ROLLBACK_COMMITTED"
        _journal_write(ctx, roots, journal)
        return {"status": "ROLLED_BACK", "receipt_sha256": rollback_sha, "apply_receipt_sha256": apply_sha, "transaction_id": journal["transaction_id"], "read_only": False}
    except InjectedFault:
        raise
    except Exception as exc:
        raise OperatorError(f"HOLD: rollback failed: {exc}") from exc


def _expected_state(ctx: Context, roots: OpenRoots) -> str:
    journal_record = _journal_read(ctx, roots)
    if journal_record is None:
        apply = _read_receipt(ctx, roots, ctx.apply_leaf, "apply receipt")
        rollback = _read_receipt(ctx, roots, ctx.rollback_leaf, "rollback receipt")
        if apply is not None or rollback is not None:
            raise OperatorError("HOLD: receipt exists without an authoritative journal")
        _validate_opening_rows(ctx, roots)
        return "READY"
    journal, _, _ = journal_record
    if journal["phase"] == "APPLY_COMMITTED":
        _read_owned_receipt(ctx, roots, ctx.apply_leaf, "apply receipt", journal, action="apply", identity_key="receipt_identity")
        _assert_all_post(ctx, roots, journal)
        return "PASS"
    if journal["phase"] == "ROLLBACK_COMMITTED":
        apply_receipt, apply_sha = _read_owned_receipt(ctx, roots, ctx.apply_leaf, "apply receipt", journal, action="apply", identity_key="receipt_identity")
        _read_owned_receipt(ctx, roots, ctx.rollback_leaf, "rollback receipt", journal, action="rollback", apply_receipt_sha256=apply_sha, identity_key="rollback_receipt_identity")
        _assert_all_pre(ctx, roots, journal)
        return "ROLLED_BACK"
    raise OperatorError("HOLD: active or ambiguous transaction journal")


def _verify_stage_candidate_manifest(ctx: Context, candidate_manifest_path: Path, archive_path: Path, archive_sha256: str) -> dict[str, Any]:
    expected_generation = ctx.manifest_path.parent.parent
    expected_manifest = expected_generation / "candidate-manifest.json"
    candidate_manifest_path = candidate_manifest_path.absolute()
    archive_path = archive_path.absolute()
    if candidate_manifest_path != expected_manifest or candidate_manifest_path != candidate_manifest_path.resolve() or candidate_manifest_path.is_symlink():
        raise OperatorError("candidate manifest path is not the frozen generation referent")
    try:
        candidate_manifest = json.loads(candidate_manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OperatorError("candidate manifest referent is unreadable") from exc
    if not isinstance(candidate_manifest, dict):
        raise OperatorError("candidate manifest referent is not an object")
    if candidate_manifest.get("generation") != ctx.manifest["generation"] or candidate_manifest.get("candidate_id") != ctx.manifest["candidate"]["id"] or candidate_manifest.get("candidate_sha256") != ctx.manifest["candidate"]["sha256"] or candidate_manifest.get("transaction", {}).get("sha256") != ctx.manifest_sha256:
        raise OperatorError("stage candidate manifest identity mismatch")
    archive_descriptor = candidate_manifest.get("candidate_archive")
    source_archive = candidate_manifest.get("source_archive")
    if not isinstance(archive_descriptor, dict) or set(archive_descriptor) != {"path", "sha256", "size", "role"} or archive_descriptor.get("role") != "candidate_archive":
        raise OperatorError("stage candidate archive descriptor is invalid")
    if source_archive != archive_descriptor:
        raise OperatorError("stage source archive identity drifted")
    if archive_path != Path(archive_descriptor["path"]) or archive_path != archive_path.resolve() or archive_path.is_symlink() or archive_descriptor.get("sha256") != archive_sha256:
        raise OperatorError("stage candidate archive projection mismatch")
    return archive_descriptor


def verify_stage(ctx: Context, roots: OpenRoots, expected_candidate_id: str, expected_candidate_sha256: str, archive_path: Path, archive_sha256: str, candidate_manifest_path: Path) -> dict[str, Any]:
    candidate = ctx.manifest["candidate"]
    if candidate["id"] != expected_candidate_id or candidate["sha256"] != expected_candidate_sha256:
        raise OperatorError("stage candidate identity mismatch")
    if not HEX64.fullmatch(archive_sha256):
        raise OperatorError("archive SHA-256 argument is invalid")
    source_archive = _verify_stage_candidate_manifest(ctx, candidate_manifest_path, archive_path, archive_sha256)
    try:
        actual_archive_sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise OperatorError("candidate archive referent is unreadable") from exc
    if actual_archive_sha256 != archive_sha256:
        raise OperatorError("candidate archive SHA-256 does not match the staged archive")
    sources = _validate_source_rows(ctx, roots)
    return {
        "schema": "recorder-next-stage-verifier/v2",
        "status": "PASS",
        "generation": ctx.manifest["generation"],
        "candidate_id": candidate["id"],
        "candidate_sha256": candidate["sha256"],
        "operator_sha256": ctx.operator_sha256,
        "source_count": len(sources),
        "archive_sha256": archive_sha256,
        "source_archive": source_archive,
        "read_only": True,
        "commands_executed": 0,
    }


def verify_apply(ctx: Context) -> dict[str, Any]:
    with _verification_roots(ctx) as roots:
        # Validate source bytes and the current target vector without opening
        # the pre-provisioned lock and without touching journal/receipt state.
        _validate_source_rows(ctx, roots)
        status = _expected_state(ctx, roots)
        return {
            "schema": "recorder-next-verify-apply/v1",
            "status": status,
            "generation": ctx.manifest["generation"],
            "candidate_id": ctx.manifest["candidate"]["id"],
            "candidate_sha256": ctx.manifest["candidate"]["sha256"],
            "manifest_sha256": ctx.manifest_sha256,
            "read_only": True,
            "commands_executed": 0,
        }


def readback(ctx: Context, action: str, receipt_leaf: str) -> dict[str, Any]:
    receipt_leaf = _safe_leaf(receipt_leaf, "receipt argument")
    if action not in {"apply", "rollback"}:
        raise OperatorError("readback action must be apply or rollback")
    with _verification_roots(ctx) as roots:
        journal_record = _journal_read(ctx, roots)
        if journal_record is None:
            raise OperatorError("HOLD: journal missing for readback")
        journal, _, _ = journal_record
        if action == "apply":
            if receipt_leaf != ctx.apply_leaf or journal["phase"] not in {"APPLY_COMMITTED", "ROLLBACK_COMMITTED"}:
                raise OperatorError("HOLD: apply receipt is not committed")
            receipt, receipt_sha = _read_owned_receipt(ctx, roots, ctx.apply_leaf, "apply receipt", journal, action="apply", identity_key="receipt_identity")
            if journal["receipt_sha256"] != receipt_sha:
                raise OperatorError("HOLD: apply receipt hash mismatch")
            _assert_all_post(ctx, roots, journal)
        else:
            if receipt_leaf != ctx.rollback_leaf or journal["phase"] != "ROLLBACK_COMMITTED":
                raise OperatorError("HOLD: rollback receipt is not committed")
            apply_receipt, apply_sha = _read_owned_receipt(ctx, roots, ctx.apply_leaf, "apply receipt", journal, action="apply", identity_key="receipt_identity")
            receipt, receipt_sha = _read_owned_receipt(ctx, roots, ctx.rollback_leaf, "rollback receipt", journal, action="rollback", apply_receipt_sha256=apply_sha, identity_key="rollback_receipt_identity")
            if journal["rollback_receipt_sha256"] != receipt_sha:
                raise OperatorError("HOLD: rollback receipt hash mismatch")
            _assert_all_pre(ctx, roots, journal)
        return {
            "schema": "recorder-next-readback/v1",
            "status": "PASS",
            "action": action,
            "receipt_leaf": receipt_leaf,
            "receipt_sha256": receipt_sha,
            "generation": ctx.manifest["generation"],
            "candidate_id": ctx.manifest["candidate"]["id"],
            "read_only": True,
            "commands_executed": 0,
        }


def apply(ctx: Context) -> dict[str, Any]:
    with _mutation_roots(ctx) as roots:
        return _apply_locked(ctx, roots)


def rollback(ctx: Context, apply_receipt_leaf: str) -> dict[str, Any]:
    with _mutation_roots(ctx) as roots:
        return _rollback_locked(ctx, roots, apply_receipt_leaf)


def authorize_rollback(ctx: Context, apply_receipt_leaf: str, rollback_receipt_leaf: str) -> dict[str, Any]:
    apply_receipt_leaf = _safe_leaf(apply_receipt_leaf, "apply receipt argument")
    rollback_receipt_leaf = _safe_leaf(rollback_receipt_leaf, "rollback receipt argument")
    if apply_receipt_leaf != ctx.apply_leaf or rollback_receipt_leaf != ctx.rollback_leaf:
        raise OperatorError("receipt argument is not the frozen direct child")
    with _verification_roots(ctx) as roots:
        journal_record = _journal_read(ctx, roots)
        if journal_record is None:
            raise OperatorError("HOLD: transaction journal is missing")
        journal, _, _ = journal_record
        if journal["phase"] == "APPLY_COMMITTED":
            _, apply_sha = _read_owned_receipt(ctx, roots, ctx.apply_leaf, "apply receipt", journal, action="apply", identity_key="receipt_identity")
            _assert_all_post(ctx, roots, journal)
        elif journal["phase"] == "ROLLBACK_COMMITTED":
            _, apply_sha = _read_owned_receipt(ctx, roots, ctx.apply_leaf, "apply receipt", journal, action="apply", identity_key="receipt_identity")
            _read_owned_receipt(ctx, roots, ctx.rollback_leaf, "rollback receipt", journal, action="rollback", apply_receipt_sha256=apply_sha, identity_key="rollback_receipt_identity")
            _assert_all_pre(ctx, roots, journal)
        else:
            raise OperatorError("HOLD: transaction is not committed")
        return {"status": "PASS", "transaction_id": journal["transaction_id"], "apply_receipt_sha256": apply_sha, "rollback_receipt": ctx.rollback_leaf, "read_only": True, "commands_executed": 0}


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--operator-sha256")
    parser.add_argument("--stage-root", type=Path)
    parser.add_argument("--live-root", type=Path)
    parser.add_argument("--receipt-root", type=Path)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--candidate-manifest", type=Path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recorder Next exact-CAS transaction operator")
    sub = parser.add_subparsers(dest="command", required=True)
    verify_stage_parser = sub.add_parser("verify-stage")
    _add_common(verify_stage_parser)
    verify_stage_parser.add_argument("--candidate-id", required=True)
    verify_stage_parser.add_argument("--candidate-sha256", required=True)
    verify_stage_parser.add_argument("--archive", type=Path, required=True)
    verify_stage_parser.add_argument("--archive-sha256", required=True)
    verify_stage_parser.add_argument("--read-only", action="store_true")
    apply_parser = sub.add_parser("apply")
    _add_common(apply_parser)
    rollback_parser = sub.add_parser("rollback")
    _add_common(rollback_parser)
    rollback_parser.add_argument("--apply-receipt", required=True)
    authorize_parser = sub.add_parser("authorize-rollback")
    _add_common(authorize_parser)
    authorize_parser.add_argument("--apply-receipt", required=True)
    authorize_parser.add_argument("--rollback-receipt", required=True)
    authorize_parser.add_argument("--read-only", action="store_true")
    restore_parser = sub.add_parser("restore-legacy")
    _add_common(restore_parser)
    restore_parser.add_argument("--apply-receipt", required=True)
    restore_parser.add_argument("--rollback-receipt", required=True)
    restore_parser.add_argument("--restore-manifest")
    restore_parser.add_argument("--restore-only-bound-preimages", action="store_true")
    verify_parser = sub.add_parser("verify-apply")
    _add_common(verify_parser)
    verify_parser.add_argument("--read-only", action="store_true")
    readback_parser = sub.add_parser("readback")
    _add_common(readback_parser)
    readback_parser.add_argument("--receipt", required=True)
    readback_parser.add_argument("--action", required=True, choices=("apply", "rollback"))
    readback_parser.add_argument("--read-only", action="store_true")
    rollback_readback_parser = sub.add_parser("readback-rollback")
    _add_common(rollback_readback_parser)
    rollback_readback_parser.add_argument("--rollback-receipt", required=True)
    rollback_readback_parser.add_argument("--protected-ports", default="")
    rollback_readback_parser.add_argument("--read-only", action="store_true")
    return parser


def _overrides(args: argparse.Namespace) -> dict[str, Path]:
    return {
        key: value
        for key, value in {
            "stage": args.stage_root,
            "live": args.live_root,
            "receipts": args.receipt_root,
            "state": args.state_root,
        }.items()
        if value is not None
    }


def _frozen_candidate_archive(ctx: Context) -> tuple[str, str]:
    candidate_manifest = ctx.stage_root / "candidate-manifest.json"
    _require_regular(candidate_manifest, "candidate manifest")
    try:
        value = _strict_load_bytes(candidate_manifest.read_bytes())
    except (OSError, OperatorError) as exc:
        raise OperatorError("candidate manifest is unreadable") from exc
    if not isinstance(value, dict):
        raise OperatorError("candidate manifest is not an object")
    descriptor = value.get("candidate_archive")
    if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256", "size", "role"} or descriptor.get("role") != "candidate_archive":
        raise OperatorError("candidate archive descriptor is not closed")
    archive_path = descriptor["path"]
    archive_sha256 = descriptor["sha256"]
    if not isinstance(archive_path, str) or not os.path.isabs(archive_path) or archive_path != str(Path(archive_path).resolve()):
        raise OperatorError("candidate archive path is not canonical")
    if not isinstance(archive_sha256, str) or HEX64.fullmatch(archive_sha256) is None:
        raise OperatorError("candidate archive SHA-256 is invalid")
    return archive_path, archive_sha256


def _canonical_operator_argv(ctx: Context, args: argparse.Namespace) -> list[str]:
    """Return the one byte-for-byte argument vector authorized by the packet."""
    common = [
        "--manifest", str(ctx.manifest_path),
        "--manifest-sha256", ctx.manifest_sha256,
        "--operator-sha256", ctx.operator_sha256,
        "--stage-root", str(ctx.stage_root),
        "--live-root", str(ctx.live_root),
        "--receipt-root", str(ctx.receipts_root),
        "--state-root", str(ctx.state_root),
        "--candidate-manifest", str(ctx.stage_root / "candidate-manifest.json"),
    ]
    candidate = ctx.manifest["candidate"]
    if args.command == "verify-stage":
        archive_path, archive_sha256 = _frozen_candidate_archive(ctx)
        return [
            "verify-stage", *common,
            "--candidate-id", candidate["id"],
            "--candidate-sha256", candidate["sha256"],
            "--archive", archive_path,
            "--archive-sha256", archive_sha256,
            "--read-only",
        ]
    if args.command == "apply":
        return ["apply", *common]
    if args.command == "rollback":
        return ["rollback", *common, "--apply-receipt", ctx.apply_leaf]
    if args.command == "authorize-rollback":
        return [
            "authorize-rollback", *common,
            "--apply-receipt", ctx.apply_leaf,
            "--rollback-receipt", ctx.rollback_leaf,
            "--read-only",
        ]
    if args.command == "restore-legacy":
        return [
            "restore-legacy", *common,
            "--apply-receipt", ctx.apply_leaf,
            "--rollback-receipt", ctx.rollback_leaf,
            "--restore-manifest", str(ctx.manifest_path),
            "--restore-only-bound-preimages",
        ]
    if args.command == "verify-apply":
        return ["verify-apply", *common, "--read-only"]
    if args.command == "readback":
        if args.action == "apply":
            receipt = ctx.apply_leaf
        elif args.action == "rollback":
            receipt = ctx.rollback_leaf
        else:
            raise OperatorError("readback action is invalid")
        return ["readback", *common, "--receipt", receipt, "--action", args.action, "--read-only"]
    if args.command == "readback-rollback":
        return [
            "readback-rollback", *common,
            "--rollback-receipt", ctx.rollback_leaf,
            "--protected-ports", "127.0.0.1:8642,127.0.0.1:8653",
            "--read-only",
        ]
    raise OperatorError("operator command is not canonical")


def _enforce_canonical_operator_argv(ctx: Context, args: argparse.Namespace, raw_argv: list[str]) -> None:
    expected = _canonical_operator_argv(ctx, args)
    if raw_argv != expected:
        raise OperatorError("operator argv is not the frozen canonical vector")


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw_argv)
    if args.command in {"verify-stage", "verify-apply", "readback", "authorize-rollback", "readback-rollback"} and not args.read_only:
        print(json.dumps({"status": "FAIL", "errors": ["--read-only is required"]}, sort_keys=True))
        return 2
    try:
        ctx = load_context(args.manifest, args.manifest_sha256, operator_sha256=args.operator_sha256, overrides=_overrides(args))
        _enforce_canonical_operator_argv(ctx, args, raw_argv)
        if args.command == "verify-stage":
            with _verification_roots(ctx) as roots:
                if args.candidate_manifest is None:
                    raise OperatorError("candidate manifest is required for stage verification")
                result = verify_stage(ctx, roots, args.candidate_id, args.candidate_sha256, args.archive, args.archive_sha256, args.candidate_manifest)
        elif args.command == "verify-apply":
            result = verify_apply(ctx)
        elif args.command == "readback":
            result = readback(ctx, args.action, args.receipt)
        elif args.command == "readback-rollback":
            result = readback(ctx, "rollback", args.rollback_receipt)
        elif args.command == "authorize-rollback":
            result = authorize_rollback(ctx, args.apply_receipt, args.rollback_receipt)
        elif args.command == "apply":
            result = apply(ctx)
        elif args.command == "restore-legacy":
            if not args.restore_only_bound_preimages:
                raise OperatorError("restore-legacy requires --restore-only-bound-preimages")
            if _safe_leaf(args.rollback_receipt, "rollback receipt argument") != ctx.rollback_leaf:
                raise OperatorError("rollback receipt argument is not the frozen direct child")
            if args.restore_manifest is not None and Path(args.restore_manifest).absolute() != ctx.manifest_path:
                raise OperatorError("restore manifest argument differs from the frozen transaction manifest")
            result = rollback(ctx, args.apply_receipt)
        else:
            result = rollback(ctx, args.apply_receipt)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except OperatorError as exc:
        message = str(exc)
        print(f"ERROR: {message}", file=sys.stderr)
        print(json.dumps({"status": "HOLD" if "HOLD" in message else "FAIL", "error": message}, sort_keys=True))
        return 75 if "HOLD" in message else 1
    except (OSError, ValueError) as exc:
        print(f"ERROR: controlled operator failure: {exc}", file=sys.stderr)
        print(json.dumps({"status": "FAIL", "error": "controlled operator failure"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
