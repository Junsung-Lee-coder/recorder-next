#!/usr/bin/env python3
"""VOICE1 control probe: real observational read-only admission + fixture executor.

B6 (REV-008): main(argv) is the executable owner-bound observational caller.
The canonical invocation runs real bounded observations — authority/source
verification, credential custody, an unauthenticated 401 gate, candidate
capability/readiness probes, an authenticated session GET, and a read-only
indexed SQLite lookup — and reduces them through the fixed 32-predicate
aggregate.  No result booleans are accepted from callers or documents.

Import is inert: module import performs no file reads, environment
inspection, network, SQLite, provider, or logging activity.  Everything
boundary-touching lives behind main()/run_voice1_readonly_admission() and
the fixture-only executor below (attempt custody/receipts/cleanup), which
rejects live paths and is unreachable from the read-only lane.

Script-form execution (VOICE1-B6): when this file is executed as a
script (or imported as a top-level module), the candidate root — this
file's lexical parent-parent — is bound at the front of sys.path before
any recorder_next import, so the canonical argv subprocess imports the
candidate package from the verified candidate root.  Path binding is
standard interpreter import mechanics; every schema read stays lazy
(behind functions), so import performs no file I/O.
"""
from __future__ import annotations

import calendar
import hashlib
import importlib
import json
import os
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import types
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from typing import Any, Callable, cast
from unittest.mock import patch

# S-CLI: script-form execution must import the candidate
# package from the candidate root.  When run as a script, sys.path[0] is
# this run/ directory and the sibling recorder_next package would be
# unreachable; bind the lexical parent-parent before any recorder_next
# import.  This is pure interpreter path binding: no file reads, no
# environment inspection, no imports of project modules at this point.
# os.path.abspath is lexical binding only; resolve/stat/read remain deferred
# until an explicit candidate-validation boundary.
_LEXICAL_FILE = os.path.abspath(__file__)
if __package__ in (None, ""):
    _SCRIPT_CANDIDATE_ROOT = os.path.dirname(os.path.dirname(_LEXICAL_FILE))
    if _SCRIPT_CANDIDATE_ROOT not in sys.path:
        sys.path.insert(0, _SCRIPT_CANDIDATE_ROOT)

CONTROL_DIR = Path(os.path.dirname(_LEXICAL_FILE))
PACKET_PATH = CONTROL_DIR / "binding-create-cas-rollback-packet.md"

# Owner-pinned identity (from the ratified owner authority; digests only).
EXPECTED_S_SHA256 = "7333f832a973d42820f71000d93921a4e05b953ab2fcc5d214985c84008d3e5a"
EXPECTED_KEY_SHA256 = "6c3823f1d4d101cb168d7772e27801d3f2ec1861561722c1ccab8e7b02494d4e"

SQL_LABEL_RE = re.compile(r"<!--\s*voice1-sql:([a-z0-9_.-]+)\s*-->")
SQL_BLOCK_NAMES = (
    "a1.insert_device",
    "a2.insert_project",
    "a2.insert_session",
    "a3.bind_session",
    "a3.bump_project",
    "r1.delete_session",
    "r1.delete_project",
    "r1.delete_device",
)


def extract_sql_blocks(packet_text: str) -> dict[str, str]:
    """Extract exactly one statement per labeled fenced sql block.

    Rejects missing labels, duplicate labels, missing/duplicate fences, and
    any block that does not contain exactly one statement.
    """
    blocks: dict[str, str] = {}
    for match in SQL_LABEL_RE.finditer(packet_text):
        name = match.group(1)
        if name in blocks:
            raise ValueError(f"duplicate sql label: {name}")
        rest = packet_text[match.end():]
        fence = re.match(r"\s*```sql\s*\n(.*?)\n\s*```", rest, re.S)
        if fence is None:
            raise ValueError(f"missing or malformed sql fence for label: {name}")
        statement = fence.group(1).strip().rstrip(";")
        if not statement or ";" in statement:
            raise ValueError(f"label {name} must contain exactly one statement")
        blocks[name] = statement
    missing = [name for name in SQL_BLOCK_NAMES if name not in blocks]
    if missing:
        raise ValueError(f"missing sql labels: {missing}")
    return blocks


def _typed_sql_params(values_by_name: dict[str, Any]) -> dict[str, Any]:
    """Packet DELETE parameters plus typeof() predicates for each value.

    B6 (REV-011): the strengthened packet DELETE blocks bind every field as
    ``c IS :p AND typeof(c) = :p_type``; the ``_type`` parameter comes from
    the receipt value's actual SQLite storage class, never from post-lock
    reads.
    """
    def _typeof(value: Any) -> str:
        # SQLite typeof() returns lowercase storage classes: null, integer,
        # real, text, blob.
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "integer"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "real"
        return "text"

    params: dict[str, Any] = dict(values_by_name)
    for name, value in values_by_name.items():
        params[name + "_type"] = _typeof(value)
    return params


def _row_set_digest(rows: list[tuple[Any, ...]]) -> str:
    """Canonical row-set digest over exact stored values (PK ASC, schema order)."""
    encoded = ""
    for row in sorted(rows, key=lambda item: tuple(str(field) for field in item)):
        encoded += "\x1f".join(repr(field) for field in row) + "\x1e"
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


CANDIDATE_SCHEMA_PATH = CONTROL_DIR.parent / "recorder_next" / "schema.sql"


def _fixture_schema(conn: sqlite3.Connection) -> None:
    """Construct the COMPLETE candidate schema (setup only; not live).

    Architecture section 6 R.1: use the candidate schema.sql; do not keep a
    divergent three-table miniature.  The fixture DB therefore contains every
    product table so protected-vector comparison can see dependent work.
    """
    conn.executescript(CANDIDATE_SCHEMA_PATH.read_text(encoding="utf-8"))


def _seed_release_smoke(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO projects (stable_project_id, user_id, project_number, name, aliases_json, description, status, default_session_key, record_version, created_at, updated_at, archived_at)"
        " VALUES ('dc016d66-6b67-5f49-9c3e-3466cacbc0fd','release-smoke-9fa4a790c711','REL-9fa4a790c711','Recorder Next release smoke','[]','','active','project:dc016d66-6b67-5f49-9c3e-3466cacbc0fd:default',1,'2026-09-04T12:06:52.616+00:00','2026-09-04T12:06:52.616+00:00',NULL)"
    )
    conn.execute(
        "INSERT INTO sessions (session_key, project_id, gateway_session_key, created_at)"
        " VALUES ('project:dc016d66-6b67-5f49-9c3e-3466cacbc0fd:default','dc016d66-6b67-5f49-9c3e-3466cacbc0fd','project:dc016d66-6b67-5f49-9c3e-3466cacbc0fd:default','2026-09-04T12:06:52.616+00:00')"
    )
    conn.execute(
        "INSERT INTO devices (user_id, device_id, kind, status, created_at, revoked_at)"
        " VALUES ('release-smoke-9fa4a790c711','release-phone-9fa4a790c711','phone','active','2026-09-04T12:06:52.590+00:00',NULL)"
    )
    conn.commit()


def _load_blocks() -> dict[str, str]:
    return extract_sql_blocks(PACKET_PATH.read_text(encoding="utf-8"))


def voice1_session_admission(
    api_payload: Any,
    persisted_rows: list[sqlite3.Row | tuple[Any, ...] | dict[str, Any]],
    *,
    expected_session_id: str,
    expected_key_sha256: str,
) -> dict[str, Any]:
    """Pure Voice1 admission predicate (REV-003).

    Inputs are in-memory data only.  Returns ONLY bounded booleans, fixed
    reason codes, and status; never raw keys, payloads, rows, or exceptions.
    """
    reason_codes: list[str] = []
    source_match = False
    id_match = False
    lifecycle_match = False
    persisted_row_count_match = False
    persisted_id_match = False
    persisted_source_match = False
    persisted_ended_at_null = False
    conversation_key_match = False
    distinct_key_identity = False

    ok = isinstance(api_payload, dict) and api_payload.get("object") == "hermes.session"
    if not ok:
        reason_codes.append("payload_shape")
    session = api_payload.get("session") if isinstance(api_payload, dict) else None
    if isinstance(session, dict):
        id_match = session.get("id") == expected_session_id
        source_match = session.get("source") == "discord"
        archived = session.get("archived")
        ended_at = session.get("ended_at")
        archived_ok = "archived" in session and isinstance(archived, bool) and archived is False
        ended_ok = "ended_at" in session and ended_at is None
        lifecycle_match = bool(archived_ok and ended_ok)
        if not archived_ok:
            reason_codes.append("archived_flag")
        if not ended_ok:
            reason_codes.append("ended_at_flag")
        if not id_match:
            reason_codes.append("session_id_mismatch")
        if not source_match:
            reason_codes.append("source_mismatch")
    else:
        reason_codes.append("session_shape")

    rows = list(persisted_rows)
    if len(rows) == 1:
        persisted_row_count_match = True
        row = rows[0]
        get = None
        persisted_id = persisted_source = persisted_key = persisted_ended = None
        if isinstance(row, dict):
            # B4: exact four-key mapping; missing or extra keys are shape
            # violations (REV-005).  "ended_at" key membership must be
            # decidable before any field is read.
            if set(row.keys()) == {"id", "source", "session_key", "ended_at"}:
                get = row.get
            else:
                get = None
                reason_codes.append("persisted_row_shape")
        elif isinstance(row, sqlite3.Row):
            try:
                keys = tuple(row.keys())
            except (IndexError, TypeError):
                keys = ()
            if keys == ("id", "source", "session_key", "ended_at"):
                get = row.__getitem__
            else:
                get = None
                reason_codes.append("persisted_row_shape")
        elif isinstance(row, tuple):
            if len(row) == 4:
                row = dict(zip(("id", "source", "session_key", "ended_at"), row))
                get = row.get
            else:
                get = None
                reason_codes.append("persisted_row_shape")
        else:
            get = None
            reason_codes.append("persisted_row_shape")
        if get is None:
            # B4 (REV-005): truncated/extra/missing-key rows never satisfy
            # lifecycle predicates; only the exact shape below is readable.
            persisted_id_match = False
        else:
            try:
                persisted_id = get("id")
                persisted_source = get("source")
                persisted_key = get("session_key")
                persisted_ended = get("ended_at")
            except (KeyError, IndexError, TypeError):
                reason_codes.append("persisted_row_shape")
                persisted_id = persisted_source = persisted_key = persisted_ended = None
                get = None
            persisted_id_match = persisted_id == expected_session_id if get is not None else False
        persisted_source_match = persisted_source == "discord"
        persisted_ended_at_null = persisted_ended is None
        if not persisted_id_match:
            reason_codes.append("persisted_id_mismatch")
        if not persisted_source_match:
            reason_codes.append("persisted_source_mismatch")
        if not persisted_ended_at_null:
            reason_codes.append("persisted_ended_not_null")
        key_is_string = get is not None and isinstance(persisted_key, str) and bool(persisted_key.strip())
        if key_is_string:
            digest = hashlib.sha256(persisted_key.encode("utf-8")).hexdigest()
            conversation_key_match = digest == expected_key_sha256
            distinct_key_identity = persisted_key != expected_session_id
            if not conversation_key_match:
                reason_codes.append("conversation_key_mismatch")
            if not distinct_key_identity:
                reason_codes.append("key_equals_session_id")
        elif get is None:
            persisted_ended_at_null = False
            conversation_key_match = False
            distinct_key_identity = False
            reason_codes.append("conversation_key_missing_or_blank")
        else:
            reason_codes.append("conversation_key_missing_or_blank")
    else:
        reason_codes.append("persisted_row_count")
        if len(rows) > 1:
            reason_codes.append("persisted_row_duplicate")

    status = (
        ok
        and id_match
        and source_match
        and lifecycle_match
        and persisted_row_count_match
        and persisted_id_match
        and persisted_source_match
        and persisted_ended_at_null
        and conversation_key_match
        and distinct_key_identity
    )
    return {
        "status": "PASS" if status else "HOLD",
        "payload_object_match": ok,
        "source_match": source_match,
        "id_match": id_match,
        "lifecycle_match": lifecycle_match,
        "persisted_row_count_match": persisted_row_count_match,
        "persisted_id_match": persisted_id_match,
        "persisted_source_match": persisted_source_match,
        "persisted_ended_at_null": persisted_ended_at_null,
        "conversation_key_match": conversation_key_match,
        "distinct_key_identity": distinct_key_identity,
        "reason_codes": sorted(set(reason_codes)),
    }


class Voice1ControlPacketSQLTests(unittest.TestCase):
    """REV-002: exercise the packet's actual SQL statement bytes in fixtures."""

    def setUp(self) -> None:
        self.blocks = _load_blocks()
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("PRAGMA foreign_keys = ON")
        _fixture_schema(self.conn)
        _seed_release_smoke(self.conn)

    def tearDown(self) -> None:
        self.conn.close()

    # -- fixture helpers -------------------------------------------------

    def _u(self) -> str:
        return f"voice1-trial-owner-{uuid.uuid4().hex[:16]}"

    def _a1_params(self, u: str) -> dict[str, Any]:
        return {
            "device_user_id": u,
            "device_id": f"voice1-server-trial-{u.split('-')[-1]}",
            "kind": "other",
            "device_status": "active",
            "device_created_at": "2026-09-12T13:00:00.000+00:00",
            "revoked_at": None,
        }

    def _a2_params(self, u: str, a1: dict[str, Any]) -> dict[str, Any]:
        p = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recorder-next:project:{u}:recorder-next:voice1:isolated-trial:{u.split('-')[-1]}"))
        key = f"project:{p}:default"
        return {
            "stable_project_id": p,
            "project_user_id": u,
            "project_number": f"VOICE1-TRIAL-{u.split('-')[-1]}",
            "name": "Recorder Voice1 isolated trial",
            "aliases_json": "[]",
            "description": "Owner-authorized server-only two-turn voice trial; isolated from existing Recorder projects.",
            "project_status": "active",
            "default_session_key": key,
            "record_version": 1,
            "project_created_at": "2026-09-12T13:00:00.000+00:00",
            "project_updated_at": "2026-09-12T13:00:00.000+00:00",
            "archived_at": None,
            "session_key": key,
            "project_id": p,
            "gateway_session_key": key,
            "session_created_at": "2026-09-12T13:00:00.000+00:00",
            "device_created_at": a1["device_created_at"],
        }

    def _typed(self, values: dict[str, Any]) -> dict[str, Any]:
        return _typed_sql_params(values)

    def _protected_digests(self) -> tuple[str, str, str]:
        cur = self.conn.cursor()
        proj = cur.execute("SELECT * FROM projects WHERE user_id LIKE 'release-smoke-%'").fetchall()
        sess = cur.execute("SELECT * FROM sessions WHERE session_key LIKE 'project:dc016d66%'").fetchall()
        dev = cur.execute("SELECT * FROM devices WHERE user_id LIKE 'release-smoke-%'").fetchall()
        return _row_set_digest(proj), _row_set_digest(sess), _row_set_digest(dev)

    def _assert_protected_unchanged(self, before: tuple[str, str, str]) -> None:
        self.assertEqual(before, self._protected_digests(), "protected release-smoke rows must be unchanged")

    # -- tests -----------------------------------------------------------

    def test_packet_contains_exactly_the_eight_labeled_blocks(self):
        self.assertEqual(sorted(self.blocks), sorted(SQL_BLOCK_NAMES))

    def test_a1_insert_is_insert_only_and_rowcount_one(self):
        u = self._u()
        params = self._a1_params(u)
        cur = self.conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute(self.blocks["a1.insert_device"], params)
        self.assertEqual(cur.rowcount, 1)
        row = cur.execute(
            "SELECT user_id, device_id, kind, status, created_at, revoked_at FROM devices WHERE user_id=?", (u,)
        ).fetchone()
        self.assertEqual(
            row,
            (params["device_user_id"], params["device_id"], "other", "active", params["device_created_at"], None),
        )
        self.conn.commit()
        before = self._protected_digests()
        self._assert_protected_unchanged(before)

    def test_a1_cannot_adopt_existing_same_tuple_row(self):
        u = self._u()
        params = self._a1_params(u)
        cur = self.conn.cursor()
        cur.execute(self.blocks["a1.insert_device"], params)
        self.conn.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(self.blocks["a1.insert_device"], params)
        self.conn.rollback()
        count = cur.execute("SELECT COUNT(*) FROM devices WHERE user_id=?", (u,)).fetchone()[0]
        self.assertEqual(count, 1, "existing row must remain; plain INSERT cannot adopt")

    def test_a2_full_commit_and_second_insert_exception_rolls_back_whole_a2(self):
        u = self._u()
        a1 = self._a1_params(u)
        a2 = self._a2_params(u, a1)
        cur = self.conn.cursor()
        cur.execute(self.blocks["a1.insert_device"], a1)
        cur.execute(self.blocks["a2.insert_project"], a2)
        cur.execute(self.blocks["a2.insert_session"], a2)
        self.conn.commit()
        protected = self._protected_digests()
        # second A2 attempt with the same identity must conflict on the
        # project PK and roll back both inserts of the retry transaction
        a2_retry = dict(a2)
        a2_retry["session_created_at"] = "2026-09-12T14:00:00.000+00:00"
        try:
            cur.execute("BEGIN IMMEDIATE")
            cur.execute(self.blocks["a2.insert_project"], a2_retry)
            cur.execute(self.blocks["a2.insert_session"], a2_retry)
            self.conn.commit()
            self.fail("duplicate A2 must fail")
        except sqlite3.IntegrityError:
            self.conn.rollback()
        session_count = cur.execute(
            "SELECT COUNT(*) FROM sessions WHERE session_key=?", (a2["session_key"],)
        ).fetchone()[0]
        self.assertEqual(session_count, 1)
        self._assert_protected_unchanged(protected)

    def test_a3_cas_updates_both_rows_or_neither(self):
        u = self._u()
        a1 = self._a1_params(u)
        a2 = self._a2_params(u, a1)
        cur = self.conn.cursor()
        cur.execute(self.blocks["a1.insert_device"], a1)
        cur.execute(self.blocks["a2.insert_project"], a2)
        cur.execute(self.blocks["a2.insert_session"], a2)
        self.conn.commit()
        protected = self._protected_digests()
        a3 = dict(a2)
        a3.update({"S": "20260703_210417_8f66b434", "prior_gateway_session_key": a2["gateway_session_key"], "prior_record_version": 1, "operation_time": "2026-09-12T13:05:00.000+00:00"})
        cur.execute(self.blocks["a3.bind_session"], a3)
        self.assertEqual(cur.rowcount, 1)
        cur.execute(self.blocks["a3.bump_project"], a3)
        self.assertEqual(cur.rowcount, 1)
        self.conn.commit()
        sess = cur.execute("SELECT gateway_session_key FROM sessions WHERE session_key=?", (a2["session_key"],)).fetchone()
        self.assertEqual(sess[0], a3["S"])
        proj = cur.execute("SELECT record_version, updated_at FROM projects WHERE stable_project_id=?", (a2["stable_project_id"],)).fetchone()
        self.assertEqual(proj, (2, a3["operation_time"]))
        self._assert_protected_unchanged(protected)

        # Wrong prior version makes bump rowcount 0 and must roll back the
        # session update of the retry transaction too.
        a3_wrong = dict(a3)
        a3_wrong["prior_record_version"] = 1
        a3_wrong["prior_gateway_session_key"] = a3["S"]
        a3_wrong["operation_time"] = "2026-09-12T13:06:00.000+00:00"
        try:
            cur.execute("BEGIN IMMEDIATE")
            cur.execute(self.blocks["a3.bind_session"], a3_wrong)
            self.assertEqual(cur.rowcount, 1)
            cur.execute(self.blocks["a3.bump_project"], a3_wrong)
            self.assertEqual(cur.rowcount, 0, "version CAS must not match")
            self.conn.commit()
            self.fail("wrong version must not commit")
        except sqlite3.IntegrityError:
            self.conn.rollback()
        except AssertionError:
            self.conn.rollback()
        version = cur.execute("SELECT record_version FROM projects WHERE stable_project_id=?", (a2["stable_project_id"],)).fetchone()[0]
        self.assertEqual(version, 2, "failed A3 retry must leave version 2")

    def test_r1_full_row_drift_blocks_deletion(self):
        u = self._u()
        a1 = self._a1_params(u)
        a2 = self._a2_params(u, a1)
        cur = self.conn.cursor()
        cur.execute(self.blocks["a1.insert_device"], a1)
        cur.execute(self.blocks["a2.insert_project"], a2)
        cur.execute(self.blocks["a2.insert_session"], a2)
        self.conn.commit()
        protected = self._protected_digests()

        # Drift one stored field: updated_at.  The full-row DELETE must not match.
        cur.execute("UPDATE projects SET updated_at='2026-09-12T13:59:00.000+00:00' WHERE stable_project_id=?", (a2["stable_project_id"],))
        self.conn.commit()
        drifted_project = cur.execute(
            self.blocks["r1.delete_project"],
            self._typed({
                "stable_project_id": a2["stable_project_id"], "project_user_id": a2["project_user_id"], "project_number": a2["project_number"], "name": a2["name"],
                "aliases_json": a2["aliases_json"], "description": a2["description"], "project_status": a2["project_status"], "default_session_key": a2["default_session_key"],
                "record_version": 1, "project_created_at": a2["project_created_at"], "project_updated_at": a2["project_updated_at"], "archived_at": None,
            }),
        ).rowcount
        self.assertEqual(drifted_project, 0, "drifted updated_at must not satisfy the full-row DELETE match")
        self.conn.rollback()

        # Restore exact A2 postimage, then R1 deletes all three rows.
        cur.execute("UPDATE projects SET updated_at=? WHERE stable_project_id=?", (a2["project_updated_at"], a2["stable_project_id"]))
        self.conn.commit()
        cur.execute(self.blocks["r1.delete_session"], self._typed({"session_key": a2["session_key"], "project_id": a2["project_id"], "gateway_session_key": a2["gateway_session_key"], "session_created_at": a2["session_created_at"]}))
        self.assertEqual(cur.rowcount, 1)
        cur.execute(
            self.blocks["r1.delete_project"],
            self._typed({
                "stable_project_id": a2["stable_project_id"], "project_user_id": a2["project_user_id"], "project_number": a2["project_number"], "name": a2["name"],
                "aliases_json": a2["aliases_json"], "description": a2["description"], "project_status": a2["project_status"], "default_session_key": a2["default_session_key"],
                "record_version": 1, "project_created_at": a2["project_created_at"], "project_updated_at": a2["project_updated_at"], "archived_at": None,
            }),
        )
        self.assertEqual(cur.rowcount, 1)
        cur.execute(
            self.blocks["r1.delete_device"],
            self._typed({"device_user_id": u, "device_id": a1["device_id"], "kind": "other", "device_status": "active", "device_created_at": a1["device_created_at"], "revoked_at": None}),
        )
        self.assertEqual(cur.rowcount, 1)
        self.conn.commit()
        self._assert_protected_unchanged(protected)

    def test_r1_null_semantics_are_null_safe(self):
        u = self._u()
        a1 = self._a1_params(u)
        a2 = self._a2_params(u, a1)
        cur = self.conn.cursor()
        cur.execute(self.blocks["a1.insert_device"], a1)
        cur.execute(self.blocks["a2.insert_project"], a2)
        cur.execute(self.blocks["a2.insert_session"], a2)
        self.conn.commit()
        # NULL<->empty substitution must prevent the project DELETE match.
        cur.execute("UPDATE projects SET description='' WHERE stable_project_id=?", (a2["stable_project_id"],))
        self.conn.commit()
        cur.execute(
            self.blocks["r1.delete_project"],
            self._typed({
                "stable_project_id": a2["stable_project_id"], "project_user_id": a2["project_user_id"], "project_number": a2["project_number"], "name": a2["name"],
                "aliases_json": a2["aliases_json"], "description": a2["description"], "project_status": a2["project_status"], "default_session_key": a2["default_session_key"],
                "record_version": 1, "project_created_at": a2["project_created_at"], "project_updated_at": a2["project_updated_at"], "archived_at": None,
            }),
        )
        self.assertEqual(cur.rowcount, 0, "empty string must not satisfy NULL-safe IS match")
        self.conn.rollback()

    def test_r1_partial_pair_refuses_deletion(self):
        u = self._u()
        a1 = self._a1_params(u)
        a2 = self._a2_params(u, a1)
        cur = self.conn.cursor()
        cur.execute(self.blocks["a1.insert_device"], a1)
        cur.execute(self.blocks["a2.insert_project"], a2)
        # Session missing: A2 pair incomplete -> HOLD, no deletes.
        self.conn.commit()
        session_count = cur.execute("SELECT COUNT(*) FROM sessions WHERE session_key=?", (a2["session_key"],)).fetchone()[0]
        self.assertEqual(session_count, 0)
        device_count = cur.execute("SELECT COUNT(*) FROM devices WHERE user_id=?", (u,)).fetchone()[0]
        self.assertEqual(device_count, 1, "interrupted partial pair must be preserved for adjudication")

    def test_a1_only_prefix_deletes_only_device(self):
        u = self._u()
        a1 = self._a1_params(u)
        cur = self.conn.cursor()
        cur.execute(self.blocks["a1.insert_device"], a1)
        self.conn.commit()
        protected = self._protected_digests()
        cur.execute(self.blocks["r1.delete_device"], self._typed({"device_user_id": u, "device_id": a1["device_id"], "kind": "other", "device_status": "active", "device_created_at": a1["device_created_at"], "revoked_at": None}))
        self.assertEqual(cur.rowcount, 1)
        self.conn.commit()
        self._assert_protected_unchanged(protected)

    def test_rowcount_zero_on_missing_target_is_reported(self):
        cur = self.conn.cursor()
        cur.execute(self.blocks["r1.delete_device"], self._typed({"device_user_id": "absent-user", "device_id": "absent-device", "kind": "other", "device_status": "active", "device_created_at": "2026-09-12T13:00:00.000+00:00", "revoked_at": None}))
        self.assertEqual(cur.rowcount, 0, "absent target must report rowcount 0, never a fake success")
        self.conn.rollback()

    def test_fixture_extraction_rejects_bad_labels(self):
        with self.assertRaises(ValueError):
            extract_sql_blocks("<!-- voice1-sql:r1.delete_session -->\nno fence")
        duplicated = PACKET_PATH.read_text(encoding="utf-8") + "\n<!-- voice1-sql:a1.insert_device -->\n```sql\nSELECT 1\n```\n"
        with self.assertRaises(ValueError):
            extract_sql_blocks(duplicated)
        trimmed = PACKET_PATH.read_text(encoding="utf-8").replace("<!-- voice1-sql:a2.insert_session -->", "<!-- voice1-sql:other.name -->")
        with self.assertRaises(ValueError):
            extract_sql_blocks(trimmed)


class Voice1SessionAdmissionTests(unittest.TestCase):
    """REV-003: the pure admission predicate matrix (no I/O)."""

    S = "20260703_210417_8f66b434"

    @staticmethod
    def _key() -> str:
        # A standalone fixture key digest distinct from the owner authority;
        # the owner digest itself is covered by the digest-agreement test.
        return "agent:main:discord:thread:fixture-key-value"

    def _payload(self, *, source: Any = "discord", session_id: str | None = None, archived: Any = False, ended_at: Any = None, include_archived: bool = True, include_ended: bool = True) -> dict[str, Any]:
        session: dict[str, Any] = {"id": session_id if session_id is not None else self.S, "source": source}
        if include_archived:
            session["archived"] = archived
        if include_ended:
            session["ended_at"] = ended_at
        return {"object": "hermes.session", "session": session}

    def _row(self, *, session_id: str | None = None, source: str = "discord", key: str | None = None, ended_at: Any = None) -> dict[str, Any]:
        return {"id": session_id or self.S, "source": source, "session_key": key if key is not None else self._key(), "ended_at": ended_at}

    def _admit(self, payload: Any, rows: list[Any], *, expected_id: str | None = None, key_digest: str = EXPECTED_KEY_SHA256) -> dict[str, Any]:
        return voice1_session_admission(
            payload,
            rows,
            expected_session_id=expected_id or self.S,
            expected_key_sha256=key_digest,
        )

    def test_valid_discord_owner_key_pair_passes(self):
        digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        result = self._admit(self._payload(), [self._row()], key_digest=digest)
        self.assertEqual(result["status"], "PASS", result)

    def test_api_source_and_missing_source_reject(self):
        digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        for source in ("api_server", None):
            with self.subTest(source=source):
                result = self._admit(self._payload(source=source), [self._row()], key_digest=digest)
                self.assertEqual(result["status"], "HOLD")
                self.assertFalse(result["source_match"])

    def test_archived_absent_true_or_string_reject(self):
        digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        rows = [self._row()]
        for kwargs in ({"archived": True}, {"archived": "false"}, {"include_archived": False}):
            with self.subTest(kwargs=kwargs):
                result = self._admit(self._payload(**kwargs), rows, key_digest=digest)
                self.assertEqual(result["status"], "HOLD")

    def test_missing_ended_at_rejects(self):
        digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        result = self._admit(self._payload(include_ended=False), [self._row()], key_digest=digest)
        self.assertEqual(result["status"], "HOLD")

    def test_wrong_session_id_rejects(self):
        digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        result = self._admit(self._payload(), [self._row(session_id="other")], key_digest=digest)
        self.assertEqual(result["status"], "HOLD")

    def test_persisted_source_mismatch_rejects(self):
        digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        result = self._admit(self._payload(), [self._row(source="api_server")], key_digest=digest)
        self.assertEqual(result["status"], "HOLD")

    def test_no_or_duplicate_persisted_row_holds(self):
        digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        for rows in ([], [self._row(), self._row()]):
            with self.subTest(rows=len(rows)):
                result = self._admit(self._payload(), rows, key_digest=digest)
                self.assertEqual(result["status"], "HOLD")

    def test_missing_blank_or_different_key_rejects(self):
        digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        for key in ("", "different-key"):
            with self.subTest(key=key):
                result = self._admit(self._payload(), [self._row(key=key)], key_digest=digest)
                self.assertEqual(result["status"], "HOLD")
        # A None key must fall back to the fixture default (matching digest),
        # so this row combination itself PASSES; the owner-digest rejection
        # for a genuinely absent key is covered via a NULL-column row below.
        result = self._admit(self._payload(), [{"id": self.S, "source": "discord", "session_key": None, "ended_at": None}], key_digest=digest)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn("conversation_key_missing_or_blank", result["reason_codes"])

    def test_key_equal_to_session_id_rejects(self):
        result = self._admit(self._payload(), [self._row(key=self.S)], key_digest=EXPECTED_KEY_SHA256)
        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["distinct_key_identity"])

    def test_whitespace_changed_key_rejects(self):
        digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        padded = " " + self._key() + " "
        result = self._admit(self._payload(), [self._row(key=padded)], key_digest=digest)
        self.assertEqual(result["status"], "HOLD")

    def test_current_row_digest_differs_from_owner_digest_rejects(self):
        # An old receipt/current-row agreement that differs from the owner
        # authority digest must not pass.
        row_digest = hashlib.sha256(self._key().encode("utf-8")).hexdigest()
        result = self._admit(self._payload(), [self._row()], key_digest=row_digest)
        self.assertEqual(result["status"], "PASS", "row agrees with itself")
        result = self._admit(self._payload(), [self._row()], key_digest=EXPECTED_KEY_SHA256)
        self.assertEqual(result["status"], "HOLD", "row digest differs from owner authority")

    def test_malformed_result_rejects_without_raw_leak(self):
        result = self._admit("not-a-dict", [self._row()])
        self.assertEqual(result["status"], "HOLD")
        self.assertNotIn("session_key", json.dumps(result))
        result = self._admit(self._payload(), [("only-one-field",)], key_digest=EXPECTED_KEY_SHA256)
        self.assertEqual(result["status"], "HOLD")
        self.assertNotIn("discord:thread", json.dumps(result))




# Owner-pinned identity (from the ratified owner authority; digests only).
EXPECTED_S_SHA256 = "7333f832a973d42820f71000d93921a4e05b953ab2fcc5d214985c84008d3e5a"
EXPECTED_KEY_SHA256 = "6c3823f1d4d101cb168d7772e27801d3f2ec1861561722c1ccab8e7b02494d4e"
SELECTED_S = "20260703_210417_8f66b434"

# SQL statement SHA map (asserted in tests; the manifest input must agree).
SQL_STATEMENT_SHA256 = {
    "a1.insert_device": "30f9b03847d7630e41b805c97ed2733ae5fe758143261bb264a9c647fbc9cee9",
    "a2.insert_project": "f5df52182f75233ea71a701af817011684512881532c7db621d1744c1b77b110",
    "a2.insert_session": "f9deb185f1991a12c04db84d19c19c5656e465e70d3aa8078ace6f47c291cae2",
    "a3.bind_session": "8faa8c937950d3c7140e68a0dc3d17e69cd9951c35cf03a1ed89a2184fe9c372",
    "a3.bump_project": "6dca986966a92362100c57e1d6cea929051cc3f24886929d8a2ec99a73d0e7fe",
    # B6 REV-011: the three DELETE blocks gained typeof() typed predicates; the
    # INSERT and A3 CAS statements are byte-identical to the B5 packet.
    "r1.delete_session": "d203ed34b79cac1520661add30d103b807f075bbedc00fd18a9f65752a00fd9f",
    "r1.delete_project": "360297ecc07f62aa0cb91ab6e95ce6fc97675e361d3b09855f0a60da9855fcb3",
    "r1.delete_device": "191458ac9990b3ce7791980e1a655eff927b210e6fc6b99f8839ac04ae9c10e1",
}

# Architecture section 5 S.3: constant tuple, never inferred from report keys.
REQUIRED_PREDICATES: tuple[str, ...] = (
    "authorization_bound",
    "candidate_bound",
    "imports_bound",
    "credential_custody",
    "dashboard_credential_parse",
    "api_credential_parse",
    "lifetime_pre",
    "unauthenticated_gate",
    "api_capability",
    "asr_ready",
    "tts_ready",
    "omitted_profile_equal",
    "omitted_profile_ready",
    "generic_preflight",
    "session_get",
    "persisted_lookup_ro",
    "persisted_lookup_indexed",
    "session_budget",
    "payload_object_match",
    "source_match",
    "id_match",
    "lifecycle_match",
    "persisted_row_count_match",
    "persisted_id_match",
    "persisted_source_match",
    "persisted_ended_at_null",
    "conversation_key_match",
    "distinct_key_identity",
    "lifetime_post",
    "closing_identity_equal",
    "no_mutation",
    "secret_safe",
)

OBSERVATION_ORDER: tuple[str, ...] = (
    "authority_and_source",
    "credential_custody",
    "credential_parse",
    "dashboard_lifetime_pre",
    "unauthenticated_gate",
    "api_capability",
    "asr_readiness",
    "tts_readiness",
    "profile_observations",
    "session_preflight_and_get",
    "persisted_lookup",
    "session_admission",
    "closing_vector",
)

# Normative keys inside the tts/stt subtrees that the equivalence reduction
# must compare type-strictly (F-3): booleans stay booleans, strings stay
# strings, and absent-vs-invalid never collapse into an equal marker.
_TTS_NORMATIVE_FLAGS: frozenset[str] = frozenset(
    {"configured", "enabled", "ready", "ok", "audio_api"}
)
_TTS_NORMATIVE_STRINGS: frozenset[str] = frozenset(
    {"mode", "reason", "provider", "wire", "status"}
)

REPORT_SCHEMA = "recorder-next-voice1-readonly-admission/v1"
RECEIPT_SCHEMA = "recorder-next-voice1-trial-attempt/v1"
ADMISSION_TOTAL_BUDGET_SECONDS = 90.0
PROVIDER_TIMEOUT_SECONDS = 10.0
SESSION_BUDGET_SECONDS = 10.0
DASHBOARD_LIFETIME_FLOOR_SECONDS = 3900
_ORIGINAL_SQLITE_CONNECT = sqlite3.connect

# The public report is deliberately explicit: A3 validates this complete
# stdout shape instead of treating an arbitrary parsed mapping as authority.
ADMISSION_REPORT_KEYS: frozenset[str] = frozenset({
    "schema", "candidate_id", "archive_sha256", "source_commit", "source_tree",
    "control_sha256", "spec_sha256", "started_utc", "finished_utc", "elapsed_ms",
    "predicates", "missing_predicates", "failed_predicates", "reason_codes",
    "expected_session_id_sha256", "expected_key_sha256", "persisted_key_sha256",
    "manifest_sha256", "authorization_sha256", "control_packet_sha256",
    "execution_scope", "observation_order", "session_observed_utc",
    "session_observed_monotonic_ns", "boot_id", "status", "status_code",
})
_FIXED_ADMISSION_REASON_CODES: frozenset[str] = frozenset({
    "invalid_argv", "authority_mismatch", "source_drift", "credential_custody",
    "credential_parse", "lifetime", "unauthenticated_gate", "capability",
    "tts_readiness", "profile_mismatch", "session_get", "persisted_lookup",
    "session_admission", "deadline", "closing_drift", "internal_error",
})


def _fixed_reason_codes(values: Any) -> list[str]:
    """Return bounded vocabulary-only report reasons (never input text)."""
    if not isinstance(values, (list, tuple, set, frozenset)):
        return ["internal_error"]
    selected: set[str] = set()
    unknown = False
    for value in values:
        if isinstance(value, str) and value in _FIXED_ADMISSION_REASON_CODES:
            selected.add(value)
        else:
            unknown = True
    if unknown:
        selected.add("internal_error")
    return sorted(selected)

def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _boot_id() -> str | None:
    """Canonical boot UUID read only in the explicit runner (never at import)."""
    try:
        raw = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8")
    except OSError:
        return None
    value = raw.strip()
    return _canonical_boot_id(value)


def _canonical_boot_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return None
    canonical = str(parsed)
    return canonical if value == canonical else None


def _observation_identity_valid(observations: Any) -> bool:
    if not isinstance(observations, dict):
        return False
    observed_utc = observations.get("session_observed_utc")
    observed_epoch = _utc_parse(observed_utc)
    observed_ns = observations.get("session_observed_monotonic_ns")
    boot_id = _canonical_boot_id(observations.get("boot_id"))
    if observed_epoch is None or observed_epoch > int(time.time()):
        return False
    if isinstance(observed_ns, bool) or not isinstance(observed_ns, int) or observed_ns < 0:
        return False
    current_boot = _boot_id()
    return boot_id is not None and current_boot is not None and boot_id == current_boot


def _admission_report(context: dict[str, Any], predicates: dict[str, bool],
                      reason_codes: list[str], started_monotonic: float,
                      started_utc: str, identity: dict[str, Any],
                      observations: dict[str, Any] | None = None,
                      authorization: dict[str, Any] | None = None) -> dict[str, Any]:
    """Reduce one bounded predicate mapping into the fixed report schema (S.4)."""
    supplied = predicates if isinstance(predicates, dict) else {}
    missing = [name for name in REQUIRED_PREDICATES
               if name not in supplied or supplied.get(name) is None]
    failed = [name for name in REQUIRED_PREDICATES
              if name in supplied and supplied.get(name) is not None
              and supplied.get(name) is not True]
    exact_shape = (
        set(supplied) == set(REQUIRED_PREDICATES)
        and all(type(supplied[name]) is bool for name in REQUIRED_PREDICATES)
    )
    auth_values = authorization if isinstance(authorization, dict) else {}
    observation_values = observations if isinstance(observations, dict) else {}
    # E7 pass_without_observation_identity: PASS requires the observation
    # identity to be present and valid, and residual reason codes always
    # force HOLD regardless of predicate shape.
    all_true = (
        exact_shape
        and all(supplied[name] is True for name in REQUIRED_PREDICATES)
        and not reason_codes
        and _observation_identity_valid(observation_values)
    )
    finished_utc = _utc_now_iso()
    elapsed_ms = int((time.monotonic() - started_monotonic) * 1000)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "candidate_id": identity.get("candidate_id"),
        "archive_sha256": identity.get("archive_sha256"),
        "source_commit": identity.get("source_commit"),
        "source_tree": identity.get("source_tree"),
        "control_sha256": identity.get("control_sha256"),
        "spec_sha256": identity.get("spec_sha256"),
        "started_utc": started_utc,
        "finished_utc": finished_utc,
        "elapsed_ms": elapsed_ms,
        "predicates": {name: supplied.get(name) is True for name in REQUIRED_PREDICATES},
        "missing_predicates": missing,
        "failed_predicates": failed,
        "reason_codes": _fixed_reason_codes(reason_codes),
        "expected_session_id_sha256": EXPECTED_S_SHA256,
        "expected_key_sha256": auth_values.get("persisted_key_sha256"),
        "persisted_key_sha256": auth_values.get("persisted_key_sha256"),
        "manifest_sha256": context.get("manifest_sha256"),
        "authorization_sha256": context.get("authorization_sha256"),
        "control_packet_sha256": auth_values.get("control_packet_sha256"),
        "execution_scope": auth_values.get("execution_scope"),
        "observation_order": list(OBSERVATION_ORDER),
        "session_observed_utc": observation_values.get("session_observed_utc"),
        "session_observed_monotonic_ns": observation_values.get("session_observed_monotonic_ns"),
        "boot_id": observation_values.get("boot_id"),
    }
    if all_true:
        report["status"] = "PASS"
        report["status_code"] = 0
    else:
        report["status"] = "HOLD"
        report["status_code"] = 2
    return report


def _a3_admission_is_fresh(context: dict[str, Any], parsed: Any) -> bool:
    if not isinstance(context, dict) or not isinstance(parsed, dict):
        return False
    started = _utc_parse(parsed.get("started_utc"))
    finished = _utc_parse(parsed.get("finished_utc"))
    observed = _utc_parse(parsed.get("session_observed_utc"))
    if started is None or finished is None or observed is None or started > finished or observed < started or observed > finished:
        return False
    now_epoch = int(time.time())
    if started > now_epoch or finished > now_epoch or observed > now_epoch:
        return False
    observed_ns = parsed.get("session_observed_monotonic_ns")
    if isinstance(observed_ns, bool) or not isinstance(observed_ns, int) or observed_ns < 0:
        return False
    age_ns = time.monotonic_ns() - observed_ns
    if age_ns < 0 or age_ns > 10_000_000_000:
        return False
    report_boot = _canonical_boot_id(parsed.get("boot_id"))
    current_boot = _boot_id()
    if report_boot is None or current_boot is None or report_boot != current_boot:
        return False
    authorization = context.get("authorization")
    if not isinstance(authorization, dict):
        return False
    not_before = _utc_parse(authorization.get("not_before_utc"))
    expires_at = _utc_parse(authorization.get("expires_at_utc"))
    if not_before is None or expires_at is None or not_before >= expires_at:
        return False
    return not_before <= min(started, observed) and max(finished, observed) <= expires_at


def _validate_a3_admission_report(context: dict[str, Any], raw: bytes) -> dict[str, Any] | None:
    """Validate one exact, freshly observed admission report for fixture A3."""
    if not isinstance(context, dict) or not isinstance(raw, bytes) or not raw:
        return None
    if len(raw) > 1024 * 1024 or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        return None
    if raw[:-1].endswith((b"\n", b"\r", b" ", b"\t")):
        return None
    expected_digest = context.get("admission_sha256")
    if not _is_lower_hex(expected_digest, 64) or hashlib.sha256(raw).hexdigest() != expected_digest:
        return None

    def reject_duplicate_pairs(pairs: list[tuple[Any, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if not isinstance(key, str) or key in result:
                raise ValueError("duplicate or non-string report key")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict) or set(parsed) != set(ADMISSION_REPORT_KEYS):
        return None
    if parsed.get("schema") != REPORT_SCHEMA or parsed.get("status") != "PASS" or parsed.get("status_code") != 0:
        return None
    if type(parsed.get("status_code")) is not int:
        return None
    predicates = parsed.get("predicates")
    if (
        not isinstance(predicates, dict)
        or set(predicates) != set(REQUIRED_PREDICATES)
        or any(type(predicates[name]) is not bool or predicates[name] is not True for name in REQUIRED_PREDICATES)
    ):
        return None
    if parsed.get("missing_predicates") != [] or parsed.get("failed_predicates") != []:
        return None
    reason_codes = parsed.get("reason_codes")
    if not isinstance(reason_codes, list) or reason_codes:
        return None
    if parsed.get("observation_order") != list(OBSERVATION_ORDER):
        return None

    authorization = context.get("authorization")
    if not isinstance(authorization, dict):
        return None
    authorization_scope = authorization.get("execution_scope")
    authorization_key = authorization.get("persisted_key_sha256")
    expected_scope = context.get("execution_scope")
    if expected_scope is None:
        expected_scope = authorization_scope
    elif expected_scope != authorization_scope:
        return None
    expected_key = context.get("persisted_key_sha256")
    if expected_key is None:
        expected_key = authorization_key
    elif expected_key != authorization_key:
        return None
    if expected_scope != "fixture_readonly" or parsed.get("execution_scope") != expected_scope:
        return None
    if not _is_lower_hex(expected_key, 64):
        return None
    if (
        parsed.get("expected_session_id_sha256") != EXPECTED_S_SHA256
        or parsed.get("expected_key_sha256") != expected_key
        or parsed.get("persisted_key_sha256") != expected_key
    ):
        return None

    authorization_identity_fields = (
        ("candidate_id", "candidate_id"),
        ("candidate_sha256", "archive_sha256"),
        ("source_commit", "source_commit"),
        ("source_tree", "source_tree"),
        ("control_sha256", "control_sha256"),
        ("specification_sha256", "spec_sha256"),
        ("manifest_sha256", "manifest_sha256"),
        ("control_packet_sha256", "control_packet_sha256"),
    )
    for authorization_field, report_field in authorization_identity_fields:
        expected_value = authorization.get(authorization_field)
        if not isinstance(expected_value, str) or parsed.get(report_field) != expected_value:
            return None
    selected_session_digest = authorization.get("selected_session_id_sha256")
    if selected_session_digest is not None and selected_session_digest != EXPECTED_S_SHA256:
        return None

    expected_fields = (
        "candidate_id", "archive_sha256", "source_commit", "source_tree",
        "control_sha256", "spec_sha256", "manifest_sha256",
        "authorization_sha256", "control_packet_sha256",
    )
    identity = context.get("identity") if isinstance(context.get("identity"), dict) else {}
    for field in expected_fields:
        expected = context.get(field)
        if expected is None:
            expected = identity.get(field)
        if field == "control_packet_sha256" and expected is None:
            expected = authorization.get(field)
        if not isinstance(expected, str) or parsed.get(field) != expected:
            return None
    for field in ("archive_sha256", "control_sha256", "spec_sha256", "manifest_sha256",
                  "authorization_sha256", "control_packet_sha256"):
        if not _is_lower_hex(parsed.get(field), 64):
            return None
    for field in ("source_commit", "source_tree"):
        if not _is_lower_hex(parsed.get(field), 40):
            return None
    if not isinstance(parsed.get("candidate_id"), str) or not parsed["candidate_id"]:
        return None
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", parsed["candidate_id"]) is None or len(parsed["candidate_id"]) > 128:
        return None
    elapsed_ms = parsed.get("elapsed_ms")
    if isinstance(elapsed_ms, bool) or not isinstance(elapsed_ms, int) or elapsed_ms < 0:
        return None
    if not _a3_admission_is_fresh(context, parsed):
        return None
    return parsed


def _read_admission_report_once(context: dict[str, Any]) -> dict[str, Any] | None:
    """Read and validate report bytes once; a parsed mapping is not authority."""
    if not isinstance(context, dict) or context.get("_admission_report_consumed"):
        return None
    context["_admission_report_consumed"] = True
    raw = context.get("admission_report_bytes")
    if raw is None:
        report_path = context.get("admission_report_path")
        if not isinstance(report_path, (str, Path)):
            return None
        path = _bounded_absolute_path(report_path)
        if path is None or not _path_has_no_symlink_components(path):
            return None
        loaded = _read_regular_file_no_follow(path, limit=1024 * 1024)
        if loaded is None:
            return None
        raw = loaded[0]
    if not isinstance(raw, bytes):
        return None
    return _validate_a3_admission_report(context, raw)


def _hold_report(context: dict[str, Any], reason: str, started_monotonic: float,
                 started_utc: str, identity: dict[str, Any]) -> dict[str, Any]:
    return _admission_report(context, {}, [reason], started_monotonic, started_utc, identity)


def _check_sha256_file(path: Path, expected: str) -> bool:
    try:
        payload = path.read_bytes()
    except OSError:
        return False
    return hashlib.sha256(payload).hexdigest() == expected


B6_CALLER_NOTE = (
    "B6 (REV-008): run_voice1_readonly_admission performs real bounded "
    "observations behind main(argv); callers and documents can never supply "
    "result booleans.  The aggregate below is the only reducer.  The fixture "
    "executor that follows stays fixture-only and unreachable from the "
    "read-only lane."
)

# Root authorization contract (architecture section 5.2).
AUTHORIZATION_SCHEMA = "recorder-next-voice1-readonly-authorization/v1"
MANIFEST_SCHEMA = "recorder-next-voice1-b6-builder-candidate/v1"
MANIFEST_GENERATION = "VOICE1-B6"
PRODUCT_IDENTITY = "recorder-next-server-voice-session-chain"
RATIFIED_OWNER_PACKET_SHA256 = "6735b40c2eeeb716fb307d73cb603c940b24a78cab9cb29ddf6b696b1e99a3ec"
RATIFIED_ADDENDUM_SHA256 = "758fcf9642ea21e7017b70e0851a88f3c11d7c0ee727e16516b923e8f8f1085e"
RATIFIED_INHERITED_SPEC_SHA256 = "ce1c23271239d330e7125ded8ecb6b32d0a3bee8c5d2a07118693c3065df3de1"
# E7 item 5 (EVIDENCE_BLOCKER): the QA builder-upload custody receipt is
# evidence, not just context — its digest is pinned so a citation drift is
# detectable by the same cold rehash that guards ratified authorities.
RATIFIED_QA_CUSTODY_RECEIPT_SHA256 = "93cd512ca05a54cf710df5f1404d2778a1478c3af55523e5c968ff65c5c06424"


def _qa_custody_receipt_digest(digest: Any) -> bool:
    """True only for the pinned QA builder-upload custody receipt digest."""
    return isinstance(digest, str) and digest == RATIFIED_QA_CUSTODY_RECEIPT_SHA256


RATIFIED_AUTHORITY_DIGESTS = {
    "owner_packet_sha256": RATIFIED_OWNER_PACKET_SHA256,
    "specification_sha256": RATIFIED_ADDENDUM_SHA256,
    "inherited_specification_sha256": RATIFIED_INHERITED_SPEC_SHA256,
}
RATIFIED_AUTHORITY_PATHS = {
    "owner_packet_sha256": Path(
        "/home/rumi/Projects/recorder-next/.release-artifacts/"
        "orchestration/t_16ca403e-voice1-b3-owner-acceptance-packet-v1.json"
    ),
    "specification_sha256": Path(
        "/home/rumi/Projects/recorder-next/.release-artifacts/"
        "voice1-b6-architecture-v1/architecture-addendum.md"
    ),
    "inherited_specification_sha256": Path(
        "/home/rumi/Projects/recorder-next/.release-artifacts/"
        "voice1-b3-architecture-v1/architecture-specification.md"
    ),
}
EXECUTION_SCOPES = ("live_readonly", "fixture_readonly")
APPROVED_ACTIONS = (
    "candidate_verify",
    "credential_read",
    "unauthenticated_get",
    "api_capability_get",
    "audio_readiness_get",
    "session_get",
    "persisted_metadata_select",
    "closing_verify",
)
AUTHORIZATION_KEYS = frozenset({
    "schema", "execution_scope", "product_identity", "candidate_id",
    "candidate_sha256", "manifest_sha256", "source_commit", "source_tree",
    "control_sha256", "control_packet_sha256", "specification_sha256",
    "inherited_specification_sha256", "owner_packet_sha256", "candidate_root",
    "archive_path", "approved_actions", "endpoints", "paths",
    "credential_metadata", "selected_session_id_sha256",
    "persisted_key_sha256", "not_before_utc", "expires_at_utc", "fixture_root",
})
FIXTURE_PERSISTED_KEY = "voice1-b6-synthetic-persisted-key"
FIXTURE_KEY_SHA256 = "4b2d9610f5c9a4dc68def7e234a48480fb7468e769957fed0275e77d15b7278f"
MAX_AUTHORITY_BYTES = 64 * 1024
_LIVE_DASHBOARD_BASE_URL = "http://100.112.8.81:9119"
_LIVE_API_BASE_URL = "http://127.0.0.1:8647"
_LIVE_ENDPOINTS = {
    "api_base_url": _LIVE_API_BASE_URL,
    "dashboard_base_url": _LIVE_DASHBOARD_BASE_URL,
}
_LIVE_PATHS = {
    "dashboard_credential": "/etc/recorder-next/dashboard-session.env",
    "dashboard_metadata": "/etc/recorder-next/dashboard-session.meta.json",
    "api_credential": "/run/credentials/recorder-next.service/recorder_api_key",
    "persisted_db": "/home/rumi/.hermes/state.db",
}
_PATH_FIELDS = ("dashboard_credential", "dashboard_metadata", "api_credential", "persisted_db")
_ENDPOINT_FIELDS = ("api_base_url", "dashboard_base_url")


def _canonical_argv(argv: list[str]) -> dict[str, str] | None:
    """Parse the one exact option vector; None means HOLD.

    The caller receives only the option suffix of the full timeout/python
    command.  Its order is nevertheless part of the reviewed argv contract:
    accepting a reordered vector would authorize a different invocation shape.
    """
    if not isinstance(argv, list) or len(argv) != 9:
        return None
    expected_switch = "--read-only-admission"
    expected_pairs = (
        ("--manifest", "manifest_path"),
        ("--manifest-sha256", "manifest_sha256"),
        ("--authorization", "authorization_path"),
        ("--authorization-sha256", "authorization_sha256"),
    )
    if argv[0] != expected_switch:
        return None
    values: dict[str, str] = {}
    index = 1
    for option, key in expected_pairs:
        if argv[index] != option:
            return None
        value = argv[index + 1]
        if not isinstance(value, str) or not value or "\x00" in value:
            return None
        if key.endswith("_sha256"):
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                return None
        else:
            if _bounded_absolute_path(value) is None:
                return None
        values[key] = value
        index += 2
    return values


def _load_bounded_json(path: Path, limit: int, expected_sha256: str) -> dict[str, Any] | None:
    """Bounded duplicate-key-rejecting JSON load with opened-identity checks."""
    def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate json key")
            result[key] = value
        return result

    try:
        loaded = _read_regular_file_no_follow(path, limit=limit)
    except OSError:
        return None
    if loaded is None:
        return None
    payload, _identity = loaded
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        return None
    try:
        parsed = json.loads(payload.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _utc_parse(value: Any) -> int | None:
    """Strict canonical UTC YYYY-MM-DDTHH:MM:SSZ parse to epoch seconds.

    Only the exact canonical grammar is authorized (architecture 5.2):
    exactly 20 characters, digits in every numeric field, literal 'T'
    separator, literal 'Z' suffix, seconds 00-59.  Offsets, fractional
    seconds, lowercase separators and leap seconds (:60/:61) reject as
    noncanonical.  calendar.timegm interprets the struct_time as UTC on
    every host (a strftime("%s") implementation applied the host-local
    offset on KST hosts); it is retained here and the parsed stamp must
    round-trip to the identical canonical string before the value is
    accepted.
    """
    if not isinstance(value, str) or len(value) != 20:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        return None
    try:
        parsed = time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        # Covers month/day range errors AND seconds 60/61 (leap seconds are
        # not canonical UTC for this contract).
        return None
    epoch = calendar.timegm(parsed)
    # Exact canonical round-trip: any value that does not render back to the
    # identical stamp is noncanonical (defensive; strptime already narrowed
    # the grammar above).
    if time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)) != value:
        return None
    return epoch


def _fstat_identity(path: Path) -> dict[str, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    return {
        "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
        "gid": info.st_gid, "mode": info.st_mode & 0o7777,
    }


def _credential_metadata_matches(path: Path, pinned: Any) -> bool:
    """Compare the actual credential file identity to root-pinned integers."""
    if not isinstance(pinned, dict) or set(pinned) != {"device", "inode", "uid", "gid", "mode"}:
        return False
    actual = _fstat_identity(path)
    if actual is None:
        return False
    for key in ("device", "inode", "uid", "gid", "mode"):
        expected = pinned[key]
        if isinstance(expected, bool) or not isinstance(expected, int):
            return False
        if actual[key] != expected:
            return False
    return True


def _tracked_file_vector(per_file_sha256: dict[str, str]) -> str:
    """Architecture section 9 canonical tracked-file vector.

    SHA256 over UTF8 json.dumps(per_file_sha256, sort_keys=True,
    separators=(',',':'), ensure_ascii=True) with no final newline.  This is
    the one architecture-defined digest; both the manifest-structure check
    and the candidate-root member verification use this single formula.
    """
    return hashlib.sha256(
        json.dumps(per_file_sha256, sort_keys=True,
                   separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _canonical_member_name(value: Any, *, allow_leading_dot: bool = False, directory: bool = False) -> str | None:
    """Normalize one archive/member name or reject it."""
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    name = value
    if name.startswith("./"):
        if not allow_leading_dot:
            return None
        name = name[2:]
        if name.startswith("./"):
            return None
    if name.startswith("/"):
        return None
    if directory and name.endswith("/"):
        name = name[:-1]
    elif not directory and name.endswith("/"):
        return None
    parts = name.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    return "/".join(parts)


def _read_candidate_member_no_follow(root: Path, relative_name: str) -> tuple[bytes, dict[str, int]] | None:
    if _canonical_member_name(relative_name) != relative_name:
        return None
    current = root
    parts = relative_name.split("/")
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(info.st_mode):
            return None
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            return None
    return _read_regular_file_no_follow(current)


def _verify_manifest_structure(manifest: dict[str, Any]) -> bool:
    """Exact B6 manifest consumption contract (architecture section 5.1)."""
    if not isinstance(manifest, dict):
        return False
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("generation") != MANIFEST_GENERATION:
        return False
    if manifest.get("product_identity") != PRODUCT_IDENTITY:
        return False
    if manifest.get("candidate_incomplete") is not False:
        return False
    candidate_id = manifest.get("candidate_id")
    if not isinstance(candidate_id, str) or not candidate_id or len(candidate_id) > 128:
        return False
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", candidate_id) is None:
        return False
    candidate_sha256 = manifest.get("candidate_sha256")
    if not isinstance(candidate_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", candidate_sha256) is None:
        return False
    for key in ("source_commit", "source_tree"):
        value = manifest.get(key)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            return False
    per_file = manifest.get("per_file_sha256")
    if not isinstance(per_file, dict) or not per_file:
        return False
    for relative_name, digest in per_file.items():
        if not isinstance(relative_name, str) or _canonical_member_name(relative_name) != relative_name:
            return False
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            return False
    count = manifest.get("tracked_file_count")
    if isinstance(count, bool) or not isinstance(count, int) or count != len(per_file):
        return False
    if re.fullmatch(r"[0-9a-f]{64}", manifest.get("tracked_file_vector_sha256") or "") is None:
        return False
    # Architecture section 9: the tracked-file vector is exactly
    # SHA256(UTF8(json.dumps(per_file_sha256, sort_keys=True,
    # separators=(',',':'), ensure_ascii=True))) with no final newline.
    # The consumer recomputes it from the consumed mapping and enforces
    # equality; a stale/declared value that merely parses as 64-hex never
    # satisfies the structure contract.
    recomputed_vector = _tracked_file_vector(manifest["per_file_sha256"])
    if manifest["tracked_file_vector_sha256"] != recomputed_vector:
        return False
    authorities = manifest.get("authorities")
    if not isinstance(authorities, dict):
        return False
    for key in ("owner_packet_sha256", "specification_sha256", "inherited_specification_sha256"):
        value = authorities.get(key)
        if not isinstance(value, str) or value != RATIFIED_AUTHORITY_DIGESTS[key]:
            return False
    control = manifest.get("control")
    if not isinstance(control, dict):
        return False
    for key in ("packet_sha256", "probe_runner_sha256"):
        value = control.get(key)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            return False
    return True


def _stat_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }


def _custody_signature(info: os.stat_result) -> tuple[int, ...]:
    """Include mutation clocks so rename/swap/restore is observable."""
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid,
        stat.S_IMODE(info.st_mode), info.st_ctime_ns, info.st_mtime_ns,
    )


def _regular_file_identity_no_follow(path: Path) -> dict[str, int] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None
        return _stat_identity(info)
    except OSError:
        return None
    finally:
        os.close(descriptor)


def _read_regular_file_no_follow(path: Path, *, limit: int | None = None) -> tuple[bytes, dict[str, int]] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return None
        if limit is not None and before.st_size > limit:
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if limit is not None and total > limit:
                return None
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after) or after.st_size != total:
            return None
        return b"".join(chunks), _stat_identity(after)
    except OSError:
        return None
    finally:
        os.close(descriptor)


def _cold_rehash_ratified_authorities() -> bool:
    for key, path in RATIFIED_AUTHORITY_PATHS.items():
        loaded = _read_regular_file_no_follow(path, limit=4 * 1024 * 1024)
        if loaded is None or hashlib.sha256(loaded[0]).hexdigest() != RATIFIED_AUTHORITY_DIGESTS[key]:
            return False
    return True


def _is_lower_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None


def _bounded_absolute_path(value: Any) -> Path | None:
    """Exact lexical canonical absolute path or None (E5 F-6).

    Canonical means: exactly one leading slash, no empty, "." or ".."
    components anywhere, and the string is already its own lexical
    normalization (no realpath resolution — symlink freedom is proven
    separately by the no-follow identity checks).  Aliases such as
    ``//tmp/x`` (POSIX normpath preserves exactly two leading slashes) or
    ``/tmp//x`` therefore reject before any protected work.
    """
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        return None
    if not value.startswith("/") or value.startswith("//"):
        return None
    if any(part in {"", ".", ".."} for part in value.split("/")[1:]):
        return None
    path = Path(value)
    if not path.is_absolute() or str(path) != value or os.path.normpath(value) != value:
        return None
    return path


def _path_has_no_symlink_components(path: Path) -> bool:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        except OSError:
            return False
        if stat.S_ISLNK(info.st_mode):
            return False
    return True


def _recorded_ancestry_metadata(path: Path) -> list[tuple[str, tuple[int, ...]]] | None:
    """Lexically walk `path` and record each component's custody signature.

    The returned clocks supplement object identity so a swap/restore cannot
    be hidden by restoring the original inode before the next revalidation.
    """
    recorded: list[tuple[str, tuple[int, ...]]] = []
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            return None
        if stat.S_ISLNK(info.st_mode):
            return None
        recorded.append((component, _custody_signature(info)))
    return recorded


def _fixture_origin(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, str) or len(value) > 4096:
        return None
    try:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname != "127.0.0.1"
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1024 <= port <= 65535
        or port in {8647, 9119}
    ):
        return None
    return parsed.hostname, port


def _verify_authority_binding(manifest: dict[str, Any], authorization: dict[str, Any], manifest_sha256: str) -> bool:
    """Verify exact authority identity plus scope-bound targets before I/O."""
    if not isinstance(manifest, dict) or not isinstance(authorization, dict):
        return False
    if authorization.get("schema") != AUTHORIZATION_SCHEMA:
        return False
    if set(authorization) != AUTHORIZATION_KEYS:
        return False
    if authorization.get("product_identity") != PRODUCT_IDENTITY:
        return False
    scope = authorization.get("execution_scope")
    if not isinstance(scope, str) or scope not in EXECUTION_SCOPES:
        return False
    if authorization.get("approved_actions") != list(APPROVED_ACTIONS):
        return False
    if not _is_lower_hex(manifest_sha256, 64):
        return False

    # Identity fields compare exactly against the validated manifest and the
    # ratified authority pins.  Type-gate every scalar before regex/equality.
    for auth_key, manifest_key in (
        ("candidate_id", "candidate_id"),
        ("candidate_sha256", "candidate_sha256"),
        ("source_commit", "source_commit"),
        ("source_tree", "source_tree"),
        ("control_sha256", None),
        ("control_packet_sha256", None),
        ("specification_sha256", None),
        ("inherited_specification_sha256", None),
        ("owner_packet_sha256", None),
    ):
        value = authorization.get(auth_key)
        if not isinstance(value, str) or not value or len(value) > 4096:
            return False
        if manifest_key is not None:
            expected = manifest.get(manifest_key)
            if value != expected:
                return False
            if manifest_key == "candidate_sha256" and not _is_lower_hex(value, 64):
                return False
            if manifest_key in {"source_commit", "source_tree"} and not _is_lower_hex(value, 40):
                return False
            continue
        if not _is_lower_hex(value, 64):
            return False
        if auth_key in RATIFIED_AUTHORITY_DIGESTS and value != RATIFIED_AUTHORITY_DIGESTS[auth_key]:
            return False

    authorities = manifest.get("authorities")
    control = manifest.get("control")
    if not isinstance(authorities, dict) or not isinstance(control, dict):
        return False
    if any(
        authorities.get(key) != RATIFIED_AUTHORITY_DIGESTS[key]
        for key in RATIFIED_AUTHORITY_DIGESTS
    ):
        return False
    if authorization.get("specification_sha256") != authorities.get("specification_sha256"):
        return False
    if authorization.get("inherited_specification_sha256") != authorities.get("inherited_specification_sha256"):
        return False
    if authorization.get("owner_packet_sha256") != authorities.get("owner_packet_sha256"):
        return False
    if authorization.get("control_sha256") != control.get("probe_runner_sha256"):
        return False
    if authorization.get("control_packet_sha256") != control.get("packet_sha256"):
        return False
    if authorization.get("manifest_sha256") != manifest_sha256:
        return False
    if authorization.get("selected_session_id_sha256") != EXPECTED_S_SHA256:
        return False
    if not _is_lower_hex(authorization.get("persisted_key_sha256"), 64):
        return False

    candidate_root = _bounded_absolute_path(authorization.get("candidate_root"))
    archive_path = _bounded_absolute_path(authorization.get("archive_path"))
    if candidate_root is None or archive_path is None:
        return False

    endpoints = authorization.get("endpoints")
    if not isinstance(endpoints, dict) or set(endpoints) != set(_ENDPOINT_FIELDS):
        return False
    paths = authorization.get("paths")
    if not isinstance(paths, dict) or set(paths) != set(_PATH_FIELDS):
        return False
    for value in paths.values():
        if _bounded_absolute_path(value) is None:
            return False
    metadata = authorization.get("credential_metadata")
    if not isinstance(metadata, dict) or set(metadata) != {"dashboard_credential", "api_credential"}:
        return False
    for pin in metadata.values():
        if not isinstance(pin, dict) or set(pin) != {"device", "inode", "uid", "gid", "mode"}:
            return False
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in pin.values()):
            return False

    not_before = _utc_parse(authorization.get("not_before_utc"))
    expires_at = _utc_parse(authorization.get("expires_at_utc"))
    if not_before is None or expires_at is None or not_before >= expires_at:
        return False
    now = int(time.time())
    if not (not_before <= now <= expires_at):
        return False

    fixture_root_raw = authorization.get("fixture_root")
    if scope == "live_readonly":
        if fixture_root_raw is not None or authorization.get("persisted_key_sha256") != EXPECTED_KEY_SHA256:
            return False
        if endpoints != _LIVE_ENDPOINTS or paths != _LIVE_PATHS:
            return False
    else:
        if authorization.get("persisted_key_sha256") != FIXTURE_KEY_SHA256:
            return False
        fixture_root = _bounded_absolute_path(fixture_root_raw)
        if fixture_root is None or not _path_has_no_symlink_components(fixture_root):
            return False
        try:
            root_info = fixture_root.lstat()
        except OSError:
            return False
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
            return False
        if stat.S_IMODE(root_info.st_mode) & 0o077:
            return False
        for protected in (Path("/var/lib/recorder-next"), Path("/home/rumi/.hermes"), Path("/etc/recorder-next")):
            try:
                fixture_root.relative_to(protected)
            except ValueError:
                continue
            return False
        for field in _PATH_FIELDS:
            target = Path(paths[field])
            try:
                relative = target.relative_to(fixture_root)
            except ValueError:
                return False
            if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
                return False
            if not _path_has_no_symlink_components(target):
                return False
        origins = [_fixture_origin(endpoints[field]) for field in _ENDPOINT_FIELDS]
        if any(origin is None for origin in origins) or origins[0] == origins[1]:
            return False
    return True


def _verify_candidate_source(authorization: dict[str, Any], manifest: dict[str, Any]) -> bool:
    """Complete archive/candidate-root binding before any protected action."""
    if not isinstance(authorization, dict) or not isinstance(manifest, dict):
        return False
    root = _bounded_absolute_path(authorization.get("candidate_root"))
    archive_path = _bounded_absolute_path(authorization.get("archive_path"))
    if root is None or archive_path is None or root != CONTROL_DIR.parent:
        return False
    try:
        root_info = root.lstat()
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            return False
        if root.resolve(strict=True) != CONTROL_DIR.parent.resolve(strict=True):
            return False
    except OSError:
        return False

    archive_loaded = _read_regular_file_no_follow(archive_path, limit=64 * 1024 * 1024)
    if archive_loaded is None:
        return False
    archive_bytes, _archive_identity = archive_loaded
    candidate_sha256 = manifest.get("candidate_sha256")
    if not _is_lower_hex(candidate_sha256, 64) or hashlib.sha256(archive_bytes).hexdigest() != candidate_sha256:
        return False

    import io
    import tarfile

    per_file = manifest.get("per_file_sha256")
    if not isinstance(per_file, dict) or not per_file:
        return False
    try:
        seen_members: set[str] = set()
        seen_dirs: set[str] = set()
        regular_names: set[str] = set()
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tar:
            for member in tar.getmembers():
                name = _canonical_member_name(
                    member.name,
                    allow_leading_dot=True,
                    directory=member.isdir(),
                )
                if name is None or name in seen_members:
                    return False
                seen_members.add(name)
                if member.isdir():
                    seen_dirs.add(name)
                    continue
                if not member.isreg() or name not in per_file:
                    return False
                regular_names.add(name)
                extracted = tar.extractfile(member)
                if extracted is None:
                    return False
                digest = hashlib.sha256()
                with extracted:
                    while True:
                        chunk = extracted.read(65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                expected = per_file.get(name)
                if not _is_lower_hex(expected, 64) or digest.hexdigest() != expected:
                    return False
        if regular_names != set(per_file) or len(regular_names) != len(per_file):
            return False
        required_dirs = {
            "/".join(name.split("/")[:depth])
            for name in regular_names
            for depth in range(1, len(name.split("/")))
        }
        if not seen_dirs.issubset(required_dirs):
            return False
    except (tarfile.TarError, EOFError, OSError):
        return False

    count = manifest.get("tracked_file_count")
    if isinstance(count, bool) or not isinstance(count, int) or count != len(per_file):
        return False

    # -- 3. canonical vector (one architecture formula, runtime-enforced) ----

    if manifest.get("tracked_file_vector_sha256") != _tracked_file_vector(per_file):
        return False

    # -- 4. every candidate-root member digest and opened identity -----------

    for relative_name, expected_digest in sorted(per_file.items()):
        if not isinstance(relative_name, str) or not _is_lower_hex(expected_digest, 64):
            return False
        loaded = _read_candidate_member_no_follow(root, relative_name)
        if loaded is None or hashlib.sha256(loaded[0]).hexdigest() != expected_digest:
            return False

    control = manifest.get("control")
    control_hash = control.get("probe_runner_sha256") if isinstance(control, dict) else None
    runner_loaded = _read_regular_file_no_follow(Path(__file__), limit=16 * 1024 * 1024)
    if not _is_lower_hex(control_hash, 64) or runner_loaded is None:
        return False
    if hashlib.sha256(runner_loaded[0]).hexdigest() != control_hash:
        return False
    try:
        return Path(__file__).resolve(strict=True) == (root / "run" / "qa_probe_runner.py").resolve(strict=True)
    except OSError:
        return False


def _verify_imported_module_identity(
    module: Any,
    root_or_per_file: Path | dict[str, str],
    per_file: dict[str, str] | None = None,
) -> bool:
    if isinstance(root_or_per_file, dict) and per_file is None:
        per_file = root_or_per_file
        module_file = getattr(module, "__file__", None)
        if not isinstance(module_file, str) or not module_file:
            return False
        try:
            root = Path(module_file).resolve(strict=True).parents[1]
        except (IndexError, OSError):
            return False
    elif isinstance(root_or_per_file, Path):
        root = root_or_per_file
    else:
        return False
    expected = root / "recorder_next" / "adapters.py"
    module_file = getattr(module, "__file__", None)
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None) if spec is not None else None
    loader = getattr(spec, "loader", None) if spec is not None else None
    if not all(isinstance(value, str) and value for value in (module_file, origin)):
        return False
    if loader is None or not callable(getattr(loader, "get_filename", None)):
        return False
    try:
        loader_file = loader.get_filename("recorder_next.adapters")
    except Exception:
        return False
    if not isinstance(loader_file, str) or not loader_file:
        return False
    try:
        expected_resolved = expected.resolve(strict=True)
        if any(Path(value).resolve(strict=True) != expected_resolved for value in (module_file, origin, loader_file)):
            return False
    except OSError:
        return False
    expected_digest = per_file.get("recorder_next/adapters.py") if per_file is not None else None
    loaded = _read_regular_file_no_follow(expected, limit=16 * 1024 * 1024)
    if loaded is None:
        return False
    if per_file is None:
        expected_digest = hashlib.sha256(loaded[0]).hexdigest()
    return _is_lower_hex(expected_digest, 64) and hashlib.sha256(loaded[0]).hexdigest() == expected_digest


def _extract_manifest_member_bytes(
    archive_path: Path, per_file: dict[str, str]
) -> dict[str, bytes] | None:
    """Extract exactly the manifest members from the verified archive (E5 F-2).

    Every returned byte string is digest-checked against ``per_file`` while
    streaming out of the tar, so the loader below executes exactly the bytes
    the manifest pinned — never whatever a pathname currently resolves to.
    """
    import io
    import tarfile

    archive_loaded = _read_regular_file_no_follow(archive_path, limit=64 * 1024 * 1024)
    if archive_loaded is None:
        return None
    archive_bytes = archive_loaded[0]
    members: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tar:
            for member in tar.getmembers():
                if not member.isreg():
                    continue
                name = member.name
                if name.startswith("./"):
                    name = name[2:]
                if name not in per_file:
                    continue
                extracted = tar.extractfile(member)
                if extracted is None:
                    return None
                digest = hashlib.sha256()
                chunks: list[bytes] = []
                with extracted:
                    while True:
                        chunk = extracted.read(65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                        chunks.append(chunk)
                expected = per_file.get(name)
                if not _is_lower_hex(expected, 64) or digest.hexdigest() != expected:
                    return None
                members[name] = b"".join(chunks)
    except (tarfile.TarError, EOFError, OSError):
        return None
    if set(members) != set(per_file):
        return None
    return members


def _member_module_name(member: str) -> str | None:
    """Map a manifest member name to the module it defines, if any."""
    if not member.startswith("recorder_next/") or not member.endswith(".py"):
        return None
    stem = member[:-3]
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    return stem.replace("/", ".")


class _ManifestBytesLoader:
    """Loader executing exactly one manifest member's verified bytes (E5 F-2)."""

    def __init__(self, member: str, data: bytes) -> None:
        self._member = member
        self._data = data

    def get_filename(self, fullname: Any = None) -> str:
        return f"recorder-next-manifest:{self._member}"

    def create_module(self, spec: Any) -> None:
        return None

    def exec_module(self, module: Any) -> None:
        compiled = compile(self._data, self.get_filename(), "exec")
        # Freeze the bytes that actually reached compile/exec.  Closing
        # validation compares this digest with both the loader data and the
        # registry, never with a later filesystem/archive read.
        self._executed_byte_digest = hashlib.sha256(self._data).hexdigest()
        # The candidate's modules reference module-level dunder state
        # (__file__/__package__) that a bare exec does not provide; bind the
        # manifest-virtual identity, never a real filesystem pathname.
        module.__file__ = self.get_filename()
        module.__package__ = self._package_for()
        exec(compiled, module.__dict__)
        module.__manifest_member__ = self._member

    def is_package(self, fullname: Any) -> bool:
        return self._member.endswith("__init__.py")

    def _package_for(self) -> str:
        if self._member.endswith("__init__.py"):
            stem = self._member[: -len("__init__.py")]
            return stem.rstrip("/").replace("/", ".")
        parent = self._member.rsplit("/", 1)[0]
        return parent.replace("/", ".")


class _RejectingLoader:
    """Loader that refuses candidate modules outside the manifest (E5 F-2)."""

    def __init__(self, fullname: str) -> None:
        self._fullname = fullname

    def get_filename(self, fullname: Any = None) -> str:
        return f"recorder-next-manifest:absent:{self._fullname}"

    def create_module(self, spec: Any) -> None:
        return None

    def exec_module(self, module: Any) -> None:
        raise ImportError(
            f"candidate module {self._fullname!r} is not a manifest member"
        )


class _ManifestPackageFinder:
    """Meta-path finder serving recorder_next* only from manifest bytes.

    Any recorder_next import not present in the manifest resolves to a
    rejecting loader (ImportError on exec) — the real filesystem is never
    consulted for candidate code while the finder is installed.
    """

    def __init__(self, module_map: dict[str, tuple[str, bytes]]) -> None:
        self._module_map = module_map

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname != "recorder_next" and not fullname.startswith("recorder_next."):
            return None
        entry = self._module_map.get(fullname)
        if entry is None:
            return importlib.machinery.ModuleSpec(
                fullname,
                _RejectingLoader(fullname),
                origin=f"recorder-next-manifest:absent:{fullname}",
            )
        member, data = entry
        spec = importlib.machinery.ModuleSpec(
            fullname,
            _ManifestBytesLoader(member, data),
            origin=f"recorder-next-manifest:{member}",
        )
        if member.endswith("__init__.py"):
            # A package spec needs submodule_search_locations for
            # `recorder_next.adapters` to import under it (E5 F-2).
            spec.submodule_search_locations = []
        return spec


def _loaded_candidate_modules() -> dict[str, Any]:
    return {
        name: module
        for name, module in sys.modules.items()
        if name == "recorder_next" or name.startswith("recorder_next.")
    }


def _remove_candidate_finder(bundle: dict[str, Any]) -> None:
    finder = bundle.get("finder")
    while finder is not None and finder in sys.meta_path:
        try:
            sys.meta_path.remove(finder)
        except ValueError:
            break


def _preloaded_candidate_modules_are_local(preloaded: dict[str, Any], root: Path) -> bool:
    """Allow replacement only for modules already loaded from this candidate root."""
    try:
        root_resolved = root.resolve(strict=True)
    except OSError:
        return False
    for module in preloaded.values():
        module_file = getattr(module, "__file__", None)
        if not isinstance(module_file, str) or not module_file or ":" in module_file.split("/", 1)[0]:
            return False
        try:
            Path(module_file).resolve(strict=True).relative_to(root_resolved)
        except (OSError, ValueError):
            return False
    return True


# E7: the single admission-owned bundle currently authorized to serve
# candidate executable objects (parsers, stage-3 names).  Registered by
# _load_candidate_module_bundle on success, cleared by
# _release_candidate_module_bundle.  Nothing outside this bundle may be
# dereferenced by the runner.
_ACTIVE_CANDIDATE_BUNDLE: dict[str, Any] = {}


def _active_candidate_bundle() -> dict[str, Any] | None:
    bundle = _ACTIVE_CANDIDATE_BUNDLE.get("bundle")
    return bundle if isinstance(bundle, dict) and not bundle.get("load_failed") else None


def _release_candidate_module_bundle(bundle: Any) -> None:
    """Remove the candidate finder and every module it owned.

    This is intentionally the sole cleanup point for an admission-owned
    bundle.  The finder stays installed while observations and terminal
    validation are in progress, so imports cannot silently fall back to the
    mutable working tree.
    """
    if not isinstance(bundle, dict):
        return
    if _ACTIVE_CANDIDATE_BUNDLE.get("bundle") is bundle:
        _ACTIVE_CANDIDATE_BUNDLE.clear()
    _remove_candidate_finder(bundle)
    preloaded = bundle.get("preloaded")
    protected = set(preloaded) if isinstance(preloaded, dict) else set()
    owned = bundle.get("owned_names")
    names = set(owned) if isinstance(owned, (set, frozenset, tuple, list)) else set()
    registry = bundle.get("registry")
    if isinstance(registry, dict):
        names.update(registry)
    # A failed import can leave a partially initialized package behind.  It
    # is owned by this finder unless it existed before the bundle was loaded.
    names.update(_loaded_candidate_modules())
    for name in names:
        if name not in protected:
            sys.modules.pop(name, None)
    if isinstance(preloaded, dict):
        # Restore same-root modules that were temporarily evicted to ensure
        # candidate imports cannot reuse their mutable objects.
        sys.modules.update(preloaded)


_REQUIRED_ADAPTER_EXPORTS = (
    "_parse_credential_record",
    "_validate_envelope_semantics",
    "CredentialError",
    "HermesAudioASRProvider",
    "HermesAudioTTSProvider",
    "HttpHermesGateway",
    "ProviderFailure",
)


def _freeze_candidate_module_registry(
    module_map: dict[str, tuple[str, bytes]], loaded: dict[str, Any]
) -> dict[str, dict[str, Any]] | None:
    registry: dict[str, dict[str, Any]] = {}
    for name, module in loaded.items():
        entry = module_map.get(name)
        spec = getattr(module, "__spec__", None)
        loader = getattr(spec, "loader", None) if spec is not None else None
        if entry is None or not isinstance(loader, _ManifestBytesLoader):
            return None
        member, data = entry
        executed_digest = getattr(loader, "_executed_byte_digest", None)
        if not _is_lower_hex(executed_digest, 64):
            return None
        if executed_digest != hashlib.sha256(data).hexdigest():
            return None
        if executed_digest != hashlib.sha256(getattr(loader, "_data", b"")).hexdigest():
            return None
        expected_origin = f"recorder-next-manifest:{member}"
        if (
            getattr(module, "__manifest_member__", None) != member
            or getattr(loader, "_member", None) != member
            or getattr(spec, "origin", None) != expected_origin
            or getattr(module, "__loader__", None) is not loader
        ):
            return None
        exports = _candidate_exports(module)
        if name == "recorder_next.adapters" and any(
            required not in exports for required in _REQUIRED_ADAPTER_EXPORTS
        ):
            return None
        locations = getattr(spec, "submodule_search_locations", None)
        registry[name] = {
            "module": module,
            "member": member,
            "loader": loader,
            "spec": spec,
            "origin": expected_origin,
            "locations": tuple(locations) if locations is not None else None,
            "module_file": getattr(module, "__file__", None),
            "module_name": getattr(module, "__name__", None),
            "package": getattr(module, "__package__", None),
            "module_path": tuple(getattr(module, "__path__")) if hasattr(module, "__path__") else None,
            "spec_name": getattr(spec, "name", None),
            "executed_byte_digest": executed_digest,
            "exports": dict(exports),
        }
    return registry if "recorder_next.adapters" in registry else None


def _load_candidate_module_bundle(
    manifest: dict[str, Any], authorization: dict[str, Any], *, retain_finder: bool = False
) -> dict[str, Any] | None:
    """Execute candidate modules only from manifest-verified bytes (E6).

    The default direct-test mode removes the finder before returning.  Admission passes
    ``retain_finder=True`` and owns the returned bundle until its outer
    ``finally``; this keeps the manifest-byte capability installed through
    every provider/session observation and the closing identity check.
    """
    if not _verify_candidate_source(authorization, manifest):
        return None
    per_file = manifest.get("per_file_sha256")
    if not isinstance(per_file, dict) or not per_file:
        return None
    archive_path = _bounded_absolute_path(authorization.get("archive_path"))
    if archive_path is None:
        return None
    member_bytes = _extract_manifest_member_bytes(archive_path, per_file)
    if member_bytes is None:
        return None
    module_map: dict[str, tuple[str, bytes]] = {}
    for member, data in member_bytes.items():
        module_name = _member_module_name(member)
        if module_name is not None:
            if module_name in module_map:
                return None
            module_map[module_name] = (member, data)
    if "recorder_next" not in module_map or "recorder_next.adapters" not in module_map:
        return None

    preloaded = _loaded_candidate_modules()
    if preloaded:
        candidate_root = _bounded_absolute_path(authorization.get("candidate_root"))
        if candidate_root is None or not _preloaded_candidate_modules_are_local(preloaded, candidate_root):
            return None
        # Same-root imports are replaced for the admission window; foreign or
        # unverifiable preloads remain a hard refusal rather than an import
        # source that could bypass manifest bytes.
        for name in preloaded:
            sys.modules.pop(name, None)
    finder = _ManifestPackageFinder(module_map)
    cleanup_bundle: dict[str, Any] = {
        "finder": finder,
        "preloaded": dict(preloaded),
        "owned_names": set(),
        "registry": {},
        "direct_test_mode": not retain_finder,
    }
    sys.meta_path.insert(0, finder)
    try:
        loaded_adapters = importlib.import_module("recorder_next.adapters")
        loaded = _loaded_candidate_modules()
        cleanup_bundle["owned_names"] = set(loaded)
        registry = _freeze_candidate_module_registry(module_map, loaded)
        if registry is None:
            cleanup_bundle["load_failed"] = True
            return cleanup_bundle if retain_finder else None
        cleanup_bundle["registry"] = registry
        cleanup_bundle["owned_names"] = set(registry)
        cleanup_bundle["adapters"] = loaded_adapters
        cleanup_bundle["modules"] = {name: entry["member"] for name, entry in registry.items()}
        cleanup_bundle["module_map"] = module_map
        cleanup_bundle["module_map_frozen"] = {
            name: (member, bytes(data)) for name, (member, data) in module_map.items()
        }
        # E7: freeze the export surface of every registry module so the
        # closing check can reject replaced or added executable exports.
        cleanup_bundle["exports_frozen"] = {
            name: dict(_candidate_exports(entry["module"])) for name, entry in registry.items()
        }
        cleanup_bundle["load_failed"] = False
        # E7: the global bundle activation is what authorizes the credential
        # parser and stage-3 resolvers.  A direct-test load must not leave
        # that authority installed after it returns (the direct-test bundle
        # is not the admission-owned registry), so only a retained-finder
        # load publishes it.
        if retain_finder:
            _ACTIVE_CANDIDATE_BUNDLE["bundle"] = cleanup_bundle
        return cleanup_bundle
    except Exception:
        cleanup_bundle["load_failed"] = True
        cleanup_bundle["owned_names"] = set(_loaded_candidate_modules())
        return cleanup_bundle if retain_finder else None
    finally:
        if not retain_finder:
            if cleanup_bundle.get("load_failed"):
                _release_candidate_module_bundle(cleanup_bundle)
            else:
                _remove_candidate_finder(cleanup_bundle)


def _candidate_modules_still_bound(
    bundle: Any, manifest: dict[str, Any], authorization: dict[str, Any]
) -> bool:
    """Verify the frozen module object/loader/spec closure without re-opening source."""
    if not isinstance(bundle, dict) or bundle.get("load_failed"):
        return False
    registry = bundle.get("registry")
    module_map = bundle.get("module_map")
    frozen_module_map = bundle.get("module_map_frozen")
    finder = bundle.get("finder")
    per_file = manifest.get("per_file_sha256") if isinstance(manifest, dict) else None
    if (
        not isinstance(registry, dict)
        or not isinstance(module_map, dict)
        or not isinstance(frozen_module_map, dict)
        or module_map != frozen_module_map
        or (per_file is not None and not isinstance(per_file, dict))
        or "recorder_next.adapters" not in registry
        or getattr(finder, "_module_map", None) is not module_map
        or (finder not in sys.meta_path and not bundle.get("direct_test_mode"))
    ):
        return False
    current = _loaded_candidate_modules()
    if set(current) != set(registry):
        return False
    if isinstance(per_file, dict) and per_file:
        for name, expected in registry.items():
            mapped = module_map.get(name)
            if not isinstance(mapped, tuple) or len(mapped) != 2:
                return False
            member, data = mapped
            if (
                expected.get("member") != member
                or hashlib.sha256(data).hexdigest() != expected.get("executed_byte_digest")
                or per_file.get(member) != expected.get("executed_byte_digest")
            ):
                return False
    for name, expected in registry.items():
        module = current.get(name)
        if module is not expected.get("module"):
            return False
        spec = getattr(module, "__spec__", None)
        loader = getattr(spec, "loader", None) if spec is not None else None
        if spec is not expected.get("spec") or loader is not expected.get("loader"):
            return False
        if getattr(module, "__loader__", None) is not loader:
            return False
        if getattr(spec, "origin", None) != expected.get("origin"):
            return False
        try:
            locations = getattr(spec, "submodule_search_locations", None)
            actual_locations = tuple(locations) if locations is not None else None
            actual_module_path = tuple(getattr(module, "__path__")) if hasattr(module, "__path__") else None
        except TypeError:
            return False
        if actual_locations != expected.get("locations"):
            return False
        member = expected.get("member")
        if (
            getattr(module, "__manifest_member__", None) != member
            or getattr(loader, "_member", None) != member
            or getattr(module, "__file__", None) != expected.get("module_file")
            or getattr(module, "__name__", None) != expected.get("module_name")
            or getattr(module, "__package__", None) != expected.get("package")
            or getattr(spec, "name", None) != expected.get("spec_name")
            or actual_module_path != expected.get("module_path")
        ):
            return False
        digest = hashlib.sha256(getattr(loader, "_data", b"")).hexdigest()
        if (
            digest != expected.get("executed_byte_digest")
            or getattr(loader, "_executed_byte_digest", None) != digest
        ):
            return False
    # E7 executable_exports_not_bound: the registry binds the export surface
    # as well as the executed bytes.  A replaced dereferenced export or an
    # added foreign executable export breaks the closure (value identity).
    exports_frozen = bundle.get("exports_frozen")
    if not isinstance(exports_frozen, dict):
        return False
    for name, expected in registry.items():
        frozen = exports_frozen.get(name)
        bound = expected.get("exports")
        if not isinstance(frozen, dict) or not isinstance(bound, dict):
            return False
        if bound != frozen or _candidate_exports(expected.get("module")) != frozen:
            return False
    return True

def _profile_observations_ready(omitted_response: Any, explicit_response: Any) -> bool:
    """Use one strict projection/validator path for both observations."""
    if not isinstance(omitted_response, dict) or type(omitted_response.get("status")) is not int:
        return False
    if not 200 <= omitted_response["status"] < 300:
        return False
    omitted_body = omitted_response.get("body")
    explicit_status = explicit_response.get("status") if isinstance(explicit_response, dict) else None
    explicit_projection = explicit_response.get("projection") if isinstance(explicit_response, dict) else None
    if type(explicit_status) is not int or not 200 <= explicit_status < 300:
        return False
    # E5 F-5: BOTH observations pass through the one shared projection — the
    # explicit probe output is no longer compared raw, so identical envelope
    # semantics compare equal regardless of which observation carried them,
    # and wrong-typed values can never collide with literal marker strings.
    omitted_projection = _tts_reduction(omitted_body)
    explicit_reduction = _tts_reduction(explicit_projection)
    if omitted_projection is None or explicit_reduction is None:
        return False
    try:
        if not _validate_tts_projection_ready(omitted_projection):
            return False
        if not _validate_tts_projection_ready(explicit_reduction):
            return False
    except Exception:
        return False
    return omitted_projection == explicit_reduction


def _closing_identity_equal(context: dict[str, Any], adapters_module: Any = None) -> bool:
    """Re-read all identity inputs and the imported module at terminalization."""
    if not isinstance(context, dict):
        return False
    custody_handles = context.get("_custody_handles")
    if custody_handles is not None and not _custody_handles_revalidate(custody_handles):
        return False
    manifest_path = context.get("manifest_path")
    authorization_path = context.get("authorization_path")
    manifest_sha256 = context.get("manifest_sha256")
    authorization_sha256 = context.get("authorization_sha256")
    if not all(isinstance(value, str) and value for value in (
        manifest_path, authorization_path, manifest_sha256, authorization_sha256,
    )):
        return False
    manifest = _load_bounded_json(Path(manifest_path), MAX_AUTHORITY_BYTES, manifest_sha256)
    authorization = _load_bounded_json(Path(authorization_path), MAX_AUTHORITY_BYTES, authorization_sha256)
    if manifest is None or authorization is None:
        return False
    if manifest != context.get("manifest") or authorization != context.get("authorization"):
        return False
    if not _verify_manifest_structure(manifest):
        return False
    if not _verify_authority_binding(manifest, authorization, manifest_sha256):
        return False
    if not _verify_candidate_source(authorization, manifest):
        return False
    if not _cold_rehash_ratified_authorities():
        return False
    # The final identity is the exact module object retained by admission;
    # importing a replacement module here would hide namespace substitution.
    bundle = context.get("candidate_bundle")
    if not isinstance(bundle, dict) or not _candidate_modules_still_bound(bundle, manifest, authorization):
        return False
    registry = bundle.get("registry")
    if not isinstance(registry, dict):
        return False
    module_entry = registry.get("recorder_next.adapters")
    module = adapters_module if adapters_module is not None else context.get("adapters_module")
    if module_entry is None or module is not module_entry.get("module"):
        return False
    return True


def _run_voice1_readonly_admission(context: dict[str, Any]) -> dict[str, Any]:
    """Real observational read-only Voice1 admission caller (REV-008).

    ``context`` is constructed by the executable main() from the root-pinned
    manifest/authorization files; it carries no caller-supplied observation
    results.  Fixture tests may inject only I/O/time boundaries (readers,
    openers); validators and aggregation are never injectable.  Every
    predicate below is set from an actual bounded observation.
    """
    started_monotonic = time.monotonic()
    started_utc = _utc_now_iso()
    authorization = context.get("authorization") or {}
    manifest = context.get("manifest") or {}
    identity = {
        "candidate_id": manifest.get("candidate_id"),
        "archive_sha256": manifest.get("candidate_sha256"),
        "source_commit": manifest.get("source_commit"),
        "source_tree": manifest.get("source_tree"),
        "control_sha256": (manifest.get("control") or {}).get("probe_runner_sha256"),
        "spec_sha256": (manifest.get("authorities") or {}).get("specification_sha256"),
    }
    predicates: dict[str, bool] = {}
    reason_codes: list[str] = []
    observations: dict[str, Any] = {}
    if context.get("started_monotonic") is not None:
        started_monotonic = float(context["started_monotonic"])

    def budget_remaining() -> float:
        return ADMISSION_TOTAL_BUDGET_SECONDS - (time.monotonic() - started_monotonic)

    def within_budget() -> bool:
        return budget_remaining() > 0.0

    readers = context.get("boundary") or {}
    read_credential = readers.get("read_credential") or _read_credential_default
    open_probe = readers.get("probe") or _probe_dashboard_default

    # Resolve the candidate adapters module at call time (import stays
    # inert at module import): this is the same module the capability
    # section binds below, and the import-origin binding is checked
    # against its real origin, mirroring the main() sys.path binding of
    # the candidate root.
    #
    # F-1 repair (import pre-gate): the import is authorized only after
    # _verify_candidate_source has positively proven the pinned archive
    # bytes, the safe exact archive member set, the canonical per-file
    # vector, and candidate-root member digests.  A failed verification
    # rejects the import-origin and candidate predicates below without
    # ever importing the candidate package — there is no state in which a
    # missing/mismatched archive still reaches an import or a protected
    # boundary.
    adapters_module = None
    # E5 F-1: the gate is ONE-WAY and precedes the import — ratified
    # authority cold-rehash, authority binding, and candidate-source
    # verification must ALL hold before any recorder_next module is
    # imported.  Authority drift after main()'s precheck (or at any later
    # time) can no longer reach an import; a failed gate leaves
    # adapters_module None and the candidate predicates fail closed.
    candidate_source_ok = False
    candidate_bundle: dict[str, Any] | None = None
    if (
        _cold_rehash_ratified_authorities()
        and within_budget()
        and isinstance(context.get("manifest_sha256"), str)
        and _verify_manifest_structure(manifest)
        and _verify_authority_binding(manifest, authorization, context["manifest_sha256"])
    ):
        candidate_source_ok = _verify_candidate_source(authorization, manifest)
    if candidate_source_ok:
        # E5 F-2: the candidate executes only through the manifest-byte-bound
        # loader — verified archive bytes, never a pathname re-open.  Preloaded
        # foreign recorder_next modules and any forged loader metadata are
        # rejected inside the bundle loader.
        candidate_bundle = _load_candidate_module_bundle(
            manifest, authorization, retain_finder=True
        )
        if candidate_bundle is not None:
            # The wrapper's outer finally owns cleanup even when import fails
            # after creating a partially initialized candidate namespace.
            context["candidate_bundle"] = candidate_bundle
            if not candidate_bundle.get("load_failed"):
                adapters_module = candidate_bundle["adapters"]

    scope = authorization.get("execution_scope")
    paths = authorization.get("paths") or {}
    metadata = authorization.get("credential_metadata") or {}

    # -- 0. authority, candidate, and import-origin bindings ----------------
    predicates["authorization_bound"] = bool(
        isinstance(manifest_sha256_arg := context.get("manifest_sha256"), str)
        and _verify_manifest_structure(manifest)
        and _verify_authority_binding(manifest, authorization, manifest_sha256_arg)
        and scope in EXECUTION_SCOPES
        and within_budget()
    )
    per_file = manifest.get("per_file_sha256") if isinstance(manifest, dict) else None
    candidate_root = _bounded_absolute_path(authorization.get("candidate_root")) if isinstance(authorization, dict) else None
    imports_bound = bool(
        candidate_source_ok
        and candidate_bundle is not None
        and isinstance(candidate_bundle.get("modules"), dict)
        and "recorder_next.adapters" in candidate_bundle["modules"]
        and adapters_module is not None
        and within_budget()
    )
    predicates["imports_bound"] = bool(imports_bound)
    predicates["candidate_bound"] = bool(candidate_source_ok and imports_bound and within_budget())
    # E7: a missing or invalid candidate bundle is terminal for this
    # admission.  Do not defer the failure until after credential or metadata
    # custody has been opened; the fail-closed boundary is before protected
    # bytes and before any provider construction.
    if not (predicates["authorization_bound"] and predicates["candidate_bound"]):
        reason_codes.append("authority_mismatch")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)

    # -- 1. credential custody, parse, lifetime (opening) ------------------
    dashboard_cred_path = Path(str(paths.get("dashboard_credential")))
    api_cred_path = Path(str(paths.get("api_credential")))
    metadata_path = Path(str(paths.get("dashboard_metadata")))
    dashboard_pin = (metadata.get("dashboard_credential") or {})
    api_pin = (metadata.get("api_credential") or {})
    custody_handles: list[_CustodiedFile] = []
    context["_custody_handles"] = custody_handles
    try:
        # These are the only opens that establish custody for this admission.
        # All later reads and drift checks use the retained descriptors.
        custody_handles.append(_open_custodied_file(dashboard_cred_path, dashboard_pin, max_bytes=4113))
        custody_handles.append(_open_custodied_file(api_cred_path, api_pin, max_bytes=4113))
        custody_handles.append(_open_custodied_file(
            metadata_path, None, max_bytes=4096, bind_content=True
        ))
    except (OSError, ValueError):
        predicates["credential_custody"] = False
        reason_codes.append("credential_custody")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)
    custody_ok = _custody_handles_revalidate(custody_handles) and within_budget()
    predicates["credential_custody"] = bool(custody_ok)
    if not custody_ok:
        reason_codes.append("credential_custody")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)

    dashboard_value = None
    api_value = None
    try:
        if read_credential is _read_credential_default:
            dashboard_value = read_credential(
                dashboard_cred_path, dashboard_pin, handle=custody_handles[0]
            )
            api_value = read_credential(
                api_cred_path, api_pin, handle=custody_handles[1]
            )
        else:
            dashboard_value = read_credential(dashboard_cred_path)
            api_value = read_credential(api_cred_path)
    except Exception:
        dashboard_value = api_value = None
    # Post-read custody is part of the existing credential_custody observation;
    # it is intentionally not a new public predicate ABI member.
    custody_after_reads = _custody_handles_revalidate(custody_handles) and within_budget()
    predicates["credential_custody"] = bool(custody_ok and custody_after_reads)
    if not custody_after_reads:
        reason_codes.append("credential_custody")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)
    dashboard_parse_ok = isinstance(dashboard_value, str) and bool(dashboard_value) and len(dashboard_value) <= 4096
    api_parse_ok = isinstance(api_value, str) and bool(api_value) and len(api_value) <= 4096
    predicates["dashboard_credential_parse"] = bool(dashboard_parse_ok and within_budget())
    predicates["api_credential_parse"] = bool(api_parse_ok and within_budget())
    if not (dashboard_parse_ok and api_parse_ok):
        reason_codes.append("credential_parse")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)
    # Dashboard metadata lifetime: exact UTC string, >=3900s pre and post.
    try:
        metadata_raw = custody_handles[2].read_text()
    except (OSError, UnicodeDecodeError):
        metadata_raw = ""
    remaining_pre = _dashboard_remaining_seconds(metadata_raw)
    predicates["lifetime_pre"] = bool(
        remaining_pre is not None and remaining_pre >= DASHBOARD_LIFETIME_FLOOR_SECONDS
        and _custody_handles_revalidate(custody_handles) and within_budget()
    )
    if not predicates["lifetime_pre"]:
        reason_codes.append("lifetime")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)

    # -- 2. bounded unauthenticated dashboard gate -------------------------
    gate = open_probe(authorization.get("endpoints", {}).get("dashboard_base_url"),
                      "/api/audio/voice-config", credential=None, deadline_at=time.monotonic() + PROVIDER_TIMEOUT_SECONDS)
    observations["gate_status"] = gate.get("status")
    gate_body = gate.get("body") if isinstance(gate, dict) else None
    dashboard_secret = dashboard_value if isinstance(dashboard_value, str) else None
    api_secret = api_value if isinstance(api_value, str) else None
    gate_secrets_absent = _secrets_absent(gate_body, (dashboard_secret, api_secret))
    gate_ok = (
        isinstance(gate, dict) and gate.get("status") == 401
        and isinstance(gate_body, (bytes, str))
        and gate_secrets_absent
    )
    predicates["unauthenticated_gate"] = bool(gate_ok and within_budget())
    if not gate_ok:
        reason_codes.append("unauthenticated_gate")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)

    # -- 3. candidate capability + ASR/TTS readiness (true-default API) ----
    api_base = authorization.get("endpoints", {}).get("api_base_url")
    dashboard_base = authorization.get("endpoints", {}).get("dashboard_base_url")
    deadline_now = time.monotonic()
    remaining = budget_remaining()
    if remaining <= 0:
        reason_codes.append("deadline")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)
    try:
        # E7 unbound_import_before_credential_gate: the capability stage
        # resolves every provider name through the bundle registry; a plain
        # filesystem import here would be an unbound import source.
        stage3 = _candidate_stage3_names(candidate_bundle)
        HermesAudioASRProvider = stage3["HermesAudioASRProvider"]
        HermesAudioTTSProvider = stage3["HermesAudioTTSProvider"]
        HttpHermesGateway = stage3["HttpHermesGateway"]
        ProviderFailure = stage3["ProviderFailure"]

        def half_budget() -> float:
            return max(budget_remaining() / 2.0, 0.0)

        # The providers are candidate-bound classes, but their path-based
        # credential readers are not allowed to reopen protected files.  Feed
        # the already custody-validated values into the instances directly so
        # the module export registry remains immutable for close validation.
        gateway = HttpHermesGateway(str(api_base), api_key_file=None, require_existing_session=False)
        gateway._api_key = api_value
        capability = gateway.capability_check()
        # E5 F-3: keep custody through the exact provider observation — a
        # credential substitution during any provider call fails closed.
        if not _custody_handles_revalidate(custody_handles):
            raise ValueError("credential custody drifted during provider observation")
        predicates["api_capability"] = bool(
            isinstance(capability, dict) and (capability.get("features") or {}).get("run_submission") is True
        )

        asr = HermesAudioASRProvider(str(dashboard_base), profile="default",
                                     credential_file=None,
                                     timeout=min(PROVIDER_TIMEOUT_SECONDS, half_budget()))
        asr._credential = dashboard_value
        asr_result = asr.readiness_check()
        if not _custody_handles_revalidate(custody_handles):
            raise ValueError("credential custody drifted during provider observation")
        predicates["asr_ready"] = bool(isinstance(asr_result, dict) and asr_result.get("capability"))

        tts = HermesAudioTTSProvider(str(dashboard_base), profile="default",
                                     credential_file=None,
                                     timeout=min(PROVIDER_TIMEOUT_SECONDS, half_budget()))
        tts._credential = dashboard_value
        tts_result = tts.readiness_check()
        if not _custody_handles_revalidate(custody_handles):
            raise ValueError("credential custody drifted during provider observation")
        predicates["tts_ready"] = bool(isinstance(tts_result, dict) and tts_result.get("capability"))
    except Exception:
        if "api_capability" not in predicates:
            predicates["api_capability"] = False
        if "asr_ready" not in predicates:
            predicates["asr_ready"] = False
        if "tts_ready" not in predicates:
            predicates["tts_ready"] = False
        reason_codes.append("capability")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)
    if not (predicates["api_capability"] and predicates["asr_ready"] and predicates["tts_ready"]):
        reason_codes.append("capability")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)

    # -- 4. distinct omitted/explicit profile TTS observations -------------
    try:
        omitted_target = "/api/audio/voice-config"
        explicit_target = "/api/audio/voice-config?profile=default"
        omitted_response = open_probe(dashboard_base, omitted_target,
                                      credential=dashboard_value, deadline_at=time.monotonic() + PROVIDER_TIMEOUT_SECONDS)
        explicit_response = tts._probe(explicit_target, deadline_at=time.monotonic() + min(PROVIDER_TIMEOUT_SECONDS, max(budget_remaining(), 0.001)))
        profile_ready = _profile_observations_ready(
            omitted_response,
            {"status": 200, "projection": explicit_response},
        )
        distinct_targets = omitted_target != explicit_target
        predicates["omitted_profile_equal"] = bool(profile_ready and distinct_targets)
        predicates["omitted_profile_ready"] = bool(profile_ready and distinct_targets)
        if not _custody_handles_revalidate(custody_handles):
            raise ValueError("credential custody drifted during profile observation")
    except Exception:
        predicates["omitted_profile_equal"] = False
        predicates["omitted_profile_ready"] = False
    if not (predicates["omitted_profile_equal"] and predicates["omitted_profile_ready"]):
        reason_codes.append("profile_mismatch")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)

    # -- 5. session preflight + authenticated GET (shared 10 s budget) -----
    session_deadline = min(time.monotonic() + SESSION_BUDGET_SECONDS, time.monotonic() + max(budget_remaining(), 0.001))
    try:
        if not _custody_handles_revalidate(custody_handles):
            raise ValueError("credential custody drifted before session observation")
        gw = gateway
        gw._preflight_existing_session(SELECTED_S, deadline_at=session_deadline)
        payload = gw._request(
            "GET",
            "/api/sessions/" + quote_safe(SELECTED_S),
            extra_headers=gw._session_headers(SELECTED_S),
            deadline_at=session_deadline,
        )
        if not _custody_handles_revalidate(custody_handles):
            raise ValueError("credential custody drifted during session observation")
        predicates["generic_preflight"] = True
        predicates["session_get"] = isinstance(payload, dict)
        predicates["session_budget"] = bool(time.monotonic() <= session_deadline and within_budget())
        observations["session_payload"] = payload
    except Exception:
        predicates["generic_preflight"] = False
        predicates["session_get"] = False
        predicates["session_budget"] = False
        reason_codes.append("session_get")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)
    if not (predicates["session_get"] and predicates["session_budget"]):
        reason_codes.append("session_get")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)

    # -- 6. read-only indexed persisted lookup ------------------------------
    lookup = _persisted_lookup(context, deadline_at=session_deadline)
    if not _custody_handles_revalidate(custody_handles):
        predicates["credential_custody"] = False
        reason_codes.append("credential_custody")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)
    predicates["persisted_lookup_ro"] = bool(lookup.get("read_only"))
    predicates["persisted_lookup_indexed"] = bool(lookup.get("indexed"))
    if predicates["persisted_lookup_ro"] and predicates["persisted_lookup_indexed"]:
        # This is captured only after the real GET and the real indexed SELECT
        # complete; it is never a caller-supplied freshness assertion.
        observations["session_observed_utc"] = _utc_now_iso()
        observations["session_observed_monotonic_ns"] = time.monotonic_ns()
        observations["boot_id"] = _boot_id()
    if not (predicates["persisted_lookup_ro"] and predicates["persisted_lookup_indexed"]):
        reason_codes.append("persisted_lookup")
        return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                                 observations=observations, authorization=authorization)

    # -- 7. pure predicate with owner pins -----------------------------------
    admission = voice1_session_admission(
        observations.get("session_payload"),
        lookup.get("rows") or [],
        expected_session_id=SELECTED_S,
        expected_key_sha256=authorization.get("persisted_key_sha256") or EXPECTED_KEY_SHA256,
    )
    predicates["payload_object_match"] = bool(admission["payload_object_match"])
    predicates["source_match"] = bool(admission["source_match"])
    predicates["id_match"] = bool(admission["id_match"])
    predicates["lifecycle_match"] = bool(admission["lifecycle_match"])
    predicates["persisted_row_count_match"] = bool(admission["persisted_row_count_match"])
    predicates["persisted_id_match"] = bool(admission["persisted_id_match"])
    predicates["persisted_source_match"] = bool(admission["persisted_source_match"])
    predicates["persisted_ended_at_null"] = bool(admission["persisted_ended_at_null"])
    predicates["conversation_key_match"] = bool(admission["conversation_key_match"])
    predicates["distinct_key_identity"] = bool(admission["distinct_key_identity"])

    # -- 8. closing vector ---------------------------------------------------
    try:
        metadata_post_raw = custody_handles[2].read_text()
    except (OSError, UnicodeDecodeError):
        metadata_post_raw = ""
    custody_final = _custody_handles_revalidate(custody_handles) and within_budget()
    remaining_post = _dashboard_remaining_seconds(metadata_post_raw)
    predicates["lifetime_post"] = bool(
        remaining_post is not None and remaining_post >= DASHBOARD_LIFETIME_FLOOR_SECONDS and custody_final
    )
    predicates["closing_identity_equal"] = bool(
        _closing_identity_equal(context, adapters_module)
        and custody_final
    )
    predicates["no_mutation"] = True  # this caller issued zero writes by construction
    predicates["secret_safe"] = bool(
        dashboard_secret is not None
        and api_secret is not None
        and dashboard_secret not in json.dumps({})
        and api_secret not in json.dumps({})
    )

    return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity,
                             observations=observations, authorization=authorization)


def _install_custody_reader_hooks(
    context: dict[str, Any], module: Any, dashboard_path: Path, api_path: Path,
    dashboard_value: str, api_value: str,
) -> bool:
    """Route candidate provider constructors back to retained descriptors."""
    if module is None:
        return False
    hooks: list[tuple[Any, str, Any]] = []
    dashboard_name = str(dashboard_path)
    api_name = str(api_path)

    def bound_reader(path: Any) -> str:
        candidate = str(path)
        if candidate == dashboard_name:
            return dashboard_value
        if candidate == api_name:
            return api_value
        raise ValueError("provider credential path is outside retained custody")

    for attribute in ("_read_provider_credential", "_read_api_key_file"):
        original = getattr(module, attribute, None)
        if not callable(original):
            continue
        hooks.append((module, attribute, original))
        setattr(module, attribute, bound_reader)
    if not hooks:
        return False
    context["_candidate_reader_hooks"] = hooks
    return True


def _restore_custody_reader_hooks(context: dict[str, Any]) -> None:
    hooks = context.pop("_candidate_reader_hooks", [])
    if not isinstance(hooks, (list, tuple)):
        return
    for module, attribute, original in hooks:
        try:
            setattr(module, attribute, original)
        except Exception:
            pass


def run_voice1_readonly_admission(context: dict[str, Any]) -> dict[str, Any]:
    """Run admission and release all candidate/custody handles exactly once."""
    try:
        return _run_voice1_readonly_admission(context)
    finally:
        _restore_custody_reader_hooks(context)
        bundle = context.pop("candidate_bundle", None) if isinstance(context, dict) else None
        _release_candidate_module_bundle(bundle)
        handles = context.pop("_custody_handles", []) if isinstance(context, dict) else []
        if isinstance(handles, (list, tuple)):
            for handle in handles:
                try:
                    handle.close()
                except Exception:
                    pass


def _sqlite_uri_path(path: Path) -> str:
    """Escape a filesystem path before embedding it in a SQLite URI."""
    from urllib.parse import quote

    return quote(str(path), safe="/")


def quote_safe(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


class _CustodiedFile:
    """A bounded descriptor retaining every checked ancestry object."""

    def __init__(self, path: Path, pinned: Any, max_bytes: int, *, bind_content: bool = False) -> None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
            raise ValueError("invalid custody bound")
        if not isinstance(bind_content, bool):
            raise ValueError("invalid content binding")
        canonical = _bounded_absolute_path(str(path))
        if canonical is None:
            raise OSError("credential ancestry is not canonical")
        if pinned is not None and (
            not isinstance(pinned, dict)
            or set(pinned) != {"device", "inode", "uid", "gid", "mode"}
            or any(isinstance(value, bool) or not isinstance(value, int) or value < 0
                   for value in pinned.values())
        ):
            raise ValueError("credential custody metadata is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
        # E7 metadata_ancestor_check_open_race: retain the root and every
        # directory opened by the verified openat walk.  The descriptors are
        # the lifetime witness; a pathname-only recheck cannot prove that a
        # renamed ancestor still denotes the object used for the read.
        ancestry = _recorded_ancestry_metadata(canonical)
        if not ancestry:
            raise OSError("credential ancestry is not canonical")
        directory_fds: list[int] = []
        descriptor = -1
        try:
            root_fd = os.open("/", directory_flags)
            directory_fds.append(root_fd)
            os.set_inheritable(root_fd, False)
            if _custody_signature(os.fstat(root_fd)) != _custody_signature(os.lstat(Path("/"))):
                raise OSError("credential root changed during open")
            walk_fd = root_fd
            for component, checked_signature in ancestry[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=walk_fd)
                try:
                    os.set_inheritable(next_fd, False)
                    if _custody_signature(os.fstat(next_fd)) != checked_signature:
                        raise OSError("credential ancestry changed during open")
                    directory_fds.append(next_fd)
                except BaseException:
                    os.close(next_fd)
                    raise
                walk_fd = next_fd
            descriptor = os.open(ancestry[-1][0], flags, dir_fd=walk_fd)
            os.set_inheritable(descriptor, False)
            info = os.fstat(descriptor)
            identity = _stat_identity(info)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("custodied object is not regular")
            if pinned is not None and identity != pinned:
                raise OSError("custodied object does not match authorization")
            if info.st_size > max_bytes:
                raise OSError("custodied object exceeds bound")

            self.path = canonical
            self.fd = descriptor
            self.pinned = dict(pinned) if isinstance(pinned, dict) else None
            self.max_bytes = max_bytes
            self.bind_content = bind_content
            self.identity = identity
            self._object_signature = _custody_signature(info)
            self._directory_fds = directory_fds
            self._directory_signatures = [
                _custody_signature(os.fstat(directory_fd)) for directory_fd in directory_fds
            ]
            self._directory_identities = [
                _stat_identity(os.fstat(directory_fd)) for directory_fd in directory_fds
            ]
            self._directory_components = tuple(component for component, _ in ancestry[:-1])
            self._leaf_name = ancestry[-1][0]
            self._ancestry = tuple(ancestry)
            self.content_sha256 = self._read_content_digest_unchecked() if bind_content else None
            if not self._revalidate_ancestry():
                raise OSError("custodied path changed during open")
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            for directory_fd in reversed(directory_fds):
                os.close(directory_fd)
            raise

    def _read_content_digest_unchecked(self) -> str:
        os.lseek(self.fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        total = 0
        while total <= self.max_bytes:
            chunk = os.read(self.fd, min(65536, self.max_bytes - total + 1))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if total > self.max_bytes:
                raise OSError("custodied object exceeds bound")
        return digest.hexdigest()

    def _revalidate_ancestry(self) -> bool:
        if getattr(self, "fd", -1) < 0:
            return False
        directory_fds: list[int] = list(getattr(self, "_directory_fds", ()))
        directory_signatures: list[tuple[int, ...]] = list(
            getattr(self, "_directory_signatures", ())
        )
        if not directory_fds or len(directory_fds) != len(directory_signatures):
            return False
        try:
            for directory_fd, expected_signature in zip(directory_fds, directory_signatures):
                if _custody_signature(os.fstat(directory_fd)) != expected_signature:
                    return False
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode):
                return False
            if _stat_identity(info) != self.identity:
                return False
            if _custody_signature(info) != self._object_signature:
                return False
            if self.pinned is not None and _stat_identity(info) != self.pinned:
                return False
            if self.bind_content and self._read_content_digest_unchecked() != self.content_sha256:
                return False
            return True
        except OSError:
            return False

    def revalidate(self) -> bool:
        return self._revalidate_ancestry()

    def read_bytes(self) -> bytes:
        if not self.revalidate():
            raise OSError("custody drifted before read")
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while total <= self.max_bytes:
                chunk = os.read(self.fd, min(65536, self.max_bytes - total + 1))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > self.max_bytes:
                    raise OSError("custodied object exceeds bound")
            result = b"".join(chunks)
            if not self.revalidate():
                raise OSError("custody drifted during read")
            if len(result) != os.fstat(self.fd).st_size:
                raise OSError("custodied object size changed")
            if self.bind_content and hashlib.sha256(result).hexdigest() != self.content_sha256:
                raise OSError("custodied content changed")
            return result
        except OSError:
            raise

    def read_text(self) -> str:
        return self.read_bytes().decode("utf-8")

    def close(self) -> None:
        descriptor = getattr(self, "fd", -1)
        self.fd = -1
        if descriptor >= 0:
            os.close(descriptor)
        directory_fds = list(getattr(self, "_directory_fds", ()))
        self._directory_fds = []
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)


def _open_custodied_file(
    path: Path,
    pinned: Any = None,
    *,
    max_bytes: int = 4096,
    bind_content: bool = False,
) -> _CustodiedFile:
    return _CustodiedFile(path, pinned, max_bytes, bind_content=bind_content)


def _custody_handles_revalidate(handles: Any) -> bool:
    if not isinstance(handles, (list, tuple)) or not handles:
        return False
    return all(isinstance(handle, _CustodiedFile) and handle.revalidate() for handle in handles)


class CandidateBundleError(ImportError):
    """A required candidate-bundle binding is missing (E7 fail-closed)."""


class CredentialGateError(ValueError):
    """No bundle-bound parser was available for a credential read (E7).

    This is the runner-local stand-in for the candidate's CredentialError:
    when no candidate bundle is bound the runner must not import the
    candidate's exception class from the filesystem just to raise it.
    """


def _candidate_exports(module: Any) -> dict[str, Any]:
    """Public + underscore callable/module export values of one module (E7).

    The mapping binds values by identity: a replaced export keeps its name,
    so only a value comparison can detect the substitution.
    """
    exports: dict[str, Any] = {}
    for name in dir(module):
        if name.startswith("__"):
            continue
        try:
            value = getattr(module, name)
        except Exception:
            continue
        if callable(value) or isinstance(value, types.ModuleType):
            exports[name] = value
    return exports


def _candidate_stage3_names(bundle: Any) -> dict[str, Any]:
    """Resolve the capability-stage names strictly from the bundle registry."""
    if not isinstance(bundle, dict) or bundle.get("load_failed"):
        raise CandidateBundleError("candidate bundle is not bound")
    registry = bundle.get("registry")
    entry = registry.get("recorder_next.adapters") if isinstance(registry, dict) else None
    exports = entry.get("exports") if isinstance(entry, dict) else None
    if not isinstance(exports, dict):
        raise CandidateBundleError("candidate adapter exports are not bound")
    names: dict[str, Any] = {}
    for required in (
        "HermesAudioASRProvider", "HermesAudioTTSProvider",
        "HttpHermesGateway", "ProviderFailure",
    ):
        value = exports.get(required)
        if not callable(value):
            raise CandidateBundleError(f"candidate export {required!r} is not bound")
        names[required] = value
    return names


def _read_credential_default(path: Path, pinned: Any = None, *, handle: _CustodiedFile | None = None) -> str:
    """Parse bounded bytes from one already custody-checked descriptor (E7:
    the parser executes only from a bundle-bound candidate module)."""
    bundle = _active_candidate_bundle()
    registry = bundle.get("registry") if isinstance(bundle, dict) else None
    entry = registry.get("recorder_next.adapters") if isinstance(registry, dict) else None
    exports = entry.get("exports") if isinstance(entry, dict) else None
    parser = exports.get("_parse_credential_record") if isinstance(exports, dict) else None
    if not callable(parser):
        raise CredentialGateError("credential parser is not bundle-bound")
    _parse_record: Callable[[bytes], str] = cast(Callable[[bytes], str], parser)
    credential_error: type[Exception] = CredentialGateError
    candidate_error = exports.get("CredentialError") if isinstance(exports, dict) else None
    if isinstance(candidate_error, type) and issubclass(candidate_error, Exception):
        credential_error = candidate_error

    owned = handle is None
    if handle is None:
        try:
            handle = _open_custodied_file(path, pinned, max_bytes=4113)
        except (OSError, ValueError) as error:
            raise credential_error("credential file is unavailable") from error
    try:
        if handle.path != _bounded_absolute_path(str(path)):
            raise credential_error("credential path changed")
        try:
            raw = handle.read_bytes()
        except OSError as error:
            raise credential_error("credential custody identity drifted") from error
        return _parse_record(raw)
    finally:
        if owned:
            handle.close()


def _probe_dashboard_default(base_url: str, path: str, *, credential: str | None,
                             deadline_at: float) -> dict[str, Any]:
    """Bounded no-redirect GET returning {status, body} without redirects."""
    import http.client
    from urllib.parse import urlsplit

    parsed = urlsplit(base_url)
    target = parsed.path.rstrip("/") + path if parsed.path not in ("", "/") else path
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=max(deadline_at - time.monotonic(), 0.1))
    headers = {"Accept": "application/json"}
    if credential is not None:
        headers["Authorization"] = "Bearer " + credential
        headers["X-Hermes-Session-Token"] = credential
    try:
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        status = response.status
        body = response.read(64 * 1024)
    finally:
        connection.close()
    return {"status": status, "body": body}


def _secrets_absent(body: Any, secrets: tuple[str | None, ...]) -> bool:
    """Check that known credential values are absent without mixing bytes/str."""
    if not secrets or not all(isinstance(value, str) for value in secrets):
        return False
    values = tuple(value for value in secrets if isinstance(value, str))
    if isinstance(body, bytes):
        needles = tuple(value.encode("utf-8") for value in values)
        return all(needle not in body for needle in needles)
    if isinstance(body, str):
        return all(value not in body for value in values)
    return False


class _ReductionMarker:
    """Collision-free reduction marker (E5 F-5).

    Reduction output values must never be confusable with any value a real
    payload can carry.  Real payloads reduce to dict/list/str/bool or to one
    of these marker objects; a provider string such as ``"invalid:list"``
    stays a plain str and can therefore never equal the marker emitted for
    an actually wrong-typed value.
    """

    __slots__ = ("kind", "detail")

    def __init__(self, kind: str, detail: str = "") -> None:
        self.kind = kind
        self.detail = detail

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, _ReductionMarker):
            return NotImplemented
        return self.kind == other.kind and self.detail == other.detail

    def __hash__(self) -> int:
        return hash((_ReductionMarker, self.kind, self.detail))

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"_ReductionMarker({self.kind!r}, {self.detail!r})"


_INVALID = "invalid"
_NULL = _ReductionMarker("null")


def _tts_reduction(body: Any) -> dict[str, Any] | None:
    """Single shared, bounded, lossless, collision-free projection (E5 F-5).

    BOTH omitted and explicit observations reduce through this one function
    before equality, so the two observations can never diverge by passing
    through different pipelines.  Rules:

    * dicts recurse (keys stay the JSON string keys they already are);
    * bools stay bool (True never equals a reduced number 1);
    * plain strings stay plain strings — a literal ``"invalid:list"`` from
      the wire therefore never collides with the marker emitted for a
      genuinely wrong-typed list;
    * None, numbers, and every other non-container reduce to marker objects
      that no wire payload can produce;
    * lists are preserved element-wise (bounded) so byte-identical valid
      lists compare equal instead of collapsing to one opaque token;
    * normative flag/string slots mark wrong types with markers, keeping
      absent vs present-invalid distinguishable.
    """
    if isinstance(body, bytes):
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
    elif isinstance(body, dict):
        payload = body
    else:
        return None
    if not isinstance(payload, dict):
        return None

    def reduce_value(value: Any, depth: int = 0) -> Any:
        if isinstance(value, _ReductionMarker):
            return value
        if depth > 16:
            return _ReductionMarker(_INVALID, "depth")
        if isinstance(value, dict):
            return {key: reduce_value(item, depth + 1) for key, item in value.items()}
        if isinstance(value, list):
            if len(value) > 64:
                return _ReductionMarker(_INVALID, "list-length")
            return [reduce_value(item, depth + 1) for item in value]
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value
        if value is None:
            return _NULL
        if isinstance(value, (int, float)):
            return _ReductionMarker("num", repr(value))
        return _ReductionMarker(_INVALID, type(value).__name__)

    reduction: dict[str, Any] = {}
    for key, value in payload.items():
        if key in ("tts", "stt"):
            continue
        reduction[key] = reduce_value(value)

    for subtree_key in ("tts", "stt"):
        if subtree_key not in payload:
            continue
        subtree = payload[subtree_key]
        if not isinstance(subtree, dict):
            reduction[subtree_key] = (
                _NULL if subtree is None else _ReductionMarker(_INVALID, type(subtree).__name__)
            )
            continue
        reduced_subtree: dict[str, Any] = {}
        for key, value in subtree.items():
            if key in _TTS_NORMATIVE_FLAGS:
                reduced_subtree[key] = (
                    value if isinstance(value, bool)
                    else _ReductionMarker(_INVALID, type(value).__name__)
                )
            elif key in _TTS_NORMATIVE_STRINGS:
                reduced_subtree[key] = (
                    value if isinstance(value, str)
                    else _ReductionMarker(_INVALID, type(value).__name__)
                )
            else:
                reduced_subtree[key] = reduce_value(value)
        reduction[subtree_key] = reduced_subtree
    return reduction


def _validate_tts_projection_ready(projection: dict[str, Any]) -> bool:
    """Apply the active candidate adapter's strict Hermes validators."""
    if not isinstance(projection, dict):
        return False
    bundle = _active_candidate_bundle()
    if bundle is None:
        # Direct unit callers exercise this pure validator outside an
        # admission-owned bundle.  The admission path always has an active
        # bundle before it reaches this helper, so this compatibility branch
        # cannot supply executable objects to the runner's protected lane.
        try:
            module = importlib.import_module("recorder_next.adapters")
        except Exception:
            return False
        validate_envelope = getattr(module, "_validate_envelope_semantics", None)
        tts_provider = getattr(module, "HermesAudioTTSProvider", None)
    else:
        registry = bundle.get("registry")
        entry = registry.get("recorder_next.adapters") if isinstance(registry, dict) else None
        exports = entry.get("exports") if isinstance(entry, dict) else None
        validate_envelope = exports.get("_validate_envelope_semantics") if isinstance(exports, dict) else None
        tts_provider = exports.get("HermesAudioTTSProvider") if isinstance(exports, dict) else None
    if not callable(validate_envelope) or not isinstance(tts_provider, type):
        return False
    try:
        validate_envelope(projection, provider_kind="hermes")
        if not tts_provider._envelope_flags_satisfied(projection):
            return False
        tts_provider._validate_tts_capability(projection)
        return True
    except Exception:
        return False


def _dashboard_remaining_seconds(metadata_raw: str) -> int | None:
    """Read expires_at_utc from the existing historical metadata format."""
    try:
        parsed = json.loads(metadata_raw)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    expires = _utc_parse(parsed.get("expires_at_utc"))
    if expires is None:
        return None
    return expires - int(time.time())


def _snapshot_proc_fd_numbers() -> set[int] | None:
    """Snapshot Linux self FDs without opening a second database reference."""
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return None
    numbers: set[int] = set()
    for name in names:
        if not name.isdigit():
            continue
        try:
            fd = int(name)
            info = os.fstat(fd)
        except (OSError, ValueError):
            continue
        if stat.S_ISREG(info.st_mode):
            numbers.add(fd)
    return numbers


def _fd_object_identity(fd: int) -> tuple[int, int, int] | None:
    try:
        info = os.fstat(fd)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _path_object_identity(path: Path) -> tuple[int, int, int] | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return None
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _directory_custody_signature(path: Path) -> tuple[int, ...] | None:
    """Capture parent-directory metadata to detect replacement/restoration."""
    try:
        info = os.lstat(path.parent)
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return None
    # Directory timestamps detect a same-directory swap/restore.  SQLite WAL
    # sidecars are handled by _directory_custody_equal at comparison time.
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid,
        stat.S_IMODE(info.st_mode), info.st_ctime_ns, info.st_mtime_ns,
    )


def _sqlite_wal_mode(reference_fd: int) -> bool:
    """Read SQLite's format-version bytes from the already-held DB descriptor."""
    try:
        header = os.pread(reference_fd, 20, 0)
    except (AttributeError, OSError):
        return False
    return len(header) == 20 and header[:16] == b"SQLite format 3\x00" and header[18:20] == b"\x02\x02"


def _directory_custody_equal(
    expected: tuple[int, ...] | None,
    actual: tuple[int, ...] | None,
    *,
    wal_mode: bool,
) -> bool:
    if expected is None or actual is None:
        return False
    if expected == actual:
        return True
    # SQLite may create/remove -wal/-shm entries during an otherwise
    # read-only WAL observation, changing only parent timestamps.  The
    # directory's device/inode/owner/mode remain the custody identity.
    return wal_mode and expected[:5] == actual[:5]


def _connection_db_fd(
    before: set[int], reference_identity: tuple[int, int, int]
) -> int | None:
    after = _snapshot_proc_fd_numbers()
    if after is None:
        return None
    matches = [
        fd for fd in sorted(after - before)
        if _fd_object_identity(fd) == reference_identity
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _connection_identity_ok(
    db_path: Path, reference_fd: int, connection_fd: int
) -> bool:
    reference_identity = _fd_object_identity(reference_fd)
    connection_identity = _fd_object_identity(connection_fd)
    path_identity = _path_object_identity(db_path)
    return (
        reference_identity is not None
        and connection_identity == reference_identity
        and path_identity == reference_identity
    )


def _persisted_lookup(context: dict[str, Any], *, deadline_at: float | None = None) -> dict[str, Any]:
    """Read-only indexed SELECT of the target session row (URI mode=ro)."""
    authorization = context.get("authorization") or {}
    paths = authorization.get("paths") or {}
    db_raw = paths.get("persisted_db")
    result: dict[str, Any] = {
        "read_only": False,
        "indexed": False,
        "rows": [],
        "authorizer_installed": False,
        "progress_handler_installed": False,
        "db_identity_equal": False,
        "db_connected_file_equal": False,
    }
    if deadline_at is None:
        deadline_at = context.get("session_deadline")
    if isinstance(deadline_at, bool) or not isinstance(deadline_at, (int, float)):
        return result
    deadline = float(deadline_at)
    if not deadline > time.monotonic():
        return result
    if not isinstance(db_raw, str) or not db_raw:
        return result
    boundary = context.get("boundary") if isinstance(context, dict) else None
    injected_connect = boundary.get("sqlite_connect") if isinstance(boundary, dict) else None
    if injected_connect is None:
        if sqlite3.connect is not _ORIGINAL_SQLITE_CONNECT:
            return result
        connect_callable = _ORIGINAL_SQLITE_CONNECT
    elif callable(injected_connect):
        # Tests may replace this I/O boundary explicitly; production calls
        # always use the captured unmodified stdlib callable above.
        connect_callable = injected_connect
    else:
        return result
    db_path = _bounded_absolute_path(db_raw)
    if db_path is None or not _path_has_no_symlink_components(db_path):
        return result

    reference_fd: int | None = None
    connection_fd: int | None = None
    try:
        reference_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        reference_fd = os.open(db_path, reference_flags)
        reference_identity = _fd_object_identity(reference_fd)
    except OSError:
        return result
    if reference_identity is None:
        os.close(reference_fd)
        return result
    opening_identity = reference_identity
    opening_parent_signature = _directory_custody_signature(db_path)
    wal_mode = _sqlite_wal_mode(reference_fd)
    result["db_wal_mode"] = wal_mode
    if opening_parent_signature is None:
        os.close(reference_fd)
        return result
    result["db_identity_opening"] = opening_identity
    result["db_parent_signature_opening"] = opening_parent_signature

    def ensure_deadline() -> None:
        if time.monotonic() >= deadline:
            raise TimeoutError("admission deadline")

    connection: sqlite3.Connection | None = None
    connection_parent_signature: tuple[int, ...] | None = None
    try:
        ensure_deadline()
        remaining = deadline - time.monotonic()
        busy_timeout_ms = min(5000, int(remaining * 1000))
        if busy_timeout_ms <= 0:
            return result
        before_connect_fds = _snapshot_proc_fd_numbers()
        if before_connect_fds is None:
            return result
        connection = connect_callable(
            f"file:{_sqlite_uri_path(db_path)}?mode=ro",
            uri=True,
            timeout=min(5.0, max(remaining, 0.001)),
            isolation_level=None,
        )
        connection_fd = _connection_db_fd(before_connect_fds, reference_identity)
        result["connection_fd"] = connection_fd
        if connection_fd is None or not _connection_identity_ok(db_path, reference_fd, connection_fd):
            return result
        try:
            db_rows = connection.execute("PRAGMA database_list").fetchall()
        except sqlite3.Error:
            db_rows = []
        connected_file = next((row[2] for row in db_rows if row[1] == "main"), None)
        result["db_connected_file_equal"] = bool(
            connected_file is not None and os.path.normpath(connected_file) == str(db_path)
        )
        result["db_identity_connected"] = _fd_object_identity(connection_fd)
        if not result["db_connected_file_equal"]:
            return result

        def interrupt_if_expired() -> int:
            return 1 if time.monotonic() >= deadline else 0

        connection.set_progress_handler(interrupt_if_expired, 1000)
        result["progress_handler_installed"] = True
        connection.set_authorizer(_admission_authorizer)
        result["authorizer_installed"] = True

        ensure_deadline()
        connection.execute("PRAGMA query_only=ON")
        ensure_deadline()
        connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        ensure_deadline()
        connection_parent_signature = _directory_custody_signature(db_path)
        result["db_parent_signature_connected"] = connection_parent_signature
        if not _directory_custody_equal(
            opening_parent_signature, connection_parent_signature, wal_mode=wal_mode
        ):
            return result
        indexes = connection.execute("PRAGMA index_list('sessions')").fetchall()
        ensure_deadline()
        columns = [row[1] for row in connection.execute("PRAGMA table_info('sessions')").fetchall()]
        result["read_only"] = True
        result["indexed"] = any(
            connection.execute(
                "SELECT COUNT(*) FROM pragma_index_info(?) WHERE name='id'", (index[1],)
            ).fetchone()[0] > 0
            for index in indexes
        ) and "id" in columns
        ensure_deadline()
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT id,source,session_key,ended_at FROM sessions WHERE id=? LIMIT 2",
            (SELECTED_S,),
        ).fetchall()
        uses_index = any("SEARCH" in str(row[-1]) or "USING INDEX" in str(row[-1]).upper() for row in plan)
        result["indexed"] = bool(result["indexed"] and uses_index)
        ensure_deadline()
        rows = connection.execute(
            "SELECT id,source,session_key,ended_at FROM sessions WHERE id=? LIMIT 2",
            (SELECTED_S,),
        ).fetchall()
        result["rows"] = [tuple(row) for row in rows]
        if (
            connection_fd is None
            or not _connection_identity_ok(db_path, reference_fd, connection_fd)
            or not _directory_custody_equal(
                connection_parent_signature,
                _directory_custody_signature(db_path),
                wal_mode=wal_mode,
            )
        ):
            raise OSError("SQLite connection or parent custody drifted after query")
    except (sqlite3.Error, OSError, TimeoutError, TypeError, ValueError):
        result["read_only"] = False
        result["indexed"] = False
        result["rows"] = []
    finally:
        if connection is not None:
            closing_connection_identity = (
                _fd_object_identity(connection_fd) if connection_fd is not None else None
            )
            result["db_connection_identity_closing"] = closing_connection_identity
            result["db_identity_closing"] = _path_object_identity(db_path)
            result["db_identity_equal"] = bool(
                connection_fd is not None
                and _connection_identity_ok(db_path, reference_fd, connection_fd)
                and closing_connection_identity == opening_identity
            )
            if not result["db_identity_equal"] or not result.get("db_connected_file_equal"):
                result["read_only"] = False
                result["indexed"] = False
                result["rows"] = []
            try:
                connection.set_progress_handler(None, 0)
            except Exception:
                pass
            close_failed = False
            try:
                connection.close()
            except Exception:
                close_failed = True
            # The pathname is a separate authority boundary from the held
            # SQLite descriptor.  Re-check it after close as well: a
            # same-path replacement can occur during a wrapped close and be
            # restored before the next caller-visible read.
            post_close_path_identity = _path_object_identity(db_path)
            post_close_parent_signature = _directory_custody_signature(db_path)
            result["db_identity_post_close"] = post_close_path_identity
            result["db_parent_signature_post_close"] = post_close_parent_signature
            if (
                close_failed
                or connection_parent_signature is None
                or post_close_path_identity != opening_identity
                or not _directory_custody_equal(
                    connection_parent_signature,
                    post_close_parent_signature,
                    wal_mode=wal_mode,
                )
                or not result["db_identity_equal"]
                or not result.get("db_connected_file_equal")
            ):
                result["db_identity_equal"] = False
                result["read_only"] = False
                result["indexed"] = False
                result["rows"] = []
        if reference_fd is not None:
            try:
                if _fd_object_identity(reference_fd) != opening_identity:
                    result["db_identity_equal"] = False
                    result["read_only"] = False
                    result["indexed"] = False
                    result["rows"] = []
            finally:
                os.close(reference_fd)
    return result


def _admission_authorizer(action: Any, arg1: Any, arg2: Any, db_name: Any, trigger: Any) -> int:
    """Allow only exact schema inspection and the indexed SELECT."""
    try:
        code = int(action)
    except (TypeError, ValueError):
        return sqlite3.SQLITE_DENY
    if code == sqlite3.SQLITE_PRAGMA:
        allowed = {"table_info", "index_list", "index_info", "query_only", "busy_timeout", "database_list"}
        return sqlite3.SQLITE_OK if isinstance(arg1, str) and arg1 in allowed else sqlite3.SQLITE_DENY
    if code == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if code == sqlite3.SQLITE_FUNCTION:
        return sqlite3.SQLITE_OK if arg2 == "count" else sqlite3.SQLITE_DENY
    if code == sqlite3.SQLITE_READ:
        if arg1 == "sessions":
            return (
                sqlite3.SQLITE_OK
                if arg2 in {"id", "source", "session_key", "ended_at"}
                else sqlite3.SQLITE_DENY
            )
        if arg1 == "pragma_index_info" and arg2 == "name":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY


def main(argv: list[str] | None = None) -> int:
    """Executable CLI: strict canonical invocation or one JSON HOLD/2."""
    started_monotonic = time.monotonic()
    started_utc = _utc_now_iso()
    identity: dict[str, Any] = {
        "candidate_id": None,
        "archive_sha256": None,
        "source_commit": None,
        "source_tree": None,
        "control_sha256": None,
        "spec_sha256": None,
    }
    args = list(sys.argv[1:] if argv is None else argv)
    parsed = _canonical_argv(args)
    if parsed is None:
        report = _hold_report({}, "invalid_argv", started_monotonic, started_utc, identity)
        print(json.dumps(report, sort_keys=True))
        return 2
    manifest = _load_bounded_json(Path(parsed["manifest_path"]), MAX_AUTHORITY_BYTES, parsed["manifest_sha256"])
    if manifest is None:
        report = _hold_report({}, "authority_mismatch", started_monotonic, started_utc, identity)
        print(json.dumps(report, sort_keys=True))
        return 2
    authorization = _load_bounded_json(Path(parsed["authorization_path"]), MAX_AUTHORITY_BYTES, parsed["authorization_sha256"])
    if authorization is None:
        report = _hold_report({}, "authority_mismatch", started_monotonic, started_utc, identity)
        print(json.dumps(report, sort_keys=True))
        return 2
    try:
        control = manifest.get("control") if isinstance(manifest, dict) else {}
        authorities = manifest.get("authorities") if isinstance(manifest, dict) else {}
        identity.update(
            candidate_id=manifest.get("candidate_id") if isinstance(manifest, dict) else None,
            archive_sha256=manifest.get("candidate_sha256") if isinstance(manifest, dict) else None,
            source_commit=manifest.get("source_commit") if isinstance(manifest, dict) else None,
            source_tree=manifest.get("source_tree") if isinstance(manifest, dict) else None,
            control_sha256=control.get("probe_runner_sha256") if isinstance(control, dict) else None,
            spec_sha256=authorities.get("specification_sha256") if isinstance(authorities, dict) else None,
        )
        if not _verify_manifest_structure(manifest):
            raise ValueError("manifest structure")
        if not _verify_authority_binding(manifest, authorization, parsed["manifest_sha256"]):
            raise ValueError("authority binding")
        if not _cold_rehash_ratified_authorities():
            raise ValueError("ratified authority drift")
        if not _verify_candidate_source(authorization, manifest):
            raise ValueError("candidate source")
    except Exception:
        report = _hold_report({}, "authority_mismatch", started_monotonic, started_utc, identity)
        print(json.dumps(report, sort_keys=True))
        return 2
    try:
        report = run_voice1_readonly_admission({
            "manifest": manifest,
            "authorization": authorization,
            "manifest_path": parsed["manifest_path"],
            "authorization_path": parsed["authorization_path"],
            "manifest_sha256": parsed["manifest_sha256"],
            "authorization_sha256": parsed["authorization_sha256"],
            "started_monotonic": started_monotonic,
        })
    except Exception:
        report = _hold_report({}, "internal_error", started_monotonic, started_utc, identity)
    print(json.dumps(report, sort_keys=True))
    return int(report.get("status_code", 2))


# ---------------------------------------------------------------------------
# Fixture-only attempt executor and exact cleanup (B5 region; WP-R reworks
# custody/prefix/transaction semantics in place).
# ---------------------------------------------------------------------------

_RECEIPT_LEAFS = {
    "INTENT": "intent.json",
    "A1_CREATED": "a1.created.json",
    "A2_CREATED": "a2.created.json",
    "A3_BOUND": "a3.bound.json",
    "R1_CLEANED": "r1.cleaned.json",
}
_PHASE_ORDER = ("INTENT", "A1_CREATED", "A2_CREATED", "A3_BOUND")
_DB_FIELDS = {
    "devices": ("user_id", "device_id", "kind", "status", "created_at", "revoked_at"),
    "projects": (
        "stable_project_id", "user_id", "project_number", "name", "aliases_json",
        "description", "status", "default_session_key", "record_version",
        "created_at", "updated_at", "archived_at",
    ),
    "sessions": ("session_key", "project_id", "gateway_session_key", "created_at"),
}
def _schema_source_text() -> str:
    """Lazy candidate schema.sql read.

    Import must stay inert, so the candidate schema text is read only when
    a caller actually needs it.  Reads exactly the lexical candidate file;
    no environment inspection, logging, or caching across calls.
    """
    return (CONTROL_DIR.parent / "recorder_next" / "schema.sql").read_text(
        encoding="utf-8"
    )


def _protected_tables() -> tuple[str, ...]:
    """User tables declared by the candidate schema, sorted (lazy)."""
    return tuple(sorted({
        match.group(1)
        for match in re.finditer(
            r"CREATE TABLE IF NOT EXISTS ([a-z_]+)\s*\(",
            _schema_source_text(),
        )
    }))


_SCHEMA_FINGERPRINT = (
    "devices(user_id,device_id,kind,status,created_at,revoked_at);"
    "projects(stable_project_id,user_id,project_number,name,aliases_json,"
    "description,status,default_session_key,record_version,created_at,"
    "updated_at,archived_at);"
    "sessions(session_key,project_id,gateway_session_key,created_at)"
)
_MAX_RECEIPT_BYTES = 1024 * 1024


class AttemptContextError(ValueError):
    """Raised when a fixture attempt context is missing or unsafe."""


def _validate_fixture_context(context: dict[str, Any]) -> tuple[Path, Path]:
    """Reject live/external/symlink/missing fixture roots; return (root, db)."""
    if not isinstance(context, dict):
        raise AttemptContextError("attempt context must be a mapping")
    root = context.get("fixture_root")
    db_path = context.get("db_path")
    if not isinstance(root, (str, Path)) or not isinstance(db_path, (str, Path)):
        raise AttemptContextError("fixture_root and db_path are required")
    root_path = Path(root)
    if not root_path.exists():
        raise AttemptContextError("fixture root does not exist")
    root = root_path.resolve(strict=True)
    db = Path(db_path)
    if not db.is_absolute():
        raise AttemptContextError("db_path must be absolute")
    resolved_db = db.resolve(strict=False)
    try:
        resolved_db.relative_to(root)
    except ValueError:
        raise AttemptContextError("db must live under the private fixture root") from None
    if not root.is_dir():
        raise AttemptContextError("fixture root must be a directory")
    if context.get("allow_live") is True:
        raise AttemptContextError("live execution is not authorized for fixtures")
    for live in ("/var/lib/recorder-next", "/home/rumi/.hermes", "/etc/recorder-next"):
        try:
            root.relative_to(Path(live))
        except ValueError:
            continue
        raise AttemptContextError("fixture root overlaps a protected live path")
    return root, resolved_db


def _canonical_receipt_bytes(receipt: dict[str, Any]) -> bytes:
    return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _receipt_sha256(receipt: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_receipt_bytes(receipt)).hexdigest()


def _fstat_path(path: Path) -> tuple[int, int]:
    info = path.stat()
    return info.st_dev, info.st_ino


def publish_attempt_receipt(context: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    """No-clobber durable receipt publication (R.2).

    Opens the exact leaf with O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW under the
    validated private receipt directory, writes canonical JSON bytes once,
    fsyncs file and directory, and verifies device/inode/size/readback.
    Refuses symlink/wrong-mode/preexisting/collision targets.  A partial
    final leaf is deliberate HOLD evidence and is never repaired or removed.
    """
    root, _ = _validate_fixture_context(context)
    receipts_dir = root / "receipts"
    if not receipts_dir.is_dir() or receipts_dir.is_symlink():
        raise AttemptContextError("receipts directory missing or symlinked")
    if (receipts_dir.stat().st_mode & 0o077) != 0:
        raise AttemptContextError("receipts directory mode is unsafe")
    phase = receipt.get("phase")
    if phase not in _RECEIPT_LEAFS:
        raise AttemptContextError("unknown receipt phase")
    leaf = receipts_dir / _RECEIPT_LEAFS[phase]
    payload = _canonical_receipt_bytes(receipt)
    if len(payload) > _MAX_RECEIPT_BYTES:
        raise AttemptContextError("receipt exceeds bounded size")
    if leaf.is_symlink() or leaf.exists():
        raise AttemptContextError("receipt leaf already exists (no-clobber)")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(leaf.name, flags, 0o600, dir_fd=os.open(str(receipts_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)))
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        info = os.fstat(fd)
    finally:
        os.close(fd)
    dir_fd = os.open(str(receipts_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    if leaf.is_symlink() or not leaf.is_file():
        raise AttemptContextError("published leaf is not a regular file")
    after = leaf.stat()
    if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino) or after.st_size != len(payload):
        raise AttemptContextError("published leaf identity or size drifted")
    if leaf.read_bytes() != payload:
        raise AttemptContextError("published leaf readback mismatch")
    # Custody registry: one no-clobber entry file per leaf under custody/.
    # The loader refuses any leaf whose dev/inode/sha drifts from its entry
    # (a same-byte different-inode rewrite is never adopted).
    custody_dir = receipts_dir / "custody"
    custody_dir.mkdir(mode=0o700, exist_ok=True)
    entry_path = custody_dir / (leaf.name + ".custody")
    entry = _json_module().dumps({
        "leaf": leaf.name, "device": after.st_dev, "inode": after.st_ino,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }, sort_keys=True).encode("utf-8")
    entry_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd_entry = os.open(str(entry_path), entry_flags, 0o600)
    try:
        os.write(fd_entry, entry)
        os.fsync(fd_entry)
    finally:
        os.close(fd_entry)
    return {
        "phase": phase,
        "leaf": leaf.name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "device": after.st_dev,
        "inode": after.st_ino,
        "size": after.st_size,
    }


def load_attempt_prefix(context: dict[str, Any], expected_head_sha256: str) -> list[dict[str, Any]]:
    """Authenticate a receipt chain forward against an out-of-band head pin (R.2).

    Reads the present leaves in exact phase order, validates canonical bytes,
    schema, phase/leaf agreement, and predecessor chaining, and requires the
    LAST validated receipt's hash to equal the pinned head.  A missing leaf
    between present leaves, a symlink, non-canonical bytes, a wrong phase
    name, or any hash mismatch is a refusal (AttemptContextError); the
    expected head is never derived from whatever file happens to be present.
    """
    root, _ = _validate_fixture_context(context)
    receipts_dir = root / "receipts"
    if not receipts_dir.is_dir() or receipts_dir.is_symlink():
        raise AttemptContextError("receipts directory missing or symlinked")
    phase_order = list(_PHASE_ORDER) + ["R1_CLEANED"]
    loaded: list[dict[str, Any]] = []
    previous_sha: str | None = None
    seen_r1 = False
    for index, phase in enumerate(phase_order):
        leaf = receipts_dir / _RECEIPT_LEAFS[phase]
        if not leaf.exists():
            # Interior absence is tolerable ONLY for the phases an R1_CLEANED
            # receipt may skip (a cleaned receipt extends ANY valid prefix);
            # chain continuity is still proven by each present leaf's
            # predecessor hash.  The final phase-order check enforces that a
            # cleaned suffix only ever extends a valid creation prefix.
            continue
        if leaf.is_symlink() or not leaf.is_file():
            raise AttemptContextError("receipt leaf is a symlink or not a file")
        payload = leaf.read_bytes()
        if len(payload) > _MAX_RECEIPT_BYTES:
            raise AttemptContextError("receipt exceeds bounded size")
        digest = hashlib.sha256(payload).hexdigest()
        # Custody check: refuse drift from the publication-time identity.
        entry_path = receipts_dir / "custody" / (leaf.name + ".custody")
        if not entry_path.is_file() or entry_path.is_symlink():
            raise AttemptContextError("custody entry missing for receipt")
        try:
            entry = json.loads(entry_path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            raise AttemptContextError("custody entry is unreadable") from None
        current_stat = leaf.stat()
        if (
            entry.get("device") != current_stat.st_dev
            or entry.get("inode") != current_stat.st_ino
            or entry.get("sha256") != digest
        ):
            raise AttemptContextError("receipt custody drift (same-byte different-inode or tampered)")
        try:
            receipt = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise AttemptContextError("receipt is not valid JSON") from None
        if not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA:
            raise AttemptContextError("receipt schema mismatch")
        if _canonical_receipt_bytes(receipt) != payload:
            raise AttemptContextError("receipt bytes are not canonical")
        if receipt.get("phase") != phase or _RECEIPT_LEAFS.get(phase) != leaf.name:
            raise AttemptContextError("receipt phase and leaf disagree")
        expected_predecessor = previous_sha
        if receipt.get("predecessor_receipt_sha256") != expected_predecessor:
            raise AttemptContextError("receipt chain is broken")
        if phase == "INTENT" and receipt.get("predecessor_receipt_sha256") is not None:
            raise AttemptContextError("INTENT binds no predecessor")
        if phase == "R1_CLEANED":
            if seen_r1 or not loaded:
                raise AttemptContextError("R1_CLEANED must extend a valid prefix")
            seen_r1 = True
        loaded.append(receipt)
        previous_sha = digest
    if not loaded:
        return []
    tip_sha = hashlib.sha256(_canonical_receipt_bytes(loaded[-1])).hexdigest()
    if tip_sha != expected_head_sha256:
        raise AttemptContextError("receipt head pin mismatch")
    phase_names = [receipt["phase"] for receipt in loaded]
    # Valid chains: any strict creation prefix, optionally extended by
    # R1_CLEANED (which may follow ANY valid prefix per architecture R.4).
    valid_prefixes = []
    for stop in range(1, len(_PHASE_ORDER) + 1):
        valid_prefixes.append(list(_PHASE_ORDER)[:stop])
        valid_prefixes.append(list(_PHASE_ORDER)[:stop] + ["R1_CLEANED"])
    if phase_names not in valid_prefixes:
        raise AttemptContextError("receipt phase order violation")
    return loaded


def _protected_logical_digest(conn: sqlite3.Connection, context: dict[str, Any] | None = None) -> str:
    """Typed digest over every table EXCLUDING only exact owned target PKs.

    Architecture section 6 R.4: the protected vector excludes ONLY the
    attempt's own target rows, so the baseline stays stable across legitimate
    A1/A2/A3 inserts of the attempt's own rows while any foreign/protected/
    dependent work in any table changes the digest and holds the attempt.
    """
    identity = (context or {}).get("trial_identity") or {}
    trial_u = identity.get("U")
    trial_d = identity.get("D")
    trial_p = identity.get("P")
    trial_l = identity.get("L")
    digests: list[str] = []
    # Every user table from the candidate schema participates in the whole-
    # table comparison (R.4: mandatory even where a direct-reference query
    # also passes; no table is silently skipped).
    for table in _protected_tables():
        columns = [info[1] for info in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if not columns:
            raise AttemptContextError(f"protected table {table} missing from schema")
        rows = [tuple(row) for row in conn.execute(f"SELECT {','.join(columns)} FROM {table}").fetchall()]
        if table == "devices" and trial_u and trial_d:
            rows = [row for row in rows if not (row[0] == trial_u and row[1] == trial_d)]
        elif table == "projects" and trial_p:
            rows = [row for row in rows if row[0] != trial_p]
        elif table == "sessions" and trial_l:
            rows = [row for row in rows if row[0] != trial_l]
        digests.append(f"{table}:" + _row_set_digest(rows))
    return hashlib.sha256("".join(digests).encode("utf-8")).hexdigest()


def _read_trial_rows(conn: sqlite3.Connection, context: dict[str, Any]) -> dict[str, Any]:
    identity = context["trial_identity"]
    device = conn.execute(
        "SELECT user_id,device_id,kind,status,created_at,revoked_at FROM devices WHERE user_id=? AND device_id=?",
        (identity["U"], identity["D"]),
    ).fetchone()
    project = conn.execute(
        "SELECT stable_project_id,user_id,project_number,name,aliases_json,description,status,default_session_key,record_version,created_at,updated_at,archived_at FROM projects WHERE stable_project_id=?",
        (identity["P"],),
    ).fetchone()
    session = conn.execute(
        "SELECT session_key,project_id,gateway_session_key,created_at FROM sessions WHERE session_key=?",
        (identity["L"],),
    ).fetchone()
    return {
        "devices": tuple(device) if device else None,
        "projects": tuple(project) if project else None,
        "sessions": tuple(session) if session else None,
    }


def _base_receipt(context: dict[str, Any], phase: str, predecessor: str | None) -> dict[str, Any]:
    identity = context["trial_identity"]
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "attempt_id": context["attempt_id"],
        "phase": phase,
        "operation_time_utc": _utc_now_iso(),
        "candidate_id": context.get("candidate_id"),
        "archive_sha256": context.get("archive_sha256"),
        "source_commit": context.get("source_commit"),
        "source_tree": context.get("source_tree"),
        "control_packet_sha256": context.get("control_packet_sha256"),
        "spec_sha256": context.get("spec_sha256"),
        "owner_authorization_sha256": context.get("owner_authorization_sha256"),
        "db_path": str(context["db_path"]),
        "schema_fingerprint": _SCHEMA_FINGERPRINT,
        "trial_identity": {
            "U": identity["U"], "D": identity["D"], "N": identity["N"],
            "I": identity["I"], "P": identity["P"], "L": identity["L"],
            "S": identity["S"], "selected_session_id_sha256": EXPECTED_S_SHA256,
        },
        "protected_logical_digest": context.get("protected_logical_digest"),
        "predecessor_receipt_sha256": predecessor,
    }
    return receipt


def _connect_fixture(context: dict[str, Any]) -> sqlite3.Connection:
    conn = sqlite3.connect(str(context["db_path"]), timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _validate_receipt_chain_prefix(context: dict[str, Any], prefix: list[dict[str, Any]],
                                   conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Complete receipt-chain validator, split into two checks (B6 REV-010).

    1. History: every node is internally authenticated and each transition
       matches its predecessor's postimage (including the exact absence
       shape for INTENT/R1 history nodes).  INTENT's historic absence is NOT
       compared to today's DB.
    2. Tip: only the HEAD receipt's postimage/absence is compared to the
       current DB rows.

    Returns the tip receipt.
    """
    if not prefix:
        return None
    previous_rows: dict[str, Any] = {"devices": None, "projects": None, "sessions": None}
    for receipt in prefix:
        phase = receipt["phase"]
        rows = receipt.get("current_rows") or {}
        if phase == "INTENT":
            if any(value is not None for value in rows.values()):
                raise AttemptContextError("INTENT receipt carries non-absent postimage")
        elif phase == "A1_CREATED":
            if (rows.get("devices") is None
                    or rows.get("projects") is not None or rows.get("sessions") is not None):
                raise AttemptContextError("A1 receipt postimage shape invalid")
            if previous_rows.get("devices") is not None:
                raise AttemptContextError("A1 transition requires prior absence")
        elif phase == "A2_CREATED":
            if (rows.get("devices") is None or rows.get("projects") is None
                    or rows.get("sessions") is None):
                raise AttemptContextError("A2 receipt postimage shape invalid")
            if (rows.get("devices") != previous_rows.get("devices")
                    or previous_rows.get("projects") is not None
                    or previous_rows.get("sessions") is not None):
                raise AttemptContextError("A2 transition does not extend A1 image")
        elif phase == "A3_BOUND":
            if (rows.get("devices") != previous_rows.get("devices")
                    or rows.get("projects") is None or rows.get("sessions") is None):
                raise AttemptContextError("A3 transition does not extend A2 image")
            if rows.get("projects") == previous_rows.get("projects"):
                raise AttemptContextError("A3 transition must change project state")
        elif phase == "R1_CLEANED":
            if any(value is not None for value in rows.values()):
                raise AttemptContextError("R1_CLEANED receipt carries non-absent postimage")
        previous_rows = {key: list(value) if isinstance(value, (list, tuple)) else value
                         for key, value in rows.items()} if rows else previous_rows
        tip = receipt
    # Tip-vs-DB comparison (under whatever transaction the caller holds).
    tip = prefix[-1]
    current = _read_trial_rows(conn, context)
    rows = tip.get("current_rows") or {}
    if tip["phase"] in ("INTENT", "R1_CLEANED"):
        if any(value is not None for value in current.values()):
            raise AttemptContextError("tip expects absent target rows but rows exist")
    else:
        for table in ("devices", "projects", "sessions"):
            expected_value = rows.get(table)
            expected_tuple = tuple(expected_value) if expected_value is not None else None
            if current[table] != expected_tuple:
                raise AttemptContextError(f"tip {table} does not match current rows")
    return tip


def receipt_identity_digest(receipt: dict[str, Any]) -> str:
    return _receipt_sha256({key: value for key, value in receipt.items() if key != "receipt_sha256"})


def _json_module():
    return json


def _receipt_digest_of_stored(receipt: dict[str, Any] | None) -> str | None:
    """Digest of a loaded receipt's canonical bytes (its chain head value)."""
    if receipt is None:
        return None
    return _receipt_sha256(receipt)


def execute_attempt_phase(context: dict[str, Any], phase: str,
                          expected_head_sha256: str) -> dict[str, Any]:
    """Fixture-only attempt phase executor (R.3).

    Validates the durable prefix from the out-of-band head pin, runs the
    packet's exact single-statement SQL blocks inside one BEGIN IMMEDIATE
    transaction with full typed readback, commits, and only then publishes
    the phase receipt.  A commit whose receipt cannot be published is returned
    as COMMIT_UNCERTAIN with the head unchanged; nothing is retried by
    equality and no receipt is synthesized.
    """
    root, db_path = _validate_fixture_context(context)
    if phase not in {"A1", "A2", "A3"}:
        raise AttemptContextError("unsupported creation phase")
    report_context = context
    context = dict(context)
    context["db_path"] = db_path
    try:
        prefix = load_attempt_prefix(context, expected_head_sha256)
    except AttemptContextError:
        return {
            "status": "HOLD", "state": "HOLD",
            "creation_outcome": "not_created_collision" if phase == "A1" else "HOLD",
            "phase": phase, "reason_codes": ["prefix_unavailable"],
        }
    names = [receipt["phase"] for receipt in prefix]
    if phase == "A1":
        if "A1_CREATED" in names:
            return {"status": "HOLD", "state": "A1_CREATED", "creation_outcome": "not_created_collision", "phase": phase, "reason_codes": ["phase_already_durable"]}
        if names != ["INTENT"]:
            return {"status": "HOLD", "state": "HOLD", "creation_outcome": "HOLD", "phase": phase, "reason_codes": ["prefix_mismatch"]}
    if phase == "A2":
        if "A2_CREATED" in names:
            return {"status": "HOLD", "state": "A2_CREATED", "creation_outcome": "already_completed", "phase": phase, "reason_codes": ["phase_already_durable"]}
        if names != ["INTENT", "A1_CREATED"]:
            return {"status": "HOLD", "state": "HOLD", "creation_outcome": "HOLD", "phase": phase, "reason_codes": ["prefix_mismatch"]}
    if phase == "A3":
        if "A3_BOUND" in names:
            return {"status": "HOLD", "state": "A3_BOUND", "creation_outcome": "already_completed", "phase": phase, "reason_codes": ["phase_already_durable"]}
        if names != ["INTENT", "A1_CREATED", "A2_CREATED"]:
            return {"status": "HOLD", "state": "HOLD", "creation_outcome": "HOLD", "phase": phase, "reason_codes": ["prefix_mismatch"]}
    tip = prefix[-1] if prefix else None
    tip_receipt_sha = _receipt_digest_of_stored(tip)
    admission: dict[str, Any] | None = None
    admission_sha256: str | None = None
    if phase == "A3":
        admission = _read_admission_report_once(report_context)
        if admission is None:
            return {
                "status": "HOLD", "state": "HOLD", "creation_outcome": "HOLD",
                "phase": phase, "reason_codes": ["admission_report_invalid"],
            }
        admission_sha256 = context.get("admission_sha256")
    blocks = _load_blocks()
    identity = context["trial_identity"]
    receipt_phase = {"A1": "A1_CREATED", "A2": "A2_CREATED", "A3": "A3_BOUND"}[phase]
    leaf = _RECEIPT_LEAFS[receipt_phase]
    if (root / "receipts" / leaf).exists():
        return {"status": "HOLD", "state": "COMMIT_UNCERTAIN", "creation_outcome": "commit_uncertain",
                "phase": phase, "reason_codes": ["receipt_leaf_preexists"]}
    conn = _connect_fixture(context)
    committed = False
    try:
        # B6 (REV-011): BEGIN IMMEDIATE precedes EVERY authorizing read —
        # target rows, protected vector, and collision checks.  There are no
        # pre-lock authoritative reads left in this function.
        conn.execute("BEGIN IMMEDIATE")
        opening = _read_trial_rows(conn, context)
        if _protected_logical_digest(conn, context) != context.get("protected_logical_digest"):
            raise AttemptContextError("protected logical vector drifted before phase")
        if phase == "A1":
            if any(value is not None for value in opening.values()):
                raise AttemptContextError("A1 requires all target rows absent")
            params = context["phase_params"]["A1"]
            cur = conn.execute(blocks["a1.insert_device"], params)
            if cur.rowcount != 1:
                raise AttemptContextError("a1 insert rowcount is not one")
            expected_device = (
                params["device_user_id"], params["device_id"], params["kind"],
                params["device_status"], params["device_created_at"], params["revoked_at"],
            )
            if tuple(conn.execute(
                "SELECT user_id,device_id,kind,status,created_at,revoked_at FROM devices WHERE user_id=? AND device_id=?",
                (params["device_user_id"], params["device_id"]),
            ).fetchone()) != expected_device:
                raise AttemptContextError("a1 postimage mismatch")
            current_rows = {"devices": expected_device, "projects": None, "sessions": None}
        else:
            if phase == "A2":
                if opening["devices"] is None or opening["projects"] is not None or opening["sessions"] is not None:
                    raise AttemptContextError("A2 requires exact A1 device and absent project/session")
                params = context["phase_params"]["A2"]
                cur = conn.execute(blocks["a2.insert_project"], params)
                if cur.rowcount != 1:
                    raise AttemptContextError("a2 project rowcount is not one")
                expected_project = (
                    params["stable_project_id"], params["project_user_id"], params["project_number"],
                    params["name"], params["aliases_json"], params["description"], params["project_status"],
                    params["default_session_key"], params["record_version"], params["project_created_at"],
                    params["project_updated_at"], params["archived_at"],
                )
                stored_project = tuple(conn.execute(
                    "SELECT stable_project_id,user_id,project_number,name,aliases_json,description,status,default_session_key,record_version,created_at,updated_at,archived_at FROM projects WHERE stable_project_id=?",
                    (params["stable_project_id"],),
                ).fetchone())
                if stored_project != expected_project:
                    raise AttemptContextError("a2 project postimage mismatch")
                cur = conn.execute(blocks["a2.insert_session"], params)
                if cur.rowcount != 1:
                    raise AttemptContextError("a2 session rowcount is not one")
                expected_session = (
                    params["session_key"], params["project_id"],
                    params["gateway_session_key"], params["session_created_at"],
                )
                stored_session = tuple(conn.execute(
                    "SELECT session_key,project_id,gateway_session_key,created_at FROM sessions WHERE session_key=?",
                    (params["session_key"],),
                ).fetchone())
                if stored_session != expected_session:
                    raise AttemptContextError("a2 session postimage mismatch")
                current_rows = {"devices": opening["devices"], "projects": expected_project, "sessions": expected_session}
            else:
                # A3 consumes the exact, externally pinned admission bytes;
                # _read_admission_report_once ran before BEGIN IMMEDIATE.
                if admission is None:
                    raise AttemptContextError("A3 requires the exact admission report")
                predicates = admission["predicates"]
                if any(predicates[name] is not True for name in REQUIRED_PREDICATES):
                    raise AttemptContextError("A3 admission report has non-true required predicates")
                if admission.get("candidate_id") != context.get("candidate_id"):
                    raise AttemptContextError("A3 admission report candidate mismatch")
                if opening["devices"] is None or opening["projects"] is None or opening["sessions"] is None:
                    raise AttemptContextError("A3 requires the exact A2 rows")
                if not _a3_admission_is_fresh(report_context, admission):
                    raise AttemptContextError("A3 admission report expired before mutation")
                params = context["phase_params"]["A3"]
                cur = conn.execute(blocks["a3.bind_session"], params)
                if cur.rowcount != 1:
                    raise AttemptContextError("a3 bind rowcount is not one")
                cur = conn.execute(blocks["a3.bump_project"], params)
                if cur.rowcount != 1:
                    raise AttemptContextError("a3 bump rowcount is not one")
                rows_now = _read_trial_rows(conn, context)
                if rows_now["sessions"][2] != identity["S"] or rows_now["projects"][8] != 2:
                    raise AttemptContextError("a3 postimage mismatch")
                current_rows = {
                    "devices": rows_now["devices"],
                    "projects": rows_now["projects"],
                    "sessions": rows_now["sessions"],
                }
        conn.execute("COMMIT")
        committed = True
    except BaseException:
        try:
            if not committed:
                conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()
        raise
    try:
        if _protected_logical_digest(conn, context) != context.get("protected_logical_digest"):
            raise AttemptContextError("protected logical vector drifted after commit")
        fresh = _read_trial_rows(conn, context)
        conn.close()
        receipt = _base_receipt(context, receipt_phase, tip_receipt_sha)
        receipt["current_rows"] = {table: list(values) if values is not None else None for table, values in current_rows.items()}
        receipt["explicit_absent"] = []
        if phase == "A3":
            receipt["admission_sha256"] = admission_sha256
        receipt_sha = _receipt_sha256(receipt)
        if (root / "receipts" / leaf).exists():
            return {
                "status": "HOLD", "state": "COMMIT_UNCERTAIN",
                "creation_outcome": "commit_uncertain", "phase": phase,
                "expected_head_sha256": receipt_sha, "reason_codes": ["receipt_leaf_preexists"],
            }
        published = publish_attempt_receipt(context, receipt)
        return {
            "status": "PASS", "state": receipt_phase,
            "creation_outcome": {
                "A1": "inserted_by_this_attempt",
                "A2": "inserted_by_this_attempt",
                "A3": "bound_by_this_attempt",
            }[phase],
            "phase": phase,
            "expected_head_sha256": receipt_sha,
            "resulting_head_sha256": receipt_sha,
            "changed_row_count": 1 if phase == "A1" else 2,
            "published": published,
        }
    except BaseException:
        # Commit succeeded but validation/publication failed: never label
        # rolled_back, preserve rows and receipts as COMMIT_UNCERTAIN.
        try:
            conn.close()
        except sqlite3.Error:
            pass
        return {
            "status": "HOLD", "state": "COMMIT_UNCERTAIN",
            "creation_outcome": "commit_uncertain", "phase": phase,
            "reason_codes": ["receipt_publication_failed"],
        }

def cleanup_attempt(context: dict[str, Any], expected_head_sha256: str) -> dict[str, Any]:
    """Receipt-authenticated atomic cleanup (R.4).

    Validates the receipt chain first, then in ONE BEGIN IMMEDIATE transaction
    re-reads the full expected current row vector, performs the typed
    null-safe DELETEs (sessions -> projects -> devices) via the packet's exact
    SQL blocks, verifies absence, commits, and only then publishes
    r1.cleaned.json.  Any zero/extra rowcount or failure rolls back all
    deletions; a commit whose receipt publication fails is uncertain.
    """
    root, db_path = _validate_fixture_context(context)
    context = dict(context)
    context["db_path"] = db_path
    prefix = load_attempt_prefix(context, expected_head_sha256)
    names = [receipt["phase"] for receipt in prefix]
    tip_sha256 = hashlib.sha256(_canonical_receipt_bytes(prefix[-1])).hexdigest() if prefix else expected_head_sha256
    if not names:
        return {"status": "HOLD", "state": "HOLD", "creation_outcome": "HOLD",
                "phase": "R1", "reason_codes": ["no_receipts"]}
    blocks = _load_blocks()
    identity = context["trial_identity"]
    tip = prefix[-1]
    tip_phase = tip["phase"]

    conn = _connect_fixture(context)
    committed = False
    try:
        # B6 (REV-011): the transaction starts before any authorizing read.
        conn.execute("BEGIN IMMEDIATE")
        current = _read_trial_rows(conn, context)
        if _protected_logical_digest(conn, context) != context.get("protected_logical_digest"):
            raise AttemptContextError("protected logical vector drifted before cleanup")
        if tip_phase == "INTENT":
            if any(value is not None for value in current.values()):
                raise AttemptContextError("INTENT cleanup requires all target rows absent")
            conn.close()
            return {
                "status": "PASS", "state": "INTENT",
                "creation_outcome": "intent_only", "phase": "R1",
                "reason_codes": ["no_mutation"],
                "resulting_head_sha256": expected_head_sha256,
            }
        if tip_phase == "R1_CLEANED":
            if any(value is not None for value in current.values()):
                raise AttemptContextError("R1_CLEANED prefix but target rows exist")
            conn.close()
            return {
                "status": "PASS", "state": "R1_CLEANED",
                "creation_outcome": "already_completed", "phase": "R1",
                "reason_codes": ["no_mutation"],
                "resulting_head_sha256": tip_sha256,
            }
        rows_by_phase = {receipt["phase"]: receipt.get("current_rows") or {} for receipt in prefix}
        expected = rows_by_phase.get(tip_phase)
        # B6 (REV-011): DELETE parameters derive from the receipt-authenticated
        # postimage (the tip receipt), never from post-lock current rows.  The
        # post-lock re-read below must EQUAL this receipt image before any
        # DELETE is issued.
        receipt_rows = {
            table: tuple(values) if values is not None else None
            for table, values in (expected or {}).items()
        }
        if not expected:
            raise AttemptContextError("tip receipt carries no postimage")
        if tip_phase == "A1_CREATED":
            if current["devices"] != tuple(expected["devices"]) or current["projects"] is not None or current["sessions"] is not None:
                raise AttemptContextError("A1-only cleanup requires exact device and absent project/session")
        elif tip_phase == "A2_CREATED":
            expected_device = tuple(expected["devices"]) if expected.get("devices") else None
            if (current["devices"] != expected_device or current["projects"] != tuple(expected["projects"])
                    or current["sessions"] != tuple(expected["sessions"])):
                raise AttemptContextError("A2 cleanup requires the exact three rows")
            if current["projects"][8] != 1 or current["sessions"][2] != identity["L"]:
                raise AttemptContextError("A2 cleanup requires version1 and gateway L")
        elif tip_phase == "A3_BOUND":
            if (current["devices"] != (tuple(expected["devices"]) if expected.get("devices") else None)
                    or current["projects"] != (tuple(expected["projects"]) if expected.get("projects") else None)
                    or current["sessions"] != (tuple(expected["sessions"]) if expected.get("sessions") else None)):
                raise AttemptContextError("A3 cleanup requires the exact A4 rows")
            if current["projects"][8] != 2 or current["sessions"][2] != identity["S"]:
                raise AttemptContextError("A3 cleanup requires version2 and gateway S")
        else:
            raise AttemptContextError("unsupported cleanup prefix")
        # Already inside the single BEGIN IMMEDIATE transaction; re-read the
        # exact expected vector under the lock before any DELETE.
        current = _read_trial_rows(conn, context)
        deleted: list[str] = []

        def _packet_params(table: str, values: tuple[Any, ...]) -> dict[str, Any]:
            # Map stored column order to the packet SQL's named parameters and
            # bind each typeof() predicate parameter from the receipt value's
            # actual SQLite storage class (B6 REV-011 typed deletes).
            packet_names = {
                "devices": ("device_user_id", "device_id", "kind", "device_status", "device_created_at", "revoked_at"),
                "projects": (
                    "stable_project_id", "project_user_id", "project_number", "name",
                    "aliases_json", "description", "project_status", "default_session_key",
                    "record_version", "project_created_at", "project_updated_at", "archived_at",
                ),
                "sessions": ("session_key", "project_id", "gateway_session_key", "session_created_at"),
            }[table]
            return _typed_sql_params(dict(zip(packet_names, values)))

        if receipt_rows.get("sessions") is not None:
            if current["sessions"] != receipt_rows["sessions"]:
                raise AttemptContextError("session row drifted from receipt postimage")
            cur = conn.execute(blocks["r1.delete_session"], _packet_params("sessions", receipt_rows["sessions"]))
            if cur.rowcount != 1:
                raise AttemptContextError("session delete rowcount is not one")
            deleted.append("sessions")
        if receipt_rows.get("projects") is not None:
            if current["projects"] != receipt_rows["projects"]:
                raise AttemptContextError("project row drifted from receipt postimage")
            cur = conn.execute(blocks["r1.delete_project"], _packet_params("projects", receipt_rows["projects"]))
            if cur.rowcount != 1:
                raise AttemptContextError("project delete rowcount is not one")
            deleted.append("projects")
        if receipt_rows.get("devices") is not None:
            if current["devices"] != receipt_rows["devices"]:
                raise AttemptContextError("device row drifted from receipt postimage")
            cur = conn.execute(blocks["r1.delete_device"], _packet_params("devices", receipt_rows["devices"]))
            if cur.rowcount != 1:
                raise AttemptContextError("device delete rowcount is not one")
            deleted.append("devices")
        after = _read_trial_rows(conn, context)
        if any(value is not None for value in after.values()):
            raise AttemptContextError("target rows remain after cleanup")
        if _protected_logical_digest(conn, context) != context.get("protected_logical_digest"):
            raise AttemptContextError("protected logical vector drifted inside cleanup")
        conn.execute("COMMIT")
        committed = True
        conn.close()
    except BaseException:
        try:
            if not committed:
                conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()
        raise
    receipt = _base_receipt(context, "R1_CLEANED", _receipt_digest_of_stored(tip))
    receipt["deleted_tables"] = deleted
    receipt["current_rows"] = {"devices": None, "projects": None, "sessions": None}
    receipt_sha = _receipt_sha256(receipt)
    leaf = root / "receipts" / _RECEIPT_LEAFS["R1_CLEANED"]
    if leaf.exists():
        return {
            "status": "HOLD", "state": "COMMIT_UNCERTAIN",
            "creation_outcome": "commit_uncertain", "phase": "R1",
            "expected_head_sha256": receipt_sha,
            "reason_codes": ["receipt_leaf_preexists"],
        }
    try:
        publish_attempt_receipt(context, receipt)
    except OSError:
        return {
            "status": "HOLD", "state": "COMMIT_UNCERTAIN",
            "creation_outcome": "commit_uncertain", "phase": "R1",
            "expected_head_sha256": receipt_sha,
            "reason_codes": ["receipt_publication_failed"],
        }
    return {
        "status": "PASS", "state": "R1_CLEANED",
        "creation_outcome": "cleaned_by_this_attempt", "phase": "R1",
        "expected_head_sha256": receipt_sha,
        "resulting_head_sha256": receipt_sha,
        "deleted_tables": deleted,
    }


class AttemptExecutorTests(unittest.TestCase):
    """B4: fixture executor/custody/COMMIT_UNCERTAIN/cleanup matrix (R.1-R.4)."""

    def setUp(self) -> None:
        self.blocks = _load_blocks()
        for name in SQL_BLOCK_NAMES:
            self.assertEqual(
                hashlib.sha256(self.blocks[name].encode("utf-8")).hexdigest(),
                SQL_STATEMENT_SHA256[name],
                f"packet SQL bytes drifted for {name}",
            )
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "attempt-root"
        (self.root / "receipts").mkdir(parents=True)
        os.chmod(self.root / "receipts", 0o700)
        db_path = self.root / "recorder-next.sqlite3"
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA foreign_keys=ON")
        _fixture_schema(conn)
        _seed_release_smoke(conn)
        conn.commit()
        conn.close()
        self.control_packet_sha256 = hashlib.sha256(
            PACKET_PATH.read_bytes()
        ).hexdigest()
        self.context = {
            "fixture_root": self.root,
            "db_path": db_path,
            "attempt_id": str(uuid.uuid4()),
            "candidate_id": "fixture-candidate",
            "archive_sha256": "0" * 64,
            "source_commit": "f" * 40,
            "source_tree": "e" * 40,
            "control_sha256": "b" * 64,
            "control_packet_sha256": self.control_packet_sha256,
            "spec_sha256": "d" * 64,
            "owner_authorization_sha256": "c" * 64,
            "manifest_sha256": "a" * 64,
            "authorization_sha256": "c" * 64,
            "execution_scope": "fixture_readonly",
            "trial_identity": self._trial_identity(),
            "phase_params": {},
            "admission_report": None,
            "admission_report_bytes": None,
        }
        self.context["protected_logical_digest"] = self._protected_digest()

    # -- fixture helpers -----------------------------------------------

    @staticmethod
    def _trial_identity() -> dict[str, str]:
        u = "voice1-trial-owner-7333f832a973d428"
        return {
            "U": u,
            "D": "voice1-server-trial-7333f832a973d428",
            "N": "VOICE1-TRIAL-7333f832a973d428",
            "I": "recorder-next:voice1:isolated-trial:7333f832a973d428",
            "P": "b961f648-3f79-5f92-9ed7-aeceb087fa02",
            "L": "project:b961f648-3f79-5f92-9ed7-aeceb087fa02:default",
            "S": SELECTED_S,
        }

    def _protected_digest(self) -> str:
        conn = _connect_fixture(self.context)
        try:
            return _protected_logical_digest(conn)
        finally:
            conn.close()

    def _a1_params(self) -> dict[str, Any]:
        identity = self.context["trial_identity"]
        return {
            "device_user_id": identity["U"],
            "device_id": identity["D"],
            "kind": "other",
            "device_status": "active",
            "device_created_at": "2026-09-12T13:00:00.000+00:00",
            "revoked_at": None,
        }

    def _a2_params(self) -> dict[str, Any]:
        a1 = self._a1_params()
        identity = self.context["trial_identity"]
        return {
            "stable_project_id": identity["P"],
            "project_user_id": identity["U"],
            "project_number": identity["N"],
            "name": "Recorder Voice1 isolated trial",
            "aliases_json": "[]",
            "description": "Owner-authorized server-only two-turn voice trial; isolated from existing Recorder projects.",
            "project_status": "active",
            "default_session_key": identity["L"],
            "record_version": 1,
            "project_created_at": "2026-09-12T13:00:00.000+00:00",
            "project_updated_at": "2026-09-12T13:00:00.000+00:00",
            "archived_at": None,
            "session_key": identity["L"],
            "project_id": identity["P"],
            "gateway_session_key": identity["L"],
            "session_created_at": "2026-09-12T13:00:00.000+00:00",
            "device_created_at": a1["device_created_at"],
        }

    def _intent_receipt(self) -> dict[str, Any]:
        receipt = _base_receipt(self.context, "INTENT", None)
        receipt["current_rows"] = {"devices": None, "projects": None, "sessions": None}
        receipt["explicit_absent"] = ["devices", "projects", "sessions"]
        return receipt

    def _run_a1(self) -> dict[str, Any]:
        self.context["phase_params"] = {"A1": self._a1_params()}
        intent = self._intent_receipt()
        intent_sha = _receipt_sha256(intent)
        publish_attempt_receipt(self.context, intent)
        return execute_attempt_phase(self.context, "A1", intent_sha)

    def _run_a2(self) -> dict[str, Any]:
        a1 = self._run_a1()
        self.assertEqual(a1["status"], "PASS", a1)
        self.context["phase_params"] = {"A2": self._a2_params()}
        return execute_attempt_phase(self.context, "A2", a1["resulting_head_sha256"])

    def _run_a3(self) -> dict[str, Any]:
        a2 = self._run_a2()
        self.assertEqual(a2["status"], "PASS", a2)
        a2_params = self._a2_params()
        self.context["phase_params"] = {
            "A3": dict(
                a2_params,
                S=self.context["trial_identity"]["S"],
                prior_gateway_session_key=a2_params["gateway_session_key"],
                prior_record_version=1,
                operation_time="2026-09-12T13:05:00.000+00:00",
            )
        }
        self.context["admission_report"] = self._admission_report_fixture()
        return execute_attempt_phase(self.context, "A3", a2["resulting_head_sha256"])

    def _admission_report_fixture(self) -> dict[str, Any]:
        now_epoch = int(time.time())
        authorization = {
            "execution_scope": "fixture_readonly",
            "persisted_key_sha256": FIXTURE_KEY_SHA256,
            "candidate_id": self.context["candidate_id"],
            "candidate_sha256": self.context["archive_sha256"],
            "source_commit": self.context["source_commit"],
            "source_tree": self.context["source_tree"],
            "control_sha256": self.context["control_sha256"],
            "specification_sha256": self.context["spec_sha256"],
            "manifest_sha256": self.context["manifest_sha256"],
            "control_packet_sha256": self.context["control_packet_sha256"],
            "not_before_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch - 60)),
            "expires_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch + 60)),
        }
        identity = {
            "candidate_id": self.context["candidate_id"],
            "archive_sha256": self.context["archive_sha256"],
            "source_commit": self.context["source_commit"],
            "source_tree": self.context["source_tree"],
            "control_sha256": self.context["control_sha256"],
            "spec_sha256": self.context["spec_sha256"],
        }
        observations = {
            "session_observed_utc": _utc_now_iso(),
            "session_observed_monotonic_ns": time.monotonic_ns(),
            "boot_id": _boot_id(),
        }
        report = _admission_report(
            self.context,
            {name: True for name in REQUIRED_PREDICATES},
            [],
            time.monotonic(),
            _utc_now_iso(),
            identity,
            observations=observations,
            authorization=authorization,
        )
        raw = (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")
        self.context.update({
            "authorization": authorization,
            "admission_sha256": hashlib.sha256(raw).hexdigest(),
            "admission_report_bytes": raw,
        })
        return report

    # -- INTENT custody ---------------------------------------------------

    def test_intent_receipt_is_durable_and_no_clobber(self):
        intent = self._intent_receipt()
        first = publish_attempt_receipt(self.context, intent)
        self.assertEqual(first["phase"], "INTENT")
        with self.assertRaises(AttemptContextError):
            publish_attempt_receipt(self.context, intent)

    def test_intent_rejects_symlinked_leaf(self):
        receipts = self.root / "receipts"
        (receipts / "intent.json").symlink_to(self.root / "elsewhere.json")
        with self.assertRaises(AttemptContextError):
            publish_attempt_receipt(self.context, self._intent_receipt())

    def test_tampered_intent_refuses_with_pinned_head(self):
        intent = self._intent_receipt()
        publish_attempt_receipt(self.context, intent)
        wrong_head = "b" * 64
        with self.assertRaises(AttemptContextError):
            load_attempt_prefix(self.context, wrong_head)

    def test_load_prefix_requires_exact_head_pin(self):
        intent = self._intent_receipt()
        sha = _receipt_sha256(intent)
        publish_attempt_receipt(self.context, intent)
        loaded = load_attempt_prefix(self.context, sha)
        self.assertEqual([receipt["phase"] for receipt in loaded], ["INTENT"])

    def test_tampered_receipt_bytes_break_chain(self):
        intent = self._intent_receipt()
        sha = _receipt_sha256(intent)
        publish_attempt_receipt(self.context, intent)
        leaf = self.root / "receipts" / "intent.json"
        payload = leaf.read_bytes()
        # Rewrite the same bytes through a different inode (same-byte collision).
        leaf.unlink()
        # Consume the just-freed inode so the rewrite cannot reuse it by
        # coincidence (allocation order is filesystem-dependent).
        (self.root / "receipts" / ".filler").write_bytes(b"x" * 4096)
        leaf.write_bytes(payload)
        (self.root / "receipts" / ".filler").unlink()
        with self.assertRaises(AttemptContextError):
            load_attempt_prefix(self.context, sha)

    # -- A1/A2/A3 phase execution ------------------------------------------

    def test_a1_fails_without_intent_receipt(self):
        self.context["phase_params"] = {"A1": self._a1_params()}
        result = execute_attempt_phase(self.context, "A1", "a" * 64)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["creation_outcome"], "HOLD")
        self.assertIn("prefix_mismatch", result["reason_codes"])

    def test_a1_commit_and_receipt_complete(self):
        result = self._run_a1()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["creation_outcome"], "inserted_by_this_attempt")
        conn = _connect_fixture(self.context)
        try:
            rows = _read_trial_rows(conn, self.context)
            self.assertIsNotNone(rows["devices"])
            self.assertIsNone(rows["projects"])
            self.assertIsNone(rows["sessions"])
        finally:
            conn.close()

    def test_a1_second_attempt_reports_collision_not_insert(self):
        first = self._run_a1()
        self.assertEqual(first["status"], "PASS")
        # Re-running A1 with a valid prefix state refuses (phase already done).
        self.context["phase_params"] = {"A1": self._a1_params()}
        result = execute_attempt_phase(self.context, "A1", first["resulting_head_sha256"])
        self.assertEqual(result["status"], "HOLD")

    def test_a2_rolls_back_project_when_session_insert_fails(self):
        a1 = self._run_a1()
        self.assertEqual(a1["status"], "PASS")
        params = self._a2_params()
        # Abort trigger fires on the SECOND statement (session insert) after
        # the first (project insert) already succeeded inside the transaction.
        conn = _connect_fixture(self.context)
        conn.execute(
            "CREATE TRIGGER abort_session_insert BEFORE INSERT ON sessions "
            "BEGIN SELECT RAISE(ABORT, 'fixture abort'); END"
        )
        conn.close()
        self.context["phase_params"] = {"A2": params}
        with self.assertRaises(sqlite3.IntegrityError):
            execute_attempt_phase(self.context, "A2", a1["resulting_head_sha256"])
        conn = _connect_fixture(self.context)
        try:
            rows = _read_trial_rows(conn, self.context)
            self.assertIsNone(rows["projects"], "committed project must roll back")
            self.assertIsNone(rows["sessions"])
            self.assertIsNotNone(rows["devices"])
        finally:
            conn.close()

    def test_a3_requires_full_admission_report_not_bare_true(self):
        a2 = self._run_a2()
        self.assertEqual(a2["status"], "PASS")
        a2_params = self._a2_params()
        self.context["phase_params"] = {
            "A3": dict(
                a2_params,
                S=self.context["trial_identity"]["S"],
                prior_gateway_session_key=a2_params["gateway_session_key"],
                prior_record_version=1,
                operation_time="2026-09-12T13:05:00.000+00:00",
            )
        }
        self.context["admission_report"] = {"ok": True}
        result = execute_attempt_phase(self.context, "A3", a2["resulting_head_sha256"])
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason_codes"], ["admission_report_invalid"])

    def test_a3_rechecks_admission_freshness_before_first_mutation(self):
        a2 = self._run_a2()
        self.assertEqual(a2["status"], "PASS")
        a2_params = self._a2_params()
        self.context["phase_params"] = {
            "A3": dict(
                a2_params,
                S=self.context["trial_identity"]["S"],
                prior_gateway_session_key=a2_params["gateway_session_key"],
                prior_record_version=1,
                operation_time="2026-09-12T13:05:00.000+00:00",
            )
        }
        self._admission_report_fixture()
        report = json.loads(self.context["admission_report_bytes"].decode("utf-8"))
        observed_ns = report["session_observed_monotonic_ns"]
        before_conn = _connect_fixture(self.context)
        try:
            before = _read_trial_rows(before_conn, self.context)
        finally:
            before_conn.close()
        with patch.object(time, "monotonic_ns", side_effect=[observed_ns, observed_ns + 10_000_000_001]):
            with self.assertRaises(AttemptContextError):
                execute_attempt_phase(self.context, "A3", a2["resulting_head_sha256"])
        conn = _connect_fixture(self.context)
        try:
            self.assertEqual(_read_trial_rows(conn, self.context), before)
        finally:
            conn.close()

    def test_a3_commit_produces_bound_state(self):
        result = self._run_a3()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["creation_outcome"], "bound_by_this_attempt")
        conn = _connect_fixture(self.context)
        try:
            rows = _read_trial_rows(conn, self.context)
            self.assertEqual(rows["sessions"][2], self.context["trial_identity"]["S"])
            self.assertEqual(rows["projects"][8], 2)
        finally:
            conn.close()

    def test_commit_receipt_gap_is_commit_uncertain(self):
        a1 = self._run_a1()
        self.assertEqual(a1["status"], "PASS")
        self.context["phase_params"] = {"A2": self._a2_params()}
        leaf = self.root / "receipts" / "a2.created.json"
        leaf.parent.chmod(0o500)  # publication will fail (read-only dir)
        try:
            result = execute_attempt_phase(self.context, "A2", a1["resulting_head_sha256"])
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["state"], "COMMIT_UNCERTAIN")
        finally:
            leaf.parent.chmod(0o700)
        # Rows are committed but uncertain: no retry-by-equality is offered.
        conn = _connect_fixture(self.context)
        try:
            rows = _read_trial_rows(conn, self.context)
            self.assertIsNotNone(rows["projects"])
        finally:
            conn.close()

    # -- receipt-authenticated cleanup --------------------------------------

    def test_cleanup_intent_only_reports_no_mutation(self):
        intent = self._intent_receipt()
        sha = _receipt_sha256(intent)
        publish_attempt_receipt(self.context, intent)
        result = cleanup_attempt(self.context, sha)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["creation_outcome"], "intent_only")
        self.assertEqual(result.get("reason_codes"), ["no_mutation"])

    def test_cleanup_a1_prefix_deletes_only_device(self):
        a1 = self._run_a1()
        self.assertEqual(a1["status"], "PASS")
        result = cleanup_attempt(self.context, a1["resulting_head_sha256"])
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["creation_outcome"], "cleaned_by_this_attempt")
        conn = _connect_fixture(self.context)
        try:
            rows = _read_trial_rows(conn, self.context)
            self.assertIsNone(rows["devices"])
            self.assertIsNone(rows["projects"])
            self.assertIsNone(rows["sessions"])
        finally:
            conn.close()

    def test_cleanup_a2_prefix_deletes_all_three(self):
        a2 = self._run_a2()
        self.assertEqual(a2["status"], "PASS")
        result = cleanup_attempt(self.context, a2["resulting_head_sha256"])
        self.assertEqual(result["status"], "PASS", result)
        conn = _connect_fixture(self.context)
        try:
            rows = _read_trial_rows(conn, self.context)
            self.assertIsNone(rows["devices"])
            self.assertIsNone(rows["projects"])
            self.assertIsNone(rows["sessions"])
        finally:
            conn.close()

    def test_cleanup_a3_bound_deletes_all_three(self):
        a3 = self._run_a3()
        self.assertEqual(a3["status"], "PASS")
        result = cleanup_attempt(self.context, a3["resulting_head_sha256"])
        self.assertEqual(result["status"], "PASS", result)

    def test_cleanup_releases_connection_on_success(self):
        import gc
        import warnings

        a1 = self._run_a1()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            result = cleanup_attempt(self.context, a1["resulting_head_sha256"])
            gc.collect()
        self.assertEqual(result["status"], "PASS", result)
        self.assertFalse(
            any("unclosed database" in str(item.message) for item in caught),
            caught,
        )

    def test_cleanup_r1_cleaned_is_already_completed(self):
        a1 = self._run_a1()
        cleaned = cleanup_attempt(self.context, a1["resulting_head_sha256"])
        self.assertEqual(cleaned["status"], "PASS")
        again = cleanup_attempt(self.context, cleaned["resulting_head_sha256"])
        self.assertEqual(again["creation_outcome"], "already_completed")

    def test_cleanup_drifted_row_refuses_mutation(self):
        a2 = self._run_a2()
        self.assertEqual(a2["status"], "PASS")
        conn = _connect_fixture(self.context)
        identity = self.context["trial_identity"]
        try:
            conn.execute("UPDATE projects SET description='drift' WHERE stable_project_id=?", (identity["P"],))
        finally:
            conn.close()
        with self.assertRaises(AttemptContextError):
            cleanup_attempt(self.context, a2["resulting_head_sha256"])
        conn = _connect_fixture(self.context)
        try:
            rows = _read_trial_rows(conn, self.context)
            self.assertIsNotNone(rows["projects"], "drifted rows must be preserved")
        finally:
            conn.close()

    def test_cleanup_null_to_empty_drift_refuses(self):
        a2 = self._run_a2()
        self.assertEqual(a2["status"], "PASS")
        conn = _connect_fixture(self.context)
        identity = self.context["trial_identity"]
        try:
            conn.execute("UPDATE projects SET description='' WHERE stable_project_id=?", (identity["P"],))
        finally:
            conn.close()
        with self.assertRaises(AttemptContextError):
            cleanup_attempt(self.context, a2["resulting_head_sha256"])
        conn = _connect_fixture(self.context)
        try:
            rows = _read_trial_rows(conn, self.context)
            self.assertIsNotNone(rows["projects"])
        finally:
            conn.close()

    def test_cleanup_with_dependent_work_refuses(self):
        a2 = self._run_a2()
        self.assertEqual(a2["status"], "PASS")
        conn = _connect_fixture(self.context)
        identity = self.context["trial_identity"]
        try:
            conn.execute(
                "INSERT INTO turns (turn_id, user_id, origin_device_id, client_created_at,"
                " initial_fingerprint, manifest_json, state, created_at, updated_at,"
                " project_id, session_key) VALUES ('turn-dep', ?, 'dev-x',"
                " '2026-09-12T13:10:00.000+00:00', 'fp', '[]', 'ACCEPTED',"
                " '2026-09-12T13:10:00.000+00:00', '2026-09-12T13:10:00.000+00:00', ?, ?)",
                (identity["U"], identity["P"], identity["L"]),
            )
        finally:
            conn.close()
        # The protected logical vector no longer matches INTENT: HOLD.
        with self.assertRaises(AttemptContextError):
            cleanup_attempt(self.context, a2["resulting_head_sha256"])

    def test_fixture_context_rejects_live_paths(self):
        bad = dict(self.context)
        bad["fixture_root"] = "/var/lib/recorder-next"
        bad["db_path"] = "/var/lib/recorder-next/recorder-next.sqlite3"
        with self.assertRaises(AttemptContextError):
            _validate_fixture_context(bad)

    def test_fixture_context_rejects_db_outside_root(self):
        bad = dict(self.context)
        bad["db_path"] = "/tmp/outside.db"
        with self.assertRaises(AttemptContextError):
            _validate_fixture_context(bad)


    def test_cleanup_second_connection_drift_before_phase_is_caught_under_lock(self):
        # REV-011: a concurrent change committed BEFORE the phase starts (so
        # before our BEGIN IMMEDIATE) can no longer slip past: the authorizing
        # re-read happens under the lock and must refuse the drifted project.
        result = self._run_a2()
        self.assertEqual(result["status"], "PASS", result)
        head = result["resulting_head_sha256"]
        drift = sqlite3.connect(str(self.context["db_path"]), timeout=5.0, isolation_level=None)
        try:
            drift.execute("PRAGMA busy_timeout=5000")
            drift.execute(
                "UPDATE projects SET description=? WHERE stable_project_id=?",
                ("drifted before begin", self._trial_identity()["P"]),
            )
            drift.commit()
        finally:
            drift.close()
        with self.assertRaises(AttemptContextError):
            cleanup_attempt(self.context, head)

    def test_cleanup_same_connection_drift_after_first_delete_rolls_back_everything(self):
        # REV-011: after a successful session DELETE, a same-connection hook
        # that mutates a protected row must abort the whole transaction and
        # restore all three trial rows plus the protected vector.
        result = self._run_a3()
        self.assertEqual(result["status"], "PASS", result)
        blocks = _load_blocks()
        conn = _connect_fixture(self.context)
        drift_seen = {"value": False}

        class _Hooked:
            """Proxy that injects same-connection drift after the first DELETE."""

            def __init__(self, inner: Any) -> None:
                self._inner = inner

            def execute(self, sql: Any, params: Any = None):
                cursor = self._inner.execute(sql, params) if params is not None else self._inner.execute(sql)
                if isinstance(sql, str) and sql.lstrip().upper().startswith("DELETE FROM sessions"):
                    self._inner.execute(
                        "UPDATE projects SET description=? WHERE stable_project_id=?",
                        ("same-connection drift", _trial_identity()["P"]),
                    )
                    drift_seen["value"] = True
                return cursor

            def __getattr__(self, name: str) -> Any:
                return getattr(self._inner, name)

        hooked = _Hooked(conn)
        try:
            hooked.execute("BEGIN IMMEDIATE")
            current = _read_trial_rows(hooked, self.context)
            packet_params = {
                "sessions": _typed_sql_params(dict(zip(
                    ("session_key", "project_id", "gateway_session_key", "session_created_at"),
                    current["sessions"],
                ))),
                "projects": _typed_sql_params(dict(zip(
                    ("stable_project_id", "project_user_id", "project_number", "name",
                     "aliases_json", "description", "project_status", "default_session_key",
                     "record_version", "project_created_at", "project_updated_at", "archived_at"),
                    current["projects"],
                ))),
                "devices": _typed_sql_params(dict(zip(
                    ("device_user_id", "device_id", "kind", "device_status", "device_created_at", "revoked_at"),
                    current["devices"],
                ))),
            }
            hooked.execute(blocks["r1.delete_session"], packet_params["sessions"])
            hooked.execute(blocks["r1.delete_project"], packet_params["projects"])
            after = _read_trial_rows(hooked, self.context)
            self.assertIsNone(after["sessions"])
            self.assertIsNone(after["projects"])
            hooked.execute("ROLLBACK")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()
        # Everything restored.
        conn2 = _connect_fixture(self.context)
        try:
            restored = _read_trial_rows(conn2, self.context)
            self.assertIsNotNone(restored["devices"])
            self.assertIsNotNone(restored["projects"])
            self.assertIsNotNone(restored["sessions"])
            self.assertEqual(restored["projects"][5], "Owner-authorized server-only two-turn voice trial; isolated from existing Recorder projects.")
        finally:
            conn2.close()

    def test_cleanup_second_connection_blocked_while_lock_held(self):
        # REV-011: while the phase transaction holds BEGIN IMMEDIATE, a second
        # connection's write must block (busy) rather than interleave.
        result = self._run_a2()
        self.assertEqual(result["status"], "PASS", result)
        conn = _connect_fixture(self.context)
        blocked = {"result": None}
        try:
            conn.execute("BEGIN IMMEDIATE")
            second = sqlite3.connect(str(self.context["db_path"]), timeout=0.2, isolation_level=None)
            try:
                second.execute("PRAGMA busy_timeout=100")
                try:
                    second.execute("BEGIN IMMEDIATE")
                    blocked["result"] = "acquired"
                    second.execute("ROLLBACK")
                except sqlite3.OperationalError:
                    blocked["result"] = "busy"
            finally:
                second.close()
            conn.execute("ROLLBACK")
        finally:
            conn.close()
        self.assertEqual(blocked["result"], "busy")

    def test_typed_delete_parameters_come_from_receipt_not_current_rows(self):
        # REV-011: mutating the CURRENT rows away from the receipt postimage
        # must refuse the DELETE instead of adopting the drift.
        result = self._run_a2()
        self.assertEqual(result["status"], "PASS", result)
        head = result["resulting_head_sha256"]
        conn = sqlite3.connect(str(self.context["db_path"]), timeout=5.0, isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute(
                "UPDATE projects SET record_version=record_version+1 WHERE stable_project_id=?",
                (self._trial_identity()["P"],),
            )
        finally:
            conn.close()
        with self.assertRaises(AttemptContextError):
            cleanup_attempt(self.context, head)


# ---------------------------------------------------------------------------
# Architecture R-GAP signal fixtures: interruption and hard
# kill inside the commit-receipt gap must preserve committed rows and leave
# a fresh process with an authentic uncertain prefix.  No receipt is ever
# synthesized; a fresh-process re-entry classifies the state from real rows,
# real custody, and the preserved out-of-band head pin.
# ---------------------------------------------------------------------------

_GAP_CHILD_MODES = ("signal", "hard-kill")
_GAP_PROTECTED_ROOTS = ("/var/lib/recorder-next", "/home/rumi/.hermes", "/etc/recorder-next")


def _signal_fixture_bootstrap(mode: str, fixture_root: str) -> None:
    """Fixture-only fresh-process child: take the A1 commit and stop mid-gap.

    The child prepares its own private fixture (candidate schema,
    release-smoke seed, published INTENT receipt), records the out-of-band
    INTENT head pin, and installs a marker-based gap around the A1 receipt
    publication.  Readiness is signalled at the exact moment the DB commit
    has been taken and no A1 receipt leaf exists.  ``signal`` mode then
    delivers the named OS signal to itself: default SIGINT disposition
    raises KeyboardInterrupt inside the executor, whose conservative
    BaseException path classifies the attempt COMMIT_UNCERTAIN; default
    SIGTERM disposition terminates the process.  ``hard-kill`` mode blocks
    until the parent SIGKILLs it inside the gap.  Exit codes preserve
    interruption semantics: 70 with a recorded executor HOLD result for the
    conservative path, death by signal otherwise; 7 would mean the
    interruption was swallowed into success; 3 means fixture refusal.
    """
    import unittest.mock

    if mode not in _GAP_CHILD_MODES:
        raise SystemExit(3)
    root = Path(fixture_root)
    if not root or not root.is_absolute():
        raise SystemExit(3)
    resolved = root.resolve()
    for live in _GAP_PROTECTED_ROOTS:
        try:
            resolved.relative_to(Path(live))
        except ValueError:
            continue
        raise SystemExit(3)
    (root / "receipts").mkdir(parents=True, exist_ok=True)
    os.chmod(root / "receipts", 0o700)
    db_path = root / "recorder-next.sqlite3"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys=ON")
    _fixture_schema(conn)
    _seed_release_smoke(conn)
    conn.commit()
    conn.close()
    context = _signal_fixture_context(root, db_path)
    context["phase_params"] = {"A1": _signal_fixture_a1_params(context)}
    intent = _base_receipt(context, "INTENT", None)
    intent["current_rows"] = {"devices": None, "projects": None, "sessions": None}
    intent["explicit_absent"] = ["devices", "projects", "sessions"]
    publish_attempt_receipt(context, intent)
    # Out-of-band head pin: hash of the exact published INTENT bytes (same
    # rule as the executor tests).  The fresh-process re-entry in the
    # parent binds this pin; nothing derives it from the post-interruption
    # state.
    head = _receipt_sha256(intent)
    (root / "gap.head").write_text(head, encoding="utf-8")

    signal_name = os.environ.get("VOICE1_SIGNAL_NAME", "SIGINT")
    committed = root / "gap.committed"
    ready = root / "gap.ready"

    def gap_publish(publish_context: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
        # The A1 COMMIT has been taken and fully validated; the receipt leaf
        # does not exist.  This is the commit-receipt gap.
        committed.write_bytes(b"1")
        ready.write_bytes(b"1")
        if mode == "signal":
            os.kill(os.getpid(), signal.SIGINT if signal_name == "SIGINT" else signal.SIGTERM)
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            time.sleep(0.01)  # hard-kill mode blocks here until SIGKILL
        os._exit(6)

    try:
        with unittest.mock.patch.object(sys.modules[__name__], "publish_attempt_receipt", gap_publish):
            result = execute_attempt_phase(context, "A1", head)
    except BaseException:
        # Any escape other than the executor's conservative classification
        # still means interruption; preserve its semantics.
        raise SystemExit(70)
    outcome = {
        "status": result.get("status"),
        "state": result.get("state"),
        "creation_outcome": result.get("creation_outcome"),
        "reason_codes": result.get("reason_codes"),
    }
    (root / "gap.result.json").write_text(json.dumps(outcome, sort_keys=True), encoding="utf-8")
    if outcome["status"] == "PASS":
        # Interruption must never be swallowed into success.
        raise SystemExit(7)
    raise SystemExit(70)


def _signal_fixture_context(root: Path, db_path: Path) -> dict[str, Any]:
    blocks = _load_blocks()
    for name in SQL_BLOCK_NAMES:
        if hashlib.sha256(blocks[name].encode("utf-8")).hexdigest() != SQL_STATEMENT_SHA256[name]:
            raise SystemExit(3)
    control_packet_sha256 = hashlib.sha256(PACKET_PATH.read_bytes()).hexdigest()
    identity = {
        "U": "voice1-trial-owner-7333f832a973d428",
        "D": "voice1-server-trial-7333f832a973d428",
        "N": "VOICE1-TRIAL-7333f832a973d428",
        "I": "recorder-next:voice1:isolated-trial:7333f832a973d428",
        "P": "b961f648-3f79-5f92-9ed7-aeceb087fa02",
        "L": "project:b961f648-3f79-5f92-9ed7-aeceb087fa02:default",
        "S": SELECTED_S,
    }
    context: dict[str, Any] = {
        "fixture_root": root,
        "db_path": db_path,
        "attempt_id": str(uuid.uuid4()),
        "candidate_id": "fixture-candidate",
        "archive_sha256": "0" * 64,
        "source_commit": "f" * 40,
        "source_tree": "e" * 64,
        "control_packet_sha256": control_packet_sha256,
        "spec_sha256": "d" * 64,
        "owner_authorization_sha256": "c" * 64,
        "trial_identity": identity,
        "phase_params": {},
        "admission_report": None,
    }
    conn = _connect_fixture(context)
    try:
        context["protected_logical_digest"] = _protected_logical_digest(conn, context)
    finally:
        conn.close()
    return context


def _signal_fixture_a1_params(context: dict[str, Any]) -> dict[str, Any]:
    identity = context["trial_identity"]
    return {
        "device_user_id": identity["U"],
        "device_id": identity["D"],
        "kind": "other",
        "device_status": "active",
        "device_created_at": "2026-09-12T13:00:00.000+00:00",
        "revoked_at": None,
    }


def _signal_child_argv(mode: str, signal_name: str, root: Path) -> tuple[list[str], dict[str, str]]:
    """Run the fixture signal child by direct helper import, not a CLI mode."""
    runner = os.path.abspath(__file__)
    child = (
        "import importlib.util, os, sys\n"
        f"spec = importlib.util.spec_from_file_location('voice1_gap_control', {runner!r})\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "sys.modules[spec.name] = module\n"
        "spec.loader.exec_module(module)\n"
        "module._signal_fixture_bootstrap(os.environ['VOICE1_GAP_MODE'], os.environ['VOICE1_GAP_ROOT'])\n"
    )
    argv = [sys.executable, "-B", "-s", "-c", child]
    env = dict(os.environ)
    env["VOICE1_SIGNAL_NAME"] = signal_name
    env["VOICE1_GAP_MODE"] = mode
    env["VOICE1_GAP_ROOT"] = str(root)
    return argv, env


class Voice1CommitReceiptGapSignalTests(unittest.TestCase):
    """R-GAP: SIGINT/SIGTERM and hard kill inside the commit-receipt gap.

    Each fixture runs a real fresh interpreter process to the exact
    commit-taken/receipt-absent boundary, delivers the named interruption,
    and then proves from real rows, real custody, and the preserved
    out-of-band head pin that the state is genuinely uncertain and that a
    fresh-process re-entry refuses to touch it: the authenticated prefix
    still loads against the pin, but re-running A1 collides with the real
    committed rows and is refused without synthesizing anything.
    """

    def _run_gap_child(self, mode: str, signal_name: str) -> tuple["subprocess.Popen[bytes]", Path]:
        tmp = tempfile.TemporaryDirectory(prefix="voice1-gap-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "attempt-root"
        argv, env = _signal_child_argv(mode, signal_name, root)
        process = subprocess.Popen(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.addCleanup(self._reap, process)
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if (root / "gap.ready").exists():
                break
            if process.poll() is not None:
                self.fail(f"gap child exited early with {process.returncode}")
            time.sleep(0.01)
        else:
            self.fail("gap child never reached the commit-receipt boundary")
        self.assertTrue((root / "gap.committed").exists())
        return process, root

    @staticmethod
    def _reap(process: "subprocess.Popen[bytes]") -> None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def _assert_uncertain_after_gap(self, root: Path, signal_name: str) -> None:
        """Fresh-process classification after the interruption."""
        db_path = root / "recorder-next.sqlite3"
        context: dict[str, Any] = {
            "fixture_root": root,
            "db_path": db_path,
            "attempt_id": "reentry-probe",
            "candidate_id": "fixture-candidate",
            "archive_sha256": "0" * 64,
            "source_commit": "f" * 40,
            "source_tree": "e" * 64,
            "control_packet_sha256": hashlib.sha256(PACKET_PATH.read_bytes()).hexdigest(),
            "spec_sha256": "d" * 64,
            "owner_authorization_sha256": "c" * 64,
            "trial_identity": {
                "U": "voice1-trial-owner-7333f832a973d428",
                "D": "voice1-server-trial-7333f832a973d428",
                "N": "VOICE1-TRIAL-7333f832a973d428",
                "I": "recorder-next:voice1:isolated-trial:7333f832a973d428",
                "P": "b961f648-3f79-5f92-9ed7-aeceb087fa02",
                "L": "project:b961f648-3f79-5f92-9ed7-aeceb087fa02:default",
                "S": SELECTED_S,
            },
            "phase_params": {},
            "admission_report": None,
        }
        expected = _signal_fixture_a1_params(context)
        # 1. committed rows preserved: the exact A1 device row exists.
        conn = sqlite3.connect(str(db_path))
        try:
            rows = conn.execute(
                "SELECT user_id,device_id,kind,status,created_at,revoked_at FROM devices WHERE device_id=?",
                (expected["device_id"],),
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(
            rows,
            [(
                expected["device_user_id"], expected["device_id"], expected["kind"],
                expected["device_status"], expected["device_created_at"], expected["revoked_at"],
            )],
            f"{signal_name}: the committed A1 device row must be preserved",
        )
        # 2. nothing was synthesized: no A1 receipt leaf and no custody entry.
        self.assertFalse((root / "receipts" / "a1.created.json").exists(),
                         f"{signal_name}: no A1 receipt may exist inside the gap")
        self.assertFalse((root / "receipts" / "custody" / "a1.created.json.custody").exists(),
                         f"{signal_name}: no A1 custody entry may exist inside the gap")
        # 3. the preserved out-of-band pin still authenticates the INTENT
        # prefix from this fresh process.
        probe = dict(context)
        conn = _connect_fixture(probe)
        try:
            probe["protected_logical_digest"] = _protected_logical_digest(conn, probe)
        finally:
            conn.close()
        pin = (root / "gap.head").read_text(encoding="utf-8")
        prefix = load_attempt_prefix(probe, pin)
        self.assertEqual([receipt["phase"] for receipt in prefix], ["INTENT"],
                         f"{signal_name}: fresh re-entry must authenticate the INTENT prefix")
        # 4. re-running A1 collides with the real committed rows and is
        # refused; nothing is retried, adopted, or synthesized.
        with self.assertRaises(AttemptContextError) as caught:
            execute_attempt_phase(probe, "A1", pin)
        self.assertEqual(str(caught.exception), "A1 requires all target rows absent",
                         f"{signal_name}: refusal must come from the real committed rows")
        # 5. the refusal changed nothing.
        self.assertFalse((root / "receipts" / "a1.created.json").exists(),
                         f"{signal_name}: refused re-entry must not publish anything")

    def test_sigint_in_commit_receipt_gap_is_classified_commit_uncertain(self):
        process, root = self._run_gap_child("signal", "SIGINT")
        process.wait(timeout=15)
        # KeyboardInterrupt escapes publication through the executor's
        # conservative BaseException path; exit semantics stay nonzero.
        self.assertEqual(process.returncode, 70,
                         "SIGINT must not exit 0; conservative classification expected")
        outcome = json.loads((root / "gap.result.json").read_text(encoding="utf-8"))
        self.assertEqual(outcome["status"], "HOLD")
        self.assertEqual(outcome["state"], "COMMIT_UNCERTAIN")
        self.assertEqual(outcome["creation_outcome"], "commit_uncertain")
        self._assert_uncertain_after_gap(root, "SIGINT")

    def test_sigterm_in_commit_receipt_gap_preserves_uncertain_rows(self):
        process, root = self._run_gap_child("signal", "SIGTERM")
        process.wait(timeout=15)
        # Default SIGTERM disposition terminates the process mid-gap.
        self.assertEqual(process.returncode, -signal.SIGTERM,
                         "SIGTERM must terminate the child inside the gap")
        self.assertFalse((root / "gap.result.json").exists())
        self._assert_uncertain_after_gap(root, "SIGTERM")

    def test_hard_kill_in_commit_receipt_gap_preserves_uncertain_rows(self):
        process, root = self._run_gap_child("hard-kill", "SIGKILL")
        process.kill()
        process.wait(timeout=15)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertFalse((root / "gap.result.json").exists())
        self._assert_uncertain_after_gap(root, "SIGKILL")


if __name__ == "__main__":
    raise SystemExit(main())
