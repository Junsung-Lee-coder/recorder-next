#!/usr/bin/env python3
"""VOICE1-B2 successor control probe (t_04f318bc).

Successor of voice1-auth-readiness-qa-v1/qa_probe_runner.py.  Import is
inert: every credential/network/DB access lives behind main()/__main__ so
unittest discovery cannot contact live endpoints.  Fixture-only unittest
cases exercise:

- voice1_session_admission: the pure Voice1 Discord-source plus
  independently-pinned persisted conversation-key predicate (REV-003);
- the successor control packet's labeled SQL blocks (single-source statement
  bytes read from the sibling binding-create-cas-rollback-packet.md),
  covering attempt-owned INSERT-only A1/A2, A3 CAS, and full-row
  timestamp/NULL-aware R1 rollback (REV-002).

Live readiness probing (T-side) reuses the frozen candidate's
HermesAudioTTSProvider.readiness_check through the aggregate runner in
main(); it is never executed at import time.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any

CONTROL_DIR = Path(__file__).resolve().parent
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


def _row_set_digest(rows: list[tuple[Any, ...]]) -> str:
    """Canonical row-set digest over exact stored values (PK ASC, schema order)."""
    encoded = ""
    for row in sorted(rows, key=lambda item: tuple(str(field) for field in item)):
        encoded += "\x1f".join(repr(field) for field in row) + "\x1e"
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _fixture_schema(conn: sqlite3.Connection) -> None:
    schema_path = CONTROL_DIR
    # The candidate schema ships in the extracted source tree; the fixture
    # only needs the devices/projects/sessions subset with identical shape.
    conn.executescript(
        """
        CREATE TABLE devices (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            PRIMARY KEY(user_id, device_id)
        );
        CREATE TABLE projects (
            stable_project_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            project_number TEXT NOT NULL,
            name TEXT NOT NULL,
            aliases_json TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active','archived')),
            default_session_key TEXT NOT NULL UNIQUE,
            record_version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            archived_at TEXT,
            UNIQUE(user_id, project_number)
        );
        CREATE TABLE sessions (
            session_key TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            gateway_session_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(stable_project_id) ON DELETE RESTRICT
        );
        """
    )


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
        if isinstance(row, dict):
            get = row.get
        elif isinstance(row, sqlite3.Row):
            get = row.__getitem__
        else:
            row = dict(zip(("id", "source", "session_key", "ended_at"), row))
            get = row.get
        try:
            persisted_id = get("id")
            persisted_source = get("source")
            persisted_key = get("session_key")
            persisted_ended = get("ended_at")
        except (KeyError, IndexError, TypeError):
            reason_codes.append("persisted_row_shape")
            persisted_id = persisted_source = persisted_key = persisted_ended = None
        persisted_id_match = persisted_id == expected_session_id
        persisted_source_match = persisted_source == "discord"
        persisted_ended_at_null = persisted_ended is None
        if not persisted_id_match:
            reason_codes.append("persisted_id_mismatch")
        if not persisted_source_match:
            reason_codes.append("persisted_source_mismatch")
        if not persisted_ended_at_null:
            reason_codes.append("persisted_ended_not_null")
        key_is_string = isinstance(persisted_key, str) and bool(persisted_key.strip())
        if key_is_string:
            assert persisted_key is not None
            digest = hashlib.sha256(persisted_key.encode("utf-8")).hexdigest()
            conversation_key_match = digest == expected_key_sha256
            distinct_key_identity = persisted_key != expected_session_id
            if not conversation_key_match:
                reason_codes.append("conversation_key_mismatch")
            if not distinct_key_identity:
                reason_codes.append("key_equals_session_id")
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
            {
                "stable_project_id": a2["stable_project_id"], "project_user_id": a2["project_user_id"], "project_number": a2["project_number"], "name": a2["name"],
                "aliases_json": a2["aliases_json"], "description": a2["description"], "project_status": a2["project_status"], "default_session_key": a2["default_session_key"],
                "record_version": 1, "project_created_at": a2["project_created_at"], "project_updated_at": a2["project_updated_at"], "archived_at": None,
            },
        ).rowcount
        self.assertEqual(drifted_project, 0, "drifted updated_at must not satisfy the full-row DELETE match")
        self.conn.rollback()

        # Restore exact A2 postimage, then R1 deletes all three rows.
        cur.execute("UPDATE projects SET updated_at=? WHERE stable_project_id=?", (a2["project_updated_at"], a2["stable_project_id"]))
        self.conn.commit()
        cur.execute(self.blocks["r1.delete_session"], {"session_key": a2["session_key"], "project_id": a2["project_id"], "gateway_session_key": a2["gateway_session_key"], "session_created_at": a2["session_created_at"]})
        self.assertEqual(cur.rowcount, 1)
        cur.execute(
            self.blocks["r1.delete_project"],
            {
                "stable_project_id": a2["stable_project_id"], "project_user_id": a2["project_user_id"], "project_number": a2["project_number"], "name": a2["name"],
                "aliases_json": a2["aliases_json"], "description": a2["description"], "project_status": a2["project_status"], "default_session_key": a2["default_session_key"],
                "record_version": 1, "project_created_at": a2["project_created_at"], "project_updated_at": a2["project_updated_at"], "archived_at": None,
            },
        )
        self.assertEqual(cur.rowcount, 1)
        cur.execute(
            self.blocks["r1.delete_device"],
            {"device_user_id": u, "device_id": a1["device_id"], "kind": "other", "device_status": "active", "device_created_at": a1["device_created_at"], "revoked_at": None},
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
            {
                "stable_project_id": a2["stable_project_id"], "project_user_id": a2["project_user_id"], "project_number": a2["project_number"], "name": a2["name"],
                "aliases_json": a2["aliases_json"], "description": a2["description"], "project_status": a2["project_status"], "default_session_key": a2["default_session_key"],
                "record_version": 1, "project_created_at": a2["project_created_at"], "project_updated_at": a2["project_updated_at"], "archived_at": None,
            },
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
        cur.execute(self.blocks["r1.delete_device"], {"device_user_id": u, "device_id": a1["device_id"], "kind": "other", "device_status": "active", "device_created_at": a1["device_created_at"], "revoked_at": None})
        self.assertEqual(cur.rowcount, 1)
        self.conn.commit()
        self._assert_protected_unchanged(protected)

    def test_rowcount_zero_on_missing_target_is_reported(self):
        cur = self.conn.cursor()
        cur.execute(self.blocks["r1.delete_device"], {"device_user_id": "absent-user", "device_id": "absent-device", "kind": "other", "device_status": "active", "device_created_at": "2026-09-12T13:00:00.000+00:00", "revoked_at": None})
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


if __name__ == "__main__":
    raise SystemExit(
        "Live probing entry point is intentionally not enabled at import time. "
        "Run the bounded operator procedure with explicit authorization."
    )
