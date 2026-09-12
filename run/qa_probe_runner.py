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
import time
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
    "r1.delete_session": "662008d0f798c032400ea8564efa6304a5aa1bf60049501c4759c40af0855387",
    "r1.delete_project": "825dc0f2d222274631cdafb10c8ea81bb2fd27d128dc882a3fa11b22abcae6a3",
    "r1.delete_device": "6df69fb7f0b9082a9d6ae757524639645d3cc1bc72b4a5267f465362b8532d91",
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

REPORT_SCHEMA = "recorder-next-voice1-readonly-admission/v1"
RECEIPT_SCHEMA = "recorder-next-voice1-trial-attempt/v1"
ADMISSION_TOTAL_BUDGET_SECONDS = 90.0
PROVIDER_TIMEOUT_SECONDS = 10.0
SESSION_BUDGET_SECONDS = 10.0
DASHBOARD_LIFETIME_FLOOR_SECONDS = 3900

B4_CALLER_NOTE = (
    "B4: run_voice1_readonly_admission(context)/main(argv) below implement the "
    "ratified executable owner-bound read-only admission caller (architecture "
    "section 5 S.2/S.3). Import stays inert: the caller runs only when main() "
    "is explicitly invoked. The fixture executor/custody/cleanup functions "
    "(architecture section 6 R.1-R.4) follow the aggregate and are "
    "fixture-only: they require a freshly-created private fixture root and "
    "reject live paths."
)

def _admission_report(context: dict[str, Any], predicates: dict[str, bool],
                      reason_codes: list[str], started_monotonic: float,
                      started_utc: str, identity: dict[str, Any]) -> dict[str, Any]:
    """Reduce one bounded predicate mapping into the fixed report schema."""
    missing = [name for name in REQUIRED_PREDICATES if name not in predicates]
    failed = [name for name in REQUIRED_PREDICATES
              if name in predicates and predicates.get(name) is not True]
    all_true = all(predicates.get(name) is True for name in REQUIRED_PREDICATES)
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
        "predicates": {name: predicates.get(name) for name in REQUIRED_PREDICATES},
        "missing_predicates": missing,
        "failed_predicates": failed,
        "reason_codes": sorted(set(reason_codes)),
        "expected_session_id_sha256": EXPECTED_S_SHA256,
        "expected_key_sha256": EXPECTED_KEY_SHA256,
    }
    if all_true:
        report["status"] = "PASS"
        report["status_code"] = 0
    else:
        report["status"] = "HOLD"
        report["status_code"] = 2
    return report


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hold_report(context: dict[str, Any], reason: str, started_monotonic: float,
                 started_utc: str, identity: dict[str, Any]) -> dict[str, Any]:
    report = _admission_report(context, {}, [reason], started_monotonic, started_utc, identity)
    return report


def _check_sha256_file(path: Path, expected: str) -> bool:
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    return hashlib.sha256(raw).hexdigest() == expected.lower()


def run_voice1_readonly_admission(context: dict[str, Any]) -> dict[str, Any]:
    """Executable owner-bound read-only Voice1 admission caller (S.2).

    ``context`` carries the manifest/authorization paths and digests, the
    candidate import root, and injectable boundary functions used by fixture
    tests (credential readers, HTTP boundary, DB opener).  The live caller
    supplies the real readers; the fixture lane never touches live endpoints,
    live DB paths, or credentials.  Returns the fixed report mapping; the
    caller (main) prints it.  No live default: a missing or failed boundary
    is a HOLD, never an exception escape or a silent pass.
    """
    started_monotonic = time.monotonic()
    started_utc = _utc_now_iso()
    identity = {
        "candidate_id": context.get("candidate_id"),
        "archive_sha256": context.get("archive_sha256"),
        "source_commit": context.get("source_commit"),
        "source_tree": context.get("source_tree"),
        "control_sha256": context.get("control_sha256"),
        "spec_sha256": context.get("spec_sha256"),
    }
    predicates: dict[str, bool] = {}
    reason_codes: list[str] = []

    def budget_remaining() -> float:
        return ADMISSION_TOTAL_BUDGET_SECONDS - (time.monotonic() - started_monotonic)

    def within_budget() -> bool:
        return budget_remaining() > 0.0

    # -- 0. authorization + candidate + control binding -------------------
    manifest = context.get("manifest") or {}
    authorization = context.get("authorization") or {}
    auth_ok = (
        isinstance(manifest, dict)
        and isinstance(authorization, dict)
        and manifest.get("candidate_id") == identity.get("candidate_id")
        and manifest.get("source_commit") == identity.get("source_commit")
        and manifest.get("source_tree") == identity.get("source_tree")
        and manifest.get("control_sha256") == identity.get("control_sha256")
        and manifest.get("spec_sha256") == identity.get("spec_sha256")
        and authorization.get("candidate_sha256") == manifest.get("archive_sha256")
        and authorization.get("selected_session_id_sha256") == EXPECTED_S_SHA256
        and authorization.get("persisted_key_sha256") == EXPECTED_KEY_SHA256
        and authorization.get("read_only") is True
        and authorization.get("approved_endpoints") == context.get("expected_endpoints")
    )
    predicates["authorization_bound"] = bool(auth_ok and within_budget())
    predicates["candidate_bound"] = bool(
        auth_ok and context.get("import_origin_ok") is True and within_budget()
    )
    predicates["imports_bound"] = bool(
        context.get("import_origin_ok") is True and context.get("per_file_hashes_ok") is True
    )
    predicates["credential_custody"] = bool(context.get("credential_custody_ok") is True)
    predicates["dashboard_credential_parse"] = bool(
        context.get("dashboard_credential_ok") is True
    )
    predicates["api_credential_parse"] = bool(context.get("api_credential_ok") is True)
    predicates["lifetime_pre"] = bool(
        isinstance(context.get("dashboard_remaining_seconds_pre"), int)
        and context["dashboard_remaining_seconds_pre"] >= DASHBOARD_LIFETIME_FLOOR_SECONDS
    )

    # -- 1. bounded unauthenticated dashboard gate (fixture-injectable) ----
    gate = context.get("unauthenticated_gate") or {}
    predicates["unauthenticated_gate"] = bool(
        gate.get("status") == 401 and gate.get("secret_in_body") is False
    )

    # -- 2. API capability + ASR/TTS readiness + omitted-profile equality --
    probes = context.get("probes") or {}
    capabilities = probes.get("api_capability") or {}
    predicates["api_capability"] = bool(capabilities.get("run_submission") is True)
    predicates["asr_ready"] = bool(probes.get("asr_ready") is True)
    predicates["tts_ready"] = bool(probes.get("tts_ready") is True)
    omitted = probes.get("omitted_profile") or {}
    explicit = probes.get("explicit_profile") or {}
    predicates["omitted_profile_equal"] = bool(
        omitted.get("target") != explicit.get("target")
        and omitted.get("reduction") is not None
        and omitted.get("reduction") == explicit.get("reduction")
    )
    predicates["omitted_profile_ready"] = bool(
        probes.get("tts_ready") is True and explicit.get("validated") is True
    )

    # -- 3. session preflight + GET under one shared 10 s budget -----------
    session = context.get("session") or {}
    predicates["generic_preflight"] = bool(session.get("preflight_ok") is True)
    predicates["session_get"] = bool(
        session.get("payload_object_match") is True
        and session.get("id_match") is True
    )
    predicates["session_budget"] = bool(
        isinstance(session.get("within_budget"), bool) and session["within_budget"]
    )

    # -- 4. read-only indexed persisted lookup -----------------------------
    persisted = context.get("persisted") or {}
    predicates["persisted_lookup_ro"] = bool(persisted.get("read_only_ok") is True)
    predicates["persisted_lookup_indexed"] = bool(persisted.get("indexed_ok") is True)

    # -- 5. pure predicate with owner pins ----------------------------------
    admission = voice1_session_admission(
        session.get("payload"),
        persisted.get("rows") or [],
        expected_session_id=context.get("expected_session_id", SELECTED_S),
        expected_key_sha256=EXPECTED_KEY_SHA256,
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

    # -- 6. closing vector ---------------------------------------------------
    predicates["lifetime_post"] = bool(
        isinstance(context.get("dashboard_remaining_seconds_post"), int)
        and context["dashboard_remaining_seconds_post"] >= DASHBOARD_LIFETIME_FLOOR_SECONDS
    )
    predicates["closing_identity_equal"] = bool(
        context.get("closing_identity_ok") is True and within_budget()
    )
    predicates["no_mutation"] = bool(context.get("no_mutation_ok") is True)
    predicates["secret_safe"] = bool(context.get("secret_safe_ok") is True)

    # Fixture lane: boundary observations may be injected directly (the live
    # caller passes no overrides; every predicate above reflects its real
    # boundary observation).  Overrides never mask the aggregate: a required
    # name still missing from the final mapping stays missing.
    overrides = context.get("predicate_overrides")
    if isinstance(overrides, dict):
        for name in REQUIRED_PREDICATES:
            if name not in overrides:
                continue
            value = overrides[name]
            if value is None:
                # A None override removes the predicate entirely so the
                # aggregate records it as missing (fixture-only semantics).
                predicates.pop(name, None)
            else:
                predicates[name] = value

    return _admission_report(context, predicates, reason_codes, started_monotonic, started_utc, identity)


def main(argv: list[str] | None = None) -> int:
    """CLI entry: strict opt-in read-only admission; no flags means HOLD/2."""
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
    if "--read-only-admission" not in args:
        report = _hold_report({}, "missing_required_flags", started_monotonic, started_utc, identity)
        print(json.dumps(report, sort_keys=True))
        return 2
    try:
        report = _main_read_only_admission(args, started_monotonic, started_utc, identity)
    except Exception:  # noqa: BLE001 - fixed internal error, never repr/traceback
        report = _hold_report({}, "internal_error", started_monotonic, started_utc, identity)
    print(json.dumps(report, sort_keys=True))
    return int(report.get("status_code", 2))


def _main_read_only_admission(args: list[str], started_monotonic: float,
                              started_utc: str, identity: dict[str, Any]) -> dict[str, Any]:
    """Bounded live lane: verify opening vector, then run the caller context."""
    def arg_value(flag: str) -> str | None:
        if flag not in args:
            return None
        index = args.index(flag)
        if index + 1 >= len(args):
            return None
        return args[index + 1]

    manifest_path = arg_value("--manifest")
    manifest_sha = arg_value("--manifest-sha256")
    authorization_path = arg_value("--authorization")
    authorization_sha = arg_value("--authorization-sha256")
    if not (manifest_path and manifest_sha and authorization_path and authorization_sha):
        return _hold_report({}, "missing_required_arguments", started_monotonic, started_utc, identity)
    if not all(re.fullmatch(r"[0-9a-fA-F]{64}", value or "") for value in (manifest_sha, authorization_sha)):
        return _hold_report({}, "malformed_digest", started_monotonic, started_utc, identity)

    manifest_file = Path(manifest_path)
    authorization_file = Path(authorization_path)
    if not manifest_file.is_file() or not authorization_file.is_file():
        return _hold_report({}, "authority_file_missing", started_monotonic, started_utc, identity)
    if not _check_sha256_file(manifest_file, manifest_sha):
        return _hold_report({}, "manifest_sha_mismatch", started_monotonic, started_utc, identity)
    if not _check_sha256_file(authorization_file, authorization_sha):
        return _hold_report({}, "authorization_sha_mismatch", started_monotonic, started_utc, identity)
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        authorization = json.loads(authorization_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _hold_report({}, "authority_parse_failed", started_monotonic, started_utc, identity)

    identity.update(
        candidate_id=manifest.get("candidate_id"),
        archive_sha256=manifest.get("candidate_sha256"),
        source_commit=manifest.get("source_commit"),
        source_tree=manifest.get("source_tree"),
        control_sha256=(manifest.get("control") or {}).get("probe_runner_sha256"),
        spec_sha256=(manifest.get("authority") or {}).get("specification_sha256"),
    )
    context = dict(manifest.get("admission_context") or {})
    context.update(manifest=manifest, authorization=authorization, **{
        key: identity[key] for key in identity
    })
    return run_voice1_readonly_admission(context)

# ---------------------------------------------------------------------------
# Fixture-only attempt executor and exact cleanup (architecture section 6).
# These functions require an explicit fixture context with a freshly-created
# private fixture root and DB under that root; they reject live paths and are
# never reachable from main()'s read-only lane.
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
_PROTECTED_TABLES = tuple(sorted({
    match.group(1)
    for match in re.finditer(
        r"CREATE TABLE IF NOT EXISTS ([a-z_]+)\s*\(",
        (CONTROL_DIR.parent / "recorder_next" / "schema.sql").read_text(encoding="utf-8"),
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
    for table in _PROTECTED_TABLES:
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
    """Authenticate the durable prefix against current rows; return tip receipt."""
    current = _read_trial_rows(conn, context)
    tip: dict[str, Any] | None = None
    for receipt in prefix:
        phase = receipt["phase"]
        rows = receipt.get("current_rows") or {}
        if phase == "INTENT":
            if any(value is not None for value in current.values()):
                raise AttemptContextError("INTENT prefix but target rows exist")
        elif phase == "A1_CREATED":
            expected = rows.get("devices")
            if current["devices"] != expected or current["projects"] is not None or current["sessions"] is not None:
                raise AttemptContextError("A1 prefix does not match current rows")
        elif phase == "A2_CREATED":
            if (current["devices"] != rows.get("devices")
                    or current["projects"] != rows.get("projects")
                    or current["sessions"] != rows.get("sessions")):
                raise AttemptContextError("A2 prefix does not match current rows")
        elif phase == "A3_BOUND":
            if (current["devices"] != rows.get("devices")
                    or current["projects"] != rows.get("projects")
                    or current["sessions"] != rows.get("sessions")):
                raise AttemptContextError("A3 prefix does not match current rows")
        elif phase == "R1_CLEANED":
            if any(value is not None for value in current.values()):
                raise AttemptContextError("R1_CLEANED prefix but target rows exist")
        tip = receipt
    if tip is not None and receipt_identity_digest(tip) != receipt_identity_digest(prefix[-1]):
        raise AttemptContextError("receipt tip identity drift")
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
        opening = _read_trial_rows(conn, context)
        if _protected_logical_digest(conn, context) != context.get("protected_logical_digest"):
            raise AttemptContextError("protected logical vector drifted before phase")
        conn.execute("BEGIN IMMEDIATE")
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
                # A3 consumes the exact admission report; a bare True is refused.
                admission = context.get("admission_report")
                if not isinstance(admission, dict) or admission.get("schema") != REPORT_SCHEMA:
                    raise AttemptContextError("A3 requires the exact admission report")
                predicates = admission.get("predicates") or {}
                if any(predicates.get(name) is not True for name in REQUIRED_PREDICATES):
                    raise AttemptContextError("A3 admission report has non-true required predicates")
                if admission.get("candidate_id") != context.get("candidate_id"):
                    raise AttemptContextError("A3 admission report candidate mismatch")
                if opening["devices"] is None or opening["projects"] is None or opening["sessions"] is None:
                    raise AttemptContextError("A3 requires the exact A2 rows")
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
        conn.execute("BEGIN IMMEDIATE")
        current = _read_trial_rows(conn, context)
        deleted: list[str] = []

        def _packet_params(table: str, values: tuple[Any, ...]) -> dict[str, Any]:
            # Map stored column order to the packet SQL's named parameters.
            packet_names = {
                "devices": ("device_user_id", "device_id", "kind", "device_status", "device_created_at", "revoked_at"),
                "projects": (
                    "stable_project_id", "project_user_id", "project_number", "name",
                    "aliases_json", "description", "project_status", "default_session_key",
                    "record_version", "project_created_at", "project_updated_at", "archived_at",
                ),
                "sessions": ("session_key", "project_id", "gateway_session_key", "session_created_at"),
            }[table]
            return dict(zip(packet_names, values))

        if current["sessions"] is not None:
            cur = conn.execute(blocks["r1.delete_session"], _packet_params("sessions", current["sessions"]))
            if cur.rowcount != 1:
                raise AttemptContextError("session delete rowcount is not one")
            deleted.append("sessions")
        if current["projects"] is not None:
            cur = conn.execute(blocks["r1.delete_project"], _packet_params("projects", current["projects"]))
            if cur.rowcount != 1:
                raise AttemptContextError("project delete rowcount is not one")
            deleted.append("projects")
        if current["devices"] is not None:
            cur = conn.execute(blocks["r1.delete_device"], _packet_params("devices", current["devices"]))
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
            "source_tree": "e" * 64,
            "control_packet_sha256": self.control_packet_sha256,
            "spec_sha256": "d" * 64,
            "owner_authorization_sha256": "c" * 64,
            "trial_identity": self._trial_identity(),
            "phase_params": {},
            "admission_report": None,
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
        predicates = {name: True for name in REQUIRED_PREDICATES}
        return {
            "schema": REPORT_SCHEMA,
            "candidate_id": self.context.get("candidate_id"),
            "predicates": predicates,
            "status": "PASS",
            "status_code": 0,
        }

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
        payload = leaf.read_bytes().replace(b"INTENT", b"INTENT", 1)
        # Rewrite the same bytes through a different inode (same-byte collision).
        leaf.unlink()
        leaf.write_bytes(payload)
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
        with self.assertRaises(AttemptContextError):
            execute_attempt_phase(self.context, "A3", a2["resulting_head_sha256"])

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



if __name__ == "__main__":
    raise SystemExit(
        "Live probing entry point is intentionally not enabled at import time. "
        "Use the bounded operator procedure with explicit authorization."
    )
