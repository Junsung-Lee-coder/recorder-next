# Recorder Voice1 isolated trial — binding / create / CAS / conditional-rollback packet (SUCCESSOR-RESOLVED, STAGED ONLY, NOT APPLIED)

product_identity: recorder-next-server-voice-session-chain
identity_resolution: candidate-manifest.json verified algorithm (the frozen
  candidate-manifest.json of the sealed successor generation is the single
  identity authority; this packet embeds NO candidate archive/commit/tree and
  no future hash, so it cannot go stale against its own successor)
candidate_id: read candidate_id from candidate-manifest.json
candidate_sha256: read candidate_sha256 from candidate-manifest.json
source commit/tree: read source_commit and source_tree from candidate-manifest.json
manifest resolution algorithm (the same main authority-loading path the
  control runner implements; operator re-runs it before any use):
  1. Root provides the absolute manifest path M and its SHA256 out of band.
     Open safely, bounded read, hash the exact bytes, reject duplicate JSON
     keys; require the successor schema, generation, and product identity.
  2. Read candidate_id, candidate_sha256, source_commit, source_tree from M;
     verify authorities.* hashes and candidate_incomplete=false; resolve the
     candidate root and archive from the separate root authorization.
  3. Hash the archive, reject duplicate/traversing/absolute/unsupported
     member types; require the normalized relative member set to equal
     per_file_sha256 exactly and tracked_file_count to match; require the
     packet and runner member hashes to equal control.packet_sha256 and
     control.probe_runner_sha256.
  4. Extract the eight labeled SQL statements with the existing parser; the
     label set and per-statement SHA256 map must equal the candidate evidence.
  5. Identity fields in every report are copied from the validated M — never
     from packet placeholders, directory basenames, or an older receipt.
target database: /var/lib/recorder-next/recorder-next.sqlite3 (never a Hermes DB)
binding S (owner-selected default transcript): session_id 20260703_210417_8f66b434
persisted Discord session key (SEPARATE identity, metadata-verified on the owning card, never edited):
  agent:main:discord:thread:... (65 chars, distinct from S; value stays in Hermes, untouched)
authority: root ratification t_16ca403e-voice1-b3-architecture-ratification-v1.json
  sha256 2e48ae1b7a6c84d39f6919ba5bd952ca439a0184117526b350aab279028f745e, adopting
  VOICE1-B3-TTS-ADMISSION-CONTROL-CLOSURE/v1 (spec sha256 ce1c23271239d330e7125ded8ecb6b32d0a3bee8c5d2a07118693c3065df3de1)
  and the B2 auth-mapping authority for sections 3-6 semantics.

All steps below are specification for a LATER root-approved executor. Nothing on
this card wrote to any live DB, project, principal, mapping, unit, config, or
credential. This successor packet corrects historical labels and successor
references only: the eight labeled SQL statement bytes and the ratified trial
identity (section 0) are unchanged from the corrected E2 packet. During B3 the
only executor is the fixture-only one in the sibling qa_probe_runner.py
(execute_attempt_phase / cleanup_attempt); any live promotion code requires its
own exact review.

## 0. Ratified trial identity (deterministic; re-derived and matched on this card)

suffix = first 16 hex of SHA-256(UTF-8("20260703_210417_8f66b434")) = 7333f832a973d428

| Field | Exact value |
|---|---|
| U (user_id) | voice1-trial-owner-7333f832a973d428 |
| D (device_id) | voice1-server-trial-7333f832a973d428 |
| device kind | other |
| N (project_number) | VOICE1-TRIAL-7333f832a973d428 |
| I (create idempotency_key) | recorder-next:voice1:isolated-trial:7333f832a973d428 |
| name | Recorder Voice1 isolated trial |
| aliases (aliases_json stored form) | [] (exact stored preimage: `[]`) |
| description | Owner-authorized server-only two-turn voice trial; isolated from existing Recorder projects. |
| P (stable_project_id) | b961f648-3f79-5f92-9ed7-aeceb087fa02 |
| L (logical session key) | project:b961f648-3f79-5f92-9ed7-aeceb087fa02:default |

P = UUIDv5(NAMESPACE_URL, "recorder-next:project:" + U + ":" + I) — exactly as
store.create_project derives it (store.py:4848). Do NOT supply P via HTTP; the
public route does not accept it.

This is one Recorder-local kind=other logical test row, ratified by root as
necessary authentication metadata for the server-only trial. It is NOT a
physical device enrollment, app/device configuration, or Discord identity
mapping. No existing principal or release-smoke row changes.

## 1. Frozen preimage (read-only revalidation 2026-09-12 on this card)

Live row counts: projects=1, sessions=1, devices=1. All pre-existing rows are the
release-smoke set; exact nonsecret tuple:

- projects: stable_project_id=dc016d66-6b67-5f49-9c3e-3466cacbc0fd,
  user_id=release-smoke-9fa4a790c711, project_number=REL-9fa4a790c711,
  name="Recorder Next release smoke", aliases_json=[], description="",
  status=active, record_version=1,
  default_session_key=project:dc016d66-6b67-5f49-9c3e-3466cacbc0fd:default,
  created_at=2026-09-04T12:06:52.616+00:00,
  updated_at=2026-09-04T12:06:52.616+00:00, archived_at=NULL
- sessions: session_key=project:dc016d66-6b67-5f49-9c3e-3466cacbc0fd:default,
  project_id=dc016d66-6b67-5f49-9c3e-3466cacbc0fd,
  gateway_session_key=project:dc016d66-6b67-5f49-9c3e-3466cacbc0fd:default,
  created_at=2026-09-04T12:06:52.616+00:00
- devices: user_id=release-smoke-9fa4a790c711 (owner), device_id=release-phone-9fa4a790c711,
  kind=phone, status=active, created_at=2026-09-04T12:06:52.590+00:00, revoked_at=NULL

Row-set digests over exact stored values (order: PK ASC; fields in schema order;
sha256 over repr(field)+0x1f per field, +0x1e per row — compute the same way at
revalidation):

- project_rowset_sha256: 4a7535f45c6df855d2e1f8a1dddd3a21fe5526a5ca845de4e260f0d99dc69d12
- session_rowset_sha256: 6508dbbd3913869bb232d2164255a6afb448e5ed48c8999e93b36716cc94cbdd
- device_rowset_sha256:  299ff52ba314ee8fe2a82dc0e267419735ccf0ed28e4e4f11fe6e84ef84e2e5d

Schema (verified via PRAGMA table_info against the live DB; matches
migrations/001_initial.sql): projects has NO sessions.updated_at-style trap —
projects has created_at AND updated_at; sessions has ONLY (session_key,
project_id, gateway_session_key, created_at). Any statement touching
`sessions.updated_at` is invalid and must be discarded (v1 example error, never
repeated here). devices: (user_id, device_id, kind, status, created_at, revoked_at).

The executor MUST revalidate this whole section immediately before the action
window; these are time-bound observations, not a lock or a permanent preimage.

## 2. Collision / absence checks (all returned ZERO on this card, active AND archived)

- U in projects: 0 — U in devices: 0
- D in devices: 0 — P in projects: 0 — N in projects: 0
- L in sessions: 0 — L in projects.default_session_key: 0
- gateway_session_key = S anywhere in sessions: 0
- S appearing in any default_session_key/name/alias: 0
- name "Recorder Voice1 isolated trial" under U: 0
- No session row maps any project to S; the release-smoke canonical key remains self-keyed.
- No accepted/queued/routing/scheduled/claimed effect exists for U/D/P/L/S (new
  principal; discovery of any such effect invalidates the absence plan and stops).

Re-run every check inside the CAS transaction (section 5) before the UPDATEs.

## 3. Ordered apply (A1 -> A2 -> A3) — VOICE1-B3 fixture executor + later root-owned live executor, held-traffic boundary only

 Preconditions for the whole window: keep external ingress held and Recorder
 processing quiescent across creation and binding; confirm source import
 provenance (frozen successor tree) before opening the live store; never let
 store initialization run an unapproved migration; bind a WAL-consistent backup
 using existing procedures.

Attempt custody: every execution generates a fresh UUIDv4 attempt_id and owns
one private receipt directory /var/lib/recorder-next/voice1-trial-receipts/<attempt_id>/
(mode 0700; files 0600; no-follow exclusive creation; fsync file and parent).
Receipt names: intent.json, a1.created.json, a2.created.json, a3.bound.json,
r1.cleaned.json under schema recorder-next-voice1-trial-attempt/v1. A phase
receipt is published only after COMMIT plus exact fresh readback. A commit
followed by a missing completion receipt is COMMIT_UNCERTAIN/HOLD: preserve
rows and receipts, never synthesize custody or retry by tuple equality.

A1. Device insert — attempt-owned, INSERT-only. Named parameters come only
    from this attempt's receipts. In ONE BEGIN IMMEDIATE transaction
    (foreign_keys=ON, busy_timeout=5000): re-verify fresh absence of U/D, all
    pinned collisions, current schema, and unchanged protected rows, then
    execute exactly this statement (plain INSERT; never OR IGNORE/REPLACE/UPSERT):
    rowcount MUST be 1. SELECT all six stored fields back inside the same
    transaction and compare the intended typed tuple before COMMIT.

    <!-- voice1-sql:a1.insert_device -->
    ```sql
    INSERT INTO devices (user_id, device_id, kind, status, created_at, revoked_at)
    VALUES (:device_user_id, :device_id, :kind, :device_status, :device_created_at, :revoked_at)
    ```

    Existing same-kind active row is a collision even when every value matches.
    Publish a1.created.json only after COMMIT plus readback.

A2. Project + session insert — validate the a1 receipt and the exact device
    row before opening the transaction and again inside it. In ONE BEGIN
    IMMEDIATE: recheck absent P/(U,N)/L, conflicting target binding, protected
    row vectors, and no-work assertions; then execute these statements, each
    rowcount MUST be 1, and both full SELECT postimages must equal the intended
    typed tuples:

    <!-- voice1-sql:a2.insert_project -->
    ```sql
    INSERT INTO projects (stable_project_id, user_id, project_number, name, aliases_json, description, status, default_session_key, record_version, created_at, updated_at, archived_at)
    VALUES (:stable_project_id, :project_user_id, :project_number, :name, :aliases_json, :description, :project_status, :default_session_key, :record_version, :project_created_at, :project_updated_at, :archived_at)
    ```

    <!-- voice1-sql:a2.insert_session -->
    ```sql
    INSERT INTO sessions (session_key, project_id, gateway_session_key, created_at)
    VALUES (:session_key, :project_id, :gateway_session_key, :session_created_at)
    ```

    Any conflict or exception after either insert rolls back the whole A2
    transaction. Publish a2.created.json containing all three current rows
    after COMMIT/readback. No Hermes session creation.

A3. Mapping/version CAS — ONE BEGIN IMMEDIATE on the target store, with exact
    A2 device/project/session full-image validation first. Source and
    persisted-key admission (B3 run_voice1_readonly_admission with all
    REQUIRED_PREDICATES true; A3 consumes the exact admission report and
    cannot accept a bare True) is performed BEFORE this transaction, never
    by a network call while the lock is held, and starts within 10 seconds
    of the successful session observation. Both statements MUST affect
    exactly one row; any failure rolls back both. Re-read all three full
    rows inside the transaction before COMMIT; publish a3.bound.json with
    the exact A4 images after commit/readback.

    <!-- voice1-sql:a3.bind_session -->
    ```sql
    UPDATE sessions SET gateway_session_key = :S
    WHERE session_key = :session_key AND project_id = :project_id
      AND gateway_session_key = :prior_gateway_session_key AND created_at = :session_created_at
    ```

    <!-- voice1-sql:a3.bump_project -->
    ```sql
    UPDATE projects SET record_version = record_version + 1, updated_at = :operation_time
    WHERE stable_project_id = :stable_project_id AND user_id = :project_user_id
      AND project_number = :project_number AND status = :project_status
      AND record_version = :prior_record_version AND default_session_key = :default_session_key
      AND name = :name AND aliases_json = :aliases_json AND description = :description
      AND created_at = :project_created_at AND updated_at = :project_updated_at
      AND archived_at IS NULL
    ```

A4. Expected postimage (all three new rows; existing rows logically
    bit-equivalent; row counts: projects 1->2, sessions 1->2, devices 1->2):

    - devices: (U, D, 'other', 'active', {device_created_at}, NULL)
    - projects: (P, U, N, name, '[]', description, 'active', L,
      record_version=2, project_created_at, operation_time, NULL)
    - sessions: (L, P, S, session_created_at)
    - release-smoke project/session/device: unchanged (digests match section 1).

    Hold traffic until same-candidate readback confirms: authenticated project
    visibility under U, exact stored join (L -> P -> S), version=2, and no
    arbitrary new project or new Hermes transcript.

A5. During the authorized real trial, each route receipt must name P/L/version 2
    and each frozen ingress/run binding must name S. Wire contract stays the
    frozen candidate: actual input text + body session_id=S + header
    X-Hermes-Session-Key: S. Never replace S with L and never write the header
    value into Hermes' persisted Discord key. A changed/rotated/ended target or
    altered version requires a NEW bounded binding decision — no automatic
    retargeting.

## 4. Conditional rollback (R1, before-use only)

Before-use means ZERO accepted or dependent trial work. Ingress is held; the
complete logical vector of every pre-existing non-trial table/row is compared
against the attempt opening; unexpected unrelated writes conservatively
invalidate this cleanup. Reference checks cover turns, jobs, routes, ingress,
schedules, session_ingress, route_receipts, hermes_run_bindings and frozen
bindings (including indirect turn/job joins). A missing check, table or schema
mismatch is HOLD.

R1 runs in ONE BEGIN IMMEDIATE for all receipt-authorized state comparison,
no-work/unchanged-protected checks, DELETEs and final logical readback.
Receipt bytes/lineage are validated BEFORE the transaction; after acquiring
the write lock the entire expected current row vector is re-read before ANY
DELETE, comparing types and values exactly including timestamps and NULL.
For bound state use a3.bound's A4; for a valid A1-only/A1+A2 prefix use that
prefix's actual postimage. These null-safe DELETEs follow the successful
SELECT comparisons; each expected-present DELETE MUST affect exactly one row;
any unexpected row count or exception invokes ROLLBACK, never partial COMMIT.

<!-- voice1-sql:r1.delete_session -->
```sql
DELETE FROM sessions
 WHERE session_key IS :session_key AND typeof(session_key) = :session_key_type
   AND project_id IS :project_id AND typeof(project_id) = :project_id_type
   AND gateway_session_key IS :gateway_session_key AND typeof(gateway_session_key) = :gateway_session_key_type
   AND created_at IS :session_created_at AND typeof(created_at) = :session_created_at_type
```

<!-- voice1-sql:r1.delete_project -->
```sql
DELETE FROM projects
 WHERE stable_project_id IS :stable_project_id AND typeof(stable_project_id) = :stable_project_id_type
   AND user_id IS :project_user_id AND typeof(user_id) = :project_user_id_type
   AND project_number IS :project_number AND typeof(project_number) = :project_number_type
   AND name IS :name AND typeof(name) = :name_type
   AND aliases_json IS :aliases_json AND typeof(aliases_json) = :aliases_json_type
   AND description IS :description AND typeof(description) = :description_type
   AND status IS :project_status AND typeof(status) = :project_status_type
   AND default_session_key IS :default_session_key AND typeof(default_session_key) = :default_session_key_type
   AND record_version IS :record_version AND typeof(record_version) = :record_version_type
   AND created_at IS :project_created_at AND typeof(created_at) = :project_created_at_type
   AND updated_at IS :project_updated_at AND typeof(updated_at) = :project_updated_at_type
   AND archived_at IS :archived_at AND typeof(archived_at) = :archived_at_type
```

<!-- voice1-sql:r1.delete_device -->
```sql
DELETE FROM devices
 WHERE user_id IS :device_user_id AND typeof(user_id) = :device_user_id_type
   AND device_id IS :device_id AND typeof(device_id) = :device_id_type
   AND kind IS :kind AND typeof(kind) = :kind_type
   AND status IS :device_status AND typeof(status) = :device_status_type
   AND created_at IS :device_created_at AND typeof(created_at) = :device_created_at_type
   AND revoked_at IS :revoked_at AND typeof(revoked_at) = :revoked_at_type
```

Permitted committed-prefix rollback states:
- INTENT only with all targets absent: no DELETE; prove absence, report no
  product mutation.
- A1_CREATED only: device exact, project/session absent; delete only device.
- A2_CREATED: device exact, project exact version1, session exact gateway L;
  delete sessions -> projects -> devices.
- A3_BOUND: exact A4 project version2 and session gateway S; delete in the
  same FK-safe order.
- R1_CLEANED exact receipt plus all target absence/protected vector match:
  no-op readback, never rerun deletion.

Any mixture outside those states, foreign same-tuple rows, one member of an
A2 pair, mismatch of even one field, or an existing r1 receipt with different
bytes is HOLD/ROLLBACK with all current rows unchanged. After successful
delete/readback/COMMIT, no-clobber publish r1.cleaned.json. A crash before
that receipt does not authorize receipt fabrication from absence; report
uncertain completion for scoped operator adjudication. Original receipt files
remain for audit.

Phase R2 — after ANY accepted trial work, or if any preimage/reference check
fails mid-flight: NO deletion, NO history rewind, NO version-1 reuse, NO
whole-backup restore over newer traffic, NO transcript cleanup. Hold trial
ingress; preserve accepted targets and evidence. If root ratifies containment,
use the existing archive/revoke primitives with the CURRENT exact version to
disable only the trial project/principal; report containment separately and do
NOT claim the absent preimage was restored. Previously accepted work drains and
terminalizes under its frozen S and normal leases.

## 5. Verification evidence classes and executable CLI

Three distinct evidence classes exist and can never substitute for each other:
- FIXTURE: the in-module unittest classes below run against temporary
  databases and private fixture roots.  These prove statement/custody/rollback
  semantics only.
- REAL SUBPROCESS: the executable read-only admission caller run exactly once
  as a subprocess with the canonical argv against owned loopback/temp data,
  defaulting to a structured JSON HOLD/exit 2.  A helper call reported as
  "subprocess execution" is not subprocess evidence.
- LIVE: later, separately root-authorized trial/live results.  Fixture or
  subprocess evidence never implies live permission.

Canonical read-only admission invocation (authority paths only; tokens are
never arguments):

    timeout 120s python3 -B -s <candidate_root>/run/qa_probe_runner.py
      --read-only-admission
      --manifest <candidate-manifest.json> --manifest-sha256 <sha256>
      --authorization <authorization.json> --authorization-sha256 <sha256>

No flags, malformed flags, validation failure, or any failed observation
prints exactly one JSON HOLD with status_code 2 on stdout and exits 2 with an
empty stderr; the all-true report exits 0.

## 5.1 Fixture semantics verification

The control module's unittest classes (Voice1ControlPacketSQLTests,
Voice1SessionAdmissionTests, and AttemptExecutorTests) execute these exact
labeled SQL bytes against a temporary file fixture built from the COMPLETE
candidate schema (recorder_next/schema.sql, per the whole-table protected
vector) plus the release-smoke seed.  AttemptExecutorTests additionally
publish and authenticate no-clobber O_EXCL/O_NOFOLLOW fsync receipts under a
private fixture root: A1/A2/A3 phases commit and publish only after exact
typed readback (INTENT durable before any product-row write); a second-insert
failure AFTER a successful project INSERT rolled the project back; A3
consumes the exact admission report and refuses a bare True; a commit whose
receipt cannot publish is returned COMMIT_UNCERTAIN with rows preserved; the
same-attempt prefix resumes only against the pinned out-of-band head;
receipt-authenticated cleanup deleted exactly the new rows (sessions ->
projects -> devices) for A1/A2/A3 prefixes; INTENT-only cleanup reported
no-mutation and an R1_CLEANED prefix reported already_completed; drifted
updated_at, NULL-to-empty description, dependent turns rows, symlinked and
tampered/same-byte-different-inode receipts, and foreign contexts all refused
mutation with rows preserved.  The B6 form adds: BEGIN IMMEDIATE precedes
every authorizing read (a second connection changing state before the lock is
caught by the locked re-read, and a second connection is busy while the lock
is held); cleanup DELETE parameters derive from the tip receipt's
authenticated typed postimage with typeof() predicates on every field, so
current-row drift (any of the 22 positions, timestamps, NULL-to-empty,
INTEGER type/value drift) refuses deletion instead of being adopted; a
same-connection drift after the first successful DELETE rolls the whole
transaction back; and the prefix validator compares only the head receipt to
the current DB — historic INTENT absence is never compared to today's rows.
Voice1B6ExecutableClosureTests (integrated suite) further prove the
executable main() HOLD paths, the strict five-option canonical argv grammar,
the 32-name REQUIRED_PREDICATES aggregate, the distinct omitted/explicit
profile observations, and the exact four-key persisted-row shape contract.
These are fixture-executable results — NOT a live-DB rehearsal and not a
substitute for the executor's own frozen-preimage revalidation at the later
live gate.

## 6. Unchanged invariants

- Preserve release-smoke and all prior rows; preserve the persisted Discord key
  and normal session-turn leases; never interrupt the originating turn, clear a
  lease, or create another Hermes transcript.
- After accepted work, never delete rows, rewind history, or restore backups.
- No live writes of any kind occurred while preparing this packet.
