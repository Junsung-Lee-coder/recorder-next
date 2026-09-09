-- R25 integrated contracts: one additive schema-5 migration.
-- Apply only to a schema-4 database inside the Recorder startup transaction;
-- the runtime guards each column for restart-safe recovery.
ALTER TABLE session_ingress ADD COLUMN run_id TEXT;
ALTER TABLE session_ingress ADD COLUMN wire_revision TEXT NOT NULL DEFAULT 'hermes-runs-v1';
ALTER TABLE session_ingress ADD COLUMN gateway_identity TEXT NOT NULL DEFAULT 'default';
ALTER TABLE worker_attempts ADD COLUMN lease_token TEXT;
ALTER TABLE turn_parts ADD COLUMN source_deleted_at TEXT;
ALTER TABLE diagnostics_consents ADD COLUMN alias_digest TEXT;
ALTER TABLE diagnostic_events ADD COLUMN alias_digest TEXT;
ALTER TABLE diagnostic_events ADD COLUMN privacy_version INTEGER NOT NULL DEFAULT 2;
ALTER TABLE diagnostic_events ADD COLUMN migration_state TEXT NOT NULL DEFAULT 'LEGACY';
ALTER TABLE diagnostic_bundles ADD COLUMN alias_digest TEXT;
ALTER TABLE diagnostic_bundles ADD COLUMN privacy_version INTEGER NOT NULL DEFAULT 2;
ALTER TABLE diagnostic_bundles ADD COLUMN migration_state TEXT NOT NULL DEFAULT 'LEGACY';
ALTER TABLE diagnostic_tombstones ADD COLUMN expires_at TEXT;

CREATE TABLE IF NOT EXISTS hermes_run_bindings (
    submission_id TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL CHECK(subject_kind IN ('turn','eavesdrop')),
    turn_id TEXT,
    eavesdrop_session_id TEXT,
    segment_sequence INTEGER,
    segment_sha256 TEXT,
    marker TEXT NOT NULL,
    gateway_session_key TEXT NOT NULL,
    gateway_identity TEXT NOT NULL,
    canonical_request_sha256 TEXT NOT NULL,
    wire_revision TEXT NOT NULL,
    request_json TEXT NOT NULL,
    run_id TEXT,
    created_at TEXT NOT NULL,
    bound_at TEXT,
    CHECK ((subject_kind='turn' AND turn_id IS NOT NULL AND eavesdrop_session_id IS NULL AND segment_sequence IS NULL AND segment_sha256 IS NULL) OR
           (subject_kind='eavesdrop' AND turn_id IS NULL AND eavesdrop_session_id IS NOT NULL AND segment_sequence IS NOT NULL AND segment_sha256 IS NOT NULL)),
    UNIQUE(gateway_identity, run_id),
    FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_hermes_binding_subject ON hermes_run_bindings(subject_kind, turn_id, eavesdrop_session_id, segment_sequence);
CREATE INDEX IF NOT EXISTS idx_diagnostic_events_ready ON diagnostic_events(user_id, device_id, retention_deadline, privacy_version, migration_state);
CREATE INDEX IF NOT EXISTS idx_diagnostic_bundles_ready ON diagnostic_bundles(user_id, device_id, retention_deadline, privacy_version, migration_state);
