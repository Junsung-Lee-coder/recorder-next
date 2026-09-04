-- Recorder Next feature groups 1-8 additive migration.
-- Existing rows and private payloads are preserved; rollback is by restoring
-- the pre-migration SQLite backup rather than dropping these tables.

ALTER TABLE tts_artifacts ADD COLUMN content_type TEXT NOT NULL DEFAULT 'audio/mpeg';
ALTER TABLE tts_artifacts ADD COLUMN byte_size INTEGER;
ALTER TABLE tts_artifacts ADD COLUMN provider_name TEXT;
ALTER TABLE tts_artifacts ADD COLUMN provider_metadata_json TEXT;
ALTER TABLE tts_artifacts ADD COLUMN expires_at TEXT;
ALTER TABLE tts_artifacts ADD COLUMN relay_state TEXT NOT NULL DEFAULT 'PENDING';
ALTER TABLE tts_artifacts ADD COLUMN playback_ack_at TEXT;
ALTER TABLE tts_artifacts ADD COLUMN retention_outcome TEXT;
ALTER TABLE tts_artifacts ADD COLUMN hermes_profile TEXT;
ALTER TABLE tts_artifacts ADD COLUMN endpoint_contract TEXT;
ALTER TABLE tts_artifacts ADD COLUMN input_sha256 TEXT;
ALTER TABLE tts_artifacts ADD COLUMN attempt_identity TEXT;
ALTER TABLE tts_artifacts ADD COLUMN completed_at TEXT;
ALTER TABLE asr_attempts ADD COLUMN mode TEXT;
ALTER TABLE asr_attempts ADD COLUMN provider_name TEXT;
ALTER TABLE asr_attempts ADD COLUMN hermes_profile TEXT;
ALTER TABLE asr_attempts ADD COLUMN endpoint_contract TEXT;
ALTER TABLE asr_attempts ADD COLUMN input_sha256 TEXT;
ALTER TABLE asr_attempts ADD COLUMN output_sha256 TEXT;
ALTER TABLE asr_attempts ADD COLUMN content_type TEXT;
ALTER TABLE asr_attempts ADD COLUMN byte_size INTEGER;
ALTER TABLE asr_attempts ADD COLUMN attempt_identity TEXT;
ALTER TABLE asr_attempts ADD COLUMN completed_at TEXT;

CREATE TABLE IF NOT EXISTS worker_jobs (
    job_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    stage TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    chain_generation TEXT,
    chain_fingerprint TEXT,
    chain_json TEXT,
    overall_deadline_at TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','CLAIMED','RETRY_WAIT','SUCCEEDED','FAILED_PERMANENT')),
    owner TEXT,
    lease_expires_at TEXT,
    next_attempt_at TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    last_error_kind TEXT,
    effect_receipt_json TEXT,
    effect_receipt_sha256 TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_worker_jobs_due ON worker_jobs(status, next_attempt_at, created_at);

CREATE TABLE IF NOT EXISTS worker_attempts (
    attempt_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    owner TEXT NOT NULL,
    stage TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    outcome TEXT NOT NULL DEFAULT 'RUNNING' CHECK(outcome IN ('RUNNING','SUCCEEDED','RETRY_WAIT','FAILED_PERMANENT','RECLAIMED')),
    error_kind TEXT,
    effect_receipt_sha256 TEXT,
    UNIQUE(job_id, attempt_number),
    FOREIGN KEY(job_id) REFERENCES worker_jobs(job_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS update_channels (
    channel TEXT PRIMARY KEY,
    current_generation INTEGER NOT NULL,
    current_manifest_sha256 TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS update_manifests (
    channel TEXT NOT NULL,
    generation INTEGER NOT NULL,
    platform TEXT NOT NULL,
    version TEXT NOT NULL,
    version_code INTEGER NOT NULL,
    artifact_name TEXT NOT NULL,
    artifact_relpath TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    signer_digest TEXT NOT NULL,
    size INTEGER NOT NULL,
    changelog TEXT NOT NULL,
    min_server_version TEXT NOT NULL,
    authorization_policy TEXT NOT NULL,
    etag TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(channel, generation),
    UNIQUE(channel, version_code)
);
CREATE INDEX IF NOT EXISTS idx_update_manifests_current ON update_manifests(channel, generation DESC);

CREATE TABLE IF NOT EXISTS eavesdrop_sessions (
    session_id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    user_id TEXT NOT NULL,
    phone_device_id TEXT NOT NULL,
    watch_device_id TEXT,
    project_id TEXT,
    state TEXT NOT NULL CHECK(state IN ('CREATED','ACTIVE','PAUSED','STOPPING','STOPPED','EXPIRED','FAILED')),
    response_enabled INTEGER NOT NULL DEFAULT 1,
    tts_enabled INTEGER NOT NULL DEFAULT 0,
    hermes_enabled INTEGER NOT NULL DEFAULT 0,
    accumulated_transcript TEXT NOT NULL DEFAULT '',
    next_sequence INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    stopped_at TEXT,
    failure_kind TEXT
);
CREATE INDEX IF NOT EXISTS idx_eavesdrop_sessions_expiry ON eavesdrop_sessions(state, expires_at);

CREATE TABLE IF NOT EXISTS eavesdrop_segments (
    session_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    client_segment_id TEXT NOT NULL,
    audio_sha256 TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    storage_path TEXT NOT NULL,
    transcript TEXT,
    status TEXT NOT NULL DEFAULT 'ACCEPTED' CHECK(status IN ('ACCEPTED','FAILED')),
    created_at TEXT NOT NULL,
    PRIMARY KEY(session_id, sequence),
    UNIQUE(session_id, client_segment_id),
    FOREIGN KEY(session_id) REFERENCES eavesdrop_sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS eavesdrop_replies (
    reply_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    segment_sequence INTEGER NOT NULL,
    text_hash TEXT NOT NULL,
    reply_text TEXT NOT NULL,
    tts_requested INTEGER NOT NULL DEFAULT 0,
    hermes_requested INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(session_id, segment_sequence),
    FOREIGN KEY(session_id) REFERENCES eavesdrop_sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS diagnostics_consents (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    event_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_diagnostics_consents_owner ON diagnostics_consents(user_id, device_id, enabled, created_at);

CREATE TABLE IF NOT EXISTS diagnostic_events (
    event_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    category TEXT NOT NULL,
    stage TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    retention_deadline TEXT NOT NULL,
    deleted_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_diagnostic_events_owner ON diagnostic_events(user_id, device_id, occurred_at);

CREATE TABLE IF NOT EXISTS diagnostic_bundles (
    bundle_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    opt_in_event_id TEXT NOT NULL,
    compressed_size INTEGER NOT NULL,
    expanded_size INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retention_deadline TEXT NOT NULL,
    deleted_at TEXT,
    UNIQUE(user_id, device_id, payload_sha256),
    FOREIGN KEY(opt_in_event_id) REFERENCES diagnostics_consents(event_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_diagnostic_bundles_owner ON diagnostic_bundles(user_id, device_id, created_at);

CREATE TABLE IF NOT EXISTS eavesdrop_decisions (
    decision_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES eavesdrop_sessions(session_id) ON DELETE CASCADE,
    segment_sequence INTEGER NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    project_id TEXT,
    gateway_session_key TEXT,
    hermes_submission_id TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(session_id, segment_sequence)
);

CREATE INDEX IF NOT EXISTS idx_eavesdrop_decisions_session ON eavesdrop_decisions(session_id, segment_sequence);

CREATE TABLE IF NOT EXISTS diagnostic_tombstones (
    tombstone_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('event','bundle')),
    entity_id TEXT NOT NULL,
    deleted_at TEXT NOT NULL,
    UNIQUE(entity_type, entity_id)
);
