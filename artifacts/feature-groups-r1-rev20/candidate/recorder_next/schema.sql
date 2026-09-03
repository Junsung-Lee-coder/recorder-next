PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_counters (
    user_id TEXT PRIMARY KEY,
    accepted_seq INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_counters (
    device_id TEXT PRIMARY KEY,
    delivery_seq INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY(user_id, device_id)
);

CREATE TABLE IF NOT EXISTS recording_leases (
    device_id TEXT PRIMARY KEY,
    active INTEGER NOT NULL DEFAULT 0,
    lease_expires_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS turns (
    turn_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    origin_device_id TEXT NOT NULL,
    client_created_at TEXT NOT NULL,
    current_project_number TEXT,
    prefer_current_project INTEGER NOT NULL DEFAULT 0,
    initial_fingerprint TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    state TEXT NOT NULL,
    accepted_seq INTEGER,
    turn_event_seq INTEGER NOT NULL DEFAULT 0,
    final_event_version INTEGER NOT NULL DEFAULT 0,
    final_combined_hash TEXT,
    final_content TEXT,
    final_outcome TEXT,
    final_error_kind TEXT,
    grace_until TEXT,
    transcript TEXT,
    authoritative_asr_outcome TEXT,
    asr_stage TEXT NOT NULL DEFAULT 'realtime',
    asr_generation INTEGER NOT NULL DEFAULT 0,
    source_deleted INTEGER NOT NULL DEFAULT 0,
    route_decision_id TEXT,
    project_id TEXT,
    session_key TEXT,
    turn_source TEXT NOT NULL DEFAULT 'client',
    schedule_id TEXT,
    trigger_instance_id TEXT,
    parent_turn_id TEXT,
    previous_turn_id TEXT,
    previous_turn_origin_device_id TEXT,
    scheduled_for TEXT,
    fired_at TEXT,
    delivery_target_device_id TEXT,
    archived_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS turn_parts (
    turn_id TEXT NOT NULL,
    part_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    mime TEXT NOT NULL,
    declared_bytes INTEGER,
    declared_sha256 TEXT,
    relationship TEXT,
    caption_hash TEXT,
    streaming INTEGER NOT NULL DEFAULT 0,
    total_chunks INTEGER,
    total_bytes INTEGER,
    whole_stream_sha256 TEXT,
    status TEXT NOT NULL DEFAULT 'RECEIVING',
    source_path TEXT,
    archived_at TEXT,
    PRIMARY KEY(turn_id, part_id),
    FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS turn_chunks (
    turn_id TEXT NOT NULL,
    part_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    byte_length INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY(turn_id, part_id, sequence),
    FOREIGN KEY(turn_id, part_id) REFERENCES turn_parts(turn_id, part_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    turn_id TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK(event_kind IN ('ACCEPTED','ROUTED','FINAL')),
    event_version INTEGER NOT NULL,
    turn_event_seq INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL,
    required_device_id TEXT NOT NULL,
    outcome TEXT,
    error_kind TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(turn_id, event_kind, event_version),
    FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS outbox (
    outbox_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    turn_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    event_version INTEGER NOT NULL,
    turn_event_seq INTEGER NOT NULL,
    required_device_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'PENDING' CHECK(state IN ('PENDING','ACKED','EXPIRED')),
    created_at TEXT NOT NULL,
    acknowledged_at TEXT,
    FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS router_queue (
    turn_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    accepted_seq INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'QUEUED' CHECK(state IN ('QUEUED','IN_PROGRESS','DONE','FAILED')),
    lease_owner TEXT,
    lease_expires_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_router_order ON router_queue(user_id, state, accepted_seq);

CREATE TABLE IF NOT EXISTS route_receipts (
    turn_id TEXT PRIMARY KEY,
    route_decision_id TEXT NOT NULL,
    project_id TEXT,
    session_key TEXT,
    project_record_version INTEGER,
    routed_text TEXT,
    decision_reason_code TEXT,
    committed_at TEXT NOT NULL,
    FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS projects (
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
CREATE INDEX IF NOT EXISTS idx_projects_user_status ON projects(user_id, status, project_number);

CREATE TABLE IF NOT EXISTS sessions (
    session_key TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    gateway_session_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(stable_project_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS session_ingress (
    hermes_submission_id TEXT PRIMARY KEY,
    turn_id TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    target_session_id TEXT NOT NULL,
    gateway_session_key TEXT NOT NULL,
    accepted_seq INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    marker TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','IN_PROGRESS','SUBMITTED','RESULT_PENDING','FAILED')),
    lease_owner TEXT,
    lease_expires_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ingress_order ON session_ingress(target_session_id, status, accepted_seq);

CREATE TABLE IF NOT EXISTS hermes_results (
    result_id TEXT PRIMARY KEY,
    hermes_submission_id TEXT NOT NULL,
    attempt_seq INTEGER NOT NULL,
    assistant_message_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    normalized_content TEXT,
    source TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    UNIQUE(hermes_submission_id, content_hash),
    FOREIGN KEY(hermes_submission_id) REFERENCES session_ingress(hermes_submission_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS final_versions (
    turn_id TEXT NOT NULL,
    event_version INTEGER NOT NULL,
    source TEXT NOT NULL,
    outcome TEXT NOT NULL,
    error_kind TEXT,
    source_ref TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    combined_content_hash TEXT NOT NULL,
    combined_content TEXT,
    committed_at TEXT NOT NULL,
    PRIMARY KEY(turn_id, event_version),
    FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tts_artifacts (
    artifact_id TEXT PRIMARY KEY,
    turn_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    artifact_version INTEGER NOT NULL,
    output_kind TEXT NOT NULL,
    origin_device_id TEXT NOT NULL,
    delivery_target_device_id TEXT,
    payload_sha256 TEXT,
    byte_size INTEGER,
    storage_path TEXT,
    source_text TEXT,
    content_type TEXT NOT NULL DEFAULT 'audio/mpeg',
    provider_name TEXT,
    provider_metadata_json TEXT,
    hermes_profile TEXT,
    endpoint_contract TEXT,
    input_sha256 TEXT,
    attempt_identity TEXT,
    completed_at TEXT,
    expires_at TEXT,
    relay_state TEXT NOT NULL DEFAULT 'PENDING' CHECK(relay_state IN ('PENDING','RELAY_RECEIVED','PLAYED','EXPIRED')),
    playback_ack_at TEXT,
    retention_outcome TEXT,
    status TEXT NOT NULL CHECK(status IN ('PENDING','READY','DELIVERY_PENDING','PLAYED','FAILED_GENERATION','EXPIRED')),
    mode TEXT NOT NULL DEFAULT 'file',
    delivery_seq INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    played_at TEXT,
    UNIQUE(turn_id, event_kind, artifact_version),
    FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE,
    FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tts_device_order ON tts_artifacts(origin_device_id, status, delivery_seq);

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

CREATE TABLE IF NOT EXISTS playback_journal (
    artifact_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PLAYED','RELAY_RECEIVED')),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY(artifact_id) REFERENCES tts_artifacts(artifact_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asr_attempts (
    attempt_id TEXT PRIMARY KEY,
    turn_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    stage TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT,
    transcript TEXT,
    mode TEXT,
    provider_name TEXT,
    hermes_profile TEXT,
    endpoint_contract TEXT,
    input_sha256 TEXT,
    output_sha256 TEXT,
    content_type TEXT,
    byte_size INTEGER,
    attempt_identity TEXT,
    completed_at TEXT,
    committed_at TEXT NOT NULL,
    FOREIGN KEY(turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_id TEXT PRIMARY KEY,
    user_id TEXT,
    turn_id TEXT,
    kind TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

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
    failure_kind TEXT,
    FOREIGN KEY(project_id) REFERENCES projects(stable_project_id) ON DELETE SET NULL
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
    policy_version TEXT NOT NULL DEFAULT 'eavesdrop-router-v1',
    covered_start_sequence INTEGER NOT NULL DEFAULT 0,
    covered_end_sequence INTEGER NOT NULL DEFAULT 0,
    dedupe_key TEXT NOT NULL DEFAULT '',
    result_state TEXT NOT NULL DEFAULT 'PENDING',
    effect_receipt_json TEXT,
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

INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('schema_version', '4');
