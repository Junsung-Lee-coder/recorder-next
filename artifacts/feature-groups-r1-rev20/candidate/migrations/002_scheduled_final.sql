-- Recorder Next R5 additive migration for scheduled FINAL and TTS delivery.
-- Rollback safety: this migration only adds nullable/defaulted columns, tables,
-- indexes, and a deterministic TTS target backfill. It does not drop or delete
-- existing R4 data. Rollback requires restoring the pre-migration SQLite backup.

ALTER TABLE turns ADD COLUMN turn_source TEXT NOT NULL DEFAULT 'client';
ALTER TABLE turns ADD COLUMN schedule_id TEXT;
ALTER TABLE turns ADD COLUMN trigger_instance_id TEXT;
ALTER TABLE turns ADD COLUMN parent_turn_id TEXT;
ALTER TABLE turns ADD COLUMN previous_turn_id TEXT;
ALTER TABLE turns ADD COLUMN previous_turn_origin_device_id TEXT;
ALTER TABLE turns ADD COLUMN scheduled_for TEXT;
ALTER TABLE turns ADD COLUMN fired_at TEXT;
ALTER TABLE turns ADD COLUMN delivery_target_device_id TEXT;
ALTER TABLE tts_artifacts ADD COLUMN delivery_target_device_id TEXT;

UPDATE tts_artifacts
SET delivery_target_device_id = origin_device_id
WHERE delivery_target_device_id IS NULL;

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
