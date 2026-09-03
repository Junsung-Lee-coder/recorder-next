-- Forward-only eavesdrop routing decision contract.
-- Existing rows are mapped to semantic outcomes without retaining reasoning.
ALTER TABLE eavesdrop_decisions ADD COLUMN policy_version TEXT NOT NULL DEFAULT 'eavesdrop-router-v1';
ALTER TABLE eavesdrop_decisions ADD COLUMN covered_start_sequence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE eavesdrop_decisions ADD COLUMN covered_end_sequence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE eavesdrop_decisions ADD COLUMN dedupe_key TEXT NOT NULL DEFAULT '';
ALTER TABLE eavesdrop_decisions ADD COLUMN result_state TEXT NOT NULL DEFAULT 'PENDING';
ALTER TABLE eavesdrop_decisions ADD COLUMN effect_receipt_json TEXT;
UPDATE eavesdrop_decisions SET decision='FORWARD_DEFAULT', result_state='QUEUED' WHERE decision='QUEUED';
UPDATE eavesdrop_decisions SET decision='FORWARD_DEFAULT', result_state='DELIVERED' WHERE decision='DELIVERED';
UPDATE eavesdrop_decisions SET decision='STORE_SILENT', result_state='STORED_SILENT' WHERE decision IN ('NO_PROJECT','IGNORED');
UPDATE eavesdrop_decisions SET covered_start_sequence=segment_sequence, covered_end_sequence=segment_sequence WHERE covered_start_sequence=0 AND covered_end_sequence=0;
UPDATE eavesdrop_decisions SET dedupe_key='eavesdrop:' || session_id || ':' || segment_sequence WHERE dedupe_key='';
CREATE INDEX IF NOT EXISTS idx_eavesdrop_decisions_outcome ON eavesdrop_decisions(session_id, decision, result_state);
