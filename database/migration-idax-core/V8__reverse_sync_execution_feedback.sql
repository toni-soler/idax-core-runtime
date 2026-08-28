ALTER TABLE idax_core.reverse_sync_outbox
    ADD COLUMN IF NOT EXISTS technical_status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
    ADD COLUMN IF NOT EXISTS functional_status VARCHAR(30) NOT NULL DEFAULT 'NOT_APPLICABLE',
    ADD COLUMN IF NOT EXISTS technical_error TEXT,
    ADD COLUMN IF NOT EXISTS functional_error TEXT,
    ADD COLUMN IF NOT EXISTS processed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_reverse_sync_outbox_message_id
    ON idax_core.reverse_sync_outbox(message_id);

CREATE INDEX IF NOT EXISTS ix_reverse_sync_outbox_business_key
    ON idax_core.reverse_sync_outbox(entity_name, business_key, created_at DESC);
