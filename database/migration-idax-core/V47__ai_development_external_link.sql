-- Generic external link model (Section D1) for entities beyond a single story - today only
-- AiSprint, but the shape (provider, entity type, external id/key/url, revision, sync status,
-- attempt/backoff, correlation id, direction) generalizes to a future relationship-sync increment
-- without a new table. Deliberately a RICHER status model than the existing per-story link tables
-- (ai_jira_link.sync_status etc, still PENDING/SYNCED/RETRY/FAILED): UNSUPPORTED and FILTERED are
-- real, distinct outcomes a caller must be able to represent honestly - "this provider genuinely
-- cannot express this" is not the same defect class as "the call failed and should be retried".
--
-- entity_id is polymorphic (which table it points into depends on entity_type), the same
-- application-enforced-integrity approach V43's ai_work_item_relationship already uses for its own
-- source/target - see that migration's comment for the rationale (a plain FK cannot point at
-- "whichever of several tables entity_type says").
CREATE TABLE IF NOT EXISTS idax_core.ai_external_link (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL CHECK (provider IN ('TAIGA', 'JIRA', 'AZURE_DEVOPS')),
    entity_type VARCHAR(20) NOT NULL CHECK (entity_type IN ('SPRINT', 'RELATIONSHIP')),
    entity_id UUID NOT NULL,
    external_id VARCHAR(80),
    external_key VARCHAR(120),
    external_url VARCHAR(1000),
    external_revision VARCHAR(60),
    sync_status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (sync_status IN
        ('PENDING', 'SYNCED', 'FAILED_RETRYABLE', 'FAILED_PERMANENT', 'CONFLICT', 'UNSUPPORTED', 'FILTERED')),
    direction VARCHAR(20) NOT NULL DEFAULT 'IDAX_TO_EXTERNAL' CHECK (direction IN
        ('IDAX_TO_EXTERNAL', 'EXTERNAL_TO_IDAX', 'BIDIRECTIONAL')),
    last_synced_at TIMESTAMPTZ,
    last_error TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    correlation_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0
);
-- One external link per (tenant, provider, local entity) - re-running the sync for the same
-- AiSprint against the same provider must update this row, never insert a second one.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_external_link_entity ON idax_core.ai_external_link
    (tenant_id, provider, entity_type, entity_id);
CREATE INDEX IF NOT EXISTS ix_ai_external_link_retry ON idax_core.ai_external_link
    (sync_status, next_attempt_at) WHERE sync_status = 'FAILED_RETRYABLE';

DROP TRIGGER IF EXISTS trg_ai_external_link_updated_at ON idax_core.ai_external_link;
CREATE TRIGGER trg_ai_external_link_updated_at
BEFORE UPDATE ON idax_core.ai_external_link
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_external_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_external_link FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_external_link_admin ON idax_core.ai_external_link;
DROP POLICY IF EXISTS p_ai_external_link_app ON idax_core.ai_external_link;
CREATE POLICY p_ai_external_link_admin ON idax_core.ai_external_link FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_external_link_app ON idax_core.ai_external_link FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_external_link TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_external_link TO idax_admin;
