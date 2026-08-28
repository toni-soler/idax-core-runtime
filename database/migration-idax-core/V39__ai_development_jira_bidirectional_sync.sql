-- Adds a bidirectional Jira Cloud integration for AI Development Studio, structured the same way
-- as the Taiga integration (V37/V38): additive only, no existing column/table/row changes meaning.
-- See docs/AI_DEVELOPMENT_JIRA_BIDIRECTIONAL_SYNC_ARCHITECTURE.md for the full design.

-- 1) Project-level Jira association / sync configuration --------------------------------
ALTER TABLE idax_core.ai_development_project
    ADD COLUMN IF NOT EXISTS jira_project_key VARCHAR(40),
    ADD COLUMN IF NOT EXISTS jira_project_id VARCHAR(40),
    ADD COLUMN IF NOT EXISTS jira_sync_configuration JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 2) Story <-> Jira issue link -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS idax_core.ai_jira_link (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    story_id UUID NOT NULL REFERENCES idax_core.ai_user_story(id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL DEFAULT 'JIRA',
    jira_project_key VARCHAR(40) NOT NULL,
    jira_project_id VARCHAR(40),
    jira_issue_key VARCHAR(40) NOT NULL,
    jira_issue_id VARCHAR(40) NOT NULL,
    jira_issue_type VARCHAR(60),
    jira_url VARCHAR(500) NOT NULL,
    last_synced_status VARCHAR(40),
    origin_system VARCHAR(20) NOT NULL DEFAULT 'IDAX',
    external_revision VARCHAR(60),
    content_hash VARCHAR(64),
    last_sync_direction VARCHAR(20),
    last_synced_at TIMESTAMPTZ,
    link_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    sync_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    filtered_at TIMESTAMPTZ,
    filtered_reason VARCHAR(200),
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    correlation_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_ai_jira_link_story UNIQUE (story_id)
);

-- Identity key: tenant + provider + Jira project id + Jira issue id (never by name/key alone;
-- key/summary can be renamed in Jira, id cannot). NULLs in jira_project_id (should not normally
-- occur once resolved) do not collide with each other under a unique index.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_jira_link_external ON idax_core.ai_jira_link
    (tenant_id, provider, jira_project_id, jira_issue_id);
CREATE INDEX IF NOT EXISTS ix_ai_jira_link_tenant ON idax_core.ai_jira_link(tenant_id);

DROP TRIGGER IF EXISTS trg_ai_jira_link_updated_at ON idax_core.ai_jira_link;
CREATE TRIGGER trg_ai_jira_link_updated_at
BEFORE UPDATE ON idax_core.ai_jira_link
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_jira_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_jira_link FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_jira_link_admin ON idax_core.ai_jira_link;
DROP POLICY IF EXISTS p_ai_jira_link_app ON idax_core.ai_jira_link;
CREATE POLICY p_ai_jira_link_admin ON idax_core.ai_jira_link FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_jira_link_app ON idax_core.ai_jira_link FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_jira_link TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_jira_link TO idax_admin;

-- 3) Technical task <-> Jira subtask/linked issue ----------------------------------------
CREATE TABLE IF NOT EXISTS idax_core.ai_jira_task_link (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    task_id UUID NOT NULL REFERENCES idax_core.ai_technical_task(id) ON DELETE CASCADE,
    jira_issue_key VARCHAR(40) NOT NULL,
    jira_issue_id VARCHAR(40) NOT NULL,
    jira_url VARCHAR(500),
    link_type VARCHAR(20) NOT NULL DEFAULT 'SUBTASK',
    content_hash VARCHAR(64),
    sync_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_synced_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_ai_jira_task_link_task UNIQUE (task_id)
);
CREATE INDEX IF NOT EXISTS ix_ai_jira_task_link_tenant ON idax_core.ai_jira_task_link(tenant_id);

DROP TRIGGER IF EXISTS trg_ai_jira_task_link_updated_at ON idax_core.ai_jira_task_link;
CREATE TRIGGER trg_ai_jira_task_link_updated_at
BEFORE UPDATE ON idax_core.ai_jira_task_link
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_jira_task_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_jira_task_link FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_jira_task_link_admin ON idax_core.ai_jira_task_link;
DROP POLICY IF EXISTS p_ai_jira_task_link_app ON idax_core.ai_jira_task_link;
CREATE POLICY p_ai_jira_task_link_admin ON idax_core.ai_jira_task_link FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_jira_task_link_app ON idax_core.ai_jira_task_link FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_jira_task_link TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_jira_task_link TO idax_admin;

-- 4) QA finding <-> Jira bug/subtask ------------------------------------------------------
CREATE TABLE IF NOT EXISTS idax_core.ai_jira_finding_link (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES idax_core.ai_qa_finding(id) ON DELETE CASCADE,
    jira_issue_key VARCHAR(40) NOT NULL,
    jira_issue_id VARCHAR(40) NOT NULL,
    jira_url VARCHAR(500),
    sync_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_synced_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_ai_jira_finding_link_finding UNIQUE (finding_id)
);
CREATE INDEX IF NOT EXISTS ix_ai_jira_finding_link_tenant ON idax_core.ai_jira_finding_link(tenant_id);

DROP TRIGGER IF EXISTS trg_ai_jira_finding_link_updated_at ON idax_core.ai_jira_finding_link;
CREATE TRIGGER trg_ai_jira_finding_link_updated_at
BEFORE UPDATE ON idax_core.ai_jira_finding_link
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_jira_finding_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_jira_finding_link FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_jira_finding_link_admin ON idax_core.ai_jira_finding_link;
DROP POLICY IF EXISTS p_ai_jira_finding_link_app ON idax_core.ai_jira_finding_link;
CREATE POLICY p_ai_jira_finding_link_admin ON idax_core.ai_jira_finding_link FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_jira_finding_link_app ON idax_core.ai_jira_finding_link FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_jira_finding_link TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_jira_finding_link TO idax_admin;

-- 5) Inbound event inbox (webhook + poll), processed asynchronously and idempotently -----
CREATE TABLE IF NOT EXISTS idax_core.ai_jira_inbox_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL DEFAULT 'JIRA',
    event_source VARCHAR(20) NOT NULL,
    event_key VARCHAR(160) NOT NULL,
    external_project_id VARCHAR(40),
    external_project_key VARCHAR(40),
    external_entity_type VARCHAR(20),
    external_entity_id VARCHAR(40),
    external_entity_key VARCHAR(40),
    action VARCHAR(20),
    payload_json JSONB NOT NULL,
    correlation_id UUID NOT NULL DEFAULT gen_random_uuid(),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    last_error TEXT,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_ai_jira_inbox_event_key UNIQUE (provider, event_key)
);
CREATE INDEX IF NOT EXISTS ix_ai_jira_inbox_event_status_next_attempt
    ON idax_core.ai_jira_inbox_event(status, next_attempt_at);

DROP TRIGGER IF EXISTS trg_ai_jira_inbox_event_updated_at ON idax_core.ai_jira_inbox_event;
CREATE TRIGGER trg_ai_jira_inbox_event_updated_at
BEFORE UPDATE ON idax_core.ai_jira_inbox_event
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

-- Same rationale as ai_taiga_inbox_event: received before tenant/project resolution and
-- processed by the scheduled inbox processor running as idax_admin - not exposed to idax_app.
ALTER TABLE idax_core.ai_jira_inbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_jira_inbox_event FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_jira_inbox_event_admin ON idax_core.ai_jira_inbox_event;
CREATE POLICY p_ai_jira_inbox_event_admin ON idax_core.ai_jira_inbox_event FOR ALL TO idax_admin USING (true) WITH CHECK (true);
GRANT ALL PRIVILEGES ON idax_core.ai_jira_inbox_event TO idax_admin;

-- 6) Pending conflicts (tenant-scoped, resolved by a human from the story/project UI) ----
CREATE TABLE IF NOT EXISTS idax_core.ai_jira_conflict (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    story_id UUID NOT NULL REFERENCES idax_core.ai_user_story(id) ON DELETE CASCADE,
    jira_link_id UUID NOT NULL REFERENCES idax_core.ai_jira_link(id) ON DELETE CASCADE,
    field_name VARCHAR(60) NOT NULL,
    idax_value TEXT,
    jira_value TEXT,
    base_value TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    resolved_by UUID,
    resolved_at TIMESTAMPTZ,
    resolution_note VARCHAR(2000),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_ai_jira_conflict_tenant_story ON idax_core.ai_jira_conflict(tenant_id, story_id);
CREATE INDEX IF NOT EXISTS ix_ai_jira_conflict_status ON idax_core.ai_jira_conflict(status);

DROP TRIGGER IF EXISTS trg_ai_jira_conflict_updated_at ON idax_core.ai_jira_conflict;
CREATE TRIGGER trg_ai_jira_conflict_updated_at
BEFORE UPDATE ON idax_core.ai_jira_conflict
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_jira_conflict ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_jira_conflict FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_jira_conflict_admin ON idax_core.ai_jira_conflict;
DROP POLICY IF EXISTS p_ai_jira_conflict_app ON idax_core.ai_jira_conflict;
CREATE POLICY p_ai_jira_conflict_admin ON idax_core.ai_jira_conflict FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_jira_conflict_app ON idax_core.ai_jira_conflict FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_jira_conflict TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_jira_conflict TO idax_admin;
