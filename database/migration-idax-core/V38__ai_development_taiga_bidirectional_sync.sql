-- Evolves the outbound-only Taiga sync (V37) into a bidirectional sync. Additive only:
-- no existing column is dropped/renamed and no existing row's meaning changes. See
-- docs/AI_DEVELOPMENT_TAIGA_BIDIRECTIONAL_SYNC_ARCHITECTURE.md for the full design.

-- 1) Project-level sync configuration ------------------------------------------------
ALTER TABLE idax_core.ai_development_project
    ADD COLUMN IF NOT EXISTS taiga_project_id INTEGER,
    ADD COLUMN IF NOT EXISTS taiga_sync_configuration JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 2) Story provenance / tags ----------------------------------------------------------
-- requested_by is relaxed to nullable: a story imported from Taiga has no IDAX app user
-- who requested it - NULL means "originated externally", not "unknown data".
ALTER TABLE idax_core.ai_user_story
    ALTER COLUMN requested_by DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS origin_system VARCHAR(20) NOT NULL DEFAULT 'IDAX',
    ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 3) External link tracking (extends the existing ai_taiga_link table) ----------------
ALTER TABLE idax_core.ai_taiga_link
    ADD COLUMN IF NOT EXISTS provider VARCHAR(20) NOT NULL DEFAULT 'TAIGA',
    ADD COLUMN IF NOT EXISTS taiga_project_id INTEGER,
    ADD COLUMN IF NOT EXISTS external_entity_type VARCHAR(20) NOT NULL DEFAULT 'USER_STORY',
    ADD COLUMN IF NOT EXISTS origin_system VARCHAR(20) NOT NULL DEFAULT 'IDAX',
    ADD COLUMN IF NOT EXISTS external_revision VARCHAR(60),
    ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS last_sync_direction VARCHAR(20),
    ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS link_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN IF NOT EXISTS filtered_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS filtered_reason VARCHAR(200),
    ADD COLUMN IF NOT EXISTS last_error TEXT,
    ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS correlation_id UUID;

-- Identity key for dedup on both directions: tenant + provider + externalProjectId +
-- externalEntityType + externalEntityId (taiga_us_id is the externalEntityId - kept
-- under its existing name for backward compatibility). NULLs in taiga_project_id (rows
-- created before this migration) do not collide with each other under a unique index;
-- they are backfilled lazily the next time that link is synced.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_taiga_link_external ON idax_core.ai_taiga_link
    (tenant_id, provider, taiga_project_id, external_entity_type, taiga_us_id);

-- 4) Story-level comments (Taiga comments live on the user story, not on an IDAX task) -
-- author_id is relaxed to nullable: a comment imported from Taiga has no IDAX app user
-- author - NULL means "external author" (see external_author for the Taiga username).
ALTER TABLE idax_core.ai_task_comment
    ALTER COLUMN task_id DROP NOT NULL,
    ALTER COLUMN author_id DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS story_id UUID REFERENCES idax_core.ai_user_story(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS origin_system VARCHAR(20) NOT NULL DEFAULT 'IDAX',
    ADD COLUMN IF NOT EXISTS provider VARCHAR(20),
    ADD COLUMN IF NOT EXISTS external_comment_id VARCHAR(60),
    ADD COLUMN IF NOT EXISTS external_author VARCHAR(160),
    ADD COLUMN IF NOT EXISTS external_date TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS comment_kind VARCHAR(20) NOT NULL DEFAULT 'USER';

ALTER TABLE idax_core.ai_task_comment
    DROP CONSTRAINT IF EXISTS ck_ai_task_comment_owner;
ALTER TABLE idax_core.ai_task_comment
    ADD CONSTRAINT ck_ai_task_comment_owner CHECK ((task_id IS NOT NULL) <> (story_id IS NOT NULL));

CREATE INDEX IF NOT EXISTS ix_ai_task_comment_story ON idax_core.ai_task_comment(story_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_task_comment_external ON idax_core.ai_task_comment
    (provider, external_comment_id) WHERE provider IS NOT NULL AND external_comment_id IS NOT NULL;

-- 5) Attachment provenance --------------------------------------------------------------
ALTER TABLE idax_core.ai_work_item_attachment
    ADD COLUMN IF NOT EXISTS origin_system VARCHAR(20) NOT NULL DEFAULT 'IDAX',
    ADD COLUMN IF NOT EXISTS provider VARCHAR(20),
    ADD COLUMN IF NOT EXISTS external_attachment_id VARCHAR(60);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_work_item_attachment_external ON idax_core.ai_work_item_attachment
    (provider, external_attachment_id) WHERE provider IS NOT NULL AND external_attachment_id IS NOT NULL;

-- 6) Inbound event inbox (webhook + poll), processed asynchronously and idempotently ---
CREATE TABLE IF NOT EXISTS idax_core.ai_taiga_inbox_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL DEFAULT 'TAIGA',
    event_source VARCHAR(20) NOT NULL,
    event_key VARCHAR(160) NOT NULL,
    external_project_id INTEGER,
    external_entity_type VARCHAR(20),
    external_entity_id INTEGER,
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
    CONSTRAINT uq_ai_taiga_inbox_event_key UNIQUE (provider, event_key)
);

CREATE INDEX IF NOT EXISTS ix_ai_taiga_inbox_event_status_next_attempt
    ON idax_core.ai_taiga_inbox_event(status, next_attempt_at);

DROP TRIGGER IF EXISTS trg_ai_taiga_inbox_event_updated_at ON idax_core.ai_taiga_inbox_event;
CREATE TRIGGER trg_ai_taiga_inbox_event_updated_at
BEFORE UPDATE ON idax_core.ai_taiga_inbox_event
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

-- Received before tenant/project resolution and processed by the scheduled inbox
-- processor running as idax_admin (same pattern as AiTaigaSyncScheduler), so this table
-- is intentionally not exposed to the idax_app role at all: no per-request user context
-- exists for an inbound webhook delivery, and the app never needs to read raw inbox rows
-- (conflicts/errors surface through ai_taiga_conflict / ai_taiga_link instead).
ALTER TABLE idax_core.ai_taiga_inbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_taiga_inbox_event FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_taiga_inbox_event_admin ON idax_core.ai_taiga_inbox_event;
CREATE POLICY p_ai_taiga_inbox_event_admin ON idax_core.ai_taiga_inbox_event FOR ALL TO idax_admin USING (true) WITH CHECK (true);
GRANT ALL PRIVILEGES ON idax_core.ai_taiga_inbox_event TO idax_admin;

-- 7) Pending conflicts (tenant-scoped, resolved by a human from the story/project UI) --
CREATE TABLE IF NOT EXISTS idax_core.ai_taiga_conflict (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    story_id UUID NOT NULL REFERENCES idax_core.ai_user_story(id) ON DELETE CASCADE,
    taiga_link_id UUID NOT NULL REFERENCES idax_core.ai_taiga_link(id) ON DELETE CASCADE,
    field_name VARCHAR(60) NOT NULL,
    idax_value TEXT,
    taiga_value TEXT,
    base_value TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    resolved_by UUID,
    resolved_at TIMESTAMPTZ,
    resolution_note VARCHAR(2000),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_ai_taiga_conflict_tenant_story ON idax_core.ai_taiga_conflict(tenant_id, story_id);
CREATE INDEX IF NOT EXISTS ix_ai_taiga_conflict_status ON idax_core.ai_taiga_conflict(status);

DROP TRIGGER IF EXISTS trg_ai_taiga_conflict_updated_at ON idax_core.ai_taiga_conflict;
CREATE TRIGGER trg_ai_taiga_conflict_updated_at
BEFORE UPDATE ON idax_core.ai_taiga_conflict
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_taiga_conflict ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_taiga_conflict FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_taiga_conflict_admin ON idax_core.ai_taiga_conflict;
DROP POLICY IF EXISTS p_ai_taiga_conflict_app ON idax_core.ai_taiga_conflict;
CREATE POLICY p_ai_taiga_conflict_admin ON idax_core.ai_taiga_conflict FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_taiga_conflict_app ON idax_core.ai_taiga_conflict FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_taiga_conflict TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_taiga_conflict TO idax_admin;
