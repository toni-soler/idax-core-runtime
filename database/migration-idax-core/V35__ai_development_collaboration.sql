CREATE TABLE IF NOT EXISTS idax_core.ai_task_comment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    task_id UUID NOT NULL REFERENCES idax_core.ai_technical_task(id) ON DELETE CASCADE,
    author_id UUID NOT NULL,
    body_html TEXT NOT NULL,
    body_text TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS idax_core.ai_work_item_attachment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    story_id UUID REFERENCES idax_core.ai_user_story(id) ON DELETE CASCADE,
    task_id UUID REFERENCES idax_core.ai_technical_task(id) ON DELETE CASCADE,
    comment_id UUID REFERENCES idax_core.ai_task_comment(id) ON DELETE CASCADE,
    source VARCHAR(30) NOT NULL DEFAULT 'USER',
    file_name VARCHAR(255) NOT NULL,
    media_type VARCHAR(120) NOT NULL,
    content_size BIGINT NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    content BYTEA NOT NULL,
    analysis_status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
    analysis_text TEXT,
    analysis_model VARCHAR(200),
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_ai_attachment_owner CHECK (
        (story_id IS NOT NULL AND task_id IS NULL AND comment_id IS NULL)
        OR (story_id IS NULL AND task_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ix_ai_task_comment_task_created
    ON idax_core.ai_task_comment(task_id, created_at);
CREATE INDEX IF NOT EXISTS ix_ai_attachment_story_created
    ON idax_core.ai_work_item_attachment(story_id, created_at) WHERE story_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ai_attachment_task_created
    ON idax_core.ai_work_item_attachment(task_id, created_at) WHERE task_id IS NOT NULL;

DROP TRIGGER IF EXISTS trg_ai_task_comment_updated_at ON idax_core.ai_task_comment;
CREATE TRIGGER trg_ai_task_comment_updated_at
BEFORE UPDATE ON idax_core.ai_task_comment
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

DO $$
DECLARE table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['ai_task_comment', 'ai_work_item_attachment'] LOOP
    EXECUTE format('ALTER TABLE idax_core.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE idax_core.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('DROP POLICY IF EXISTS %I ON idax_core.%I', 'p_' || table_name || '_admin', table_name);
    EXECUTE format('DROP POLICY IF EXISTS %I ON idax_core.%I', 'p_' || table_name || '_app', table_name);
    EXECUTE format('CREATE POLICY %I ON idax_core.%I FOR ALL TO idax_admin USING (true) WITH CHECK (true)', 'p_' || table_name || '_admin', table_name);
    EXECUTE format('CREATE POLICY %I ON idax_core.%I FOR ALL TO idax_app USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id))', 'p_' || table_name || '_app', table_name);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.%I TO idax_app', table_name);
    EXECUTE format('GRANT ALL PRIVILEGES ON idax_core.%I TO idax_admin', table_name);
  END LOOP;
END $$;
