-- Optional outbound synchronization of AI Development Studio stories into a Taiga project.
-- Taiga is never a source of truth (see docs/AI_DEVELOPMENT_STUDIO_ARCHITECTURE.md): this only
-- tracks the mapping and last-synced status needed to keep an external Taiga user story mirrored.
ALTER TABLE idax_core.ai_development_project
    ADD COLUMN IF NOT EXISTS taiga_project_slug VARCHAR(160);

CREATE TABLE IF NOT EXISTS idax_core.ai_taiga_link (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    story_id UUID NOT NULL REFERENCES idax_core.ai_user_story(id) ON DELETE CASCADE,
    taiga_project_slug VARCHAR(160) NOT NULL,
    taiga_us_id INTEGER NOT NULL,
    taiga_us_ref INTEGER NOT NULL,
    taiga_url VARCHAR(500) NOT NULL,
    last_synced_status VARCHAR(40) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_ai_taiga_link_story UNIQUE (story_id)
);

CREATE INDEX IF NOT EXISTS ix_ai_taiga_link_tenant ON idax_core.ai_taiga_link(tenant_id);

DROP TRIGGER IF EXISTS trg_ai_taiga_link_updated_at ON idax_core.ai_taiga_link;
CREATE TRIGGER trg_ai_taiga_link_updated_at
BEFORE UPDATE ON idax_core.ai_taiga_link
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_taiga_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_taiga_link FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_ai_taiga_link_admin ON idax_core.ai_taiga_link;
DROP POLICY IF EXISTS p_ai_taiga_link_app ON idax_core.ai_taiga_link;
CREATE POLICY p_ai_taiga_link_admin ON idax_core.ai_taiga_link FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_taiga_link_app ON idax_core.ai_taiga_link FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_taiga_link TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_taiga_link TO idax_admin;
