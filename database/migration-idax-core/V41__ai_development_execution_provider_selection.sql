-- Lets a user story or technical task override which AI execution provider (ollama/groq/gemini/
-- claude-code-slot) runs it instead of inheriting the project's model_configuration, and adds a new
-- tenant-wide default (ai_global_execution_settings) used when a project itself sets none. Additive
-- only: existing ai_development_project.model_configuration rows/shape are untouched.

-- 1) Story-level provider override, one entry per role ("developer"/"qa"/"planner") -------
ALTER TABLE idax_core.ai_user_story
    ADD COLUMN IF NOT EXISTS provider_overrides JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 2) Task-level provider override - a task has exactly one assigned_agent role, so a single
-- nullable column (not a per-role map) is enough.
ALTER TABLE idax_core.ai_technical_task
    ADD COLUMN IF NOT EXISTS provider_override VARCHAR(40);

-- 3) Tenant-wide default execution settings - exactly one row per tenant (tenant_id IS the PK, no
-- separate surrogate id, unlike every other table in this domain - this is the first true
-- singleton-per-tenant table, so there is no prior convention to match beyond the PK choice itself).
CREATE TABLE IF NOT EXISTS idax_core.ai_global_execution_settings (
    tenant_id UUID PRIMARY KEY REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    provider_configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0
);

DROP TRIGGER IF EXISTS trg_ai_global_execution_settings_updated_at ON idax_core.ai_global_execution_settings;
CREATE TRIGGER trg_ai_global_execution_settings_updated_at
BEFORE UPDATE ON idax_core.ai_global_execution_settings
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_global_execution_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_global_execution_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_global_execution_settings_admin ON idax_core.ai_global_execution_settings;
DROP POLICY IF EXISTS p_ai_global_execution_settings_app ON idax_core.ai_global_execution_settings;
CREATE POLICY p_ai_global_execution_settings_admin ON idax_core.ai_global_execution_settings FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_global_execution_settings_app ON idax_core.ai_global_execution_settings FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_global_execution_settings TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_global_execution_settings TO idax_admin;
