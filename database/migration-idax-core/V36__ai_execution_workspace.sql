CREATE TABLE IF NOT EXISTS idax_core.ai_execution_workspace (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    execution_id UUID NOT NULL REFERENCES idax_core.ai_execution(id) ON DELETE CASCADE,
    repository_id VARCHAR(80) NOT NULL,
    workspace VARCHAR(500),
    commit_sha VARCHAR(80),
    merge_request_url VARCHAR(1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_ai_execution_workspace_repo UNIQUE (execution_id, repository_id)
);

CREATE INDEX IF NOT EXISTS ix_ai_execution_workspace_execution
    ON idax_core.ai_execution_workspace(execution_id);

DROP TRIGGER IF EXISTS trg_ai_execution_workspace_updated_at ON idax_core.ai_execution_workspace;
CREATE TRIGGER trg_ai_execution_workspace_updated_at
BEFORE UPDATE ON idax_core.ai_execution_workspace
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_execution_workspace ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_execution_workspace FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_ai_execution_workspace_admin ON idax_core.ai_execution_workspace;
DROP POLICY IF EXISTS p_ai_execution_workspace_app ON idax_core.ai_execution_workspace;
CREATE POLICY p_ai_execution_workspace_admin ON idax_core.ai_execution_workspace FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_execution_workspace_app ON idax_core.ai_execution_workspace FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_execution_workspace TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_execution_workspace TO idax_admin;
