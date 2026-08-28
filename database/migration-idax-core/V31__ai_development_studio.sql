CREATE TABLE IF NOT EXISTS idax_core.ai_development_project (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    name VARCHAR(160) NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    default_base_branch VARCHAR(160) NOT NULL DEFAULT 'develop',
    repository_configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    model_configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    security_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_ai_development_project_tenant_name UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS idax_core.ai_user_story (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES idax_core.ai_development_project(id),
    external_reference VARCHAR(120),
    title VARCHAR(240) NOT NULL,
    description TEXT NOT NULL,
    business_context TEXT,
    status VARCHAR(40) NOT NULL,
    priority VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    acceptance_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
    requested_by UUID NOT NULL,
    require_plan_approval BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS idax_core.ai_execution (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    story_id UUID NOT NULL REFERENCES idax_core.ai_user_story(id) ON DELETE CASCADE,
    iteration INTEGER NOT NULL,
    status VARCHAR(40) NOT NULL,
    current_agent VARCHAR(30),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    paused_at TIMESTAMPTZ,
    pause_reason TEXT,
    workspace VARCHAR(500),
    branch VARCHAR(240),
    merge_request_url VARCHAR(1000),
    commit_sha VARCHAR(80),
    error_summary TEXT,
    lease_owner VARCHAR(160),
    lease_until TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_ai_execution_story_iteration UNIQUE (story_id, iteration)
);

CREATE TABLE IF NOT EXISTS idax_core.ai_technical_task (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    execution_id UUID NOT NULL REFERENCES idax_core.ai_execution(id) ON DELETE CASCADE,
    parent_task_id UUID REFERENCES idax_core.ai_technical_task(id),
    task_type VARCHAR(40) NOT NULL DEFAULT 'IMPLEMENTATION',
    title VARCHAR(240) NOT NULL,
    description TEXT NOT NULL,
    repository VARCHAR(300) NOT NULL,
    module VARCHAR(300),
    status VARCHAR(40) NOT NULL,
    priority INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    dependencies JSONB NOT NULL DEFAULT '[]'::jsonb,
    acceptance_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
    implementation_strategy JSONB NOT NULL DEFAULT '[]'::jsonb,
    test_strategy JSONB NOT NULL DEFAULT '[]'::jsonb,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    assigned_agent VARCHAR(30),
    created_by_agent VARCHAR(30),
    version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS idax_core.ai_qa_finding (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    execution_id UUID NOT NULL REFERENCES idax_core.ai_execution(id) ON DELETE CASCADE,
    task_id UUID REFERENCES idax_core.ai_technical_task(id),
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(240) NOT NULL,
    description TEXT NOT NULL,
    expected_behavior TEXT,
    actual_behavior TEXT,
    evidence TEXT,
    file_path VARCHAR(1000),
    line_number INTEGER,
    status VARCHAR(30) NOT NULL,
    source_commit_sha VARCHAR(80),
    source_merge_request_url VARCHAR(1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS idax_core.ai_agent_run (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    execution_id UUID NOT NULL REFERENCES idax_core.ai_execution(id) ON DELETE CASCADE,
    task_id UUID REFERENCES idax_core.ai_technical_task(id),
    agent_type VARCHAR(30) NOT NULL,
    model VARCHAR(200),
    prompt_template_version VARCHAR(80),
    status VARCHAR(30) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    input_summary TEXT,
    output_summary TEXT,
    error TEXT,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key VARCHAR(240) NOT NULL,
    CONSTRAINT uq_ai_agent_run_idempotency UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS idax_core.ai_agent_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    story_id UUID NOT NULL REFERENCES idax_core.ai_user_story(id) ON DELETE CASCADE,
    execution_id UUID REFERENCES idax_core.ai_execution(id) ON DELETE CASCADE,
    task_id UUID REFERENCES idax_core.ai_technical_task(id),
    sequence BIGINT NOT NULL,
    event_type VARCHAR(120) NOT NULL,
    agent_type VARCHAR(30),
    level VARCHAR(20) NOT NULL DEFAULT 'INFO',
    message TEXT NOT NULL,
    structured_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_ai_agent_event_story_sequence UNIQUE (story_id, sequence)
);

CREATE TABLE IF NOT EXISTS idax_core.ai_approval (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    execution_id UUID NOT NULL REFERENCES idax_core.ai_execution(id) ON DELETE CASCADE,
    approval_type VARCHAR(40) NOT NULL,
    status VARCHAR(30) NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    requested_by UUID,
    resolved_at TIMESTAMPTZ,
    resolved_by UUID,
    comment TEXT,
    version BIGINT NOT NULL DEFAULT 0
);

-- Reconcile installations where an earlier revision of this migration created
-- ai_execution before retry scheduling was added. CREATE TABLE IF NOT EXISTS
-- does not add columns to an already existing table.
ALTER TABLE idax_core.ai_execution
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_ai_story_tenant_status_updated ON idax_core.ai_user_story(tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS ix_ai_execution_story ON idax_core.ai_execution(story_id, iteration DESC);
CREATE INDEX IF NOT EXISTS ix_ai_execution_dispatch ON idax_core.ai_execution(status, next_attempt_at, lease_until);
CREATE INDEX IF NOT EXISTS ix_ai_task_execution_sequence ON idax_core.ai_technical_task(execution_id, sequence);
CREATE INDEX IF NOT EXISTS ix_ai_finding_execution_status ON idax_core.ai_qa_finding(execution_id, status);
CREATE INDEX IF NOT EXISTS ix_ai_event_story_sequence ON idax_core.ai_agent_event(story_id, sequence);

DROP TRIGGER IF EXISTS trg_ai_user_story_updated_at ON idax_core.ai_user_story;
CREATE TRIGGER trg_ai_user_story_updated_at
BEFORE UPDATE ON idax_core.ai_user_story
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

DO $$
DECLARE table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'ai_development_project', 'ai_user_story', 'ai_execution', 'ai_technical_task',
    'ai_qa_finding', 'ai_agent_run', 'ai_agent_event', 'ai_approval'
  ] LOOP
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

INSERT INTO idax_core.idax_permission
    (permission_code, module_key, resource_key, action_key, label_key, api_path, description)
VALUES
    ('ai.development.read', 'ai', 'ai.development', 'read', 'permissions.actions.read', '/api/ai-development', 'View AI development projects and stories'),
    ('ai.development.request', 'ai', 'ai.development', 'request', 'permissions.actions.create', '/api/ai-development', 'Create and submit AI development stories'),
    ('ai.development.develop', 'ai', 'ai.development', 'develop', 'permissions.actions.update', '/api/ai-development', 'Operate AI development executions'),
    ('ai.development.approve', 'ai', 'ai.development', 'approve', 'permissions.actions.approve', '/api/ai-development', 'Approve AI development plans'),
    ('ai.development.admin', 'ai', 'ai.development', 'admin', 'permissions.actions.manage', '/api/ai-development', 'Configure AI development projects and policies')
ON CONFLICT (permission_code) DO NOTHING;

INSERT INTO idax_core.idax_role_permission(role_id, permission_code)
SELECT r.role_id, p.permission_code
FROM idax_core.idax_role r
JOIN idax_core.idax_permission p ON p.permission_code LIKE 'ai.development.%'
WHERE r.role_key IN ('owner', 'admin')
ON CONFLICT DO NOTHING;
