-- Sprints and Scrum ceremonies for AI Development Studio. A story (PBI) optionally belongs to one
-- sprint; a sprint moves through PLANNED -> ACTIVE -> COMPLETED (or CANCELLED from either open
-- state); ceremonies are persisted, auditable events on a sprint, some requiring human approval
-- before the sprint can proceed. See docs/AI_DEVELOPMENT_STUDIO_ARCHITECTURE.md for the full design
-- and AiSprintService/AiSprintOrchestrator (idax-core/idax-app) for the rules that use this schema.

CREATE TABLE IF NOT EXISTS idax_core.ai_sprint (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES idax_core.ai_development_project(id),
    name VARCHAR(160) NOT NULL,
    goal TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'PLANNED' CHECK (status IN ('PLANNED', 'ACTIVE', 'COMPLETED', 'CANCELLED')),
    start_date DATE,
    end_date DATE,
    capacity_points INTEGER,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT ck_ai_sprint_dates CHECK (start_date IS NULL OR end_date IS NULL OR end_date >= start_date)
);
CREATE INDEX IF NOT EXISTS ix_ai_sprint_project ON idax_core.ai_sprint(tenant_id, project_id);
CREATE INDEX IF NOT EXISTS ix_ai_sprint_status ON idax_core.ai_sprint(tenant_id, status);

-- A PBI (product backlog item) is an AiUserStory that may be assigned to a sprint; NULL means it is
-- still in the backlog. ON DELETE SET NULL: deleting a sprint (an admin action on a PLANNED/CANCELLED
-- sprint only - see AiSprintService) returns its stories to the backlog rather than orphaning them.
ALTER TABLE idax_core.ai_user_story
    ADD COLUMN IF NOT EXISTS sprint_id UUID REFERENCES idax_core.ai_sprint(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS ix_ai_user_story_sprint ON idax_core.ai_user_story(sprint_id);

CREATE TABLE IF NOT EXISTS idax_core.ai_sprint_ceremony (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    sprint_id UUID NOT NULL REFERENCES idax_core.ai_sprint(id) ON DELETE CASCADE,
    ceremony_type VARCHAR(30) NOT NULL CHECK (ceremony_type IN
        ('BACKLOG_REFINEMENT', 'SPRINT_PLANNING', 'DAILY_STANDUP', 'SPRINT_REVIEW', 'SPRINT_RETROSPECTIVE', 'SPRINT_COMPLETION')),
    status VARCHAR(20) NOT NULL DEFAULT 'COMPLETED' CHECK (status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'COMPLETED')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    summary TEXT,
    structured_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    requires_human_approval BOOLEAN NOT NULL DEFAULT false,
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_ai_sprint_ceremony_sprint ON idax_core.ai_sprint_ceremony(tenant_id, sprint_id, occurred_at);
-- Enforces "at most one DAILY_STANDUP per sprint per calendar day" at the database level, not only
-- in application code - the actual idempotency guarantee AiSprintOrchestrator's automation depends
-- on, since a second scheduler node racing the first must fail loudly (unique violation) rather than
-- silently create a duplicate standup.
--
-- Anchored to UTC via AT TIME ZONE rather than a bare ::date cast: a plain `occurred_at::date` on a
-- TIMESTAMPTZ column is timezone-dependent (it implicitly uses the current session's TimeZone
-- setting), which Postgres refuses to index at all ("functions in index expression must be marked
-- IMMUTABLE") - so the bare-cast form never actually created this index on any real Postgres
-- instance; every fresh migration run failed here, not merely lost the idempotency guarantee.
-- `occurred_at AT TIME ZONE 'UTC'` converts to the wall-clock TIMESTAMP that instant represents in a
-- fixed, literal zone, which Postgres does accept as IMMUTABLE - and matches
-- AiSprintOrchestrator.recordDailyStandupIfDue's own dayStart/dayEnd window, which is already
-- computed from OffsetDateTime.now() (UTC-normalized), not session-local time.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_sprint_ceremony_daily_standup ON idax_core.ai_sprint_ceremony
    (tenant_id, sprint_id, ((occurred_at AT TIME ZONE 'UTC')::date)) WHERE ceremony_type = 'DAILY_STANDUP';

DROP TRIGGER IF EXISTS trg_ai_sprint_updated_at ON idax_core.ai_sprint;
CREATE TRIGGER trg_ai_sprint_updated_at
BEFORE UPDATE ON idax_core.ai_sprint
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

DO $$
DECLARE table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['ai_sprint', 'ai_sprint_ceremony'] LOOP
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
