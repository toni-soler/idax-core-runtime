-- Real Product Owner and Scrum Master agent content (Section C of this increment). Before this
-- migration PRODUCT_OWNER/SCRUM_MASTER existed only as AiAgentType enum values with no behaviour
-- (see that enum's own Javadoc) - Sprint ceremony automation was purely deterministic status-diff
-- logic (AiSprintOrchestrator's daily standup).
--
-- Agent-generated ceremony content is additive, never a replacement for the deterministic summary
-- a ceremony already carries (AiSprintService.recordCeremony / AiSprintOrchestrator's daily
-- standup): the agent_* columns are all nullable, so a ceremony with no agent enrichment - or one
-- whose enrichment call failed - still has its full deterministic minimum. Re-enrichment overwrites
-- these columns on the SAME ceremony row rather than creating a new one, satisfying "regeneration
-- without duplicating the canonical ceremony" without needing a separate history table.
ALTER TABLE idax_core.ai_sprint_ceremony
    ADD COLUMN IF NOT EXISTS agent_type VARCHAR(20) CHECK (agent_type IS NULL OR agent_type IN ('PRODUCT_OWNER', 'SCRUM_MASTER')),
    ADD COLUMN IF NOT EXISTS agent_summary TEXT,
    ADD COLUMN IF NOT EXISTS agent_structured_payload JSONB,
    ADD COLUMN IF NOT EXISTS agent_model VARCHAR(120),
    ADD COLUMN IF NOT EXISTS agent_provider VARCHAR(40),
    ADD COLUMN IF NOT EXISTS agent_prompt_version VARCHAR(40),
    ADD COLUMN IF NOT EXISTS agent_generated_at TIMESTAMPTZ;

-- A Product Owner agent's analysis of one story's Definition of Ready: proposed acceptance
-- criteria/story points/business value and any ambiguity it found, always a PROPOSAL a human must
-- accept or reject - the agent never writes these values onto the story itself (C1's "no puede
-- modificar código" / "no puede cambiar silenciosamente el alcance" restrictions: a story's actual
-- acceptance criteria/points only ever change through the existing human-facing story update path).
CREATE TABLE IF NOT EXISTS idax_core.ai_product_owner_review (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    story_id UUID NOT NULL REFERENCES idax_core.ai_user_story(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'PROPOSED' CHECK (status IN ('PROPOSED', 'ACCEPTED', 'REJECTED')),
    definition_of_ready_issues JSONB NOT NULL DEFAULT '[]'::jsonb,
    proposed_acceptance_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
    proposed_story_points INTEGER,
    proposed_business_value INTEGER,
    rationale TEXT,
    model VARCHAR(120),
    provider VARCHAR(40),
    prompt_version VARCHAR(40),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by UUID,
    decided_at TIMESTAMPTZ,
    decision_note TEXT,
    version BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_ai_product_owner_review_story ON idax_core.ai_product_owner_review(tenant_id, story_id, created_at);

ALTER TABLE idax_core.ai_product_owner_review ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_product_owner_review FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_product_owner_review_admin ON idax_core.ai_product_owner_review;
DROP POLICY IF EXISTS p_ai_product_owner_review_app ON idax_core.ai_product_owner_review;
CREATE POLICY p_ai_product_owner_review_admin ON idax_core.ai_product_owner_review FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_product_owner_review_app ON idax_core.ai_product_owner_review FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_product_owner_review TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_product_owner_review TO idax_admin;
