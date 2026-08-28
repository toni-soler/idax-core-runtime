-- Typed relationships between AI Development Studio work items (stories and technical tasks). The
-- BLOCKS type is what AiDevelopmentQaOrchestrator's task readiness check (idax-app) reads to skip
-- a task whose predecessor has not finished yet. See docs/AI_DEVELOPMENT_STUDIO_ARCHITECTURE.md.
--
-- Relationships are polymorphic (source/target can each be a STORY or a TASK) so a single model
-- covers backlog-level relationships (e.g. one story BLOCKS another) and execution-level ones (one
-- task BLOCKS another within the same story's plan) without duplicating the table. Referential
-- integrity across that polymorphism is enforced in the application layer (AiWorkItemRelationshipService),
-- the same approach already used for AiAgentEvent's optional taskId - a plain FK cannot point at
-- "whichever of two tables this row's type says", and a trigger duplicating that check in SQL would
-- just be the same validation twice, with the attendant risk of the two copies drifting apart.
--
-- Only the canonical direction of each type is ever stored (BLOCKS, PARENT_OF, RELATES_TO,
-- DUPLICATES, PREDECESSOR_OF) - the inverse (IS_BLOCKED_BY, CHILD_OF, RELATES_TO, IS_DUPLICATED_BY,
-- SUCCESSOR_OF) is derived at read time by swapping source/target, never written as a second row.
-- Storing both directions would let them silently disagree after a partial update; deriving one from
-- the other cannot.
CREATE TABLE IF NOT EXISTS idax_core.ai_work_item_relationship (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    source_type VARCHAR(10) NOT NULL CHECK (source_type IN ('STORY', 'TASK')),
    source_id UUID NOT NULL,
    relationship_type VARCHAR(20) NOT NULL CHECK (relationship_type IN
        ('BLOCKS', 'PARENT_OF', 'RELATES_TO', 'DUPLICATES', 'PREDECESSOR_OF')),
    target_type VARCHAR(10) NOT NULL CHECK (target_type IN ('STORY', 'TASK')),
    target_id UUID NOT NULL,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT ck_ai_work_item_relationship_no_self CHECK (NOT (source_type = target_type AND source_id = target_id))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_work_item_relationship ON idax_core.ai_work_item_relationship
    (tenant_id, source_type, source_id, relationship_type, target_type, target_id);
CREATE INDEX IF NOT EXISTS ix_ai_work_item_relationship_source ON idax_core.ai_work_item_relationship
    (tenant_id, source_type, source_id);
CREATE INDEX IF NOT EXISTS ix_ai_work_item_relationship_target ON idax_core.ai_work_item_relationship
    (tenant_id, target_type, target_id);

DROP TRIGGER IF EXISTS trg_ai_work_item_relationship_updated_at ON idax_core.ai_work_item_relationship;
CREATE TRIGGER trg_ai_work_item_relationship_updated_at
BEFORE UPDATE ON idax_core.ai_work_item_relationship
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.ai_work_item_relationship ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.ai_work_item_relationship FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_ai_work_item_relationship_admin ON idax_core.ai_work_item_relationship;
DROP POLICY IF EXISTS p_ai_work_item_relationship_app ON idax_core.ai_work_item_relationship;
CREATE POLICY p_ai_work_item_relationship_admin ON idax_core.ai_work_item_relationship FOR ALL TO idax_admin USING (true) WITH CHECK (true);
CREATE POLICY p_ai_work_item_relationship_app ON idax_core.ai_work_item_relationship FOR ALL TO idax_app
    USING (idax_core.is_current_user_member_of_tenant(tenant_id)) WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_work_item_relationship TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.ai_work_item_relationship TO idax_admin;
