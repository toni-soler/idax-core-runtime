ALTER TABLE idax_core.ai_execution
    ADD COLUMN IF NOT EXISTS qa_cycle_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS manual_intervention_required BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS ix_ai_execution_qa_cycles
    ON idax_core.ai_execution(tenant_id, qa_cycle_count)
    WHERE status IN ('READY_FOR_QA', 'QA_IN_PROGRESS', 'QA_FAILED', 'REWORK_PLANNED');
