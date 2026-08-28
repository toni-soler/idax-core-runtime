-- Real per-task claim/lease for parallel AI Development Studio task dispatch (see
-- AiTaskClaimService, idax-app). Before this migration, AiExecution.lease_owner/lease_until were
-- the only lease in the system, held for the whole duration of a single agent call and reused as
-- both "which dispatcher is currently claiming" and "which agent call currently owns this task's
-- result" - the two purposes conflated because only one task per execution was ever in flight.
-- These new columns are a SEPARATE, per-task lease: AiExecution's lease now only guards the short
-- "claim up to N tasks" step (see AiTaskClaimService.claimBatch), while a task's own lease is held
-- for the full duration of its agent call and is what AiDevelopmentQaOrchestrator checks before
-- accepting that call's result - so a second, unrelated claim of a DIFFERENT task belonging to the
-- same execution can no longer be mistaken for ownership of THIS task's still-running call.
ALTER TABLE idax_core.ai_technical_task
    ADD COLUMN IF NOT EXISTS lease_owner VARCHAR(160),
    ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS ix_ai_technical_task_claim ON idax_core.ai_technical_task
    (tenant_id, execution_id, status, lease_until);

-- How many tasks belonging to the SAME execution may hold an active lease (i.e. be running through
-- a development or QA agent call) at once. Defaults to 1: the exact serialized behaviour every
-- execution had before this migration, preserved unless a project explicitly opts into more -
-- see AiTaskClaimService.claimBatch, which never claims past this limit regardless of how many
-- tasks are otherwise ready.
ALTER TABLE idax_core.ai_development_project
    ADD COLUMN IF NOT EXISTS max_concurrent_tasks_per_execution SMALLINT NOT NULL DEFAULT 1
        CHECK (max_concurrent_tasks_per_execution BETWEEN 1 AND 20);

-- Publish-exactly-once guard (B5). Before per-task parallelism, exactly one QA task was ever in
-- flight per execution, so "this QA pass just completed and no other task is still pending QA"
-- could safely be a plain COUNT check. With several QA tasks completing concurrently, two of them
-- can each observe the same "only one left" count before either has recorded its own completion -
-- a genuine double-publish race. published_at is claimed with a single atomic conditional UPDATE
-- (AiExecutionRepository.claimPublishIfLast: "SET published_at=now() WHERE published_at IS NULL
-- AND no other task of mine is still pending QA"), so only one concurrent completion can ever win
-- it. Reset to NULL when an execution returns to SCHEDULED for a rework cycle, so the eventual next
-- QA pass can publish again.
ALTER TABLE idax_core.ai_execution ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ;

-- Generic, multi-node-safe capacity accounting for concurrency scopes that span more than one
-- execution (global across the whole deployment, per execution-provider such as
-- "provider:ollama", ...). One row per scope key, created lazily on first use by
-- AiConcurrencySlotService. current_count is only ever changed while this specific row is locked
-- (SELECT ... FOR UPDATE) by the claiming transaction, so two nodes racing to claim the last slot
-- of the same scope cannot both succeed - an in-memory counter would not survive a second app
-- instance, this row does.
CREATE TABLE IF NOT EXISTS idax_core.ai_concurrency_slot (
    scope_key VARCHAR(200) PRIMARY KEY,
    max_concurrent INT NOT NULL,
    current_count INT NOT NULL DEFAULT 0 CHECK (current_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Administrative bookkeeping, not tenant business data - a scope key such as "global" or
-- "provider:ollama" spans every tenant by design and has no tenant_id to enforce a policy
-- against. Touched only by the orchestrator, which always runs under the idax_admin role (see
-- AiOrchestrationScheduler, matching AiSprintOrchestrator's precedent) - no idax_app grant, no RLS.
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ai_concurrency_slot TO idax_admin;
