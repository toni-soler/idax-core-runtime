-- Gives the outbound Taiga/Jira/Azure DevOps push schedulers durable, DB-backed pending/backoff
-- state, fixing two related defects:
--
-- 1) A story's very first outbound push had nowhere to record failure state until it succeeded
--    once: the link row (ai_taiga_link/ai_jira_link/ai_azure_devops_link) was only ever created
--    AFTER a successful external create call, so a failure on that very first attempt only lived in
--    an in-memory retry map with no durability across a restart and no visibility anywhere in the
--    UI (there was simply no row to show lastError/attemptCount on).
-- 2) The outbound schedulers picked their next batch of candidate stories ordered by the story's
--    own updated_at - a column the sync process itself never touches. Once a tenant had more
--    syncable stories than one page, the same oldest-by-updated_at stories permanently occupied
--    page 0 of every tick and newer stories past that page were never reached, regardless of how
--    many ticks ran. A durable next_attempt_at the scheduler query can order and filter by (instead
--    of an in-memory map keyed by story id, invisible to the SQL query) fixes both: a link now
--    exists from the first attempt onward, and readiness is decided in the database, not in memory.
--
-- Jira and Azure DevOps already carry the sync_status/attempt_count lifecycle (added when their
-- integrations were built) but their orchestrators never actually created the link row before the
-- first external call either - this migration only adds what both were still missing
-- (next_attempt_at) and relaxes the external-identity columns to nullable so a PENDING row can be
-- saved before that identity is known. Taiga did not yet have sync_status/attempt_count at all;
-- added here so all three providers share one shape.

-- Only taiga_us_id needs to become nullable: it is the column uq_ai_taiga_link_external's
-- uniqueness depends on, so a shared non-null placeholder (e.g. 0) would make two PENDING rows in
-- the same Taiga project collide, whereas a unique index treats every NULL as distinct from every
-- other NULL. taiga_us_ref/taiga_url have no such constraint and keep using their existing 0/""
-- "not assigned yet" convention (see AiTaigaLink.taigaUsRef/taigaUrl).
ALTER TABLE idax_core.ai_taiga_link
    ALTER COLUMN taiga_us_id DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS sync_status VARCHAR(20) NOT NULL DEFAULT 'SYNCED',
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;
-- Every row that already exists in this table predates this migration and therefore represents an
-- already-completed sync; only rows the application inserts after this migration should ever
-- default to PENDING.
ALTER TABLE idax_core.ai_taiga_link ALTER COLUMN sync_status SET DEFAULT 'PENDING';

ALTER TABLE idax_core.ai_jira_link
    ALTER COLUMN jira_issue_key DROP NOT NULL,
    ALTER COLUMN jira_issue_id DROP NOT NULL,
    ALTER COLUMN jira_url DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

ALTER TABLE idax_core.ai_azure_devops_link
    ALTER COLUMN azure_devops_work_item_id DROP NOT NULL,
    ALTER COLUMN azure_devops_url DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

-- Postgres unique indexes already treat NULLs as pairwise-distinct, so several PENDING rows with
-- no external identity yet never collide with each other under the existing uq_*_external indexes
-- (same reasoning already applied to taiga_project_id when it was introduced in V38).
CREATE INDEX IF NOT EXISTS ix_ai_taiga_link_next_attempt ON idax_core.ai_taiga_link(next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_ai_jira_link_next_attempt ON idax_core.ai_jira_link(next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_ai_azure_devops_link_next_attempt ON idax_core.ai_azure_devops_link(next_attempt_at);
