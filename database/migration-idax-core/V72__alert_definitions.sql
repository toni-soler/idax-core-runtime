-- V72__alert_definitions.sql
--
-- Generic, admin-configurable alert framework: one row per (tenant, alert
-- type) describing whether it is active, on what schedule, over which
-- channels (email / internal IDAX messaging / both) and to whom it is
-- delivered. Each concrete alert type is implemented in Java (registered by
-- alert_code) and reads its own tuning knobs from the params jsonb column;
-- the framework itself only owns scheduling and delivery.
CREATE TABLE IF NOT EXISTS idax_core.idax_alert_definition (
    alert_definition_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    alert_code VARCHAR(80) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    cron VARCHAR(120) NOT NULL,
    channel_email BOOLEAN NOT NULL DEFAULT FALSE,
    channel_message BOOLEAN NOT NULL DEFAULT FALSE,
    recipient_user_ids UUID[] NOT NULL DEFAULT '{}',
    recipient_group_ids TEXT[] NOT NULL DEFAULT '{}',
    recipient_emails TEXT[] NOT NULL DEFAULT '{}',
    params JSONB NOT NULL DEFAULT '{}',
    last_run_at TIMESTAMPTZ NULL,
    created_by UUID NULL REFERENCES idax_core.app_user(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_idax_alert_definition_tenant_code UNIQUE (tenant_id, alert_code)
);

CREATE TABLE IF NOT EXISTS idax_core.idax_alert_run_log (
    run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_definition_id UUID NOT NULL REFERENCES idax_core.idax_alert_definition(alert_definition_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'SUCCESS' CHECK (status IN ('SUCCESS', 'FAILED', 'SKIPPED')),
    matched_count INTEGER NOT NULL DEFAULT 0,
    -- Generic "prominent vs secondary" split each AlertCheck may report (for
    -- the orders-without-manipulation-order alert: AI-originated vs manual).
    primary_count INTEGER NOT NULL DEFAULT 0,
    secondary_count INTEGER NOT NULL DEFAULT 0,
    email_sent BOOLEAN NOT NULL DEFAULT FALSE,
    message_sent BOOLEAN NOT NULL DEFAULT FALSE,
    error_message TEXT NULL
);

CREATE INDEX IF NOT EXISTS ix_idax_alert_definition_enabled
    ON idax_core.idax_alert_definition (enabled);

CREATE INDEX IF NOT EXISTS ix_idax_alert_run_log_definition
    ON idax_core.idax_alert_run_log (alert_definition_id, started_at DESC);

ALTER TABLE idax_core.idax_alert_definition ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_alert_run_log ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_idax_alert_definition_tenant ON idax_core.idax_alert_definition;
CREATE POLICY p_idax_alert_definition_tenant ON idax_core.idax_alert_definition
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

DROP POLICY IF EXISTS p_idax_alert_run_log_tenant ON idax_core.idax_alert_run_log;
CREATE POLICY p_idax_alert_run_log_tenant ON idax_core.idax_alert_run_log
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

-- The alert scheduler runs cross-tenant under TenantContext.DbRole.IDAX_ADMIN
-- (idax_admin role) to load every enabled definition and write run logs
-- regardless of tenant, same as messaging's admin bypass (V19).
DROP POLICY IF EXISTS p_idax_alert_definition_admin ON idax_core.idax_alert_definition;
CREATE POLICY p_idax_alert_definition_admin ON idax_core.idax_alert_definition
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS p_idax_alert_run_log_admin ON idax_core.idax_alert_run_log;
CREATE POLICY p_idax_alert_run_log_admin ON idax_core.idax_alert_run_log
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_alert_definition TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_alert_run_log TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.idax_alert_definition TO idax_admin;
GRANT ALL PRIVILEGES ON idax_core.idax_alert_run_log TO idax_admin;
