-- V75__saved_filter_alerts.sql
--
-- Lets any user turn a filter they already have applied on a legacy grid
-- into a recurring alert emailing/messaging the matching rows. Distinct
-- from idax_alert_definition (one row per tenant+alertCode, admin-owned,
-- code-registered types) since this is many rows per tenant, one per
-- user-created filter, and starts out unusable until an owner/admin
-- approves it (status PENDING -> APPROVED/REJECTED).
CREATE TABLE IF NOT EXISTS idax_core.idax_saved_filter_alert (
    saved_filter_alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    entity_key VARCHAR(120) NOT NULL,
    name VARCHAR(160) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    filters JSONB NOT NULL DEFAULT '{}',
    columns TEXT[] NOT NULL DEFAULT '{}',
    cron VARCHAR(120) NOT NULL,
    channel_email BOOLEAN NOT NULL DEFAULT FALSE,
    channel_message BOOLEAN NOT NULL DEFAULT FALSE,
    recipient_user_ids UUID[] NOT NULL DEFAULT '{}',
    recipient_group_ids TEXT[] NOT NULL DEFAULT '{}',
    recipient_emails TEXT[] NOT NULL DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    requested_by UUID NOT NULL REFERENCES idax_core.app_user(user_id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_by UUID NULL REFERENCES idax_core.app_user(user_id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ NULL,
    resolution_comment TEXT NULL,
    last_run_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_idax_saved_filter_alert_tenant_status
    ON idax_core.idax_saved_filter_alert (tenant_id, status);

CREATE INDEX IF NOT EXISTS ix_idax_saved_filter_alert_requested_by
    ON idax_core.idax_saved_filter_alert (tenant_id, requested_by);

ALTER TABLE idax_core.idax_saved_filter_alert ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_idax_saved_filter_alert_tenant ON idax_core.idax_saved_filter_alert;
CREATE POLICY p_idax_saved_filter_alert_tenant ON idax_core.idax_saved_filter_alert
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

-- The alert scheduler runs cross-tenant under TenantContext.DbRole.IDAX_ADMIN,
-- same as idax_alert_definition (V61).
DROP POLICY IF EXISTS p_idax_saved_filter_alert_admin ON idax_core.idax_saved_filter_alert;
CREATE POLICY p_idax_saved_filter_alert_admin ON idax_core.idax_saved_filter_alert
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_saved_filter_alert TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.idax_saved_filter_alert TO idax_admin;

-- alerts.request: propose a saved-filter alert (any tenant user). Approving/
-- rejecting reuses alerts.manage (V62), already owner/admin-only.
INSERT INTO idax_core.idax_permission
    (permission_code, module_key, resource_key, action_key, label_key, api_path, description)
VALUES
    ('alerts.request', 'system', 'alerts', 'request', 'permissions.actions.request',
     '/api/core/alerts/saved-filters', 'Turn a saved grid filter into a recurring alert (needs admin approval)')
ON CONFLICT (permission_code) DO NOTHING;

INSERT INTO idax_core.idax_role_permission (role_id, permission_code)
SELECT r.role_id, p.permission_code
FROM idax_core.idax_role r
JOIN idax_core.idax_permission p
  ON p.permission_code = 'alerts.request'
WHERE r.role_key IN ('owner', 'admin', 'user')
ON CONFLICT DO NOTHING;
