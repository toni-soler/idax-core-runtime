CREATE TABLE IF NOT EXISTS idax_core.app_user_preference (
    user_preference_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    last_dataareaid VARCHAR(3) NULL,
    default_dataareaid VARCHAR(3) NULL,
    default_page_size INTEGER NOT NULL DEFAULT 10,
    page_size_by_page JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_app_user_preference_user_tenant UNIQUE (user_id, tenant_id),
    CONSTRAINT ck_app_user_preference_default_page_size
        CHECK (default_page_size IN (10, 25, 50, 100, 200, 500)),
    CONSTRAINT fk_app_user_preference_user
        FOREIGN KEY (user_id)
        REFERENCES idax_core.app_user (user_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_app_user_preference_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES idax_core.tenant (tenant_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_app_user_preference_tenant_user
    ON idax_core.app_user_preference (tenant_id, user_id);

CREATE TRIGGER trg_app_user_preference_updated_at
BEFORE UPDATE ON idax_core.app_user_preference
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.app_user_preference ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.app_user_preference FORCE ROW LEVEL SECURITY;

CREATE POLICY p_app_user_preference_admin
ON idax_core.app_user_preference
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

CREATE POLICY p_app_user_preference_app
ON idax_core.app_user_preference
FOR ALL TO idax_app
USING (
    user_id = idax_core.current_app_user_id()
    AND idax_core.is_current_user_member_of_tenant(tenant_id)
)
WITH CHECK (
    user_id = idax_core.current_app_user_id()
    AND idax_core.is_current_user_member_of_tenant(tenant_id)
);

CREATE TRIGGER trg_app_user_preference_no_tenant_update
BEFORE UPDATE ON idax_core.app_user_preference
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_audit_app_user_preference
AFTER INSERT OR UPDATE OR DELETE ON idax_core.app_user_preference
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.app_user_preference TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.app_user_preference TO idax_admin;
