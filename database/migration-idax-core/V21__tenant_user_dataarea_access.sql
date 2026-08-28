CREATE TABLE IF NOT EXISTS idax_core.tenant_user_dataarea (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    dataareaid VARCHAR(3) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, user_id, dataareaid),
    CONSTRAINT fk_tenant_user_dataarea_user
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES idax_core.tenant_user (tenant_id, user_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_tenant_user_dataarea_dataarea
        FOREIGN KEY (tenant_id, dataareaid)
        REFERENCES idax_core.tenant_legacy (tenant_id, dataareaid)
        ON DELETE CASCADE,
    CONSTRAINT ck_tenant_user_dataarea_len
        CHECK (char_length(dataareaid) = 3)
);

CREATE INDEX IF NOT EXISTS ix_tenant_user_dataarea_user
    ON idax_core.tenant_user_dataarea (tenant_id, user_id);

ALTER TABLE idax_core.tenant_user_dataarea ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.tenant_user_dataarea FORCE ROW LEVEL SECURITY;

CREATE POLICY p_tenant_user_dataarea_admin
ON idax_core.tenant_user_dataarea
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

CREATE POLICY p_tenant_user_dataarea_app
ON idax_core.tenant_user_dataarea
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

CREATE TRIGGER trg_tenant_user_dataarea_no_tenant_update
BEFORE UPDATE ON idax_core.tenant_user_dataarea
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_audit_tenant_user_dataarea
AFTER INSERT OR UPDATE OR DELETE ON idax_core.tenant_user_dataarea
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.tenant_user_dataarea TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.tenant_user_dataarea TO idax_admin;
