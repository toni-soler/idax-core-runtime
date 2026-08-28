ALTER TABLE idax_core.tenant_legacy
    ALTER COLUMN created_at TYPE timestamptz USING created_at AT TIME ZONE 'UTC';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'uq_tenant_legacy_tenant_dataarea'
          AND conrelid = 'idax_core.tenant_legacy'::regclass
    ) THEN
        ALTER TABLE idax_core.tenant_legacy
            ADD CONSTRAINT uq_tenant_legacy_tenant_dataarea UNIQUE (tenant_id, dataareaid);
    END IF;
END $$;

CREATE TABLE idax_core.dataarea_branding (
    dataarea_branding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    dataareaid VARCHAR(3) NOT NULL,
    display_name VARCHAR(150) NULL,
    logo_image VARCHAR(500) NULL,
    primary_color VARCHAR(15) NULL,
    font_primary_color VARCHAR(15) NULL,
    header_footer_color VARCHAR(15) NULL,
    font_header_footer_color VARCHAR(15) NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_dataarea_branding_tenant_dataarea UNIQUE (tenant_id, dataareaid),
    CONSTRAINT fk_dataarea_branding_tenant_legacy
        FOREIGN KEY (tenant_id, dataareaid)
        REFERENCES idax_core.tenant_legacy (tenant_id, dataareaid)
        ON DELETE CASCADE
);

CREATE INDEX ix_dataarea_branding_tenant_enabled
    ON idax_core.dataarea_branding (tenant_id, enabled);

CREATE TRIGGER trg_dataarea_branding_updated_at
BEFORE UPDATE ON idax_core.dataarea_branding
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.dataarea_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.dataarea_branding FORCE ROW LEVEL SECURITY;

CREATE POLICY p_dataarea_branding_admin
ON idax_core.dataarea_branding
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

CREATE POLICY p_dataarea_branding_app
ON idax_core.dataarea_branding
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

CREATE TRIGGER trg_dataarea_branding_no_tenant_update
BEFORE UPDATE ON idax_core.dataarea_branding
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_audit_dataarea_branding
AFTER INSERT OR UPDATE OR DELETE ON idax_core.dataarea_branding
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.dataarea_branding TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.dataarea_branding TO idax_admin;
