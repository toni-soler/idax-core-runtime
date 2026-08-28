CREATE TABLE idax_core.tenant_legacy (
    tenant_legacy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES idax_core.tenant(tenant_id)
        ON DELETE CASCADE,

    dataareaid VARCHAR(3) NOT NULL,

    company_id BIGINT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMP NOT NULL DEFAULT now(),
    created_by UUID NULL,

    UNIQUE (dataareaid)
);

ALTER TABLE idax_core.tenant_legacy ENABLE ROW LEVEL SECURITY;

CREATE POLICY p_tenant_legacy_tenant
ON idax_core.tenant_legacy
USING (tenant_id = idax_core.current_tenant_id());
