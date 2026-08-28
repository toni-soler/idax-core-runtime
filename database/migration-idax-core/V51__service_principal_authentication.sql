CREATE TABLE idax_core.service_principal (
    service_principal_id UUID PRIMARY KEY,
    client_id VARCHAR(120) NOT NULL UNIQUE,
    display_name VARCHAR(200) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE idax_core.service_principal_credential (
    credential_id UUID PRIMARY KEY,
    service_principal_id UUID NOT NULL REFERENCES idax_core.service_principal(service_principal_id),
    secret_hash TEXT NOT NULL,
    active_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by VARCHAR(200)
);
CREATE INDEX ix_service_principal_credential_principal
    ON idax_core.service_principal_credential(service_principal_id);

CREATE TABLE idax_core.service_principal_grant (
    grant_id UUID PRIMARY KEY,
    service_principal_id UUID NOT NULL REFERENCES idax_core.service_principal(service_principal_id),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id),
    audience VARCHAR(120) NOT NULL,
    permissions TEXT[] NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    active_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by VARCHAR(200),
    CONSTRAINT uq_service_principal_grant UNIQUE(service_principal_id, tenant_id, audience),
    CONSTRAINT ck_service_principal_grant_audience CHECK (audience <> '' AND audience <> '*'),
    CONSTRAINT ck_service_principal_grant_permissions CHECK (cardinality(permissions) > 0)
);
CREATE INDEX ix_service_principal_grant_tenant
    ON idax_core.service_principal_grant(tenant_id, service_principal_id);

CREATE TABLE idax_core.service_principal_audit (
    audit_id UUID PRIMARY KEY,
    event_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    service_principal_id UUID,
    client_id VARCHAR(120),
    tenant_id UUID,
    audience VARCHAR(120),
    event_type VARCHAR(80) NOT NULL,
    result VARCHAR(20) NOT NULL,
    actor VARCHAR(200),
    reason_code VARCHAR(120)
);
CREATE INDEX ix_service_principal_audit_principal_time ON idax_core.service_principal_audit(service_principal_id, event_time);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idax_service_auth') THEN
        CREATE ROLE idax_service_auth NOINHERIT;
    END IF;
END $$;
GRANT idax_service_auth TO idax_backend;
GRANT USAGE ON SCHEMA idax_core TO idax_service_auth;

ALTER TABLE idax_core.service_principal DISABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.service_principal_credential DISABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.service_principal_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.service_principal_grant FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.service_principal_audit DISABLE ROW LEVEL SECURITY;

CREATE POLICY service_principal_grant_tenant_isolation ON idax_core.service_principal_grant
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- V1 grants CRUD on future idax_core tables to idax_app through default privileges. SERVICE
-- credentials and lifecycle state are not ordinary application data, so remove those inherited
-- privileges explicitly. The tenant-scoped grant remains read-only for idax_app and is filtered
-- by the forced RLS policy above.
REVOKE ALL ON idax_core.service_principal FROM idax_app;
REVOKE ALL ON idax_core.service_principal_credential FROM idax_app;
REVOKE ALL ON idax_core.service_principal_grant FROM idax_app;
REVOKE ALL ON idax_core.service_principal_audit FROM idax_app;
GRANT SELECT ON idax_core.service_principal_grant TO idax_app;

GRANT SELECT, INSERT, UPDATE ON idax_core.service_principal TO idax_admin;
GRANT SELECT, INSERT, UPDATE ON idax_core.service_principal_credential TO idax_admin;
GRANT SELECT, INSERT, UPDATE ON idax_core.service_principal_grant TO idax_admin;
GRANT SELECT, INSERT ON idax_core.service_principal_audit TO idax_admin;

GRANT SELECT ON idax_core.service_principal TO idax_service_auth;
GRANT SELECT ON idax_core.service_principal_credential TO idax_service_auth;
GRANT SELECT ON idax_core.service_principal_grant TO idax_service_auth;
GRANT SELECT ON idax_core.tenant TO idax_service_auth;
GRANT INSERT ON idax_core.service_principal_audit TO idax_service_auth;
