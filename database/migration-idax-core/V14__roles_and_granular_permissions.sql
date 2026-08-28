CREATE TABLE idax_core.idax_permission (
    permission_code VARCHAR(160) PRIMARY KEY,
    module_key VARCHAR(80) NOT NULL,
    resource_key VARCHAR(120) NOT NULL,
    action_key VARCHAR(40) NOT NULL,
    label_key VARCHAR(200) NULL,
    api_path VARCHAR(240) NULL,
    description VARCHAR(500) NULL,
    source_type VARCHAR(40) NOT NULL DEFAULT 'IDAX',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_idax_permission_resource_action UNIQUE (resource_key, action_key)
);

CREATE INDEX ix_idax_permission_module_resource
    ON idax_core.idax_permission (module_key, resource_key, action_key);

CREATE INDEX ix_idax_permission_api_path
    ON idax_core.idax_permission (api_path)
    WHERE api_path IS NOT NULL;

CREATE TABLE idax_core.idax_role (
    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    role_key VARCHAR(80) NOT NULL,
    name VARCHAR(160) NOT NULL,
    description VARCHAR(500) NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    system_role BOOLEAN NOT NULL DEFAULT FALSE,
    source_type VARCHAR(40) NOT NULL DEFAULT 'IDAX',
    source_key VARCHAR(160) NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_idax_role_tenant
        FOREIGN KEY (tenant_id) REFERENCES idax_core.tenant (tenant_id) ON DELETE CASCADE,
    CONSTRAINT uq_idax_role_tenant_key UNIQUE (tenant_id, role_key)
);

CREATE INDEX ix_idax_role_tenant_enabled
    ON idax_core.idax_role (tenant_id, enabled, name);

CREATE UNIQUE INDEX uq_idax_role_tenant_source
    ON idax_core.idax_role (tenant_id, source_type, source_key)
    WHERE source_key IS NOT NULL;

CREATE TABLE idax_core.idax_role_permission (
    role_id UUID NOT NULL,
    permission_code VARCHAR(160) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_code),
    CONSTRAINT fk_idax_role_permission_role
        FOREIGN KEY (role_id) REFERENCES idax_core.idax_role (role_id) ON DELETE CASCADE,
    CONSTRAINT fk_idax_role_permission_permission
        FOREIGN KEY (permission_code) REFERENCES idax_core.idax_permission (permission_code) ON DELETE CASCADE
);

CREATE TABLE idax_core.idax_user_role (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id, role_id),
    CONSTRAINT fk_idax_user_role_tenant_user
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES idax_core.tenant_user (tenant_id, user_id) ON DELETE CASCADE,
    CONSTRAINT fk_idax_user_role_role
        FOREIGN KEY (role_id) REFERENCES idax_core.idax_role (role_id) ON DELETE CASCADE
);

CREATE INDEX ix_idax_user_role_user
    ON idax_core.idax_user_role (tenant_id, user_id);

CREATE TRIGGER trg_idax_permission_updated_at
BEFORE UPDATE ON idax_core.idax_permission
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE TRIGGER trg_idax_role_updated_at
BEFORE UPDATE ON idax_core.idax_role
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

ALTER TABLE idax_core.idax_role ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_role FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_role_permission ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_role_permission FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_user_role ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_user_role FORCE ROW LEVEL SECURITY;

CREATE POLICY p_idax_role_admin ON idax_core.idax_role
FOR ALL TO idax_admin USING (true) WITH CHECK (true);

CREATE POLICY p_idax_role_app ON idax_core.idax_role
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

CREATE POLICY p_idax_role_permission_admin ON idax_core.idax_role_permission
FOR ALL TO idax_admin USING (true) WITH CHECK (true);

CREATE POLICY p_idax_role_permission_app ON idax_core.idax_role_permission
FOR ALL TO idax_app
USING (
    EXISTS (
        SELECT 1 FROM idax_core.idax_role r
        WHERE r.role_id = idax_role_permission.role_id
          AND idax_core.is_current_user_member_of_tenant(r.tenant_id)
    )
)
WITH CHECK (
    EXISTS (
        SELECT 1 FROM idax_core.idax_role r
        WHERE r.role_id = idax_role_permission.role_id
          AND idax_core.is_current_user_member_of_tenant(r.tenant_id)
    )
);

CREATE POLICY p_idax_user_role_admin ON idax_core.idax_user_role
FOR ALL TO idax_admin USING (true) WITH CHECK (true);

CREATE POLICY p_idax_user_role_app ON idax_core.idax_user_role
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

GRANT SELECT, INSERT, UPDATE ON idax_core.idax_permission TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.idax_permission TO idax_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_role TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_role_permission TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_user_role TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.idax_role TO idax_admin;
GRANT ALL PRIVILEGES ON idax_core.idax_role_permission TO idax_admin;
GRANT ALL PRIVILEGES ON idax_core.idax_user_role TO idax_admin;

INSERT INTO idax_core.idax_permission
    (permission_code, module_key, resource_key, action_key, label_key, api_path, description)
VALUES
    ('system.roles.read', 'system', 'system.roles', 'read', 'permissions.actions.read', '/api/tenants', 'View roles and permissions'),
    ('system.roles.manage', 'system', 'system.roles', 'manage', 'permissions.actions.manage', '/api/tenants', 'Manage roles and permissions'),
    ('system.users.read', 'system', 'system.users', 'read', 'permissions.actions.read', '/api/tenants', 'View tenant users'),
    ('system.users.create', 'system', 'system.users', 'create', 'permissions.actions.create', '/api/tenants', 'Create tenant users'),
    ('system.users.update', 'system', 'system.users', 'update', 'permissions.actions.update', '/api/tenants', 'Update tenant users'),
    ('system.users.delete', 'system', 'system.users', 'delete', 'permissions.actions.delete', '/api/tenants', 'Delete tenant users'),
    ('system.dataareas.read', 'system', 'system.dataareas', 'read', 'permissions.actions.read', '/api/tenants', 'View tenant DataAreas'),
    ('system.dataareas.create', 'system', 'system.dataareas', 'create', 'permissions.actions.create', '/api/tenants', 'Create tenant DataAreas'),
    ('system.dataareas.update', 'system', 'system.dataareas', 'update', 'permissions.actions.update', '/api/tenants', 'Update tenant DataAreas and branding'),
    ('system.dataareas.delete', 'system', 'system.dataareas', 'delete', 'permissions.actions.delete', '/api/tenants', 'Delete tenant DataAreas'),
    ('system.audit.read', 'system', 'system.audit', 'read', 'permissions.actions.read', '/api/audit/events', 'View audit events'),
    ('profile.read', 'system', 'profile', 'read', 'permissions.actions.read', '/api/me', 'View own profile'),
    ('profile.update', 'system', 'profile', 'update', 'permissions.actions.update', '/api/me', 'Update own profile')
ON CONFLICT (permission_code) DO NOTHING;

INSERT INTO idax_core.idax_role
    (tenant_id, role_key, name, description, enabled, system_role, source_type, source_key)
SELECT t.tenant_id, seed.role_key, seed.name, seed.description, TRUE, TRUE, 'IDAX', seed.role_key
FROM idax_core.tenant t
CROSS JOIN (
    VALUES
        ('owner', 'Owner', 'Tenant owner with unrestricted access'),
        ('admin', 'Administrator', 'Tenant administrator with unrestricted access'),
        ('user', 'User', 'Standard tenant user')
) AS seed(role_key, name, description)
ON CONFLICT (tenant_id, role_key) DO NOTHING;

INSERT INTO idax_core.idax_role_permission (role_id, permission_code)
SELECT r.role_id, p.permission_code
FROM idax_core.idax_role r
CROSS JOIN idax_core.idax_permission p
WHERE r.role_key IN ('owner', 'admin')
ON CONFLICT DO NOTHING;

INSERT INTO idax_core.idax_role_permission (role_id, permission_code)
SELECT r.role_id, p.permission_code
FROM idax_core.idax_role r
JOIN idax_core.idax_permission p
  ON p.permission_code IN ('profile.read', 'profile.update')
WHERE r.role_key = 'user'
ON CONFLICT DO NOTHING;

INSERT INTO idax_core.idax_user_role (tenant_id, user_id, role_id)
SELECT tu.tenant_id, tu.user_id, r.role_id
FROM idax_core.tenant_user tu
JOIN idax_core.idax_role r
  ON r.tenant_id = tu.tenant_id
 AND r.role_key = lower(tu.role)
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION idax_core.tg_sync_legacy_tenant_role()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = idax_core, pg_temp
AS $$
BEGIN
    DELETE FROM idax_core.idax_user_role ur
    USING idax_core.idax_role r
    WHERE ur.role_id = r.role_id
      AND ur.tenant_id = NEW.tenant_id
      AND ur.user_id = NEW.user_id
      AND r.system_role
      AND r.role_key <> lower(NEW.role);

    INSERT INTO idax_core.idax_user_role (tenant_id, user_id, role_id)
    SELECT NEW.tenant_id, NEW.user_id, r.role_id
    FROM idax_core.idax_role r
    WHERE r.tenant_id = NEW.tenant_id
      AND r.system_role
      AND r.role_key = lower(NEW.role)
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_sync_legacy_tenant_role
AFTER INSERT OR UPDATE OF role ON idax_core.tenant_user
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_sync_legacy_tenant_role();

CREATE TRIGGER trg_audit_idax_role
AFTER INSERT OR UPDATE OR DELETE ON idax_core.idax_role
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();
