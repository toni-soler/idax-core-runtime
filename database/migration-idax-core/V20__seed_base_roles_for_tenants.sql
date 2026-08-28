CREATE OR REPLACE FUNCTION idax_core.ensure_base_roles_for_tenant(p_tenant_id UUID)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = idax_core, pg_temp
AS $$
BEGIN
    IF p_tenant_id IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO idax_core.idax_role
        (tenant_id, role_key, name, description, enabled, system_role, source_type, source_key)
    SELECT p_tenant_id, seed.role_key, seed.name, seed.description, TRUE, TRUE, 'IDAX', seed.role_key
    FROM (
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
    WHERE r.tenant_id = p_tenant_id
      AND r.system_role
      AND r.role_key IN ('owner', 'admin')
    ON CONFLICT DO NOTHING;

    INSERT INTO idax_core.idax_role_permission (role_id, permission_code)
    SELECT r.role_id, p.permission_code
    FROM idax_core.idax_role r
    JOIN idax_core.idax_permission p
      ON p.permission_code IN ('profile.read', 'profile.update')
    WHERE r.tenant_id = p_tenant_id
      AND r.system_role
      AND r.role_key = 'user'
    ON CONFLICT DO NOTHING;

    INSERT INTO idax_core.idax_user_role (tenant_id, user_id, role_id)
    SELECT tu.tenant_id, tu.user_id, r.role_id
    FROM idax_core.tenant_user tu
    JOIN idax_core.idax_role r
      ON r.tenant_id = tu.tenant_id
     AND r.system_role
     AND r.role_key = lower(tu.role)
    WHERE tu.tenant_id = p_tenant_id
    ON CONFLICT DO NOTHING;
END;
$$;

CREATE OR REPLACE FUNCTION idax_core.tg_seed_base_roles_for_tenant()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = idax_core, pg_temp
AS $$
BEGIN
    PERFORM idax_core.ensure_base_roles_for_tenant(NEW.tenant_id);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_seed_base_roles_for_tenant ON idax_core.tenant;

CREATE TRIGGER trg_seed_base_roles_for_tenant
AFTER INSERT ON idax_core.tenant
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_seed_base_roles_for_tenant();

SELECT idax_core.ensure_base_roles_for_tenant(t.tenant_id)
FROM idax_core.tenant t;

REVOKE ALL ON FUNCTION idax_core.ensure_base_roles_for_tenant(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION idax_core.tg_seed_base_roles_for_tenant() FROM PUBLIC;
