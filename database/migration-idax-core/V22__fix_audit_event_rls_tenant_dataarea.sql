CREATE OR REPLACE FUNCTION idax_core.current_user_can_see_dataarea(
    p_tenant_id uuid,
    p_dataareaid text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
    SELECT
        p_tenant_id IS NOT NULL
        AND p_tenant_id = idax_core.current_tenant_id()
        AND (
            NULLIF(btrim(p_dataareaid), '') IS NULL
            OR (
                EXISTS (
                    SELECT 1
                    FROM idax_core.tenant_legacy tl
                    WHERE tl.tenant_id = p_tenant_id
                      AND tl.enabled = TRUE
                      AND lower(tl.dataareaid) = lower(p_dataareaid)
                )
                AND (
                    idax_core.current_app_user_id() IS NULL
                    OR NOT EXISTS (
                        SELECT 1
                        FROM idax_core.tenant_user_dataarea tuda
                        WHERE tuda.tenant_id = p_tenant_id
                          AND tuda.user_id = idax_core.current_app_user_id()
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM idax_core.tenant_user_dataarea tuda
                        WHERE tuda.tenant_id = p_tenant_id
                          AND tuda.user_id = idax_core.current_app_user_id()
                          AND lower(tuda.dataareaid) = lower(p_dataareaid)
                    )
                )
            )
        )
$$;

ALTER FUNCTION idax_core.current_user_can_see_dataarea(uuid, text)
    SET search_path = idax_core, pg_temp;

REVOKE ALL ON FUNCTION idax_core.current_user_can_see_dataarea(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.current_user_can_see_dataarea(uuid, text) TO idax_app, idax_admin;

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_tenant_dataarea_event_time
    ON idax_core.idax_audit_event (tenant_id, dataareaid, event_time DESC);

ALTER TABLE idax_core.idax_audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_audit_event FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_idax_audit_event_admin ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_select ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_insert ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_update ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_delete ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_app_select ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_app_insert ON idax_core.idax_audit_event;

CREATE POLICY p_idax_audit_event_app_select
ON idax_core.idax_audit_event
FOR SELECT TO idax_app
USING (
    idax_core.current_user_can_see_dataarea(tenant_id, dataareaid)
);

CREATE POLICY p_idax_audit_event_admin_select
ON idax_core.idax_audit_event
FOR SELECT TO idax_admin
USING (
    idax_core.current_user_can_see_dataarea(tenant_id, dataareaid)
);

CREATE POLICY p_idax_audit_event_app_insert
ON idax_core.idax_audit_event
FOR INSERT TO idax_app
WITH CHECK (
    tenant_id IS NULL
    OR tenant_id = idax_core.current_tenant_id()
);

CREATE POLICY p_idax_audit_event_admin_insert
ON idax_core.idax_audit_event
FOR INSERT TO idax_admin
WITH CHECK (
    tenant_id IS NULL
    OR tenant_id = idax_core.current_tenant_id()
);

CREATE POLICY p_idax_audit_event_admin_update
ON idax_core.idax_audit_event
FOR UPDATE TO idax_admin
USING (
    idax_core.current_user_can_see_dataarea(tenant_id, dataareaid)
)
WITH CHECK (
    tenant_id IS NULL
    OR tenant_id = idax_core.current_tenant_id()
);

CREATE POLICY p_idax_audit_event_admin_delete
ON idax_core.idax_audit_event
FOR DELETE TO idax_admin
USING (
    idax_core.current_user_can_see_dataarea(tenant_id, dataareaid)
);
