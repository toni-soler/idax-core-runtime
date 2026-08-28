CREATE OR REPLACE FUNCTION idax_core.current_user_can_see_audit_event(
    p_tenant_id uuid,
    p_dataareaid text,
    p_company text,
    p_business_key text,
    p_external_key text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
    WITH effective AS (
        SELECT COALESCE(
            NULLIF(btrim(p_dataareaid), ''),
            NULLIF(btrim(p_company), ''),
            CASE
                WHEN NULLIF(btrim(p_business_key), '') ~ '^[[:alnum:]_]{3}:'
                    THEN split_part(btrim(p_business_key), ':', 1)
                ELSE NULL
            END,
            CASE
                WHEN NULLIF(btrim(p_external_key), '') ~ '^[[:alnum:]_]{3}:'
                    THEN split_part(btrim(p_external_key), ':', 1)
                ELSE NULL
            END
        ) AS dataareaid
    )
    SELECT idax_core.current_user_can_see_dataarea(p_tenant_id, effective.dataareaid)
    FROM effective
$$;

ALTER FUNCTION idax_core.current_user_can_see_audit_event(uuid, text, text, text, text)
    SET search_path = idax_core, pg_temp;

REVOKE ALL ON FUNCTION idax_core.current_user_can_see_audit_event(uuid, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.current_user_can_see_audit_event(uuid, text, text, text, text) TO idax_app, idax_admin;

DROP POLICY IF EXISTS p_idax_audit_event_app_select ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_select ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_update ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_delete ON idax_core.idax_audit_event;

CREATE POLICY p_idax_audit_event_app_select
ON idax_core.idax_audit_event
FOR SELECT TO idax_app
USING (
    idax_core.current_user_can_see_audit_event(tenant_id, dataareaid, company, business_key, external_key)
);

CREATE POLICY p_idax_audit_event_admin_select
ON idax_core.idax_audit_event
FOR SELECT TO idax_admin
USING (
    idax_core.current_user_can_see_audit_event(tenant_id, dataareaid, company, business_key, external_key)
);

CREATE POLICY p_idax_audit_event_admin_update
ON idax_core.idax_audit_event
FOR UPDATE TO idax_admin
USING (
    idax_core.current_user_can_see_audit_event(tenant_id, dataareaid, company, business_key, external_key)
)
WITH CHECK (
    tenant_id IS NULL
    OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
);

CREATE POLICY p_idax_audit_event_admin_delete
ON idax_core.idax_audit_event
FOR DELETE TO idax_admin
USING (
    idax_core.current_user_can_see_audit_event(tenant_id, dataareaid, company, business_key, external_key)
);
