CREATE OR REPLACE FUNCTION idax_core.audit_json_text(
    p_json text,
    p_key text
)
RETURNS text
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    IF p_json IS NULL OR btrim(p_json) = '' OR p_key IS NULL OR btrim(p_key) = '' THEN
        RETURN NULL;
    END IF;

    RETURN p_json::jsonb ->> p_key;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

ALTER FUNCTION idax_core.audit_json_text(text, text)
    SET search_path = idax_core, pg_temp;

REVOKE ALL ON FUNCTION idax_core.audit_json_text(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.audit_json_text(text, text) TO idax_app, idax_admin;

CREATE OR REPLACE FUNCTION idax_core.current_user_can_see_audit_event(
    p_tenant_id uuid,
    p_dataareaid text,
    p_company text,
    p_business_key text,
    p_external_key text,
    p_payload_json text,
    p_before_json text,
    p_after_json text
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
            NULLIF(btrim(idax_core.audit_json_text(p_payload_json, 'dataAreaId')), ''),
            NULLIF(btrim(idax_core.audit_json_text(p_payload_json, 'dataareaid')), ''),
            NULLIF(btrim(idax_core.audit_json_text(p_payload_json, 'company')), ''),
            NULLIF(btrim(idax_core.audit_json_text(p_before_json, 'dataAreaId')), ''),
            NULLIF(btrim(idax_core.audit_json_text(p_before_json, 'dataareaid')), ''),
            NULLIF(btrim(idax_core.audit_json_text(p_before_json, 'company')), ''),
            NULLIF(btrim(idax_core.audit_json_text(p_after_json, 'dataAreaId')), ''),
            NULLIF(btrim(idax_core.audit_json_text(p_after_json, 'dataareaid')), ''),
            NULLIF(btrim(idax_core.audit_json_text(p_after_json, 'company')), ''),
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

ALTER FUNCTION idax_core.current_user_can_see_audit_event(uuid, text, text, text, text, text, text, text)
    SET search_path = idax_core, pg_temp;

REVOKE ALL ON FUNCTION idax_core.current_user_can_see_audit_event(uuid, text, text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.current_user_can_see_audit_event(uuid, text, text, text, text, text, text, text) TO idax_app, idax_admin;

DROP POLICY IF EXISTS p_idax_audit_event_app_select ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_select ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_update ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_delete ON idax_core.idax_audit_event;

CREATE POLICY p_idax_audit_event_app_select
ON idax_core.idax_audit_event
FOR SELECT TO idax_app
USING (
    idax_core.current_user_can_see_audit_event(
        tenant_id, dataareaid, company, business_key, external_key, payload_json, before_json, after_json
    )
);

CREATE POLICY p_idax_audit_event_admin_select
ON idax_core.idax_audit_event
FOR SELECT TO idax_admin
USING (
    idax_core.current_user_can_see_audit_event(
        tenant_id, dataareaid, company, business_key, external_key, payload_json, before_json, after_json
    )
);

CREATE POLICY p_idax_audit_event_admin_update
ON idax_core.idax_audit_event
FOR UPDATE TO idax_admin
USING (
    idax_core.current_user_can_see_audit_event(
        tenant_id, dataareaid, company, business_key, external_key, payload_json, before_json, after_json
    )
)
WITH CHECK (
    tenant_id IS NULL
    OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
);

CREATE POLICY p_idax_audit_event_admin_delete
ON idax_core.idax_audit_event
FOR DELETE TO idax_admin
USING (
    idax_core.current_user_can_see_audit_event(
        tenant_id, dataareaid, company, business_key, external_key, payload_json, before_json, after_json
    )
);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_sales_candidates
    ON idax_core.idax_audit_event (tenant_id, event_type, entity_name, event_time DESC)
    WHERE event_type IN (
        'SALES_ORDER_CREATED_FROM_IDAX',
        'SALES_ORDER_CREATED_FROM_EMAIL',
        'SALES_LINE_CREATED_FROM_IDAX',
        'SALES_LINE_SYNC_FROM_AX',
        'SALES_ORDER_SYNC_FROM_AX',
        'SALES_TABLE_FIELDS_UPDATED',
        'SALES_LINE_FIELDS_UPDATED',
        'SALES_ORDER_UPDATED_BY_USER',
        'CUSTOMER_SYNC_FROM_AX'
    );

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_tenant_business_event_time
    ON idax_core.idax_audit_event (tenant_id, business_key, event_time DESC);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_tenant_external_event_time
    ON idax_core.idax_audit_event (tenant_id, external_key, event_time DESC);
