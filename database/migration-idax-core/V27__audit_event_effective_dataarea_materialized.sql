ALTER TABLE idax_core.idax_audit_event
    ADD COLUMN IF NOT EXISTS effective_dataareaid varchar(10);

CREATE OR REPLACE FUNCTION idax_core.audit_event_effective_dataarea(
    p_dataareaid text,
    p_company text,
    p_business_key text,
    p_external_key text,
    p_payload_json text,
    p_before_json text,
    p_after_json text
)
RETURNS text
LANGUAGE sql
STABLE
AS $$
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
    )
$$;

ALTER FUNCTION idax_core.audit_event_effective_dataarea(text, text, text, text, text, text, text)
    SET search_path = idax_core, pg_temp;

REVOKE ALL ON FUNCTION idax_core.audit_event_effective_dataarea(text, text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.audit_event_effective_dataarea(text, text, text, text, text, text, text) TO idax_app, idax_admin;

UPDATE idax_core.idax_audit_event
SET effective_dataareaid = idax_core.audit_event_effective_dataarea(
    dataareaid,
    company,
    business_key,
    external_key,
    payload_json,
    before_json,
    after_json
)
WHERE effective_dataareaid IS DISTINCT FROM idax_core.audit_event_effective_dataarea(
    dataareaid,
    company,
    business_key,
    external_key,
    payload_json,
    before_json,
    after_json
);

CREATE OR REPLACE FUNCTION idax_core.tg_set_audit_event_effective_dataarea()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.effective_dataareaid := idax_core.audit_event_effective_dataarea(
        NEW.dataareaid,
        NEW.company,
        NEW.business_key,
        NEW.external_key,
        NEW.payload_json,
        NEW.before_json,
        NEW.after_json
    );
    RETURN NEW;
END;
$$;

ALTER FUNCTION idax_core.tg_set_audit_event_effective_dataarea()
    SET search_path = idax_core, pg_temp;

DROP TRIGGER IF EXISTS trg_idax_audit_event_effective_dataarea ON idax_core.idax_audit_event;
CREATE TRIGGER trg_idax_audit_event_effective_dataarea
BEFORE INSERT OR UPDATE OF dataareaid, company, business_key, external_key, payload_json, before_json, after_json
ON idax_core.idax_audit_event
FOR EACH ROW
EXECUTE FUNCTION idax_core.tg_set_audit_event_effective_dataarea();

DROP POLICY IF EXISTS p_idax_audit_event_app_select ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_select ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_update ON idax_core.idax_audit_event;
DROP POLICY IF EXISTS p_idax_audit_event_admin_delete ON idax_core.idax_audit_event;

CREATE POLICY p_idax_audit_event_app_select
ON idax_core.idax_audit_event
FOR SELECT TO idax_app
USING (
    idax_core.current_user_can_see_dataarea(tenant_id, effective_dataareaid)
);

CREATE POLICY p_idax_audit_event_admin_select
ON idax_core.idax_audit_event
FOR SELECT TO idax_admin
USING (
    idax_core.current_user_can_see_dataarea(tenant_id, effective_dataareaid)
);

CREATE POLICY p_idax_audit_event_admin_update
ON idax_core.idax_audit_event
FOR UPDATE TO idax_admin
USING (
    idax_core.current_user_can_see_dataarea(tenant_id, effective_dataareaid)
)
WITH CHECK (
    tenant_id IS NULL
    OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
);

CREATE POLICY p_idax_audit_event_admin_delete
ON idax_core.idax_audit_event
FOR DELETE TO idax_admin
USING (
    idax_core.current_user_can_see_dataarea(tenant_id, effective_dataareaid)
);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_tenant_effective_dataarea_time
    ON idax_core.idax_audit_event (tenant_id, effective_dataareaid, event_time DESC);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_sales_tenant_effective_time
    ON idax_core.idax_audit_event (tenant_id, effective_dataareaid, event_time DESC)
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
