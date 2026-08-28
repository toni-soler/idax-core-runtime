CREATE OR REPLACE FUNCTION idax_core.current_user_can_see_dataarea(
    p_tenant_id uuid,
    p_dataareaid text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
    WITH ctx AS (
        SELECT
            NULLIF(current_setting('app.tenant_id', true), '')::uuid AS tenant_id,
            idax_core.current_app_user_id() AS user_id
    )
    SELECT
        p_tenant_id IS NOT NULL
        AND ctx.tenant_id IS NOT NULL
        AND p_tenant_id = ctx.tenant_id
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
                    ctx.user_id IS NULL
                    OR NOT EXISTS (
                        SELECT 1
                        FROM idax_core.tenant_user_dataarea tuda
                        WHERE tuda.tenant_id = p_tenant_id
                          AND tuda.user_id = ctx.user_id
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM idax_core.tenant_user_dataarea tuda
                        WHERE tuda.tenant_id = p_tenant_id
                          AND tuda.user_id = ctx.user_id
                          AND lower(tuda.dataareaid) = lower(p_dataareaid)
                    )
                )
            )
        )
    FROM ctx
$$;

ALTER FUNCTION idax_core.current_user_can_see_dataarea(uuid, text)
    SET search_path = idax_core, pg_temp;

REVOKE ALL ON FUNCTION idax_core.current_user_can_see_dataarea(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.current_user_can_see_dataarea(uuid, text) TO idax_app, idax_admin;
