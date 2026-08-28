-- ============================================================
-- V4__fix_permissions_on_idax.sql
-- Fix de permisos para esquema IDAX
-- ============================================================

DO $$
DECLARE
    v_user TEXT := 'idax_app'; -- <-- CAMBIAR SI ES NECESARIO
BEGIN

    RAISE NOTICE 'Applying permissions to user: %', v_user;

    -- ========================================================
    -- 1. SCHEMA PERMISSIONS
    -- ========================================================
    EXECUTE format('GRANT USAGE ON SCHEMA idax TO %I', v_user);

    -- ========================================================
    -- 2. TABLE PERMISSIONS (todas las existentes)
    -- ========================================================
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA idax TO %I', v_user);

    -- ========================================================
    -- 3. SEQUENCE PERMISSIONS (muy importante para inserts)
    -- ========================================================
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA idax TO %I', v_user);

    -- ========================================================
    -- 4. DEFAULT PRIVILEGES (para futuras tablas creadas por Flyway)
    -- ========================================================
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA idax GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', v_user);

    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA idax GRANT USAGE, SELECT ON SEQUENCES TO %I', v_user);

END $$;

-- ============================================================
-- END
-- ============================================================