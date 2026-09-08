-- V54: DB-C1A.1 - narrow LOCAL auth identity lookup capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 23/28 (capability AUTH_LOCAL_IDENTITY_LOOKUP).
-- LocalCredentialAuthenticator currently resolves identity/credential for the LOCAL login
-- (POST /api/auth/login) through direct JPA repository reads on idax_core.app_user and
-- idax_core.app_user_credential. Those reads only work pre-tenant because V1's default
-- privileges grant idax_app (and, through inherited membership, the bare idax_backend login
-- used before any tenant/role context exists - see RlsTransactionAspect) broad CRUD on every
-- table in this schema - an intentionally overbroad grant this capability starts narrowing.
--
-- This function replaces that broad table access, for this one callsite only, with a single
-- typed, non-enumerable, at-most-one-row lookup. Existing broad grants are deliberately left
-- untouched here for compatibility/rollback (see section 10 "Upgrade safety rules") - only the
-- Java call site changes in this increment, not the underlying privilege model.
--
-- Version note: idax-db/flyway/sql/idax_core already contains V53 (secure first administrator
-- bootstrap), mirrored there from idax-platform branch feature/core-neutral-first-admin-bootstrap
-- (commit c29d994), which has not been merged into idax-platform main. Since V53 is already part
-- of idax-db main (the deployed migration mirror), that version is treated as occupied and this
-- migration is assigned V54 instead of reusing or renumbering V53. V53 itself is not touched.

-- Dedicated NOLOGIN owner for narrow SQL capability functions. Never granted to idax_backend or
-- any login role; only used so SECURITY DEFINER capability functions run with a minimal, explicit
-- privilege set instead of inheriting whatever the migration identity happens to have.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idax_capability_owner') THEN
    CREATE ROLE idax_capability_owner NOLOGIN NOINHERIT;
  END IF;
END
$$;

-- Ownership transfer below requires the migration role to be a member of the new owner role.
GRANT idax_capability_owner TO CURRENT_USER;

GRANT USAGE ON SCHEMA idax_core TO idax_capability_owner;
GRANT SELECT ON idax_core.app_user TO idax_capability_owner;
GRANT SELECT ON idax_core.app_user_credential TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.auth_local_identity_lookup(p_identifier text)
RETURNS TABLE (
    user_id           uuid,
    external_subject  text,
    display_name      text,
    password_hash     text,
    password_algo     text,
    is_active         boolean,
    is_superuser      boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $function$
    SELECT u.user_id,
           u.external_subject,
           u.display_name,
           c.password_hash,
           c.password_algo,
           u.is_active,
           u.is_superuser
    FROM idax_core.app_user u
    JOIN idax_core.app_user_credential c ON c.user_id = u.user_id
    WHERE u.external_subject = p_identifier
    LIMIT 1
$function$;

ALTER FUNCTION idax_core.auth_local_identity_lookup(text)
  SET search_path = pg_catalog, pg_temp;

ALTER FUNCTION idax_core.auth_local_identity_lookup(text)
  OWNER TO idax_capability_owner;

REVOKE ALL ON FUNCTION idax_core.auth_local_identity_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_local_identity_lookup(text) TO idax_backend;
