-- V68: DB-C2A first bounded slice - narrow global admin user-by-email lookup capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 28 (capability USER_LOOKUP_BY_EMAIL, GLOBAL
-- NARROW) and the DB-C2A gate report for the full inventory/selection rationale. Traced exactly
-- from the real implementation: UserAdminController#findByEmail (GET /api/admin/users/by-email/{email},
-- @PreAuthorize("hasAuthority('ROLE_SUPERUSER')"), global - not tenant-scoped) calls
-- AppUserService#findByEmail, which currently does a direct JPA
-- AppUserRepository#findByEmail(String) - a plain SELECT against idax_core.app_user, no other
-- table, no write, no atomicity concern. This is the ONLY production call site of
-- AppUserRepository#findByEmail (confirmed by a full source search before authoring this
-- migration) - the JPA method itself becomes unused after the Java-side migration and is removed
-- from AppUserRepository.
--
-- SCOPE: exactly the 7 fields the existing UserResponse DTO already carries
-- (id/email/display_name/external_subject/auth_provider/is_active/is_superuser) - no password
-- hash, no MFA state, no tenant membership. This is a read-only identity lookup, not a
-- password/security-material projection - same data-minimization discipline as every DB-C1A
-- capability, applied here to the first DB-C2A slice.
--
-- AMBIGUITY BEHAVIOR PRESERVED EXACTLY: idax_core.app_user.email carries no UNIQUE constraint, so
-- today's Optional<AppUser>-returning JPA derived query throws (IncorrectResultSizeDataAccessException)
-- if more than one row matches, rather than silently picking one - this function replicates that
-- exact "ambiguous match is an error, never a silent pick" behavior via an explicit count check
-- before the real SELECT, instead of relying on a bare LIMIT 1 that would quietly change behavior.
--
-- EXECUTION CONTEXT (Phase 7, derived from the real call site, not assumed): the ONLY real caller
-- is UserAdminController's superuser-only endpoint - always authenticated, never tenant-scoped
-- (superuser JWTs never carry a tenantId claim - see LocalAuthService#issueTokens). Per section 21
-- ("INCIDENTAL SUPERUSER DB ELEVATION"), a functional superuser's authenticated request currently
-- selects idax_admin - this is the CURRENT reachable execution context, not the target one. Per
-- the target architecture (DB-C1B: HTTP always selects idax_app; @PreAuthorize alone enforces
-- authorization), this capability's target grantee is idax_app, with idax_admin retained only as
-- the TRANSITIONAL accommodation for the current incidental-elevation reality - added to the
-- existing DB-C1B cleanup checklist (DATABASE_PRIVILEGED_CAPABILITIES.md section 29) exactly like
-- every DB-C1A capability before it. idax_backend is NOT granted - no pre-tenant call site exists
-- or is expected for an authenticated, superuser-only admin lookup.
--
-- OWNER PRIVILEGE: ZERO new grants. idax_capability_owner already holds table-wide SELECT on
-- idax_core.app_user, granted at V54 (DB-C1A.1, auth_local_identity_lookup) and reused
-- unmodified since - this function needs nothing beyond what already exists.
--
-- DEFAULT PRIVILEGES (Phase 8): no new table or sequence is created by this migration, so V1's
-- ALTER DEFAULT PRIVILEGES rules for TABLES/SEQUENCES in idax_core (which auto-grant idax_app/
-- idax_admin broad access to any NEWLY CREATED object) do not apply here at all. No
-- ALTER DEFAULT PRIVILEGES rule exists for FUNCTIONS in this schema (checked directly, not
-- assumed) - PostgreSQL's own built-in default (EXECUTE granted to PUBLIC on any newly created
-- function unless explicitly revoked) is the only default-privilege concern for this migration,
-- and is handled the same way every prior capability handles it: an explicit
-- REVOKE ALL ... FROM PUBLIC immediately after creation. DEFAULT PRIVILEGE MODEL: SAFE FOR THIS GATE.
--
-- app_user itself is NOT closed the way the two MFA tables are (DB-C1A closure, V67) - it remains
-- broadly granted to idax_app/idax_admin from V1, and has many other legitimate direct JPA
-- consumers throughout Auth/tenant/self-service code (AppUserRepository#findById, etc.) untouched
-- by this migration. This capability ADDS a narrow additional access path; it does not attempt,
-- and is not intended, to close app_user's broader grant - that table's
-- DIRECT-GRANT REVOCATION READINESS remains BLOCKED (many other consumers), unrelated to this slice.

-- Granting EXECUTE on/reassigning ownership of a function to idax_capability_owner requires the
-- migration role to be a member of that owner role - re-issued here for self-containment, matching
-- every prior capability migration's convention (see V60's comment for the full rationale).
GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.user_lookup_by_email(p_email text)
RETURNS TABLE (
    user_id          uuid,
    email            text,
    display_name     text,
    external_subject text,
    auth_provider    text,
    is_active        boolean,
    is_superuser     boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
DECLARE
    v_match_count integer;
BEGIN
    IF p_email IS NULL OR p_email = '' THEN
        RAISE EXCEPTION 'user_lookup_by_email: invalid email' USING ERRCODE = '22023';
    END IF;

    SELECT count(*) INTO v_match_count FROM idax_core.app_user u WHERE u.email = p_email;
    IF v_match_count > 1 THEN
        RAISE EXCEPTION 'user_lookup_by_email: multiple users share this email' USING ERRCODE = '21000';
    END IF;

    -- app_user.email/display_name/external_subject/auth_provider are varchar(n); PL/pgSQL's
    -- RETURN QUERY requires an exact type match against RETURNS TABLE (unlike a plain top-level
    -- SELECT, it does not implicitly cast varchar(n) to text) - explicit casts avoid
    -- "structure of query does not match function result type".
    RETURN QUERY
    SELECT u.user_id, u.email::text, u.display_name::text, u.external_subject::text, u.auth_provider::text, u.is_active, u.is_superuser
    FROM idax_core.app_user u
    WHERE u.email = p_email;
END;
$function$;

ALTER FUNCTION idax_core.user_lookup_by_email(text)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.user_lookup_by_email(text)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.user_lookup_by_email(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.user_lookup_by_email(text)
  TO idax_app, idax_admin;
