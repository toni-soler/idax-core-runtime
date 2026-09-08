-- V69: DB-C2A.2 - narrow atomic external-identity ensure capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29h for the full trust-boundary trace and this
-- gate's report. Traced exactly from AppUserResolver#resolveOrCreate(String subject), called from
-- TenantContextFilter on authenticated HTTP requests (external/Keycloak-authenticated identities;
-- also a no-op lookup-hit for already-provisioned LOCAL users, since LOCAL users always pre-exist
-- by the time a LOCAL token is validated).
--
-- FLOW SCOPE: this is the FIRST-EXTERNAL-LOGIN-PROVISIONING flow (find-or-create by subject only),
-- distinct from the SEPARATE explicit-admin-provisioning flow
-- (AppUserResolver#resolveOrCreateAppUserId, called only from TenantOnboardingService and
-- TenantUserService with admin-typed email/displayName) - that flow is NOT touched by this
-- migration; combining them would violate the "do not combine unrelated flows" gate instruction.
--
-- AUTHORITATIVE EXTERNAL IDENTITY KEY: external_subject alone, backed by V1's
-- CONSTRAINT uq_app_user_subject UNIQUE (external_subject). Not issuer+subject (no issuer column
-- exists in the schema) and never email (app_user.email carries no UNIQUE constraint - see
-- DB-C2A.1/V68's own trace).
--
-- EMAIL-BASED IDENTITY LINKING: FORBIDDEN (not applicable) - the traced flow never reads or writes
-- email at all. This function accepts and touches nothing but external_subject; two different
-- external subjects that happen to share an email simply become two independent app_user rows,
-- exactly as today's Java code already behaves (no accidental account merge is possible when email
-- is never part of the lookup/insert).
--
-- SUPERUSER INVARIANT (mandatory security gate, Phase 11): is_superuser is a hard-coded literal
-- `false` in the INSERT - it is not a function parameter and cannot be influenced by any caller
-- input. An external claim can never create or escalate a superuser through this capability.
--
-- DISABLED-USER INVARIANT (Phase 12): the upsert is `ON CONFLICT (external_subject) DO NOTHING` -
-- an existing row (active or is_active = false) is never updated by this function, so a disabled
-- external user's re-login never silently reactivates it, matching current Java behavior exactly
-- (resolveOrCreate never touches is_active on the found-row path).
--
-- AUTH_PROVIDER / SUBJECT MUTATION (Phase 13): this function has no UPDATE branch at all - an
-- existing binding's auth_provider/external_subject can never be reassigned by this capability.
--
-- DISPLAY ATTRIBUTE SYNCHRONIZATION (Phase 14): out of scope by design - email/display_name are
-- not inputs to this function; they retain their table DEFAULT ('') on insert and are never
-- touched on the found-row path. Profile synchronization, if ever needed, is a deliberately
-- separate, explicitly-authorized operation (see resolveOrCreateAppUserId's own admin-driven
-- flow), not a side effect of every authenticated request's identity-ensure call.
--
-- TENANT MEMBERSHIP (Phase 15): NOT touched. This capability performs no tenant_user read or
-- write, matching current resolveOrCreate behavior exactly.
--
-- A REAL PRE-EXISTING CORRECTNESS BUG WAS FOUND while tracing this flow (Phase 5/25, not
-- manufactured): the current Java AppUserResolver#createUser(subject, null, null, false) passes
-- explicit SQL NULL for email/display_name into columns declared `NOT NULL DEFAULT ''` - explicit
-- NULL always violates a NOT NULL constraint regardless of a column DEFAULT, so this INSERT throws
-- DataIntegrityViolationException for every genuinely new external subject; the method's own catch
-- block re-queries by subject, finds nothing (the insert never committed), and rethrows - meaning
-- first-time external (KEYCLOAK/DUAL) login provisioning is currently broken in any environment
-- where it is reachable. This migration fixes it as a natural consequence of omitting
-- email/display_name from the INSERT entirely (letting the table's own DEFAULT '' apply), since
-- this flow never needed those columns in the first place.
--
-- EXECUTION CONTEXT (Phase 16, traced from the real call site): AppUserResolver hard-codes
-- `SET LOCAL ROLE idax_admin` inline, in Java, before every one of its SQL operations - independent
-- of TenantContext's own dbRole selection. This is an existing instance of "incidental superuser DB
-- elevation" (section 21), broader-scoped than this single gate; changing AppUserResolver's own
-- role-selection strategy is a DB-C1B-shaped redesign, explicitly out of scope here. The capability
-- is therefore granted EXECUTE to idax_admin only, matching today's one real, traced, direct
-- caller identity - idax_backend gets EFFECTIVE (not direct) EXECUTE via V1's standing
-- `GRANT idax_admin TO idax_backend` membership. idax_app is NOT granted: no real code path reaches
-- this exact function as idax_app today, and granting it speculatively would be an unjustified
-- over-grant per this program's minimum-real-call-path rule. Added to the DB-C1B cleanup checklist
-- below, with the added note that AppUserResolver's own hardcoded elevation is itself unrelated
-- technical debt this migration does not fix.
--
-- OWNER PRIVILEGE (Phase 20): idax_capability_owner already holds table-wide SELECT on app_user
-- (V54). This migration adds column-level INSERT on exactly (external_subject, is_superuser) -
-- every other inserted column (user_id, email, display_name, auth_provider, is_active,
-- created_at, updated_at) is left to its own table DEFAULT, which requires no INSERT privilege on
-- those columns. No UPDATE, no DELETE privilege is granted - this function never updates or
-- deletes a row.
--
-- ATOMICITY (Phase 17/18): `INSERT ... ON CONFLICT (external_subject) DO NOTHING` followed by a
-- SELECT of the (now guaranteed-existing) row in the same statement/transaction is PostgreSQL's
-- standard atomic upsert-without-clobbering idiom - it relies on the real uq_app_user_subject
-- UNIQUE constraint as the conflict target (proven to exist, not assumed), replacing the current
-- Java-side SELECT-then-INSERT-then-catch-and-recover pattern with a single round trip that cannot
-- create two rows for the same subject under concurrent first login, and never fires
-- trg_app_user_updated_at on a mere lookup-hit (DO NOTHING performs no UPDATE at all).
--
-- DEFAULT PRIVILEGES (Phase 22, carried forward from DB-C2A.1): this migration creates a function
-- only, no new table/sequence/constraint - V1's ALTER DEFAULT PRIVILEGES rules for TABLES/SEQUENCES
-- do not apply, and no FUNCTIONS default-privilege rule exists in this schema. PostgreSQL's own
-- default (PUBLIC EXECUTE on newly created functions) is handled by the standard
-- REVOKE ALL ... FROM PUBLIC below. DEFAULT PRIVILEGE MODEL: SAFE FOR THIS GATE.

GRANT idax_capability_owner TO CURRENT_USER;

GRANT INSERT (external_subject, is_superuser) ON idax_core.app_user TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.identity_ensure_external_user(p_external_subject text)
RETURNS TABLE (
    user_id      uuid,
    is_superuser boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
    IF p_external_subject IS NULL OR p_external_subject = '' THEN
        RAISE EXCEPTION 'identity_ensure_external_user: invalid external subject' USING ERRCODE = '22023';
    END IF;

    INSERT INTO idax_core.app_user (external_subject, is_superuser)
    VALUES (p_external_subject, false)
    ON CONFLICT (external_subject) DO NOTHING;

    RETURN QUERY
    SELECT u.user_id, u.is_superuser
    FROM idax_core.app_user u
    WHERE u.external_subject = p_external_subject;
END;
$function$;

ALTER FUNCTION idax_core.identity_ensure_external_user(text)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.identity_ensure_external_user(text)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.identity_ensure_external_user(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.identity_ensure_external_user(text)
  TO idax_admin;
