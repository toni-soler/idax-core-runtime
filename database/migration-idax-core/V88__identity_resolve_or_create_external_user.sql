-- V88: DB-C2A.13 - narrow atomic external-identity resolve-or-create-with-metadata capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29w for the full trace and this gate's report.
--
-- FLOW SCOPE (Phase 1-3, fresh full source search): traced exactly from
-- AppUserResolver#resolveOrCreateAppUserId(subject, email, displayName), called from exactly two
-- production sites - TenantOnboardingService#ensureAdminUserAndMembership (new-tenant admin
-- provisioning) and TenantUserService#create (POST /api/tenants/{tenantId}/users, tenant-admin-
-- triggered user creation). This is the SEPARATE, ADMIN-DRIVEN provisioning flow V69's own header
-- already called out and deliberately deferred - distinct from V69's identity_ensure_external_user
-- (the passive, subject-only, every-authenticated-request ensure). CLASSIFICATION: RESOLVE OR
-- CREATE WITH METADATA SYNC - a single coherent identity operation (not account-linking, not
-- credential/MFA/membership/onboarding-orchestration), so no STOP triggered by Phase 3.
--
-- AUTHORITATIVE EXTERNAL IDENTITY KEY (Phase 4, reconfirmed): external_subject alone, backed by
-- V1's CONSTRAINT uq_app_user_subject UNIQUE (external_subject) - unchanged, unweakened. Never
-- email (app_user.email carries no UNIQUE constraint).
--
-- EMAIL-BASED IDENTITY LINKING (Phase 5/6, PRIMARY SECURITY REVIEW): FORBIDDEN, and the traced Java
-- method never does it - findUserIdBySubject looks up EXCLUSIVELY by external_subject
-- (`WHERE external_subject = ?`), never by email. Two different subjects sharing the same email
-- become two independent app_user rows (user A: subject=A, email=x@example.com; incoming
-- subject=B, email=x@example.com -> B is created as a SEPARATE row, A is never touched, no
-- constraint failure, no link, no merge) - reconfirmed by this migration's own negative-proof test.
-- No account-linking security bug exists in the traced Java code; this capability preserves that
-- exact behavior (lookup by external_subject only, both in the INSERT's conflict target and
-- nowhere else).
--
-- DISPLAY NAME / EMAIL SEMANTICS (Phase 7/8, exact, not assumed): on an EXISTING external_subject,
-- the traced Java code updates email/display_name on EVERY call, but only when the incoming value
-- is non-null AND non-blank (`COALESCE(NULLIF(?, ''), <existing column>)`) - a blank/null incoming
-- value preserves the current value; a non-blank incoming value OVERWRITES it unconditionally. This
-- is genuine per-call metadata SYNCHRONIZATION (not a one-time creation-only value, unlike V69's own
-- deliberate no-touch-on-existing design) - reproduced exactly, not weakened into a broader profile
-- upsert and not narrowed into a create-only capability that would then need Java-side broad UPDATE.
--
-- A REAL PRE-EXISTING CORRECTNESS BUG WAS FOUND while tracing this flow (same class V69 already
-- fixed for the sibling method, not manufactured here): AppUserResolver#createUser passes its raw
-- email/displayName parameters directly into the INSERT's VALUES list; email/display_name are
-- `NOT NULL DEFAULT ''` columns, so a caller that omits either field (TenantOnboardingRequest does
-- not require adminEmail/adminDisplayName; TenantUserRequest does not require email/displayName
-- either) passes an explicit SQL NULL, which violates the NOT NULL constraint regardless of the
-- column's own DEFAULT - meaning first-time admin-provisioned user creation with an omitted
-- email/displayName is broken today (DataIntegrityViolationException, not caught by createUser's
-- own catch block since findUserIdBySubject then finds nothing for a row that was never inserted).
-- This migration fixes it as a natural consequence of coalescing NULL to '' before the INSERT
-- (`COALESCE(p_email, '')` / `COALESCE(p_display_name, '')`), exactly mirroring V69's own precedent
-- of fixing the analogous bug as a side effect of routing through a single atomic SQL operation.
--
-- AUTH_PROVIDER (Phase 9): never read or written by the traced Java method (not in its INSERT
-- column list, not in its UPDATE clause) - this capability does the same; a newly created row gets
-- the column's own DEFAULT 'local' (unchanged, not this capability's concern), an existing row's
-- auth_provider is never touched.
--
-- ENABLED / IS_ACTIVE (Phase 10): never read or written by the traced Java method on either branch
-- - this capability does the same. A disabled existing user's re-provisioning through this path can
-- never silently re-enable it, matching V69's own disabled-state invariant exactly.
--
-- SUPERUSER (Phase 11, mandatory): is_superuser is a hard-coded literal `false` in the INSERT,
-- exactly as V69's own capability and the traced Java code's own `createUser(..., false)` call
-- (isSuperuser is a private-helper parameter, but every real call site passes the literal `false` -
-- confirmed by fresh source search, no caller ever passes anything else) - not a function parameter,
-- cannot be influenced by any external claim. An existing row's is_superuser is never touched by
-- either the traced Java code or this capability (no UPDATE branch touches it). No JWT claim, role
-- string, or authorization flag is read by this migration or passed into this function.
--
-- CREDENTIAL SIDE EFFECTS (Phase 12): NONE - this function touches only idax_core.app_user; no
-- app_user_credential, MFA, or recovery-code table is read or written, matching the traced Java
-- method exactly (its own credential handling, when present, is a separate, later, explicit
-- ensureLocalCredential call in TenantUserService/TenantOnboardingService - untouched here).
--
-- TENANT MEMBERSHIP SEPARATION (Phase 13/14): NOT touched - this function performs no tenant_user
-- read or write. Both real callers already treat identity resolution and tenant_user membership as
-- two separate operations today (AppUserResolver#ensureTenantMembership is called SEPARATELY, after
-- resolveOrCreateAppUserId returns, in both TenantOnboardingService and TenantUserService) - this
-- migration does not change that shape, and this capability could not create tenant_user rows even
-- if it wanted to (idax_capability_owner is granted no privilege on that table by this migration).
--
-- EXECUTION CONTEXT / DIRECT GRANTEE (Phase 15/28, traced fresh from both real call sites, not
-- assumed): AppUserResolver#resolveOrCreateAppUserId hard-codes `SET LOCAL ROLE idax_admin` inline,
-- unconditionally, before any of its SQL operations - exactly like V69's own sibling method
-- (resolveOrCreate) and independent of TenantContext's own dbRole selection (which would otherwise
-- select idax_app for an ordinary, non-superuser tenant admin calling
-- POST /api/tenants/{tenantId}/users - JwtAuthFilter sets TenantContext.DbRole.IDAX_APP unless
-- user.isSuperuser()). Reordering this specific elevation earlier (DB-C2A.12b style) was evaluated
-- and REJECTED for this gate: SET LOCAL ROLE persists for the rest of the transaction, and this same
-- elevation is ALSO incidentally relied on by code this gate must not touch or re-verify -
-- TenantUserService#create's own direct JPA auth_provider fix-up (`appUserRepository.save(appUser)`)
-- and AppUserResolver#ensureTenantMembership's own separate INSERT into tenant_user, both of which
-- execute later in the SAME transaction, after this elevation has already taken effect. Removing or
-- moving it risks silently breaking those out-of-scope operations under the ordinary-tenant-admin
-- (idax_app) case. The capability is therefore granted EXECUTE to idax_admin only, matching both
-- real, traced, direct call sites' actual execution role - idax_backend gets EFFECTIVE (not direct)
-- EXECUTE via V1's standing `GRANT idax_admin TO idax_backend` membership; idax_app is NOT granted
-- (no real code path reaches this exact function as idax_app today - the internal elevation always
-- runs first). This mirrors V69's own identical reasoning and grantee choice exactly.
--
-- OWNER PRIVILEGE (Phase 30, minimized precisely): idax_capability_owner already holds table-wide
-- SELECT (V54) and column-level INSERT(external_subject, is_superuser) (V69) on idax_core.app_user.
-- This migration adds INSERT(email, display_name) - needed for first-creation metadata - and
-- UPDATE(email, display_name) - needed for the existing-row sync branch. No INSERT/UPDATE privilege
-- is added for user_id/auth_provider/is_active/created_at/updated_at (all DB-generated or
-- untouched), and is_superuser keeps its existing INSERT-only privilege (still no UPDATE) - an
-- existing row's is_superuser can never be changed through this or any capability.
--
-- ATOMICITY (Phase 20/21/26): a single `INSERT ... ON CONFLICT (external_subject) DO UPDATE ...
-- RETURNING user_id` replaces the current Java find-then-insert-then-catch race, using the real
-- uq_app_user_subject UNIQUE constraint as the sole concurrency authority - concurrent calls with
-- the identical subject converge on exactly one canonical row (the DO UPDATE branch fires for
-- every conflict, whether against a genuinely pre-existing row or a concurrently-racing insert, so -
-- unlike today's Java code, where a losing racer's own email/displayName are silently dropped -
-- every caller's non-blank metadata is applied; this is a strict improvement, not a behavior
-- regression, and does not touch any protected column). Concurrent calls with distinct subjects
-- create/resolve fully independently (different conflict targets).
--
-- INPUT / NORMALIZATION (Phase 23/24): null/blank external_subject raises an exception (defense in
-- depth backstop; the real Java call sites already validate this first). null or blank email/
-- display_name are treated identically to "no update requested" for an existing row, and coalesced
-- to '' for a first insert - no LOWER/TRIM/ILIKE/case-folding of any kind is introduced; both
-- columns are compared and stored exactly as supplied, matching the traced Java code precisely.
--
-- OUTPUT (Phase 22): both real call sites use only the returned UUID (to pass into
-- ensureTenantMembership/appUserRepository.findById) - this function returns uuid only, not a
-- row/table, and never exposes is_superuser, credential state, or tenant memberships.
--
-- DEFAULT PRIVILEGES: this migration creates a function only, adds column grants to the existing
-- idax_capability_owner role - no table/sequence/constraint is created, no ALTER DEFAULT PRIVILEGES
-- statement is used (out of scope per this gate's own instruction).

GRANT idax_capability_owner TO CURRENT_USER;

GRANT INSERT (email, display_name) ON idax_core.app_user TO idax_capability_owner;
GRANT UPDATE (email, display_name) ON idax_core.app_user TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.identity_resolve_or_create_external_user(
    p_external_subject text,
    p_email            text,
    p_display_name     text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_user_id uuid;
BEGIN
    IF p_external_subject IS NULL OR p_external_subject = '' THEN
        RAISE EXCEPTION 'identity_resolve_or_create_external_user: invalid external subject' USING ERRCODE = '22023';
    END IF;

    INSERT INTO idax_core.app_user (external_subject, email, display_name, is_superuser)
    VALUES (p_external_subject, COALESCE(p_email, ''), COALESCE(p_display_name, ''), false)
    ON CONFLICT (external_subject) DO UPDATE
    SET email        = COALESCE(NULLIF(p_email, ''), idax_core.app_user.email),
        display_name = COALESCE(NULLIF(p_display_name, ''), idax_core.app_user.display_name)
    RETURNING idax_core.app_user.user_id INTO v_user_id;

    RETURN v_user_id;
END;
$function$;

ALTER FUNCTION idax_core.identity_resolve_or_create_external_user(text, text, text)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.identity_resolve_or_create_external_user(text, text, text)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.identity_resolve_or_create_external_user(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.identity_resolve_or_create_external_user(text, text, text)
  TO idax_admin;
