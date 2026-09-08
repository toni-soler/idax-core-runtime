-- V89: DB-C2A.14a - reserve the break-glass admin subject in the external identity capabilities
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29y for the full trace and this gate's report.
--
-- CONTEXT (not rewriting V69/V88's own migration files, per this program's own standing rule -
-- CREATE OR REPLACE only, exact same signatures/owners/grantees, matching the style already used by
-- V79 to correct V78 without touching it): DB-C2A.14 found that
-- LocalAdminCredentialSynchronizer's OLD identity ("local:" + idax.admin.user) could be silently
-- claimed by an ORDINARY tenant-local user created through TenantUserService/TenantOnboardingService
-- (both share the exact same "local:" + username convention), causing the next application restart
-- to promote that unrelated row to a global superuser. DB-C2A.14a's Java-side fix
-- (LocalIdentitySubjectPolicy) moves the break-glass identity to a fixed, reserved, username-
-- independent subject - idax_core.identity_resolve_or_create_external_user('system:local-break-
-- glass-admin', ...) - and TenantUserService/TenantOnboardingService now reject that exact literal
-- subject in Java before ever reaching either capability. This migration adds the SAME rejection at
-- the DB layer, for BOTH V69's identity_ensure_external_user(text) and V88's
-- identity_resolve_or_create_external_user(text,text,text) - the strongest boundary available,
-- independent of any Java-side validation, so neither a malicious/misconfigured external identity
-- provider nor any future Java call site that forgets the Java-side check can ever create, touch, or
-- have returned to it a row under the reserved subject through either capability.
--
-- WHY BOTH FUNCTIONS (Phase 6): V88 is reachable not only by genuine external-identity admin
-- provisioning but also by TenantUserService/TenantOnboardingService's own "external" provider
-- branch, which passes the caller-supplied subject through UNPREFIXED - a tenant admin could
-- otherwise literally pass subject='system:local-break-glass-admin' with authProvider='external' and
-- reach the reserved identity directly through the capability, bypassing the "local:" convention
-- entirely. V69 is reached only by the passive per-request external-login-provisioning flow
-- (AppUserResolver#resolveOrCreate, called from TenantContextFilter) - protecting it too is
-- defense-in-depth against a real external IdP issuing the reserved string as a "sub" claim.
--
-- EXACT PRIOR BEHAVIOR PRESERVED (Phase 32): every existing invariant is reproduced byte-for-byte -
-- validation, ON CONFLICT semantics (DO NOTHING for V69, DO UPDATE with the same COALESCE/NULLIF
-- email/display_name sync for V88), RETURNING shape, SECURITY DEFINER/owner/search_path, REVOKE ALL
-- FROM PUBLIC, and the existing EXECUTE grantee (idax_admin only, unchanged for both) - the ONLY
-- behavioral change is an added rejection for the one reserved literal subject, checked before any
-- other validation or write.
--
-- NO OWNER PRIVILEGE CHANGE: this migration grants nothing new to idax_capability_owner - both
-- functions already hold exactly the column privileges V69/V88 established.

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

    IF p_external_subject = 'system:local-break-glass-admin' THEN
        RAISE EXCEPTION 'identity_ensure_external_user: subject is reserved for system use' USING ERRCODE = '22023';
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

    IF p_external_subject = 'system:local-break-glass-admin' THEN
        RAISE EXCEPTION 'identity_resolve_or_create_external_user: subject is reserved for system use' USING ERRCODE = '22023';
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
