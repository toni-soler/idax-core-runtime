-- V61: DB-C1A.7 - narrow self-service MFA status lookup capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md (binding architecture) and
-- MfaSelfServiceService#status, the single production consumer of this projection
-- (GET /api/me/mfa/status, "Mi perfil -> Seguridad"). Traced exactly from the real Java
-- implementation before writing this migration - see the DB-C1A.7 gate report for the
-- full inventory of remaining direct MFA management surfaces and why this specific
-- read-only slice was selected as the smallest bounded next increment.
--
-- Scope: READ ONLY, single exact-user projection. Replaces the direct JPA read
-- (AppUserMfaConfigurationRepository#findByUserId, loading the FULL entity just to read
-- three scalar fields) plus a separate AppUserRecoveryCodeRepository#countByUserIdAndUsedAtIsNull
-- call, with one narrow function returning exactly the four values MfaSelfServiceService#status
-- actually consumes: whether MFA is effectively active (mirroring
-- AppUserMfaConfiguration#isMfaActive()/MfaVerificationState#isMfaActive() exactly - enabled,
-- type TOTP, secret present), the type to display (never anything but 'NONE' when inactive,
-- matching the existing Java ternary), the activation timestamp, and the count of unused
-- recovery codes.
--
-- Deliberately NOT a reuse/broadening of V56 (auth_mfa_verification_state_lookup, DB-C1A.3):
-- V56's contract is immutable and already serves a different purpose (TOTP verification, not
-- status display) - it lacks mfa_activated_at (genuinely needed here) and would otherwise expose
-- totp_secret_encrypted/last_used_totp_step to a call site that has no legitimate reason to ever
-- see ciphertext or replay-counter state, needlessly widening this capability's crypto-adjacent
-- surface for a feature that displays only booleans/a timestamp/a count. A second, purpose-built
-- read-only function is the narrower choice; V56's file is untouched.
--
-- Grantee derivation (independent per function, DATABASE_PRIVILEGED_CAPABILITIES.md's corrected
-- rule): MfaSelfServiceService#status is reached only via /api/me/mfa/status
-- (MeMfaController), which requires @AuthenticationPrincipal CurrentUser - always
-- authenticated, always tenant-scoped. TenantContextFilter selects idax_app for an ordinary
-- user and, for the same reason already documented at DB-C1A.2/DB-C1A.5/DB-C1A.6, transitionally
-- idax_admin for a superuser request that still resolves an effective tenant. This capability has
-- no pre-tenant call site, so idax_backend is NOT granted EXECUTE (unlike V54/V56/V58, which are
-- pre-tenant-only in the opposite direction).
--
-- Owner privileges: NONE newly granted. SELECT on idax_core.app_user_mfa_configuration
-- (table-wide) was already granted to idax_capability_owner by V56; SELECT (user_id, used_at)
-- on idax_core.app_user_recovery_code was already granted (among other columns) by V59. This
-- function references only columns already covered by those two existing grants - no new
-- GRANT statement on any table/column appears in this migration at all, only the ownership
-- transfer/EXECUTE grants a new function always needs.
--
-- Time authority: N/A - this function performs no writes. mfa_activated_at is read exactly as
-- stored (last written by activate()/disable()/resetMfa(), unchanged by this capability).
--
-- Atomicity: N/A - single read-only statement, no read-then-write window, nothing to race.

-- Ownership transfer below requires the migration role to be a member of the owner role. V54/
-- V56/V57/V58/V59/V60 already granted this for the same migration identity in the common case,
-- but re-issuing here keeps this migration self-contained if it ever runs in a different session.
GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.auth_mfa_self_status_lookup(p_user_id uuid)
RETURNS TABLE (
    mfa_active                 boolean,
    mfa_type                   text,
    mfa_activated_at           timestamptz,
    unused_recovery_code_count integer
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
DECLARE
    v_mfa_enabled           boolean;
    v_mfa_type              varchar(20);
    v_totp_secret_encrypted text;
    v_mfa_activated_at      timestamptz;
    v_active                boolean;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_self_status_lookup: invalid user id' USING ERRCODE = '22023';
    END IF;

    SELECT c.mfa_enabled, c.mfa_type, c.totp_secret_encrypted, c.mfa_activated_at
      INTO v_mfa_enabled, v_mfa_type, v_totp_secret_encrypted, v_mfa_activated_at
    FROM idax_core.app_user_mfa_configuration c
    WHERE c.user_id = p_user_id;

    IF NOT FOUND THEN
        mfa_active := false;
        mfa_type := 'NONE';
        mfa_activated_at := NULL;
        unused_recovery_code_count := 0;
        RETURN NEXT;
        RETURN;
    END IF;

    v_active := COALESCE(v_mfa_enabled, false)
        AND v_mfa_type = 'TOTP'
        AND v_totp_secret_encrypted IS NOT NULL;

    mfa_active := v_active;
    mfa_type := CASE WHEN v_active THEN v_mfa_type::text ELSE 'NONE' END;
    mfa_activated_at := v_mfa_activated_at;

    SELECT count(*)::integer
      INTO unused_recovery_code_count
    FROM idax_core.app_user_recovery_code rc
    WHERE rc.user_id = p_user_id
      AND rc.used_at IS NULL;

    RETURN NEXT;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_self_status_lookup(uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_self_status_lookup(uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_self_status_lookup(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_self_status_lookup(uuid)
  TO idax_app, idax_admin;
