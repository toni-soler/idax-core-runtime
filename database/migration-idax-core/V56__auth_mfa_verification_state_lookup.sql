-- V56: DB-C1A.3 - narrow MFA verification-state lookup capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md (binding architecture) and MfaLoginService#verify, the
-- single production consumer of idax_core.app_user_mfa_configuration during MFA challenge
-- verification (POST /api/auth/mfa/verify). Traced exactly from the real Java implementation
-- before writing this migration - see the DB-C1A.3 gate report for the full trace and the
-- concurrent-TOTP-replay discovery evidence.
--
-- Scope: READ ONLY. This capability replaces only the direct JPA read
-- (AppUserMfaConfigurationRepository#findByUserId) that MfaLoginService#verify uses to decide
-- whether MFA is active and to obtain the ciphertext/replay-counter needed to verify one TOTP
-- code. It does not write anything. The existing anti-replay write (advancing
-- last_used_totp_step) stays exactly as it is today, still through
-- AppUserMfaConfigurationRepository - DB-C1A.3 gate discovery found that write is NOT currently
-- protected by any row lock or optimistic version column (AppUserMfaConfiguration has no
-- @Version field, and MfaLoginService never issues SELECT ... FOR UPDATE), so two concurrent
-- requests presenting the same valid TOTP code can currently both be accepted
-- (CONCURRENT TOTP REPLAY GAP: CONFIRMED by a real-PostgreSQL concurrency test). This migration
-- does not touch that write path at all, so it preserves that pre-existing gap exactly as-is -
-- neither fixing nor worsening it. An atomic compare-and-set capability for the write is
-- explicitly out of scope here and proposed as a future DB-C1A.4.
--
-- Fields returned are exactly the four MfaLoginService#verify actually consumes: mfa_enabled and
-- mfa_type (gate identical to AppUserMfaConfiguration#isMfaActive), totp_secret_encrypted (AES-
-- 256-GCM ciphertext - decryption stays in Java via TotpSecretCipher; the decryption key is never
-- passed to or known by PostgreSQL), and last_used_totp_step (the anti-replay comparison value).
-- totp_secret_pending_encrypted, totp_pending_expires_at, mfa_activated_at and all recovery-code
-- state are deliberately excluded - MfaLoginService#verify never reads them.
--
-- Grantee: unlike DB-C1A.2's rate-limit capability, this one has exactly one production call
-- site (MfaLoginService#verify), reached only via POST /api/auth/mfa/verify - permitAll, the MFA
-- challenge token is a request-body parameter (never an Authorization: Bearer header, and
-- JwtAuthFilter explicitly rejects "mfa_challenge"-typed tokens as bearer tokens anyway), so no
-- TenantContext is ever established for this call and RlsTransactionAspect applies no role at
-- all - the connection runs as the bare login. EXECUTE is therefore granted to idax_backend ONLY,
-- per the corrected grantee-derivation rule (DATABASE_PRIVILEGED_CAPABILITIES.md section 28):
-- each capability's grantees come from its own traced call sites, not copied from another
-- capability's precedent (V55 needed idax_app/idax_admin too because its call sites genuinely
-- differ; this one does not, so it is not granted to them).
--
-- Existing broad grants on idax_core.app_user_mfa_configuration (idax_app/idax_admin CRUD from
-- V1's default privileges) are deliberately left untouched for compatibility/rollback, matching
-- the DB-C1A.1/DB-C1A.2 precedent - only the Java call site for challenge verification changes.

GRANT SELECT ON idax_core.app_user_mfa_configuration TO idax_capability_owner;

GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.auth_mfa_verification_state_lookup(p_user_id uuid)
RETURNS TABLE (
    mfa_enabled          boolean,
    mfa_type             text,
    totp_secret_encrypted text,
    last_used_totp_step  bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_verification_state_lookup: invalid user id' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT c.mfa_enabled, c.mfa_type::text, c.totp_secret_encrypted, c.last_used_totp_step
    FROM idax_core.app_user_mfa_configuration c
    WHERE c.user_id = p_user_id
    LIMIT 1;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_verification_state_lookup(uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_verification_state_lookup(uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_verification_state_lookup(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_verification_state_lookup(uuid) TO idax_backend;
