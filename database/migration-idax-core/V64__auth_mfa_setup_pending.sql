-- V64: DB-C1A.10 - atomic MFA pending-setup capability, migrating the last direct-JPA
-- persistence surface of MfaSelfServiceService#setup into a narrow database capability.
--
-- ROW-EXISTENCE MODEL (Phase 2): app_user_mfa_configuration may or may not already have a row
-- for this user (first-time setup vs re-setup/pending-secret rotation) - a plain UPDATE is
-- insufficient. This uses INSERT ... ON CONFLICT (user_id) DO UPDATE ... WHERE, an atomic upsert:
-- the INSERT branch handles a first-time row (defaults mfa_enabled=false, mfa_type='NONE',
-- matching AppUserMfaConfiguration's builder defaults); the DO UPDATE branch handles an existing
-- row, gated by "WHERE mfa_enabled = false" - the SAME re-check-at-commit-time pattern V63 uses,
-- so a concurrent activation that commits first (mfa_enabled -> true) correctly causes this
-- statement to affect zero rows, closing the "setup must not overwrite active MFA" requirement
-- (Phase 6) authoritatively, not via a stale Java-side isMfaActive() read.
--
-- RESET / SETUP RACE (Phase 3) - reclassified into two distinct cases:
--   CASE A (stale-state resurrection): under the CLOSED DB-C1A.8/9 invariants, mfa_enabled=false
--   always implies totp_secret_encrypted/mfa_activated_at are NULL, and Java's own isMfaActive()
--   pre-check (using the same in-memory read) already blocks any path that could otherwise
--   resurrect ACTIVE state via a stale save. The one genuine narrow resurrection risk identified
--   was last_used_totp_step (untouched by auth_mfa_clear, but reset by a concurrent activation) -
--   closed structurally here by giving this capability the smallest possible write surface: it
--   NEVER touches totp_secret_encrypted, mfa_activated_at, or last_used_totp_step, so there is
--   nothing stale left for it to resurrect. CLOSED / NOT PRESENT for anything this capability
--   writes.
--   CASE B (fresh pending setup after reset): a reset that commits, followed by a genuinely NEW
--   setup request generating a fresh secret, is normal, acceptable database serialization
--   (RESET, then NEW SETUP) - not a vulnerability. DATABASE SERIALIZATION ORDER IS ACCEPTABLE.
--
-- PENDING EXPIRY AUTHORITY (Phase 9): p_pending_lifetime_seconds is trusted server configuration
-- (MfaProperties#setupPendingExpirationSeconds), never user input - mirrors V55's
-- p_lockout_seconds convention exactly. The expiry itself is computed as
-- now() + make_interval(secs => p_pending_lifetime_seconds) using PostgreSQL's own clock, never a
-- caller-supplied absolute timestamp.
--
-- Owner privileges: column-level INSERT(user_id, mfa_enabled, mfa_type,
-- totp_secret_pending_encrypted, totp_pending_expires_at) is the only NEW grant - UPDATE on
-- totp_secret_pending_encrypted/totp_pending_expires_at (for the DO UPDATE branch) and SELECT
-- (for the WHERE guard and the ON CONFLICT check) already exist from V62/V56.

GRANT INSERT (user_id, mfa_enabled, mfa_type, totp_secret_pending_encrypted, totp_pending_expires_at)
  ON idax_core.app_user_mfa_configuration TO idax_capability_owner;

GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.auth_mfa_setup_pending(
    p_user_id uuid,
    p_pending_secret_encrypted text,
    p_pending_lifetime_seconds integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_row_count integer;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_setup_pending: invalid user id' USING ERRCODE = '22023';
    END IF;
    IF p_pending_secret_encrypted IS NULL OR p_pending_secret_encrypted = '' THEN
        RAISE EXCEPTION 'auth_mfa_setup_pending: invalid pending secret ciphertext' USING ERRCODE = '22023';
    END IF;
    IF p_pending_lifetime_seconds IS NULL OR p_pending_lifetime_seconds <= 0 THEN
        RAISE EXCEPTION 'auth_mfa_setup_pending: invalid pending lifetime' USING ERRCODE = '22023';
    END IF;

    INSERT INTO idax_core.app_user_mfa_configuration
        (user_id, mfa_enabled, mfa_type, totp_secret_pending_encrypted, totp_pending_expires_at)
    VALUES
        (p_user_id, false, 'NONE', p_pending_secret_encrypted,
         now() + make_interval(secs => p_pending_lifetime_seconds))
    ON CONFLICT (user_id) DO UPDATE
        SET totp_secret_pending_encrypted = EXCLUDED.totp_secret_pending_encrypted,
            totp_pending_expires_at = EXCLUDED.totp_pending_expires_at
        WHERE idax_core.app_user_mfa_configuration.mfa_enabled = false;

    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    RETURN v_row_count > 0;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_setup_pending(uuid, text, integer)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_setup_pending(uuid, text, integer)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_setup_pending(uuid, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_setup_pending(uuid, text, integer)
  TO idax_app, idax_admin;
