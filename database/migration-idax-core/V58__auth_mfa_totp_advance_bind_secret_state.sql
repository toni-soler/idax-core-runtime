-- V58: DB-C1A.4a - bind the atomic TOTP anti-replay advance to the verified MFA secret state
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md and the DB-C1A.4a gate report for the full analysis.
-- V57 (DB-C1A.4, do not modify - immutable) closed the same-step concurrent replay gap, but its
-- WHERE clause only checked mfa_enabled/mfa_type, never which secret the Java caller actually
-- verified the code against. MFA SECRET-ROTATION VERIFICATION TOCTOU was empirically CONFIRMED
-- (a deterministic, real-PostgreSQL, real-repository reproduction, not just reasoning): a request
-- that reads and verifies against Secret A can still successfully advance/claim the step and
-- issue tokens after a concurrent disable+re-setup+activate cycle has already rotated the row to
-- Secret B, because setup() unconditionally rejects starting a new secret while MFA is already
-- active (MFA_ALREADY_ENABLED) - the ONLY way an already-active secret's value ever changes is via
-- a full disable() (mfa_enabled=false) then a later activate() (mfa_enabled=true again, with the
-- new secret) - so the row genuinely does return to mfa_enabled=true with a DIFFERENT secret,
-- which V57's mfa_enabled/mfa_type-only check cannot distinguish from "still Secret A".
--
-- Fix: bind the atomic claim to the exact ciphertext MfaLoginService already loaded via
-- idax_core.auth_mfa_verification_state_lookup (V56, unchanged, immutable) for THIS verification
-- attempt. The ciphertext is a naturally-occurring, already-present opaque version token - AES-
-- 256-GCM ciphertext with a fresh random 12-byte nonce per encryption (TotpSecretCipher), so it
-- changes on every re-encryption event, not merely on plaintext-secret changes, making it a
-- strictly stronger version signal than the plaintext value alone would be. No new schema/version
-- column was introduced: comparing the already-loaded ciphertext for exact equality is the
-- smallest robust fix (evaluated against: a new explicit version/hash column - unnecessary schema
-- change when the ciphertext already serves this purpose; updated_at as a version token -
-- unsound, since the trigger that maintains it fires on ANY update to the row, including the
-- advance's own write, making it self-referential garbage as a version signal).
--
-- Security properties preserved: PostgreSQL still receives only ciphertext (never plaintext,
-- never the decryption key, never the OTP code) and performs only an exact equality comparison
-- plus the existing atomic CAS - no cryptography moves into SQL. The comparison uses only data
-- the caller already legitimately possesses for this one exact user (the ciphertext this same
-- request already read); it cannot be used to probe or affect any other identity's row.
--
-- Old capability surface retirement: the V57 two-argument overload is REVOKEd and DROPped in this
-- same migration. This does not edit or rewrite V57's file (byte-for-byte immutable, unchanged);
-- it is ordinary later-migration DDL adjusting grants/objects V57 created, the same way V5 later
-- disabled RLS V1 had enabled. After this migration, idax_backend has no EXECUTE-capable path to
-- an unbound TOTP-step advance at all - only the new, secret-bound three-argument function exists
-- and is reachable.
--
-- Grantee/owner: unchanged reasoning from V57 - sole call site remains MfaLoginService#verify,
-- always pre-tenant, EXECUTE to idax_backend only. No new owner table privilege is required: V56
-- already granted SELECT (covers reading totp_secret_encrypted for the WHERE-clause comparison)
-- and V57 already granted column-level UPDATE(last_used_totp_step) - both are reused as-is.

-- Ownership transfer below requires the migration role to be a member of the owner role. V54/V56/
-- V57 already granted this for the same migration identity in the common case, but re-issuing
-- here keeps this migration self-contained if it ever runs in a different session.
GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.auth_mfa_totp_advance(
    p_user_id uuid,
    p_matched_step bigint,
    p_expected_totp_secret_encrypted text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_row_count integer;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_totp_advance: invalid user id' USING ERRCODE = '22023';
    END IF;
    IF p_matched_step IS NULL OR p_matched_step < 0 THEN
        RAISE EXCEPTION 'auth_mfa_totp_advance: invalid matched step' USING ERRCODE = '22023';
    END IF;
    IF p_expected_totp_secret_encrypted IS NULL OR length(p_expected_totp_secret_encrypted) = 0 THEN
        RAISE EXCEPTION 'auth_mfa_totp_advance: invalid expected secret state' USING ERRCODE = '22023';
    END IF;

    UPDATE idax_core.app_user_mfa_configuration c
    SET last_used_totp_step = p_matched_step
    WHERE c.user_id = p_user_id
      AND c.mfa_enabled = true
      AND c.mfa_type = 'TOTP'
      AND c.totp_secret_encrypted = p_expected_totp_secret_encrypted
      AND (c.last_used_totp_step IS NULL OR c.last_used_totp_step < p_matched_step);

    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    RETURN v_row_count > 0;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint, text)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint, text)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint, text) TO idax_backend;

-- Retire the old, unbound two-argument overload entirely.
REVOKE EXECUTE ON FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint) FROM idax_backend;
DROP FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint);
