-- V63: DB-C1A.9 - atomic MFA activation CAS and recovery-code replacement, closing the
-- reset/activation and reset/regeneration races confirmed (empirically) at DB-C1A.8.
--
-- STATE-VERSION STRATEGY SELECTED: the existing AES-256-GCM ciphertext columns
-- (totp_secret_pending_encrypted for activation, totp_secret_encrypted for recovery-code
-- replacement) serve as opaque compare-and-set tokens - NOT a new version/generation column.
-- TotpSecretCipher#encrypt uses a fresh random 12-byte GCM nonce on every call, so re-encrypting
-- the identical plaintext secret produces a different ciphertext string with overwhelming
-- probability (~2^-96 collision chance) - ciphertext equality reliably represents "this exact
-- persisted encryption operation", ruling out ABA: State A -> reset -> some other state ->
-- "State A again" cannot happen by coincidence even if the underlying plaintext secret were
-- somehow regenerated identically (see DB-C1A.9 gate report's ABA review).
--
-- auth_mfa_activate(uuid, text): promotes a pending TOTP secret to active ONLY if the config
-- row is STILL in the exact state Java verified (mfa not already enabled, pending ciphertext
-- unchanged, pending expiry not yet passed - checked against the database's own now(), never a
-- caller-supplied timestamp, closing the activation-expiry TOCTOU). A single UPDATE's WHERE
-- clause is the entire CAS - under PostgreSQL's standard READ COMMITTED re-check semantics
-- (EvalPlanQual), if a concurrent auth_mfa_clear reset commits between Java's read and this
-- statement, this UPDATE re-evaluates its WHERE clause against the post-reset row (pending
-- ciphertext now NULL) and correctly matches zero rows - no stale Java-side entity can ever
-- resurrect a cleared row. Also resets last_used_totp_step to NULL: a newly activated secret
-- starts an independent anti-replay domain from whatever secret it replaces - a stale step
-- number left over from a DIFFERENT secret has no meaning against the new one and can otherwise
-- reject that new secret's very first legitimate code if reactivation happens within the same or
-- an earlier TOTP time-step window (DB-C1A.9 finding: BUG CONFIRMED against the pre-DB-C1A.9
-- "never reset" behavior, closed here).
--
-- auth_mfa_recovery_codes_replace(uuid, text, uuid[], text[]): atomically replaces a user's
-- entire recovery-code batch (delete all existing, insert exactly the supplied hashed codes)
-- ONLY if the config row still shows active TOTP MFA with the exact expected active ciphertext -
-- shared by activate() (initial batch, expected ciphertext = the value just activated in the
-- SAME transaction) and regenerateRecoveryCodes() (expected ciphertext = the value read at call
-- time). The state check locks the config row (FOR UPDATE) BEFORE deleting/inserting,
-- serializing against a concurrent reset (whichever transaction reaches the row first wins; the
-- other blocks until commit, then re-evaluates with fresh data) and against a concurrent second
-- replacement for the same user (whichever commits last leaves one complete, non-mixed batch -
-- never a partial mixture of two batches). Receives ONLY already-hashed codes and pre-generated
-- ids - plaintext recovery codes and bcrypt hashing never leave Java.
--
-- Owner privileges: auth_mfa_activate needs ZERO new grants - column-level UPDATE on all 7
-- columns it touches (mfa_enabled, mfa_type, totp_secret_encrypted, totp_secret_pending_encrypted,
-- totp_pending_expires_at, mfa_activated_at from V62; last_used_totp_step from V57) and
-- table-wide SELECT (V56, covers the WHERE-clause columns) already exist. Only new grant needed:
-- column-level INSERT(id, user_id, code_hash) on app_user_recovery_code for the replace function
-- (DELETE was already granted by V62).

GRANT INSERT (id, user_id, code_hash) ON idax_core.app_user_recovery_code TO idax_capability_owner;

GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.auth_mfa_activate(
    p_user_id uuid,
    p_expected_pending_ciphertext text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_row_count integer;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_activate: invalid user id' USING ERRCODE = '22023';
    END IF;
    IF p_expected_pending_ciphertext IS NULL OR p_expected_pending_ciphertext = '' THEN
        RAISE EXCEPTION 'auth_mfa_activate: invalid expected pending ciphertext' USING ERRCODE = '22023';
    END IF;

    UPDATE idax_core.app_user_mfa_configuration c
    SET totp_secret_encrypted = p_expected_pending_ciphertext,
        totp_secret_pending_encrypted = NULL,
        totp_pending_expires_at = NULL,
        mfa_enabled = true,
        mfa_type = 'TOTP',
        mfa_activated_at = now(),
        last_used_totp_step = NULL
    WHERE c.user_id = p_user_id
      AND c.mfa_enabled = false
      AND c.totp_secret_pending_encrypted = p_expected_pending_ciphertext
      AND c.totp_pending_expires_at IS NOT NULL
      AND c.totp_pending_expires_at > now();

    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    RETURN v_row_count > 0;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_activate(uuid, text)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_activate(uuid, text)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_activate(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_activate(uuid, text)
  TO idax_app, idax_admin;


CREATE OR REPLACE FUNCTION idax_core.auth_mfa_recovery_codes_replace(
    p_user_id uuid,
    p_expected_active_ciphertext text,
    p_code_ids uuid[],
    p_code_hashes text[]
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_id_count integer;
    v_hash_count integer;
    v_distinct_id_count integer;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_recovery_codes_replace: invalid user id' USING ERRCODE = '22023';
    END IF;
    IF p_expected_active_ciphertext IS NULL OR p_expected_active_ciphertext = '' THEN
        RAISE EXCEPTION 'auth_mfa_recovery_codes_replace: invalid expected active ciphertext' USING ERRCODE = '22023';
    END IF;
    IF p_code_ids IS NULL OR p_code_hashes IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_recovery_codes_replace: invalid batch' USING ERRCODE = '22023';
    END IF;

    v_id_count := array_length(p_code_ids, 1);
    v_hash_count := array_length(p_code_hashes, 1);

    IF v_id_count IS NULL OR v_id_count = 0 THEN
        RAISE EXCEPTION 'auth_mfa_recovery_codes_replace: empty batch' USING ERRCODE = '22023';
    END IF;
    IF v_id_count <> v_hash_count THEN
        RAISE EXCEPTION 'auth_mfa_recovery_codes_replace: mismatched batch lengths' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(p_code_ids) x WHERE x IS NULL) THEN
        RAISE EXCEPTION 'auth_mfa_recovery_codes_replace: null code id in batch' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(p_code_hashes) x WHERE x IS NULL OR x = '') THEN
        RAISE EXCEPTION 'auth_mfa_recovery_codes_replace: null/blank code hash in batch' USING ERRCODE = '22023';
    END IF;

    SELECT count(DISTINCT x) INTO v_distinct_id_count FROM unnest(p_code_ids) x;
    IF v_distinct_id_count <> v_id_count THEN
        RAISE EXCEPTION 'auth_mfa_recovery_codes_replace: duplicate code id in batch' USING ERRCODE = '22023';
    END IF;

    PERFORM 1
    FROM idax_core.app_user_mfa_configuration
    WHERE user_id = p_user_id
      AND mfa_enabled = true
      AND mfa_type = 'TOTP'
      AND totp_secret_encrypted = p_expected_active_ciphertext
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    DELETE FROM idax_core.app_user_recovery_code WHERE user_id = p_user_id;

    INSERT INTO idax_core.app_user_recovery_code (id, user_id, code_hash)
    SELECT ids.id, p_user_id, hashes.hash
    FROM unnest(p_code_ids) WITH ORDINALITY AS ids(id, ord)
    JOIN unnest(p_code_hashes) WITH ORDINALITY AS hashes(hash, ord) ON ids.ord = hashes.ord;

    RETURN true;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_recovery_codes_replace(uuid, text, uuid[], text[])
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_recovery_codes_replace(uuid, text, uuid[], text[])
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_recovery_codes_replace(uuid, text, uuid[], text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_recovery_codes_replace(uuid, text, uuid[], text[])
  TO idax_app, idax_admin;
