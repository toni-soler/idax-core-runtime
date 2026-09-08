-- V57: DB-C1A.4 - atomic TOTP anti-replay advance capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md (binding architecture) and MfaLoginService#verify,
-- the single production consumer. Closes the CONCURRENT TOTP REPLAY GAP discovered and confirmed
-- during DB-C1A.3 (MfaTotpReplayConcurrencyTest, real PostgreSQL + real MfaLoginService.verify:
-- 5 concurrent requests presenting the same valid TOTP code were previously all accepted, because
-- the old sequence - read last_used_totp_step, compare in Java, JPA save - had no row lock and
-- no optimistic version column).
--
-- This migration does not touch V56's read-only auth_mfa_verification_state_lookup contract at
-- all (immutable, already published in main). Instead it adds a second, narrow, write-only
-- capability: a single atomic conditional UPDATE that is simultaneously the "is this step already
-- consumed" check AND the write. PostgreSQL evaluates the WHERE clause against the row under the
-- UPDATE's own row lock, so two concurrent calls for the same user/step can never both succeed -
-- the second one's WHERE clause fails to match once the first has committed, affecting zero rows.
-- There is no read-compare-write sequence anywhere in this function, in Java, or across the two.
--
-- Config-state TOCTOU: the WHERE clause also requires mfa_enabled = true AND mfa_type = 'TOTP' at
-- the moment of the atomic write (not just at the earlier read in MfaLoginService), so a request
-- racing a concurrent MFA disable can no longer advance the counter and issue tokens after MFA
-- was turned off mid-verification. This does not bind the advance to a specific secret
-- version/hash (that would require a material protocol change - a secret identifier or version
-- column - which is out of scope here); the residual exposure is a TOTP code computed against a
-- secret read moments earlier in the SAME request racing a concurrent secret rotation within that
-- same request's brief Java computation window, not across separate requests or the whole
-- challenge-token lifetime. See the DB-C1A.4 gate report for the full analysis.
--
-- Grantee: same reasoning as V56 (DB-C1A.3) - this capability's one production call site
-- (MfaLoginService#verify, via POST /api/auth/mfa/verify) is always pre-tenant (permitAll,
-- challenge token in the request body, never an Authorization: Bearer header), so no
-- TenantContext is ever established and RlsTransactionAspect applies no role - bare idax_backend.
-- EXECUTE is granted to idax_backend only.
--
-- Owner privilege: column-level UPDATE(last_used_totp_step) only, not table-wide UPDATE - the
-- narrowest grant PostgreSQL supports for this single-column write. SELECT on the table (needed
-- to evaluate the WHERE clause) was already granted to idax_capability_owner by V56 and is not
-- re-granted here. No INSERT/DELETE, no access to any other MFA/recovery-code table.
--
-- Trigger/audit semantics preserved automatically: idax_core.app_user_mfa_configuration already
-- has trg_app_user_mfa_configuration_updated (BEFORE UPDATE, sets updated_at = now()) from V48.
-- That trigger fires for any UPDATE regardless of caller role, so this plain UPDATE statement
-- keeps updated_at behavior identical to the JPA path it replaces without this function needing
-- to set it explicitly.

GRANT UPDATE (last_used_totp_step) ON idax_core.app_user_mfa_configuration TO idax_capability_owner;

-- Ownership transfer below requires the migration role to be a member of the owner role. V54/V56
-- already granted this for the same migration identity in the common case, but re-issuing here
-- keeps this migration self-contained if it ever runs in a different session.
GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.auth_mfa_totp_advance(
    p_user_id uuid,
    p_matched_step bigint
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

    UPDATE idax_core.app_user_mfa_configuration c
    SET last_used_totp_step = p_matched_step
    WHERE c.user_id = p_user_id
      AND c.mfa_enabled = true
      AND c.mfa_type = 'TOTP'
      AND (c.last_used_totp_step IS NULL OR c.last_used_totp_step < p_matched_step);

    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    RETURN v_row_count > 0;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint) TO idax_backend;
