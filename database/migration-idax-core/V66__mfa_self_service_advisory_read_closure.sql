-- V66: DB-C1A.12 - close MfaSelfServiceService's remaining direct AppUserMfaConfigurationRepository
-- reads (four call sites traced exactly from the real implementation - see the DB-C1A.12 gate
-- report for the full per-site trace). Disposition, decided per site, not uniformly:
--
--   1. setup()'s advisory "already active" pre-check - ELIMINATED. mfaSetupPendingRepository's
--      auth_mfa_setup_pending (V64) already re-checks "mfa_enabled = false" authoritatively at
--      commit time and, on conflict, is caught by the SAME MFA_ALREADY_ENABLED error the advisory
--      read used to produce - the read added no observable behavior, only a redundant DB
--      round-trip. No new SQL needed for this site.
--
--   2. activate()'s pending-secret read - genuinely needed in Java (must decrypt the pending
--      ciphertext and verify the submitted TOTP code BEFORE the V63 activation CAS can run at
--      all) - migrated to the new auth_mfa_pending_secret_lookup(uuid) below. Neither V56
--      (wrong secret entirely - the ACTIVE one, not pending), V61 (never returns any ciphertext,
--      by design), nor V65 (single boolean, no ciphertext) fit; a purpose-specific narrow lookup
--      is required (Phase 5/7 conclusion).
--
--   3. regenerateRecoveryCodes()'s active-ciphertext read (the expected-state token the V63
--      replacement CAS needs) - migrated to the new auth_mfa_active_secret_lookup(uuid) below.
--      V56 would fit functionally but overexposes last_used_totp_step (an anti-replay counter
--      this caller has no use for and never validates active-state itself - reauthenticate()
--      already did, see #4) - same data-minimization reasoning that motivated V61's existence at
--      DB-C1A.7, applied consistently here rather than reused past its intended scope.
--
--   4. reauthenticate()'s upfront "is MFA active" gate (shared by disable()/regenerateRecoveryCodes(),
--      produces MFA_NOT_ENABLED before any password/code check) - REUSES auth_local_mfa_gate_lookup
--      (V65) unchanged: its contract (a single boolean, exactly isMfaActive()'s definition) is a
--      precise semantic fit regardless of caller identity - a capability boundary describes an
--      operation's security semantics, not which Java service calls it (same rule already applied
--      at DB-C1A.6/V60 for V56/V58). V65's SQL body/ownership/idax_backend grant are untouched;
--      this migration only extends its EXECUTE grantee list, mirroring V60's precedent exactly.
--
-- Deliberately NOT created: any single "MFA configuration lookup" returning a union of pending
-- and active fields for all four callers to share - that would recreate table access behind one
-- function. Two callers need pending-domain state, one needs active-domain state, one needs only
-- a boolean; each gets exactly what it needs and nothing else.
--
-- Grantee derivation: MfaSelfServiceService is reached only via /api/me/mfa/** (MeMfaController,
-- @AuthenticationPrincipal CurrentUser) - always authenticated, always tenant-scoped. Same
-- derivation as every other MfaSelfServiceService capability (V60/61/62/63/64): idax_app, and
-- transitionally idax_admin for the same superuser/effective-tenant reason already documented
-- (DATABASE_PRIVILEGED_CAPABILITIES.md section 21) - added to the DB-C1B cleanup checklist.
--
-- Owner privileges: ZERO new grants for either new function - table-wide SELECT on
-- app_user_mfa_configuration already exists from V56, covering every column both functions read.

GRANT idax_capability_owner TO CURRENT_USER;

-- Extends V65's grantee list only - does not alter its SQL body, ownership, or idax_backend grant.
GRANT EXECUTE ON FUNCTION idax_core.auth_local_mfa_gate_lookup(uuid)
  TO idax_app, idax_admin;

CREATE OR REPLACE FUNCTION idax_core.auth_mfa_pending_secret_lookup(p_user_id uuid)
RETURNS TABLE (
    totp_secret_pending_encrypted text,
    totp_pending_expires_at       timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_pending_secret_lookup: invalid user id' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT c.totp_secret_pending_encrypted, c.totp_pending_expires_at
    FROM idax_core.app_user_mfa_configuration c
    WHERE c.user_id = p_user_id
    LIMIT 1;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_pending_secret_lookup(uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_pending_secret_lookup(uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_pending_secret_lookup(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_pending_secret_lookup(uuid)
  TO idax_app, idax_admin;

CREATE OR REPLACE FUNCTION idax_core.auth_mfa_active_secret_lookup(p_user_id uuid)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
DECLARE
    v_totp_secret_encrypted text;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_active_secret_lookup: invalid user id' USING ERRCODE = '22023';
    END IF;

    SELECT c.totp_secret_encrypted
    INTO v_totp_secret_encrypted
    FROM idax_core.app_user_mfa_configuration c
    WHERE c.user_id = p_user_id;

    RETURN v_totp_secret_encrypted;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_active_secret_lookup(uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_active_secret_lookup(uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_active_secret_lookup(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_active_secret_lookup(uuid)
  TO idax_app, idax_admin;
