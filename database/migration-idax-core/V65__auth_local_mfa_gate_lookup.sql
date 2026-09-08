-- V65: DB-C1A.11 - narrow pre-tenant LOCAL login MFA gate lookup
--
-- LocalAuthService#login's remaining direct-JPA read (traced exactly from the real
-- implementation): after LocalCredentialAuthenticator verifies credentials via
-- idax_core.auth_local_identity_lookup(text) (V54), LocalAuthService separately calls
-- AppUserMfaConfigurationRepository#findByUserId and checks the entity's isMfaActive() - a
-- SINGLE boolean decision (does password login need to transition into an MFA challenge?), never
-- consuming any other field. See the DB-C1A.11 gate report for the full trace.
--
-- CAPABILITY SELECTION (DB-C1A.11 Phase 3/4/5, do not re-derive without re-reading this note):
--   V54 (auth_local_identity_lookup) does NOT already provide this - its actual, immutable
--   contract (read the file, not the architecture doc's earlier planning-stage snippet in
--   section 23, which was aspirational and never implemented that way) returns only
--   user_id/external_subject/display_name/password_hash/password_algo/is_active/is_superuser -
--   no MFA field at all. V54 is NOT modified here.
--   V56 (auth_mfa_verification_state_lookup) FUNCTIONALLY FITS BUT OVEREXPOSES: it returns
--   totp_secret_encrypted (ciphertext) and last_used_totp_step (anti-replay counter) - both are
--   MfaLoginService#verify's business, not a login-gate decision's. Reusing it here would trade
--   "no broad table access" for "an unnecessarily broad function result" reaching a caller that
--   only needs a boolean. V56 is NOT modified or reused here.
--   Selected strategy: C - a new, minimal, single-boolean pre-tenant lookup, scoped to exactly
--   the login-gate decision and nothing else.
--
-- Semantics: replicates AppUserMfaConfiguration#isMfaActive() exactly (mfa_enabled AND
-- mfa_type = 'TOTP' AND totp_secret_encrypted IS NOT NULL) - the SAME authoritative "MFA active"
-- definition used everywhere else in the application (V56, V61), not a subtly different
-- mfa_enabled-only check. No row (unknown user, or a user who never configured MFA) returns
-- false, not an error - matches the current Java Optional.isPresent()-gated behavior exactly and
-- creates no user-enumeration oracle (same non-error-on-absence shape as V54/V56/V61).
--
-- Owner privilege: ZERO new grants - table-wide SELECT on app_user_mfa_configuration already
-- exists from V56, covering every column this function reads.
--
-- Grantee: EXECUTE to idax_backend ONLY (direct). LocalAuthService#login is reached only via
-- POST /api/auth/login (permitAll, no Authorization: Bearer header, no TenantContext ever
-- established for this request) - the connection runs as the bare pre-tenant login, exactly the
-- same reasoning already established for V54/V56. No other production call site exists, so
-- idax_app/idax_admin are deliberately NOT granted (unlike V56, whose grantee list was later
-- extended by V60 because MfaSelfServiceService's authenticated reauth path genuinely needed it -
-- this capability has no such second call site).

GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.auth_local_mfa_gate_lookup(p_user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
DECLARE
    v_mfa_enabled boolean;
    v_mfa_type text;
    v_totp_secret_encrypted text;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_local_mfa_gate_lookup: invalid user id' USING ERRCODE = '22023';
    END IF;

    SELECT c.mfa_enabled, c.mfa_type::text, c.totp_secret_encrypted
    INTO v_mfa_enabled, v_mfa_type, v_totp_secret_encrypted
    FROM idax_core.app_user_mfa_configuration c
    WHERE c.user_id = p_user_id;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    RETURN v_mfa_enabled AND v_mfa_type = 'TOTP' AND v_totp_secret_encrypted IS NOT NULL;
END;
$function$;

ALTER FUNCTION idax_core.auth_local_mfa_gate_lookup(uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_local_mfa_gate_lookup(uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_local_mfa_gate_lookup(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_local_mfa_gate_lookup(uuid) TO idax_backend;
