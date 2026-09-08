-- V59: DB-C1A.5 - narrow MFA recovery-code verification + atomic consumption
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md (binding architecture). Two production call sites
-- perform the IDENTICAL semantic operation - "verify one supplied recovery code against this
-- exact user's unused codes, then consume exactly one row" - traced exactly from the real Java
-- implementation before writing this migration: MfaLoginService#tryConsumeRecoveryCode
-- (pre-tenant, POST /api/auth/mfa/verify) and MfaSelfServiceService#tryConsumeRecoveryCode
-- (authenticated, called from disable()/regenerateRecoveryCodes() via the shared reauthenticate()
-- helper). Both previously read ALL of a user's unused AppUserRecoveryCode entities via
-- AppUserRecoveryCodeRepository#findByUserIdAndUsedAtIsNull, compared bcrypt in Java, then did a
-- plain entity mutate + JPA save with no row lock and no optimistic version - the same
-- read-compare-write shape DB-C1A.4 already proved unsafe under concurrency for TOTP steps. A
-- deterministic real-PostgreSQL, real-service-bean reproduction (MfaRecoveryCodeConcurrencyTest,
-- pre-fix variant, since replaced) confirmed the identical gap here: 5 concurrent requests
-- presenting the SAME valid recovery code were all accepted.
-- MFA RECOVERY CODE CONCURRENT REUSE: GAP CONFIRMED, closed by this migration.
--
-- Scope chosen (DB-C1A.5 Phase "do not assume the final shape"): BOTH a narrow candidate lookup
-- AND an atomic consume, not consume alone. The existing broad read
-- (findByUserIdAndUsedAtIsNull) returns full AppUserRecoveryCode entities (id, userId, codeHash,
-- createdAt, usedAt) for bcrypt comparison in Java - narrowing it to exactly the two columns Java
-- actually compares (id, code_hash), for exactly one exact user, exactly mirrors what DB-C1A.3 did
-- for the TOTP secret read and does not expand scope: no new table, no new domain, no join beyond
-- this one already-existing table.
--
-- Recovery-code GENERATION/regeneration/deletion (RecoveryCodeGenerator, MfaSelfServiceService's
-- regenerateRecoveryCodesFor/disable, TenantUserService#resetMfa) stays exactly as it is today -
-- direct JPA delete+insert - and is explicitly OUT OF SCOPE here (see DB-C1A.5 gate report,
-- "generation/regeneration race review" and "MFA disable race review"): both regeneration and
-- disable/reset perform a physical DELETE of every existing row for that user (deleteByUserId),
-- inside the SAME transaction as the state change that invalidates them, before any new codes (if
-- any) are inserted. Because the atomic consume below is bound to the row's own id (not to a
-- separately-tracked user/generation version), a code that has been physically deleted by a
-- concurrent regeneration/disable/reset can never be consumed afterwards - the UPDATE's WHERE
-- clause simply matches zero rows once the row is gone, under ordinary PostgreSQL MVCC/row-lock
-- semantics, with no version/generation column needed. This was proven empirically (real
-- PostgreSQL, real service beans, deterministic sequencing) rather than assumed - see
-- MfaRecoveryCodeConcurrencyTest's regeneration and disable race tests.
--
-- Hash threat model (same discipline as password_hash and the encrypted TOTP secret): SQL returns
-- bcrypt hashes, never plaintext recovery codes: the candidate lookup's result columns are exactly
-- (id, code_hash), bcrypt comparison happens in Java via the existing PasswordEncoder bean, and no
-- plaintext recovery code, password or encryption key is ever passed into any SQL statement here.
-- The candidate lookup is scoped to exactly one caller-supplied user_id and excludes used codes,
-- so a compromised legitimate Auth capability could obtain unused hashes for one exact user it
-- already controls the identity of - it cannot enumerate hashes across users (no wildcard/list/
-- pagination interface exists), and RecoveryCodeCandidate's toString() is explicitly overridden in
-- Java so the hash can never leak through a log line, exception message or default record
-- toString().
--
-- Time authority: used_at is set from transaction_timestamp(), never a caller-supplied value -
-- same reasoning as V55's rate-limit "now" authority - so a compromised Auth runtime that can call
-- this function cannot backdate, future-date or otherwise manufacture consumption state.
--
-- Defense in depth (Phase "consume must bind user + code id"): the consume WHERE clause requires
-- BOTH id = p_code_id AND user_id = p_user_id AND used_at IS NULL - a caller cannot consume
-- another user's code even if it somehow obtained/guessed a valid code id, because the row simply
-- will not match unless it also belongs to the exact user passed in. Tested explicitly
-- (wrongUserIdCannotConsumeAnotherUsersCode).
--
-- Grantee derivation (independent per function, DATABASE_PRIVILEGED_CAPABILITIES.md's corrected
-- rule): MfaLoginService's call site is always pre-tenant (permitAll, no TenantContext, bare
-- idax_backend - same reasoning as V56/V57/V58). MfaSelfServiceService#reauthenticate's call site
-- is always authenticated with an established TenantContext - idax_app for an ordinary tenant
-- user, or idax_admin for the same self-service code path when the calling user is currently
-- resolved as a superuser (TenantContextFilter's DbRole selection, same transitional situation
-- V55 already documented - not yet fixed by DB-C1B). Since one shared pair of functions serves
-- both call sites, EXECUTE is granted to the union of their real execution contexts:
-- idax_backend, idax_app, idax_admin - not copied wholesale from V55's precedent, but re-derived
-- from these two call sites specifically. TenantUserService#resetMfa (admin-triggered MFA reset)
-- and MfaSelfServiceService's generation/regeneration/deletion paths never call either new
-- function - they perform unconditional physical deletes, not verification - so they need no
-- EXECUTE grant here and are unaffected.
--
-- Owner privileges (minimum derived exactly, Phase "owner privileges"): the candidate lookup's
-- query and the consume function's WHERE clause together reference exactly four columns -
-- id, user_id, code_hash, used_at - so SELECT is granted only on those four (created_at excluded,
-- since neither function ever reads it). The consume function's SET clause needs only
-- column-level UPDATE(used_at) - the narrowest grant PostgreSQL supports for this single-column
-- write, matching V57's precedent. No INSERT/DELETE privilege is granted to idax_capability_owner
-- here - neither function inserts or deletes a row, and generation/regeneration/deletion stays on
-- the existing broad idax_app/idax_admin CRUD grants from V48 untouched.
--
-- Existing broad grants on idax_core.app_user_recovery_code (idax_app/idax_admin CRUD from V48)
-- are deliberately left untouched for compatibility/rollback, matching the DB-C1A.1-4a precedent -
-- only the two Java call sites' consume path changes in this increment. Generation, regeneration
-- and admin-triggered reset still use those broad grants directly via
-- AppUserRecoveryCodeRepository - grep confirms this is the only remaining production use of that
-- repository after this migration (see DB-C1A.5 gate report, "old JPA surface").

GRANT SELECT (id, user_id, code_hash, used_at) ON idax_core.app_user_recovery_code TO idax_capability_owner;
GRANT UPDATE (used_at) ON idax_core.app_user_recovery_code TO idax_capability_owner;

-- Ownership transfer below requires the migration role to be a member of the owner role. V54/V56/
-- V57/V58 already granted this for the same migration identity in the common case, but re-issuing
-- here keeps this migration self-contained if it ever runs in a different session.
GRANT idax_capability_owner TO CURRENT_USER;

-- ============================================================================
-- auth_mfa_recovery_code_candidates: read-only, exact-user lookup. Returns only this user's own
-- unused recovery-code ids and bcrypt hashes - no cross-user listing, no pagination/global
-- enumeration, no used codes, no timestamps, no MFA config fields, no password/TOTP state.
-- ============================================================================
CREATE OR REPLACE FUNCTION idax_core.auth_mfa_recovery_code_candidates(p_user_id uuid)
RETURNS TABLE (
    id        uuid,
    code_hash text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_recovery_code_candidates: invalid user id' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT c.id, c.code_hash
    FROM idax_core.app_user_recovery_code c
    WHERE c.user_id = p_user_id
      AND c.used_at IS NULL;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_recovery_code_candidates(uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_recovery_code_candidates(uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_recovery_code_candidates(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_recovery_code_candidates(uuid)
  TO idax_backend, idax_app, idax_admin;

-- ============================================================================
-- auth_mfa_recovery_code_consume: atomic conditional UPDATE, simultaneously the "is this code
-- already used / does it belong to this user" check AND the write. Bound to BOTH user_id and
-- code id, so two concurrent callers for the same row can never both succeed (the second's WHERE
-- clause fails to match once the first has committed), and a caller cannot consume another user's
-- code by id alone. used_at is database-authoritative (transaction_timestamp()), never a
-- caller-supplied value.
-- ============================================================================
CREATE OR REPLACE FUNCTION idax_core.auth_mfa_recovery_code_consume(
    p_user_id uuid,
    p_code_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_row_count integer;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_recovery_code_consume: invalid user id' USING ERRCODE = '22023';
    END IF;
    IF p_code_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_recovery_code_consume: invalid code id' USING ERRCODE = '22023';
    END IF;

    UPDATE idax_core.app_user_recovery_code c
    SET used_at = transaction_timestamp()
    WHERE c.id = p_code_id
      AND c.user_id = p_user_id
      AND c.used_at IS NULL;

    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    RETURN v_row_count > 0;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_recovery_code_consume(uuid, uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_recovery_code_consume(uuid, uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_recovery_code_consume(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_recovery_code_consume(uuid, uuid)
  TO idax_backend, idax_app, idax_admin;
