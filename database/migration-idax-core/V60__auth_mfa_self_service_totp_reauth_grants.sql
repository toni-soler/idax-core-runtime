-- V60: DB-C1A.6 - reuse the DB-C1A.3/DB-C1A.4a MFA TOTP capabilities for self-service reauthentication
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md (binding architecture) and
-- MfaSelfServiceService#reauthenticate's TOTP branch, called from disable()/regenerateRecoveryCodes()
-- (authenticated, tenant-scoped self-service). Traced exactly from the real Java implementation
-- before writing this migration - see the DB-C1A.6 gate report for the full trace.
--
-- Pre-fix gap (empirically confirmed, real PostgreSQL + real service beans, not reasoning alone):
-- reauthenticate's TOTP branch performed the exact pre-DB-C1A.4 shape - read last_used_totp_step
-- from the JPA entity (no lock), compare in Java, JPA save (no optimistic version) - the SAME
-- read-compare-write sequence already proved unsafe for MfaLoginService. A deterministic
-- concurrency test (MfaSelfServiceTotpReauthConcurrencyTest, pre-fix run) confirmed: 2 concurrent
-- self-service reauth attempts with the same TOTP step both succeeded (expected 1), 5 concurrent
-- attempts all 5 succeeded (expected 1), and - critically - a concurrent MfaLoginService#verify
-- call and a MfaSelfServiceService reauth call for the SAME step could BOTH succeed (expected
-- exactly one globally), because the two Java call sites shared no common atomic authority.
-- SELF-SERVICE TOTP CONCURRENT REPLAY: GAP CONFIRMED.
-- CROSS-FLOW TOTP REPLAY: GAP CONFIRMED.
--
-- Fix: no new SQL primitive. The self-service TOTP branch's read is semantically IDENTICAL to
-- MfaLoginService#verify's read (same four fields: mfa_enabled, mfa_type, totp_secret_encrypted,
-- last_used_totp_step - see MfaVerificationState.isMfaActive(), which already matches
-- AppUserMfaConfiguration#isMfaActive() field-for-field), and the atomic claim is semantically
-- IDENTICAL to MfaLoginService#verify's claim (atomic step CAS bound to the exact verified
-- ciphertext). A capability boundary describes an operation's security semantics, not which Java
-- service happens to call it, so this migration does not duplicate
-- auth_mfa_verification_state_lookup(uuid) (V56) or auth_mfa_totp_advance(uuid,bigint,text) (V58)
-- - it only extends their EXECUTE grants to the newly-proven legitimate caller. Sharing one atomic
-- authority between MfaLoginService and MfaSelfServiceService is exactly what closes the
-- cross-flow gap: PostgreSQL's row lock on the single conditional UPDATE makes two concurrent
-- callers - regardless of which Java service issued them - mutually exclusive for the same
-- user/step, and (via V58's DB-C1A.4a binding) the same secret-state check.
--
-- Grantee derivation (independent per function, DATABASE_PRIVILEGED_CAPABILITIES.md's corrected
-- rule): MfaSelfServiceService is reached only via /api/me/mfa/** (MeMfaController), which requires
-- @AuthenticationPrincipal CurrentUser - always authenticated, always tenant-scoped. TenantContextFilter
-- selects idax_app for an ordinary user and, for the same reason V55's rate-limit capability already
-- documented, transitionally idax_admin for a superuser request that still resolves an effective
-- tenant (DATABASE_PRIVILEGED_CAPABILITIES.md section 21, "INCIDENTAL SUPERUSER DB ELEVATION").
-- MfaLoginService's own call site is untouched and remains bare idax_backend only (pre-tenant,
-- permitAll) - this migration does not grant or revoke anything for idax_backend, and does not
-- alter V56/V58's function bodies, ownership, or existing idax_backend grant.
--
-- Owner privileges: unchanged. This migration grants no new SELECT/UPDATE/INSERT/DELETE to
-- idax_capability_owner - V56 (SELECT) and V57/V58 (column-level UPDATE) already cover every
-- column either function reads or writes; a pure EXECUTE grant needs no additional owner data
-- privilege. No idax_capability_owner membership is granted to any runtime role.
--
-- PUBLIC: unchanged, still denied on both functions.
--
-- DB-C1B transitional cleanup obligation (extends the checklist already started at DB-C1A.2 and
-- DB-C1A.5): once DB-C1B makes HTTP always select idax_app for authenticated requests,
-- REVOKE EXECUTE ON FUNCTION idax_core.auth_mfa_verification_state_lookup(uuid),
-- idax_core.auth_mfa_totp_advance(uuid,bigint,text) FROM idax_admin becomes safe and required.

-- Granting EXECUTE on a function owned by idax_capability_owner requires the migration role to be
-- a member of that owner role (or superuser). V54/56/57/58/59 already granted this for the same
-- migration identity in the common case, but re-issuing here keeps this migration self-contained
-- if it ever runs in a different session. This grants no new DATA privilege - membership alone
-- does not let CURRENT_USER read/write the underlying tables, only administer EXECUTE on
-- functions this role already owns.
GRANT idax_capability_owner TO CURRENT_USER;

GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_verification_state_lookup(uuid)
  TO idax_app, idax_admin;

GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_totp_advance(uuid, bigint, text)
  TO idax_app, idax_admin;
