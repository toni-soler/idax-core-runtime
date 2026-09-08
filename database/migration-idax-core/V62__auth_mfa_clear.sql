-- V62: DB-C1A.8 - atomic MFA clear/reset capability, shared by self-service and admin
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md (binding architecture). Traced exactly from the real
-- Java implementations before writing this migration - see the DB-C1A.8 gate report for the full
-- field-by-field state-transition comparison.
--
-- Two production call sites currently perform the IDENTICAL database state transition via direct
-- JPA read-modify-save + a separate delete, with no cross-table atomicity:
--   MfaSelfServiceService#disable (self-service, gated by reauthenticate() - password + a fresh
--     TOTP/recovery-code proof, DB-C1A.4a/DB-C1A.5/DB-C1A.6's atomic capabilities);
--   TenantUserService#resetMfa (admin, gated by @PreAuthorize on the controller -
--     tenantAuth.validateTenantAccess + permissionService.hasPermission('system.users.update')).
-- Both set mfa_enabled=false, mfa_type='NONE', totp_secret_encrypted=NULL,
-- totp_secret_pending_encrypted=NULL, totp_pending_expires_at=NULL, mfa_activated_at=NULL on
-- idax_core.app_user_mfa_configuration (resetMfa skips this update entirely - not an error, just
-- a no-op - when no config row exists at all, since a user who never set up MFA has nothing to
-- clear there; disable() can never reach this case, since reauthenticate() already requires an
-- active config to proceed), and both unconditionally delete every
-- idax_core.app_user_recovery_code row for the user regardless of whether a config row existed.
-- DATABASE TRANSITION: IDENTICAL. One shared capability is therefore the correct architecture -
-- not two near-duplicate functions, and not a generic action-dispatcher function taking a
-- caller-supplied action/role/permission flag (WHO may invoke this stays entirely Java-side,
-- exactly as today: reauthenticate() for self-service, @PreAuthorize for admin - this SQL
-- function has no notion of "self-service" vs "admin" and must never be given one).
--
-- last_used_totp_step is deliberately left untouched, matching BOTH pre-existing Java behaviors
-- exactly - neither disable() nor resetMfa() ever wrote it. It becomes inert immediately: V58's
-- atomic claim (idax_core.auth_mfa_totp_advance) requires mfa_enabled=true AND mfa_type='TOTP' AND
-- a matching totp_secret_encrypted, all three of which this function clears/nulls, so a stale
-- last_used_totp_step can never enable an accepted claim after this function runs, with or without
-- a future re-activation (TOTP steps are monotonically increasing wall-clock counters, and
-- re-activation always writes a brand-new secret, so a residual old counter value is harmless -
-- same reasoning already established at DB-C1A.4a/DB-C1A.6).
--
-- Idempotent by construction: calling this twice in a row for the same user produces the same
-- final row state both times (the UPDATE's WHERE clause matches on user_id alone, not on prior
-- state, so re-running it against an already-cleared row simply re-writes the same values), and
-- the recovery-code DELETE is naturally idempotent (deleting zero remaining rows the second time
-- is not an error).
--
-- Grantee derivation (independent, DATABASE_PRIVILEGED_CAPABILITIES.md's corrected rule): both
-- real call sites are authenticated/tenant-scoped - MfaSelfServiceService#disable via
-- POST /api/me/mfa/disable (idax_app, transitionally idax_admin for the same superuser reason
-- already documented at DB-C1A.2/5/6/7), TenantUserService#resetMfa via
-- POST /api/tenants/{tenantId}/users/{userId}/mfa/reset (same TenantContext-derived role
-- selection - idax_app for an ordinary tenant admin, idax_admin for a superuser). Both flows
-- reach the identical grantee set (idax_app, idax_admin), so this migration grants the union,
-- derived independently rather than copied. idax_backend is NOT granted directly - neither call
-- site is pre-tenant - though it remains a standing INHERIT member of both idax_app and idax_admin
-- since V1 (predating DB-C1A), so it has EFFECTIVE EXECUTE via role inheritance regardless of this
-- migration's own grants - the same pre-existing role-graph caveat already documented at
-- DB-C1A.7 (DATABASE_PRIVILEGED_CAPABILITIES.md), not something this migration introduces or can
-- fix in isolation. DIRECT EXECUTE: idax_app, idax_admin. EFFECTIVE EXECUTE (via inheritance):
-- additionally idax_backend.
--
-- Owner privileges: column-level UPDATE on exactly the six cleared columns (narrower than V57/V58's
-- single-column precedent, but the same discipline) plus table-level DELETE on
-- app_user_recovery_code (PostgreSQL has no column-level DELETE - it is inherently table-scoped).
-- No SELECT is newly granted for app_user_mfa_configuration (V56 already granted table-wide
-- SELECT to idax_capability_owner, which also covers what an UPDATE's WHERE/RETURNING needs), and
-- no SELECT/INSERT is granted on app_user_recovery_code at all - this function only deletes there,
-- it never reads or creates a row.
--
-- Time authority: N/A - no timestamp column is written by this function.
-- updated_at on app_user_mfa_configuration is already PostgreSQL-authoritative via V48's
-- trg_app_user_mfa_configuration_updated (BEFORE UPDATE trigger, sets updated_at = now()) - it
-- fires automatically for this function's plain UPDATE exactly as it already did for the JPA path
-- it replaces, without this function needing to set it explicitly (same precedent as V57/V58).

GRANT UPDATE (mfa_enabled, mfa_type, totp_secret_encrypted, totp_secret_pending_encrypted,
              totp_pending_expires_at, mfa_activated_at)
  ON idax_core.app_user_mfa_configuration TO idax_capability_owner;
GRANT DELETE ON idax_core.app_user_recovery_code TO idax_capability_owner;

-- Ownership transfer below requires the migration role to be a member of the owner role. V54/V56/
-- V57/V58/V59/V60/V61 already granted this for the same migration identity in the common case,
-- but re-issuing here keeps this migration self-contained if it ever runs in a different session.
GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.auth_mfa_clear(p_user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_config_row_count integer;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'auth_mfa_clear: invalid user id' USING ERRCODE = '22023';
    END IF;

    UPDATE idax_core.app_user_mfa_configuration c
    SET mfa_enabled = false,
        mfa_type = 'NONE',
        totp_secret_encrypted = NULL,
        totp_secret_pending_encrypted = NULL,
        totp_pending_expires_at = NULL,
        mfa_activated_at = NULL
    WHERE c.user_id = p_user_id;

    GET DIAGNOSTICS v_config_row_count = ROW_COUNT;

    DELETE FROM idax_core.app_user_recovery_code
    WHERE user_id = p_user_id;

    RETURN v_config_row_count > 0;
END;
$function$;

ALTER FUNCTION idax_core.auth_mfa_clear(uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_mfa_clear(uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_mfa_clear(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_mfa_clear(uuid)
  TO idax_app, idax_admin;
