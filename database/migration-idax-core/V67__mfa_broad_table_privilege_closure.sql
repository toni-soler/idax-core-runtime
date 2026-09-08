-- V67: DB-C1A CLOSURE - revoke broad legacy runtime table access to both MFA tables
--
-- This is the culmination of DB-C1A.1 through DB-C1A.12: every legitimate runtime access path to
-- idax_core.app_user_mfa_configuration and idax_core.app_user_recovery_code now goes through a
-- narrow, idax_capability_owner-owned, SECURITY DEFINER function (V54-V66) - a full
-- production-source inventory, re-run immediately before this migration was authored (see the
-- DB-C1A closure gate report), found ZERO remaining direct consumers of either table anywhere in
-- production code (AppUserMfaConfigurationRepository/AppUserRecoveryCodeRepository, the entity
-- classes, and raw table-name JDBC access all searched). This migration removes the broad direct
-- table privileges that access no longer needs.
--
-- HISTORICAL GRANT SOURCE (traced from the immutable migration history, not assumed):
--   V1 (idax_core_modern_multitenant_rls) established the role graph this REVOKE undoes:
--     - idax_backend is a standing member of BOTH idax_app and idax_admin
--       (GRANT idax_app TO idax_backend; GRANT idax_admin TO idax_backend;) - it has never held
--       any DIRECT table grant of its own (V1 itself: "REVOKE ALL ON ALL TABLES IN SCHEMA
--       idax_core FROM idax_backend;", and no later migration ever grants idax_backend anything
--       on either MFA table directly - confirmed by searching every migration that touches
--       app_user_mfa_configuration/app_user_recovery_code). Its MFA table access has always been
--       purely EFFECTIVE, via this inheritance.
--     - V1 also sets schema-wide default privileges
--       (ALTER DEFAULT PRIVILEGES IN SCHEMA idax_core GRANT SELECT, INSERT, UPDATE, DELETE ON
--       TABLES TO idax_app; ... GRANT ALL ON TABLES TO idax_admin;) - these apply automatically
--       to any NEW table created in the schema by the same privileged identity, which is the
--       likely origin of (or at minimum is redundant with) V48's explicit grants below. This
--       migration does not touch that schema-wide default-privilege rule itself (it is out of
--       this gate's table-scoped mandate, and only affects tables created AFTER it runs - it
--       cannot retroactively restore a privilege this migration revokes from an already-existing
--       table).
--   V48 (mfa_totp) created both tables and explicitly granted:
--     GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.app_user_mfa_configuration TO idax_app;
--     GRANT ALL PRIVILEGES ON idax_core.app_user_mfa_configuration TO idax_admin;
--     GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.app_user_recovery_code TO idax_app;
--     GRANT ALL PRIVILEGES ON idax_core.app_user_recovery_code TO idax_admin;
--   No later migration (V49, V56-V66) ever grants idax_app/idax_admin/idax_backend anything
--   further at the TABLE level on either table - every migration from V56 onward grants only
--   EXECUTE on narrow functions, or column-level/table-level DATA privileges to
--   idax_capability_owner specifically (never to a runtime role). The four REVOKEs below are the
--   exact, complete undo of V48's four GRANTs - nothing more, nothing less.
--
-- WHAT THIS MIGRATION DOES NOT TOUCH (explicitly out of scope for this gate):
--   - idax_capability_owner's own accumulated data privileges (SELECT/UPDATE/INSERT/DELETE on
--     specific columns/tables, granted across V56-V66) - these remain exactly as they are; the
--     capability functions still need them to do their own SECURITY DEFINER work.
--   - EXECUTE on any MFA capability function - runtime roles keep exactly the EXECUTE grants they
--     already had (idax_backend on the pre-tenant functions; idax_app/transitionally idax_admin
--     on the self-service/verification functions). SECURITY DEFINER is precisely what allows a
--     role with EXECUTE-but-no-table-access to still successfully call a function whose OWNER has
--     the necessary table privilege - revoking table access does not, and must not, touch this.
--   - Any other table in idax_core, any other role, any global role membership, any capability
--     business logic. This migration is a privilege-boundary closure only.
--
-- IMPORTANT: this REVOKE removes DIRECT grants from idax_app/idax_admin. Because idax_backend's
-- access to these two tables has only ever been EFFECTIVE (via its standing membership in
-- idax_app/idax_admin, never a direct grant of its own), revoking the source roles' privilege
-- automatically removes idax_backend's effective access too - no separate action is needed or
-- possible for an inherited-only privilege. The explicit no-op REVOKEs on idax_backend below exist
-- purely as defensive, self-documenting completeness (mirroring V1's own defensive style), proving
-- the invariant rather than merely assuming it.

REVOKE SELECT, INSERT, UPDATE, DELETE ON idax_core.app_user_mfa_configuration FROM idax_app;
REVOKE ALL PRIVILEGES ON idax_core.app_user_mfa_configuration FROM idax_admin;

REVOKE SELECT, INSERT, UPDATE, DELETE ON idax_core.app_user_recovery_code FROM idax_app;
REVOKE ALL PRIVILEGES ON idax_core.app_user_recovery_code FROM idax_admin;

-- Defensive completeness only - idax_backend never held a direct grant on either table (see the
-- historical trace above); these REVOKEs are no-ops that document and guarantee the invariant.
REVOKE ALL ON idax_core.app_user_mfa_configuration FROM idax_backend;
REVOKE ALL ON idax_core.app_user_recovery_code FROM idax_backend;
