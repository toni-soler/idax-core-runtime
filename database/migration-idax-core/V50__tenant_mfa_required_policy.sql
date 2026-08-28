-- V50: tenant-wide "require MFA for all users" policy
--
-- A tenant admin/superuser can force every user of that tenant to have TOTP MFA configured -
-- see LocalAuthService#login (MFA_SETUP_REQUIRED path) and MfaForcedSetupService.
--
-- Backward compatible: defaults to false, so no existing tenant changes behavior on deploy.

ALTER TABLE idax_core.tenant
    ADD COLUMN IF NOT EXISTS mfa_required boolean NOT NULL DEFAULT false;
