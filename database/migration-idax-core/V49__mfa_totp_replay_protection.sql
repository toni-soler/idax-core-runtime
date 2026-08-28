-- V49: TOTP anti-replay protection (follow-up to V48__mfa_totp.sql)
--
-- Kept as its own migration rather than folded into V48: by the time this was written, V48
-- had already been applied in a dev environment, and Flyway migrations must never be edited
-- once applied (checksum validation would then fail everywhere they already ran).
--
-- Stores the RFC 6238 time-step counter of the last TOTP code consumed for a user, so the exact
-- same code cannot authenticate more than one session within its validity window - see
-- TotpService#matchTimeStep / MfaLoginService#verify.

ALTER TABLE idax_core.app_user_mfa_configuration
    ADD COLUMN IF NOT EXISTS last_used_totp_step bigint;
