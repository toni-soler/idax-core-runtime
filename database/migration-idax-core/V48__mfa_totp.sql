-- V48: Local MFA (TOTP) support
--
-- app_user_mfa_configuration / app_user_recovery_code mirror app_user_credential
-- (V3__local_auth.sql): one row per user, global (app_user itself is not tenant-scoped,
-- see V5__fix_app_user_rls.sql), so no RLS here either.
--
-- auth_rate_limit_bucket is the shared anti-bruteforce counter for /api/auth/login and
-- /api/auth/mfa/verify (AuthRateLimiterService) - also global, keyed by an arbitrary string.
--
-- Backward compatible: no existing app_user row is touched. "no app_user_mfa_configuration row"
-- means MFA disabled, so every current user keeps logging in exactly as before.

CREATE TABLE IF NOT EXISTS idax_core.app_user_mfa_configuration (
    user_id uuid PRIMARY KEY REFERENCES idax_core.app_user(user_id) ON DELETE CASCADE,
    mfa_enabled boolean NOT NULL DEFAULT false,
    mfa_type varchar(20) NOT NULL DEFAULT 'NONE',
    totp_secret_encrypted text,
    totp_secret_pending_encrypted text,
    totp_pending_expires_at timestamptz,
    mfa_activated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS idax_core.app_user_recovery_code (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES idax_core.app_user(user_id) ON DELETE CASCADE,
    code_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at timestamptz
);

CREATE INDEX IF NOT EXISTS ix_app_user_recovery_code_user
ON idax_core.app_user_recovery_code(user_id);

CREATE TABLE IF NOT EXISTS idax_core.auth_rate_limit_bucket (
    throttle_key varchar(200) PRIMARY KEY,
    attempt_count integer NOT NULL DEFAULT 0,
    window_started_at timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION idax_core.tg_mfa_configuration_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_app_user_mfa_configuration_updated
ON idax_core.app_user_mfa_configuration;

CREATE TRIGGER trg_app_user_mfa_configuration_updated
BEFORE UPDATE ON idax_core.app_user_mfa_configuration
FOR EACH ROW
EXECUTE FUNCTION idax_core.tg_mfa_configuration_updated_at();

DROP TRIGGER IF EXISTS trg_auth_rate_limit_bucket_updated
ON idax_core.auth_rate_limit_bucket;

CREATE TRIGGER trg_auth_rate_limit_bucket_updated
BEFORE UPDATE ON idax_core.auth_rate_limit_bucket
FOR EACH ROW
EXECUTE FUNCTION idax_core.tg_mfa_configuration_updated_at();

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.app_user_mfa_configuration TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.app_user_mfa_configuration TO idax_admin;

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.app_user_recovery_code TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.app_user_recovery_code TO idax_admin;

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.auth_rate_limit_bucket TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.auth_rate_limit_bucket TO idax_admin;
