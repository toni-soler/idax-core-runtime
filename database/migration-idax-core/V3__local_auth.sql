-- IDAX Core - Local authentication support (optional)

-- 1) Superuser flag (global)
ALTER TABLE idax_core.app_user
    ADD COLUMN IF NOT EXISTS is_superuser boolean NOT NULL DEFAULT false;

-- 2) Local credentials
CREATE TABLE IF NOT EXISTS idax_core.app_user_credential (
    user_id uuid PRIMARY KEY REFERENCES idax_core.app_user(user_id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    password_algo text NOT NULL DEFAULT 'bcrypt',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_app_user_credential_user
ON idax_core.app_user_credential(user_id);

CREATE OR REPLACE FUNCTION idax_core.tg_credential_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_app_user_credential_updated
ON idax_core.app_user_credential;

CREATE TRIGGER trg_app_user_credential_updated
BEFORE UPDATE ON idax_core.app_user_credential
FOR EACH ROW
EXECUTE FUNCTION idax_core.tg_credential_updated_at();


-- 3) Crear usuario base
INSERT INTO idax_core.app_user (
    external_subject,
    email,
    display_name,
    auth_provider,
    is_superuser
)
VALUES (
    'local:admin',
    'admin@local',
    'Admin',
    'local',
    true
)
ON CONFLICT (external_subject) DO NOTHING;


-- 4) Crear credencial
INSERT INTO idax_core.app_user_credential (
    user_id,
    password_hash
)
SELECT
    u.user_id,
    '$2a$10$jkXIK9Hn/xk3sqjmFWZDSe2QXGR2490zdTYHPyo.O.fMVKdzL80XS'
FROM idax_core.app_user u
WHERE u.external_subject = 'local:admin'
ON CONFLICT (user_id) DO NOTHING;