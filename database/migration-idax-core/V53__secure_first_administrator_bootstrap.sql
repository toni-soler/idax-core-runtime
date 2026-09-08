CREATE TABLE idax_core.first_administrator_bootstrap (
    singleton_key boolean PRIMARY KEY DEFAULT true CHECK (singleton_key),
    completed boolean NOT NULL DEFAULT false,
    completed_at timestamptz NULL,
    tenant_id uuid NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE SET NULL,
    user_id uuid NULL REFERENCES idax_core.app_user(user_id) ON DELETE SET NULL
);

-- V3 created a development-only account with a published default password. Remove only
-- that exact untouched seed; customized or tenant-linked accounts are deliberately retained.
DELETE FROM idax_core.app_user u
WHERE u.external_subject = 'local:admin'
  AND u.email = 'admin@local'
  AND u.is_superuser
  AND NOT EXISTS (SELECT 1 FROM idax_core.tenant_user tu WHERE tu.user_id = u.user_id)
  AND EXISTS (
      SELECT 1
      FROM idax_core.app_user_credential c
      WHERE c.user_id = u.user_id
        AND c.password_hash = '$2a$10$jkXIK9Hn/xk3sqjmFWZDSe2QXGR2490zdTYHPyo.O.fMVKdzL80XS'
  );

INSERT INTO idax_core.first_administrator_bootstrap (singleton_key, completed, completed_at)
SELECT true,
       EXISTS (
           SELECT 1
           FROM idax_core.app_user u
           WHERE u.is_active
             AND (
                 u.is_superuser
                 OR EXISTS (
                     SELECT 1
                     FROM idax_core.tenant_user tu
                     WHERE tu.user_id = u.user_id
                       AND lower(tu.role) IN ('owner', 'admin')
                 )
             )
       ),
       CASE WHEN EXISTS (
           SELECT 1
           FROM idax_core.app_user u
           WHERE u.is_active
             AND (u.is_superuser OR EXISTS (
                 SELECT 1 FROM idax_core.tenant_user tu
                 WHERE tu.user_id = u.user_id AND lower(tu.role) IN ('owner', 'admin')
             ))
       ) THEN now() ELSE NULL END;

ALTER TABLE idax_core.first_administrator_bootstrap ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.first_administrator_bootstrap FORCE ROW LEVEL SECURITY;

CREATE POLICY p_first_administrator_bootstrap_admin
ON idax_core.first_administrator_bootstrap
FOR ALL TO idax_admin USING (true) WITH CHECK (true);

REVOKE ALL ON idax_core.first_administrator_bootstrap FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON idax_core.first_administrator_bootstrap TO idax_admin;
