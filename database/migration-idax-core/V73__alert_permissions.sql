-- V73__alert_permissions.sql
--
-- Permissions gating the generic alert configuration screen: any tenant
-- user can see which alerts are configured (read), only owner/admin can
-- create/edit alert definitions or trigger a manual run (manage).
INSERT INTO idax_core.idax_permission
    (permission_code, module_key, resource_key, action_key, label_key, api_path, description)
VALUES
    ('alerts.read', 'system', 'alerts', 'read', 'permissions.actions.read',
     '/api/core/alerts', 'View configured alert definitions and their run history'),
    ('alerts.manage', 'system', 'alerts', 'manage', 'permissions.actions.update',
     '/api/core/alerts', 'Create, edit, enable/disable and manually trigger alert definitions')
ON CONFLICT (permission_code) DO NOTHING;

INSERT INTO idax_core.idax_role_permission (role_id, permission_code)
SELECT r.role_id, p.permission_code
FROM idax_core.idax_role r
JOIN idax_core.idax_permission p
  ON p.permission_code = 'alerts.read'
WHERE r.role_key IN ('owner', 'admin', 'user')
ON CONFLICT DO NOTHING;

INSERT INTO idax_core.idax_role_permission (role_id, permission_code)
SELECT r.role_id, p.permission_code
FROM idax_core.idax_role r
JOIN idax_core.idax_permission p
  ON p.permission_code = 'alerts.manage'
WHERE r.role_key IN ('owner', 'admin')
ON CONFLICT DO NOTHING;
