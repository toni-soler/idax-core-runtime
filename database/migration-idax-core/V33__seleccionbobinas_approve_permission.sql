-- V33__seleccionbobinas_approve_permission.sql
--
-- Permission gating the "Marcar revisado" action of the "Seleccion de
-- bobinas" (CMT_INF) screen replica, and re-locking of the selection
-- checkboxes once a sales order has been reviewed by management. Any
-- authenticated tenant user can view the screen and, while the order is not
-- yet reviewed, edit the selection; only holders of this permission (plus
-- owner/admin, who implicitly hold every permission) can mark an order as
-- reviewed or keep editing it afterwards.
INSERT INTO idax_core.idax_permission
    (permission_code, module_key, resource_key, action_key, label_key, api_path, description)
VALUES
    ('sales.seleccionbobinas.approve', 'sales', 'sales.seleccionbobinas', 'approve',
     'permissions.actions.approve', '/api/legacy/cmt-seleccionbobinas',
     'Mark a sales order Seleccion de bobinas as reviewed and edit it after review')
ON CONFLICT (permission_code) DO NOTHING;

INSERT INTO idax_core.idax_role_permission(role_id, permission_code)
SELECT r.role_id, p.permission_code
FROM idax_core.idax_role r
JOIN idax_core.idax_permission p ON p.permission_code = 'sales.seleccionbobinas.approve'
WHERE r.role_key IN ('owner', 'admin')
ON CONFLICT DO NOTHING;
