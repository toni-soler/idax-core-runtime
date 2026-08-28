CREATE TABLE IF NOT EXISTS idax_core.idax_message_header (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    message_date TIMESTAMPTZ NOT NULL DEFAULT now(),
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    critical BOOLEAN NOT NULL DEFAULT FALSE,
    response_required BOOLEAN NOT NULL DEFAULT FALSE,
    automatic BOOLEAN NOT NULL DEFAULT FALSE,
    origin_message_id UUID NULL REFERENCES idax_core.idax_message_header(message_id) ON DELETE SET NULL,
    event_code VARCHAR(80) NULL,
    event_text VARCHAR(255) NULL,
    created_by UUID NULL REFERENCES idax_core.app_user(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS idax_core.idax_message_user (
    message_user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    message_id UUID NOT NULL REFERENCES idax_core.idax_message_header(message_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES idax_core.app_user(user_id) ON DELETE CASCADE,
    message_type CHAR(1) NOT NULL CHECK (message_type IN ('S', 'E')),
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    read_at TIMESTAMPTZ NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at TIMESTAMPTZ NULL,
    is_responded BOOLEAN NOT NULL DEFAULT FALSE,
    responded_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_idax_message_user UNIQUE (message_id, user_id, message_type)
);

CREATE TABLE IF NOT EXISTS idax_core.idax_message_attachment (
    attachment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    message_id UUID NOT NULL REFERENCES idax_core.idax_message_header(message_id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    content_type VARCHAR(120) NOT NULL DEFAULT 'application/octet-stream',
    content BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_idax_message_header_tenant_date
    ON idax_core.idax_message_header (tenant_id, message_date DESC);

CREATE INDEX IF NOT EXISTS ix_idax_message_header_origin
    ON idax_core.idax_message_header (tenant_id, origin_message_id);

CREATE INDEX IF NOT EXISTS ix_idax_message_user_mailbox
    ON idax_core.idax_message_user (tenant_id, user_id, message_type, is_deleted, is_read);

CREATE INDEX IF NOT EXISTS ix_idax_message_user_message
    ON idax_core.idax_message_user (tenant_id, message_id);

CREATE INDEX IF NOT EXISTS ix_idax_message_attachment_message
    ON idax_core.idax_message_attachment (tenant_id, message_id);

ALTER TABLE idax_core.idax_message_header ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_message_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_message_attachment ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_idax_message_header_tenant ON idax_core.idax_message_header;
CREATE POLICY p_idax_message_header_tenant ON idax_core.idax_message_header
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

DROP POLICY IF EXISTS p_idax_message_user_tenant ON idax_core.idax_message_user;
CREATE POLICY p_idax_message_user_tenant ON idax_core.idax_message_user
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

DROP POLICY IF EXISTS p_idax_message_attachment_tenant ON idax_core.idax_message_attachment;
CREATE POLICY p_idax_message_attachment_tenant ON idax_core.idax_message_attachment
FOR ALL TO idax_app
USING (idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_message_header TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_message_user TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_message_attachment TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.idax_message_header TO idax_admin;
GRANT ALL PRIVILEGES ON idax_core.idax_message_user TO idax_admin;
GRANT ALL PRIVILEGES ON idax_core.idax_message_attachment TO idax_admin;

INSERT INTO idax_core.idax_permission
    (permission_code, module_key, resource_key, action_key, label_key, api_path, description)
VALUES
    ('messaging.read', 'system', 'messaging', 'read', 'permissions.actions.read', '/api/core/messages', 'View own messages'),
    ('messaging.create', 'system', 'messaging', 'create', 'permissions.actions.create', '/api/core/messages', 'Send messages'),
    ('messaging.update', 'system', 'messaging', 'update', 'permissions.actions.update', '/api/core/messages', 'Update own message state'),
    ('messaging.delete', 'system', 'messaging', 'delete', 'permissions.actions.delete', '/api/core/messages', 'Delete own messages')
ON CONFLICT (permission_code) DO NOTHING;

INSERT INTO idax_core.idax_role_permission (role_id, permission_code)
SELECT r.role_id, p.permission_code
FROM idax_core.idax_role r
JOIN idax_core.idax_permission p
  ON p.permission_code IN ('messaging.read', 'messaging.create', 'messaging.update', 'messaging.delete')
WHERE r.role_key IN ('owner', 'admin', 'user')
ON CONFLICT DO NOTHING;
