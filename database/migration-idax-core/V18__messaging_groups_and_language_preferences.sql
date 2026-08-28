ALTER TABLE idax_core.app_user_preference
    ADD COLUMN IF NOT EXISTS default_language VARCHAR(10) NULL,
    ADD COLUMN IF NOT EXISTS last_language VARCHAR(10) NULL;

ALTER TABLE idax_core.idax_message_header
    ADD COLUMN IF NOT EXISTS system_sender BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS idax_core.idax_message_group (
    group_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NULL REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
    owner_user_id UUID NULL REFERENCES idax_core.app_user(user_id) ON DELETE SET NULL,
    group_name VARCHAR(120) NOT NULL,
    description VARCHAR(255) NULL,
    system_group BOOLEAN NOT NULL DEFAULT FALSE,
    all_users BOOLEAN NOT NULL DEFAULT FALSE,
    created_by UUID NULL REFERENCES idax_core.app_user(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS idax_core.idax_message_group_member (
    group_id UUID NOT NULL REFERENCES idax_core.idax_message_group(group_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES idax_core.app_user(user_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS ix_idax_message_group_tenant
    ON idax_core.idax_message_group (tenant_id, group_name);

CREATE INDEX IF NOT EXISTS ix_idax_message_group_member_user
    ON idax_core.idax_message_group_member (user_id);

ALTER TABLE idax_core.idax_message_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_message_group_member ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_idax_message_group_tenant ON idax_core.idax_message_group;
CREATE POLICY p_idax_message_group_tenant ON idax_core.idax_message_group
FOR ALL TO idax_app
USING (tenant_id IS NULL OR idax_core.is_current_user_member_of_tenant(tenant_id))
WITH CHECK (tenant_id IS NULL OR idax_core.is_current_user_member_of_tenant(tenant_id));

DROP POLICY IF EXISTS p_idax_message_group_member_tenant ON idax_core.idax_message_group_member;
CREATE POLICY p_idax_message_group_member_tenant ON idax_core.idax_message_group_member
FOR ALL TO idax_app
USING (
    EXISTS (
        SELECT 1
        FROM idax_core.idax_message_group g
        WHERE g.group_id = idax_message_group_member.group_id
          AND (g.tenant_id IS NULL OR idax_core.is_current_user_member_of_tenant(g.tenant_id))
    )
)
WITH CHECK (
    EXISTS (
        SELECT 1
        FROM idax_core.idax_message_group g
        WHERE g.group_id = idax_message_group_member.group_id
          AND (g.tenant_id IS NULL OR idax_core.is_current_user_member_of_tenant(g.tenant_id))
    )
);

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_message_group TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.idax_message_group_member TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.idax_message_group TO idax_admin;
GRANT ALL PRIVILEGES ON idax_core.idax_message_group_member TO idax_admin;
