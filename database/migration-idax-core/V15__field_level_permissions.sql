ALTER TABLE idax_core.idax_permission
    ADD COLUMN field_key VARCHAR(120) NULL;

ALTER TABLE idax_core.idax_permission
    DROP CONSTRAINT uq_idax_permission_resource_action;

CREATE UNIQUE INDEX uq_idax_permission_resource_action
    ON idax_core.idax_permission (resource_key, action_key)
    WHERE field_key IS NULL;

CREATE UNIQUE INDEX uq_idax_permission_resource_field_action
    ON idax_core.idax_permission (resource_key, field_key, action_key)
    WHERE field_key IS NOT NULL;

