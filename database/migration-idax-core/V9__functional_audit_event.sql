CREATE TABLE IF NOT EXISTS idax_core.idax_audit_event (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_time      timestamptz NOT NULL DEFAULT now(),
  dataareaid      varchar(10) NULL,
  company         varchar(50) NULL,
  tenant_id       uuid NULL,
  origin_system   varchar(50) NOT NULL,
  event_type      varchar(120) NOT NULL,
  operation       varchar(50) NOT NULL,
  entity_name     varchar(120) NULL,
  entity_id       varchar(200) NULL,
  business_key    varchar(300) NULL,
  external_key    varchar(300) NULL,
  real_user_id    varchar(100) NULL,
  real_user_name  varchar(200) NULL,
  technical_user  varchar(200) NULL,
  source_ip       varchar(100) NULL,
  request_id      varchar(100) NULL,
  correlation_id  varchar(100) NULL,
  status          varchar(30) NOT NULL,
  error_message   text NULL,
  before_json     text NULL,
  after_json      text NULL,
  payload_json    text NULL,
  metadata_json   text NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_idax_audit_event_tenant
    FOREIGN KEY (tenant_id) REFERENCES idax_core.tenant(tenant_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_correlation_id
  ON idax_core.idax_audit_event(correlation_id);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_event_time
  ON idax_core.idax_audit_event(event_time DESC);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_entity_id
  ON idax_core.idax_audit_event(entity_name, entity_id);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_entity_business_key
  ON idax_core.idax_audit_event(entity_name, business_key);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_event_type
  ON idax_core.idax_audit_event(event_type);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_status
  ON idax_core.idax_audit_event(status);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_real_user_id
  ON idax_core.idax_audit_event(real_user_id);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_tenant_event_time
  ON idax_core.idax_audit_event(tenant_id, event_time DESC);

ALTER TABLE idax_core.idax_audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.idax_audit_event FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_idax_audit_event_admin ON idax_core.idax_audit_event;
CREATE POLICY p_idax_audit_event_admin ON idax_core.idax_audit_event
  FOR ALL TO idax_admin
  USING (true)
  WITH CHECK (true);

DROP POLICY IF EXISTS p_idax_audit_event_app_select ON idax_core.idax_audit_event;
CREATE POLICY p_idax_audit_event_app_select ON idax_core.idax_audit_event
  FOR SELECT TO idax_app
  USING (tenant_id IS NOT NULL AND idax_core.is_current_user_member_of_tenant(tenant_id));

DROP POLICY IF EXISTS p_idax_audit_event_app_insert ON idax_core.idax_audit_event;
CREATE POLICY p_idax_audit_event_app_insert ON idax_core.idax_audit_event
  FOR INSERT TO idax_app
  WITH CHECK (tenant_id IS NULL OR idax_core.is_current_user_member_of_tenant(tenant_id));

GRANT SELECT, INSERT ON idax_core.idax_audit_event TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.idax_audit_event TO idax_admin;
