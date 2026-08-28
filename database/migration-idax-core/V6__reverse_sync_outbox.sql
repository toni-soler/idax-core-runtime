-- Reverse-sync transactional outbox foundation (IDAX -> AX4)
-- Generic tenant-scoped outbox with explicit tenantId/dataAreaId metadata.

CREATE TABLE IF NOT EXISTS idax_core.reverse_sync_outbox (
  outbox_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id        uuid NOT NULL UNIQUE,
  tenant_id         uuid NOT NULL,
  dataareaid        varchar(3) NOT NULL,
  schema_version    integer NOT NULL DEFAULT 1,
  source_system     varchar(50) NOT NULL DEFAULT 'IDAX',
  entity_name       varchar(100) NOT NULL,
  operation_name    varchar(100) NOT NULL,
  business_key      varchar(200) NOT NULL,
  payload_json      text NOT NULL,
  correlation_id    varchar(100) NULL,
  causation_id      varchar(100) NULL,
  occurred_at       timestamptz NOT NULL DEFAULT now(),
  status            varchar(30) NOT NULL DEFAULT 'PENDING',
  attempt_count     integer NOT NULL DEFAULT 0,
  next_attempt_at   timestamptz NULL,
  last_error        text NULL,
  last_dispatch_at  timestamptz NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_reverse_sync_outbox_tenant
    FOREIGN KEY (tenant_id) REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
  CONSTRAINT ck_reverse_sync_outbox_attempt_count_non_negative
    CHECK (attempt_count >= 0),
  CONSTRAINT ck_reverse_sync_outbox_dataarea_len
    CHECK (char_length(dataareaid) = 3)
);

CREATE INDEX IF NOT EXISTS ix_reverse_sync_outbox_status_next_attempt
  ON idax_core.reverse_sync_outbox(status, next_attempt_at, created_at);

CREATE INDEX IF NOT EXISTS ix_reverse_sync_outbox_tenant_created_at
  ON idax_core.reverse_sync_outbox(tenant_id, created_at);

CREATE TRIGGER trg_reverse_sync_outbox_updated_at
BEFORE UPDATE ON idax_core.reverse_sync_outbox
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE TRIGGER trg_reverse_sync_outbox_set_tenant
BEFORE INSERT ON idax_core.reverse_sync_outbox
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_reverse_sync_outbox_no_tenant_update
BEFORE UPDATE ON idax_core.reverse_sync_outbox
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

ALTER TABLE idax_core.reverse_sync_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.reverse_sync_outbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_reverse_sync_outbox_admin ON idax_core.reverse_sync_outbox;
CREATE POLICY p_reverse_sync_outbox_admin ON idax_core.reverse_sync_outbox
  FOR ALL TO idax_admin
  USING (true)
  WITH CHECK (true);

DROP POLICY IF EXISTS p_reverse_sync_outbox_app ON idax_core.reverse_sync_outbox;
CREATE POLICY p_reverse_sync_outbox_app ON idax_core.reverse_sync_outbox
  FOR ALL TO idax_app
  USING (idax_core.is_current_user_member_of_tenant(tenant_id))
  WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.reverse_sync_outbox TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.reverse_sync_outbox TO idax_admin;
