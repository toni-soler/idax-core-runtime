-- Forward integration IDAX -> FactuFlow: mismo patron transaccional que
-- reverse_sync_outbox (V6__reverse_sync_outbox.sql) pero para el sentido
-- contrario (IDAX detecta una entidad recien sincronizada desde AX4 y
-- dispara la creacion de la factura equivalente en FactuFlow), y con
-- target_system explicito para dejar la tabla abierta a futuros destinos
-- distintos de FactuFlow sin necesitar otra tabla.
--
-- factuflow_company_mapping resuelve, por empresa AX (dataareaid), a que
-- tenant/empresa/actividad de FactuFlow debe ir la factura, si el envio
-- esta activo, y si se debe emitir automaticamente (Veri*factu/e-factura)
-- nada mas crearla o dejarla en BORRADOR para revision manual. Multi-empresa
-- desde el origen: una fila por dataareaid, no una unica config global.

CREATE TABLE IF NOT EXISTS idax_core.factuflow_company_mapping (
  mapping_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL,
  dataareaid            varchar(3) NOT NULL,
  factuflow_tenant_id   uuid NOT NULL,
  factuflow_empresa_id  uuid NOT NULL,
  factuflow_actividad_id uuid NOT NULL,
  enabled               boolean NOT NULL DEFAULT true,
  auto_issue            boolean NOT NULL DEFAULT false,
  fiscal_series_id      uuid NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_factuflow_company_mapping_tenant
    FOREIGN KEY (tenant_id) REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
  CONSTRAINT ck_factuflow_company_mapping_dataarea_len
    CHECK (char_length(dataareaid) = 3),
  CONSTRAINT uq_factuflow_company_mapping_tenant_dataarea
    UNIQUE (tenant_id, dataareaid)
);

CREATE TRIGGER trg_factuflow_company_mapping_updated_at
BEFORE UPDATE ON idax_core.factuflow_company_mapping
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE TRIGGER trg_factuflow_company_mapping_set_tenant
BEFORE INSERT ON idax_core.factuflow_company_mapping
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_factuflow_company_mapping_no_tenant_update
BEFORE UPDATE ON idax_core.factuflow_company_mapping
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

ALTER TABLE idax_core.factuflow_company_mapping ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.factuflow_company_mapping FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_factuflow_company_mapping_admin ON idax_core.factuflow_company_mapping;
CREATE POLICY p_factuflow_company_mapping_admin ON idax_core.factuflow_company_mapping
  FOR ALL TO idax_admin
  USING (true)
  WITH CHECK (true);

DROP POLICY IF EXISTS p_factuflow_company_mapping_app ON idax_core.factuflow_company_mapping;
CREATE POLICY p_factuflow_company_mapping_app ON idax_core.factuflow_company_mapping
  FOR ALL TO idax_app
  USING (idax_core.is_current_user_member_of_tenant(tenant_id))
  WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.factuflow_company_mapping TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.factuflow_company_mapping TO idax_admin;

CREATE TABLE IF NOT EXISTS idax_core.factuflow_outbox (
  outbox_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id        uuid NOT NULL UNIQUE,
  tenant_id         uuid NOT NULL,
  dataareaid        varchar(3) NOT NULL,
  target_system     varchar(30) NOT NULL DEFAULT 'FACTUFLOW',
  entity_name       varchar(100) NOT NULL,
  business_key      varchar(200) NOT NULL,
  correlation_id    varchar(100) NULL,
  occurred_at       timestamptz NOT NULL DEFAULT now(),
  status            varchar(30) NOT NULL DEFAULT 'PENDING',
  attempt_count     integer NOT NULL DEFAULT 0,
  next_attempt_at   timestamptz NULL,
  last_error        text NULL,
  last_dispatch_at  timestamptz NULL,
  factuflow_invoice_id uuid NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_factuflow_outbox_tenant
    FOREIGN KEY (tenant_id) REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
  CONSTRAINT ck_factuflow_outbox_attempt_count_non_negative
    CHECK (attempt_count >= 0),
  CONSTRAINT ck_factuflow_outbox_dataarea_len
    CHECK (char_length(dataareaid) = 3),
  -- Un mismo registro AX (entity_name+business_key) no debe encolarse dos
  -- veces mientras siga pendiente/en curso; una vez SENT/SKIPPED se libera
  -- para permitir un reintento manual explicito si hiciera falta.
  CONSTRAINT uq_factuflow_outbox_pending_entity_key
    UNIQUE (tenant_id, entity_name, business_key, status)
);

CREATE INDEX IF NOT EXISTS ix_factuflow_outbox_status_next_attempt
  ON idax_core.factuflow_outbox(status, next_attempt_at, created_at);

CREATE INDEX IF NOT EXISTS ix_factuflow_outbox_tenant_created_at
  ON idax_core.factuflow_outbox(tenant_id, created_at);

CREATE TRIGGER trg_factuflow_outbox_updated_at
BEFORE UPDATE ON idax_core.factuflow_outbox
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE TRIGGER trg_factuflow_outbox_set_tenant
BEFORE INSERT ON idax_core.factuflow_outbox
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_factuflow_outbox_no_tenant_update
BEFORE UPDATE ON idax_core.factuflow_outbox
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

ALTER TABLE idax_core.factuflow_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.factuflow_outbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_factuflow_outbox_admin ON idax_core.factuflow_outbox;
CREATE POLICY p_factuflow_outbox_admin ON idax_core.factuflow_outbox
  FOR ALL TO idax_admin
  USING (true)
  WITH CHECK (true);

DROP POLICY IF EXISTS p_factuflow_outbox_app ON idax_core.factuflow_outbox;
CREATE POLICY p_factuflow_outbox_app ON idax_core.factuflow_outbox
  FOR ALL TO idax_app
  USING (idax_core.is_current_user_member_of_tenant(tenant_id))
  WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.factuflow_outbox TO idax_app;
GRANT ALL PRIVILEGES ON idax_core.factuflow_outbox TO idax_admin;
