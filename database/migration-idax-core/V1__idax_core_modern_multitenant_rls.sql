-- ============================================================================
-- V1__idax_core_modern.sql
-- Core moderno IDAX v1.0 (multi-tenant real) con Row Level Security (RLS)
-- PostgreSQL 17
--
-- Objetivo:
--   - Modelo ER limpio y desacoplado del legado (AX / Sync iOS / tablas heredadas)
--   - Multi-tenant real por columna tenant_id + RLS
--   - Preparado para trazabilidad (runs, logs, artefactos) y orquestación (schedules)
--
-- Decisión de arquitectura (recomendada):
--   - Crear el core moderno en un esquema SEPARADO para no mezclarlo con el legado.
--     Esquema sugerido: idax_core
--   - Ventajas: migraciones claras, menor deuda, objetos modernos aislados
--   - El legado puede permanecer en schema "public" o "idax" (según tu setup)
--
-- Cómo funciona RLS:
--   - La app debe setear el tenant activo por sesión:
--       SELECT idax_core.set_tenant('<uuid-tenant>');
--   - Las políticas comparan tenant_id con current_setting('app.tenant_id', true)
--
-- Nota:
--   - Este script asume que lo ejecutas como un rol con permisos de DDL.
--   - Se crean roles lógicos idax_app e idax_admin (si tu plataforma gestiona roles
--     fuera de Flyway, puedes comentar ese bloque).
-- ============================================================================

-- =========================
-- 0) EXTENSIONES
-- =========================
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

-- =========================
-- 1) ESQUEMA, ROLES Y USUARIO
-- =========================
DO $$
BEGIN
   IF NOT EXISTS (
      SELECT 1 FROM pg_roles WHERE rolname = 'idax_backend'
   ) THEN
      CREATE ROLE idax_backend;
   END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS idax_core;

-- Roles lógicos (opcionales)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idax_app') THEN
    CREATE ROLE idax_app NOINHERIT;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idax_admin') THEN
    CREATE ROLE idax_admin NOINHERIT;
  END IF;
END$$;

-- Seguridad: por defecto, nadie ve nada salvo owner/roles explícitos
REVOKE ALL ON SCHEMA idax_core FROM PUBLIC;
GRANT USAGE ON SCHEMA idax_core TO idax_app, idax_admin;

-- Se asume que idax_backend es creado por infraestructura (Docker / IaC)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idax_backend') THEN
    RAISE NOTICE 'Role idax_backend must be created by infrastructure';
  END IF;
END $$;

GRANT idax_app   TO idax_backend;
GRANT idax_admin TO idax_backend;

-- =========================
-- 2) HELPERS (tenant context + timestamps)
-- =========================

-- Setter del tenant actual en la sesión
-- (SECURITY DEFINER para permitir que la app lo llame aunque tenga permisos limitados)
CREATE OR REPLACE FUNCTION idax_core.set_tenant(p_tenant_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM idax_core.tenant t WHERE t.tenant_id = p_tenant_id) THEN
    RAISE EXCEPTION 'Invalid tenant_id %', p_tenant_id USING ERRCODE = '22023';
  END IF;

  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
END;
$$;
  
ALTER FUNCTION idax_core.set_tenant(uuid) SET search_path = idax_core, pg_temp;

-- Obtener tenant actual (o NULL si no está seteado)
CREATE OR REPLACE FUNCTION idax_core.current_tenant_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  v text;
BEGIN
  v := current_setting('app.tenant_id', true);

  IF v IS NULL OR v = '' THEN
    RAISE EXCEPTION 'Tenant not set in session'
      USING ERRCODE = '22023';
  END IF;

  RETURN v::uuid;
END;
$$;

-- Trigger genérico updated_at
CREATE OR REPLACE FUNCTION idax_core.tg_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- =========================
-- 3) TABLAS PRINCIPALES (core)
-- =========================

-- 3.1 Tenants (catálogo global)
CREATE TABLE IF NOT EXISTS idax_core.tenant (
  tenant_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code             varchar(50) NOT NULL UNIQUE,   -- identificador corto (slug)
  name             varchar(200) NOT NULL,
  status           varchar(20) NOT NULL DEFAULT 'active', -- active | suspended | deleted
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_tenant_updated_at
BEFORE UPDATE ON idax_core.tenant
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

-- 3.2 Usuarios (identidad global con soporte local + external)

CREATE TABLE IF NOT EXISTS idax_core.app_user (
  user_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Identidad estable (username en local / sub en external)
  external_subject     varchar(200) NOT NULL,

  email                varchar(320) NOT NULL DEFAULT '',
  display_name         varchar(200) NOT NULL DEFAULT '',

  -- Tipo de autenticación
  auth_provider        varchar(30) NOT NULL DEFAULT 'local', 
  -- local | external | service

  is_active            boolean NOT NULL DEFAULT true,

  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT uq_app_user_subject UNIQUE (external_subject)
);

CREATE INDEX IF NOT EXISTS ix_app_user_provider
ON idax_core.app_user(auth_provider);

CREATE TRIGGER trg_app_user_updated_at
BEFORE UPDATE ON idax_core.app_user
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

-- 3.3 Membership (usuarios dentro de tenant)
CREATE TABLE IF NOT EXISTS idax_core.tenant_user (
  tenant_id        uuid NOT NULL,
  user_id          uuid NOT NULL,
  role             varchar(30) NOT NULL DEFAULT 'user', -- owner | admin | user | readonly | service
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id),
  CONSTRAINT fk_tenant_user_tenant FOREIGN KEY (tenant_id)
    REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
  CONSTRAINT fk_tenant_user_user FOREIGN KEY (user_id)
    REFERENCES idax_core.app_user(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_tenant_user_user_tenant
  ON idax_core.tenant_user(user_id, tenant_id);

-- 3.4 Conectores (config de integración: p.ej. AX4, S3, SMTP, etc.)
CREATE TABLE IF NOT EXISTS idax_core.connector (
  connector_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  code             varchar(80) NOT NULL,           -- p.ej. 'ax4-sql', 'sftp', 'graph-mail'
  name             varchar(200) NOT NULL,
  type             varchar(50) NOT NULL,           -- 'erp', 'mail', 'storage', 'api', ...
  is_enabled       boolean NOT NULL DEFAULT true,
  config_json      jsonb NOT NULL DEFAULT '{}'::jsonb, -- configuración no sensible
  secret_ref       varchar(200) NOT NULL DEFAULT '',   -- referencia a vault/secret manager (no guardar secretos aquí)
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_connector_tenant FOREIGN KEY (tenant_id)
    REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
  CONSTRAINT uq_connector_code UNIQUE (tenant_id, code)
);

ALTER TABLE idax_core.connector
  ADD CONSTRAINT uq_connector_tenant_connector_id UNIQUE (tenant_id, connector_id);

CREATE TRIGGER trg_connector_updated_at
BEFORE UPDATE ON idax_core.connector
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE INDEX IF NOT EXISTS ix_connector_tenant_enabled
  ON idax_core.connector(tenant_id, is_enabled);

-- 3.5 Runs (una ejecución orquestada: importación, sync, batch, etc.)
CREATE TABLE IF NOT EXISTS idax_core.run (
  run_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  connector_id     uuid NULL,
  run_type         varchar(50) NOT NULL,           -- 'import-sales', 'sync-master', ...
  status           varchar(30) NOT NULL DEFAULT 'queued', -- queued|running|success|failed|canceled
  requested_by     uuid NULL,                      -- app_user.user_id
  started_at       timestamptz NULL,
  finished_at      timestamptz NULL,
  correlation_id   varchar(100) NOT NULL DEFAULT '', -- id externo (job id, request id, etc.)
  input_json       jsonb NOT NULL DEFAULT '{}'::jsonb,
  output_json      jsonb NOT NULL DEFAULT '{}'::jsonb,
  error_code       varchar(100) NOT NULL DEFAULT '',
  error_message    text NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_run_tenant FOREIGN KEY (tenant_id)
    REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
  CONSTRAINT fk_run_connector FOREIGN KEY (tenant_id, connector_id)
    REFERENCES idax_core.connector(tenant_id, connector_id) ON DELETE SET NULL,
  CONSTRAINT fk_run_requested_by FOREIGN KEY (requested_by)
    REFERENCES idax_core.app_user(user_id) ON DELETE SET NULL
);

ALTER TABLE idax_core.run
  ADD CONSTRAINT uq_run_tenant_run_id UNIQUE (tenant_id, run_id);

CREATE TRIGGER trg_run_updated_at
BEFORE UPDATE ON idax_core.run
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE INDEX IF NOT EXISTS ix_run_tenant_status_created
  ON idax_core.run(tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_run_tenant_type_created
  ON idax_core.run(tenant_id, run_type, created_at DESC);

-- 3.6 RunLog (eventos y logs estructurados por run)
CREATE TABLE IF NOT EXISTS idax_core.run_log (
  run_log_id       bigserial PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  run_id           uuid NOT NULL,
  log_ts           timestamptz NOT NULL DEFAULT now(),
  level            varchar(10) NOT NULL DEFAULT 'INFO', -- TRACE|DEBUG|INFO|WARN|ERROR
  message          text NOT NULL DEFAULT '',
  details_json     jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT fk_run_log_run FOREIGN KEY (tenant_id, run_id)
    REFERENCES idax_core.run(tenant_id, run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_run_log_run_ts
  ON idax_core.run_log(tenant_id, run_id, log_ts);

-- 3.7 Artefactos (ficheros, outputs, reportes, etc. asociados a un run)
CREATE TABLE IF NOT EXISTS idax_core.artifact (
  artifact_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  run_id           uuid NULL,
  kind             varchar(50) NOT NULL,           -- 'file', 'report', 'payload', ...
  name             varchar(260) NOT NULL DEFAULT '',
  content_type     varchar(120) NOT NULL DEFAULT '',
  storage_provider varchar(30) NOT NULL DEFAULT 's3',  -- 's3','fs','azureblob',...
  storage_bucket   varchar(200) NOT NULL DEFAULT '',
  storage_key      varchar(800) NOT NULL DEFAULT '',
  size_bytes       bigint NOT NULL DEFAULT 0,
  checksum_sha256  varchar(64) NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_artifact_run FOREIGN KEY (tenant_id, run_id)
    REFERENCES idax_core.run(tenant_id, run_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_artifact_run
  ON idax_core.artifact(tenant_id, run_id);

-- 3.8 Schedules (planificación recurrente)
CREATE TABLE IF NOT EXISTS idax_core.schedule (
  schedule_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  code             varchar(80) NOT NULL,           -- identificador funcional
  name             varchar(200) NOT NULL,
  is_enabled       boolean NOT NULL DEFAULT true,
  timezone         varchar(64) NOT NULL DEFAULT 'Europe/Madrid',
  cron_expr        varchar(120) NOT NULL,          -- expresión cron (texto). La validación se hace en capa app/worker
  run_type         varchar(50) NOT NULL,
  connector_id     uuid NULL,
  default_input    jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_run_at      timestamptz NULL,
  next_run_at      timestamptz NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_schedule_tenant FOREIGN KEY (tenant_id)
    REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
  CONSTRAINT fk_schedule_connector FOREIGN KEY (tenant_id, connector_id)
    REFERENCES idax_core.connector(tenant_id, connector_id) ON DELETE SET NULL,
  CONSTRAINT uq_schedule_code UNIQUE (tenant_id, code)
);

CREATE TRIGGER trg_schedule_updated_at
BEFORE UPDATE ON idax_core.schedule
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE INDEX IF NOT EXISTS ix_schedule_tenant_enabled_next
  ON idax_core.schedule(tenant_id, is_enabled, next_run_at);

-- 3.9 Ingestion Inbox (eventos entrantes genéricos: webhooks, ficheros detectados, mails, etc.)
CREATE TABLE IF NOT EXISTS idax_core.inbox_event (
  inbox_event_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  source           varchar(50) NOT NULL,           -- 'webhook','mail','sftp','manual',...
  source_key       varchar(300) NOT NULL DEFAULT '', -- id externo del evento (Message-Id, filename, etc.)
  received_at      timestamptz NOT NULL DEFAULT now(),
  status           varchar(30) NOT NULL DEFAULT 'new', -- new|processing|processed|failed|discarded
  payload_json     jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_error       varchar(4000) NOT NULL DEFAULT '',
  processed_run_id uuid NULL,
  CONSTRAINT fk_inbox_tenant FOREIGN KEY (tenant_id)
    REFERENCES idax_core.tenant(tenant_id) ON DELETE CASCADE,
  CONSTRAINT fk_inbox_processed_run FOREIGN KEY (tenant_id, processed_run_id)
    REFERENCES idax_core.run(tenant_id, run_id) ON DELETE SET NULL,
  CONSTRAINT uq_inbox_source UNIQUE (tenant_id, source, source_key)
);

CREATE INDEX IF NOT EXISTS ix_inbox_tenant_status_received
  ON idax_core.inbox_event(tenant_id, status, received_at);

CREATE TABLE idax_core.integration (
    integration_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE idax_core.audit_log (
  audit_id        bigserial PRIMARY KEY,
  tenant_id       uuid NOT NULL,
  table_name      text NOT NULL,
  operation       varchar(10) NOT NULL, -- INSERT|UPDATE|DELETE
  db_user         text NOT NULL DEFAULT current_user,
  app_user_id     uuid NULL,
  changed_at      timestamptz NOT NULL DEFAULT now(),
  before_data     jsonb,
  after_data      jsonb
);

CREATE INDEX ix_audit_tenant_ts
ON idax_core.audit_log (tenant_id, changed_at DESC);

CREATE OR REPLACE FUNCTION idax_core.current_app_user_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  v text;
BEGIN
  v := current_setting('app.user_id', true);

  IF v IS NULL OR v = '' THEN
    RETURN NULL;
  END IF;

  RETURN v::uuid;
END;
$$;

CREATE OR REPLACE FUNCTION idax_core.tg_audit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_tenant uuid;
BEGIN

  IF TG_OP = 'DELETE' THEN
    v_tenant := OLD.tenant_id;
  ELSE
    v_tenant := NEW.tenant_id;
  END IF;

  BEGIN
    INSERT INTO idax_core.audit_log (
      tenant_id,
      table_name,
      operation,
      app_user_id,
      before_data,
      after_data
    )
    VALUES (
      v_tenant,
      TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
      TG_OP,
      idax_core.current_app_user_id(),
      CASE WHEN TG_OP IN ('UPDATE','DELETE') THEN to_jsonb(OLD) ELSE NULL END,
      CASE WHEN TG_OP IN ('INSERT','UPDATE') THEN to_jsonb(NEW) ELSE NULL END
    );

  EXCEPTION WHEN OTHERS THEN
    -- auditoría nunca debe romper la operación principal
    NULL;
  END;

  RETURN COALESCE(NEW, OLD);

END;
$$;

ALTER FUNCTION idax_core.tg_audit() SET search_path = idax_core, pg_temp;
REVOKE ALL ON FUNCTION idax_core.tg_audit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.tg_audit() TO idax_app, idax_admin;

CREATE TRIGGER trg_audit_connector
AFTER INSERT OR UPDATE OR DELETE ON idax_core.connector
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

CREATE TRIGGER trg_audit_run
AFTER INSERT OR UPDATE OR DELETE ON idax_core.run
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

CREATE TRIGGER trg_audit_run_log
AFTER INSERT OR UPDATE OR DELETE ON idax_core.run_log
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

CREATE TRIGGER trg_audit_artifact
AFTER INSERT OR UPDATE OR DELETE ON idax_core.artifact
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

CREATE TRIGGER trg_audit_schedule
AFTER INSERT OR UPDATE OR DELETE ON idax_core.schedule
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

CREATE TRIGGER trg_audit_inbox
AFTER INSERT OR UPDATE OR DELETE ON idax_core.inbox_event
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

CREATE TRIGGER trg_audit_tenant_user
AFTER INSERT OR UPDATE OR DELETE ON idax_core.tenant_user
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_audit();

CREATE OR REPLACE FUNCTION idax_core.block_audit_mod()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'Audit log is immutable';
END;
$$;

CREATE TRIGGER trg_block_audit_update
BEFORE UPDATE OR DELETE ON idax_core.audit_log
FOR EACH ROW EXECUTE FUNCTION idax_core.block_audit_mod();

-- =========================
-- 4) ROW LEVEL SECURITY (RLS)
-- =========================

-- Helper: comparación tenant actual
CREATE OR REPLACE FUNCTION idax_core.tenant_match(p_tenant_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT p_tenant_id = idax_core.current_tenant_id()
$$;

-- Helper: validación de membresía del usuario actual sobre un tenant
-- IMPORTANTE:
--   - SECURITY DEFINER para evitar depender de RLS sobre tenant_user
--   - search_path fijado para evitar problemas de seguridad
CREATE OR REPLACE FUNCTION idax_core.is_current_user_member_of_tenant(p_tenant_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM idax_core.tenant_user tu
    WHERE tu.user_id = idax_core.current_app_user_id()
      AND tu.tenant_id = p_tenant_id
  )
$$;

ALTER FUNCTION idax_core.is_current_user_member_of_tenant(uuid)
  SET search_path = idax_core, pg_temp;

REVOKE ALL ON FUNCTION idax_core.is_current_user_member_of_tenant(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.is_current_user_member_of_tenant(uuid) TO idax_app, idax_admin;

-- Activar RLS y forzar
ALTER TABLE idax_core.app_user          ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.tenant_user       ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.connector         ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.run               ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.run_log           ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.artifact          ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.schedule          ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.inbox_event       ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.integration       ENABLE ROW LEVEL SECURITY;
ALTER TABLE idax_core.audit_log         ENABLE ROW LEVEL SECURITY;

ALTER TABLE idax_core.app_user          FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.tenant_user       FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.connector         FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.run               FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.run_log           FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.artifact          FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.schedule          FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.inbox_event       FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.integration       FORCE ROW LEVEL SECURITY;
ALTER TABLE idax_core.audit_log         FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION idax_core.tg_set_tenant_id()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Forzar tenant_id desde la sesión
  NEW.tenant_id := idax_core.current_tenant_id();
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_connector_set_tenant
BEFORE INSERT ON idax_core.connector
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_run_set_tenant
BEFORE INSERT ON idax_core.run
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_run_log_set_tenant
BEFORE INSERT ON idax_core.run_log
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_artifact_set_tenant
BEFORE INSERT ON idax_core.artifact
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_schedule_set_tenant
BEFORE INSERT ON idax_core.schedule
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_inbox_set_tenant
BEFORE INSERT ON idax_core.inbox_event
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_tenant_user_set_tenant
BEFORE INSERT ON idax_core.tenant_user
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE TRIGGER trg_integration_set_tenant
BEFORE INSERT ON idax_core.integration
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_tenant_id();

CREATE OR REPLACE FUNCTION idax_core.tg_prevent_tenant_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id THEN
    RAISE EXCEPTION 'tenant_id cannot be modified';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_connector_no_tenant_update
BEFORE UPDATE ON idax_core.connector
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_run_no_tenant_update
BEFORE UPDATE ON idax_core.run
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_run_log_no_tenant_update
BEFORE UPDATE ON idax_core.run_log
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_artifact_no_tenant_update
BEFORE UPDATE ON idax_core.artifact
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_schedule_no_tenant_update
BEFORE UPDATE ON idax_core.schedule
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_inbox_no_tenant_update
BEFORE UPDATE ON idax_core.inbox_event
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_tenant_user_no_tenant_update
BEFORE UPDATE ON idax_core.tenant_user
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

CREATE TRIGGER trg_integration_no_tenant_update
BEFORE UPDATE ON idax_core.integration
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_prevent_tenant_update();

-- Políticas:
--  - idax_admin: acceso total
--  - idax_app: acceso sólo al tenant actual (y usuarios/membership del tenant)

-- APP_USER:
-- La identidad es global, pero por simplicidad y privacidad:
--  - app puede ver usuarios SOLO si están en el tenant actual (vía tenant_user)
--  - admin ve todo
DROP POLICY IF EXISTS p_app_user_admin ON idax_core.app_user;
CREATE POLICY p_app_user_admin ON idax_core.app_user
  FOR ALL TO idax_admin
  USING (true)
  WITH CHECK (true);

DROP POLICY IF EXISTS p_app_user_app ON idax_core.app_user;
CREATE POLICY p_app_user_app ON idax_core.app_user
  FOR SELECT TO idax_app
  USING (
    EXISTS (
      SELECT 1
      FROM idax_core.tenant_user tu
      WHERE tu.user_id = idax_core.app_user.user_id
        AND idax_core.tenant_match(tu.tenant_id)
    )
  );

-- TENANT_USER: app ve/crea/borra solo dentro del tenant actual
DROP POLICY IF EXISTS p_tenant_user_admin ON idax_core.tenant_user;
CREATE POLICY p_tenant_user_admin ON idax_core.tenant_user
  FOR ALL TO idax_admin
  USING (true)
  WITH CHECK (true);

DROP POLICY IF EXISTS p_tenant_user_app ON idax_core.tenant_user;
CREATE POLICY p_tenant_user_app ON idax_core.tenant_user
  FOR ALL TO idax_app
  USING (idax_core.tenant_match(tenant_id))
  WITH CHECK (idax_core.tenant_match(tenant_id));

DROP POLICY IF EXISTS p_integration_admin ON idax_core.integration;
CREATE POLICY p_integration_admin ON idax_core.integration
  FOR ALL TO idax_admin
  USING (true)
  WITH CHECK (true);

DROP POLICY IF EXISTS p_integration_app ON idax_core.integration;
CREATE POLICY p_integration_app ON idax_core.integration
  FOR ALL TO idax_app
  USING (idax_core.is_current_user_member_of_tenant(tenant_id))
  WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id));

DROP POLICY IF EXISTS p_audit_admin ON idax_core.audit_log;
CREATE POLICY p_audit_admin ON idax_core.audit_log
  FOR ALL TO idax_admin
  USING (true)
  WITH CHECK (true);

DROP POLICY IF EXISTS p_audit_app ON idax_core.audit_log;
CREATE POLICY p_audit_app ON idax_core.audit_log
  FOR SELECT TO idax_app
  USING (idax_core.is_current_user_member_of_tenant(tenant_id));

-- TENANT-SCOPED TABLES: patrón común
DO $$
DECLARE
  t regclass;
  tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY[
    'idax_core.connector',
    'idax_core.run',
    'idax_core.run_log',
    'idax_core.artifact',
    'idax_core.schedule',
    'idax_core.inbox_event'
  ]
  LOOP
    t := tbl::regclass;

    EXECUTE format('DROP POLICY IF EXISTS p_%s_admin ON %s', replace(tbl,'.','_'), tbl);
    EXECUTE format($sql$
      CREATE POLICY p_%s_admin ON %s
      FOR ALL TO idax_admin
      USING (true)
      WITH CHECK (true)
    $sql$, replace(tbl,'.','_'), tbl);

    EXECUTE format('DROP POLICY IF EXISTS p_%s_app ON %s', replace(tbl,'.','_'), tbl);
    EXECUTE format($sql$
      CREATE POLICY p_%s_app ON %s
      FOR ALL TO idax_app
      USING (idax_core.is_current_user_member_of_tenant(tenant_id))
      WITH CHECK (idax_core.is_current_user_member_of_tenant(tenant_id))
    $sql$, replace(tbl,'.','_'), tbl);
  END LOOP;
END$$;

-- =========================
-- 5) PRIVILEGIOS (mínimos)
-- =========================
-- Nota: Si usas roles por conexión (usuario DB = app), concede a ese rol y hazlo miembro de idax_app.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA idax_core TO idax_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA idax_core TO idax_app;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA idax_core TO idax_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA idax_core TO idax_admin;

-- Asegurar que futuros objetos hereden grants
ALTER DEFAULT PRIVILEGES IN SCHEMA idax_core
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO idax_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA idax_core
  GRANT USAGE, SELECT ON SEQUENCES TO idax_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA idax_core
  GRANT ALL ON TABLES TO idax_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA idax_core
  GRANT ALL ON SEQUENCES TO idax_admin;

-- tenant es tabla global: lectura para app, control total para admin
GRANT SELECT ON idax_core.tenant TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.tenant TO idax_admin;

REVOKE ALL ON FUNCTION idax_core.set_tenant(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.set_tenant(uuid) TO idax_app, idax_admin;

REVOKE ALL ON ALL TABLES IN SCHEMA idax_core FROM idax_backend;

REVOKE INSERT, UPDATE, DELETE ON idax_core.audit_log FROM idax_app;

-- Ensure legacy schema exists
CREATE SCHEMA IF NOT EXISTS idax;

GRANT USAGE ON SCHEMA idax TO idax_app;
GRANT USAGE ON SCHEMA idax TO idax_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA idax
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO idax_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA idax
GRANT USAGE, SELECT ON SEQUENCES TO idax_admin;

-- =========================
-- 6) NOTAS OPERATIVAS
-- =========================
-- Ejemplo de bootstrap:
--   INSERT INTO idax_core.tenant(code, name) VALUES ('demo', 'Tenant Demo') RETURNING tenant_id;
--   SELECT idax_core.set_tenant('<tenant_uuid>');
--   INSERT INTO idax_core.connector(tenant_id, code, name, type) VALUES (idax_core.current_tenant_id(), 'ax4-sql', 'AX4 SQL', 'erp');
--
-- Validación rápida:
--   SET ROLE idax_app;
--   SELECT idax_core.set_tenant('<tenant_uuid>');
--   SELECT * FROM idax_core.tenant; -- solo ese
-- ============================================================================
