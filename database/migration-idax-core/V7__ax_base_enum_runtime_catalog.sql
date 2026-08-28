-- AX Base Enums runtime catalog (phase 1)
-- Global metadata catalog prepared for multilingual label delivery.
-- This phase adds persistence + read model; import/backfill is handled separately.

CREATE TABLE IF NOT EXISTS idax_core.ax_base_enum_catalog (
  enum_catalog_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  enum_name       varchar(200) NOT NULL,
  source_system   varchar(50) NOT NULL DEFAULT 'AX4',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_ax_base_enum_catalog_enum_name UNIQUE (enum_name)
);

CREATE TRIGGER trg_ax_base_enum_catalog_updated_at
BEFORE UPDATE ON idax_core.ax_base_enum_catalog
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE TABLE IF NOT EXISTS idax_core.ax_base_enum_value (
  enum_value_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  enum_catalog_id  uuid NOT NULL,
  ax_value         integer NOT NULL,
  symbol_or_name   varchar(200) NULL,
  default_label    varchar(500) NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_ax_base_enum_value_catalog
    FOREIGN KEY (enum_catalog_id) REFERENCES idax_core.ax_base_enum_catalog(enum_catalog_id) ON DELETE CASCADE,
  CONSTRAINT uq_ax_base_enum_value_catalog_value UNIQUE (enum_catalog_id, ax_value)
);

CREATE INDEX IF NOT EXISTS ix_ax_base_enum_value_catalog
  ON idax_core.ax_base_enum_value(enum_catalog_id, ax_value);

CREATE TRIGGER trg_ax_base_enum_value_updated_at
BEFORE UPDATE ON idax_core.ax_base_enum_value
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE TABLE IF NOT EXISTS idax_core.ax_base_enum_value_i18n (
  enum_value_translation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  enum_value_id             uuid NOT NULL,
  lang_code                 varchar(16) NOT NULL,
  label                     varchar(500) NOT NULL,
  created_at                timestamptz NOT NULL DEFAULT now(),
  updated_at                timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_ax_base_enum_value_i18n_value
    FOREIGN KEY (enum_value_id) REFERENCES idax_core.ax_base_enum_value(enum_value_id) ON DELETE CASCADE,
  CONSTRAINT uq_ax_base_enum_value_i18n_lang UNIQUE (enum_value_id, lang_code)
);

CREATE INDEX IF NOT EXISTS ix_ax_base_enum_value_i18n_value_lang
  ON idax_core.ax_base_enum_value_i18n(enum_value_id, lang_code);

CREATE TRIGGER trg_ax_base_enum_value_i18n_updated_at
BEFORE UPDATE ON idax_core.ax_base_enum_value_i18n
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

CREATE TABLE IF NOT EXISTS idax_core.ax_base_enum_binding (
  enum_binding_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  table_name       varchar(200) NOT NULL,
  field_name       varchar(200) NOT NULL,
  enum_catalog_id  uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_ax_base_enum_binding_catalog
    FOREIGN KEY (enum_catalog_id) REFERENCES idax_core.ax_base_enum_catalog(enum_catalog_id) ON DELETE CASCADE,
  CONSTRAINT uq_ax_base_enum_binding_table_field UNIQUE (table_name, field_name)
);

CREATE INDEX IF NOT EXISTS ix_ax_base_enum_binding_catalog
  ON idax_core.ax_base_enum_binding(enum_catalog_id);

CREATE TRIGGER trg_ax_base_enum_binding_updated_at
BEFORE UPDATE ON idax_core.ax_base_enum_binding
FOR EACH ROW EXECUTE FUNCTION idax_core.tg_set_updated_at();

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ax_base_enum_catalog TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ax_base_enum_value TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ax_base_enum_value_i18n TO idax_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.ax_base_enum_binding TO idax_app;

GRANT ALL PRIVILEGES ON idax_core.ax_base_enum_catalog TO idax_admin;
GRANT ALL PRIVILEGES ON idax_core.ax_base_enum_value TO idax_admin;
GRANT ALL PRIVILEGES ON idax_core.ax_base_enum_value_i18n TO idax_admin;
GRANT ALL PRIVILEGES ON idax_core.ax_base_enum_binding TO idax_admin;
