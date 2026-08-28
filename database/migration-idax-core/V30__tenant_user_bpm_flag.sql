ALTER TABLE idax_core.tenant_user
  ADD COLUMN IF NOT EXISTS bpm_user_enabled boolean NOT NULL DEFAULT false;
