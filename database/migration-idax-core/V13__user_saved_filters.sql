ALTER TABLE idax_core.app_user_preference
    ADD COLUMN IF NOT EXISTS saved_filters JSONB NOT NULL DEFAULT '{}'::jsonb;
