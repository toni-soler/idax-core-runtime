ALTER TABLE idax_core.app_user_preference
    ADD COLUMN IF NOT EXISTS filter_preferences JSONB NOT NULL DEFAULT '{}'::jsonb;
