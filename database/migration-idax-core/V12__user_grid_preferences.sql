ALTER TABLE idax_core.app_user_preference
    ADD COLUMN IF NOT EXISTS grid_preferences JSONB NOT NULL DEFAULT '{}'::jsonb;
