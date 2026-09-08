-- V76__saved_filter_alert_column_labels.sql
--
-- Parallel array to `columns` (same length, same order): the human-readable
-- column label, resolved in the requester's UI language at the moment the
-- alert was saved, so the rendered table shows "Cliente" instead of
-- "custaccount" - the raw field name is all the generic column-replay
-- mechanism (GenericFilterExecutor) otherwise has, and the backend has no
-- access to the frontend's i18next locale files to translate it itself.
-- Existing rows (created before this column existed) simply have an empty
-- array here, and the renderer falls back to the raw field name for them.
ALTER TABLE idax_core.idax_saved_filter_alert
    ADD COLUMN IF NOT EXISTS column_labels TEXT[] NOT NULL DEFAULT '{}';
