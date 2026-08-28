-- V5: Fix app_user RLS
-- app_user is a GLOBAL table (users can belong to multiple tenants via tenant_user)
-- Therefore, app_user must NOT be tenant-isolated via RLS
-- This migration removes RLS policies and disables RLS for app_user

-- Drop all policies on idax_core.app_user
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (
        SELECT policyname
        FROM pg_policies
        WHERE schemaname = 'idax_core'
          AND tablename = 'app_user'
    ) LOOP
        EXECUTE 'DROP POLICY IF EXISTS ' || quote_ident(r.policyname) || ' ON idax_core.app_user';
    END LOOP;
END $$;

-- Disable Row Level Security on app_user
ALTER TABLE idax_core.app_user DISABLE ROW LEVEL SECURITY;