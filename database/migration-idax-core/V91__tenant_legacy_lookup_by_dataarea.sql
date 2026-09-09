-- V91: narrow PRE-TENANT capability TENANT_LEGACY_LOOKUP_BY_DATAAREA
--
-- INCIDENT: TenantLegacyLookupController (GET /api/tenant-legacy/**, ROLE_SUPERUSER-only,
-- documented as used by external synchronization processes to resolve the tenant that owns a
-- given DataAreaId - i.e. the tenant is NOT YET KNOWN when this endpoint is called, by design)
-- started failing with "ERROR: Tenant not set in session" immediately after the legacy DB
-- identity cutover (idax_backend no longer superuser/BYPASSRLS).
--
-- ROOT CAUSE (traced from the real Java call chain, not assumed):
--   TenantLegacyLookupController -> TenantLegacyLookupService (@Transactional(readOnly = true))
--   -> TenantLegacyRepository.findAllEnabledByDataAreaIdIgnoreCase (plain JPQL, NO tenant_id
--   predicate at all - relies entirely on RLS).
--   idax_core.tenant_legacy carries RLS policy p_tenant_legacy_tenant (V2), USING
--   (tenant_id = idax_core.current_tenant_id()), with no FOR/TO clause (applies to ALL roles that
--   are not the table owner and not BYPASSRLS). RlsTransactionAspect explicitly SKIPS
--   SET LOCAL ROLE / idax_core.set_tenant(...) whenever TenantContext is null - which it always is
--   for this endpoint's genuinely pre-tenant callers (no tenantId claim, no X-Tenant header
--   allowed on this path). So the RLS policy's own USING clause calls
--   idax_core.current_tenant_id(), which unconditionally RAISEs when app.tenant_id was never set.
--
-- This is NOT a regression the cutover introduced by breaking something that worked correctly -
-- idax_backend was the literal Postgres bootstrap superuser before the cutover, which is
-- unconditionally BYPASSRLS, so this endpoint's genuine dependency on an RLS-protected table with
-- no tenant context was ALWAYS structurally broken; it was simply never enforced until idax_backend
-- became genuinely non-superuser/non-BYPASSRLS today. The cutover is correct; this table's one
-- caller pattern (a legitimate pre-tenant lookup) was never given a legitimate access path.
--
-- FIX: exactly the same "narrow SECURITY DEFINER capability" pattern already established for
-- every other pre-tenant-only caller in this program (auth_local_identity_lookup V54,
-- service_principal_create V81, tenant_create V86, etc.) - naming mirrors the existing
-- "X_lookup_by_Y" convention (service_principal_lookup_by_client_id, V80). Does NOT touch RLS on
-- idax_core.tenant_legacy, does NOT grant BYPASSRLS/SUPERUSER to anything, does NOT weaken
-- current_tenant_id(). Ordinary tenant-scoped access to tenant_legacy (the other 5
-- TenantLegacyRepository methods, all still RLS-protected, all still require a tenant already set)
-- is completely untouched by this migration.
--
-- OUTPUT CONTRACT: exactly the 5 fields TenantLegacyLookupResponse actually needs (verified
-- directly from the DTO, not guessed) - tenant_legacy_id, tenant_id, dataareaid, company_id,
-- enabled. No secret_hash-style sensitive column exists on this table, but the function still
-- deliberately does not select created_at/created_by, which no caller needs.
--
-- OWNER PRIVILEGE (the necessary, narrow piece this fix actually depends on): idax_capability_owner
-- currently holds ZERO privilege on idax_core.tenant_legacy (it only ever received ALTER DEFAULT
-- PRIVILEGES targeting idax_app/idax_admin - idax_capability_owner is not in that list, verified by
-- inspection of every prior migration touching this table). Worse, even a bare table GRANT would
-- not be enough on its own: idax_capability_owner is not tenant_legacy's owner and holds no
-- BYPASSRLS, so policy p_tenant_legacy_tenant (V2) would still apply to it exactly as it applies to
-- idax_backend today - and a capability whose entire purpose is resolving a tenant that is not yet
-- known cannot itself require a tenant to already be set. This migration therefore adds BOTH a
-- column-scoped SELECT grant AND a second, narrow, SELECT-only RLS policy scoped exclusively to
-- idax_capability_owner - mirroring the exact "FOR ALL TO idax_admin USING (true)" idiom this
-- schema already uses for every other role-scoped RLS exemption (V1's p_app_user_admin,
-- p_tenant_user_admin, etc.), just narrower (FOR SELECT only, not ALL) and on a role no live
-- application session ever runs as directly (idax_capability_owner is only ever entered transiently
-- inside a SECURITY DEFINER function body). This does NOT touch, weaken, or add any exemption to
-- idax_backend/idax_app/idax_admin's own RLS behavior on this or any other table - they remain
-- exactly as restrictive as before this migration.

GRANT SELECT (tenant_legacy_id, tenant_id, dataareaid, company_id, enabled)
  ON idax_core.tenant_legacy TO idax_capability_owner;

CREATE POLICY p_tenant_legacy_capability_owner
  ON idax_core.tenant_legacy
  FOR SELECT
  TO idax_capability_owner
  USING (true);
--
-- AMBIGUITY: idax_core.tenant_legacy carries a table-level UNIQUE(dataareaid) constraint (V2),
-- so more than one ENABLED row can never exist for the same dataareaid today - true ambiguity is
-- structurally unreachable. This function still returns a SETOF (not a single row via LIMIT 1 or
-- similar), so the existing Java-side 0/1/N branching in TenantLegacyLookupService (unchanged by
-- this migration) continues to fail closed (IllegalStateException -> HTTP 409) rather than silently
-- picking a row, if that constraint is ever relaxed in the future.

CREATE OR REPLACE FUNCTION idax_core.tenant_legacy_lookup_by_dataarea(p_dataareaid text)
RETURNS TABLE (
  tenant_legacy_id uuid,
  tenant_id uuid,
  dataareaid varchar(3),
  company_id bigint,
  enabled boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
  SELECT tl.tenant_legacy_id, tl.tenant_id, tl.dataareaid, tl.company_id, tl.enabled
  FROM idax_core.tenant_legacy tl
  WHERE lower(tl.dataareaid) = lower(p_dataareaid)
    AND tl.enabled = true;
$$;

ALTER FUNCTION idax_core.tenant_legacy_lookup_by_dataarea(text)
  SET search_path = idax_core, pg_temp;

ALTER FUNCTION idax_core.tenant_legacy_lookup_by_dataarea(text)
  OWNER TO idax_capability_owner;

REVOKE ALL ON FUNCTION idax_core.tenant_legacy_lookup_by_dataarea(text) FROM PUBLIC;

-- idax_backend ONLY: this endpoint's real, sole, verified caller shape (bare pre-tenant superuser
-- sync-process JWT, no effective tenant, TenantContext always null - see root cause above). No
-- genuine idax_app/idax_admin execution path exists for this endpoint, matching the permanent
-- grantee rule already established across this program (idax_admin/idax_app receive nothing).
GRANT EXECUTE ON FUNCTION idax_core.tenant_legacy_lookup_by_dataarea(text) TO idax_backend;
