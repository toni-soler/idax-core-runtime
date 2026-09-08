-- V71: DB-C2A.4 - narrow atomic tenant enabled/disabled status-toggle capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29j for the full trace and this gate's report.
--
-- LIFECYCLE DECOMPOSITION (Phase 1/2): idax_core.tenant has FIVE distinct current Java mutation
-- paths - CREATE (TenantController#create, out of scope, explicitly excluded), UPDATE METADATA
-- (TenantController#update -> TenantService#update, writes name+status+mfa_required together,
-- NOT this gate), STATUS TOGGLE (TenantController#updateEnabled -> TenantService#updateEnabled,
-- THIS gate), and physical DELETE (TenantController#delete -> TenantService#delete ->
-- tenantRepository.delete - a real hard DELETE, out of scope, explicitly excluded - "decommission"
-- in the current codebase IS this same physical delete; there is no separate soft-decommission
-- state). SELECTED SUB-SLICE: TENANT_SET_ENABLED (status toggle only) - narrowest single-column
-- mutation, avoids UPDATE METADATA's tangled mfa_required field (a materially wider security
-- surface - see below), and is fully atomic/self-contained.
--
-- EXACT SEMANTICS: idax_core.tenant.status is a free varchar(20) column (V1 comment documents
-- "active | suspended | deleted" as the intended domain, but there is no CHECK constraint - see
-- DB-C2A.3's own finding). The existing TenantController#updateEnabled endpoint accepted a raw
-- Tenant JSON body and forwarded tenant.getStatus() to the column completely unvalidated. This
-- migration deliberately NARROWS that to a typed p_enabled boolean, mapped exactly the same way
-- TenantService#isEnabled and DB-C2A.3's own tenant_search_global already interpret this column
-- (true -> 'active', false -> 'disabled') - not an invention, reapplying an existing codebase
-- convention consistently. This is a considered, security-improving narrowing (validated input
-- instead of an unchecked passthrough), not a silent behavior change: the HTTP wire contract is
-- unchanged (TenantService#updateEnabled still derives its own boolean from the request body the
-- exact same "active"-equalsIgnoreCase way TenantService#isEnabled already does elsewhere in the
-- same class), so no legitimate current caller behavior is broken.
--
-- EXISTING-SESSION SEMANTICS (Phase 6, traced, not assumed): disabling a tenant does NOT block an
-- already-issued JWT. Neither TenantResolver#resolveByHeader, TenantContextFilter, JwtAuthFilter,
-- nor RlsTransactionAspect/DbSessionContextService ever check tenant.status while establishing
-- TenantContext or applying RLS session state - and LocalAuthService#refresh re-mints a new access
-- token purely from the refresh token's own embedded claims, with ZERO database lookups (no
-- AppUserRepository/TenantRepository call at all), so it never re-validates tenant.status either.
-- TENANT DISABLE / EXISTING SESSION: REMAINS VALID INDEFINITELY VIA REFRESH (not merely "until
-- token expiry" - refresh never re-checks). Disabling a tenant currently, provably, only affects:
-- (1) new service-principal token issuance (ServiceTokenIssuer/ServicePrincipalManagementService
-- both filter on status='active'), and (2) whether the tenant appears in the /api/me tenant list
-- (MeService filters to "active" tenants). This is NOT security-ambiguous (it is precisely traced,
-- not unknown), so it is not a STOP condition - it is a pre-existing, broader Auth/session-security
-- property this narrow migration neither introduces nor is scoped to fix; recorded for a future
-- dedicated Auth/session-security review, alongside the existing DB-C2A.2 JWT-claim-trust finding.
--
-- AUTHORIZATION (Phase 7): unchanged, entirely Java-side -
-- @PreAuthorize("hasAuthority('ROLE_SUPERUSER') or (@tenantAuth.validateTenantAccess(#id) and
-- @tenantAuth.canManageTenant(#id))") on TenantController#updateEnabled - genuinely reachable by
-- BOTH a global superuser AND an ordinary non-superuser tenant owner/admin managing their OWN
-- tenant (DB-verified role check via TenantAuthorizationService, not merely a JWT claim). No
-- role/permission string is passed into this function.
--
-- EXECUTION CONTEXT (Phase 8, traced fresh for this exact endpoint, not copied from DB-C2A.3):
-- TenantController/TenantService use ordinary JPA - the active role is whatever
-- RlsTransactionAspect/DbSessionContextService applies from TenantContext. Unlike DB-C2A.3's
-- GET .../paginado, this endpoint's path shape (/api/tenants/enabled/{id}) does NOT match
-- JwtAuthFilter#extractTenantIdFromPath's "tenants/<next-segment>" pattern (the segment right
-- after "tenants" here is literally "enabled", not the tenant id), so pathTenantId is always null
-- for this endpoint - TenantContext establishment depends on an X-Tenant header or the caller's
-- JWT tenantId claim. For the NON-SUPERUSER tenant-admin path, @tenantAuth.validateTenantAccess
-- REQUIRES TenantContext.getTenantId() to already equal the path id (or authorization fails
-- outright) - so TenantContext, and therefore a role, IS always genuinely established for that
-- caller, resolving (per the uniform isSuperuser() ? IDAX_ADMIN : IDAX_APP rule) to
-- **idax_app** - a real, proven, DB-verified direct caller, unlike every prior DB-C2A capability.
-- For the SUPERUSER path, the @PreAuthorize OR short-circuits without requiring TenantContext at
-- all, so a superuser may reach this with TenantContext established (dbRole idax_admin, if an
-- X-Tenant header or JWT tenantId happens to be present) or with none at all (bare idax_backend,
-- the same pre-existing, out-of-scope ambiguity DB-C2A.3 already found and did not resolve).
-- **DIRECT EXECUTE: idax_app AND idax_admin** (both real, traced call paths - a meaningfully
-- different grantee set from every prior DB-C2A capability, found by tracing this endpoint
-- independently rather than reusing DB-C2A.2/.3's idax_admin-only pattern). EFFECTIVE EXECUTE:
-- idax_backend via V1's standing membership in both.
--
-- OPTIMISTIC LOCKING / LOST UPDATE (Phase 10): idax_core.tenant carries no @Version, ETag, or
-- If-Match mechanism (confirmed by reading the Tenant entity directly). TENANT METADATA LOST
-- UPDATE: LAST-WRITER-WINS BY DESIGN - this migration does not invent CAS/version semantics beyond
-- what already exists, matching Phase 11's explicit instruction not to introduce a state machine
-- without evidence. The status column itself is written unconditionally to the caller's own
-- intended value (never derived from a stale read), so a benign SELECT-before-UPDATE race only
-- affects this function's own no-op/audit bookkeeping, never the persisted status value's
-- correctness - proven safe by this gate's own concurrent enable/disable test.
--
-- NO-OP UPDATE (Phase 21): `WHERE ... AND status IS DISTINCT FROM v_new_status` - if the new value
-- equals the current one, no row is touched at all, updated_at is not bumped, and no audit event
-- is emitted (matching Hibernate's own dirty-checking, which already skips issuing any UPDATE SQL
-- - and therefore never fires @PreUpdate/the audit listener - for a true no-op today).
--
-- AUDIT (Phase 19, PRIMARY MUTATION REQUIREMENT): idax_core.tenant is NOT in
-- AutomaticFieldChangeAuditListener#shouldSkipEntity's exclusion list, so every current JPA-driven
-- Tenant UPDATE (including today's updateEnabled) automatically produces a generic
-- "TENANT_FIELDS_UPDATED" audit event (Hibernate PostUpdateEvent-based, before/after diff of
-- exactly the dirty fields) with ZERO manual audit code in TenantService today. Bypassing JPA for
-- this write (this capability is raw SQL, not a JPA save()) means that automatic listener can
-- never fire for status changes made through this capability - this WOULD silently drop the
-- existing audit trail unless explicitly replicated. TenantService#updateEnabled therefore keeps
-- its existing advisory findById() read (Phase 18 explicitly permits an advisory read for "audit"
-- purposes - this is not a "read solely to perform the mutation," the mutation itself is fully
-- atomic in this one function) to capture the pre-change status, and emits one equivalent
-- IdaxAuditService event (same eventType/entityName/entityId/businessKey/before/after shape the
-- generic listener would have produced for a Tenant status-only change), registered after-commit
-- exactly like the listener's own registerAfterCommit pattern, and ONLY when the status actually
-- changed - so no audit event is ever duplicated or manufactured for a no-op call.
--
-- OWNER PRIVILEGE (Phase 23): idax_capability_owner already holds table-wide SELECT on
-- idax_core.tenant (V70). This migration adds column-level UPDATE(status, updated_at) only - no
-- INSERT (CREATE is explicitly out of scope), no DELETE.
--
-- DEFAULT PRIVILEGES (Phase 26, carried forward): function-only migration, no new
-- table/sequence/constraint - PUBLIC-execute-on-create handled by the standard
-- REVOKE ALL ... FROM PUBLIC. DEFAULT PRIVILEGE MODEL: SAFE FOR THIS GATE.
--
-- PRE-FIX CHARACTERIZATION (Phase 27): PRIVILEGE-HARDENING. No lost-update, audit, or status-race
-- bug was found in the underlying mutation itself - the deliberate boolean-narrowing above is a
-- considered improvement, not a bug fix, and is documented as such rather than framed as a
-- vulnerability that did not exist.

GRANT idax_capability_owner TO CURRENT_USER;

GRANT UPDATE (status, updated_at) ON idax_core.tenant TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.tenant_set_enabled(
    p_tenant_id uuid,
    p_enabled   boolean
)
RETURNS TABLE (
    tenant_id    uuid,
    code         text,
    name         text,
    status       text,
    mfa_required boolean,
    created_at   timestamptz,
    updated_at   timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_new_status text := CASE WHEN p_enabled THEN 'active' ELSE 'disabled' END;
BEGIN
    IF p_tenant_id IS NULL THEN
        RAISE EXCEPTION 'tenant_set_enabled: invalid tenant id' USING ERRCODE = '22023';
    END IF;

    UPDATE idax_core.tenant t
    SET status = v_new_status,
        updated_at = now()
    WHERE t.tenant_id = p_tenant_id
      AND t.status IS DISTINCT FROM v_new_status;

    RETURN QUERY
    SELECT t.tenant_id,
           t.code::text,
           t.name::text,
           t.status::text,
           t.mfa_required,
           t.created_at,
           t.updated_at
    FROM idax_core.tenant t
    WHERE t.tenant_id = p_tenant_id;
END;
$function$;

ALTER FUNCTION idax_core.tenant_set_enabled(uuid, boolean)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.tenant_set_enabled(uuid, boolean)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.tenant_set_enabled(uuid, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.tenant_set_enabled(uuid, boolean)
  TO idax_app, idax_admin;
