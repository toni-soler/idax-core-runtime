-- V70: DB-C2A.3 - narrow bounded/pageable global tenant search capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29i for the full trace and this gate's report.
-- Traced exactly from GET /api/tenants/paginado (TenantController#findAllPaginado,
-- @PreAuthorize("hasAuthority('ROLE_SUPERUSER')")) -> TenantService#findAll(pageable, code, name,
-- enabled), which builds a JPA Specification over idax_core.tenant and calls
-- TenantRepository#findAll(specification, pageable) (JpaSpecificationExecutor, two round trips:
-- content query + a separate COUNT query).
--
-- GLOBAL READ BOUNDARY (Phase 4): this is genuinely global (no TenantContext / no tenant
-- ownership check) because the application operation itself is global - a superuser's "list every
-- tenant" screen. It does not authorize reading tenant-owned business data, users, credentials,
-- MFA, service principals, or messages - only idax_core.tenant's own metadata columns, all 7 of
-- which are returned (id/code/name/status/mfa_required/created_at/updated_at). None are secret,
-- internal-infrastructure, or unrelated-tenant metadata (confirmed by reading the Tenant entity
-- directly - it carries no such fields), so no field needed exclusion.
--
-- EXACT SEARCH SEMANTICS (Phase 2/9/10, preserved exactly, not invented):
--   code:    case-insensitive substring match (JPA: lower(code) LIKE '%term%') -> ILIKE '%term%'.
--   name:    same, case-insensitive substring match -> ILIKE '%term%'.
--   enabled: Boolean -> exact match against status = 'active' (true) / 'disabled' (false). This
--            exact string mapping is reproduced unchanged from TenantService's current
--            Specification, including its literal use of 'disabled' - V1's own schema comment on
--            this column documents a different intended domain ("active | suspended | deleted"),
--            but status carries no CHECK constraint and is entirely caller-driven via the plain
--            update/updateEnabled endpoints, so this migration cannot and does not decide which
--            domain is "correct" - it preserves TenantService's current, exact, unmodified
--            behavior rather than silently reinterpreting it.
-- Neither code nor name input is escaped for literal '%'/'_' before matching, exactly matching
-- today's JPA Specification (which does not escape them either) - a caller-supplied '%' or '_'
-- acts as a SQL wildcard today and continues to do so here; this is existing API behavior, not a
-- security concern (search input, safely parameter-bound, not used to construct SQL text).
--
-- SORTING (Phase 8): the controller hard-codes Sort.by("name").ascending() - it is NOT
-- client-controllable at all, so no dynamic/arbitrary sort mechanism is needed or introduced. This
-- function always orders by name ASC. A secondary `tenant_id ASC` tiebreaker is added (Phase 20)
-- for deterministic pagination when multiple tenants share the same name - name alone is not
-- unique, so without a stable tiebreaker, page boundaries could be non-deterministic across pages.
--
-- COUNT + PAGE CONSISTENCY (Phase 11): TWO narrow functions (option B) -
-- `tenant_search_global(...)` (rows only) and `tenant_search_global_count(...)` (total match
-- count only), sharing an identical predicate. A single-function `count(*) OVER()` design (option
-- A) was tried first and rejected: a page-beyond-end request legitimately returns zero rows, and
-- a window-function value can only ever be carried on a returned row - so an empty page would
-- silently report total_count=0 even when real matching rows exist, a genuine behavior
-- REGRESSION versus the original JPA `findAll(specification, pageable)` (which always issues a
-- separate COUNT query, so `Page#getTotalElements()` stays correct even on an empty page). Two
-- functions - matching the original's own two-round-trip shape exactly - avoids this loss.
--
-- AUTHORIZATION (Phase 5): unchanged, stays entirely Java-side
-- (@PreAuthorize("hasAuthority('ROLE_SUPERUSER')") on the controller) - no role/permission string
-- is passed into this function; it performs the bounded, already-authorized search only.
--
-- EXECUTION CONTEXT (Phase 6, traced from the real call site, not inferred from prior gates):
-- TenantController/TenantService use ordinary JPA (no explicit SET LOCAL ROLE, unlike
-- AppUserResolver) - the active role is whatever RlsTransactionAspect/DbSessionContextService
-- applies from TenantContext. `/api/tenants/` is on JwtAuthFilter's tenant-scoped-endpoint
-- allowlist, so an X-Tenant header (if the caller sends one) establishes TenantContext even for
-- this global endpoint; per JwtAuthFilter/TenantContextFilter's uniform rule, a superuser's
-- dbRole always resolves to IDAX_ADMIN. If no tenant context is ever established for a given call
-- (superuser JWTs carry no tenantId claim, and this endpoint does not require one), the connection
-- would remain at bare idax_backend, which holds zero direct grant on any idax_core table - this
-- pre-existing, real ambiguity is outside this gate's scope to resolve (it depends on frontend
-- request behavior, DO-NOT-TOUCH). This capability is granted EXECUTE to idax_admin - the one
-- real, traced role this call path can reach when a role is actually applied - added to the
-- DB-C1B cleanup checklist. idax_app is NOT granted: @PreAuthorize already blocks any ordinary
-- non-superuser caller from reaching TenantService#findAll(pageable, code, name, enabled) at all,
-- so no real call path reaches this function as idax_app.
--
-- OWNER PRIVILEGE (Phase 17): idax_capability_owner currently holds ZERO privilege on
-- idax_core.tenant (checked directly - only V1's idax_app/idax_admin grants and V51's unrelated
-- idax_service_auth grant exist). This migration adds table-wide SELECT only - every returned
-- column is genuinely needed, so column-level SELECT would offer no real narrowing here. No
-- INSERT/UPDATE/DELETE granted - this function only reads.
--
-- DEFAULT PRIVILEGES (Phase 18/22, carried forward): function-only migration, no new
-- table/sequence/constraint - V1's TABLES/SEQUENCES default-privilege rules do not apply, no
-- FUNCTIONS default-privilege rule exists, PUBLIC-execute-on-create handled by the standard
-- REVOKE ALL ... FROM PUBLIC below. DEFAULT PRIVILEGE MODEL: SAFE FOR THIS GATE.
--
-- PRE-FIX PRIVILEGE CHARACTERIZATION (Phase 22): this gate is PRIVILEGE-HARDENING / PUBLIC
-- ARCHITECTURE - no genuine correctness/security bug was found in the search logic itself (the
-- 'disabled' vs V1-comment domain question above is an unresolvable ambiguity given the column's
-- lack of a CHECK constraint and caller-driven status values, not a provable bug, so it is
-- preserved exactly rather than "fixed").

GRANT idax_capability_owner TO CURRENT_USER;

GRANT SELECT ON idax_core.tenant TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.tenant_search_global(
    p_code    text,
    p_name    text,
    p_enabled boolean,
    p_limit   integer,
    p_offset  integer
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
STABLE
SECURITY DEFINER
AS $function$
BEGIN
    IF p_limit IS NULL OR p_limit < 0 THEN
        RAISE EXCEPTION 'tenant_search_global: invalid limit' USING ERRCODE = '22023';
    END IF;
    IF p_offset IS NULL OR p_offset < 0 THEN
        RAISE EXCEPTION 'tenant_search_global: invalid offset' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT t.tenant_id,
           t.code::text,
           t.name::text,
           t.status::text,
           t.mfa_required,
           t.created_at,
           t.updated_at
    FROM idax_core.tenant t
    WHERE (p_code IS NULL OR p_code = '' OR t.code ILIKE '%' || p_code || '%')
      AND (p_name IS NULL OR p_name = '' OR t.name ILIKE '%' || p_name || '%')
      AND (p_enabled IS NULL OR t.status = (CASE WHEN p_enabled THEN 'active' ELSE 'disabled' END))
    ORDER BY t.name ASC, t.tenant_id ASC
    LIMIT p_limit OFFSET p_offset;
END;
$function$;

ALTER FUNCTION idax_core.tenant_search_global(text, text, boolean, integer, integer)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.tenant_search_global(text, text, boolean, integer, integer)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.tenant_search_global(text, text, boolean, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.tenant_search_global(text, text, boolean, integer, integer)
  TO idax_admin;

-- Shares the exact same predicate as tenant_search_global above - kept intentionally byte-for-byte
-- parallel in this same migration so any future edit to one predicate is immediately visible next
-- to the other (Phase 11's explicit "predicates must be identical" requirement for a two-function
-- design).
CREATE OR REPLACE FUNCTION idax_core.tenant_search_global_count(
    p_code    text,
    p_name    text,
    p_enabled boolean
)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
DECLARE
    v_total bigint;
BEGIN
    SELECT count(*) INTO v_total
    FROM idax_core.tenant t
    WHERE (p_code IS NULL OR p_code = '' OR t.code ILIKE '%' || p_code || '%')
      AND (p_name IS NULL OR p_name = '' OR t.name ILIKE '%' || p_name || '%')
      AND (p_enabled IS NULL OR t.status = (CASE WHEN p_enabled THEN 'active' ELSE 'disabled' END));

    RETURN v_total;
END;
$function$;

ALTER FUNCTION idax_core.tenant_search_global_count(text, text, boolean)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.tenant_search_global_count(text, text, boolean)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.tenant_search_global_count(text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.tenant_search_global_count(text, text, boolean)
  TO idax_admin;
