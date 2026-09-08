-- V83: DB-C2A.10 - narrow atomic SERVICE_PRINCIPAL_REVOKE_GRANT capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29q for the full trace and this gate's report.
--
-- REVOKE GRANT TRACED EXACTLY (Phase 1, fresh): TenantServicePrincipalGrantAdminController#revoke
-- (DELETE /api/admin/tenants/{tenantId}/service-principals/{principalId}/grants/{grantId},
-- class-level ROLE_SUPERUSER) -> ServicePrincipalManagementService#revokeGrant(principalId,
-- tenantId, grantId). Prior exact algorithm: requireEffectiveTenant(tenantId) (throws
-- IllegalArgumentException if TenantContext is null or its tenantId does not match the supplied
-- tenantId); grants.findById(grantId).filter(x -> x.getServicePrincipalId().equals(principalId) &&
-- x.getTenantId().equals(tenantId)).orElseThrow(() -> new IllegalArgumentException(...)) (a
-- Java-side, post-fetch filter - already correctly checking ALL THREE identifiers, unlike
-- DB-C2A.9's revokeCredential defect); g.setRevokedAt(now()); g.setEnabled(false) (JPA
-- dirty-checked); principals.findById(principalId).orElseThrow(); audit.record(...) using
-- p.getClientId() and g.getAudience().
--
-- AUTHORITATIVE GRANT KEY (Phase 2): grant_id (PK, service_principal_grant). A SEPARATE genuine
-- UNIQUE constraint exists on (service_principal_id, tenant_id, audience) (V51,
-- uq_service_principal_grant) - used by grant()'s own upsert-by-audience lookup, not by this
-- operation, which targets by grant_id per the URL's own /grants/{grantId} segment.
--
-- RESOURCE HIERARCHY / TARGET BINDING (Phase 3): route carries all three - tenantId, principalId,
-- grantId. UNLIKE DB-C2A.9's revokeCredential, this gate's PRE-FIX Java code was ALREADY CORRECT:
-- requireEffectiveTenant enforces the caller's TenantContext matches the path tenantId, and the
-- .filter(...) call enforces the fetched grant's own service_principal_id AND tenant_id both match
-- the path identifiers - re-verified fresh, not assumed. CROSS-PRINCIPAL TARGETING (Phase 4): pre-
-- fix SAFE (Java filter already rejects). CROSS-TENANT TARGETING (Phase 5): pre-fix SAFE (Java
-- filter already rejects AND, independently, RLS - see below - would also reject at the DB layer).
-- CLASSIFICATION: no defect found here - PURE PRIVILEGE-HARDENING, unlike DB-C2A.9's mixed
-- correctness-fix classification. This migration upgrades the existing correct-but-Java-only,
-- post-fetch filter into a single atomic SQL WHERE clause (Phase 8), and - critically - proves
-- RLS remains independently live underneath the new SECURITY DEFINER capability (Phase 6/7).
--
-- RLS - PRIMARY ARCHITECTURE REVIEW (Phase 6, verified directly from V51, not assumed): ENABLE ROW
-- LEVEL SECURITY: YES. FORCE ROW LEVEL SECURITY: YES (applies even to the table's own owner unless
-- BYPASSRLS). ONE policy, service_principal_grant_tenant_isolation, no "TO <role>" clause (applies
-- to every role including idax_admin/idax_app/idax_capability_owner): USING (tenant_id =
-- nullif(current_setting('app.tenant_id', true), '')::uuid) and an IDENTICAL WITH CHECK predicate.
-- GUC: app.tenant_id, set LOCAL-scoped by idax_core.set_tenant(uuid) (itself SECURITY DEFINER,
-- V1), invoked by DbSessionContextService BEFORE this controller's transactional method body runs
-- - always set to the exact same tenantId as the URL path for this specific controller (see below).
-- idax_capability_owner is created NOLOGIN NOINHERIT (V54) with NO BYPASSRLS attribute - confirmed
-- it does NOT bypass RLS, and it does not own idax_core.service_principal_grant either - RLS is
-- therefore FULLY LIVE for any SECURITY DEFINER function it owns, including this one.
--
-- SECURITY DEFINER + RLS LIVE PROOF (Phase 7, mandatory, proven by dedicated tests against a real
-- PostgreSQL fixture, not assumed): with the session's app.tenant_id GUC set to tenant A, invoking
-- this capability with p_tenant_id = B against a REAL tenant-B grant row (i.e. the function's own
-- WHERE-clause parameter genuinely matches the row) still mutates ZERO rows and returns empty -
-- RLS's USING/WITH CHECK compares the ROW's tenant_id against the SESSION's GUC, independently of
-- what this function's own p_tenant_id parameter says, catching a class of mismatch this
-- function's own WHERE clause alone could not. This proves the capability cannot convert one
-- tenant's session authority into cross-tenant mutation, REGARDLESS of what UUIDs are passed as
-- arguments - RLS is a genuinely independent, still-enforced second layer, not bypassed by
-- SECURITY DEFINER. No STOP triggered.
--
-- EXECUTION CONTEXT / CALLER (Phase 14/15/16, re-traced fresh from JwtAuthFilter, not assumed):
-- JwtAuthFilter#isTenantServiceGrantAdminPath matches this exact controller family
-- (/api/admin/tenants/.../service-principals/.../grants) and REJECTS any non-superuser with 403
-- BEFORE the controller/Spring Security layer is even reached - no tenant-admin (non-superuser)
-- path exists or is authorized here, confirmed doubly (filter-level AND the controller's own
-- class-level ROLE_SUPERUSER @PreAuthorize). Because this controller's URL always carries a
-- "/tenants/{tenantId}/" segment, TenantContext IS always established here (Priority 1: path
-- tenant, matching V77's own established finding for a differently-shaped but structurally
-- identical superuser+tenant-path endpoint) - resolving via the uniform "isSuperuser() ?
-- IDAX_ADMIN : IDAX_APP" rule to **idax_admin every time**, since only superusers ever reach this
-- controller. **ACTUAL CALLER: idax_admin** (via SET LOCAL ROLE, NOT bare idax_backend - this is
-- the first service-principal capability in this program executing as idax_admin rather than
-- idax_backend, because this specific controller's URL always carries a tenant path segment while
-- every prior service-principal controller's did not). No idax_app caller exists (no tenant-admin
-- path). No bare idax_backend caller exists either (TenantContext always established here).
--
-- DIRECT GRANTEE (permanent grantee rule, DB-C2A.6a taxonomy): idax_admin DIRECT - a genuine,
-- current, traced idax_admin execution path REALLY reaches this capability (not "just in case"),
-- matching the established V68/V77 "transitional idax_admin" pattern exactly (added to the
-- existing DB-C1B cleanup checklist in section 29 - DB-C1B's eventual target model has HTTP always
-- select idax_app with @PreAuthorize alone enforcing authorization, at which point this grantee
-- would move to idax_app). idax_backend receives EFFECTIVE-only access via its own standing
-- INHERIT membership in idax_admin (V1) - inert, since no genuine idax_backend call path exists for
-- this capability. idax_app receives nothing (no genuine caller).
--
-- OWNER PRIVILEGE (Phase 26/27, minimized precisely): idax_capability_owner held ZERO privilege on
-- service_principal_grant before this gate. This migration grants exactly
-- SELECT(grant_id, service_principal_id, tenant_id, audience, enabled, revoked_at) - the six
-- columns genuinely referenced by this function's WHERE clause, RETURN QUERY projection, and audit
-- enrichment (audience) - never table-wide SELECT - and UPDATE(enabled, revoked_at) only (this
-- table carries no updated_at column at all, confirmed from V51's own DDL). No INSERT, no DELETE.
-- No privilege whatsoever on service_principal_credential (Phase 44 invariant, untouched by this
-- gate) or service_principal_audit. ACL minimality (owner grants) and RLS liveness (Phase 6/7) are
-- reported and proven as two SEPARATE properties, per Phase 27 - both hold simultaneously.
--
-- REVOKE / ALREADY-REVOKED SEMANTICS (Phase 10/11): enabled = false AND revoked_at = now()
-- (DB-authoritative), both fields, exactly as today - never physical deletion. Re-revoking an
-- already-revoked grant succeeds again (the WHERE clause matches regardless of current
-- enabled/revoked_at state, exactly like today's Java filter), advances revoked_at, and produces a
-- second SUCCESS audit event - preserved exactly, not converted to a no-op (matching DB-C2A.9's own
-- established precedent for this class of already-revoked semantics).
--
-- UNKNOWN GRANT / WRONG PARENT (Phase 12/13): PRESERVED EXACTLY AS AN IllegalArgumentException ->
-- HTTP 400 (NOT the 404/NoSuchElementException pattern used by DB-C2A.9's revokeCredential) - this
-- gate's pre-fix contract was already safely unified (unknown grant_id and wrong parent both
-- already funneled into the same exception today, since the Java filter runs on the SAME
-- findById-then-filter chain) - no observable behavior change is introduced here, matching Phase
-- 13's explicit instruction to derive semantics from the current application contract rather than
-- blindly copying a sibling gate's different (but equally safe) pattern.
--
-- PERMISSIONS ARRAY (Phase 17): NOT accepted as input, NOT returned - this capability never reads
-- or writes the permissions column at all.
--
-- NEW TOKEN ISSUANCE (Phase 18): BLOCKED IMMEDIATELY for that tenant/audience - ServiceTokenIssuer
-- #issue performs a live grants.findByServicePrincipalIdAndTenantIdAndAudience(...) read on every
-- call, filtered by isEffective(now()) (which checks enabled AND revoked_at) - both become
-- effectively false the instant this capability commits. A grant for a DIFFERENT tenant/audience,
-- if still active, remains usable exactly as before - proven fresh by this gate's own dedicated
-- test.
--
-- EXISTING TOKEN (Phase 19, PRE-EXISTING, NOT ADDRESSED): identical systemic property already
-- documented for service-credential revoke (DB-C2A.9) and service-principal disable (DB-C2A.6) -
-- ServiceTokenValidator is purely stateless (JWT claims only, zero DB lookup on resource-server
-- requests), so an already-issued token remains valid until its own natural JWT expiry even after
-- its underlying grant is revoked. Recorded as the same, already-tracked Auth/session policy debt -
-- not fixed, not redesigned here.
--
-- PRINCIPAL-ENABLED / OTHER-GRANT INDEPENDENCE (Phase 20/21): proven by dedicated tests - revoking
-- one grant never touches service_principal.enabled, another grant for the same principal, or a
-- grant for a different principal/tenant.
--
-- PRE-FIX CLASSIFICATION: PRIVILEGE-HARDENING / PUBLIC ARCHITECTURE. No correctness or security
-- defect exists in the current revokeGrant path (unlike DB-C2A.9's revokeCredential) - this
-- replaces an already-working, but overly broad, direct table UPDATE (reachable via idax_admin's
-- full SELECT/INSERT/UPDATE on the whole table) with a narrow, column-scoped, atomically-targeted
-- SECURITY DEFINER capability, while additionally proving (not merely assuming) that the table's
-- existing RLS tenant-isolation policy remains fully live and unbypassed underneath it.

GRANT idax_capability_owner TO CURRENT_USER;

GRANT SELECT (grant_id, service_principal_id, tenant_id, audience, enabled, revoked_at)
  ON idax_core.service_principal_grant TO idax_capability_owner;
GRANT UPDATE (enabled, revoked_at)
  ON idax_core.service_principal_grant TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.service_principal_revoke_grant(
    p_service_principal_id uuid,
    p_tenant_id            uuid,
    p_grant_id             uuid
)
RETURNS TABLE (
    grant_id              uuid,
    service_principal_id  uuid,
    tenant_id             uuid,
    audience               text,
    enabled                boolean,
    revoked_at             timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
    IF p_service_principal_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_revoke_grant: invalid service principal id' USING ERRCODE = '22023';
    END IF;
    IF p_tenant_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_revoke_grant: invalid tenant id' USING ERRCODE = '22023';
    END IF;
    IF p_grant_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_revoke_grant: invalid grant id' USING ERRCODE = '22023';
    END IF;

    -- Atomic exact-target transition (Phase 8, defense-in-depth): all three URL-supplied
    -- identifiers are enforced in one WHERE clause. RLS (service_principal_grant_tenant_isolation,
    -- FORCEd, not bypassed by idax_capability_owner - see this migration's header) applies
    -- INDEPENDENTLY on top of this, comparing the row's tenant_id against the session's own
    -- app.tenant_id GUC rather than this function's own p_tenant_id parameter - a genuinely
    -- separate defense layer, proven live by this gate's own tests.
    UPDATE idax_core.service_principal_grant spg
    SET enabled = false,
        revoked_at = now()
    WHERE spg.grant_id = p_grant_id
      AND spg.service_principal_id = p_service_principal_id
      AND spg.tenant_id = p_tenant_id;

    RETURN QUERY
    SELECT spg.grant_id,
           spg.service_principal_id,
           spg.tenant_id,
           spg.audience::text,
           spg.enabled,
           spg.revoked_at
    FROM idax_core.service_principal_grant spg
    WHERE spg.grant_id = p_grant_id
      AND spg.service_principal_id = p_service_principal_id
      AND spg.tenant_id = p_tenant_id;
END;
$function$;

ALTER FUNCTION idax_core.service_principal_revoke_grant(uuid, uuid, uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.service_principal_revoke_grant(uuid, uuid, uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.service_principal_revoke_grant(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.service_principal_revoke_grant(uuid, uuid, uuid)
  TO idax_admin;
