-- V84: DB-C2A.11 - narrow atomic SERVICE_PRINCIPAL_GRANT (create/reactivate) capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29r for the full trace and this gate's report.
--
-- GRANT CREATION TRACED EXACTLY (Phase 1, fresh): TenantServicePrincipalGrantAdminController#grant
-- (POST /api/admin/tenants/{tenantId}/service-principals/{principalId}/grants, class-level
-- ROLE_SUPERUSER, request body record Grant(audience, permissions)) ->
-- ServicePrincipalManagementService#grant(principalId, tenantId, audience, permissions, actor).
-- Prior exact algorithm, in order: (1) requireEffectiveTenant(tenantId); (2) Java validation -
-- audience null/blank/'*' rejected, permissions null/empty/any-null/any-blank/any-'*' rejected
-- (IllegalArgumentException, 400); (3) tenants.findById(tenantId).filter(active) - tenant must
-- exist AND be active (400 if not); (4) principals.findById(principalId) - principal must exist
-- (400 if not); (5) grants.findByServicePrincipalIdAndTenantIdAndAudience(...) - a lookup by the
-- BUSINESS KEY regardless of current enabled/revoked_at state - .orElseGet(new entity with a fresh
-- UUID) if absent, REUSES the existing entity (same grant_id) if present; (6) unconditionally sets
-- permissions=sorted(input), enabled=true, active_from=now(), revoked_at=null, created_by=actor;
-- (7) grants.save(g) (JPA merge/insert); (8) audit.record(...); returns the full entity.
--
-- AUTHORITATIVE KEYS (Phase 3): ROW IDENTITY = grant_id (PK). BUSINESS UNIQUENESS =
-- (service_principal_id, tenant_id, audience) (V51, uq_service_principal_grant).
--
-- CREATE VS ENSURE VS REACTIVATE (Phase 4, THE PRIMARY DECISION, traced from real code, not
-- guessed): **UPSERT / REACTIVATE-AND-REPLACE, scoped to the business key.** Case A (active grant
-- already exists for the same principal+tenant+audience): the SAME row is reused (same grant_id),
-- permissions are REPLACED (not merged/unioned) with the newly requested set, active_from is RESET
-- to now(), created_by is overwritten to the latest actor. Case B (a REVOKED grant exists for the
-- same key): identical to Case A - the revoked row is REACTIVATED in place (enabled flips back to
-- true, revoked_at cleared to null, same grant_id preserved, permissions replaced). Case C (same
-- principal+tenant, different audience): audience is part of the business key, so this is a wholly
-- independent row - no interference, confirmed by schema. Case D (same audience, different
-- permissions on a re-call): permissions are REPLACED, matching Case A exactly - this is not an
-- "additive" grant model. created_at is NEVER touched on reactivation (the JPA entity's own
-- `@Column(updatable = false)` on createdAt is honored by Hibernate's UPDATE statement already -
-- confirmed from the entity source, not assumed). No STOP triggered - this is fully deterministic,
-- not ambiguous.
--
-- UNIQUE-CONSTRAINT BEHAVIOR (Phase 5): maps directly onto PostgreSQL's native
-- `INSERT ... ON CONFLICT ON CONSTRAINT uq_service_principal_grant DO UPDATE` - a single atomic
-- statement reproducing the exact same "reuse existing row, replace permissions/enabled/
-- active_from/revoked_at/created_by, preserve grant_id and created_at" semantics as the current
-- JPA find-then-merge pattern, using the authoritative UNIQUE constraint as the correctness
-- boundary rather than a Java exists-then-insert race (Phase 23).
--
-- GRANT_ID GENERATION (Phase 6): preserved exactly - Java generates UUID.randomUUID() and passes
-- it as a parameter (used only for the INSERT branch; on conflict, the existing row's own grant_id
-- is never overwritten, matching today's JPA reuse-the-fetched-entity behavior).
--
-- PRINCIPAL / TENANT EXISTENCE (Phase 10/11): UNCHANGED, remains entirely Java-side -
-- requireEffectiveTenant, tenants.findById(...).filter(active), and
-- principals.findById(...).orElseThrow() all still run BEFORE this capability is ever called,
-- preserving the exact current 400 messages and not converting either check into an FK-violation-
-- driven error path. This capability's own scope is narrower than the full Java method: only the
-- persistence transition itself.
--
-- AUDIENCE CONTRACT (Phase 12/13): varchar(120) NOT NULL, DB CHECK
-- (audience <> '' AND audience <> '*') (V51, ck_service_principal_grant_audience) - Java's own
-- validation duplicates this defensively but the DB is also authoritative. No case normalization
-- anywhere - ServiceTokenIssuer's own audience match
-- (findByServicePrincipalIdAndTenantIdAndAudience) is exact and case-sensitive; this migration
-- preserves that with no LOWER()/TRIM() introduced.
--
-- PERMISSIONS CONTRACT (Phase 14/15/17/18): Java `Set<String> permissions` (deduplication happens
-- structurally via the Set type before this method is ever called - Jackson deserializes a JSON
-- array into a Set, collapsing exact-duplicate strings); sorted alphabetically before storage
-- (`permissions.stream().sorted()`) - preserved exactly, sorting stays Java-side, this migration
-- accepts the already-sorted array as a plain parameter. Validation (non-null, non-empty, no
-- null/blank/'*' entries) remains entirely Java-side, matching the established "business/
-- application validation stays Java-side" policy from every prior gate - this capability does not
-- re-implement or relax it. No permission vocabulary/enum exists anywhere in this codebase today -
-- permissions are arbitrary bounded strings (Phase 16: GRANT PERMISSION AUTHORITY = global
-- superuser only, no tenant-admin path exists for this controller at all, confirmed doubly by
-- JwtAuthFilter#isTenantServiceGrantAdminPath - matching DB-C2A.10's own finding for the sibling
-- revoke endpoint on this identical controller class).
--
-- ENABLED / ACTIVE_FROM / REVOKED_AT (Phase 19/20): hardcoded, never caller-controlled - enabled
-- always true, active_from always now() (DB-authoritative, via column DEFAULT, not a Java
-- timestamp), revoked_at always cleared to NULL on both branches. No future-activation contract
-- exists today; none is introduced.
--
-- CREATED_AT / CREATED_BY (Phase 21): created_at is DB-generated via its own column DEFAULT
-- now() on first INSERT only, and is NEVER included in the DO UPDATE SET list - reproducing the
-- entity's own `updatable = false` semantics exactly, so a reactivation preserves the original
-- creation timestamp. created_by is Java-derived (SecurityContextHolder's authentication name,
-- NEVER a raw caller-supplied string) and IS overwritten on every call including reactivation,
-- matching today's unconditional `g.setCreatedBy(actor)` - and is genuinely nullable (the column
-- carries no NOT NULL constraint, matching actor() returning null when unauthenticated) - no NULL
-- rejection is applied to this one parameter.
--
-- FORBIDDEN FIELDS (Phase 22, exact classification): grant_id - JAVA-DERIVED TRUSTED INPUT.
-- service_principal_id/tenant_id/audience - CALLER INPUT (pre-validated to exist/be well-formed by
-- Java before this capability is ever invoked). permissions - CALLER INPUT (Java-validated,
-- deduplicated, sorted). enabled - HARDCODED SAFE VALUE (true). active_from - DB-GENERATED
-- (DEFAULT now()). revoked_at - HARDCODED SAFE VALUE (NULL, via omission + explicit DO UPDATE
-- SET). created_at - DB-GENERATED, NOT WRITABLE on reactivation. created_by - JAVA-DERIVED TRUSTED
-- INPUT.
--
-- RLS - PRESERVING DB-C2A.10's ARCHITECTURE (Phase 7/8, verified directly, not assumed):
-- service_principal_grant retains ENABLE + FORCE ROW LEVEL SECURITY (V51, unchanged) and its
-- single service_principal_grant_tenant_isolation policy, whose WITH CHECK clause
-- (tenant_id = current_setting('app.tenant_id')) applies to BOTH the INSERT and the UPDATE branch
-- of this capability's single ON CONFLICT statement - PostgreSQL enforces WITH CHECK against every
-- new/modified row value regardless of which branch produced it. idax_capability_owner still has
-- no BYPASSRLS and still does not own this table (DB-C2A.10's own findings, unaffected by this
-- gate) - RLS remains fully live inside this new SECURITY DEFINER function exactly as it did for
-- REVOKE. Proven fresh by this gate's own dedicated tests: a session pinned to tenant A attempting
-- to INSERT/reactivate a grant with p_tenant_id = B is rejected by RLS's WITH CHECK with zero rows
-- persisted - the capability provides no alternate bypass path. No STOP triggered.
--
-- EXECUTION CONTEXT / CALLER (Phase 9/33, re-traced fresh, not assumed from the sibling revoke
-- endpoint despite being the identical controller class): this grant() endpoint shares the exact
-- same @RequestMapping path prefix, the exact same class-level ROLE_SUPERUSER @PreAuthorize, and
-- is matched by the exact same JwtAuthFilter#isTenantServiceGrantAdminPath check (URL-pattern-
-- based, not HTTP-verb-based) as DB-C2A.10's revoke endpoint - re-confirmed by re-reading the
-- controller class fresh this gate. **ACTUAL CALLER: idax_admin** (identical reasoning to
-- DB-C2A.10: TenantContext always established from the path, no tenant-admin path exists, superuser
-- always resolves to idax_admin). idax_backend gets EFFECTIVE-only access via its own standing
-- INHERIT membership in idax_admin (V1) - inert, no genuine call path. idax_app gets nothing (no
-- genuine tenant-admin caller for this specific superuser-only controller).
--
-- DIRECT GRANTEE: idax_admin DIRECT - matching DB-C2A.10's own established V68/V77-style
-- "transitional idax_admin" pattern exactly (same DB-C1B cleanup checklist entry, not duplicated).
--
-- OWNER PRIVILEGE (Phase 30/31, minimized precisely): idax_capability_owner held only SELECT/
-- UPDATE(enabled, revoked_at) on this table before this gate (DB-C2A.10). This migration adds
-- INSERT(grant_id, service_principal_id, tenant_id, audience, permissions, enabled, created_by) -
-- explicitly excluding active_from/revoked_at/created_at, which rely entirely on column DEFAULTs -
-- and extends UPDATE to (permissions, enabled, active_from, revoked_at, created_by) - explicitly
-- excluding created_at (preserving its immutability) and the four business-key columns (never
-- touched on conflict). SELECT is extended to the full 10-column row, matching this operation's own
-- genuine RETURNING requirement (the current API already returns the complete entity - Phase 29;
-- this is not a broadened grant, it is the actual output contract). No DELETE. No privilege
-- whatsoever on service_principal_credential or service_principal_audit.
--
-- PRE-FIX CLASSIFICATION: PRIVILEGE-HARDENING / PUBLIC ARCHITECTURE. No correctness or security
-- defect exists in the current grant() path - this replaces an already-working, but overly broad,
-- direct table INSERT/UPDATE (reachable via idax_admin's full SELECT/INSERT/UPDATE on the whole
-- table) with a narrow, column-scoped, atomically-upserting SECURITY DEFINER capability, while
-- reconfirming (not merely assuming) that RLS remains fully live for the INSERT path exactly as it
-- was proven live for UPDATE at DB-C2A.10.

GRANT idax_capability_owner TO CURRENT_USER;

GRANT INSERT (grant_id, service_principal_id, tenant_id, audience, permissions, enabled, created_by)
  ON idax_core.service_principal_grant TO idax_capability_owner;
GRANT UPDATE (permissions, enabled, active_from, revoked_at, created_by)
  ON idax_core.service_principal_grant TO idax_capability_owner;
GRANT SELECT (grant_id, service_principal_id, tenant_id, audience, permissions, enabled, active_from, revoked_at, created_at, created_by)
  ON idax_core.service_principal_grant TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.service_principal_create_grant(
    p_grant_id             uuid,
    p_service_principal_id uuid,
    p_tenant_id            uuid,
    p_audience             text,
    p_permissions          text[],
    p_created_by           text
)
RETURNS TABLE (
    grant_id              uuid,
    service_principal_id  uuid,
    tenant_id             uuid,
    audience               text,
    permissions             text[],
    enabled                 boolean,
    active_from             timestamptz,
    revoked_at              timestamptz,
    created_at              timestamptz,
    created_by              text
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
    IF p_grant_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_create_grant: invalid grant id' USING ERRCODE = '22023';
    END IF;
    IF p_service_principal_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_create_grant: invalid service principal id' USING ERRCODE = '22023';
    END IF;
    IF p_tenant_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_create_grant: invalid tenant id' USING ERRCODE = '22023';
    END IF;
    IF p_audience IS NULL THEN
        RAISE EXCEPTION 'service_principal_create_grant: invalid audience' USING ERRCODE = '22023';
    END IF;
    IF p_permissions IS NULL THEN
        RAISE EXCEPTION 'service_principal_create_grant: invalid permissions' USING ERRCODE = '22023';
    END IF;
    -- p_created_by is intentionally NOT null-checked: the column is nullable, matching the Java
    -- actor() call this parameter is sourced from (returns null when unauthenticated).

    -- Single atomic upsert-by-business-key (Phase 5/23): the authoritative UNIQUE constraint
    -- (service_principal_id, tenant_id, audience) is the correctness boundary, not a Java
    -- exists-then-insert race. RLS's WITH CHECK (tenant_id = current session tenant) applies to
    -- both branches of this statement identically - proven live by this gate's own tests.
    RETURN QUERY
    INSERT INTO idax_core.service_principal_grant
        (grant_id, service_principal_id, tenant_id, audience, permissions, enabled, created_by)
    VALUES
        (p_grant_id, p_service_principal_id, p_tenant_id, p_audience, p_permissions, true, p_created_by)
    ON CONFLICT ON CONSTRAINT uq_service_principal_grant
    DO UPDATE SET
        permissions = EXCLUDED.permissions,
        enabled = true,
        active_from = now(),
        revoked_at = NULL,
        created_by = EXCLUDED.created_by
    RETURNING
        idax_core.service_principal_grant.grant_id,
        idax_core.service_principal_grant.service_principal_id,
        idax_core.service_principal_grant.tenant_id,
        idax_core.service_principal_grant.audience::text,
        idax_core.service_principal_grant.permissions,
        idax_core.service_principal_grant.enabled,
        idax_core.service_principal_grant.active_from,
        idax_core.service_principal_grant.revoked_at,
        idax_core.service_principal_grant.created_at,
        idax_core.service_principal_grant.created_by::text;
END;
$function$;

ALTER FUNCTION idax_core.service_principal_create_grant(uuid, uuid, uuid, text, text[], text)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.service_principal_create_grant(uuid, uuid, uuid, text, text[], text)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.service_principal_create_grant(uuid, uuid, uuid, text, text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.service_principal_create_grant(uuid, uuid, uuid, text, text[], text)
  TO idax_admin;
