-- V86: DB-C2A.12 - narrow atomic TENANT_CREATE capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29t for the full trace and this gate's report.
--
-- CREATE TRACED EXACTLY (Phase 1, fresh): TenantController#create (POST /api/tenants, class has no
-- tenant path segment at all, @PreAuthorize("hasAuthority('ROLE_SUPERUSER')")) ->
-- TenantService#create(Tenant). Prior exact algorithm: (1) if code is null/blank, throw
-- IllegalArgumentException("Tenant code is required"); (2) else if
-- tenantRepository.existsByCode(code), throw IllegalArgumentException("Tenant with code X already
-- exists") - a Java-side pre-check, NOT the sole concurrency guard (the table's own UNIQUE
-- constraint on code is authoritative for the race window - see Phase 9/10 below); (3)
-- tenant.setCreatedAt(now()) (redundant with the entity's own @PrePersist, both Java-side); (4)
-- tenantRepository.save(tenant) - a single JPA INSERT. No further operation follows - this is the
-- LAST statement in the method, so no later-failure-rolls-back-the-insert scenario exists for
-- create() (unlike update()'s composed name+status/mfa_required write at DB-C2A.5).
--
-- TENANT ROW VS ONBOARDING (Phase 2, THE PRIMARY DECISION, fresh full source search): a
-- COMPLETELY independent, standalone operation. TenantService#create performs ONLY the row
-- insert - no first-administrator creation, no AppUser membership, no tenant-admin role
-- assignment, no service-principal provisioning, no onboarding workflow of any kind. A full source
-- search confirms TenantController/TenantService are the ONLY production code that ever
-- constructs a new Tenant or calls tenantRepository.save() with one - no other caller composes
-- tenant creation with anything else. **TENANT ROW WITHOUT USERS/MEMBERSHIPS: VALID STATE.** No
-- STOP triggered.
--
-- AUTHORITATIVE IDENTITY / BUSINESS KEY (Phase 5): tenant_id (PK, `uuid PRIMARY KEY DEFAULT
-- gen_random_uuid()` - V1's own schema, confirmed directly, not assumed). code (`varchar(50) NOT
-- NULL UNIQUE` - a genuine DB-level UNIQUE constraint, not merely a Java-side check). Unlike every
-- prior "identity" capability in this program (service_principal/service_principal_grant, whose PK
-- columns carry NO default and require Java/the function to supply the value), idax_core.tenant's
-- tenant_id has ALWAYS had a native DB-level generator since its very first creation in V1 - this
-- migration therefore lets that pre-existing DEFAULT populate tenant_id directly, rather than
-- accepting it as a caller-supplied parameter (Phase 6: this is preservation of intent, not a
-- strategy change - Hibernate's own GenerationType.UUID and Postgres's gen_random_uuid() both
-- produce "a random UUID"; the RESULT is indistinguishable either way).
--
-- REQUEST FIELDS / DEFAULTS (Phase 7, traced from the Tenant entity, not inferred): code - no
-- Java validation beyond the null/blank pre-check above; DB CHECK/UNIQUE only. name - varchar(200)
-- NOT NULL, no Java-side validation at all (matches DB-C2A.5's own "name" finding for update - pure
-- display metadata, no normalization). status - varchar(20) NOT NULL, Java field initializer
-- `= "active"` (applies whenever the request JSON omits "status" - Lombok's @Builder.Default only
-- governs the .builder() path, but the plain field initializer applies unconditionally through the
-- no-args-constructor path Jackson actually uses for @RequestBody); if the caller DOES supply a
-- status, it is used as a RAW UNVALIDATED STRING (matching TenantService#update's own already-
-- established permissiveness - "any value, no boolean coercion", DB-C2A.5). mfa_required -
-- `Boolean NOT NULL` column, Java field initializer `= false` (same omitted-vs-supplied rule as
-- status); this migration preserves this exactly - it does not add or remove any validation, and
-- does not change WHERE the "default when omitted" logic lives (it remains entirely Java-side, in
-- the Tenant entity's own field initializers, untouched by this migration).
--
-- TENANT CODE MUTABILITY (Phase 8): CREATE-ONLY. Neither TenantService#update nor #updateEnabled
-- (the only two other tenant-mutating operations) ever reads or writes `code` - reconfirmed fresh.
--
-- DUPLICATE CODE / CREATE VS ENSURE (Phase 9/19): CREATE ONLY - a duplicate is a hard failure,
-- never a silent return-existing/update. Today's dual observable behavior (a non-racing duplicate
-- fails Java-side with IllegalArgumentException/400 via the existsByCode pre-check; a genuinely
-- racing concurrent duplicate instead fails via the table's own UNIQUE constraint,
-- DataIntegrityViolationException/409) is preserved exactly - this migration does NOT remove the
-- existing Java pre-check (kept verbatim in TenantService#create, unchanged), it only replaces the
-- final persistence step. The capability's own single INSERT statement is therefore only ever
-- reached for the race-window case, using the UNIQUE constraint as the authoritative concurrency
-- boundary per Phase 10 - no ON CONFLICT clause is used (an actual duplicate must fail, not upsert).
--
-- CREATED_AT / UPDATED_AT (Phase 16): both columns already carry `DEFAULT now()` at the table
-- level (V1's own schema, confirmed directly) - this migration omits both from its INSERT column
-- list entirely, relying on those pre-existing DB defaults instead of Java's current
-- OffsetDateTime.now() - strictly more precise, not an observable behavior change, matching every
-- prior create-capability's own established choice (V78/V81/V84).
--
-- FORBIDDEN FIELDS (Phase 20, exact classification): tenant_id - DB-GENERATED (pre-existing
-- DEFAULT gen_random_uuid(), never a caller/Java-supplied parameter). code/name/status/
-- mfa_required - CALLER INPUT (validated/defaulted entirely Java-side, unchanged). created_at/
-- updated_at - DB-GENERATED (pre-existing DEFAULT now()), NOT WRITABLE by this capability. No
-- membership/admin/user/credential/service-principal field exists in this contract at all.
--
-- AUDIT (Phase 17/18): TRACED FRESH - TenantService#create has NO explicit audit call of any kind
-- (unlike update()/updateEnabled(), which both explicitly replicate AutomaticFieldChangeAuditListener's
-- TENANT_FIELDS_UPDATED event for their bypassed-JPA field). AutomaticFieldChangeAuditListener
-- itself implements Hibernate's PreInsertEventListener/PreUpdateEventListener (field-STAMPING only -
-- idaxCreatedBy/idaxModifiedBy - never an audit event) and PostUpdateEventListener (the ONLY method
-- that emits an actual audit event, and it is UPDATE-only - there is no PostInsertEventListener
-- implementation at all). Additionally, the Tenant entity has no idaxCreatedBy/idaxModifiedBy
-- fields/setters, so even the field-stamping silently no-ops for it (reflection lookup fails,
-- caught, ignored). CREATE therefore produces NO audit event and NO field-stamping today, from any
-- source - verified precisely, not assumed. This capability introduces no audit regression: there
-- is nothing to preserve or replicate, because nothing existed before.
--
-- RLS (Phase 26): idax_core.tenant carries NO Row-Level Security at all - confirmed directly (no
-- ENABLE/FORCE ROW LEVEL SECURITY or CREATE POLICY statement targets this table anywhere in the
-- migration history) - it is the global tenant catalog itself, not tenant-owned data, so no
-- tenant-context predicate applies or should be invented here.
--
-- EXECUTION CONTEXT / CALLER (Phase 3/4, re-traced fresh from JwtAuthFilter, NOT assumed from
-- TENANT_SEARCH_GLOBAL's own different, frontend-dependent finding at DB-C2A.3): POST /api/tenants
-- carries no path segment after "tenants" at all - JwtAuthFilter#extractTenantIdFromPath's own
-- `i + 1 < parts.length` guard makes pathTenantId unconditionally null for this exact URI.
-- Separately, JwtAuthFilter's X-Tenant-header eligibility check requires
-- `uri.startsWith("/api/tenants/")` (WITH a trailing slash) - "/api/tenants" (no trailing content)
-- does NOT satisfy this, so a caller who sends an X-Tenant header to this exact endpoint is
-- rejected outright with 400 BEFORE the controller is ever reached. The JWT-tenant fallback
-- (Priority 3) is also null for any superuser (established repeatedly across this program).
-- **There is therefore no possible path - unlike TENANT_SEARCH_GLOBAL's own genuinely
-- frontend-dependent ambiguity - by which TenantContext could ever be established for this
-- specific endpoint: TenantContext is unconditionally null, and the connection unconditionally
-- remains at bare idax_backend.** DIRECT EXECUTE: idax_backend ONLY - no genuine idax_admin
-- execution path exists for this endpoint (re-verified fresh, not assumed), so idax_admin receives
-- nothing, matching the permanent grantee rule exactly (unlike V70's own, earlier, pre-DB-C2A.6a
-- idax_admin-direct choice for the search endpoint, which remains untouched and immutable).
--
-- CURRENT TENANT TABLE ACL / GRANT PROVENANCE (Phase 24/25, verified empirically by this gate's
-- own tests, not merely read from migration text - the DB-C2A.11a lesson applied again, and a NEW
-- distinct mechanism discovered this time, not the same one): initial assumption (tenant is
-- created, V1 line ~133, BEFORE V1's own `ALTER DEFAULT PRIVILEGES ... GRANT ALL ON TABLES TO
-- idax_admin`, line ~734) was DISPROVEN by this gate's own negative-proof tests, which found
-- idax_admin genuinely holds TRUNCATE/REFERENCES/TRIGGER on idax_core.tenant and idax_app
-- genuinely holds INSERT/UPDATE/DELETE (not just SELECT). Root cause, re-traced precisely: V1
-- contains TWO separate, EARLIER, IMMEDIATE blanket statements - `GRANT SELECT, INSERT, UPDATE,
-- DELETE ON ALL TABLES IN SCHEMA idax_core TO idax_app` (line ~721) and `GRANT ALL PRIVILEGES ON
-- ALL TABLES IN SCHEMA idax_core TO idax_admin` (line ~724) - which, UNLIKE `ALTER DEFAULT
-- PRIVILEGES` (future-object-only), apply IMMEDIATELY to every table that ALREADY EXISTS at
-- execution time, including idax_core.tenant (created earlier at line ~133, well before these
-- blanket grants run). The LATER, comment-labeled "tenant es tabla global: lectura para app,
-- control total para admin" per-table statements (`GRANT SELECT ON idax_core.tenant TO idax_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.tenant TO idax_admin;`, line ~741-742) read,
-- in isolation, as if they defined the FULL intended privilege set - but GRANT is purely additive,
-- never restrictive, so these later statements are entirely redundant subsets of what the earlier
-- blanket grants already established, and change nothing. **idax_admin's actual privilege on
-- idax_core.tenant is therefore the full "ALL" set (SELECT/INSERT/UPDATE/DELETE/TRUNCATE/
-- REFERENCES/TRIGGER); idax_app's is SELECT/INSERT/UPDATE/DELETE** - both broader than either
-- table's own comment or later per-table GRANT statement would suggest when read alone. This is a
-- DIFFERENT mechanism from DB-C2A.11a's own finding (that gate's tables inherited breadth via
-- `ALTER DEFAULT PRIVILEGES` on FUTURE object creation; this table's breadth comes from an
-- IMMEDIATE blanket grant over EXISTING objects) but the same class of problem: an early,
-- broad-scope privilege statement silently outliving a later, narrower-looking, purely-additive
-- one. CLASSIFICATION: SAFE FOR THIS GATE / TECHNICAL DEBT, NOT BLOCKING - Phase 25 explicitly
-- forbids revoking any of this here (remaining tenant-table consumers - update()/updateEnabled()/
-- delete() - still need broad access, unrelated to this gate), and the new capability's own DIRECT
-- grant to idax_backend does not depend on any of it (proven, see Phase 30/31 below). Recorded as
-- tracked technical debt for a future dedicated tenant-table closure gate, not duplicated
-- elsewhere, not fixed here.
--
-- OWNER PRIVILEGE (Phase 23, minimized precisely): idax_capability_owner already holds table-wide
-- SELECT (V70) and column-level UPDATE(status/updated_at from V71, name from V77) on
-- idax_core.tenant - SELECT already covers every column this capability's RETURNING clause needs,
-- so NO new SELECT is added. This migration adds exactly INSERT(code, name, status, mfa_required) -
-- explicitly excluding tenant_id/created_at/updated_at (all three rely on pre-existing column
-- DEFAULTs) - never table-wide INSERT. No DELETE.
--
-- PRE-FIX CLASSIFICATION: PRIVILEGE-HARDENING / PUBLIC ARCHITECTURE. No correctness or security
-- defect exists in the current create() path - this replaces an already-working, but overly broad,
-- direct table INSERT (reachable via idax_admin's V1 grant, inherited by idax_backend) with a
-- narrow, column-scoped, SECURITY DEFINER capability granted DIRECTLY to the real caller.

GRANT idax_capability_owner TO CURRENT_USER;

GRANT INSERT (code, name, status, mfa_required)
  ON idax_core.tenant TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.tenant_create(
    p_code         text,
    p_name         text,
    p_status       text,
    p_mfa_required boolean
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
BEGIN
    IF p_code IS NULL THEN
        RAISE EXCEPTION 'tenant_create: invalid code' USING ERRCODE = '22023';
    END IF;
    IF p_name IS NULL THEN
        RAISE EXCEPTION 'tenant_create: invalid name' USING ERRCODE = '22023';
    END IF;
    IF p_status IS NULL THEN
        RAISE EXCEPTION 'tenant_create: invalid status' USING ERRCODE = '22023';
    END IF;
    IF p_mfa_required IS NULL THEN
        RAISE EXCEPTION 'tenant_create: invalid mfa_required' USING ERRCODE = '22023';
    END IF;

    -- No ON CONFLICT clause - a duplicate code must fail (CREATE ONLY, Phase 9/19), relying on the
    -- table's own UNIQUE constraint as the authoritative concurrency boundary (Phase 10).
    -- tenant_id/created_at/updated_at are intentionally omitted - their pre-existing column
    -- DEFAULTs (gen_random_uuid()/now()/now()) populate them.
    RETURN QUERY
    INSERT INTO idax_core.tenant (code, name, status, mfa_required)
    VALUES (p_code, p_name, p_status, p_mfa_required)
    RETURNING
        idax_core.tenant.tenant_id,
        idax_core.tenant.code::text,
        idax_core.tenant.name::text,
        idax_core.tenant.status::text,
        idax_core.tenant.mfa_required,
        idax_core.tenant.created_at,
        idax_core.tenant.updated_at;
END;
$function$;

ALTER FUNCTION idax_core.tenant_create(text, text, text, boolean)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.tenant_create(text, text, text, boolean)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.tenant_create(text, text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.tenant_create(text, text, text, boolean)
  TO idax_backend;
