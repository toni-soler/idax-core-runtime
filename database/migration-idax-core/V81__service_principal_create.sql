-- V81: DB-C2A.8 - narrow atomic SERVICE_PRINCIPAL_CREATE capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29o for the full trace and this gate's report.
--
-- CREATE TRACED EXACTLY (Phase 1, fresh, not copied from DB-C2A.6's summary):
-- ServicePrincipalAdminController#create (POST /api/admin/service-principals, class-level
-- @PreAuthorize("hasAuthority('ROLE_SUPERUSER')"), no tenant path, request body record
-- Create(clientId, displayName)) -> ServicePrincipalManagementService#create(String clientId,
-- String displayName). Current exact algorithm, before this migration: (1) Java generates
-- UUID.randomUUID() for the identity; (2) builds a ServicePrincipal entity with that id, clientId,
-- displayName, enabled=true (hardcoded, never caller-controlled - the Create DTO carries no
-- "enabled" field at all); (3) principals.save(...) - a single JPA INSERT; entity's own
-- @PrePersist sets createdAt/updatedAt to Java OffsetDateTime.now() (id is already set, so the
-- id==null branch never fires); (4) audit.record(p.getId(), clientId, null, null,
-- "SERVICE_PRINCIPAL_CREATED", "SUCCESS", actor(), null) - AFTER the insert succeeds, inside the
-- same outer @Transactional method, but internally its own REQUIRES_NEW transaction (unchanged,
-- persistence-mechanism-agnostic Java call - see DB-C2A.6); (5) returns the persisted entity,
-- serialized by the controller as JSON.
--
-- CREATE VS FIRST CREDENTIAL (Phase 2, THE PRIMARY DECISION): PRINCIPAL WITHOUT CREDENTIAL IS A
-- VALID STATE, proven from the real product workflow, not assumed. scripts/register-service-
-- principal.sh performs three genuinely separate HTTP calls in sequence - create, then issue a
-- credential, then create a grant - with no atomic combination anywhere. A brand-new principal
-- necessarily exists with ZERO credential rows for a real span of time between the first two calls
-- (including indefinitely, if the second call never happens). ServicePrincipalManagementService
-- exposes create() and addCredential()/rotateCredential() as entirely separate methods, never
-- composed. No STOP triggered.
--
-- ZERO-CREDENTIAL AUTHENTICATION SAFETY (Phase 3): structurally guaranteed, not just tested.
-- ServiceTokenIssuer#issue calls credentials.findByServicePrincipalId(principal.id()) and requires
-- .anyMatch(...) against the effective rows; an empty list makes anyMatch trivially false
-- regardless of the supplied clientSecret, so secretOk=false unconditionally and
-- ServiceAuthenticationException is thrown - true whether the principal is enabled or disabled.
-- Additionally, idax_service_auth (ServiceTokenIssuer's real execution role) has been asserted to
-- hold NO INSERT privilege on service_principal at all in the pre-existing
-- ServicePrincipalAuthenticationPostgresTest#assertMinimumDatabasePrivileges - authentication
-- cannot create identities even if it tried. Proven fresh by this gate's own dedicated test.
--
-- INPUT CONTRACT (Phase 4): exactly two fields, matching the Create DTO precisely - clientId
-- (varchar(120) NOT NULL UNIQUE at the table level; NO Java-side validation exists today - blank
-- ("") is currently permitted, not rejected, matching V77's own precedent for tenant name: only
-- NULL is rejected, mirroring the pre-existing NOT NULL constraint, no NEW validation introduced),
-- displayName (varchar(200) NOT NULL; same story - blank permitted today, only NULL rejected).
-- "enabled" is NOT an input field of the current contract at all (Phase 9) - hardcoded true, both
-- in today's Java and in this capability; the SQL function does not accept it as a parameter.
--
-- CLIENT_ID AUTHORITY / GENERATION (Phase 5): service_principal_id remains the canonical internal
-- identity (DB-C2A.7); client_id is caller-supplied (the admin/onboarding tool decides it, e.g.
-- "idax-platform-factuflow-connector" in register-service-principal.sh) - never server-generated,
-- unchanged by this migration.
--
-- NORMALIZATION (Phase 6): none today, none added - exact case-sensitive value stored as supplied,
-- consistent with DB-C2A.7's proven exact-match lookup contract. No LOWER/TRIM introduced.
--
-- UNIQUE CONSTRAINT / CONCURRENCY (Phase 7/12): idax_core.service_principal.client_id carries a
-- genuine table-level UNIQUE constraint (V51). This capability performs a single INSERT relying
-- entirely on that constraint as the authoritative concurrency boundary - no
-- "exists(client_id) then insert" Java-side check exists today or is introduced here. A duplicate
-- client_id raises a Postgres unique_violation (23505), which Spring translates to
-- DataIntegrityViolationException exactly as JPA's own save() already does today -
-- GlobalExceptionHandler maps this to HTTP 409 - unchanged observable behavior.
--
-- CREATE VS ENSURE (Phase 13): CREATE. Confirmed from GlobalExceptionHandler#handleDataIntegrity -
-- any DataIntegrityViolationException (including a duplicate client_id) returns HTTP 409, matching
-- register-service-principal.sh's own explicit handling of a 409 response as "already exists,
-- reuse via lookup" - the API is not idempotent; a duplicate is a hard failure, never a silent
-- return of the existing row. This function preserves that: a duplicate is a raised exception, not
-- an ON CONFLICT DO NOTHING/UPDATE.
--
-- UUID / PRIMARY KEY GENERATION (Phase 8): preserved exactly as today - Java generates
-- UUID.randomUUID() and passes it as a parameter (matching this program's established convention
-- of every prior capability accepting the identity as an input rather than generating it in SQL).
-- No new randomness/generation dependency introduced.
--
-- CREATED_AT / UPDATED_AT (Phase 10): today's Java @PrePersist sets both from Java-side
-- OffsetDateTime.now(). This migration instead relies on the table's own pre-existing column
-- defaults (V51: `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`, `updated_at TIMESTAMPTZ NOT NULL
-- DEFAULT now()`) - DB-authoritative time, a strictly more precise source for the same observable
-- semantics (a timestamp at/near insert time), not a behavior change. Neither column is included
-- in this migration's explicit INSERT column list or owner grant.
--
-- FORBIDDEN FIELDS (Phase 11): this capability accepts and touches only
-- service_principal_id/client_id/display_name/enabled(hardcoded true) on service_principal itself.
-- It cannot accept or write: credential hash/secret plaintext, grant rows, tenant bindings,
-- permissions/scopes, audit rows (Java's own audit.record(...) remains the sole audit writer,
-- unchanged), last-used authentication metadata, or a caller-supplied enabled value.
--
-- MANAGEMENT VS AUTHENTICATION (Phase 16): MANAGEMENT ONLY. Confirmed by fresh full source search -
-- ServiceTokenIssuer never calls create() or any principal-creation path; no token-issuance flow
-- implicitly provisions a service principal. No STOP triggered.
--
-- APPLICATION AUTHORIZATION (Phase 17): unchanged, entirely Java-side -
-- @PreAuthorize("hasAuthority('ROLE_SUPERUSER')") at ServicePrincipalAdminController class level. No
-- role/permission string passed into SQL.
--
-- EXECUTION CONTEXT (Phase 18, re-traced fresh for THIS endpoint, not assumed from sibling
-- endpoints): POST /api/admin/service-principals carries no "tenants" path segment and is not on
-- JwtAuthFilter's X-Tenant-header-allowed prefix list; superuser JWTs carry no tenantId claim -
-- TenantContext is never established, leaving the connection at bare idax_backend for this call,
-- exactly matching every other operation on this same controller (DB-C2A.6/.6a/.7). **ACTUAL
-- CALLER: idax_backend.** No genuine idax_admin execution path exists for this endpoint. Today,
-- idax_backend's own INSERT capability on this table is EFFECTIVE ONLY, via its standing INHERIT
-- membership in idax_admin (V51: `GRANT SELECT, INSERT, UPDATE ON idax_core.service_principal TO
-- idax_admin`) - re-confirmed directly from V51's own text, not by analogy. Per the permanent
-- grantee rule (DB-C2A.6a), this capability grants idax_backend DIRECT EXECUTE from inception -
-- idax_admin receives nothing (no genuine caller), idax_app/idax_service_auth receive nothing (no
-- caller at all - idax_service_auth never creates identities, confirmed above).
--
-- OWNER PRIVILEGE (Phase 20): idax_capability_owner already holds table-wide SELECT (V78) and
-- column-level UPDATE(enabled, updated_at) (V78) on service_principal. This migration adds
-- column-scoped INSERT(service_principal_id, client_id, display_name, enabled) only - explicitly
-- excluding created_at/updated_at (left to the table's own defaults, see above) - never table-wide
-- INSERT. No privilege whatsoever on service_principal_credential/service_principal_grant/
-- service_principal_audit.
--
-- SEQUENCE / DEFAULT PRIVILEGES (Phase 21): NONE. service_principal_id is a plain UUID PK with no
-- sequence/identity column; no new table/sequence/constraint is created by this migration - PUBLIC-
-- execute-on-create handled by the standard REVOKE ALL ... FROM PUBLIC. DEFAULT PRIVILEGE MODEL:
-- SAFE FOR THIS GATE.
--
-- AUDIT / TRANSACTION (Phase 24/25): unchanged. ServicePrincipalManagementService#create keeps its
-- existing audit.record(...) call, made AFTER the capability call succeeds, inside the same outer
-- @Transactional method; the audit logger's own internal REQUIRES_NEW transaction is untouched -
-- if create's outer transaction later rolls back for any unrelated reason after audit.record(...)
-- already committed, the pre-existing (not introduced by this gate) inconsistency window is
-- unchanged, matching every prior DB-C2A.6-family capability's own documented behavior exactly.
--
-- PRE-FIX CLASSIFICATION: PRIVILEGE-HARDENING / PUBLIC ARCHITECTURE. No correctness, ambiguity, or
-- security bug exists in the current create() path - this replaces an already-working, but overly
-- broad, direct table INSERT (reachable via idax_admin's full SELECT/INSERT/UPDATE on the whole
-- table, inherited by idax_backend) with a narrow, column-scoped, SECURITY DEFINER capability
-- granted DIRECTLY to the real caller.

GRANT idax_capability_owner TO CURRENT_USER;

GRANT INSERT (service_principal_id, client_id, display_name, enabled)
  ON idax_core.service_principal TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.service_principal_create(
    p_service_principal_id uuid,
    p_client_id            text,
    p_display_name         text
)
RETURNS TABLE (
    service_principal_id uuid,
    client_id             text,
    display_name          text,
    enabled                boolean,
    created_at             timestamptz,
    updated_at             timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
    IF p_service_principal_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_create: invalid service principal id' USING ERRCODE = '22023';
    END IF;
    IF p_client_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_create: invalid client id' USING ERRCODE = '22023';
    END IF;
    IF p_display_name IS NULL THEN
        RAISE EXCEPTION 'service_principal_create: invalid display name' USING ERRCODE = '22023';
    END IF;

    INSERT INTO idax_core.service_principal (service_principal_id, client_id, display_name, enabled)
    VALUES (p_service_principal_id, p_client_id, p_display_name, true);

    -- idax_core.service_principal.client_id/display_name are varchar(n); PL/pgSQL's RETURN QUERY
    -- requires an exact type match against RETURNS TABLE - explicit casts avoid "structure of query
    -- does not match function result type" (DB-C2A.1 lesson).
    RETURN QUERY
    SELECT sp.service_principal_id,
           sp.client_id::text,
           sp.display_name::text,
           sp.enabled,
           sp.created_at,
           sp.updated_at
    FROM idax_core.service_principal sp
    WHERE sp.service_principal_id = p_service_principal_id;
END;
$function$;

ALTER FUNCTION idax_core.service_principal_create(uuid, text, text)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.service_principal_create(uuid, text, text)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.service_principal_create(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.service_principal_create(uuid, text, text)
  TO idax_backend;
