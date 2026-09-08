-- V80: DB-C2A.7 - narrow SERVICE_PRINCIPAL_LOOKUP_BY_CLIENT_ID read-only capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29n for the full trace and this gate's report.
--
-- CALLERS TRACED (Phase 1, fresh full source search, exactly two production call sites of
-- ServicePrincipalRepository#findByClientId - a plain JPA WHERE client_id = ? derived query):
--
-- 1. MANAGEMENT: ServicePrincipalAdminController#findByClientId
--    (GET /api/admin/service-principals/by-client-id/{clientId}, class-level
--    @PreAuthorize("hasAuthority('ROLE_SUPERUSER')"), no "tenants" path segment) ->
--    ServicePrincipalManagementService#findByClientId. Consumer: scripts/register-service-principal.sh,
--    an idempotent onboarding tool that re-looks-up an already-existing clientId (HTTP 409 on create)
--    to recover its service_principal_id without rotating its credential. Consumes: id, and the
--    endpoint returns the same 6-column non-secret shape the sibling create() endpoint already
--    returns. TenantContext is never established for this controller (reconfirmed exactly as in
--    DB-C2A.6/.6a - no "tenants" path segment, not on JwtAuthFilter's X-Tenant allowlist, superuser
--    JWTs carry no tenantId claim) - RlsTransactionAspect#aroundTransactional therefore does nothing
--    (ctx == null branch), leaving the connection at bare idax_backend for the whole call. No
--    genuine idax_admin execution path exists for this controller (re-verified this gate, matching
--    DB-C2A.6a's own finding for the sibling setEnabled endpoint on the same controller).
--
-- 2. AUTHENTICATION: ServiceTokenIssuer#issue -> principals.findByClientId(request.clientId())
--    .filter(ServicePrincipal::isEnabled). Runs under an EXPLICIT `SET LOCAL ROLE idax_service_auth`
--    (issued at the top of issue(), before this lookup) - a genuinely different, already-correct
--    (DIRECT, not inherited) execution role, unrelated to the management path above. Consumes:
--    id (later used for the credential/grant queries, run as separate JPA calls, unchanged by this
--    migration), enabled (as an authentication gate, via .filter(...)), clientId (embedded in the
--    issued JWT's "client_id" claim). Credential data is loaded by a SEPARATE query
--    (credentials.findByServicePrincipalId(principal.getId())) - never joined here, never touched by
--    this capability.
--
-- MANAGEMENT VS AUTHENTICATION BOUNDARY (Phase 2): BOTH planes call this lookup, but both consume
-- only the same non-secret 6-column projection of idax_core.service_principal (the table itself
-- carries no credential/grant data - those live in separate tables entirely, joined by neither
-- caller). Their needs do not actually differ enough to justify two separate contracts: management
-- returns all 6 columns (matching the sibling create()/setEnabled() endpoints' response shape
-- exactly, for admin-tooling consistency), and authentication merely uses a subset (id/enabled/
-- clientId) of that same already-non-sensitive projection - returning the unused extra columns
-- (display_name/created_at/updated_at) to the authentication code path exposes nothing it doesn't
-- already see today via the full JPA entity it currently loads. ONE shared capability is selected;
-- unknown-client-id and disabled-principal interpretation remain entirely Java-side per plane
-- (Phase 9): management surfaces HTTP 404 (ResponseStatusException) for "no such client_id";
-- authentication collapses "no such client_id" and "wrong secret" into the same generic
-- ServiceAuthenticationException (deliberately, to avoid a client-id-existence oracle) - this
-- migration changes neither behavior, both remain caller-side interpretations of the same
-- zero-or-one-row result.
--
-- AUTHORITATIVE KEY (Phase 3, reconfirmed from schema): idax_core.service_principal.client_id
-- carries a genuine table-level UNIQUE constraint (V51: `client_id VARCHAR(120) NOT NULL UNIQUE`) -
-- not merely an application-level assumption. service_principal_id (the PK) remains the canonical
-- internal identity, exactly as DB-C2A.6 established; client_id is confirmed here as a true,
-- DB-enforced secondary unique lookup key, so this function's result is guaranteed at most one row
-- without needing V68's ambiguity-count-check pattern (idax_core.app_user.email carries no such
-- constraint - client_id genuinely does).
--
-- NORMALIZATION (Phase 4): current JPA derived query compiles to an exact `WHERE client_id = ?`
-- (case-sensitive, no trim/lower/collation override anywhere in the codebase - confirmed by source
-- search of ServicePrincipalManagementService#create, the only writer of this column). This function
-- preserves that exact behavior: no LOWER()/TRIM()/ILIKE introduced.
--
-- OUTPUT PROJECTION (Phase 5/14): service_principal_id, client_id, display_name, enabled,
-- created_at, updated_at - the table's own full non-secret column set (6 columns, no more exist on
-- this table). No secret_hash, no credential_id, no revocation state, no grant rows, no permissions -
-- those live on entirely separate tables (service_principal_credential/service_principal_grant),
-- never joined here.
--
-- SELECTED CAPABILITY (Phase 13): idax_core.service_principal_lookup_by_client_id(text) - a plain,
-- single-purpose, operation-specific name (not a generic service_principal_lookup(...) dispatcher).
--
-- EXISTING CAPABILITIES CONSIDERED (Phase 12): only idax_core.service_principal_set_enabled(uuid,
-- boolean) (V78) exists in this domain - a write capability, unrelated shape, not reusable for a
-- read-by-client-id lookup. No existing narrow read capability for this table exists yet.
--
-- DIRECT GRANTEES (Phase 10, permanent grantee rule from DB-C2A.6a - "operation genuinely spanning
-- both -> both DIRECT"): idax_backend (the real, sole management caller - pre-tenant-only, exactly
-- as re-verified above) AND idax_service_auth (the real, sole authentication caller, already
-- executing under an explicit SET LOCAL ROLE before this call). idax_admin is granted NOTHING - no
-- genuine idax_admin execution path exists for either caller (re-verified by fresh source search
-- this gate, not assumed from any prior gate's conclusion). idax_app is granted NOTHING - no
-- tenant-scoped caller of this lookup exists.
--
-- OWNER PRIVILEGE (Phase 17, verified not assumed): idax_capability_owner already holds table-wide
-- SELECT on idax_core.service_principal, granted at V78 (DB-C2A.6) and unmodified since (checked
-- directly: no REVOKE of it exists in V79). This migration therefore requires ZERO new owner
-- privilege - it reuses that existing SELECT grant as-is, adding no INSERT/UPDATE/DELETE and no
-- access to any other table.
--
-- JAVA CHANGES (Phase 19/20): both ServiceTokenIssuer#issue and
-- ServicePrincipalManagementService#findByClientId are updated to call a new narrow typed JDBC
-- adapter (ServicePrincipalLookupByClientIdRepository) instead of the JPA derived query. This was
-- the ONLY production use of ServicePrincipalRepository#findByClientId (confirmed by a full source
-- search before authoring this migration) - the JPA method itself becomes unused and is removed
-- from ServicePrincipalRepository, matching V68's own precedent for AppUserRepository#findByEmail.
--
-- CREDENTIAL/GRANT/AUDIT INVARIANT (Phase 28): this migration touches no privilege on
-- service_principal_credential, service_principal_grant, or service_principal_audit - only
-- idax_core.service_principal (SELECT only, already granted) and the new function's own EXECUTE
-- grants. ServiceTokenIssuer's own credential/grant verification queries and
-- ServicePrincipalAuditLogger's audit write are entirely unchanged by this migration.
--
-- PRE-FIX CLASSIFICATION (Phase 22): PRIVILEGE-HARDENING / PUBLIC ARCHITECTURE. No correctness,
-- enumeration, ambiguity, or security bug exists in either existing call site - this replaces two
-- already-working JPA full-table-entity reads (each already running under an appropriately narrow
-- role - idax_backend's own effective SELECT via inheritance for management, idax_service_auth's own
-- DIRECT SELECT for authentication) with one narrow, SECURITY DEFINER, minimal-projection capability,
-- and - for the management path specifically - upgrades its execution model from relying on
-- idax_backend's incidental inheritance (via idax_admin and/or idax_service_auth) to a genuine DIRECT
-- grant, matching the permanent grantee rule established by DB-C2A.6a.

GRANT idax_capability_owner TO CURRENT_USER;

CREATE OR REPLACE FUNCTION idax_core.service_principal_lookup_by_client_id(p_client_id text)
RETURNS TABLE (
    service_principal_id uuid,
    client_id             text,
    display_name          text,
    enabled                boolean,
    created_at             timestamptz,
    updated_at             timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
BEGIN
    IF p_client_id IS NULL OR p_client_id = '' THEN
        RAISE EXCEPTION 'service_principal_lookup_by_client_id: invalid client id' USING ERRCODE = '22023';
    END IF;

    -- idax_core.service_principal.client_id/display_name are varchar(n); PL/pgSQL's RETURN QUERY
    -- requires an exact type match against RETURNS TABLE (unlike a plain top-level SELECT) - explicit
    -- casts avoid "structure of query does not match function result type" (DB-C2A.1 lesson).
    RETURN QUERY
    SELECT sp.service_principal_id,
           sp.client_id::text,
           sp.display_name::text,
           sp.enabled,
           sp.created_at,
           sp.updated_at
    FROM idax_core.service_principal sp
    WHERE sp.client_id = p_client_id;
END;
$function$;

ALTER FUNCTION idax_core.service_principal_lookup_by_client_id(text)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.service_principal_lookup_by_client_id(text)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.service_principal_lookup_by_client_id(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.service_principal_lookup_by_client_id(text)
  TO idax_backend, idax_service_auth;
