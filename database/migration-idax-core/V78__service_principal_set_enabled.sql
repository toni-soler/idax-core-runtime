-- V78: DB-C2A.6 - narrow atomic service-principal enable/disable capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29l for the full trace and this gate's report.
--
-- SERVICE-PRINCIPAL LIFECYCLE DECOMPOSITION (Phase 1/2): idax_core.service_principal (global
-- machine identity: service_principal_id PK, client_id UNIQUE, display_name, enabled,
-- created_at/updated_at), idax_core.service_principal_credential (hashed secrets, multiple rows
-- per principal, active_from/revoked_at lifecycle - overlap/grace period supported by design),
-- idax_core.service_principal_grant (tenant+audience+permissions, RLS-isolated, tenant-scoped),
-- idax_core.service_principal_audit (dedicated append-only audit table). Real operations traced
-- from ServicePrincipalManagementService: create, findByClientId (lookup), addCredential/
-- rotateCredential, revokeCredential, grant, revokeGrant, setEnabled - all called only from
-- ServicePrincipalAdminController (global, superuser-only, no tenant path) or
-- TenantServicePrincipalGrantAdminController (tenant-scoped, grant/revokeGrant only).
--
-- MANAGEMENT vs AUTHENTICATION PLANE (Phase 3): cleanly separated in the existing code.
-- ServiceTokenIssuer (authentication plane) is a wholly separate class with its own
-- SET LOCAL ROLE idax_service_auth and its own credential/grant verification - untouched by this
-- migration. This capability touches only idax_core.service_principal.enabled, never credentials
-- or grants, preserving that separation exactly.
--
-- SELECTED SUB-SLICE: SERVICE_PRINCIPAL_SET_ENABLED (targets
-- ServicePrincipalManagementService#setEnabled). WHY: narrowest field (one boolean), zero secret
-- material touched, fully global (no tenant/grant complexity), single-entity transaction, and the
-- existing ServicePrincipalAuditLogger#record call is an explicit, persistence-mechanism-agnostic
-- Java method call (not Hibernate-listener-driven) - it requires no special replication, unlike
-- every prior DB-C2A capability's audit story. DEFERRED: create, findByClientId, addCredential/
-- rotateCredential, revokeCredential, grant, revokeGrant - all out of scope this gate.
--
-- AUTHORITATIVE SERVICE-PRINCIPAL KEY (Phase 6): service_principal_id (the table's own primary
-- key, and what every internal call site - including the controller's own @PathVariable UUID id -
-- actually targets). client_id is a separate, independently-unique secondary lookup key (used only
-- by the deferred findByClientId operation) - not assumed to be the operation's own targeting key.
--
-- AUTHORIZATION (Phase 8): unchanged, entirely Java-side -
-- @PreAuthorize("hasAuthority('ROLE_SUPERUSER')") at ServicePrincipalAdminController class level
-- (POST /api/admin/service-principals/{id}/enabled/{enabled}) - no role/permission string passed
-- into SQL.
--
-- EXECUTION CONTEXT (Phase 9, traced fresh, empirically verified - not by analogy):
-- ServicePrincipalAdminController's path (/api/admin/service-principals/...) contains no "tenants"
-- segment (JwtAuthFilter#extractTenantIdFromPath never matches it) and is NOT on
-- JwtAuthFilter's X-Tenant-header-allowed prefix list (an X-Tenant header sent to this endpoint is
-- rejected outright with 400) - and superuser JWTs never carry a tenantId claim (confirmed
-- repeatedly across this program). This means TenantContext is NEVER established for ANY of
-- ServicePrincipalAdminController's five operations - RlsTransactionAspect's own "if TenantContext
-- is null, apply nothing" rule leaves the connection at bare idax_backend for the entire call.
--
-- IMPORTANT CORRECTION, verified empirically this gate (a test initially written to reproduce an
-- assumed privilege gap for bare idax_backend did NOT reproduce it - investigated rather than
-- dismissed): idax_backend's own role definition (V1, `CREATE ROLE idax_backend;`) carries no
-- NOINHERIT clause, so it defaults to PostgreSQL's own INHERIT default. Per PostgreSQL role
-- semantics, whether a member role automatically uses a group role's privileges is governed by the
-- MEMBER's own INHERIT/NOINHERIT attribute, not the group role's - idax_admin/idax_app being
-- NOINHERIT only constrains their own further upward inheritance, not what idax_backend (their
-- member) inherits from them. idax_backend is therefore a standing, INHERIT member of idax_admin
-- (V1) and idax_service_auth (V51), and automatically, continuously has EFFECTIVE use of
-- everything directly granted to idax_admin - including V51's own
-- `GRANT SELECT, INSERT, UPDATE ON idax_core.service_principal TO idax_admin` - with NO SET ROLE
-- needed at all. Confirmed directly by test: a raw UPDATE on idax_core.service_principal under
-- `SET LOCAL ROLE idax_backend` (no further role switch) succeeds today. **No correctness bug
-- exists** - ServicePrincipalManagementService#setEnabled already works correctly under real
-- production privilege constraints today, via this automatic inheritance path. This corrects an
-- imprecise framing used informally in some earlier DB-C2A gate narration ("bare idax_backend has
-- zero privilege without SET ROLE") - true only for tables/functions where idax_admin/idax_app
-- themselves hold no grant either; it does not invalidate any prior gate's actual GRANT
-- statements, which remain correct regardless of this nomenclature clarification.
--
-- **DIRECT EXECUTE: idax_admin** (matching V51's own direct-grant target for this exact table -
-- the established, consistent choice). **EFFECTIVE EXECUTE: idax_backend**, automatically, via its
-- standing INHERIT membership in idax_admin - no SET ROLE required, proven by test. idax_app is
-- NOT granted: V51 deliberately revoked idax_app's own default-inherited access to this table
-- ("SERVICE credentials and lifecycle state are not ordinary application data") and this
-- migration preserves that exclusion.
--
-- SERVICE PRINCIPAL DISABLE / EXISTING TOKEN (Phase 13, traced precisely, not ambiguous): unlike
-- the still-unresolved tenant-disable/mfa_required session-revalidation gaps, ServiceTokenIssuer
-- re-checks ServicePrincipal.isEnabled() on EVERY token issuance (no refresh-token mechanism
-- exists for service-principal tokens at all in this codebase - each short-lived JWT must be
-- re-issued via a fresh issue() call, which re-validates enabled + credential effectiveness +
-- grant effectiveness + tenant active status, all four, every time). Disabling therefore blocks
-- NEW token issuance immediately and has no indefinite-bypass path; an already-issued token
-- remains valid only until its own natural (short) JWT expiry, exactly as any stateless JWT
-- design implies - a materially safer, already-well-understood property, not a repeat of the
-- earlier ambiguous findings. No STOP triggered.
--
-- AUDIT (Phase 17): ServicePrincipalAuditLogger#record is an explicit Java method call
-- (@Transactional(REQUIRES_NEW), its own internal SET LOCAL ROLE idax_service_auth) - not
-- Hibernate-PostUpdateEvent-driven, so it requires no special replication when the underlying
-- ServicePrincipal write moves off JPA. TenantService's audit-listener-bypass problem (DB-C2A.4/
-- .5) does not apply here at all - ServicePrincipalManagementService#setEnabled keeps its existing
-- audit.record(...) call completely unchanged.
--
-- CONCURRENCY (Phase 18): idax_core.service_principal carries no @Version - last-writer-wins by
-- design, matching every prior DB-C2A status-toggle finding (TENANT_SET_ENABLED, V71). The
-- `enabled IS DISTINCT FROM p_enabled` no-op guard avoids an unnecessary updated_at bump/audit
-- trigger for a redundant call, mirroring V71's own established pattern exactly.
--
-- OWNER PRIVILEGE (Phase 22): idax_capability_owner holds ZERO privilege on
-- idax_core.service_principal today (checked directly - only V51's grants to idax_admin/
-- idax_service_auth exist). This migration adds table-wide SELECT (every returned column is
-- genuinely needed) and column-level UPDATE(enabled, updated_at) only. No INSERT, no DELETE.
--
-- DEFAULT PRIVILEGES (Phase 25): function-only migration, no new table/sequence/constraint -
-- PUBLIC-execute-on-create handled by the standard REVOKE ALL ... FROM PUBLIC.
-- DEFAULT PRIVILEGE MODEL: SAFE FOR THIS GATE.
--
-- PRE-FIX CLASSIFICATION (Phase 26): PRIVILEGE-HARDENING. No correctness or security bug exists
-- in the operation being migrated (see the EXECUTION CONTEXT correction above) - this replaces an
-- already-working, but overly broad, direct table UPDATE (reachable via idax_admin's full
-- SELECT/INSERT/UPDATE on the whole table) with a narrow, single-column, SECURITY DEFINER
-- capability, exactly matching every other DB-C2A privilege-hardening gate's classification.

GRANT idax_capability_owner TO CURRENT_USER;

GRANT SELECT ON idax_core.service_principal TO idax_capability_owner;
GRANT UPDATE (enabled, updated_at) ON idax_core.service_principal TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.service_principal_set_enabled(
    p_service_principal_id uuid,
    p_enabled              boolean
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
        RAISE EXCEPTION 'service_principal_set_enabled: invalid service principal id' USING ERRCODE = '22023';
    END IF;
    IF p_enabled IS NULL THEN
        RAISE EXCEPTION 'service_principal_set_enabled: invalid enabled value' USING ERRCODE = '22023';
    END IF;

    UPDATE idax_core.service_principal sp
    SET enabled = p_enabled,
        updated_at = now()
    WHERE sp.service_principal_id = p_service_principal_id
      AND sp.enabled IS DISTINCT FROM p_enabled;

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

ALTER FUNCTION idax_core.service_principal_set_enabled(uuid, boolean)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.service_principal_set_enabled(uuid, boolean)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.service_principal_set_enabled(uuid, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.service_principal_set_enabled(uuid, boolean)
  TO idax_admin;
