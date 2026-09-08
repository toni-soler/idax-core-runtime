-- V77: DB-C2A.5 - narrow atomic tenant display-name update capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29k for the full trace and this gate's report.
--
-- VERSION NOTE: V72-V76 are reserved on remote branch origin/claude/order-alerts-slot-03
-- ("Renumber idax_core alert migrations V61-V65 to V72-V76") - an unrelated, in-progress alerts
-- feature not yet merged to main at the time this migration was authored. V71 remains the latest
-- on main; this migration uses V77 (the first number free of BOTH main and that reserved range)
-- to avoid a future collision when that branch merges, rather than assuming V72 is free.
--
-- GENERAL UPDATE DECOMPOSITION (Phase 1-4): TenantController#update (PUT /api/tenants/{id},
-- superuser-only) -> TenantService#update currently performs, in ONE JPA save(): unconditional
-- existing.setName(tenant.getName()) [no null-guard - omitting/nulling "name" in the request body
-- crashes today with a NOT NULL constraint violation, since name has no Java-side validation
-- either], unconditional existing.setStatus(tenant.getStatus()) [same unguarded pattern, same
-- crash-on-omission], and a null-guarded existing.setMfaRequired(...) [the only genuinely optional
-- field today]. GENERAL TENANT UPDATE ATOMICITY: the single Hibernate flush issues exactly one
-- UPDATE statement for whichever fields are dirty - INSEPARABLE at the SQL-statement level for
-- fields that stay JPA-managed, but there is no real constraint coupling name to status/
-- mfa_required (name and status can each independently violate only their own NOT NULL constraint;
-- mfa_required's Java-side null guard means it never risks a constraint violation) - so extracting
-- ONLY name into its own atomic capability, called from the SAME @Transactional
-- TenantService#update method (same Spring-managed transaction, same physical DB connection/
-- transaction as the still-JPA-managed status/mfa_required write), preserves true all-or-nothing
-- rollback semantics: proven by this gate's own rollback test, which forces the JPA save
-- 's status write to fail (via TODAY's own pre-existing null-status crash) after the name
-- capability has already run, and confirms the name change rolls back with it.
--
-- GENERAL UPDATE STATUS vs V71 (Phase 6): DIFFERENT CONTRACT, not reused. TenantService#update
-- forwards tenant.getStatus() as a raw, unvalidated string (any value, no boolean coercion, no
-- active/disabled mapping) directly to the column; V71's tenant_set_enabled(uuid,boolean) only
-- ever accepts a typed boolean mapped to exactly 'active'/'disabled'. Substituting V71 into the
-- general endpoint would silently narrow what status values a superuser could set via THIS
-- endpoint - not attempted here. Status stays exactly as unconditional JPA passthrough in
-- TenantService#update, unchanged by this migration.
--
-- MFA_REQUIRED (Phase 7-9, DISCOVERY ONLY, NOT IMPLEMENTED): the sole real consumer is
-- LocalAuthService#mustSetUpMfaBeforeAccess, called only from LocalAuthService#login (LOCAL
-- password login). Current contract: a non-superuser user who has NO MFA configured yet AND
-- belongs to at least one tenant with mfa_required=true is forced through MFA SETUP before being
-- issued tokens (blocked at fresh LOCAL login only, gated behind idax.security.mfa.enabled,
-- superusers exempt). It does NOT force re-verification for a user who already has MFA configured
-- (that is the separate, unconditional isMfaActive() challenge path). MFA REQUIRED ENABLED /
-- EXISTING SESSION: NOT REVALIDATED - this check only runs inside a fresh LocalAuthService#login
-- call; LocalAuthService#refresh performs zero database lookups (confirmed at DB-C2A.4), so
-- flipping mfa_required to true has no effect on an already-issued access/refresh token pair -
-- the same systemic "refresh never re-validates" property already found for tenant disable
-- (DB-C2A.4), now corroborated by a second, independent consumer. Recorded, not fixed, not
-- implemented here.
--
-- TENANT DISABLE / SESSION REVALIDATION (carried forward from DB-C2A.4, reconfirmed unchanged by
-- this gate): GAP CONFIRMED - PRE-EXISTING. Not addressed by this migration.
--
-- NAME SEMANTICS (Phase 10): varchar(200) NOT NULL, no Java-side @NotBlank/@Size validation, no
-- uniqueness constraint (only `code` is unique), no trim, case preserved as supplied. Confirmed
-- (by full source search) to have no lifecycle/security side effects anywhere else in the
-- codebase - pure display metadata. Blank ("") is currently permitted (no rejection anywhere) and
-- remains permitted by this capability - only NULL is rejected (the one genuinely required,
-- pre-existing DB constraint), matching the established RAISE-EXCEPTION-for-required-input
-- convention used by every prior capability in this program rather than relying on a raw
-- NOT NULL constraint crash, without adding any NEW validation beyond what already exists today.
--
-- LOST UPDATE (Phase 11): idax_core.tenant carries no @Version/ETag (confirmed at V71).
-- TENANT NAME LOST UPDATE: LAST-WRITER-WINS BY DESIGN - no CAS/version semantics invented.
--
-- AUDIT (Phase 5/23): idax_core.tenant is not excluded from AutomaticFieldChangeAuditListener
-- (V71's own finding). Extracting name out of the JPA-tracked entity means the listener's
-- automatic TENANT_FIELDS_UPDATED event (still fired for status/mfa_required, since those remain
-- JPA-managed) no longer includes "name" in its dirty-field set for a call that changes name too.
-- TenantService#update therefore emits one additional, separate, manually-constructed audit event
-- for the name change alone (same shape as DB-C2A.4's status-change replication), registered
-- after-commit, only when the name actually changed. NAME EXTRACTION AUDIT: PRESERVABLE - no
-- field's change goes unrecorded and none is duplicated; a single update() call that changes both
-- name and status/mfa_required together now produces two coherent, correctly-gated audit events
-- instead of one combined event - a bounded, documented granularity change, not a redesign, and
-- each event's own before/after values remain individually accurate.
--
-- EXECUTION CONTEXT (Phase 20, traced fresh for THIS endpoint, not copied from V71):
-- TenantController#update's @PreAuthorize is superuser-only ("hasAuthority('ROLE_SUPERUSER')",
-- no tenant-admin OR-clause, unlike updateEnabled) - there is no legitimate non-superuser caller
-- of this endpoint at all. Unlike updateEnabled's path shape, PUT /api/tenants/{id} DOES match
-- JwtAuthFilter#extractTenantIdFromPath's "tenants/<next-segment>" pattern exactly (the segment
-- right after "tenants" here IS the tenant id itself), so pathTenantId reliably resolves on every
-- call (Spring's @PathVariable UUID also rejects a non-UUID path segment before the controller is
-- even reached) - TenantContext is therefore reliably established here (Priority 1: path tenant,
-- always allowed), resolving via the uniform isSuperuser() ? IDAX_ADMIN : IDAX_APP rule to
-- **idax_admin** every time for this endpoint's only real caller - unlike DB-C2A.3/DB-C2A.4, this
-- endpoint does NOT carry the bare-idax_backend TenantContext-establishment ambiguity. DIRECT
-- EXECUTE: idax_admin ONLY (no idax_app grant - no real call path reaches this as idax_app).
-- EFFECTIVE EXECUTE: idax_backend via V1's standing membership.
--
-- OWNER PRIVILEGE (Phase 18): idax_capability_owner already holds table-wide SELECT (V70) and
-- column-level UPDATE(status, updated_at) (V71) on idax_core.tenant. This migration adds only
-- UPDATE(name) - the updated_at column privilege already exists from V71 and is reused unmodified,
-- not re-granted. No INSERT, no DELETE.
--
-- DEFAULT PRIVILEGES: function-only migration, no new table/sequence/constraint - PUBLIC-execute-
-- on-create handled by the standard REVOKE ALL ... FROM PUBLIC. DEFAULT PRIVILEGE MODEL: SAFE FOR
-- THIS GATE.

GRANT idax_capability_owner TO CURRENT_USER;

GRANT UPDATE (name) ON idax_core.tenant TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.tenant_update_name(
    p_tenant_id uuid,
    p_name      text
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
    IF p_tenant_id IS NULL THEN
        RAISE EXCEPTION 'tenant_update_name: invalid tenant id' USING ERRCODE = '22023';
    END IF;
    IF p_name IS NULL THEN
        RAISE EXCEPTION 'tenant_update_name: invalid name' USING ERRCODE = '22023';
    END IF;

    UPDATE idax_core.tenant t
    SET name = p_name,
        updated_at = now()
    WHERE t.tenant_id = p_tenant_id
      AND t.name IS DISTINCT FROM p_name;

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

ALTER FUNCTION idax_core.tenant_update_name(uuid, text)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.tenant_update_name(uuid, text)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.tenant_update_name(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.tenant_update_name(uuid, text)
  TO idax_admin;
