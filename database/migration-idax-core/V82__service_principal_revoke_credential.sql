-- V82: DB-C2A.9 - narrow atomic SERVICE_PRINCIPAL_REVOKE_CREDENTIAL capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md section 29p for the full trace and this gate's report.
--
-- REVOKE TRACED EXACTLY (Phase 1, fresh): ServicePrincipalAdminController#revokeCredential (DELETE
-- /api/admin/service-principals/{id}/credentials/{credentialId}, class-level ROLE_SUPERUSER, no
-- tenant path) -> ServicePrincipalManagementService#revokeCredential. Prior exact algorithm:
-- credentials.findById(credentialId).orElseThrow() (throws NoSuchElementException -> 404 if
-- unknown); c.setRevokedAt(OffsetDateTime.now()) (JPA dirty-checked, no explicit save() call
-- needed - flushed at commit); principals.findById(c.getServicePrincipalId()).orElseThrow() (looks
-- up the OWNING principal FROM THE CREDENTIAL'S OWN FK, never from the path); audit.record(...)
-- using that FK-derived principal.
--
-- PARENT/TARGET BINDING FINDING (Phase 2/3, PRIMARY SECURITY REVIEW - already flagged in this
-- document's own capability matrix, section 7/16, as a "G/security review" item; this gate
-- resolves it): the controller's path {id} (intended service principal) was NEVER passed to the
-- service method at all - only {credentialId} was used. CROSS-PRINCIPAL CREDENTIAL REVOCATION
-- (pre-fix): ALLOWED - DELETE .../service-principals/<ANY_UUID>/credentials/<realCredentialId>
-- succeeded regardless of whether <ANY_UUID> matched the credential's real owning principal, as
-- long as the credential existed. CLASSIFICATION: API CONSISTENCY / LATENT AUTHORIZATION-SCOPING
-- DEFECT, NOT a currently-exploitable IDOR - re-verified from the real authorization model:
-- ServicePrincipalAdminController is superuser-only with NO per-principal-scoped ROLE_SUPERUSER
-- variant anywhere in this codebase (a functional superuser is either fully authorized for every
-- principal or not authorized at all), so no real actor "authorized for A" but "not authorized for
-- B" exists today to exploit this gap - a superuser could already reach B's credential directly via
-- the correct URL. It is nonetheless a genuine correctness/defense-in-depth defect: the URL's own
-- REST hierarchy semantics, the table's own NOT NULL FK modeling exactly one owning principal per
-- credential, and this exact class's OWN sibling method (revokeGrant, which DOES filter
-- `x.getServicePrincipalId().equals(principalId)`) all establish that the parent id is intended to
-- be authoritative here too - this was an isolated oversight in revokeCredential alone, not a
-- deliberate "principal id is decorative" design choice. RESOLVED TARGET INVARIANT (Phase 4):
-- credential_id = C AND service_principal_id = P, enforced atomically in a single WHERE clause -
-- matching revokeGrant's own established pattern. URL SHAPE UNCHANGED (Phase 5): {id} and
-- {credentialId} both remain in the route; {id} is now genuinely wired through instead of dropped.
--
-- WRONG-PARENT / UNKNOWN-CREDENTIAL UNIFICATION (Phase 10/11): both cases now produce the exact
-- same observable outcome - zero rows match `WHERE credential_id = ? AND service_principal_id = ?`
-- - collapsed into one generic "no matching credential for this service principal" 404, with no
-- distinguishing detail that would let a caller learn whether the credential exists at all, let
-- alone which principal actually owns it. No credential metadata, owning principal, or hash is ever
-- revealed for a mismatch.
--
-- CREDENTIAL MODEL (Phase 6): idax_core.service_principal_credential (V51) - credential_id (PK),
-- service_principal_id (FK NOT NULL REFERENCES service_principal), secret_hash (TEXT NOT NULL),
-- active_from (NOT NULL DEFAULT now()), revoked_at (nullable), created_at (NOT NULL DEFAULT now()),
-- created_by (varchar 200). No expires_at, no version column. This operation READS
-- credential_id/service_principal_id (WHERE match) and revoked_at (return projection only); WRITES
-- revoked_at only. secret_hash/active_from/created_at/created_by are never read or written by this
-- capability.
--
-- SECRET BOUNDARY (Phase 7): no plaintext secret, no secret generation, no hashing, no comparison.
-- secret_hash is never selected, granted, returned, or logged by this capability.
--
-- REVOKE SEMANTICS (Phase 8/9): revoked_at = now() (DB-authoritative, Phase 20) - never physical
-- deletion. ALREADY-REVOKED BEHAVIOR PRESERVED EXACTLY, not converted to a no-op: calling revoke
-- again on an already-revoked credential (matching the correct principal) succeeds again, moves
-- revoked_at forward to a new now(), and produces a second SUCCESS audit event - identical to
-- today's actual JPA behavior (no `IS DISTINCT FROM` guard is introduced, unlike SET_ENABLED's own
-- different, deliberate no-op design). This is not a security or correctness defect - a credential
-- with any non-null revoked_at in the past is already permanently excluded from
-- ServicePrincipalCredential#isEffective() regardless of the exact timestamp value, so re-revoking
-- cannot un-revoke or otherwise change effective authentication behavior.
--
-- NEW TOKEN ISSUANCE (Phase 14): BLOCKED IMMEDIATELY upon commit - ServiceTokenIssuer#issue
-- performs a live credentials.findByServicePrincipalId(...) read on every call and filters by
-- isEffective(now()), which becomes false the instant revoked_at is committed in the past. Proven
-- fresh by this gate's own dedicated authenticate-vs-revoke test.
--
-- EXISTING TOKEN (Phase 15, PRE-EXISTING, NOT ADDRESSED HERE): ServiceTokenValidator performs
-- PURELY STATELESS JWT validation (issuer/principal_type/audience/expiry/jti checks against the
-- decoded JWT claims only) - zero database lookup on any resource-server request. An
-- already-issued service token therefore remains valid until its own natural (short) JWT expiry
-- even after its originating credential is revoked - the exact same systemic "no per-request
-- revalidation" property already documented for LOCAL user sessions (tenant-disable,
-- mfa_required) and for service-principal disable (DB-C2A.6). Recorded as separate, pre-existing
-- Auth/session policy debt - not fixed, not redesigned by this gate.
--
-- ROTATION / OTHER-CREDENTIAL BOUNDARY (Phase 16): the atomic WHERE clause touches exactly the one
-- (credential_id, service_principal_id) pair - proven by this gate's own cross-credential negative
-- proof that a sibling credential for the same principal, and any credential for a different
-- principal, are provably untouched, and that service_principal.enabled and grant rows are
-- unaffected.
--
-- EXECUTION CONTEXT (Phase 13, re-traced fresh, not assumed from sibling endpoints): DELETE
-- .../service-principals/{id}/credentials/{credentialId} carries no "tenants" path segment;
-- TenantContext is never established. **ACTUAL CALLER: idax_backend** (bare), exactly matching
-- every other operation on this same controller. Today, idax_backend's UPDATE on this table is
-- EFFECTIVE ONLY via its standing membership in idax_admin (V51: `GRANT SELECT, INSERT, UPDATE ON
-- idax_core.service_principal_credential TO idax_admin`). Per the permanent grantee rule, this
-- migration grants idax_backend DIRECT EXECUTE from inception. idax_admin receives nothing (no
-- genuine caller); idax_app/idax_service_auth receive nothing (no caller for either).
--
-- OWNER PRIVILEGE (Phase 21/22, minimized precisely): idax_capability_owner currently holds ZERO
-- privilege on service_principal_credential (DB-C2A.8's own finding, reconfirmed). This migration
-- grants exactly SELECT(credential_id, service_principal_id, revoked_at) - the three columns
-- genuinely referenced by this function's WHERE clause and RETURN QUERY projection, never
-- table-wide SELECT - and UPDATE(revoked_at) only. No INSERT, no DELETE. No privilege whatsoever on
-- service_principal, service_principal_grant, or service_principal_audit (Phase 33: the parent
-- binding is enforced solely via the credential's own FK column - service_principal itself is never
-- read by this capability).
--
-- OUTPUT PROJECTION (Phase 19): credential_id, service_principal_id, revoked_at only - no secret
-- hash, no other credentials, no grants, no full principal row.
--
-- PRE-FIX CLASSIFICATION: mixed. The underlying UPDATE mechanism itself is PRIVILEGE-HARDENING
-- (narrowing an already-working, overly broad direct table UPDATE to column-scoped SECURITY
-- DEFINER access) exactly like every prior DB-C2A.6-family capability; the parent-binding
-- enforcement is a genuine CORRECTNESS FIX for the latent authorization-scoping defect described
-- above, closed by this same migration rather than deferred.

GRANT idax_capability_owner TO CURRENT_USER;

GRANT SELECT (credential_id, service_principal_id, revoked_at)
  ON idax_core.service_principal_credential TO idax_capability_owner;
GRANT UPDATE (revoked_at)
  ON idax_core.service_principal_credential TO idax_capability_owner;

CREATE OR REPLACE FUNCTION idax_core.service_principal_revoke_credential(
    p_service_principal_id uuid,
    p_credential_id        uuid
)
RETURNS TABLE (
    credential_id         uuid,
    service_principal_id  uuid,
    revoked_at             timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
    IF p_service_principal_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_revoke_credential: invalid service principal id' USING ERRCODE = '22023';
    END IF;
    IF p_credential_id IS NULL THEN
        RAISE EXCEPTION 'service_principal_revoke_credential: invalid credential id' USING ERRCODE = '22023';
    END IF;

    -- Atomic exact-target transition: a credential belonging to a DIFFERENT principal, or a
    -- credential that does not exist at all, both match zero rows here - the caller cannot
    -- distinguish "unknown" from "wrong parent" from this function's behavior alone.
    UPDATE idax_core.service_principal_credential spc
    SET revoked_at = now()
    WHERE spc.credential_id = p_credential_id
      AND spc.service_principal_id = p_service_principal_id;

    RETURN QUERY
    SELECT spc.credential_id,
           spc.service_principal_id,
           spc.revoked_at
    FROM idax_core.service_principal_credential spc
    WHERE spc.credential_id = p_credential_id
      AND spc.service_principal_id = p_service_principal_id;
END;
$function$;

ALTER FUNCTION idax_core.service_principal_revoke_credential(uuid, uuid)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.service_principal_revoke_credential(uuid, uuid)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.service_principal_revoke_credential(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.service_principal_revoke_credential(uuid, uuid)
  TO idax_backend;
