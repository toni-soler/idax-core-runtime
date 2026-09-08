-- V55: DB-C1A.2 - narrow Auth rate-limit capability
--
-- See DATABASE_PRIVILEGED_CAPABILITIES.md (binding architecture) and AuthRateLimiterService,
-- the single centralized anti-bruteforce mechanism shared by every "guess a short secret"
-- LOCAL-provider endpoint: /api/auth/login ("login:<username>"), /api/auth/mfa/verify
-- ("mfa:<userId>"), MFA setup activation ("mfa-setup:<userId>") and MFA self-service
-- reauth ("mfa-manage:<userId>"). Traced exactly from the real Java implementation before
-- this migration was written - see the DB-C1A.2 gate report for the full semantics trace.
--
-- This introduces three narrow, typed, SECURITY DEFINER capability functions that replace
-- AuthRateLimitBucketRepository's direct JPA access to idax_core.auth_rate_limit_bucket for
-- this one bounded purpose, mirroring exactly: checkAllowed (read-only), registerFailure
-- (atomic upsert + threshold/lockout logic), registerSuccess (exact-key delete). No wildcard,
-- prefix or bulk operation is possible - every function takes one exact throttle_key.
--
-- Time authority: all "now" comparisons and lockout timestamps are computed with PostgreSQL's
-- own now() (frozen for the whole transaction, same value used consistently across the
-- attempt-count/lockout decision in one call - matching the current Java implementation's single
-- captured Instant per operation). No caller-supplied timestamp parameter exists in any function:
-- a compromised Auth runtime that can call these functions cannot manufacture, shorten or bypass
-- a lockout by passing a crafted "now", because "now" is never an input.
--
-- Grantee model: unlike DB-C1A.1's auth_local_identity_lookup (EXECUTE granted only to
-- idax_backend, since the LOCAL login lookup always runs pre-tenant with no SET LOCAL ROLE
-- applied), this capability is genuinely called under three different active roles depending on
-- call site: bare idax_backend for the two pre-tenant flows (login/mfa-verify, before any
-- TenantContext exists), idax_app for an ordinary authenticated single-tenant user's self-service
-- MFA setup/manage calls (TenantContext already established by JwtAuthFilter for that request -
-- via the JWT's tenantId claim for a single-tenant user, or via the X-Tenant header, which
-- JwtAuthFilter explicitly allows on /api/me/** paths), and idax_admin for a superuser exercising
-- the same self-service endpoints while an effective tenant is resolved - today unavoidable
-- because JwtAuthFilter/TenantContextFilter still select IDAX_ADMIN for any superuser request
-- with an effective tenant, regardless of the endpoint (INCIDENTAL SUPERUSER DB ELEVATION, see
-- DATABASE_PRIVILEGED_CAPABILITIES.md). idax_admin EXECUTE here is explicitly TRANSITIONAL: DB-C1B
-- (make HTTP always idax_app) must revisit these grants and remove idax_admin EXECUTE once
-- superusers no longer select it for ordinary authenticated requests. EXECUTE is granted to all
-- three now so no currently-working call path regresses.
--
-- Existing broad grants on idax_core.auth_rate_limit_bucket (idax_app/idax_admin CRUD from V1's
-- default privileges) are deliberately left untouched for compatibility/rollback, matching the
-- DB-C1A.1 precedent - only the Java call site changes in this increment.

GRANT SELECT, INSERT, UPDATE, DELETE ON idax_core.auth_rate_limit_bucket TO idax_capability_owner;

-- Ownership transfer below requires the migration role to be a member of the owner role. V54
-- already granted this for the same migration identity in the common case, but re-issuing here
-- keeps this migration self-contained if it ever runs in a different session.
GRANT idax_capability_owner TO CURRENT_USER;

-- ============================================================================
-- auth_rate_limit_check: read-only, exact-key lookup. Mirrors
-- AuthRateLimiterService#checkAllowed exactly - an unknown key or a row whose locked_until has
-- already passed is "allowed" with no mutation; only a currently-locked row rejects.
-- ============================================================================
CREATE OR REPLACE FUNCTION idax_core.auth_rate_limit_check(p_key text)
RETURNS TABLE (allowed boolean, locked_until timestamptz)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $function$
DECLARE
    v_locked_until timestamptz;
BEGIN
    IF p_key IS NULL OR length(p_key) = 0 OR length(p_key) > 200 THEN
        RAISE EXCEPTION 'auth_rate_limit_check: invalid throttle key' USING ERRCODE = '22023';
    END IF;

    SELECT b.locked_until INTO v_locked_until
    FROM idax_core.auth_rate_limit_bucket b
    WHERE b.throttle_key = p_key;

    allowed := (v_locked_until IS NULL OR v_locked_until <= now());
    locked_until := v_locked_until;
    RETURN NEXT;
END;
$function$;

ALTER FUNCTION idax_core.auth_rate_limit_check(text) SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_rate_limit_check(text) OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_rate_limit_check(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_rate_limit_check(text) TO idax_backend, idax_app, idax_admin;

-- ============================================================================
-- auth_rate_limit_register_failure: atomic upsert + threshold/lockout transition. Mirrors
-- AuthRateLimiterService#registerFailure exactly, including its ">=" threshold comparison and
-- resetting attempt_count/window_started_at to the lockout moment when the threshold is crossed.
-- max_attempts/lockout_seconds are trusted server configuration (MfaProperties.RateLimit), never
-- user input. Validation here is deliberately limited to NOT NULL and strictly positive - the
-- exact contract MfaProperties.RateLimit's own compact constructor already enforces (a
-- non-positive configured value is defaulted to 5 attempts / 300 seconds before it would ever
-- reach this function), so this is a faithful narrowing, not a new restriction. Earlier drafts of
-- this migration added upper bounds (1,000,000 attempts / 31,536,000 seconds); those were found
-- to be NEW ARBITRARY LIMITS with no basis in the Java configuration contract (int/long, no
-- @Max/upper-bound anywhere), PostgreSQL's own `integer` parameter type (which already rejects
-- anything outside +/-2^31-1 at the binding level - no explicit check can add safety a SQL type
-- doesn't already provide), or documented policy, so they were removed rather than kept as
-- "defense in depth". p_lockout_seconds is `integer` (not the Java-side `long`) specifically
-- because AuthRateLimitCapabilityJdbcRepository narrows it with Math.toIntExact before binding -
-- that throws on the Java side for any configured value PostgreSQL's own type could not represent
-- either, so no additional SQL-side ceiling is reachable dead code.
--
-- Race-safe by construction: the increment is a single atomic "INSERT ... ON CONFLICT DO UPDATE"
-- statement, which PostgreSQL guarantees has no check-then-act window - unlike a separate
-- "INSERT ... ON CONFLICT DO NOTHING" followed by "SELECT ... FOR UPDATE", which was tried first
-- and rejected: a concurrent auth_rate_limit_clear_success on the same *existing* key could delete
-- the row between those two statements, making the later SELECT ... FOR UPDATE observe zero rows
-- and silently drop the failure. The single upsert statement below cannot lose a concurrent
-- failure this way, and the row lock it takes is held for the rest of this transaction, so the
-- second UPDATE (only reached when the threshold is crossed) can never race with a concurrent
-- clear either.
-- ============================================================================
CREATE OR REPLACE FUNCTION idax_core.auth_rate_limit_register_failure(
    p_key text,
    p_max_attempts integer,
    p_lockout_seconds integer
)
RETURNS TABLE (locked boolean, attempt_count integer, locked_until timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_now timestamptz := now();
    v_next_count integer;
    v_locked_until timestamptz;
BEGIN
    IF p_key IS NULL OR length(p_key) = 0 OR length(p_key) > 200 THEN
        RAISE EXCEPTION 'auth_rate_limit_register_failure: invalid throttle key' USING ERRCODE = '22023';
    END IF;
    IF p_max_attempts IS NULL OR p_max_attempts <= 0 THEN
        RAISE EXCEPTION 'auth_rate_limit_register_failure: invalid max attempts' USING ERRCODE = '22023';
    END IF;
    IF p_lockout_seconds IS NULL OR p_lockout_seconds <= 0 THEN
        RAISE EXCEPTION 'auth_rate_limit_register_failure: invalid lockout seconds' USING ERRCODE = '22023';
    END IF;

    INSERT INTO idax_core.auth_rate_limit_bucket AS b (throttle_key, attempt_count, window_started_at)
    VALUES (p_key, 1, v_now)
    ON CONFLICT (throttle_key) DO UPDATE
        SET attempt_count = b.attempt_count + 1
    RETURNING b.attempt_count INTO v_next_count;

    IF v_next_count >= p_max_attempts THEN
        v_locked_until := v_now + make_interval(secs => p_lockout_seconds);

        UPDATE idax_core.auth_rate_limit_bucket b
        SET attempt_count = 0,
            locked_until = v_locked_until,
            window_started_at = v_now
        WHERE b.throttle_key = p_key;

        locked := true;
        attempt_count := 0;
        locked_until := v_locked_until;
    ELSE
        locked := false;
        attempt_count := v_next_count;
        locked_until := NULL;
    END IF;

    RETURN NEXT;
END;
$function$;

ALTER FUNCTION idax_core.auth_rate_limit_register_failure(text, integer, integer)
  SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_rate_limit_register_failure(text, integer, integer)
  OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_rate_limit_register_failure(text, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_rate_limit_register_failure(text, integer, integer)
  TO idax_backend, idax_app, idax_admin;

-- ============================================================================
-- auth_rate_limit_clear_success: exact-key delete. Mirrors AuthRateLimiterService#registerSuccess
-- exactly (deletes the whole bucket row on success; a no-op, not an error, if none existed).
-- Returns whether a row actually existed, purely informational for the Java caller.
-- ============================================================================
CREATE OR REPLACE FUNCTION idax_core.auth_rate_limit_clear_success(p_key text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
    v_row_count integer;
BEGIN
    IF p_key IS NULL OR length(p_key) = 0 OR length(p_key) > 200 THEN
        RAISE EXCEPTION 'auth_rate_limit_clear_success: invalid throttle key' USING ERRCODE = '22023';
    END IF;

    DELETE FROM idax_core.auth_rate_limit_bucket b
    WHERE b.throttle_key = p_key;

    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    RETURN v_row_count > 0;
END;
$function$;

ALTER FUNCTION idax_core.auth_rate_limit_clear_success(text) SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION idax_core.auth_rate_limit_clear_success(text) OWNER TO idax_capability_owner;
REVOKE ALL ON FUNCTION idax_core.auth_rate_limit_clear_success(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idax_core.auth_rate_limit_clear_success(text) TO idax_backend, idax_app, idax_admin;
