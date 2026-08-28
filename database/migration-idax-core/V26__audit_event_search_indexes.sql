CREATE INDEX IF NOT EXISTS ix_idax_audit_event_tenant_event_time
    ON idax_core.idax_audit_event (tenant_id, event_time DESC);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_tenant_status_event_time
    ON idax_core.idax_audit_event (tenant_id, status, event_time DESC);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_tenant_origin_event_time
    ON idax_core.idax_audit_event (tenant_id, origin_system, event_time DESC);
