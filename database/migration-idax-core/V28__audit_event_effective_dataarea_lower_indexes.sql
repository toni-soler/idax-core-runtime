CREATE INDEX IF NOT EXISTS ix_idax_audit_event_tenant_effective_dataarea_lower_time
    ON idax_core.idax_audit_event (tenant_id, lower(effective_dataareaid), event_time DESC);

CREATE INDEX IF NOT EXISTS ix_idax_audit_event_sales_tenant_effective_lower_time
    ON idax_core.idax_audit_event (tenant_id, lower(effective_dataareaid), event_time DESC)
    WHERE event_type IN (
        'SALES_ORDER_CREATED_FROM_IDAX',
        'SALES_ORDER_CREATED_FROM_EMAIL',
        'SALES_LINE_CREATED_FROM_IDAX',
        'SALES_LINE_SYNC_FROM_AX',
        'SALES_ORDER_SYNC_FROM_AX',
        'SALES_TABLE_FIELDS_UPDATED',
        'SALES_LINE_FIELDS_UPDATED',
        'SALES_ORDER_UPDATED_BY_USER',
        'CUSTOMER_SYNC_FROM_AX'
    );
