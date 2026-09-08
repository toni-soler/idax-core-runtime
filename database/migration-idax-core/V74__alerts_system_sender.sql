-- V74__alerts_system_sender.sql
--
-- Dedicated, non-interactive AppUser used as the sender identity for
-- automatic internal messages raised by the alert framework
-- (IdaxMessagingService.create requires a real app_user row to resolve the
-- sender - see AlertNotificationDispatcher). external_subject is not a
-- reachable SSO/local identity so nobody can authenticate as this account;
-- auth_provider='service' matches the convention already documented on
-- idax_core.app_user (V1). The id is fixed so backend code can reference it
-- as a constant instead of looking it up by a magic string every run.
INSERT INTO idax_core.app_user
    (user_id, external_subject, email, display_name, auth_provider, is_active)
VALUES
    ('3a07164d-34bf-41e0-8745-0163bf32c057', 'system:idax-alerts', '', 'IDAX Alertas', 'service', FALSE)
ON CONFLICT (external_subject) DO NOTHING;
