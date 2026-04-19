-- Seed audit events for Playwright tests
DELETE FROM audit_events WHERE actor_id = 'user_admin' AND user_agent = 'playwright-seed';

INSERT INTO audit_events
    (tenant_id, event_type, actor_id, actor_email, target_type, target_id, ip_address, user_agent, metadata, created_at)
VALUES
    ('system', 'user.login_success', 'user_admin', 'admin@example.com', 'session', 'sess_seed_1', '127.0.0.1', 'playwright-seed', '{}', NOW()),
    ('system', 'user.login_failed',  'user_admin', 'admin@example.com', 'session', NULL,          '127.0.0.1', 'playwright-seed', '{"reason":"invalid_password"}', NOW() - interval '1 hour'),
    ('system', 'user.logout',        'user_admin', 'admin@example.com', 'session', 'sess_seed_1', '127.0.0.1', 'playwright-seed', '{}', NOW() - interval '30 minutes'),
    ('system', 'api_key.created',    'user_admin', 'admin@example.com', 'api_key', 'key_seed_1',  '127.0.0.1', 'playwright-seed', '{"key_name":"Test Key"}', NOW() - interval '2 hours'),
    ('system', 'user.login_success', 'user_admin', 'admin@example.com', 'session', 'sess_seed_2', '192.168.1.100', 'playwright-seed', '{}', NOW() - interval '3 hours');
