-- Seed development data
INSERT INTO organizations (id, name, slug, branding, auth_config, created_at, updated_at)
VALUES
  ('system', 'System (Provider)', 'admin',
   '{"logo_url": null, "primary_color": "#3B82F6", "background_color": "#F8FAFC", "text_color": "#1E293B", "font_family": "Inter"}'::jsonb,
   '{"password_min_length": 8, "mfa_policy": "optional", "session_lifetime_minutes": 60, "allowed_methods": ["email_password", "passkey"]}'::jsonb,
   NOW(), NOW()),
  ('default', 'Default Organization', 'default',
   '{"logo_url": null, "primary_color": "#6366F1", "background_color": "#F8FAFC", "text_color": "#1E293B", "font_family": "Inter"}'::jsonb,
   '{"password_min_length": 8, "mfa_policy": "optional", "session_lifetime_minutes": 60, "allowed_methods": ["email_password"]}'::jsonb,
   NOW(), NOW())
ON CONFLICT (id) DO NOTHING;
