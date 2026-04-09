-- =============================================================================
-- Migration 039: Policy Builder System
-- =============================================================================
--
-- Implements an Okta/Auth0-style no-code policy builder that allows tenant
-- admins to configure authorization policies through a structured UI without
-- writing AST JSON or WASM code.
--
-- Architecture:
--   policy_templates        → AuthStar-defined reusable policy blueprints
--   policy_template_params  → Parameter schema for each template
--   policy_builder_configs  → Tenant's configured policy (template + param values)
--   policy_builder_rules    → Individual rules within a builder config (ordered)
--   policy_actions          → Registry of all known actions (platform + tenant-defined)
--
-- Flow:
--   1. AuthStar engineers define templates (e.g., "Require MFA on new device")
--   2. Tenant admin selects a template, fills in parameters
--   3. Backend compiles the parameter values into a capsule AST
--   4. Capsule is compiled to WASM and activated — no code required
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Policy Actions Registry
--    Defines all known actions in the system. Platform actions are seeded by
--    AuthStar. Tenants can register custom actions for their own resources.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_actions (
    id              VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id       VARCHAR(50),                          -- NULL = platform-wide action
    action_key      VARCHAR(100) NOT NULL,                -- e.g. "auth:login", "billing:read"
    display_name    VARCHAR(200) NOT NULL,                -- "User Login"
    description     TEXT,
    category        VARCHAR(50)  NOT NULL DEFAULT 'custom', -- 'auth', 'billing', 'org', 'custom'
    is_platform     BOOLEAN      NOT NULL DEFAULT false,  -- true = defined by AuthStar
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_policy_actions_key UNIQUE (tenant_id, action_key)
);

-- Null-safe unique index: PostgreSQL UNIQUE treats NULLs as distinct,
-- so we COALESCE tenant_id to '' to prevent duplicate platform actions.
CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_actions_key_nullsafe
    ON policy_actions (COALESCE(tenant_id, ''), action_key);

CREATE INDEX IF NOT EXISTS idx_policy_actions_tenant   ON policy_actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policy_actions_platform ON policy_actions(is_platform) WHERE is_platform = true;

-- Seed platform-level actions (tenant_id = NULL means applies to all tenants)
INSERT INTO policy_actions (action_key, display_name, description, category, is_platform)
VALUES
    ('auth:login',           'User Login',              'Triggered on every login attempt',                          'auth',    true),
    ('auth:signup',          'User Signup',             'Triggered when a new user registers',                       'auth',    true),
    ('auth:mfa_enroll',      'MFA Enrollment',          'Triggered when a user enrolls a new MFA factor',           'auth',    true),
    ('auth:password_reset',  'Password Reset',          'Triggered when a user requests a password reset',          'auth',    true),
    ('auth:session_refresh', 'Session Refresh',         'Triggered on JWT/session token refresh',                   'auth',    true),
    ('billing:read',         'View Billing',            'Triggered when a user views billing information',           'billing', true),
    ('billing:update',       'Update Billing',          'Triggered when a user updates payment methods or plans',    'billing', true),
    ('org:invite_member',    'Invite Member',           'Triggered when an org admin invites a new member',         'org',     true),
    ('org:remove_member',    'Remove Member',           'Triggered when an org admin removes a member',             'org',     true),
    ('org:update_settings',  'Update Org Settings',     'Triggered when org settings are changed',                  'org',     true),
    ('user:update_profile',  'Update Profile',          'Triggered when a user updates their profile',              'user',    true),
    ('user:delete_account',  'Delete Account',          'Triggered when a user requests account deletion',          'user',    true),
    ('api:key_create',       'Create API Key',          'Triggered when a new API key is created',                  'auth',    true),
    ('api:key_delete',       'Delete API Key',          'Triggered when an API key is revoked',                     'auth',    true)
ON CONFLICT (tenant_id, action_key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Policy Templates
--    AuthStar-defined reusable policy blueprints. Each template has a fixed
--    set of parameters that tenants fill in. The template_ast_fn column
--    stores the name of the Rust function that generates the capsule AST
--    from the parameter values.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_templates (
    id              VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    slug            VARCHAR(100) NOT NULL UNIQUE,         -- machine-readable ID, e.g. "require_mfa"
    display_name    VARCHAR(200) NOT NULL,                -- "Require MFA"
    description     TEXT         NOT NULL,
    category        VARCHAR(50)  NOT NULL DEFAULT 'authentication',
                                                          -- 'authentication', 'risk', 'compliance', 'access_control'
    applicable_actions TEXT[]    NOT NULL DEFAULT '{}',   -- which action_keys this template applies to
    icon            VARCHAR(50),                          -- icon name for UI (e.g. "shield", "lock")
    is_active       BOOLEAN      NOT NULL DEFAULT true,
    sort_order      INTEGER      NOT NULL DEFAULT 0,
    -- JSON Schema for the parameters this template accepts
    param_schema    JSONB        NOT NULL DEFAULT '{}',
    -- Default parameter values
    param_defaults  JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_templates_category ON policy_templates(category);
CREATE INDEX IF NOT EXISTS idx_policy_templates_active   ON policy_templates(is_active) WHERE is_active = true;

-- Seed the built-in templates
INSERT INTO policy_templates (slug, display_name, description, category, applicable_actions, icon, sort_order, param_schema, param_defaults)
VALUES

-- Template 1: Require MFA
('require_mfa',
 'Require Multi-Factor Authentication',
 'Force users to complete a second authentication factor before access is granted. Choose which MFA methods are acceptable.',
 'authentication',
 ARRAY['auth:login', 'auth:session_refresh', 'billing:read', 'billing:update', 'org:update_settings'],
 'shield-check',
 10,
 '{
   "type": "object",
   "required": ["allowed_methods"],
   "properties": {
     "allowed_methods": {
       "type": "array",
       "title": "Allowed MFA Methods",
       "description": "Which MFA methods users can use to satisfy this requirement",
       "items": { "type": "string", "enum": ["totp", "passkey", "sms_otp", "email_otp", "backup_code"] },
       "minItems": 1,
       "default": ["totp", "passkey"]
     },
     "require_phishing_resistant": {
       "type": "boolean",
       "title": "Require Phishing-Resistant MFA",
       "description": "Only allow passkeys and hardware security keys (FIDO2). Disables TOTP and SMS.",
       "default": false
     },
     "grace_period_seconds": {
       "type": "integer",
       "title": "MFA Grace Period (seconds)",
       "description": "How long after a successful MFA challenge before requiring it again. 0 = always require.",
       "minimum": 0,
       "maximum": 86400,
       "default": 3600
     }
   }
 }',
 '{"allowed_methods": ["totp", "passkey"], "require_phishing_resistant": false, "grace_period_seconds": 3600}'
),

-- Template 2: Block High-Risk Logins
('block_high_risk',
 'Block High-Risk Access',
 'Automatically deny access when the risk score exceeds a threshold. Optionally step up to MFA for medium-risk requests instead of blocking.',
 'risk',
 ARRAY['auth:login', 'auth:session_refresh', 'billing:update', 'user:delete_account'],
 'shield-x',
 20,
 '{
   "type": "object",
   "required": ["block_threshold"],
   "properties": {
     "block_threshold": {
       "type": "integer",
       "title": "Block Threshold (0-100)",
       "description": "Risk score at or above which access is denied outright",
       "minimum": 0,
       "maximum": 100,
       "default": 80
     },
     "stepup_threshold": {
       "type": "integer",
       "title": "Step-Up Threshold (0-100)",
       "description": "Risk score at or above which MFA step-up is required (must be less than block threshold). Set to 0 to disable.",
       "minimum": 0,
       "maximum": 100,
       "default": 50
     },
     "stepup_methods": {
       "type": "array",
       "title": "Step-Up MFA Methods",
       "description": "MFA methods acceptable for step-up (only used when step-up threshold is set)",
       "items": { "type": "string", "enum": ["totp", "passkey", "sms_otp", "email_otp"] },
       "default": ["totp", "passkey"]
     }
   }
 }',
 '{"block_threshold": 80, "stepup_threshold": 50, "stepup_methods": ["totp", "passkey"]}'
),

-- Template 3: Require Email Verification
('require_email_verified',
 'Require Verified Email',
 'Block access for users who have not verified their email address.',
 'authentication',
 ARRAY['auth:login', 'billing:read', 'billing:update', 'org:invite_member'],
 'mail-check',
 30,
 '{
   "type": "object",
   "properties": {
     "allow_grace_period_minutes": {
       "type": "integer",
       "title": "Grace Period (minutes)",
       "description": "Allow unverified users to access for this many minutes after signup before blocking. 0 = block immediately.",
       "minimum": 0,
       "maximum": 10080,
       "default": 0
     }
   }
 }',
 '{"allow_grace_period_minutes": 0}'
),

-- Template 4: Geo-Restriction
('geo_restriction',
 'Geographic Access Restriction',
 'Allow or deny access based on the user''s country. Use an allowlist (only these countries) or a blocklist (all except these countries).',
 'access_control',
 ARRAY['auth:login', 'auth:signup', 'billing:update'],
 'globe',
 40,
 '{
   "type": "object",
   "required": ["mode", "countries"],
   "properties": {
     "mode": {
       "type": "string",
       "title": "Mode",
       "description": "allowlist = only allow listed countries; blocklist = block listed countries",
       "enum": ["allowlist", "blocklist"],
       "default": "blocklist"
     },
     "countries": {
       "type": "array",
       "title": "Countries (ISO 3166-1 alpha-2)",
       "description": "List of country codes (e.g. [\"US\", \"GB\", \"DE\"])",
       "items": { "type": "string", "minLength": 2, "maxLength": 2 },
       "minItems": 1
     },
     "action_on_match": {
       "type": "string",
       "title": "Action on Match",
       "description": "What to do when the country matches: deny = block access, stepup = require MFA",
       "enum": ["deny", "stepup"],
       "default": "deny"
     }
   }
 }',
 '{"mode": "blocklist", "countries": [], "action_on_match": "deny"}'
),

-- Template 5: New Device Step-Up
('new_device_stepup',
 'Step-Up on New Device',
 'Require additional authentication when a user logs in from a device they have not used before.',
 'risk',
 ARRAY['auth:login'],
 'device-mobile',
 50,
 '{
   "type": "object",
   "properties": {
     "stepup_methods": {
       "type": "array",
       "title": "Step-Up MFA Methods",
       "description": "MFA methods acceptable for new-device step-up",
       "items": { "type": "string", "enum": ["totp", "passkey", "sms_otp", "email_otp"] },
       "default": ["totp", "passkey", "email_otp"]
     },
     "device_trust_days": {
       "type": "integer",
       "title": "Device Trust Duration (days)",
       "description": "How many days to remember a device before requiring step-up again",
       "minimum": 1,
       "maximum": 365,
       "default": 30
     }
   }
 }',
 '{"stepup_methods": ["totp", "passkey", "email_otp"], "device_trust_days": 30}'
),

-- Template 6: Session AAL Enforcement
('enforce_aal',
 'Enforce Authentication Assurance Level',
 'Require a minimum Authentication Assurance Level (AAL) for sensitive operations. AAL2 requires MFA; AAL3 requires phishing-resistant MFA.',
 'compliance',
 ARRAY['billing:read', 'billing:update', 'org:update_settings', 'org:remove_member', 'user:delete_account', 'api:key_create', 'api:key_delete'],
 'badge-check',
 60,
 '{
   "type": "object",
   "required": ["minimum_aal"],
   "properties": {
     "minimum_aal": {
       "type": "integer",
       "title": "Minimum AAL",
       "description": "1 = password only, 2 = password + MFA, 3 = phishing-resistant MFA required",
       "enum": [1, 2, 3],
       "default": 2
     },
     "stepup_methods": {
       "type": "array",
       "title": "Acceptable Step-Up Methods",
       "description": "MFA methods that can be used to reach the required AAL",
       "items": { "type": "string", "enum": ["totp", "passkey", "sms_otp", "email_otp"] },
       "default": ["totp", "passkey"]
     }
   }
 }',
 '{"minimum_aal": 2, "stepup_methods": ["totp", "passkey"]}'
),

-- Template 7: Time-Based Access
('time_based_access',
 'Time-Based Access Control',
 'Restrict access to specific hours of the day or days of the week. Useful for enforcing business-hours-only access.',
 'access_control',
 ARRAY['auth:login', 'billing:update', 'org:update_settings'],
 'clock',
 70,
 '{
   "type": "object",
   "required": ["allowed_days", "allowed_hours_start", "allowed_hours_end", "timezone"],
   "properties": {
     "allowed_days": {
       "type": "array",
       "title": "Allowed Days",
       "description": "Days of the week when access is permitted",
       "items": { "type": "string", "enum": ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"] },
       "default": ["monday", "tuesday", "wednesday", "thursday", "friday"]
     },
     "allowed_hours_start": {
       "type": "integer",
       "title": "Start Hour (0-23)",
       "description": "Hour of day when access window opens (24-hour format)",
       "minimum": 0,
       "maximum": 23,
       "default": 8
     },
     "allowed_hours_end": {
       "type": "integer",
       "title": "End Hour (0-23)",
       "description": "Hour of day when access window closes (24-hour format)",
       "minimum": 0,
       "maximum": 23,
       "default": 18
     },
     "timezone": {
       "type": "string",
       "title": "Timezone",
       "description": "IANA timezone name (e.g. America/New_York)",
       "default": "UTC"
     },
     "action_outside_window": {
       "type": "string",
       "title": "Action Outside Window",
       "description": "deny = block access, stepup = require MFA approval",
       "enum": ["deny", "stepup"],
       "default": "deny"
     }
   }
 }',
 '{"allowed_days": ["monday","tuesday","wednesday","thursday","friday"], "allowed_hours_start": 8, "allowed_hours_end": 18, "timezone": "UTC", "action_outside_window": "deny"}'
),

-- Template 8: Impossible Travel Detection
('impossible_travel',
 'Impossible Travel Detection',
 'Block or step up when a user appears to be logging in from two geographically distant locations in an impossibly short time.',
 'risk',
 ARRAY['auth:login'],
 'map-pin-x',
 80,
 '{
   "type": "object",
   "properties": {
     "max_velocity_km_per_hour": {
       "type": "integer",
       "title": "Max Travel Speed (km/h)",
       "description": "Maximum plausible travel speed. Logins exceeding this are flagged.",
       "minimum": 100,
       "maximum": 2000,
       "default": 800
     },
     "action": {
       "type": "string",
       "title": "Action on Detection",
       "description": "deny = block access, stepup = require MFA",
       "enum": ["deny", "stepup"],
       "default": "stepup"
     },
     "stepup_methods": {
       "type": "array",
       "title": "Step-Up Methods",
       "items": { "type": "string", "enum": ["totp", "passkey", "sms_otp", "email_otp"] },
       "default": ["totp", "passkey", "email_otp"]
     }
   }
 }',
 '{"max_velocity_km_per_hour": 800, "action": "stepup", "stepup_methods": ["totp", "passkey", "email_otp"]}'
),

-- Template 9: Allow All (Passthrough)
('allow_all',
 'Allow All (No Restrictions)',
 'Allow all authenticated users to perform this action without additional checks. Use this to explicitly mark an action as unrestricted.',
 'access_control',
 ARRAY['auth:login', 'auth:signup', 'auth:mfa_enroll', 'auth:password_reset', 'auth:session_refresh', 'billing:read', 'billing:update', 'org:invite_member', 'org:remove_member', 'org:update_settings', 'user:update_profile', 'user:delete_account', 'api:key_create', 'api:key_delete'],
 'check-circle',
 90,
 '{
   "type": "object",
   "properties": {
     "log_access": {
       "type": "boolean",
       "title": "Log All Access",
       "description": "Record every access attempt in the audit log even though all are allowed",
       "default": true
     }
   }
 }',
 '{"log_access": true}'
)

ON CONFLICT (slug) DO UPDATE SET
    display_name        = EXCLUDED.display_name,
    description         = EXCLUDED.description,
    param_schema        = EXCLUDED.param_schema,
    param_defaults      = EXCLUDED.param_defaults,
    updated_at          = NOW();

-- ---------------------------------------------------------------------------
-- 3. Policy Builder Configurations
--    A tenant's configured policy for a specific action. This is the
--    "saved state" of the policy builder UI. Multiple rules can be stacked
--    (evaluated in order). The compiled capsule hash is stored here once
--    the config is compiled.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_builder_configs (
    id                  VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id           VARCHAR(50)  NOT NULL,
    action_key          VARCHAR(100) NOT NULL,
    display_name        VARCHAR(200),                     -- optional human name for this config
    description         TEXT,
    -- Lifecycle state
    state               VARCHAR(20)  NOT NULL DEFAULT 'draft',
                                                          -- draft | active | archived
    -- Compiled capsule reference (populated after compile)
    capsule_hash_b64    VARCHAR(200),
    compiled_at         TIMESTAMPTZ,
    compiled_by         VARCHAR(50),
    -- Activation tracking
    activated_at        TIMESTAMPTZ,
    activated_by        VARCHAR(50),
    -- Audit
    created_by          VARCHAR(50)  NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_builder_config_tenant_action UNIQUE (tenant_id, action_key)
);

CREATE INDEX IF NOT EXISTS idx_builder_configs_tenant  ON policy_builder_configs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_builder_configs_state   ON policy_builder_configs(state);

-- ---------------------------------------------------------------------------
-- 4. Policy Builder Rules
--    Individual rules within a builder config. Rules are evaluated in
--    sort_order. Each rule references a template and stores the parameter
--    values the tenant chose. The AST fragment for each rule is generated
--    at compile time from (template_slug, param_values).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_builder_rules (
    id              VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    config_id       VARCHAR(50)  NOT NULL REFERENCES policy_builder_configs(id) ON DELETE CASCADE,
    template_slug   VARCHAR(100) NOT NULL REFERENCES policy_templates(slug),
    -- Parameter values chosen by the tenant (validated against template param_schema)
    param_values    JSONB        NOT NULL DEFAULT '{}',
    -- Display
    display_name    VARCHAR(200),                         -- optional override for rule name in UI
    is_enabled      BOOLEAN      NOT NULL DEFAULT true,
    sort_order      INTEGER      NOT NULL DEFAULT 0,
    -- Audit
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_builder_rules_config ON policy_builder_rules(config_id);
CREATE INDEX IF NOT EXISTS idx_builder_rules_order  ON policy_builder_rules(config_id, sort_order);

-- ---------------------------------------------------------------------------
-- 5. Policy Builder Audit Log
--    Every change to a builder config or its rules is recorded here.
--    This provides a full history of who changed what and when.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_builder_audit (
    id              VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id       VARCHAR(50)  NOT NULL,
    config_id       VARCHAR(50)  NOT NULL,
    action_key      VARCHAR(100) NOT NULL,
    event_type      VARCHAR(50)  NOT NULL,
                                                          -- config_created | rule_added | rule_updated | rule_removed
                                                          -- rule_reordered | config_compiled | config_activated | config_archived
    actor_id        VARCHAR(50)  NOT NULL,
    actor_email     VARCHAR(200),
    -- Snapshot of the config state at the time of the event
    config_snapshot JSONB,
    -- Human-readable description
    description     TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_builder_audit_tenant    ON policy_builder_audit(tenant_id);
CREATE INDEX IF NOT EXISTS idx_builder_audit_config    ON policy_builder_audit(config_id);
CREATE INDEX IF NOT EXISTS idx_builder_audit_created   ON policy_builder_audit(created_at DESC);

-- ---------------------------------------------------------------------------
-- 6. Extend eiaa_policies to track builder origin
--    When a policy is created via the builder (not raw AST), we record
--    which builder config it came from. This enables "edit in builder" for
--    policies that were originally created via the UI.
-- ---------------------------------------------------------------------------
ALTER TABLE eiaa_policies
    ADD COLUMN IF NOT EXISTS builder_config_id VARCHAR(50) REFERENCES policy_builder_configs(id),
    ADD COLUMN IF NOT EXISTS source VARCHAR(20) NOT NULL DEFAULT 'raw_ast';
                                                          -- 'raw_ast' | 'builder' | 'yaml_ci'

COMMENT ON COLUMN eiaa_policies.source IS 'How this policy was created: raw_ast (API), builder (UI), yaml_ci (CI/CD pipeline)';
COMMENT ON COLUMN eiaa_policies.builder_config_id IS 'If source=builder, the builder config that generated this policy';

-- ---------------------------------------------------------------------------
-- 7. Row-Level Security
-- ---------------------------------------------------------------------------
ALTER TABLE policy_actions          ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_builder_configs  ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_builder_rules    ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_builder_audit    ENABLE ROW LEVEL SECURITY;

-- policy_actions: tenants see platform actions + their own custom actions
CREATE POLICY policy_actions_tenant_isolation ON policy_actions
    USING (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true));

-- builder_configs: strict tenant isolation
CREATE POLICY builder_configs_tenant_isolation ON policy_builder_configs
    USING (tenant_id = current_setting('app.tenant_id', true));

-- builder_rules: isolated via config ownership
CREATE POLICY builder_rules_tenant_isolation ON policy_builder_rules
    USING (config_id IN (
        SELECT id FROM policy_builder_configs
        WHERE tenant_id = current_setting('app.tenant_id', true)
    ));

-- builder_audit: strict tenant isolation
CREATE POLICY builder_audit_tenant_isolation ON policy_builder_audit
    USING (tenant_id = current_setting('app.tenant_id', true));

-- ---------------------------------------------------------------------------
-- Comments
-- ---------------------------------------------------------------------------
COMMENT ON TABLE policy_actions         IS 'Registry of all known policy actions (platform + tenant-defined)';
COMMENT ON TABLE policy_templates       IS 'AuthStar-defined reusable policy blueprints with parameter schemas';
COMMENT ON TABLE policy_builder_configs IS 'Tenant policy configurations created via the no-code policy builder';
COMMENT ON TABLE policy_builder_rules   IS 'Individual rules within a builder config, each referencing a template';
COMMENT ON TABLE policy_builder_audit   IS 'Full audit trail of all policy builder changes';