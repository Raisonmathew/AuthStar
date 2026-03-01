-- =============================================================================
-- Migration 040: Unified Policy Builder — Complete Redesign
-- =============================================================================
--
-- Replaces migration 039 with a production-grade unified policy builder that
-- serves all personas (platform engineers, tenant developers, tenant admins)
-- through a single API with permission tiers.
--
-- Key improvements over 039:
--   1. Templates are API-managed (not SQL-only) — platform_admin can CRUD them
--   2. Rule groups with AND/OR match logic
--   3. Composable conditions attachable to any rule
--   4. Immutable version snapshots with rollback
--   5. Simulation support (dry-run before activation)
--   6. Full version diff capability
--
-- Tables:
--   policy_actions              (kept from 039, minor additions)
--   policy_templates            (replaced — adds supported_conditions, deprecation)
--   policy_builder_configs      (replaced — adds versioning fields)
--   policy_builder_versions     (NEW — immutable snapshots)
--   policy_builder_rule_groups  (NEW — AND/OR group logic)
--   policy_builder_rules        (replaced — now belongs to a group)
--   policy_builder_conditions   (NEW — composable conditions on rules)
--   policy_builder_audit        (kept from 039, no changes)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Drop 039 tables (safe — no production data yet)
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS policy_builder_rules     CASCADE;
DROP TABLE IF EXISTS policy_builder_configs   CASCADE;
DROP TABLE IF EXISTS policy_templates         CASCADE;
-- Keep policy_actions and policy_builder_audit — they're fine as-is

-- ---------------------------------------------------------------------------
-- 1. Policy Templates (API-managed, replaces SQL-seed-only approach)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_templates (
    slug                VARCHAR(100) PRIMARY KEY,
    display_name        VARCHAR(200) NOT NULL,
    description         TEXT         NOT NULL,
    category            VARCHAR(50)  NOT NULL,  -- 'mfa', 'risk', 'identity', 'geo', 'device', 'time', 'access'
    applicable_actions  TEXT[],                 -- empty = applies to all actions
    icon                VARCHAR(50),            -- icon name for UI

    -- JSON Schema for param_values validation (react-jsonschema-form compatible)
    param_schema        JSONB        NOT NULL DEFAULT '{}',
    param_defaults      JSONB        NOT NULL DEFAULT '{}',

    -- Which condition types make semantic sense for this template
    -- (used by UI to filter the condition picker)
    supported_conditions TEXT[]      NOT NULL DEFAULT '{}',

    -- Ownership: NULL = platform template (managed by platform_admin)
    --            tenant_id = tenant-custom template
    owner_tenant_id     VARCHAR(50),

    -- Lifecycle
    is_active           BOOLEAN      NOT NULL DEFAULT true,
    is_deprecated       BOOLEAN      NOT NULL DEFAULT false,
    deprecated_at       TIMESTAMPTZ,
    deprecated_reason   TEXT,
    migration_guide     TEXT,        -- How to migrate away from this template

    sort_order          INTEGER      NOT NULL DEFAULT 100,
    created_by          VARCHAR(50),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_templates_active     ON policy_templates(is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_policy_templates_category   ON policy_templates(category);
CREATE INDEX IF NOT EXISTS idx_policy_templates_owner      ON policy_templates(owner_tenant_id);

-- ---------------------------------------------------------------------------
-- 2. Policy Builder Configs (versioned, one per tenant+action)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_builder_configs (
    id              VARCHAR(50)  PRIMARY KEY,
    tenant_id       VARCHAR(50)  NOT NULL,
    action_key      VARCHAR(100) NOT NULL,
    display_name    VARCHAR(200),
    description     TEXT,

    -- State: 'draft' | 'compiled' | 'active' | 'archived'
    -- 'draft'    = being configured, not yet compiled
    -- 'compiled' = WASM capsule generated, ready to activate
    -- 'active'   = live, serving authorization requests
    -- 'archived' = soft-deleted, no longer modifiable
    state           VARCHAR(20)  NOT NULL DEFAULT 'draft',

    -- Current working draft version number (increments on each compile)
    draft_version   INTEGER      NOT NULL DEFAULT 1,

    -- Currently active version (NULL if never activated)
    active_version  INTEGER,
    active_capsule_hash_b64 VARCHAR(200),
    activated_at    TIMESTAMPTZ,
    activated_by    VARCHAR(50),

    -- Metadata
    created_by      VARCHAR(50)  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- One config per (tenant, action) — versioning is internal
    CONSTRAINT uq_config_tenant_action UNIQUE (tenant_id, action_key)
);

CREATE INDEX IF NOT EXISTS idx_pb_configs_tenant   ON policy_builder_configs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pb_configs_action   ON policy_builder_configs(tenant_id, action_key);
CREATE INDEX IF NOT EXISTS idx_pb_configs_state    ON policy_builder_configs(tenant_id, state);

-- ---------------------------------------------------------------------------
-- 3. Policy Builder Versions (immutable snapshots — never updated after creation)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_builder_versions (
    id               VARCHAR(50)  PRIMARY KEY,
    config_id        VARCHAR(50)  NOT NULL REFERENCES policy_builder_configs(id) ON DELETE CASCADE,
    version_number   INTEGER      NOT NULL,

    -- Complete snapshot of the policy at compile time
    -- Stored as JSON so we can reconstruct the full policy without joining
    rule_snapshot    JSONB        NOT NULL,  -- { groups: [...], rules: [...], conditions: [...] }
    ast_snapshot     JSONB        NOT NULL,  -- The generated AST program

    -- Compilation result: SHA-256 of canonical AST JSON, base64-encoded
    ast_hash_b64     VARCHAR(200),

    -- Who compiled it
    compiled_by      VARCHAR(50),
    compiled_at      TIMESTAMPTZ  DEFAULT NOW(),

    -- Source of this version: 'builder' | 'ast_import' | 'rollback'
    source           VARCHAR(20)  NOT NULL DEFAULT 'builder',

    CONSTRAINT uq_config_version UNIQUE (config_id, version_number)
);

CREATE INDEX IF NOT EXISTS idx_pb_versions_config    ON policy_builder_versions(config_id);
CREATE INDEX IF NOT EXISTS idx_pb_versions_number    ON policy_builder_versions(config_id, version_number DESC);

-- ---------------------------------------------------------------------------
-- 4. Policy Builder Rule Groups (AND/OR logic containers)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_builder_rule_groups (
    id              VARCHAR(50)  PRIMARY KEY,
    config_id       VARCHAR(50)  NOT NULL REFERENCES policy_builder_configs(id) ON DELETE CASCADE,

    -- Groups are evaluated in sort_order (ascending)
    sort_order      INTEGER      NOT NULL DEFAULT 0,
    display_name    VARCHAR(200),
    description     TEXT,

    -- How rules within this group are combined:
    -- 'all' = ALL rules must evaluate to true (AND logic)
    -- 'any' = ANY rule evaluating to true is sufficient (OR logic)
    match_mode      VARCHAR(10)  NOT NULL DEFAULT 'all'
        CHECK (match_mode IN ('all', 'any')),

    -- What happens when this group's condition IS met:
    -- 'continue' = proceed to next group
    -- 'deny'     = immediately deny (Deny step in AST)
    -- 'stepup'   = require step-up MFA (RequireFactor step in AST)
    -- 'allow'    = immediately allow (short-circuit remaining groups)
    on_match        VARCHAR(20)  NOT NULL DEFAULT 'continue'
        CHECK (on_match IN ('continue', 'deny', 'stepup', 'allow')),

    -- What happens when this group's condition is NOT met:
    on_no_match     VARCHAR(20)  NOT NULL DEFAULT 'continue'
        CHECK (on_no_match IN ('continue', 'deny', 'stepup', 'allow')),

    -- Step-up configuration (used when on_match='stepup' or on_no_match='stepup')
    stepup_methods  TEXT[]       DEFAULT '{"totp","passkey"}',

    is_enabled      BOOLEAN      NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pb_groups_config ON policy_builder_rule_groups(config_id);

-- ---------------------------------------------------------------------------
-- 5. Policy Builder Rules (within groups, template + params)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_builder_rules (
    id              VARCHAR(50)  PRIMARY KEY,
    config_id       VARCHAR(50)  NOT NULL REFERENCES policy_builder_configs(id) ON DELETE CASCADE,
    group_id        VARCHAR(50)  NOT NULL REFERENCES policy_builder_rule_groups(id) ON DELETE CASCADE,
    template_slug   VARCHAR(100) NOT NULL REFERENCES policy_templates(slug),

    -- Template parameter values (validated against param_schema at write time)
    param_values    JSONB        NOT NULL DEFAULT '{}',
    display_name    VARCHAR(200),

    -- Rules within a group are evaluated in sort_order
    sort_order      INTEGER      NOT NULL DEFAULT 0,
    is_enabled      BOOLEAN      NOT NULL DEFAULT true,

    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pb_rules_config ON policy_builder_rules(config_id);
CREATE INDEX IF NOT EXISTS idx_pb_rules_group  ON policy_builder_rules(group_id);

-- ---------------------------------------------------------------------------
-- 6. Policy Builder Conditions (composable conditions on rules)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_builder_conditions (
    id               VARCHAR(50)  PRIMARY KEY,
    rule_id          VARCHAR(50)  NOT NULL REFERENCES policy_builder_rules(id) ON DELETE CASCADE,

    -- Condition type (maps to AST condition types)
    condition_type   VARCHAR(50)  NOT NULL,
    -- Supported types:
    --   risk_above, risk_below
    --   country_in, country_not_in
    --   new_device
    --   aal_below, aal_above
    --   outside_time_window, inside_time_window
    --   impossible_travel
    --   email_not_verified, email_verified
    --   role_in, role_not_in
    --   custom_claim
    --   ip_in_range, ip_not_in_range
    --   vpn_detected, tor_detected

    -- Type-specific parameters
    condition_params JSONB        NOT NULL DEFAULT '{}',
    -- Examples:
    --   risk_above:          { "threshold": 75.0 }
    --   country_in:          { "countries": ["RU", "KP", "IR"] }
    --   aal_below:           { "minimum_aal": 2 }
    --   outside_time_window: { "allowed_days": ["monday",...], "start_hour": 9, "end_hour": 17, "timezone": "UTC" }
    --   impossible_travel:   { "max_velocity_km_per_hour": 800 }
    --   role_in:             { "roles": ["owner", "admin"] }
    --   custom_claim:        { "claim_path": "app_metadata.tier", "operator": "eq", "value": "enterprise" }
    --   ip_in_range:         { "cidr_ranges": ["10.0.0.0/8", "192.168.0.0/16"] }

    -- Logical operator connecting this condition to the NEXT condition in this rule
    -- 'and' = this AND next must both be true
    -- 'or'  = this OR next is sufficient
    -- NULL  = last condition in the rule (no next operator)
    next_operator    VARCHAR(5)   DEFAULT 'and'
        CHECK (next_operator IS NULL OR next_operator IN ('and', 'or')),

    -- Conditions within a rule are evaluated in sort_order
    sort_order       INTEGER      NOT NULL DEFAULT 0,

    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pb_conditions_rule ON policy_builder_conditions(rule_id);

-- ---------------------------------------------------------------------------
-- 7. Policy Builder Audit (immutable event log)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_builder_audit (
    id          VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id   VARCHAR(50)  NOT NULL,
    config_id   VARCHAR(50),
    action_key  VARCHAR(100),
    event_type  VARCHAR(50)  NOT NULL,
    -- Event types:
    --   config_created, config_updated, config_archived, config_rolled_back
    --   config_compiled, config_activated, config_simulated
    --   group_added, group_updated, group_removed, groups_reordered
    --   rule_added, rule_updated, rule_removed, rules_reordered
    --   condition_added, condition_updated, condition_removed, conditions_reordered
    --   template_created, template_updated, template_deprecated
    --   ast_imported, ast_exported
    actor_id    VARCHAR(50)  NOT NULL,
    actor_ip    VARCHAR(50),             -- caller IP address (from X-Forwarded-For or socket)
    description TEXT,
    -- Additional structured data for the event (e.g., version number, diff summary)
    metadata    JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pb_audit_tenant    ON policy_builder_audit(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pb_audit_config    ON policy_builder_audit(config_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pb_audit_event     ON policy_builder_audit(event_type);

-- ---------------------------------------------------------------------------
-- 8. Seed Platform Templates (9 built-in + supported_conditions)
-- ---------------------------------------------------------------------------
INSERT INTO policy_templates
    (slug, display_name, description, category, applicable_actions, icon,
     param_schema, param_defaults, supported_conditions, sort_order, created_by)
VALUES

-- MFA Templates
('require_mfa',
 'Require MFA',
 'Require multi-factor authentication before allowing access. Supports TOTP, passkeys, SMS, and email OTP. Configure which methods are acceptable and set a grace period for recently-authenticated users.',
 'mfa', '{}', 'shield-check',
 '{
   "type": "object",
   "properties": {
     "allowed_methods": {
       "type": "array",
       "items": { "type": "string", "enum": ["totp","passkey","sms_otp","email_otp","backup_code"] },
       "minItems": 1,
       "description": "Acceptable MFA methods"
     },
     "require_phishing_resistant": {
       "type": "boolean",
       "description": "If true, only passkeys (FIDO2) are accepted — overrides allowed_methods"
     },
     "grace_period_seconds": {
       "type": "integer",
       "minimum": 0,
       "maximum": 86400,
       "description": "Skip MFA if user authenticated within this many seconds"
     }
   },
   "required": ["allowed_methods"]
 }'::jsonb,
 '{"allowed_methods": ["totp","passkey"], "require_phishing_resistant": false, "grace_period_seconds": 3600}'::jsonb,
 ARRAY['role_in','role_not_in','new_device','aal_below','risk_above'],
 10, 'system'),

('enforce_aal',
 'Enforce Assurance Level (AAL)',
 'Require a minimum Authenticator Assurance Level. AAL1 = password only, AAL2 = password + MFA, AAL3 = phishing-resistant MFA (passkey/FIDO2 hardware key).',
 'mfa', '{}', 'badge-check',
 '{
   "type": "object",
   "properties": {
     "minimum_aal": {
       "type": "integer",
       "minimum": 1,
       "maximum": 3,
       "description": "Minimum required AAL (1, 2, or 3)"
     },
     "stepup_methods": {
       "type": "array",
       "items": { "type": "string", "enum": ["totp","passkey","sms_otp","email_otp"] },
       "description": "Methods to offer for step-up authentication"
     }
   },
   "required": ["minimum_aal"]
 }'::jsonb,
 '{"minimum_aal": 2, "stepup_methods": ["totp","passkey"]}'::jsonb,
 ARRAY['role_in','role_not_in','aal_below'],
 20, 'system'),

-- Risk Templates
('block_high_risk',
 'Block or Step-Up on High Risk',
 'Evaluate the risk score for this request and block or require step-up MFA based on configurable thresholds. Risk scores range from 0 (safe) to 100 (critical).',
 'risk', '{}', 'alert-triangle',
 '{
   "type": "object",
   "properties": {
     "block_threshold": {
       "type": "integer",
       "minimum": 0,
       "maximum": 100,
       "description": "Risk score at or above this value → deny access"
     },
     "stepup_threshold": {
       "type": "integer",
       "minimum": 0,
       "maximum": 100,
       "description": "Risk score at or above this value → require MFA step-up (must be < block_threshold)"
     },
     "stepup_methods": {
       "type": "array",
       "items": { "type": "string", "enum": ["totp","passkey","sms_otp","email_otp"] },
       "description": "Methods to offer for step-up authentication"
     }
   },
   "required": ["block_threshold"]
 }'::jsonb,
 '{"block_threshold": 80, "stepup_threshold": 50, "stepup_methods": ["totp","passkey"]}'::jsonb,
 ARRAY['risk_above','risk_below','country_in','new_device'],
 30, 'system'),

('impossible_travel',
 'Impossible Travel Detection',
 'Detect when a user appears to have traveled an impossible distance between logins (e.g., logged in from New York, then Tokyo 5 minutes later). Block or require step-up MFA.',
 'risk', '{}', 'map-pin',
 '{
   "type": "object",
   "properties": {
     "max_velocity_km_per_hour": {
       "type": "integer",
       "minimum": 100,
       "maximum": 10000,
       "description": "Maximum plausible travel speed in km/h (default: 800 = commercial flight)"
     },
     "action": {
       "type": "string",
       "enum": ["deny","stepup"],
       "description": "What to do when impossible travel is detected"
     },
     "stepup_methods": {
       "type": "array",
       "items": { "type": "string", "enum": ["totp","passkey","sms_otp","email_otp"] }
     }
   },
   "required": ["max_velocity_km_per_hour", "action"]
 }'::jsonb,
 '{"max_velocity_km_per_hour": 800, "action": "stepup", "stepup_methods": ["totp","passkey","email_otp"]}'::jsonb,
 ARRAY['impossible_travel','risk_above'],
 40, 'system'),

-- Identity Templates
('require_email_verified',
 'Require Verified Email',
 'Block access for users who have not verified their email address. Optionally allow a grace period for newly registered users.',
 'identity', '{}', 'mail-check',
 '{
   "type": "object",
   "properties": {
     "allow_grace_period_minutes": {
       "type": "integer",
       "minimum": 0,
       "maximum": 10080,
       "description": "Allow unverified users for this many minutes after signup (0 = no grace)"
     }
   }
 }'::jsonb,
 '{"allow_grace_period_minutes": 0}'::jsonb,
 ARRAY['email_not_verified','role_in'],
 50, 'system'),

-- Geo Templates
('geo_restriction',
 'Geographic Restriction',
 'Allow or block access based on the user''s country. Use allowlist mode to only permit specific countries, or blocklist mode to deny specific countries.',
 'geo', '{}', 'globe',
 '{
   "type": "object",
   "properties": {
     "mode": {
       "type": "string",
       "enum": ["allowlist","blocklist"],
       "description": "allowlist = only permit listed countries; blocklist = deny listed countries"
     },
     "countries": {
       "type": "array",
       "items": { "type": "string", "minLength": 2, "maxLength": 2 },
       "minItems": 1,
       "description": "ISO 3166-1 alpha-2 country codes (e.g. US, GB, DE)"
     },
     "action_on_match": {
       "type": "string",
       "enum": ["deny","stepup"],
       "description": "What to do when the geo condition matches"
     }
   },
   "required": ["mode", "countries", "action_on_match"]
 }'::jsonb,
 '{"mode": "blocklist", "countries": [], "action_on_match": "deny"}'::jsonb,
 ARRAY['country_in','country_not_in','vpn_detected','tor_detected'],
 60, 'system'),

-- Device Templates
('new_device_stepup',
 'New Device Step-Up',
 'Require additional authentication when a user logs in from a device that has not been seen before. After successful step-up, the device is trusted for a configurable number of days.',
 'device', '{}', 'monitor',
 '{
   "type": "object",
   "properties": {
     "stepup_methods": {
       "type": "array",
       "items": { "type": "string", "enum": ["totp","passkey","sms_otp","email_otp"] },
       "minItems": 1
     },
     "device_trust_days": {
       "type": "integer",
       "minimum": 1,
       "maximum": 365,
       "description": "Trust this device for this many days after successful step-up"
     }
   },
   "required": ["stepup_methods", "device_trust_days"]
 }'::jsonb,
 '{"stepup_methods": ["totp","passkey","email_otp"], "device_trust_days": 30}'::jsonb,
 ARRAY['new_device','risk_above'],
 70, 'system'),

-- Time Templates
('time_based_access',
 'Time-Based Access Control',
 'Restrict access to specific days of the week and hours of the day. Useful for enforcing business-hours-only access for sensitive operations.',
 'time', '{}', 'clock',
 '{
   "type": "object",
   "properties": {
     "allowed_days": {
       "type": "array",
       "items": { "type": "string", "enum": ["monday","tuesday","wednesday","thursday","friday","saturday","sunday"] },
       "minItems": 1
     },
     "allowed_hours_start": {
       "type": "integer",
       "minimum": 0,
       "maximum": 23,
       "description": "Start of allowed window (24h, e.g. 9 = 9:00 AM)"
     },
     "allowed_hours_end": {
       "type": "integer",
       "minimum": 1,
       "maximum": 24,
       "description": "End of allowed window (24h, e.g. 17 = 5:00 PM)"
     },
     "timezone": {
       "type": "string",
       "description": "IANA timezone (e.g. America/New_York, Europe/London)"
     },
     "action_outside_window": {
       "type": "string",
       "enum": ["deny","stepup"],
       "description": "What to do outside the allowed window"
     }
   },
   "required": ["allowed_days", "allowed_hours_start", "allowed_hours_end", "timezone", "action_outside_window"]
 }'::jsonb,
 '{"allowed_days": ["monday","tuesday","wednesday","thursday","friday"], "allowed_hours_start": 8, "allowed_hours_end": 18, "timezone": "UTC", "action_outside_window": "deny"}'::jsonb,
 ARRAY['outside_time_window','role_in'],
 80, 'system'),

-- Access Templates
('allow_all',
 'Allow All Authenticated Users',
 'Allow all authenticated users without any additional checks. Use this as a baseline rule or to explicitly permit access for specific groups.',
 'access', '{}', 'check-circle',
 '{
   "type": "object",
   "properties": {
     "log_access": {
       "type": "boolean",
       "description": "Log each access event for audit purposes"
     }
   }
 }'::jsonb,
 '{"log_access": true}'::jsonb,
 ARRAY['role_in','role_not_in'],
 90, 'system')

ON CONFLICT (slug) DO UPDATE SET
    display_name         = EXCLUDED.display_name,
    description          = EXCLUDED.description,
    category             = EXCLUDED.category,
    param_schema         = EXCLUDED.param_schema,
    param_defaults       = EXCLUDED.param_defaults,
    supported_conditions = EXCLUDED.supported_conditions,
    updated_at           = NOW();

-- ---------------------------------------------------------------------------
-- 9. Ensure policy_actions has the updated platform seeds (idempotent)
-- ---------------------------------------------------------------------------
INSERT INTO policy_actions (action_key, display_name, description, category, is_platform)
VALUES
    ('auth:login',              'User Login',                   'Triggered on every login attempt',                                    'auth',    true),
    ('auth:signup',             'User Signup',                  'Triggered when a new user registers',                                 'auth',    true),
    ('auth:mfa_enroll',         'MFA Enrollment',               'Triggered when a user enrolls a new MFA factor',                      'auth',    true),
    ('auth:password_reset',     'Password Reset',               'Triggered when a user requests a password reset',                     'auth',    true),
    ('auth:step_up',            'Step-Up Authentication',       'Triggered when elevated assurance is required mid-session',           'auth',    true),
    ('auth:logout',             'User Logout',                  'Triggered when a user logs out',                                      'auth',    true),
    ('auth:session_refresh',    'Session Refresh',              'Triggered when a session token is refreshed',                         'auth',    true),
    ('admin:login',             'Admin Login',                  'Triggered when an admin logs into the management console',            'admin',   true),
    ('admin:impersonate',       'Admin Impersonation',          'Triggered when an admin impersonates a user',                         'admin',   true),
    ('org:create',              'Create Organization',          'Triggered when a new organization is created',                        'org',     true),
    ('org:delete',              'Delete Organization',          'Triggered when an organization is deleted',                           'org',     true),
    ('billing:read',            'View Billing',                 'Triggered when billing information is accessed',                      'billing', true),
    ('billing:write',           'Modify Billing',               'Triggered when billing information is modified',                      'billing', true),
    ('apikeys:manage',          'Manage API Keys',              'Triggered when API keys are created, listed, or revoked',             'api',     true)
ON CONFLICT (tenant_id, action_key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 10. Extend eiaa_policies with builder tracking columns (idempotent)
-- ---------------------------------------------------------------------------
ALTER TABLE eiaa_policies
    ADD COLUMN IF NOT EXISTS builder_config_id  VARCHAR(50),
    ADD COLUMN IF NOT EXISTS builder_version_id VARCHAR(50),
    ADD COLUMN IF NOT EXISTS source             VARCHAR(20) DEFAULT 'raw_ast';

COMMENT ON COLUMN eiaa_policies.source IS
    'Origin of this policy: raw_ast | builder | yaml_ci | rollback';

CREATE INDEX IF NOT EXISTS idx_eiaa_policies_builder
    ON eiaa_policies(builder_config_id) WHERE builder_config_id IS NOT NULL;