# Policy Builder — Design Reference

**AuthStar IDaaS Platform**  
**Version:** 1.0  
**Status:** Implemented (Migration 039, `routes/policy_builder.rs`)

---

## 1. Overview

The Policy Builder is an Okta/Auth0-style **no-code policy configuration system** that allows tenant administrators to configure authorization policies through a structured API (backed by a UI) without writing AST JSON, YAML, or WASM code.

### The Three-Persona Model

| Persona | Interface | Capability |
|---------|-----------|------------|
| **AuthStar Platform Engineers** | Database seed (migration 039) | Define `policy_templates` — the reusable blueprints |
| **Tenant Developers** | `POST /api/eiaa/v1/capsules/compile` (existing) | Write raw AST JSON / YAML CI pipeline |
| **Tenant Admins (no-code)** | `POST /api/v1/policy-builder/...` (new) | Configure policies via templates + parameters |

All three paths produce the same output: a signed WASM capsule stored in `eiaa_capsules` and activated via `eiaa_policy_activations`. The Policy Builder is an **additional on-ramp**, not a replacement.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Policy Builder API                          │
│              /api/v1/policy-builder/*                           │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Templates   │  │   Actions    │  │       Configs        │  │
│  │  (read-only) │  │  (registry)  │  │  (draft→compiled     │  │
│  │              │  │              │  │   →active)           │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                               │                 │
│                                               ▼                 │
│                                    ┌──────────────────┐        │
│                                    │  AST Compiler    │        │
│                                    │  Engine          │        │
│                                    │  (Rust, in-proc) │        │
│                                    └──────────────────┘        │
│                                               │                 │
└───────────────────────────────────────────────┼─────────────────┘
                                                ▼
                              ┌─────────────────────────────┐
                              │   capsule_compiler::compile  │
                              │   (existing WASM compiler)   │
                              └─────────────────────────────┘
                                                │
                              ┌─────────────────┴──────────────┐
                              │         eiaa_capsules           │
                              │    eiaa_policies (source=       │
                              │    'builder')                   │
                              │    eiaa_policy_activations      │
                              └────────────────────────────────┘
```

### Data Model

```
policy_actions          ← Registry of all known actions (platform + tenant-custom)
policy_templates        ← AuthStar-defined reusable blueprints (seeded, read-only for tenants)
policy_builder_configs  ← Tenant's configured policy (state: draft → compiled → active)
policy_builder_rules    ← Ordered rules within a config (template_slug + param_values)
policy_builder_audit    ← Full change history for compliance
eiaa_policies           ← Extended with builder_config_id + source columns
```

---

## 3. Core Concepts

### 3.1 Policy Templates

Templates are **AuthStar-defined blueprints** that encapsulate a security pattern. Each template has:

- **`slug`** — Unique identifier (e.g., `require_mfa`, `block_high_risk`)
- **`param_schema`** — JSON Schema defining the configurable parameters
- **`param_defaults`** — Sensible defaults for all parameters
- **`applicable_actions`** — Which actions this template can be applied to (empty = all)
- **`category`** — UI grouping (`mfa`, `risk`, `identity`, `geo`, `device`, `time`, `access`)

Templates are **immutable from the tenant's perspective** — they can only be read, not modified. AuthStar engineers add new templates via database migrations.

#### Built-in Templates (Migration 039)

| Slug | Category | Description |
|------|----------|-------------|
| `require_mfa` | mfa | Require MFA with configurable methods and grace period |
| `block_high_risk` | risk | Block or step-up based on risk score thresholds |
| `require_email_verified` | identity | Block unverified email addresses |
| `geo_restriction` | geo | Allow/block by country code (allowlist or blocklist) |
| `new_device_stepup` | device | Require MFA on first login from a new device |
| `enforce_aal` | mfa | Enforce minimum Authenticator Assurance Level |
| `time_based_access` | time | Restrict access to specific hours/days |
| `impossible_travel` | risk | Detect and respond to impossible travel events |
| `allow_all` | access | Allow all authenticated users (no restrictions) |

### 3.2 Policy Actions

Actions define **what event** a policy governs. Platform actions are seeded by AuthStar (e.g., `auth:login`, `auth:signup`). Tenants can register custom actions for their own resources (e.g., `billing:export`, `admin:impersonate`).

### 3.3 Policy Builder Configs

A **config** is a tenant's configured policy for a specific action. It has a lifecycle:

```
draft ──────────────────────────────────────────────────────► archived
  │                                                              ▲
  │  (add/edit/remove rules)                                     │
  │                                                              │
  ▼                                                              │
compiled ──────────────────────────────────────────────────────►│
  │                                                              │
  │  (activate)                                                  │
  ▼                                                              │
active ─────────────────────────────────────────────────────────┘
```

- **`draft`** — Being configured; not yet compiled. Any rule change resets to draft.
- **`compiled`** — WASM capsule generated; ready to activate.
- **`active`** — Live; all authorization requests for this action use this policy.
- **`archived`** — Soft-deleted; no longer modifiable.

**Constraint:** Only one `active` config per (tenant, action) pair at a time.

### 3.4 Rules

Rules are **ordered instances of templates** within a config. Each rule has:

- **`template_slug`** — Which template to use
- **`param_values`** — The tenant's chosen parameter values (validated against `param_schema`)
- **`sort_order`** — Execution order (lower = earlier)
- **`is_enabled`** — Can be toggled without removing the rule

Rules are executed in `sort_order` order. The final step is always an implicit `Allow`.

---

## 4. API Reference

**Base path:** `/api/v1/policy-builder`  
**Auth:** JWT Bearer token (tenant-scoped)  
**EIAA action:** `policies:manage`

### 4.1 Templates

#### `GET /templates`
List all active policy templates.

**Response:** `200 OK`
```json
[
  {
    "slug": "require_mfa",
    "display_name": "Require MFA",
    "description": "Require multi-factor authentication...",
    "category": "mfa",
    "applicable_actions": [],
    "icon": "shield-check",
    "param_schema": {
      "type": "object",
      "properties": {
        "allowed_methods": { "type": "array", ... },
        "grace_period_seconds": { "type": "integer", "minimum": 0, "maximum": 86400 }
      }
    },
    "param_defaults": {
      "allowed_methods": ["totp", "passkey"],
      "grace_period_seconds": 3600
    }
  }
]
```

#### `GET /templates/:slug`
Get a single template by slug.

---

### 4.2 Actions

#### `GET /actions`
List all actions available to this tenant (platform + tenant-custom).

#### `POST /actions`
Register a custom action for this tenant.

**Request:**
```json
{
  "action_key": "billing:export",
  "display_name": "Export Billing Data",
  "description": "Triggered when a user exports billing records",
  "category": "billing"
}
```

---

### 4.3 Configs

#### `GET /configs`
List all non-archived configs for this tenant.

**Response:** `200 OK` — Array of `ConfigSummary` objects with `rule_count`.

#### `POST /configs`
Create a new policy config for an action.

**Request:**
```json
{
  "action_key": "auth:login",
  "display_name": "Login Policy v2",
  "description": "Stricter login policy with geo-restriction"
}
```

**Validation:**
- `action_key` must exist (platform or tenant-owned)
- No existing `active` config for this action (must archive first)

**Response:** `201 Created` — `ConfigDetail` with empty `rules` array.

#### `GET /configs/:id`
Get a config with all its rules (including resolved template info).

#### `DELETE /configs/:id`
Archive a config (soft delete). Cannot be undone.

---

### 4.4 Rules

#### `POST /configs/:id/rules`
Add a rule to a config.

**Request:**
```json
{
  "template_slug": "require_mfa",
  "param_values": {
    "allowed_methods": ["passkey", "totp"],
    "require_phishing_resistant": false,
    "grace_period_seconds": 1800
  },
  "display_name": "Require MFA (30min grace)"
}
```

**Validation:**
- Template must exist and be active
- Template must be applicable to the config's action (if `applicable_actions` is non-empty)
- `param_values` validated against template's `param_schema`
- Config must not be archived

**Side effect:** Config state reset to `draft`, `capsule_hash_b64` cleared.

#### `PUT /configs/:id/rules/:rid`
Update a rule's parameters, display name, or enabled state.

**Request:** (all fields optional)
```json
{
  "param_values": { "grace_period_seconds": 0 },
  "display_name": "Require MFA (no grace)",
  "is_enabled": true
}
```

#### `DELETE /configs/:id/rules/:rid`
Remove a rule from a config.

#### `POST /configs/:id/rules/reorder`
Reorder rules by providing the desired order of rule IDs.

**Request:**
```json
{
  "rule_ids": ["pbr_abc123", "pbr_def456", "pbr_ghi789"]
}
```

---

### 4.5 Compile & Activate

#### `GET /configs/:id/preview`
Preview the generated AST and human-readable summary **without** compiling to WASM.

**Response:**
```json
{
  "action_key": "auth:login",
  "rule_count": 3,
  "ast_program": {
    "action": "auth:login",
    "version": 1,
    "steps": [
      { "type": "EvaluateRisk" },
      { "type": "Conditional", "condition": { "type": "RiskScoreAbove", "threshold": 80 }, ... },
      { "type": "RequireFactor", "acceptable_capabilities": ["passkey", "totp"], ... },
      { "type": "Allow" }
    ]
  },
  "human_summary": [
    "Block High-Risk Access: Block risk ≥ 80, step-up MFA for risk ≥ 50",
    "Require MFA (30min grace): Require MFA — accepted methods: passkey, totp",
    "New Device Step-Up: Require MFA on new devices (trust for 30 days)"
  ]
}
```

#### `POST /configs/:id/compile`
Compile the config to a WASM capsule.

**What happens:**
1. All enabled rules compiled to AST steps (in `sort_order`)
2. Final `Allow` step appended
3. `capsule_compiler::compile()` called → signed WASM capsule
4. Capsule stored in `eiaa_capsules`
5. Policy record inserted in `eiaa_policies` with `source='builder'`
6. Config updated with `capsule_hash_b64` and `compiled_at`

**Response:**
```json
{
  "config_id": "pbc_abc123",
  "capsule_hash_b64": "abc123...",
  "compiled_at": "2026-03-01T10:00:00Z",
  "message": "Policy compiled successfully. 3 rule(s) compiled to WASM capsule (policy v2). Use the activate endpoint to make it live."
}
```

#### `POST /configs/:id/activate`
Activate the compiled capsule — makes it live for all authorization requests.

**What happens (in a transaction):**
1. All existing `eiaa_policy_activations` for this (tenant, action) set to `is_active=false`
2. New activation record inserted for the compiled policy
3. Config state set to `active`, `activated_at` recorded
4. Capsule cache invalidated (immediate effect, no TTL wait)

**Response:**
```json
{
  "config_id": "pbc_abc123",
  "action_key": "auth:login",
  "activated_at": "2026-03-01T10:05:00Z",
  "message": "Policy is now live. All authorization requests for this action will use the new policy."
}
```

---

### 4.6 Audit

#### `GET /configs/:id/audit`
Get the last 100 audit events for a config.

**Response:** Array of `AuditEntry` objects with `event_type`, `actor_id`, `description`, `created_at`.

**Event types:** `config_created`, `config_compiled`, `config_activated`, `config_archived`, `rule_added`, `rule_updated`, `rule_removed`, `rule_reordered`

---

## 5. AST Compiler Engine

The compiler engine (`compile_rules_to_ast`) translates template + param_values into capsule AST steps. Each template has a dedicated `compile_*` function.

### Template → AST Mapping

#### `require_mfa`
```
params: { allowed_methods, require_phishing_resistant, grace_period_seconds }
→ RequireFactor { acceptable_capabilities, require_phishing_resistant, grace_period_seconds }
```
If `require_phishing_resistant=true`, methods are overridden to `["passkey"]`.

#### `block_high_risk`
```
params: { block_threshold, stepup_threshold, stepup_methods }
→ EvaluateRisk
→ Conditional(RiskScoreAbove(block_threshold)) → Deny(risk_too_high)
→ Conditional(RiskScoreAbove(stepup_threshold)) → RequireFactor(stepup_methods)
```

#### `require_email_verified`
```
params: { allow_grace_period_minutes }
→ VerifyIdentity { require_email_verified: true, grace_period_minutes }
```

#### `geo_restriction`
```
params: { mode, countries, action_on_match }
→ Conditional(CountryIn/CountryNotIn(countries)) → Deny | RequireFactor
```
`mode=allowlist` → `CountryNotIn` (deny if NOT in list)  
`mode=blocklist` → `CountryIn` (deny if IN list)

#### `new_device_stepup`
```
params: { stepup_methods, device_trust_days }
→ Conditional(NewDevice) → RequireFactor { device_trust_days }
```

#### `enforce_aal`
```
params: { minimum_aal, stepup_methods }
→ Conditional(AalBelow(minimum_aal)) → RequireFactor { required_assurance: "AAL{n}" }
```

#### `time_based_access`
```
params: { allowed_days, allowed_hours_start, allowed_hours_end, timezone, action_outside_window }
→ Conditional(OutsideTimeWindow { allowed_days, start_hour, end_hour, timezone }) → Deny | RequireFactor
```

#### `impossible_travel`
```
params: { max_velocity_km_per_hour, action, stepup_methods }
→ Conditional(ImpossibleTravel { max_velocity_km_per_hour }) → Deny | RequireFactor
```

#### `allow_all`
```
params: { log_access }
→ Allow { log_access }
```

### Step Merging

All enabled rules are compiled in `sort_order` order. Their steps are concatenated. A final `Allow` step is appended. This means:

- Rules execute sequentially
- Any `Deny` in a rule terminates the policy
- Any `RequireFactor` in a rule triggers step-up authentication
- If all rules pass, the final `Allow` grants access

---

## 6. Typical Workflow

### Example: Configure a Login Policy

```bash
# 1. Browse available templates
GET /api/v1/policy-builder/templates

# 2. Create a config for auth:login
POST /api/v1/policy-builder/configs
{
  "action_key": "auth:login",
  "display_name": "Production Login Policy"
}
# → config_id: "pbc_abc123"

# 3. Add a risk-based blocking rule
POST /api/v1/policy-builder/configs/pbc_abc123/rules
{
  "template_slug": "block_high_risk",
  "param_values": {
    "block_threshold": 75,
    "stepup_threshold": 45,
    "stepup_methods": ["passkey", "totp"]
  },
  "display_name": "Block High-Risk Logins"
}

# 4. Add an MFA requirement
POST /api/v1/policy-builder/configs/pbc_abc123/rules
{
  "template_slug": "require_mfa",
  "param_values": {
    "allowed_methods": ["passkey", "totp"],
    "grace_period_seconds": 3600
  },
  "display_name": "Require MFA"
}

# 5. Add geo-restriction (block Russia, North Korea, Iran)
POST /api/v1/policy-builder/configs/pbc_abc123/rules
{
  "template_slug": "geo_restriction",
  "param_values": {
    "mode": "blocklist",
    "countries": ["RU", "KP", "IR"],
    "action_on_match": "deny"
  },
  "display_name": "Block Sanctioned Countries"
}

# 6. Preview the generated AST
GET /api/v1/policy-builder/configs/pbc_abc123/preview

# 7. Compile to WASM
POST /api/v1/policy-builder/configs/pbc_abc123/compile

# 8. Activate (goes live immediately)
POST /api/v1/policy-builder/configs/pbc_abc123/activate
```

---

## 7. Security Considerations

### Tenant Isolation
- All queries are scoped by `tenant_id` from the JWT claims
- `verify_config_ownership()` is called on every mutating operation
- Platform templates are read-only for all tenants
- Custom actions are scoped to the creating tenant

### Audit Trail
- Every operation writes to `policy_builder_audit`
- Audit records include `actor_id`, `event_type`, `description`, and timestamp
- Audit log is immutable (no UPDATE/DELETE on audit table)

### Compile → Activate Separation
- Compiling does not make a policy live — it only generates the WASM capsule
- Activation is a separate, explicit step requiring a second API call
- This allows review of the compiled capsule before it affects production traffic

### Cache Invalidation
- On activation, `capsule_cache.invalidate(tenant_id, action_key)` is called
- This ensures the new policy takes effect immediately without waiting for TTL expiry
- If cache invalidation fails, a warning is logged but the activation succeeds (TTL will expire naturally)

### Param Validation
- All `param_values` are validated against the template's `param_schema` before storage
- Validation checks: required fields, type correctness, enum membership, integer bounds, array minItems
- Full JSON Schema validation (jsonschema crate) can be added as a future enhancement

---

## 8. Database Schema Summary

### `policy_actions`
```sql
id, tenant_id (NULL=platform), action_key, display_name, description, category, is_platform
UNIQUE (tenant_id, action_key)
```

### `policy_templates`
```sql
slug (PK), display_name, description, category, applicable_actions[], icon,
param_schema (JSONB), param_defaults (JSONB), sort_order, is_active
```

### `policy_builder_configs`
```sql
id (PK), tenant_id, action_key, display_name, description,
state ('draft'|'active'|'archived'),
capsule_hash_b64, compiled_at, compiled_by,
activated_at, activated_by,
created_by, created_at, updated_at
```

### `policy_builder_rules`
```sql
id (PK), config_id (FK), template_slug (FK),
param_values (JSONB), display_name, is_enabled, sort_order,
created_at, updated_at
```

### `policy_builder_audit`
```sql
id (PK), tenant_id, config_id, action_key,
event_type, actor_id, actor_email, description, created_at
```

### `eiaa_policies` (extended)
```sql
-- Added columns:
builder_config_id VARCHAR(50) REFERENCES policy_builder_configs(id),
source VARCHAR(20) DEFAULT 'raw_ast'  -- 'raw_ast' | 'builder' | 'yaml_ci'
```

---

## 9. Extension Points

### Adding a New Template
1. Add a row to `policy_templates` in a new migration
2. Add a `compile_<slug>()` function in `policy_builder.rs`
3. Add the slug to the `match` in `compile_template_to_steps()`
4. No API changes required — templates are discovered dynamically

### Adding Full JSON Schema Validation
Replace the lightweight `validate_params()` with the `jsonschema` crate:
```toml
jsonschema = "0.17"
```
```rust
let compiled = jsonschema::JSONSchema::compile(&template.param_schema)?;
compiled.validate(&req.param_values).map_err(|errors| {
    AppError::BadRequest(errors.map(|e| e.to_string()).collect::<Vec<_>>().join("; "))
})?;
```

### UI Integration
The API is designed to be consumed by a React/Vue dashboard:
- `GET /templates` → Template picker with icons and descriptions
- `param_schema` → Auto-generate form fields (react-jsonschema-form compatible)
- `param_defaults` → Pre-fill form with sensible defaults
- `GET /configs/:id/preview` → Live AST preview panel
- `human_summary` → Plain-English policy description for non-technical admins

---

## 10. Relationship to Existing Policy System

| Feature | Raw AST (`/api/eiaa/v1/capsules`) | Policy Builder (`/api/v1/policy-builder`) |
|---------|-----------------------------------|-------------------------------------------|
| **Target persona** | Tenant developers | Tenant admins (no-code) |
| **Input format** | Raw AST JSON / YAML | Template + param values |
| **Flexibility** | Unlimited | Template-constrained |
| **Validation** | Schema check | JSON Schema + semantic |
| **Audit trail** | None | Full `policy_builder_audit` |
| **Preview** | No | Yes (`/preview`) |
| **Output** | `eiaa_capsules` | `eiaa_capsules` (same) |
| **Activation** | `eiaa_policy_activations` | `eiaa_policy_activations` (same) |
| **`eiaa_policies.source`** | `raw_ast` | `builder` |

Both paths produce identical runtime artifacts. The Policy Builder is a **higher-level abstraction** over the same underlying capsule system.