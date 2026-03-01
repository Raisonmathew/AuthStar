# Unified Policy Builder — Architecture Design Document

**Version:** 2.0  
**Status:** Implemented  
**Author:** Principal Software Engineer / Architect  
**Date:** 2026-03-01  

---

## 1. Executive Summary

The Unified Policy Builder (UPB) is a no-code/low-code policy configuration system for the AuthStar IDaaS platform. It replaces the previous raw-AST-only policy management approach with a structured, visual-friendly API that serves all personas — from platform engineers to tenant developers to non-technical tenant admins — through a single unified system with permission tiers.

The UPB enables tenant admins to configure authentication and authorization policies (e.g., "require MFA for admin logins from new devices", "block logins from sanctioned countries") without writing WASM capsule code or understanding the internal AST format.

---

## 2. Design Goals

| Goal | Description |
|------|-------------|
| **Persona-unified** | One API, one data model, one UI surface for all user types |
| **Permission-tiered** | Platform admins, tenant admins, and tenant developers each have appropriate access |
| **No-code first** | Tenant admins configure policies through templates and visual rule groups |
| **Developer escape hatch** | Raw AST import/export for CI/CD pipelines and advanced use cases |
| **Immutable audit trail** | Every change, compile, activation, and rollback is logged |
| **Safe activation** | Preview → Simulate → Compile → Activate workflow prevents accidental breakage |
| **Rollback** | Any previous version can be reactivated in one API call |

---

## 3. Permission Tier Model

```
PlatformAdmin ⊃ TenantAdmin ⊃ TenantDeveloper
```

### Tier Derivation (from JWT claims, no DB lookup)

```rust
pub enum Tier {
    TenantDeveloper = 0,  // Any authenticated user with policies:manage EIAA action
    TenantAdmin     = 1,  // role = "owner" | "admin"
    PlatformAdmin   = 2,  // tenant_id = "system" AND role = "owner" | "admin"
}
```

### Tier Capabilities

| Operation | TenantDeveloper | TenantAdmin | PlatformAdmin |
|-----------|:-:|:-:|:-:|
| List/read templates | ✓ | ✓ | ✓ (all, incl. deprecated) |
| Create platform template | ✗ | ✗ | ✓ |
| Create tenant-custom template | ✗ | ✓ | ✓ |
| Update/deprecate platform template | ✗ | ✗ | ✓ |
| Update/deprecate own custom template | ✗ | ✓ | ✓ |
| List/read configs | ✓ | ✓ | ✓ |
| Create/update/archive config | ✗ | ✓ | ✓ |
| Add/update/remove rule groups | ✗ | ✓ | ✓ |
| Add/update/remove rules | ✗ | ✓ | ✓ |
| Add/update/remove conditions | ✗ | ✓ | ✓ |
| Preview config (dry AST) | ✓ | ✓ | ✓ |
| Simulate config | ✓ | ✓ | ✓ |
| Compile config | ✗ | ✓ | ✓ |
| Activate config | ✗ | ✓ | ✓ |
| Rollback to previous version | ✗ | ✓ | ✓ |
| Import raw AST | ✗ | ✓ | ✓ |
| Export AST | ✓ | ✓ | ✓ |
| View config audit log | ✗ | ✓ | ✓ |
| View tenant audit log | ✗ | ✓ | ✓ |
| List/create/delete custom actions | ✗ | ✓ | ✓ |

---

## 4. Data Model

### 4.1 Entity Relationship

```
policy_actions (platform + tenant-custom)
    │
    └── policy_builder_configs (one per tenant+action)
            │
            ├── policy_builder_versions (immutable snapshots)
            │
            ├── policy_builder_rule_groups (ordered, AND/OR logic)
            │       │
            │       └── policy_builder_rules (template + params)
            │               │
            │               └── policy_builder_conditions (composable, AND/OR chain)
            │
            └── policy_builder_audit (immutable event log)

policy_templates (platform + tenant-custom)
    └── referenced by policy_builder_rules.template_slug
```

### 4.2 Table Descriptions

#### `policy_actions`
The registry of all EIAA action keys. Platform actions (e.g., `auth:login`, `auth:mfa_enroll`) are seeded by migration. Tenant admins can register custom actions.

Key columns:
- `action_key` — unique per (tenant_id, action_key); platform actions have `tenant_id = NULL`
- `is_platform` — true for built-in platform actions
- `category` — groups actions in the UI (auth, admin, org, billing, api)

#### `policy_templates`
Reusable policy building blocks. Platform templates (owner_tenant_id = NULL) are managed by platform admins. Tenant-custom templates are scoped to a single tenant.

Key columns:
- `slug` — primary key, human-readable identifier (e.g., `require_mfa`, `geo_restriction`)
- `param_schema` — JSON Schema (react-jsonschema-form compatible) for validating `param_values`
- `param_defaults` — default values merged with user-provided `param_values`
- `supported_conditions` — condition types that make semantic sense for this template (UI hint)
- `applicable_actions` — empty = applies to all actions; non-empty = restricted to listed actions
- `is_deprecated` — soft-delete; existing rules continue to work, new rules cannot use deprecated templates

#### `policy_builder_configs`
One config per (tenant, action). The config is the top-level container for all rule groups, rules, and conditions for a given action.

State machine:
```
draft → compiled → active
  ↑         ↓
  └─────────┘ (edit after compile resets to draft)
  
archived (terminal — no further modifications)
```

Key columns:
- `draft_version` — increments on each compile; used as the version_number for new snapshots
- `active_version` — the currently live version number (NULL if never activated)
- `active_capsule_hash_b64` — SHA-256 of the active AST, base64-encoded
- `activated_at` / `activated_by` — activation audit fields

#### `policy_builder_versions`
Immutable snapshots created by every compile, AST import, or rollback. Never updated after creation.

Key columns:
- `version_number` — monotonically increasing per config
- `rule_snapshot` — JSONB snapshot of the full rule tree at compile time (for diff/rollback)
- `ast_snapshot` — the generated AST JSON (what the capsule runtime executes)
- `ast_hash_b64` — SHA-256 of canonical AST JSON, base64-encoded (integrity verification)
- `source` — `'builder'` | `'ast_import'` | `'rollback'`

#### `policy_builder_rule_groups`
Logical containers within a config. Groups are evaluated in `sort_order` (ascending). Each group has AND/OR match logic and configurable outcomes.

Key columns:
- `match_mode` — `'all'` (AND) or `'any'` (OR) — how rules within the group are combined
- `on_match` — outcome when the group condition IS met: `continue | deny | stepup | allow`
- `on_no_match` — outcome when the group condition is NOT met: `continue | deny | stepup | allow`
- `stepup_methods` — MFA methods to offer when outcome is `stepup`

#### `policy_builder_rules`
Individual policy rules within a group. Each rule references a template and provides `param_values` that override the template's `param_defaults`.

Key columns:
- `template_slug` — FK to `policy_templates`
- `param_values` — JSONB, validated against `template.param_schema` at write time
- `sort_order` — evaluation order within the group

#### `policy_builder_conditions`
Composable conditions attached to rules. Conditions are evaluated left-to-right with AND/OR chaining via `next_operator`.

Key columns:
- `condition_type` — one of 16 supported types (see §5)
- `condition_params` — type-specific parameters (validated at write time)
- `next_operator` — `'and'` | `'or'` | NULL (last condition)
- `sort_order` — evaluation order within the rule

#### `policy_builder_audit`
Immutable event log. Every mutation (create, update, delete, compile, activate, rollback, simulate) writes an audit entry. Fire-and-forget — non-fatal on failure.

---

## 5. Condition Type Catalog

16 built-in condition types, all validated at write time and compile time:

| Type | Required Params | Description |
|------|----------------|-------------|
| `risk_above` | `threshold: f64` | Risk score > threshold (0–100) |
| `risk_below` | `threshold: f64` | Risk score < threshold (0–100) |
| `country_in` | `countries: [String]` | ISO-3166 alpha-2 country codes |
| `country_not_in` | `countries: [String]` | ISO-3166 alpha-2 country codes |
| `new_device` | _(none)_ | Device fingerprint not previously seen |
| `aal_below` | `level: i64` (1–3) | Session AAL below required level |
| `outside_time_window` | `start_hour`, `end_hour`, `timezone` | Outside allowed hours |
| `impossible_travel` | `max_speed_kmh: f64` | Travel speed exceeds threshold |
| `email_not_verified` | _(none)_ | User email not verified |
| `role_in` | `roles: [String]` | User role is in list |
| `role_not_in` | `roles: [String]` | User role is not in list |
| `vpn_detected` | _(none)_ | IP identified as VPN exit node |
| `tor_detected` | _(none)_ | IP identified as Tor exit node |
| `ip_in_range` | `cidr: String` | IP within CIDR range |
| `ip_not_in_range` | `cidr: String` | IP not within CIDR range |
| `custom_claim` | `claim_key`, `claim_value` | JWT claim key equals value |

### Condition Evaluation Semantics

Conditions within a rule are evaluated left-to-right using flat boolean logic:

```
result = eval(cond[0])
for i in 1..n:
    if cond[i-1].next_op == "and":
        result = result AND eval(cond[i])
    else:  // "or"
        result = result OR eval(cond[i])
```

For grouped sub-expressions (e.g., `(A AND B) OR (C AND D)`), use multiple rule groups.

---

## 6. API Surface

Base path: `POST /api/v1/policy-builder/...`  
Auth: JWT Bearer token (or API key) + EIAA action `policies:manage`

### 6.1 Templates

```
GET    /templates                          → List templates (filtered by tier)
POST   /templates                          → Create template (TenantAdmin+)
GET    /templates/:slug                    → Get template detail
PUT    /templates/:slug                    → Update template (ownership-checked)
DELETE /templates/:slug                    → Soft-deprecate template (ownership-checked)
GET    /templates/:slug/conditions         → List supported condition types for template
```

### 6.2 Condition Types

```
GET    /condition-types                    → Full catalog of all 16 condition types
```

### 6.3 Actions

```
GET    /actions                            → List platform + tenant-custom actions
POST   /actions                            → Register custom action (TenantAdmin+)
PUT    /actions/:id                        → Update custom action (TenantAdmin+)
DELETE /actions/:id                        → Delete custom action (TenantAdmin+, not in use)
```

### 6.4 Configs

```
GET    /configs                            → List configs for tenant
POST   /configs                            → Create config (TenantAdmin+)
GET    /configs/:id                        → Get config with full rule tree
PUT    /configs/:id                        → Update display_name/description (TenantAdmin+)
DELETE /configs/:id                        → Archive config (TenantAdmin+)
```

### 6.5 Rule Groups

```
POST   /configs/:id/groups                 → Add group (TenantAdmin+)
PUT    /configs/:id/groups/:gid            → Update group (TenantAdmin+)
DELETE /configs/:id/groups/:gid            → Remove group + cascade (TenantAdmin+)
POST   /configs/:id/groups/reorder         → Reorder groups (TenantAdmin+)
```

### 6.6 Rules

```
POST   /configs/:id/groups/:gid/rules                → Add rule (TenantAdmin+)
PUT    /configs/:id/groups/:gid/rules/:rid            → Update rule (TenantAdmin+)
DELETE /configs/:id/groups/:gid/rules/:rid            → Remove rule (TenantAdmin+)
POST   /configs/:id/groups/:gid/rules/reorder         → Reorder rules (TenantAdmin+)
```

### 6.7 Conditions

```
POST   /configs/:id/groups/:gid/rules/:rid/conditions          → Add condition (TenantAdmin+)
PUT    /configs/:id/groups/:gid/rules/:rid/conditions/:cid     → Update condition (TenantAdmin+)
DELETE /configs/:id/groups/:gid/rules/:rid/conditions/:cid     → Remove condition (TenantAdmin+)
POST   /configs/:id/groups/:gid/rules/:rid/conditions/reorder  → Reorder conditions (TenantAdmin+)
```

### 6.8 Compile / Preview / Simulate / Activate

```
GET    /configs/:id/preview                → Preview AST (all tiers, no persist)
POST   /configs/:id/simulate               → Simulate against TestContext (all tiers)
POST   /configs/:id/compile                → Compile + snapshot (TenantAdmin+)
POST   /configs/:id/activate               → Activate latest compiled version (TenantAdmin+)
POST   /configs/:id/import-ast             → Import raw AST (TenantAdmin+)
GET    /configs/:id/export-ast             → Export active/latest AST (all tiers)
```

### 6.9 Version History

```
GET    /configs/:id/versions               → List all versions
GET    /configs/:id/versions/:vid          → Get version detail with snapshots
POST   /configs/:id/versions/:vid/rollback → Rollback to version (TenantAdmin+)
POST   /configs/:id/versions/:vid/diff     → Diff two versions
GET    /configs/:id/versions/:vid/export-ast → Export specific version AST
```

### 6.10 Audit

```
GET    /configs/:id/audit                  → Config-scoped audit (TenantAdmin+)
GET    /audit                              → Tenant-wide audit (TenantAdmin+)
```

---

## 7. Compile / Activate Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Policy Builder Workflow                       │
│                                                                  │
│  1. Create Config                                                │
│     POST /configs  →  state: 'draft'                            │
│                                                                  │
│  2. Build Rule Tree                                              │
│     POST /configs/:id/groups                                     │
│     POST /configs/:id/groups/:gid/rules                         │
│     POST /configs/:id/groups/:gid/rules/:rid/conditions         │
│     (any edit resets state to 'draft')                          │
│                                                                  │
│  3. Preview (optional, non-destructive)                          │
│     GET /configs/:id/preview  →  returns AST + warnings         │
│                                                                  │
│  4. Simulate (optional, non-destructive)                         │
│     POST /configs/:id/simulate  →  decision + trace             │
│                                                                  │
│  5. Compile                                                      │
│     POST /configs/:id/compile                                    │
│     →  creates immutable version snapshot                        │
│     →  state: 'compiled'                                        │
│     →  draft_version++                                          │
│                                                                  │
│  6. Activate                                                     │
│     POST /configs/:id/activate                                   │
│     →  state: 'active'                                          │
│     →  active_version = latest compiled version                 │
│     →  active_capsule_hash_b64 = SHA-256 of AST                 │
│                                                                  │
│  7. Rollback (if needed)                                         │
│     POST /configs/:id/versions/:vid/rollback                    │
│     →  creates new version with source='rollback'               │
│     →  immediately activates it                                 │
│     →  full audit trail preserved                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. AST Format

The compiled AST is the canonical JSON representation consumed by the capsule runtime:

```json
{
  "version": 2,
  "action": "auth:login",
  "groups": [
    {
      "id": "pbg_abc123",
      "display_name": "High-Risk Block",
      "match_mode": "any",
      "on_match": "deny",
      "on_no_match": "continue",
      "stepup_methods": [],
      "rules": [
        {
          "id": "pbr_def456",
          "template": "block_high_risk",
          "display_name": "Block Critical Risk",
          "params": { "block_threshold": 90, "stepup_threshold": 60 },
          "conditions": [
            {
              "type": "risk_above",
              "params": { "threshold": 60.0 },
              "next_op": "or"
            },
            {
              "type": "tor_detected",
              "params": {},
              "next_op": null
            }
          ]
        }
      ]
    },
    {
      "id": "pbg_ghi789",
      "display_name": "New Device Step-Up",
      "match_mode": "all",
      "on_match": "stepup",
      "on_no_match": "continue",
      "stepup_methods": ["totp", "passkey"],
      "rules": [
        {
          "id": "pbr_jkl012",
          "template": "new_device_stepup",
          "display_name": "Require MFA on New Device",
          "params": { "stepup_methods": ["totp", "passkey"], "device_trust_days": 30 },
          "conditions": [
            {
              "type": "new_device",
              "params": {},
              "next_op": null
            }
          ]
        }
      ]
    }
  ]
}
```

### AST Evaluation Semantics

Groups are evaluated in order. For each group:
1. Evaluate all rules according to `match_mode` (AND/OR)
2. If group matched → apply `on_match` outcome
3. If group did not match → apply `on_no_match` outcome
4. Outcomes: `continue` (next group), `deny` (immediate block), `allow` (immediate pass), `stepup` (require MFA)
5. If all groups return `continue` → default: **allow**

---

## 9. Simulation Engine

The simulation endpoint (`POST /configs/:id/simulate`) runs the compiled AST against a synthetic `TestContext` without touching the live authorization system.

### TestContext Fields

```json
{
  "risk_score":        85.0,
  "country_code":      "RU",
  "is_new_device":     true,
  "email_verified":    false,
  "vpn_detected":      false,
  "tor_detected":      false,
  "aal_level":         1,
  "current_hour":      14,
  "impossible_travel": false,
  "user_roles":        ["developer"],
  "ip_address":        "203.0.113.42",
  "custom_claims":     { "app_tier": "free" }
}
```

All fields are optional. Omitted fields are treated as "unknown" / safe defaults.

### Simulation Response

```json
{
  "config_id":    "pbc_xxx",
  "action_key":   "auth:login",
  "decision":     "deny",
  "groups_evaluated": [
    {
      "group_id":     "pbg_abc123",
      "display_name": "High-Risk Block",
      "matched":      true,
      "outcome":      "deny",
      "rules": [
        { "rule_id": "pbr_def456", "display_name": "Block Critical Risk", "matched": true }
      ]
    }
  ],
  "human_explanation": [
    "Group 'High-Risk Block' (pbg_abc123): 1 rules evaluated, group MATCHED → outcome: DENY",
    "→ DENY: request blocked."
  ],
  "test_context": { ... }
}
```

---

## 10. Version Diff

The diff endpoint compares two version snapshots and returns a structured list of changes:

```json
{
  "from_version_id":     "pbv_v3",
  "from_version_number": 3,
  "to_version_id":       "pbv_v2",
  "to_version_number":   2,
  "changes_count":       3,
  "changes": [
    {
      "change_type": "rule_added",
      "path":        "groups/pbg_abc/rules/pbr_new",
      "description": "Rule 'Block Tor Traffic' was added to group 'High-Risk Block'",
      "from_value":  null,
      "to_value":    { ... }
    },
    {
      "change_type": "field_changed",
      "path":        "pbr_def/param_values",
      "description": "Field 'param_values' changed on entity 'pbr_def'",
      "from_value":  { "block_threshold": 80 },
      "to_value":    { "block_threshold": 90 }
    }
  ]
}
```

Change types: `group_added`, `group_removed`, `rule_added`, `rule_removed`, `condition_added`, `condition_removed`, `field_changed`

---

## 11. Platform Templates (9 Built-In)

| Slug | Category | Description |
|------|----------|-------------|
| `require_mfa` | mfa | Require MFA with configurable methods and grace period |
| `enforce_aal` | mfa | Enforce minimum Authentication Assurance Level (AAL1/2/3) |
| `block_high_risk` | risk | Block or step-up based on risk score thresholds |
| `impossible_travel` | risk | Detect and respond to impossible travel events |
| `require_email_verified` | identity | Block unverified email users |
| `geo_restriction` | geo | Allow/block by country (allowlist or blocklist mode) |
| `new_device_stepup` | device | Step-up MFA on unrecognized devices |
| `time_based_access` | time | Restrict to business hours / specific days |
| `allow_all` | access | Explicit allow for authenticated users |

---

## 12. Module Structure

```
routes/policy_builder/
├── mod.rs                    ← Router (35+ endpoints)
├── permissions.rs            ← Tier enum, ownership verification, audit writer
├── types.rs                  ← All request/response structs
├── templates.rs              ← Template CRUD + condition type metadata
├── actions.rs                ← Action registry CRUD
├── configs.rs                ← Config CRUD + load_groups_with_rules + load_rules_for_group
├── groups.rs                 ← Rule group CRUD + reorder
├── rules.rs                  ← Rule CRUD + reorder + param validation
├── conditions.rs             ← Condition CRUD + reorder + condition type catalog
├── compile.rs                ← Preview / Simulate / Compile / Activate / Import-AST / Export-AST
├── versions.rs               ← Version history / Rollback / Diff / Per-version export
├── audit.rs                  ← Config audit + tenant audit (cursor-based pagination)
└── compiler/
    ├── mod.rs                ← compile_config_to_ast(), validate_ast()
    └── condition_compiler.rs ← compile_conditions(), evaluate_conditions(), SimulationContext
```

---

## 13. Security Considerations

### 13.1 Tenant Isolation
Every query is scoped to `tenant_id` from JWT claims. `verify_config_ownership()` enforces this at the config level. Cross-tenant access is structurally impossible.

### 13.2 EIAA Authorization
All policy builder endpoints require the `policies:manage` EIAA action, which is itself enforced by the capsule runtime. This means policy management is itself subject to policy — a meta-authorization property.

### 13.3 Permission Tier Enforcement
Tier is derived from JWT claims at request time (no DB lookup). Write operations require `TenantAdmin` tier minimum. Platform template management requires `PlatformAdmin` tier.

### 13.4 Archived Config Protection
Archived configs cannot be modified. All mutation handlers check `config.state == "archived"` and return `400 Bad Request`.

### 13.5 Template Deprecation (Soft Delete)
Templates are never hard-deleted. Deprecated templates continue to work in existing rules but cannot be used in new rules. This prevents breaking existing configs.

### 13.6 AST Integrity
Every compiled version stores a SHA-256 hash of the canonical AST JSON (`ast_hash_b64`). This enables integrity verification when loading a version for activation or rollback.

### 13.7 Audit Trail
Every mutation writes to `policy_builder_audit`. The audit log is append-only (no UPDATE/DELETE). Audit writes are fire-and-forget (non-fatal) to avoid blocking the primary operation.

---

## 14. Integration with EIAA Pipeline

The policy builder produces AST snapshots that are stored in `policy_builder_versions`. The activation step writes the `active_capsule_hash_b64` to `policy_builder_configs`.

The `eiaa_policies` table has been extended with:
- `builder_config_id` — FK to the policy builder config that generated this policy
- `builder_version_id` — FK to the specific version
- `source` — `'raw_ast'` | `'builder'` | `'yaml_ci'` | `'rollback'`

This enables the EIAA pipeline to trace every authorization decision back to the specific policy builder version that was active at the time.

---

## 15. Known Limitations and Future Work

| Item | Priority | Notes |
|------|----------|-------|
| Full JSON Schema validation for `param_values` | Medium | Currently validates required fields only; full schema validation would use a JSON Schema library |
| IPv6 CIDR support in simulation | Low | Simulation engine uses simplified IPv4-only CIDR matching; production runtime handles IPv6 |
| Condition grouping (parentheses) | Medium | Currently flat AND/OR chain; grouped sub-expressions require multiple rule groups |
| Template versioning | Low | Templates are not versioned; a template change affects all rules using it |
| Policy testing framework integration | High | Simulation results should be storable as regression test cases |
| UI component library | High | React component library consuming this API (separate project) |
| Webhook on activation | Medium | Notify downstream systems when a policy is activated |
| Policy inheritance | Low | Allow configs to inherit from a parent config (for multi-tenant hierarchies) |

---

## 16. Bug Fixes Applied (Post-Implementation Review)

The following bugs were identified and fixed during the principal architect review:

| Bug | File | Issue | Fix |
|-----|------|-------|-----|
| BUG-1 | `templates.rs` | `aal_below` condition metadata used `"minimum_aal"` param key; compiler and conditions.rs used `"level"` | Standardized on `"level"` in templates.rs |
| BUG-2 | `templates.rs` | `impossible_travel` condition metadata used `"max_velocity_km_per_hour"`; compiler and conditions.rs used `"max_speed_kmh"` | Standardized on `"max_speed_kmh"` in templates.rs |
| BUG-3 | `templates.rs` | `ip_in_range`/`ip_not_in_range` condition metadata used `"cidr_ranges"` (array); compiler and conditions.rs used `"cidr"` (single string) | Standardized on `"cidr"` (single string) in templates.rs |
| BUG-4 | `templates.rs` | `custom_claim` condition metadata used `"claim_path"/"operator"/"value"`; compiler and conditions.rs used `"claim_key"/"claim_value"` | Standardized on `"claim_key"/"claim_value"` in templates.rs |
| BUG-5 | `rules.rs` | `template.param_schema` and `template.param_defaults` used directly as `serde_json::Value`; sqlx returns `Option<serde_json::Value>` for JSONB columns | Added `.unwrap_or_else(|| serde_json::json!({}))` for both fields |
| BUG-6 | `migration 040` | Bogus indexes `idx_pb_versions_tenant` and `idx_pb_versions_active` referenced non-existent columns `tenant_id` and `activated_at` on `policy_builder_versions` | Replaced with correct `idx_pb_versions_number ON policy_builder_versions(config_id, version_number DESC)` |
| BUG-7 | `configs.rs` | `get_config` handler returned `activated_at: None` hardcoded | Fixed to fetch `activated_at` from DB and return it |