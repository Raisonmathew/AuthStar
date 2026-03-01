# Policy Builder UI — Design Specification

**Version:** 1.0  
**Author:** Principal Architect  
**Date:** 2026-03-01  
**Status:** Approved for Implementation

---

## 1. Design Philosophy

The Policy Builder UI must be usable by **two very different personas**:

| Persona | Mental Model | Needs |
|---|---|---|
| **Tenant Admin** (non-technical) | "I want to block logins from Russia and require MFA for high-risk users" | Plain English labels, guided wizard, no JSON |
| **Tenant Developer** (technical) | "I need to configure a step-up policy for the `transfer_funds` action" | Full control, raw AST export, version diff |

**Core UX principles:**
1. **Progressive disclosure** — simple things are simple; advanced things are accessible but not in the way
2. **Immediate feedback** — every change shows a live preview of what the policy will do
3. **No dead ends** — every error state has a clear recovery path
4. **Confidence before activation** — users must simulate before they can activate
5. **Dark theme** — matches the existing `AdminLayout` (slate-900/slate-950 palette)

---

## 2. Information Architecture

```
/admin/policies                     ← ConfigListPage (replaces AdminPoliciesPage)
/admin/policies/new                 ← CreateConfigModal (inline, not a page)
/admin/policies/:configId           ← ConfigDetailPage
/admin/policies/:configId/simulate  ← SimulatePanel (tab within ConfigDetailPage)
/admin/policies/:configId/versions  ← VersionHistoryPanel (tab within ConfigDetailPage)
/admin/policies/:configId/audit     ← AuditPanel (tab within ConfigDetailPage)
```

The `ConfigDetailPage` is a **tabbed single-page editor** — no navigation away from the config. This keeps context and avoids losing unsaved state.

---

## 3. Screen Designs

### 3.1 ConfigListPage (`/admin/policies`)

**Purpose:** Overview of all policy configs for the tenant.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Policies                                          [+ New Policy]   │
│  Manage authentication and authorization rules for your tenant.     │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  🔐 Sign In                          [ACTIVE v3]  [Edit →]   │
│  │  signin · 2 groups · 5 rules · Activated 2 days ago          │
│  └──────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  📝 Sign Up                          [DRAFT v1]   [Edit →]   │
│  │  signup · 1 group · 2 rules · Never activated                │
│  └──────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  💸 Transfer Funds                   [ACTIVE v2]  [Edit →]   │
│  │  transfer_funds · 3 groups · 8 rules · Activated 1 week ago  │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

**State badges:**
- `DRAFT` → amber/yellow pill
- `ACTIVE` → green pill with version number
- `ARCHIVED` → gray pill (hidden by default, shown via "Show archived" toggle)

**Empty state:**
```
┌─────────────────────────────────────────────────────────────────────┐
│                    🛡️                                               │
│              No policies configured yet                             │
│    Policies control who can sign in, sign up, and perform           │
│    sensitive actions. Create your first policy to get started.      │
│                                                                     │
│                    [Create First Policy]                            │
└─────────────────────────────────────────────────────────────────────┘
```

**Create New Policy modal** (triggered by "+ New Policy" button):
```
┌─────────────────────────────────────────┐
│  Create New Policy                  [×] │
├─────────────────────────────────────────┤
│  Action                                 │
│  ┌─────────────────────────────────┐    │
│  │ Select an action...          ▼  │    │
│  └─────────────────────────────────┘    │
│  The action this policy governs.        │
│                                         │
│  Display Name (optional)                │
│  ┌─────────────────────────────────┐    │
│  │ e.g. "High-Risk Login Policy"   │    │
│  └─────────────────────────────────┘    │
│                                         │
│  Description (optional)                 │
│  ┌─────────────────────────────────┐    │
│  │                                 │    │
│  └─────────────────────────────────┘    │
│                                         │
│  [Cancel]              [Create Policy]  │
└─────────────────────────────────────────┘
```

The action dropdown is populated from `GET /api/v1/policy-builder/actions`. If an action already has a config, it is shown as disabled with "(already configured)" label.

---

### 3.2 ConfigDetailPage (`/admin/policies/:configId`)

This is the main editor. It has a **header bar** and **four tabs**.

#### Header Bar

```
┌─────────────────────────────────────────────────────────────────────┐
│  ← Policies   Sign In Policy                    [DRAFT v2]         │
│               signin · Last edited 5 minutes ago                   │
│                                                                     │
│  [Builder] [Simulate] [Versions] [Audit]        [Compile] [Activate]│
└─────────────────────────────────────────────────────────────────────┘
```

**Header elements:**
- Back link → `/admin/policies`
- Config display name (editable inline — click to edit)
- State badge
- Tab bar: Builder | Simulate | Versions | Audit
- Action buttons (right-aligned):
  - `[Compile]` → calls `POST /configs/:id/compile`, enabled when state is `draft`
  - `[Activate]` → calls `POST /configs/:id/activate`, enabled only after a successful compile (state becomes `compiled`)

**State machine for action buttons:**

```
draft     → [Compile ✓] [Activate ✗ disabled, tooltip: "Compile first"]
compiled  → [Compile ✓] [Activate ✓]
active    → [Compile ✓] [Activate ✗ disabled, tooltip: "Already active"]
```

---

#### Tab 1: Builder

The core editing experience. Three-column layout on desktop, stacked on mobile.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  BUILDER TAB                                                             │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  How this policy works:                                                  │
│  Groups are evaluated in order. Each group checks its rules and          │
│  takes an action (Allow / Deny / Step-Up / Continue).                    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │  GROUP 1: Risk Checks                    [all] → [deny]  [⋮]   │     │
│  │  If ALL rules match → Deny                                      │     │
│  │  ─────────────────────────────────────────────────────────────  │     │
│  │  ┌─────────────────────────────────────────────────────────┐   │     │
│  │  │  🔴 High Risk Score                              [⋮]    │   │     │
│  │  │  Risk score above 80                                     │   │     │
│  │  │  + Add Condition                                         │   │     │
│  │  └─────────────────────────────────────────────────────────┘   │     │
│  │  ┌─────────────────────────────────────────────────────────┐   │     │
│  │  │  🌍 Blocked Countries                            [⋮]    │   │     │
│  │  │  Country is: RU, KP, IR                                  │   │     │
│  │  │  + Add Condition                                         │   │     │
│  │  └─────────────────────────────────────────────────────────┘   │     │
│  │  [+ Add Rule]                                                   │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │  GROUP 2: Step-Up Triggers               [any] → [stepup] [⋮]  │     │
│  │  If ANY rule matches → Require MFA                              │     │
│  │  ─────────────────────────────────────────────────────────────  │     │
│  │  ┌─────────────────────────────────────────────────────────┐   │     │
│  │  │  📱 New Device                                   [⋮]    │   │     │
│  │  │  User is on a new device                                 │   │     │
│  │  │  + Add Condition                                         │   │     │
│  │  └─────────────────────────────────────────────────────────┘   │     │
│  │  [+ Add Rule]                                                   │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                                                          │
│  [+ Add Group]                                                           │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**Group card anatomy:**

```
┌─────────────────────────────────────────────────────────────────────┐
│  ⠿  GROUP 1: Risk Checks                                            │
│     ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│     │ Match: [ALL ▼]   │  │ On Match: [DENY▼]│  │ [⋮ Options]  │  │
│     └──────────────────┘  └──────────────────┘  └───────────────┘  │
│     ─────────────────────────────────────────────────────────────   │
│     [rules here]                                                    │
│     [+ Add Rule from Template]                                      │
└─────────────────────────────────────────────────────────────────────┘
```

- `⠿` = drag handle for reordering groups
- `Match` dropdown: `ALL rules must match` / `ANY rule must match`
- `On Match` dropdown: `Allow` / `Deny` / `Require Step-Up` / `Continue to next group`
- When `Require Step-Up` is selected, a secondary field appears: `Step-Up Methods` (multi-select: TOTP, SMS, Passkey, Email)
- `[⋮ Options]` menu: Rename, Disable/Enable, Delete

**Rule card anatomy:**

```
┌─────────────────────────────────────────────────────────────────────┐
│  ⠿  🔴 High Risk Score                                    [⋮]      │
│     Template: risk_above · Risk Score Above Threshold               │
│     ─────────────────────────────────────────────────────────────   │
│     Threshold: [80          ]                                       │
│     ─────────────────────────────────────────────────────────────   │
│     Additional Conditions (optional):                               │
│     [+ Add Condition]                                               │
└─────────────────────────────────────────────────────────────────────┘
```

- `⠿` = drag handle for reordering rules within a group
- Template icon comes from `template.icon` field
- Template params are rendered as a **dynamic form** based on `template.param_schema` (JSON Schema → form fields)
- `[⋮]` menu: Rename, Disable/Enable, Delete
- Conditions section is collapsed by default if empty; expands when "+ Add Condition" is clicked

**"Add Rule" flow — Template Picker:**

Clicking `[+ Add Rule from Template]` opens a slide-over panel:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Choose a Rule Template                                         [×] │
├─────────────────────────────────────────────────────────────────────┤
│  🔍 [Search templates...                                        ]   │
│                                                                     │
│  RISK                                                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  📊 Risk Score Above    Block high-risk logins              │   │
│  │  Trigger when risk score exceeds a threshold                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  📊 Risk Score Below    Allow low-risk logins               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  LOCATION                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  🌍 Country Is          Block or allow by country           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  🌍 Country Is Not      Allow only specific countries       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  DEVICE                                                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  📱 New Device          Detect first-time device logins     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  NETWORK                                                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  🔒 VPN Detected        Detect VPN/proxy usage              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  🧅 Tor Exit Node       Detect Tor browser usage            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  🌐 IP In Range         Allow/block by IP CIDR              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  AUTHENTICATION                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  🔐 Assurance Level     Require MFA level                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  ✉️  Email Not Verified  Require email verification         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  TIME                                                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  🕐 Outside Time Window  Block off-hours access             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  ✈️  Impossible Travel   Detect impossible location jumps   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

Clicking a template immediately adds the rule to the group with default param values and closes the panel. The user then edits the params inline.

**Condition row anatomy (within a rule):**

```
  [condition_type ▼]  [params...]  [AND/OR ▼]  [×]
```

Example for `risk_above`:
```
  [Risk Score Above ▼]  Threshold: [80]  [AND ▼]  [×]
  [Country Is ▼]        Countries: [RU, KP]        [×]
```

The last condition has no AND/OR selector. Conditions are chained with the `next_operator` field.

---

#### Tab 2: Simulate

**Purpose:** Test the policy against a synthetic context before activating. This is the "confidence gate" — users should run at least one simulation before activating.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  SIMULATE TAB                                                            │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Test your policy against a hypothetical user context.                   │
│  No real users are affected.                                             │
│                                                                          │
│  ┌─────────────────────────────────┐  ┌──────────────────────────────┐  │
│  │  TEST CONTEXT                   │  │  RESULT                      │  │
│  │                                 │  │                              │  │
│  │  Risk Score                     │  │  (run a simulation to see    │  │
│  │  [────────●──────] 65           │  │   results here)              │  │
│  │                                 │  │                              │  │
│  │  Country Code                   │  │                              │  │
│  │  [US              ]             │  │                              │  │
│  │                                 │  │                              │  │
│  │  ☐ New Device                   │  │                              │  │
│  │  ☐ Email Verified               │  │                              │  │
│  │  ☐ VPN Detected                 │  │                              │  │
│  │  ☐ Tor Detected                 │  │                              │  │
│  │  ☐ Impossible Travel            │  │                              │  │
│  │                                 │  │                              │  │
│  │  AAL Level                      │  │                              │  │
│  │  [1 ▼]                          │  │                              │  │
│  │                                 │  │                              │  │
│  │  Current Hour (0-23)            │  │                              │  │
│  │  [14             ]              │  │                              │  │
│  │                                 │  │                              │  │
│  │  IP Address (optional)          │  │                              │  │
│  │  [192.168.1.1     ]             │  │                              │  │
│  │                                 │  │                              │  │
│  │  User Roles                     │  │                              │  │
│  │  [member ▼] [+ Add]             │  │                              │  │
│  │                                 │  │                              │  │
│  │  Custom Claims (optional)       │  │                              │  │
│  │  [key] = [value]  [+ Add]       │  │                              │  │
│  │                                 │  │                              │  │
│  │  [Run Simulation →]             │  │                              │  │
│  └─────────────────────────────────┘  └──────────────────────────────┘  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**After simulation runs — Result panel:**

```
┌──────────────────────────────────────────────────────────────────────────┐
│  RESULT                                                                  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  ❌  DENY                                                        │   │
│  │  This user would be blocked from signing in.                     │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Why?                                                                    │
│  • Group "Risk Checks" matched (ALL rules matched)                       │
│  • Rule "High Risk Score" matched: risk score 65 > threshold 60          │
│  • Group action: Deny                                                    │
│                                                                          │
│  Group Trace                                                             │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  ✓ GROUP 1: Risk Checks                    MATCHED → DENY        │   │
│  │    ✓ High Risk Score                       matched               │   │
│  │    ✗ Blocked Countries                     not matched           │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  — GROUP 2: Step-Up Triggers               SKIPPED (early exit)  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**Decision color coding:**
- `ALLOW` → green background, ✅ icon
- `DENY` → red background, ❌ icon
- `STEPUP` → amber background, 🔐 icon

**Quick scenario presets** (above the form):
```
  Presets: [Normal User] [High Risk] [New Device] [Blocked Country] [VPN User]
```
Each preset fills in the form with a representative context so users can quickly test common scenarios.

---

#### Tab 3: Versions

```
┌──────────────────────────────────────────────────────────────────────────┐
│  VERSION HISTORY                                                         │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  v3  ● ACTIVE    Compiled by alice@acme.com  2 days ago          │   │
│  │  SHA: a3f9b2c1...                            [View] [Export AST] │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  v2  ○ inactive  Compiled by alice@acme.com  1 week ago          │   │
│  │  SHA: 7d4e1a09...                [View] [Diff vs v3] [Rollback]  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  v1  ○ inactive  Compiled by bob@acme.com    2 weeks ago         │   │
│  │  SHA: 2b8f3d77...                [View] [Diff vs v3] [Rollback]  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**Rollback confirmation modal:**
```
┌─────────────────────────────────────────────────────────────────────┐
│  Rollback to v2?                                                [×] │
├─────────────────────────────────────────────────────────────────────┤
│  This will:                                                         │
│  1. Create a new version (v4) from v2's snapshot                    │
│  2. Activate v4 immediately                                         │
│  3. The current active version (v3) will become inactive            │
│                                                                     │
│  This action is logged in the audit trail.                          │
│                                                                     │
│  [Cancel]                              [Confirm Rollback]           │
└─────────────────────────────────────────────────────────────────────┘
```

**Diff view** (shown in a modal or slide-over):
```
┌─────────────────────────────────────────────────────────────────────┐
│  Diff: v2 → v3                                              [×]    │
├─────────────────────────────────────────────────────────────────────┤
│  3 changes                                                          │
│                                                                     │
│  MODIFIED  groups[0].rules[0].param_values.threshold                │
│  - 60                                                               │
│  + 80                                                               │
│                                                                     │
│  ADDED     groups[1].rules[1]                                       │
│  + { template: "vpn_detected", display_name: "VPN Check" }         │
│                                                                     │
│  MODIFIED  groups[0].on_match                                       │
│  - "continue"                                                       │
│  + "deny"                                                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

#### Tab 4: Audit

```
┌──────────────────────────────────────────────────────────────────────────┐
│  AUDIT LOG                                                               │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  2026-03-01 12:30  alice@acme.com  config_activated    v3 activated      │
│  2026-03-01 12:28  alice@acme.com  config_compiled     v3 compiled       │
│  2026-03-01 12:15  alice@acme.com  rule_updated        "High Risk Score" │
│  2026-02-28 09:00  bob@acme.com    config_compiled     v2 compiled       │
│  2026-02-28 08:55  bob@acme.com    group_added         "Step-Up Triggers"│
│                                                                          │
│  [Load more]                                                             │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Hierarchy

```
features/policy-builder/
├── types.ts                    ← TypeScript types mirroring backend types.rs
├── api.ts                      ← All API calls (replaces lib/api/policies.ts)
├── hooks/
│   ├── useConfigs.ts           ← useQuery for config list
│   ├── useConfigDetail.ts      ← useQuery for single config with groups/rules
│   ├── useTemplates.ts         ← useQuery for template list (cached)
│   └── useActions.ts           ← useQuery for action list (cached)
├── pages/
│   ├── ConfigListPage.tsx      ← /admin/policies
│   └── ConfigDetailPage.tsx    ← /admin/policies/:configId (tabs)
├── components/
│   ├── ConfigCard.tsx          ← Card in the list page
│   ├── CreateConfigModal.tsx   ← New policy modal
│   ├── GroupCard.tsx           ← Collapsible group with rules
│   ├── RuleCard.tsx            ← Rule with param form + conditions
│   ├── ConditionRow.tsx        ← Single condition with type picker + params
│   ├── TemplatePicker.tsx      ← Slide-over template browser
│   ├── ParamForm.tsx           ← Dynamic form from JSON Schema
│   ├── SimulatePanel.tsx       ← Simulate tab content
│   ├── VersionHistoryPanel.tsx ← Versions tab content
│   ├── AuditPanel.tsx          ← Audit tab content
│   ├── StateBadge.tsx          ← DRAFT/ACTIVE/ARCHIVED pill
│   ├── CompileButton.tsx       ← Compile with loading/error state
│   └── ActivateButton.tsx      ← Activate with confirmation modal
└── index.ts                    ← Re-exports
```

---

## 5. API Client Design (`features/policy-builder/api.ts`)

All calls go to `/api/v1/policy-builder/*`. The base URL is handled by the existing `api` axios instance from `lib/api.ts`.

```typescript
// Configs
listConfigs(): Promise<ConfigSummary[]>
createConfig(req: CreateConfigRequest): Promise<ConfigDetail>
getConfig(id: string): Promise<ConfigDetail>
updateConfig(id: string, req: UpdateConfigRequest): Promise<void>
archiveConfig(id: string): Promise<void>

// Groups
addGroup(configId: string, req: AddGroupRequest): Promise<GroupDetail>
updateGroup(configId: string, groupId: string, req: UpdateGroupRequest): Promise<void>
removeGroup(configId: string, groupId: string): Promise<void>
reorderGroups(configId: string, order: string[]): Promise<void>

// Rules
addRule(configId: string, groupId: string, req: AddRuleRequest): Promise<RuleDetail>
updateRule(configId: string, groupId: string, ruleId: string, req: UpdateRuleRequest): Promise<void>
removeRule(configId: string, groupId: string, ruleId: string): Promise<void>
reorderRules(configId: string, groupId: string, order: string[]): Promise<void>

// Conditions
addCondition(configId: string, groupId: string, ruleId: string, req: AddConditionRequest): Promise<ConditionDetail>
updateCondition(configId: string, groupId: string, ruleId: string, condId: string, req: UpdateConditionRequest): Promise<void>
removeCondition(configId: string, groupId: string, ruleId: string, condId: string): Promise<void>

// Compile / Simulate / Activate
previewConfig(id: string): Promise<PreviewResponse>
simulateConfig(id: string, context: TestContext): Promise<SimulateResponse>
compileConfig(id: string): Promise<CompileResponse>
activateConfig(id: string): Promise<void>

// Versions
listVersions(id: string): Promise<VersionSummary[]>
getVersion(id: string, versionId: string): Promise<VersionDetail>
rollbackVersion(id: string, versionId: string): Promise<void>
diffVersions(id: string, versionId: string, compareToId?: string): Promise<DiffResponse>
exportVersionAst(id: string, versionId: string): Promise<object>

// Templates & Actions
listTemplates(): Promise<TemplateItem[]>
listActions(): Promise<ActionItem[]>
listConditionTypes(): Promise<ConditionTypeItem[]>

// Audit
getConfigAudit(id: string, params?: AuditQueryParams): Promise<AuditPage>
```

---

## 6. State Management Strategy

**No Redux/Zustand.** Use React Query (`@tanstack/react-query`) for server state + local `useState` for UI state.

```
Server state (React Query):
  - Config list → useQuery(['configs'])
  - Config detail → useQuery(['config', configId])
  - Templates → useQuery(['templates'], { staleTime: 5 * 60 * 1000 })  // 5 min cache
  - Actions → useQuery(['actions'], { staleTime: 5 * 60 * 1000 })

Local UI state (useState):
  - Active tab
  - Which group/rule is expanded
  - Template picker open/closed
  - Simulate form values
  - Simulate result
  - Compile/activate loading states
```

**Optimistic updates:** For add/remove/reorder operations, update the local cache immediately and roll back on error. This makes the UI feel instant.

**Invalidation strategy:**
- After any mutation (add group, update rule, etc.) → invalidate `['config', configId]`
- After compile/activate → invalidate `['config', configId]` + `['configs']`

---

## 7. Dynamic Param Form (`ParamForm.tsx`)

This is the most technically interesting component. It renders a form from a JSON Schema object.

**Supported field types:**

| JSON Schema type | UI control |
|---|---|
| `number` / `integer` | Number input or slider (if `minimum`/`maximum` present) |
| `string` (no enum) | Text input |
| `string` (with enum) | Select dropdown |
| `boolean` | Toggle switch |
| `array` of strings | Tag input (type and press Enter) |
| `array` of enum strings | Multi-select checkboxes |

**Examples:**

`risk_above` param schema → `{ threshold: number (0-100) }`:
```
  Risk Threshold
  [────────────●──] 80
  0                100
```

`country_in` param schema → `{ countries: string[] }`:
```
  Countries
  [RU ×] [KP ×] [IR ×] [type country code...]
```

`outside_time_window` param schema → `{ allowed_days, start_hour, end_hour, timezone }`:
```
  Allowed Days
  [☑ Mon] [☑ Tue] [☑ Wed] [☑ Thu] [☑ Fri] [☐ Sat] [☐ Sun]

  Hours
  From [09] to [17]

  Timezone
  [America/New_York ▼]
```

`aal_below` param schema → `{ level: integer (1-3) }`:
```
  Minimum AAL Level
  ○ 1 — Password only
  ● 2 — Password + MFA
  ○ 3 — Hardware key
```

---

## 8. UX Micro-interactions

### 8.1 Compile Flow

```
User clicks [Compile]
  → Button shows spinner: "Compiling..."
  → POST /configs/:id/compile
  → On success:
      - Button returns to normal
      - State badge changes from DRAFT to COMPILED
      - [Activate] button becomes enabled
      - Toast: "✅ Compiled successfully — v3 ready to activate"
  → On error:
      - Button returns to normal
      - Inline error banner below header: "Compilation failed: [error message]"
```

### 8.2 Activate Flow

```
User clicks [Activate]
  → Confirmation modal appears:
      "Activate v3?
       This will replace the currently active version (v2) immediately.
       All new authentication requests will use this policy.
       [Cancel] [Activate Now]"
  → User confirms
  → Button shows spinner: "Activating..."
  → POST /configs/:id/activate
  → On success:
      - State badge changes to ACTIVE v3
      - Toast: "🚀 Policy activated — v3 is now live"
      - [Activate] button becomes disabled
  → On error:
      - Toast error: "Activation failed: [error]"
```

### 8.3 Unsaved Changes Warning

Since all mutations are sent immediately to the API (no "save" button), there are no unsaved changes. Each field change triggers an API call. This is the **auto-save model** — same as Notion, Linear, etc.

Visual feedback for auto-save:
- After a successful mutation: brief "✓ Saved" indicator near the changed field (fades after 2s)
- During mutation: field shows a subtle loading ring
- On error: field shows red border + inline error message

### 8.4 Empty Group State

```
┌─────────────────────────────────────────────────────────────────────┐
│  GROUP 1: Untitled Group                                            │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                     │
│  No rules yet. Add a rule to define when this group matches.        │
│                                                                     │
│  [+ Add Rule from Template]                                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Accessibility

- All interactive elements have `aria-label` attributes
- Keyboard navigation: Tab through all controls, Enter to activate buttons
- Drag-and-drop reordering has keyboard alternative: up/down arrow buttons in the `[⋮]` menu
- Color is never the only indicator of state (icons + text always accompany color)
- Focus management: when a modal opens, focus moves to the first interactive element; when it closes, focus returns to the trigger

---

## 10. Responsive Behavior

| Breakpoint | Layout |
|---|---|
| `lg` (≥1024px) | Full three-column layout for Simulate tab; groups/rules full width |
| `md` (768-1023px) | Simulate: stacked (context above, result below); groups full width |
| `sm` (<768px) | All stacked; template picker becomes bottom sheet instead of slide-over |

---

## 11. What Happens to the Old Policy UI

The existing files are **replaced**, not deleted:

| Old file | Action |
|---|---|
| `pages/AdminPoliciesPage.tsx` | Replace with import of new `ConfigListPage` |
| `features/policies/PolicyEditor.tsx` | Delete (raw JSON editor — replaced by builder) |
| `features/policies/PolicyEditorPage.tsx` | Delete (called old `/admin/v1/policies` API) |
| `features/policies/VisualPolicyEditor.tsx` | Delete (ReactFlow canvas — wrong data model) |
| `features/policies/types.ts` | Delete (replaced by `features/policy-builder/types.ts`) |
| `lib/api/policies.ts` | Delete (replaced by `features/policy-builder/api.ts`) |

The route `/admin/policies` stays the same — only the component it renders changes.

---

## 12. Implementation Order

Build in this order to always have a working (if incomplete) UI:

1. **`types.ts`** — TypeScript types (no dependencies)
2. **`api.ts`** — API client (depends on `lib/api.ts`)
3. **`hooks/`** — React Query hooks (depends on api.ts)
4. **`StateBadge.tsx`** — Simple display component
5. **`ConfigListPage.tsx`** + `ConfigCard.tsx` + `CreateConfigModal.tsx` — List page works end-to-end
6. **`ConfigDetailPage.tsx`** — Shell with tabs (no content yet)
7. **`ParamForm.tsx`** — Dynamic form (standalone, testable)
8. **`TemplatePicker.tsx`** — Template browser slide-over
9. **`ConditionRow.tsx`** — Single condition editor
10. **`RuleCard.tsx`** — Rule with params + conditions
11. **`GroupCard.tsx`** — Group with rules
12. **Builder tab** — Wire GroupCard into ConfigDetailPage
13. **`SimulatePanel.tsx`** — Simulate tab
14. **`VersionHistoryPanel.tsx`** — Versions tab
15. **`AuditPanel.tsx`** — Audit tab
16. **`CompileButton.tsx` + `ActivateButton.tsx`** — Header actions
17. **Wire into `App.tsx`** — Add routes, update AdminLayout nav

---

## 13. Dependencies Required

Check `frontend/package.json` — if not already present, these need to be added:

| Package | Purpose | Already present? |
|---|---|---|
| `@tanstack/react-query` | Server state management | Check |
| `react-router-dom` | Routing | ✅ (used in App.tsx) |
| `sonner` | Toast notifications | ✅ (used in App.tsx) |
| `@dnd-kit/core` + `@dnd-kit/sortable` | Drag-and-drop reordering | Check |

ReactFlow is **not needed** — the new builder is a structured form, not a canvas.

---

## 14. Key Design Decisions & Rationale

| Decision | Rationale |
|---|---|
| Auto-save (no Save button) | Eliminates "lost work" anxiety; matches modern SaaS UX (Notion, Linear) |
| Simulate before Activate | Prevents accidental lockouts; builds user confidence |
| Template picker as slide-over | Keeps context visible; user can see the group they're adding to |
| Dynamic form from JSON Schema | Single source of truth — backend schema drives UI; no duplication |
| Tabs not separate pages | Keeps config context; avoids navigation state loss |
| React Query not Redux | Server state is the source of truth; no need for client-side store |
| Replace old UI entirely | Old UI is a raw JSON textarea — not user-friendly; no migration path |
| Keep `/admin/policies` route | Zero disruption to existing bookmarks/navigation |