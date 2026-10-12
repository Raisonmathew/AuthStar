/**
 * templateToAst.ts
 *
 * Converts a high-level "template form" definition (produced by the TemplateEditor UI)
 * into the server-side group/rule payload accepted by:
 *
 *   POST /api/v1/policy-builder/groups          → GroupDetail
 *   POST /api/v1/policy-builder/groups/:id/rules → RuleDetail
 *
 * IMPORTANT: This module produces *builder-format* JSON (groups + rules), NOT raw
 * AST JSON.  The builder payload is sent to the /compile endpoint which then calls
 * capsule_compiler::compile() server-side and returns a CapsuleSigned.
 *
 * Do NOT send the output of this module to /import-ast — that endpoint expects a
 * raw EIAA AST and does not produce a live WASM capsule at import time.
 */

// ─── Template form types ──────────────────────────────────────────────────────

/** A single rule entry in the template editor form. */
export interface TemplateRule {
  /** Template slug (e.g. "block_high_risk"). */
  templateSlug: string;
  /** User-visible label for this rule. */
  displayName: string;
  /** Param values for the template (e.g. { block_threshold: 80 }). */
  params: Record<string, unknown>;
  enabled: boolean;
}

/** A group of rules in the template editor. */
export interface TemplateGroup {
  displayName: string;
  description?: string;
  /** 'all' = AND, 'any' = OR */
  matchMode: 'all' | 'any';
  /** Action taken when the group condition is met. */
  onMatch: 'continue' | 'deny' | 'allow' | 'stepup';
  /** Action taken when the group condition is NOT met. */
  onNoMatch: 'continue' | 'deny' | 'allow' | 'stepup';
  /** Step-up MFA methods (only meaningful when onMatch = 'stepup'). */
  stepupMethods?: string[];
  rules: TemplateRule[];
}

/** The root structure produced by the TemplateEditor form. */
export interface TemplatePolicyForm {
  /** Maps to the config's action_key (e.g. "billing:read"). */
  actionKey: string;
  groups: TemplateGroup[];
}

// ─── Builder payload types (match backend AddGroupRequest / AddRuleRequest) ───

export interface BuilderGroupPayload {
  display_name: string;
  description: string;
  match_mode: 'all' | 'any';
  on_match: 'continue' | 'deny' | 'allow' | 'stepup';
  on_no_match: 'continue' | 'deny' | 'allow' | 'stepup';
  stepup_methods: string[];
}

export interface BuilderRulePayload {
  template_slug: string;
  display_name: string;
  param_values: Record<string, unknown>;
  is_enabled: boolean;
  sort_order: number;
}

export interface BuilderFormPayload {
  actionKey: string;
  groups: Array<{
    group: BuilderGroupPayload;
    rules: BuilderRulePayload[];
  }>;
}

// ─── Conversion ───────────────────────────────────────────────────────────────

/**
 * Convert a TemplatePolicyForm into a BuilderFormPayload ready to send to
 * the policy builder API.
 *
 * The return value contains one entry per group, each with the group metadata
 * and an ordered list of rule payloads.
 */
export function templateFormToBuilderPayload(form: TemplatePolicyForm): BuilderFormPayload {
  const groups = form.groups.map((g) => ({
    group: {
      display_name: g.displayName,
      description: g.description ?? '',
      match_mode: g.matchMode,
      on_match: g.onMatch,
      on_no_match: g.onNoMatch,
      stepup_methods: g.stepupMethods ?? [],
    } satisfies BuilderGroupPayload,
    rules: g.rules.map((r, i) => ({
      template_slug: r.templateSlug,
      display_name: r.displayName,
      param_values: r.params,
      is_enabled: r.enabled,
      sort_order: i,
    }) satisfies BuilderRulePayload),
  }));

  return { actionKey: form.actionKey, groups };
}

// ─── Built-in template catalogue ─────────────────────────────────────────────

/** Starter templates a user can pick from in the TemplateEditor. */
export const BUILT_IN_TEMPLATES: ReadonlyArray<{
  slug: string;
  label: string;
  description: string;
  defaultParams: Record<string, unknown>;
  paramSchema: Array<{ key: string; label: string; type: 'number' | 'boolean' | 'string' }>;
}> = [
  {
    slug: 'block_high_risk',
    label: 'Block high-risk requests',
    description: 'Deny requests above a risk score threshold; require MFA above a lower threshold.',
    defaultParams: { block_threshold: 80, stepup_threshold: 50 },
    paramSchema: [
      { key: 'block_threshold', label: 'Block threshold (0–100)', type: 'number' },
      { key: 'stepup_threshold', label: 'Step-up threshold (0–100)', type: 'number' },
    ],
  },
  {
    slug: 'impossible_travel',
    label: 'Deny impossible travel',
    description: 'Deny requests that the risk engine flags as geographically impossible.',
    defaultParams: {},
    paramSchema: [],
  },
  {
    slug: 'new_device_stepup',
    label: 'Step-up on new device',
    description: 'Require MFA when the request comes from an unrecognised device.',
    defaultParams: {},
    paramSchema: [],
  },
  {
    slug: 'time_based_access',
    label: 'Time-based access window',
    description: 'Restrict access to specific hours of the day.',
    defaultParams: { start_hour: 9, end_hour: 17 },
    paramSchema: [
      { key: 'start_hour', label: 'Start hour (0–23)', type: 'number' },
      { key: 'end_hour', label: 'End hour (0–23)', type: 'number' },
    ],
  },
  {
    slug: 'require_verified_email',
    label: 'Require verified email',
    description: 'Deny requests from users who have not verified their email address.',
    defaultParams: {},
    paramSchema: [],
  },
  {
    slug: 'vpn_tor_detection',
    label: 'Block VPN / Tor',
    description: 'Deny requests originating from known VPN or Tor exit nodes.',
    defaultParams: {},
    paramSchema: [],
  },
  {
    slug: 'allow_all',
    label: 'Allow all (starter / no-op)',
    description: 'Unconditionally allow this action. Use as the first policy before customising.',
    defaultParams: {},
    paramSchema: [],
  },
] as const;
