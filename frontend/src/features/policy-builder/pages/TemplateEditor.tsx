/**
 * TemplateEditor.tsx
 *
 * A structured-form policy editor that lets tenant admins build EIAA policies
 * without writing JSON AST.  The editor:
 *
 *   1. Presents a form-based interface for selecting templates and configuring params.
 *   2. Converts form state to builder-format payloads via templateToAst.ts.
 *   3. POSTs to /compile to produce a server-validated capsule.
 *   4. Shows a Test Console (simulate) before unlocking the Deploy button.
 *   5. POSTs to /activate (with expected_version for optimistic-lock safety).
 *
 * Does NOT use /import-ast — that endpoint skips capsule compilation.
 */

import { useState, useCallback } from 'react';
import { toast } from 'sonner';
import * as pbApi from '../api';
import type { ConfigDetail, SimulateRequest } from '../types';
import {
  BUILT_IN_TEMPLATES,
  templateFormToBuilderPayload,
  type TemplateGroup,
  type TemplateRule,
} from '../lib/templateToAst';

// ─── Props ────────────────────────────────────────────────────────────────────

interface TemplateEditorProps {
  config: ConfigDetail;
  onPolicyDeployed: () => void;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function ParamField({
  paramKey,
  label,
  type,
  value,
  onChange,
}: {
  paramKey: string;
  label: string;
  type: 'number' | 'boolean' | 'string';
  value: unknown;
  onChange: (key: string, val: unknown) => void;
}) {
  if (type === 'boolean') {
    return (
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={Boolean(value)}
          onChange={(e) => onChange(paramKey, e.target.checked)}
          className="rounded border-gray-300"
        />
        {label}
      </label>
    );
  }
  if (type === 'number') {
    return (
      <div className="flex flex-col gap-1">
        <label className="text-xs text-gray-500">{label}</label>
        <input
          type="number"
          className="border rounded px-2 py-1 text-sm w-28"
          value={Number(value ?? 0)}
          onChange={(e) => onChange(paramKey, Number(e.target.value))}
        />
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs text-gray-500">{label}</label>
      <input
        type="text"
        className="border rounded px-2 py-1 text-sm w-48"
        value={String(value ?? '')}
        onChange={(e) => onChange(paramKey, e.target.value)}
      />
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function TemplateEditor({ config, onPolicyDeployed }: TemplateEditorProps) {
  const [groups, setGroups] = useState<TemplateGroup[]>([
    {
      displayName: 'Default policy',
      matchMode: 'any',
      onMatch: 'deny',
      onNoMatch: 'allow',
      rules: [],
    },
  ]);

  const [compileResult, setCompileResult] = useState<{
    versionNumber: number;
    versionId: string;
    warnings: string[];
  } | null>(null);

  const [simulateResult, setSimulateResult] = useState<{
    decision: string;
    explanation: string[];
  } | null>(null);

  const [deploying, setDeploying] = useState(false);
  const [compiling, setCompiling] = useState(false);
  const [simulating, setSimulating] = useState(false);

  // ─── Group mutation helpers ─────────────────────────────────────────────────

  const addGroup = useCallback(() => {
    setGroups((prev) => [
      ...prev,
      {
        displayName: `Group ${prev.length + 1}`,
        matchMode: 'any',
        onMatch: 'deny',
        onNoMatch: 'allow',
        rules: [],
      },
    ]);
    // Adding a group changes the policy — clear compile result to force re-compile.
    setCompileResult(null);
    setSimulateResult(null);
  }, []);

  const removeGroup = useCallback((groupIndex: number) => {
    setGroups((prev) => prev.filter((_, i) => i !== groupIndex));
    setCompileResult(null);
    setSimulateResult(null);
  }, []);

  const updateGroup = useCallback(
    (groupIndex: number, patch: Partial<TemplateGroup>) => {
      setGroups((prev) =>
        prev.map((g, i) => (i === groupIndex ? { ...g, ...patch } : g))
      );
      setCompileResult(null);
      setSimulateResult(null);
    },
    []
  );

  const addRule = useCallback((groupIndex: number, templateSlug: string) => {
    const tpl = BUILT_IN_TEMPLATES.find((t) => t.slug === templateSlug);
    if (!tpl) return;
    const rule: TemplateRule = {
      templateSlug,
      displayName: tpl.label,
      params: { ...tpl.defaultParams },
      enabled: true,
    };
    setGroups((prev) =>
      prev.map((g, i) =>
        i === groupIndex ? { ...g, rules: [...g.rules, rule] } : g
      )
    );
    setCompileResult(null);
    setSimulateResult(null);
  }, []);

  const removeRule = useCallback((groupIndex: number, ruleIndex: number) => {
    setGroups((prev) =>
      prev.map((g, i) =>
        i === groupIndex
          ? { ...g, rules: g.rules.filter((_, ri) => ri !== ruleIndex) }
          : g
      )
    );
    setCompileResult(null);
    setSimulateResult(null);
  }, []);

  const updateRuleParam = useCallback(
    (groupIndex: number, ruleIndex: number, key: string, value: unknown) => {
      setGroups((prev) =>
        prev.map((g, i) =>
          i === groupIndex
            ? {
                ...g,
                rules: g.rules.map((r, ri) =>
                  ri === ruleIndex
                    ? { ...r, params: { ...r.params, [key]: value } }
                    : r
                ),
              }
            : g
        )
      );
      setCompileResult(null);
      setSimulateResult(null);
    },
    []
  );

  // ─── Step 1: Apply template form to the existing config via API ─────────────
  // We POST each group and rule to the builder API, then compile.

  const applyAndCompile = useCallback(async () => {
    setCompiling(true);
    setCompileResult(null);
    setSimulateResult(null);
    try {
      const payload = templateFormToBuilderPayload({
        actionKey: config.action_key,
        groups,
      });

      // Delete existing groups first (clean slate).
      for (const existingGroup of config.groups ?? []) {
        await pbApi.removeGroup(config.id, existingGroup.id);
      }

      // Create new groups + rules.
      for (const { group: groupPayload, rules: rulePaylods } of payload.groups) {
        const created = await pbApi.addGroup(config.id, {
          display_name: groupPayload.display_name,
          description: groupPayload.description,
          match_mode: groupPayload.match_mode,
          on_match: groupPayload.on_match,
          on_no_match: groupPayload.on_no_match,
          stepup_methods: groupPayload.stepup_methods,
        });

        for (const rulePayload of rulePaylods) {
          await pbApi.addRule(config.id, created.id, {
            template_slug: rulePayload.template_slug,
            display_name: rulePayload.display_name,
            param_values: rulePayload.param_values,
            is_enabled: rulePayload.is_enabled,
            sort_order: rulePayload.sort_order,
          });
        }
      }

      // Compile — this creates a version snapshot server-side.
      const compiled = await pbApi.compileConfig(config.id);
      setCompileResult({
        versionNumber: compiled.version_number,
        versionId: compiled.version_id,
        warnings: compiled.warnings,
      });
      if (compiled.warnings.length > 0) {
        toast.warning(`Compiled with ${compiled.warnings.length} warning(s)`);
      } else {
        toast.success(`Policy compiled (v${compiled.version_number})`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Compilation failed';
      toast.error(msg);
    } finally {
      setCompiling(false);
    }
  }, [config, groups]);

  // ─── Step 2: Simulate (Test Console) ───────────────────────────────────────

  const runSimulate = useCallback(async () => {
    setSimulating(true);
    setSimulateResult(null);
    try {
      const simReq: SimulateRequest = {
        context: {
          risk_score: 0,
          aal_level: 1,
          is_new_device: false,
          email_verified: true,
          vpn_detected: false,
          tor_detected: false,
          impossible_travel: false,
        },
      };
      const result = await pbApi.simulateConfig(config.id, simReq);
      setSimulateResult({
        decision: result.decision,
        explanation: result.human_explanation,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Simulation failed';
      toast.error(msg);
    } finally {
      setSimulating(false);
    }
  }, [config.id]);

  // ─── Step 3: Deploy (activate) ─────────────────────────────────────────────
  // Passes expected_version for optimistic-lock safety (Issue 1-B-2).

  const deploy = useCallback(async () => {
    if (!compileResult || !simulateResult) return;
    setDeploying(true);
    try {
      await pbApi.activateConfig(config.id, {
        expected_version: config.active_version ?? undefined,
      });
      toast.success('Policy deployed successfully');
      onPolicyDeployed();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Deployment failed';
      // Surface optimistic-lock conflict with a clear message.
      if (msg.toLowerCase().includes('conflict') || msg.includes('409')) {
        toast.error('Policy was updated in another tab — reload to continue.');
      } else {
        toast.error(msg);
      }
    } finally {
      setDeploying(false);
    }
  }, [compileResult, simulateResult, config.id, config.active_version, onPolicyDeployed]);

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-700">Template Editor</h3>
        <div className="flex gap-2">
          <button
            onClick={applyAndCompile}
            disabled={compiling || groups.every((g) => g.rules.length === 0)}
            className="px-3 py-1.5 text-sm rounded bg-blue-600 text-white disabled:opacity-50 hover:bg-blue-700"
          >
            {compiling ? 'Compiling…' : 'Compile'}
          </button>
          {compileResult && (
            <button
              onClick={runSimulate}
              disabled={simulating}
              className="px-3 py-1.5 text-sm rounded bg-gray-100 text-gray-700 hover:bg-gray-200 disabled:opacity-50"
            >
              {simulating ? 'Running…' : 'Test'}
            </button>
          )}
          <button
            onClick={deploy}
            disabled={
              deploying ||
              !compileResult ||
              !simulateResult ||
              simulateResult.decision === 'deny'
            }
            className="px-3 py-1.5 text-sm rounded bg-green-600 text-white disabled:opacity-50 hover:bg-green-700"
          >
            {deploying ? 'Deploying…' : 'Deploy'}
          </button>
        </div>
      </div>

      {/* Groups */}
      {groups.map((group, gi) => (
        <GroupForm
          key={gi}
          group={group}
          groupIndex={gi}
          onUpdateGroup={(patch) => updateGroup(gi, patch)}
          onAddRule={(slug) => addRule(gi, slug)}
          onRemoveRule={(ri) => removeRule(gi, ri)}
          onUpdateRuleParam={(ri, key, val) => updateRuleParam(gi, ri, key, val)}
          onRemoveGroup={() => removeGroup(gi)}
        />
      ))}

      <button
        onClick={addGroup}
        className="text-sm text-blue-600 hover:underline"
      >
        + Add group
      </button>

      {/* Compile result */}
      {compileResult && (
        <div className="rounded border border-green-200 bg-green-50 px-4 py-3 text-sm">
          <p className="font-medium text-green-800">
            ✓ Compiled — version {compileResult.versionNumber}
          </p>
          {compileResult.warnings.length > 0 && (
            <ul className="mt-2 list-disc pl-4 text-yellow-700">
              {compileResult.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          )}
          <p className="mt-2 text-gray-500">
            Run a test before deploying to verify behaviour.
          </p>
        </div>
      )}

      {/* Simulate result */}
      {simulateResult && (
        <div
          className={`rounded border px-4 py-3 text-sm ${
            simulateResult.decision === 'allow'
              ? 'border-green-200 bg-green-50'
              : simulateResult.decision === 'deny'
              ? 'border-red-200 bg-red-50'
              : 'border-yellow-200 bg-yellow-50'
          }`}
        >
          <p className="font-semibold uppercase tracking-wide text-xs text-gray-500 mb-1">
            Simulation result
          </p>
          <p className="font-bold text-lg">
            {simulateResult.decision.toUpperCase()}
          </p>
          <ul className="mt-2 space-y-0.5 text-gray-600">
            {simulateResult.explanation.map((line, i) => (
              <li key={i} className="font-mono text-xs">
                {line}
              </li>
            ))}
          </ul>
          {simulateResult.decision === 'deny' && (
            <p className="mt-2 text-red-600 text-xs">
              ⚠ Default test context was denied. Adjust rules before deploying.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── GroupForm ────────────────────────────────────────────────────────────────

interface GroupFormProps {
  group: TemplateGroup;
  groupIndex: number;
  onUpdateGroup: (patch: Partial<TemplateGroup>) => void;
  onAddRule: (slug: string) => void;
  onRemoveRule: (ruleIndex: number) => void;
  onUpdateRuleParam: (ruleIndex: number, key: string, value: unknown) => void;
  onRemoveGroup: () => void;
}

function GroupForm({
  group,
  groupIndex: _groupIndex,
  onUpdateGroup,
  onAddRule,
  onRemoveRule,
  onUpdateRuleParam,
  onRemoveGroup,
}: GroupFormProps) {
  const [showTemplatePicker, setShowTemplatePicker] = useState(false);

  return (
    <div className="rounded border border-gray-200 bg-gray-50 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <input
          className="text-sm font-medium border-0 bg-transparent focus:outline-none focus:ring-1 ring-blue-300 rounded px-1"
          value={group.displayName}
          onChange={(e) => onUpdateGroup({ displayName: e.target.value })}
        />
        <button
          onClick={onRemoveGroup}
          className="text-xs text-gray-400 hover:text-red-500"
        >
          Remove group
        </button>
      </div>

      <div className="flex gap-4 flex-wrap text-sm">
        <label className="flex items-center gap-1.5 text-gray-600">
          Match mode
          <select
            className="border rounded px-1 py-0.5 text-sm"
            value={group.matchMode}
            onChange={(e) =>
              onUpdateGroup({ matchMode: e.target.value as 'all' | 'any' })
            }
          >
            <option value="all">All (AND)</option>
            <option value="any">Any (OR)</option>
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-gray-600">
          On match
          <select
            className="border rounded px-1 py-0.5 text-sm"
            value={group.onMatch}
            onChange={(e) =>
              onUpdateGroup({
                onMatch: e.target.value as TemplateGroup['onMatch'],
              })
            }
          >
            <option value="continue">Continue</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="stepup">Step-up MFA</option>
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-gray-600">
          On no-match
          <select
            className="border rounded px-1 py-0.5 text-sm"
            value={group.onNoMatch}
            onChange={(e) =>
              onUpdateGroup({
                onNoMatch: e.target.value as TemplateGroup['onNoMatch'],
              })
            }
          >
            <option value="continue">Continue</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="stepup">Step-up MFA</option>
          </select>
        </label>
      </div>

      {/* Rules */}
      <div className="space-y-2">
        {group.rules.length === 0 && (
          <p className="text-xs text-gray-400 italic">
            No rules yet — add a template below.
          </p>
        )}
        {group.rules.map((rule, ri) => {
          const tpl = BUILT_IN_TEMPLATES.find((t) => t.slug === rule.templateSlug);
          return (
            <div
              key={ri}
              className="rounded border border-gray-200 bg-white p-3 space-y-2"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{rule.displayName}</span>
                <button
                  onClick={() => onRemoveRule(ri)}
                  className="text-xs text-gray-400 hover:text-red-500"
                >
                  ✕
                </button>
              </div>
              {tpl &&
                tpl.paramSchema.map((param) => (
                  <ParamField
                    key={param.key}
                    paramKey={param.key}
                    label={param.label}
                    type={param.type}
                    value={rule.params[param.key] ?? tpl.defaultParams[param.key]}
                    onChange={(key, val) => onUpdateRuleParam(ri, key, val)}
                  />
                ))}
            </div>
          );
        })}
      </div>

      {/* Template picker */}
      {showTemplatePicker ? (
        <div className="rounded border border-blue-100 bg-blue-50 p-3 space-y-2">
          <p className="text-xs font-medium text-blue-700">Select a template:</p>
          <div className="grid grid-cols-2 gap-2">
            {BUILT_IN_TEMPLATES.map((tpl) => (
              <button
                key={tpl.slug}
                onClick={() => {
                  onAddRule(tpl.slug);
                  setShowTemplatePicker(false);
                }}
                className="text-left rounded border border-blue-200 bg-white px-3 py-2 text-sm hover:bg-blue-50"
              >
                <span className="font-medium">{tpl.label}</span>
                <span className="block text-xs text-gray-500 mt-0.5 line-clamp-1">
                  {tpl.description}
                </span>
              </button>
            ))}
          </div>
          <button
            onClick={() => setShowTemplatePicker(false)}
            className="text-xs text-gray-400 hover:text-gray-600"
          >
            Cancel
          </button>
        </div>
      ) : (
        <button
          onClick={() => setShowTemplatePicker(true)}
          className="text-sm text-blue-600 hover:underline"
        >
          + Add rule from template
        </button>
      )}
    </div>
  );
}
