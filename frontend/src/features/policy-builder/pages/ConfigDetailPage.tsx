/**
 * ConfigDetailPage — tabbed editor for a single policy config.
 *
 * Tabs:
 *  - builder   → groups list with GroupCard components
 *  - simulate  → SimulatePanel
 *  - versions  → VersionHistoryPanel
 *  - audit     → AuditPanel
 *
 * Header:
 *  - Back link to /admin/policies
 *  - Inline-editable display name
 *  - StateBadge
 *  - Compile button (enabled when state === 'draft')
 *  - Activate button (enabled when state === 'compiled') + confirmation modal
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { getApiError } from '../../../lib/api';
import { useParams, Link } from 'react-router-dom';
import { toast } from 'sonner';
import type { ConfigDetail, TemplateItem, ConditionTypeItem } from '../types';
import * as pbApi from '../api';
import { StateBadge } from '../components/StateBadge';
import { GroupCard } from '../components/GroupCard';
import { SimulatePanel } from '../components/SimulatePanel';
import { VersionHistoryPanel } from '../components/VersionHistoryPanel';
import { AuditPanel } from '../components/AuditPanel';
import { NlCompilePanel } from '../components/NlCompilePanel';

// ============================================================================
// AddGroupModal
// ============================================================================

interface AddGroupModalProps {
  onClose: () => void;
  onAdd: (req: {
    display_name: string;
    description: string;
    match_mode: 'all' | 'any';
    on_match: 'continue' | 'deny' | 'stepup' | 'allow';
    on_no_match: 'continue' | 'deny' | 'stepup' | 'allow';
    stepup_methods: string[];
  }) => Promise<void>;
}

const STEPUP_METHOD_OPTIONS = [
  { value: 'totp',      label: 'Authenticator App (TOTP)' },
  { value: 'email_otp', label: 'Email OTP' },
  { value: 'sms_otp',   label: 'SMS Code' },
  { value: 'passkey',   label: 'Passkey (WebAuthn)' },
  { value: 'password',  label: 'Password re-entry' },
];

function AddGroupModal({ onClose, onAdd }: AddGroupModalProps) {
  const [displayName, setDisplayName] = useState('');
  const [description, setDescription] = useState('');
  const [matchMode, setMatchMode] = useState<'all' | 'any'>('all');
  const [onMatch, setOnMatch] = useState<'continue' | 'deny' | 'stepup' | 'allow'>('continue');
  const [onNoMatch, setOnNoMatch] = useState<'continue' | 'deny' | 'stepup' | 'allow'>('continue');
  const [stepupMethods, setStepupMethods] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const needsStepup = onMatch === 'stepup' || onNoMatch === 'stepup';

  const toggleStepupMethod = (method: string) => {
    setStepupMethods((prev) =>
      prev.includes(method) ? prev.filter((m) => m !== method) : [...prev, method]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!displayName.trim()) {
      setError('Display name is required.');
      return;
    }
    if (needsStepup && stepupMethods.length === 0) {
      setError('Select at least one step-up method.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onAdd({
        display_name: displayName.trim(),
        description: description.trim(),
        match_mode: matchMode,
        on_match: onMatch,
        on_no_match: onNoMatch,
        stepup_methods: needsStepup ? stepupMethods : [],
      });
    } catch (err: any) {
      setError(getApiError(err, 'Failed to add group.'));
      setSaving(false);
    }
  };

  const selectClass =
    'w-full bg-muted border border-border rounded-xl px-3 py-2.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-transparent';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <h2 className="text-base font-semibold text-foreground">Add Rule Group</h2>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-foreground mb-1.5">
              Display Name <span className="text-destructive">*</span>
            </label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. High-Risk Checks"
              autoFocus
              className="w-full bg-muted border border-border rounded-xl px-3 py-2.5 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-transparent"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-1.5">Description</label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description…"
              className="w-full bg-muted border border-border rounded-xl px-3 py-2.5 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-transparent"
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5">Match Mode</label>
              <select value={matchMode} onChange={(e) => setMatchMode(e.target.value as any)} className={selectClass}>
                <option value="all">All rules</option>
                <option value="any">Any rule</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5">On Match</label>
              <select value={onMatch} onChange={(e) => setOnMatch(e.target.value as any)} className={selectClass}>
                <option value="continue">Continue</option>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
                <option value="stepup">Step-up</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5">On No Match</label>
              <select value={onNoMatch} onChange={(e) => setOnNoMatch(e.target.value as any)} className={selectClass}>
                <option value="continue">Continue</option>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
                <option value="stepup">Step-up</option>
              </select>
            </div>
          </div>

          {needsStepup && (
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5">
                Step-up methods{' '}
                <span className="text-muted-foreground font-normal">(leave empty for any)</span>
              </label>
              <div className="flex flex-col gap-1.5">
                {STEPUP_METHOD_OPTIONS.map((opt) => (
                  <label key={opt.value} className="flex items-center gap-2 text-sm text-foreground cursor-pointer">
                    <input
                      type="checkbox"
                      checked={stepupMethods.includes(opt.value)}
                      onChange={() => toggleStepupMethod(opt.value)}
                      className="w-4 h-4 rounded border-border accent-primary"
                    />
                    {opt.label}
                  </label>
                ))}
              </div>
            </div>
          )}

          {error && (
            <p className="text-sm text-destructive bg-destructive/10 border border-destructive/20 rounded-xl px-3 py-2">
              {error}
            </p>
          )}

          <div className="flex items-center justify-end gap-3 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground bg-accent hover:bg-accent/80 rounded-xl transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !displayName.trim()}
              className="px-4 py-2 text-sm font-medium text-primary-foreground bg-primary hover:bg-primary/90 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {saving ? (
                <>
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Adding…
                </>
              ) : (
                'Add Group'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ============================================================================
// ActivateConfirmModal
// ============================================================================

interface ActivateConfirmModalProps {
  configName: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

function ActivateConfirmModal({ configName, onClose, onConfirm }: ActivateConfirmModalProps) {
  const [activating, setActivating] = useState(false);

  const handleConfirm = async () => {
    setActivating(true);
    try {
      await onConfirm();
    } finally {
      setActivating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-sm bg-card border border-border rounded-2xl shadow-2xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <div>
            <h3 className="text-base font-semibold text-foreground">Activate Policy?</h3>
            <p className="text-xs text-muted-foreground mt-0.5">This will go live immediately</p>
          </div>
        </div>

        <p className="text-sm text-foreground mb-6">
          Activating <span className="font-semibold text-foreground">{configName}</span> will replace
          the currently active policy for this action. All new authentication requests will use
          this policy immediately.
        </p>

        <div className="flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground bg-accent hover:bg-accent/80 rounded-xl transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            disabled={activating}
            className="px-4 py-2 text-sm font-medium text-white bg-emerald-600 hover:bg-emerald-500 rounded-xl transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {activating ? (
              <>
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Activating…
              </>
            ) : (
              'Activate Now'
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// ConfigDetailPage
// ============================================================================

type Tab = 'builder' | 'simulate' | 'versions' | 'audit';

export function ConfigDetailPage() {
  const { configId } = useParams<{ configId: string }>();

  const [config, setConfig] = useState<ConfigDetail | null>(null);
  const [templates, setTemplates] = useState<TemplateItem[]>([]);
  const [conditionTypes, setConditionTypes] = useState<ConditionTypeItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<Tab>('builder');
  const [showAddGroup, setShowAddGroup] = useState(false);
  const [showActivateConfirm, setShowActivateConfirm] = useState(false);
  const [showNlPanel, setShowNlPanel] = useState(false);

  // Inline display name editing
  const [editingName, setEditingName] = useState(false);
  const [nameValue, setNameValue] = useState('');
  const nameInputRef = useRef<HTMLInputElement>(null);

  // Compile state
  const [compiling, setCompiling] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [previewData, setPreviewData] = useState<import('../types').PreviewResponse | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const handlePreview = async () => {
    if (!configId) return;
    if (showPreview) { setShowPreview(false); return; }
    setPreviewLoading(true);
    setShowPreview(true);
    try {
      const result = await pbApi.previewConfig(configId);
      setPreviewData(result);
    } catch {
      setPreviewData(null);
    } finally {
      setPreviewLoading(false);
    }
  };

  const load = useCallback(async () => {
    if (!configId) return;
    setLoading(true);
    setError(null);
    try {
      const [cfg, tmpl, conds] = await Promise.all([
        pbApi.getConfig(configId),
        pbApi.listTemplates(),
        pbApi.listConditionTypes(),
      ]);
      setConfig(cfg);
      setNameValue(cfg.display_name ?? '');
      setTemplates(tmpl);
      setConditionTypes(conds);
    } catch (err: any) {
      setError(getApiError(err, 'Failed to load policy config.'));
    } finally {
      setLoading(false);
    }
  }, [configId]);

  useEffect(() => {
    load();
  }, [load]);

  // Focus name input when editing starts
  useEffect(() => {
    if (editingName) {
      nameInputRef.current?.focus();
      nameInputRef.current?.select();
    }
  }, [editingName]);

  const handleNameSave = async () => {
    if (!config || !configId) return;
    setEditingName(false);
    const trimmed = nameValue.trim();
    if (trimmed === (config.display_name ?? '')) return;
    try {
      await pbApi.updateConfig(configId, { display_name: trimmed || undefined });
      setConfig((prev) => prev ? { ...prev, display_name: trimmed || null } : prev);
    } catch {
      toast.error('Failed to update name');
      setNameValue(config.display_name ?? '');
    }
  };

  const handleCompile = async () => {
    if (!configId) return;
    setCompiling(true);
    try {
      const result = await pbApi.compileConfig(configId);
      if (result.warnings && result.warnings.length > 0) {
        // Show each warning as a separate toast so they don't stack and get missed
        result.warnings.forEach((w) =>
          toast.warning(`Policy warning: ${w}`, { duration: 8000 })
        );
      }
      toast.success(`Compiled successfully — v${result.version_number}`);
      setConfig((prev) => prev ? { ...prev, state: 'compiled', draft_version: result.version_number } : prev);
    } catch (err: any) {
      toast.error(getApiError(err, 'Compile failed'));
    } finally {
      setCompiling(false);
    }
  };

  const handleActivate = async () => {
    if (!configId) return;
    try {
      await pbApi.activateConfig(configId);
      toast.success('Policy activated — now live');
      setShowActivateConfirm(false);
      setConfig((prev) =>
        prev ? { ...prev, state: 'active', active_version: prev.draft_version, activated_at: new Date().toISOString() } : prev
      );
    } catch (err: any) {
      toast.error(getApiError(err, 'Activation failed'));
      setShowActivateConfirm(false);
    }
  };

  // Group mutation callbacks — reload config to get fresh data
  const handleGroupAdded = async (req: Parameters<typeof pbApi.addGroup>[1]) => {
    if (!configId) return;
    await pbApi.addGroup(configId, req);
    toast.success('Group added');
    setShowAddGroup(false);
    await load();
  };

  const handleGroupReorder = async (order: string[]) => {
    if (!configId) return;
    await pbApi.reorderGroups(configId, order);
    setConfig((prev) => {
      if (!prev) return prev;
      const byId = Object.fromEntries(prev.groups.map((g) => [g.id, g]));
      return {
        ...prev,
        groups: order.map((id, i) => ({ ...byId[id], sort_order: i })).filter(Boolean),
      };
    });
  };

  // ---- Render ----

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <svg className="w-8 h-8 animate-spin text-primary" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      </div>
    );
  }

  if (error || !config) {
    return (
      <div className="space-y-4">
        <Link
          to="/admin/policies"
          className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Back to Policies
        </Link>
        <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-xl text-sm text-destructive">
          {error ?? 'Policy config not found.'}
        </div>
      </div>
    );
  }

  const configName = config.display_name || config.action_key;
  const canCompile = config.state === 'draft';
  const canActivate = config.state === 'compiled';

  const tabs: { id: Tab; label: string }[] = [
    { id: 'builder', label: 'Builder' },
    { id: 'simulate', label: 'Simulate' },
    { id: 'versions', label: 'Versions' },
    { id: 'audit', label: 'Audit' },
  ];

  return (
    <div className="space-y-6">
      {/* ── Back link ── */}
      <Link
        to="/admin/policies"
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
        All Policies
      </Link>

      {/* ── Header card ── */}
      <div className="bg-card border border-border rounded-2xl p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          {/* Left: name + action key + state */}
          <div className="flex-1 min-w-0">
            {/* Inline editable name */}
            <div className="flex items-center gap-2 mb-1">
              {editingName ? (
                <input
                  ref={nameInputRef}
                  type="text"
                  value={nameValue}
                  onChange={(e) => setNameValue(e.target.value)}
                  onBlur={handleNameSave}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleNameSave();
                    if (e.key === 'Escape') {
                      setEditingName(false);
                      setNameValue(config.display_name ?? '');
                    }
                  }}
                  className="text-xl font-bold text-foreground bg-muted border border-primary rounded-lg px-2 py-0.5 focus:outline-none focus:ring-2 focus:ring-ring min-w-0 w-full max-w-sm"
                />
              ) : (
                <button
                  type="button"
                  onClick={() => setEditingName(true)}
                  className="text-xl font-bold text-foreground hover:text-primary transition-colors text-left group flex items-center gap-2"
                  title="Click to rename"
                >
                  {configName}
                  <svg
                    className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors flex-shrink-0"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                  </svg>
                </button>
              )}
              <StateBadge state={config.state} />
            </div>

            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <span className="font-mono">{config.action_key}</span>
              {config.active_version && (
                <span className="text-emerald-500">v{config.active_version} active</span>
              )}
              <span>Draft v{config.draft_version}</span>
            </div>
          </div>

          {/* Right: action buttons */}
          <div className="flex items-center gap-2 flex-shrink-0">
            {/* NL Compile */}
            <button
              type="button"
              onClick={() => setShowNlPanel(true)}
              title="Generate policy from plain-English description using AI"
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-xl transition-colors bg-accent hover:bg-accent/80 text-foreground"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.347.346a3.977 3.977 0 01-.982 2.016 1 1 0 01-.718.305H9.718a1 1 0 01-.718-.305 3.976 3.976 0 01-.982-2.016l-.347-.346z" />
              </svg>
              AI Generate
            </button>
            {/* Compile */}
            <button
              type="button"
              onClick={handleCompile}
              disabled={!canCompile || compiling}
              title={!canCompile ? 'Already compiled or active' : 'Compile policy to WASM capsule'}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-xl transition-colors disabled:opacity-40 disabled:cursor-not-allowed bg-primary hover:bg-primary/90 text-primary-foreground"
            >
              {compiling ? (
                <>
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Compiling…
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                  Compile
                </>
              )}
            </button>

            {/* Activate */}
            <button
              type="button"
              onClick={() => setShowActivateConfirm(true)}
              disabled={!canActivate}
              title={!canActivate ? 'Compile first before activating' : 'Activate this policy version'}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-xl transition-colors disabled:opacity-40 disabled:cursor-not-allowed bg-emerald-600 hover:bg-emerald-500 text-white"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              Activate
            </button>
          </div>
        </div>

        {/* Description */}
        {config.description && (
          <p className="mt-3 text-sm text-muted-foreground">{config.description}</p>
        )}
      </div>

      {/* ── Tab bar ── */}
      <div className="flex items-center gap-1 bg-card border border-border rounded-xl p-1 w-fit">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${activeTab === tab.id
              ? 'bg-primary text-primary-foreground shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent'
              }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Tab content ── */}

      {/* Builder tab */}
      {activeTab === 'builder' && (
        <div className="space-y-4">
          {config.groups.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center bg-card border border-border rounded-2xl">
              <div className="w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center mb-4">
                <svg className="w-7 h-7 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                </svg>
              </div>
              <h3 className="text-base font-semibold text-foreground mb-2">No rule groups yet</h3>
              <p className="text-sm text-muted-foreground max-w-xs mb-6">
                Add a rule group to start building your policy. Groups contain rules that are
                evaluated together.
              </p>
              <button
                type="button"
                onClick={() => setShowAddGroup(true)}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-primary-foreground bg-primary hover:bg-primary/90 rounded-xl transition-colors"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                Add First Group
              </button>
            </div>
          ) : (
            <>
              {config.groups.map((group, idx) => (
                <GroupCard
                  key={group.id}
                  group={group}
                  configId={config.id}
                  templates={templates}
                  conditionTypes={conditionTypes}
                  isFirst={idx === 0}
                  isLast={idx === config.groups.length - 1}
                  onUpdated={load}
                  onMoveUp={() => {
                    const order = config.groups.map((g) => g.id);
                    const i = order.indexOf(group.id);
                    if (i > 0) {
                      [order[i - 1], order[i]] = [order[i], order[i - 1]];
                      handleGroupReorder(order);
                    }
                  }}
                  onMoveDown={() => {
                    const order = config.groups.map((g) => g.id);
                    const i = order.indexOf(group.id);
                    if (i < order.length - 1) {
                      [order[i], order[i + 1]] = [order[i + 1], order[i]];
                      handleGroupReorder(order);
                    }
                  }}
                />
              ))}

              {/* Add group button */}
              <button
                type="button"
                onClick={() => setShowAddGroup(true)}
                className="w-full flex items-center justify-center gap-2 py-3 border-2 border-dashed border-border hover:border-primary/50 rounded-2xl text-sm text-muted-foreground hover:text-primary transition-all"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                Add Rule Group
              </button>
            </>
          )}

          {/* ── Preview AST panel ── */}
          {config.groups.length > 0 && (
            <div className="bg-card border border-border rounded-2xl overflow-hidden">
              <button
                type="button"
                onClick={handlePreview}
                className="w-full flex items-center justify-between px-5 py-3 text-sm text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors"
              >
                <span className="flex items-center gap-2 font-medium">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                  </svg>
                  Preview Generated AST
                </span>
                <svg
                  className={`w-4 h-4 transition-transform ${showPreview ? 'rotate-180' : ''}`}
                  fill="none" viewBox="0 0 24 24" stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              {showPreview && (
                <div className="border-t border-border">
                  {previewLoading ? (
                    <div className="flex items-center justify-center py-8">
                      <svg className="w-5 h-5 animate-spin text-primary" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                    </div>
                  ) : previewData ? (
                    <div className="p-4 space-y-3">
                      {previewData.warnings.length > 0 && (
                        <div className="space-y-1">
                          {previewData.warnings.map((w, i) => (
                            <div key={i} className="flex items-start gap-2 text-xs text-yellow-700 bg-yellow-500/10 border border-yellow-500/20 rounded-lg px-3 py-2">
                              <svg className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                              </svg>
                              {w}
                            </div>
                          ))}
                        </div>
                      )}
                      <pre className="text-xs font-mono text-foreground bg-muted rounded-xl p-4 overflow-x-auto max-h-96 border border-border">
                        {JSON.stringify(previewData.ast, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground p-4">Failed to load preview.</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Simulate tab */}
      {activeTab === 'simulate' && configId && (
        <div className="bg-card border border-border rounded-2xl p-6">
          <SimulatePanel configId={configId} />
        </div>
      )}

      {/* Versions tab */}
      {activeTab === 'versions' && configId && (
        <div className="bg-card border border-border rounded-2xl p-6">
          <VersionHistoryPanel
            configId={configId}
            policyName={config?.display_name || config?.action_key || 'policy'}
            onRolledBack={() => {
              load();
              setActiveTab('builder');
            }}
          />
        </div>
      )}

      {/* Audit tab */}
      {activeTab === 'audit' && configId && (
        <div className="bg-card border border-border rounded-2xl p-6">
          <AuditPanel configId={configId} />
        </div>
      )}

      {/* ── Modals ── */}
      {showAddGroup && (
        <AddGroupModal
          onClose={() => setShowAddGroup(false)}
          onAdd={handleGroupAdded}
        />
      )}

      {showActivateConfirm && (
        <ActivateConfirmModal
          configName={configName}
          onClose={() => setShowActivateConfirm(false)}
          onConfirm={handleActivate}
        />
      )}

      {showNlPanel && (
        <NlCompilePanel
          initialActionKey={config?.action_key ?? ''}
          onAccept={(_draft) => {
            // Draft accepted — inform user to use the template editor to apply it
            toast.info('Draft policy generated. Use the Template Editor to apply it to this config.');
          }}
          onClose={() => setShowNlPanel(false)}
        />
      )}
    </div>
  );
}