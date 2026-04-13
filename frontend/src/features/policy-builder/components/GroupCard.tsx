/**
 * GroupCard — displays a rule group with its rules.
 * Handles: match mode, on_match action, stepup methods, enable/disable, delete.
 * Contains RuleCard list + "Add Rule" button that opens TemplatePicker.
 */

import { useState } from 'react';
import { clsx } from 'clsx';
import type { GroupDetail, TemplateItem, ConditionTypeItem, MatchMode, OnMatch } from '../types';
import { RuleCard } from './RuleCard';
import { TemplatePicker } from './TemplatePicker';
import * as pbApi from '../api';

interface GroupCardProps {
  group: GroupDetail;
  configId: string;
  templates: TemplateItem[];
  conditionTypes: ConditionTypeItem[];
  onUpdated: () => void;
  onMoveUp?: () => void;
  onMoveDown?: () => void;
  isFirst: boolean;
  isLast: boolean;
}

const ON_MATCH_LABELS: Record<OnMatch, string> = {
  allow: 'Allow',
  deny: 'Deny',
  stepup: 'Require Step-Up',
  continue: 'Continue to next group',
};

const STEPUP_METHOD_OPTIONS = ['totp', 'sms', 'passkey', 'email'];
const STEPUP_METHOD_LABELS: Record<string, string> = {
  totp: 'Authenticator App',
  sms: 'SMS Code',
  passkey: 'Passkey',
  email: 'Email Code',
};

export function GroupCard({
  group,
  configId,
  templates,
  conditionTypes,
  onUpdated,
  onMoveUp,
  onMoveDown,
  isFirst,
  isLast,
}: GroupCardProps) {
  const [showTemplatePicker, setShowTemplatePicker] = useState(false);
  const [addingRule, setAddingRule] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [isEnabled, setIsEnabled] = useState(group.is_enabled);
  const [matchMode, setMatchMode] = useState<MatchMode>(group.match_mode);
  const [onMatch, setOnMatch] = useState<OnMatch>(group.on_match);
  const [onNoMatch, setOnNoMatch] = useState<OnMatch>(group.on_no_match);
  const [stepupMethods, setStepupMethods] = useState<string[]>(group.stepup_methods);
  const [saving, setSaving] = useState(false);

  const handleUpdate = async (patch: Partial<{
    match_mode: MatchMode;
    on_match: OnMatch;
    on_no_match: OnMatch;
    stepup_methods: string[];
    is_enabled: boolean;
  }>) => {
    setSaving(true);
    try {
      await pbApi.updateGroup(configId, group.id, patch);
      onUpdated();
    } catch (err) {
      console.error('Failed to update group', err);
    } finally {
      setSaving(false);
    }
  };

  const handleMatchModeChange = async (val: MatchMode) => {
    setMatchMode(val);
    await handleUpdate({ match_mode: val });
  };

  const handleOnMatchChange = async (val: OnMatch) => {
    setOnMatch(val);
    await handleUpdate({ on_match: val });
  };

  const handleOnNoMatchChange = async (val: OnMatch) => {
    setOnNoMatch(val);
    await handleUpdate({ on_no_match: val });
  };

  const handleStepupMethodToggle = async (method: string) => {
    const newMethods = stepupMethods.includes(method)
      ? stepupMethods.filter((m) => m !== method)
      : [...stepupMethods, method];
    setStepupMethods(newMethods);
    await handleUpdate({ stepup_methods: newMethods });
  };

  const handleToggleEnabled = async () => {
    const newVal = !isEnabled;
    setIsEnabled(newVal);
    await handleUpdate({ is_enabled: newVal });
  };

  const handleDelete = async () => {
    if (!confirm(`Delete group "${group.display_name}"? All rules in this group will be deleted.`)) return;
    setDeleting(true);
    try {
      await pbApi.removeGroup(configId, group.id);
      onUpdated();
    } catch {
      setDeleting(false);
    }
  };

  const handleTemplateSelect = async (template: TemplateItem) => {
    setShowTemplatePicker(false);
    setAddingRule(true);
    try {
      await pbApi.addRule(configId, group.id, {
        template_slug: template.slug,
        display_name: template.display_name,
        param_values: template.param_defaults ?? {},
      });
      onUpdated();
    } catch (err) {
      console.error('Failed to add rule', err);
    } finally {
      setAddingRule(false);
    }
  };

  const handleMoveRule = async (ruleId: string, direction: 'up' | 'down') => {
    const ids = group.rules.map((r) => r.id);
    const idx = ids.indexOf(ruleId);
    if (direction === 'up' && idx > 0) {
      [ids[idx - 1], ids[idx]] = [ids[idx], ids[idx - 1]];
    } else if (direction === 'down' && idx < ids.length - 1) {
      [ids[idx], ids[idx + 1]] = [ids[idx + 1], ids[idx]];
    } else {
      return;
    }
    try {
      await pbApi.reorderRules(configId, group.id, ids);
      onUpdated();
    } catch (err) {
      console.error('Failed to reorder rules', err);
    }
  };

  const onMatchColor: Record<OnMatch, string> = {
    allow: 'text-emerald-400',
    deny: 'text-red-400',
    stepup: 'text-amber-400',
    continue: 'text-blue-400',
  };

  return (
    <>
      <div
        className={clsx(
          'bg-card border rounded-2xl transition-all',
          isEnabled ? 'border-border' : 'border-border/40 opacity-60',
          deleting && 'opacity-20 pointer-events-none',
          saving && 'ring-1 ring-primary/30'
        )}
      >
        {/* Group header */}
        <div className="flex items-start gap-3 px-4 py-3 border-b border-border">
          {/* Reorder buttons */}
          <div className="flex flex-col gap-0.5 mt-1 flex-shrink-0">
            <button
              type="button"
              onClick={onMoveUp}
              disabled={isFirst}
            className="p-0.5 text-muted-foreground hover:text-foreground disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
              aria-label="Move group up"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
              </svg>
            </button>
            <button
              type="button"
              onClick={onMoveDown}
              disabled={isLast}
              className="p-0.5 text-muted-foreground hover:text-foreground disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
              aria-label="Move group down"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
          </div>

          {/* Group name + controls */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-semibold text-foreground">{group.display_name}</span>
              {!isEnabled && (
                <span className="text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground rounded">
                  Disabled
                </span>
              )}
            </div>

            {/* Match mode + on_match controls */}
            <div className="flex items-center gap-2 mt-2 flex-wrap">
              <span className="text-xs text-muted-foreground">If</span>
              <select
                value={matchMode}
                onChange={(e) => handleMatchModeChange(e.target.value as MatchMode)}
                disabled={saving}
                className="bg-muted border border-border rounded-lg px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring disabled:opacity-50"
              >
                <option value="all">ALL rules match</option>
                <option value="any">ANY rule matches</option>
              </select>
              <span className="text-xs text-muted-foreground">→</span>
              <select
                value={onMatch}
                onChange={(e) => handleOnMatchChange(e.target.value as OnMatch)}
                disabled={saving}
                className={clsx(
                  'bg-muted border border-border rounded-lg px-2 py-1 text-xs font-medium focus:outline-none focus:ring-1 focus:ring-ring disabled:opacity-50',
                  onMatchColor[onMatch]
                )}
              >
                {(Object.entries(ON_MATCH_LABELS) as [OnMatch, string][]).map(([val, label]) => (
                  <option key={val} value={val}>{label}</option>
                ))}
              </select>

              {/* On no match */}
              <span className="text-xs text-muted-foreground">else</span>
              <select
                value={onNoMatch}
                onChange={(e) => handleOnNoMatchChange(e.target.value as OnMatch)}
                disabled={saving}
                className={clsx(
                  'bg-muted border border-border rounded-lg px-2 py-1 text-xs font-medium focus:outline-none focus:ring-1 focus:ring-ring disabled:opacity-50',
                  onMatchColor[onNoMatch]
                )}
              >
                {(Object.entries(ON_MATCH_LABELS) as [OnMatch, string][]).map(([val, label]) => (
                  <option key={val} value={val}>{label}</option>
                ))}
              </select>
            </div>

            {/* Step-up methods (shown only when on_match = stepup) */}
            {onMatch === 'stepup' && (
              <div className="flex items-center gap-2 mt-2 flex-wrap">
                <span className="text-xs text-muted-foreground">Methods:</span>
                {STEPUP_METHOD_OPTIONS.map((method) => (
                  <button
                    key={method}
                    type="button"
                    onClick={() => handleStepupMethodToggle(method)}
                    disabled={saving}
                    className={clsx(
                      'px-2 py-0.5 rounded-lg text-xs border transition-colors disabled:opacity-50',
                      stepupMethods.includes(method)
                        ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                        : 'bg-muted border-border text-muted-foreground hover:border-muted-foreground'
                    )}
                  >
                    {STEPUP_METHOD_LABELS[method]}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Options menu */}
          <div className="relative flex-shrink-0">
            <button
              type="button"
              onClick={() => setMenuOpen((o) => !o)}
              className="p-1.5 text-muted-foreground hover:text-foreground transition-colors rounded-lg hover:bg-accent"
              aria-label="Group options"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <circle cx="12" cy="5" r="1.5" />
                <circle cx="12" cy="12" r="1.5" />
                <circle cx="12" cy="19" r="1.5" />
              </svg>
            </button>
            {menuOpen && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} />
                <div className="absolute right-0 top-8 z-20 w-44 bg-accent border border-border rounded-xl shadow-xl py-1">
                  <button
                    type="button"
                    onClick={() => { handleToggleEnabled(); setMenuOpen(false); }}
                    className="w-full text-left px-3 py-2 text-sm text-foreground hover:bg-accent/80 hover:text-foreground transition-colors"
                  >
                    {isEnabled ? 'Disable group' : 'Enable group'}
                  </button>
                  <button
                    type="button"
                    onClick={() => { handleDelete(); setMenuOpen(false); }}
                    className="w-full text-left px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors"
                  >
                    Delete group
                  </button>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Rules list */}
        <div className="p-3 space-y-2">
          {group.rules.length === 0 ? (
            <div className="py-4 text-center">
              <p className="text-sm text-muted-foreground">No rules yet.</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Add a rule to define when this group matches.
              </p>
            </div>
          ) : (
            group.rules.map((rule, idx) => (
              <RuleCard
                key={rule.id}
                rule={rule}
                configId={configId}
                groupId={group.id}
                conditionTypes={conditionTypes}
                onUpdated={onUpdated}
                onMoveUp={() => handleMoveRule(rule.id, 'up')}
                onMoveDown={() => handleMoveRule(rule.id, 'down')}
                isFirst={idx === 0}
                isLast={idx === group.rules.length - 1}
              />
            ))
          )}

          {/* Add rule button */}
          <button
            type="button"
            onClick={() => setShowTemplatePicker(true)}
            disabled={addingRule}
            className="w-full flex items-center justify-center gap-2 py-2 border border-dashed border-border rounded-xl text-sm text-muted-foreground hover:text-foreground hover:border-muted-foreground transition-colors disabled:opacity-50 mt-1"
          >
            {addingRule ? (
              <>
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Adding rule...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 4v16m8-8H4" />
                </svg>
                Add Rule from Template
              </>
            )}
          </button>
        </div>
      </div>

      {/* Template picker slide-over */}
      {showTemplatePicker && (
        <TemplatePicker
          templates={templates}
          onSelect={handleTemplateSelect}
          onClose={() => setShowTemplatePicker(false)}
        />
      )}
    </>
  );
}