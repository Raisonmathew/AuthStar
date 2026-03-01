/**
 * RuleCard — displays a single rule within a group.
 * Shows: template icon + name, param form, conditions list, add condition button.
 * Auto-saves param changes to the API.
 */

import { useState, useEffect, useCallback } from 'react';
import { clsx } from 'clsx';
import type { RuleDetail, ConditionTypeItem } from '../types';
import { ParamForm } from './ParamForm';
import { ConditionRow } from './ConditionRow';
import * as pbApi from '../api';

interface RuleCardProps {
  rule: RuleDetail;
  configId: string;
  groupId: string;
  conditionTypes: ConditionTypeItem[];
  onUpdated: () => void;
  onMoveUp?: () => void;
  onMoveDown?: () => void;
  isFirst: boolean;
  isLast: boolean;
}

export function RuleCard({
  rule,
  configId,
  groupId,
  conditionTypes,
  onUpdated,
  onMoveUp,
  onMoveDown,
  isFirst,
  isLast,
}: RuleCardProps) {
  const [expanded, setExpanded] = useState(true);
  const [conditionsExpanded, setConditionsExpanded] = useState(rule.conditions.length > 0);
  const [paramValues, setParamValues] = useState<Record<string, any>>(rule.param_values ?? {});
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [saveTimer, setSaveTimer] = useState<ReturnType<typeof setTimeout> | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [addingCondition, setAddingCondition] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [isEnabled, setIsEnabled] = useState(rule.is_enabled);

  // Debounced auto-save for param changes
  const saveParams = useCallback(
    async (values: Record<string, any>) => {
      setSaveStatus('saving');
      try {
        await pbApi.updateRule(configId, groupId, rule.id, { param_values: values });
        setSaveStatus('saved');
        setTimeout(() => setSaveStatus('idle'), 2000);
        onUpdated();
      } catch {
        setSaveStatus('error');
        setTimeout(() => setSaveStatus('idle'), 3000);
      }
    },
    [configId, groupId, rule.id, onUpdated]
  );

  const handleParamChange = (values: Record<string, any>) => {
    setParamValues(values);
    if (saveTimer) clearTimeout(saveTimer);
    const timer = setTimeout(() => saveParams(values), 600);
    setSaveTimer(timer);
  };

  // Cleanup timer on unmount
  useEffect(() => {
    return () => {
      if (saveTimer) clearTimeout(saveTimer);
    };
  }, [saveTimer]);

  const handleDelete = async () => {
    if (!confirm(`Delete rule "${rule.display_name}"?`)) return;
    setDeleting(true);
    try {
      await pbApi.removeRule(configId, groupId, rule.id);
      onUpdated();
    } catch {
      setDeleting(false);
    }
  };

  const handleToggleEnabled = async () => {
    const newVal = !isEnabled;
    setIsEnabled(newVal);
    try {
      await pbApi.updateRule(configId, groupId, rule.id, { is_enabled: newVal });
      onUpdated();
    } catch {
      setIsEnabled(!newVal); // revert
    }
  };

  const handleAddCondition = async () => {
    if (conditionTypes.length === 0) return;
    setAddingCondition(true);
    try {
      // Add the first available condition type as default
      await pbApi.addCondition(configId, groupId, rule.id, {
        condition_type: conditionTypes[0].condition_type,
        condition_params: {},
        next_operator: 'and',
      });
      setConditionsExpanded(true);
      onUpdated();
    } catch (err) {
      console.error('Failed to add condition', err);
    } finally {
      setAddingCondition(false);
    }
  };

  const template = rule.template;

  return (
    <div
      className={clsx(
        'bg-slate-800/60 border rounded-xl transition-all',
        isEnabled ? 'border-slate-700' : 'border-slate-700/50 opacity-60',
        deleting && 'opacity-30 pointer-events-none'
      )}
    >
      {/* Rule header */}
      <div className="flex items-center gap-2 px-3 py-2.5">
        {/* Reorder buttons */}
        <div className="flex flex-col gap-0.5 flex-shrink-0">
          <button
            type="button"
            onClick={onMoveUp}
            disabled={isFirst}
            className="p-0.5 text-slate-600 hover:text-slate-300 disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
            aria-label="Move rule up"
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
            </svg>
          </button>
          <button
            type="button"
            onClick={onMoveDown}
            disabled={isLast}
            className="p-0.5 text-slate-600 hover:text-slate-300 disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
            aria-label="Move rule down"
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>

        {/* Template icon */}
        <span className="text-base flex-shrink-0">{template.icon ?? '⚙️'}</span>

        {/* Rule name + template */}
        <button
          type="button"
          onClick={() => setExpanded((e) => !e)}
          className="flex-1 text-left min-w-0"
        >
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-100 truncate">{rule.display_name}</span>
            {!isEnabled && (
              <span className="text-[10px] px-1.5 py-0.5 bg-slate-700 text-slate-400 rounded">
                Disabled
              </span>
            )}
            {saveStatus === 'saving' && (
              <span className="text-[10px] text-slate-500">saving...</span>
            )}
            {saveStatus === 'saved' && (
              <span className="text-[10px] text-emerald-500">✓ saved</span>
            )}
            {saveStatus === 'error' && (
              <span className="text-[10px] text-red-400">save failed</span>
            )}
          </div>
          <p className="text-xs text-slate-500 truncate">{template.display_name}</p>
        </button>

        {/* Expand chevron */}
        <button
          type="button"
          onClick={() => setExpanded((e) => !e)}
          className="p-1 text-slate-500 hover:text-slate-300 transition-colors"
          aria-label={expanded ? 'Collapse rule' : 'Expand rule'}
        >
          <svg
            className={clsx('w-4 h-4 transition-transform', expanded && 'rotate-180')}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 9l-7 7-7-7" />
          </svg>
        </button>

        {/* Options menu */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setMenuOpen((o) => !o)}
            className="p-1 text-slate-500 hover:text-slate-300 transition-colors rounded"
            aria-label="Rule options"
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
              <div className="absolute right-0 top-7 z-20 w-40 bg-slate-800 border border-slate-700 rounded-xl shadow-xl py-1">
                <button
                  type="button"
                  onClick={() => { handleToggleEnabled(); setMenuOpen(false); }}
                  className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
                >
                  {isEnabled ? 'Disable rule' : 'Enable rule'}
                </button>
                <button
                  type="button"
                  onClick={() => { handleDelete(); setMenuOpen(false); }}
                  className="w-full text-left px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors"
                >
                  Delete rule
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Expanded content */}
      {expanded && (
        <div className="px-4 pb-3 space-y-4 border-t border-slate-700/50 pt-3">
          {/* Param form */}
          <ParamForm
            schema={template.param_schema}
            defaults={template.param_defaults}
            values={paramValues}
            onChange={handleParamChange}
          />

          {/* Conditions section */}
          <div>
            <button
              type="button"
              onClick={() => setConditionsExpanded((e) => !e)}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors mb-2"
            >
              <svg
                className={clsx('w-3 h-3 transition-transform', conditionsExpanded && 'rotate-90')}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
              <span className="font-medium">
                Additional Conditions
                {rule.conditions.length > 0 && (
                  <span className="ml-1 text-indigo-400">({rule.conditions.length})</span>
                )}
              </span>
              <span className="text-slate-600 text-[10px]">optional — further restrict when this rule matches</span>
            </button>

            {conditionsExpanded && (
              <div className="space-y-2 pl-2 border-l border-slate-700">
                {rule.conditions.map((cond, idx) => (
                  <ConditionRow
                    key={cond.id}
                    condition={cond}
                    conditionTypes={conditionTypes}
                    configId={configId}
                    groupId={groupId}
                    ruleId={rule.id}
                    isLast={idx === rule.conditions.length - 1}
                    onUpdated={onUpdated}
                  />
                ))}

                <button
                  type="button"
                  onClick={handleAddCondition}
                  disabled={addingCondition || conditionTypes.length === 0}
                  className="flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 transition-colors disabled:opacity-50 mt-1"
                >
                  {addingCondition ? (
                    <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : (
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                  )}
                  Add Condition
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}