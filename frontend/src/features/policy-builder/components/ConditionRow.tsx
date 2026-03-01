/**
 * ConditionRow — a single condition within a rule.
 * Shows: condition type picker | params | AND/OR operator | delete button
 */

import { useState } from 'react';
import { clsx } from 'clsx';
import type { ConditionDetail, ConditionTypeItem, NextOperator } from '../types';
import * as pbApi from '../api';

interface ConditionRowProps {
  condition: ConditionDetail;
  conditionTypes: ConditionTypeItem[];
  configId: string;
  groupId: string;
  ruleId: string;
  isLast: boolean;
  onUpdated: () => void;
}

export function ConditionRow({
  condition,
  conditionTypes,
  configId,
  groupId,
  ruleId,
  isLast,
  onUpdated,
}: ConditionRowProps) {
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const currentType = conditionTypes.find((ct) => ct.condition_type === condition.condition_type);

  const handleTypeChange = async (newType: string) => {
    setSaving(true);
    try {
      await pbApi.updateCondition(configId, groupId, ruleId, condition.id, {
        condition_type: newType,
        condition_params: {},
      });
      onUpdated();
    } catch (err) {
      console.error('Failed to update condition type', err);
    } finally {
      setSaving(false);
    }
  };

  const handleParamChange = async (key: string, value: any) => {
    setSaving(true);
    try {
      const newParams = { ...(condition.condition_params ?? {}), [key]: value };
      await pbApi.updateCondition(configId, groupId, ruleId, condition.id, {
        condition_params: newParams,
      });
      onUpdated();
    } catch (err) {
      console.error('Failed to update condition params', err);
    } finally {
      setSaving(false);
    }
  };

  const handleOperatorChange = async (op: NextOperator) => {
    setSaving(true);
    try {
      await pbApi.updateCondition(configId, groupId, ruleId, condition.id, {
        next_operator: op,
      });
      onUpdated();
    } catch (err) {
      console.error('Failed to update operator', err);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await pbApi.removeCondition(configId, groupId, ruleId, condition.id);
      onUpdated();
    } catch (err) {
      console.error('Failed to remove condition', err);
      setDeleting(false);
    }
  };

  // Render inline param inputs based on the condition type's schema
  const renderParams = () => {
    if (!currentType) return null;
    const props = currentType.params_schema?.properties ?? {};
    if (Object.keys(props).length === 0) return null;

    return (
      <div className="flex flex-wrap gap-2 items-center">
        {Object.entries(props).map(([key, propSchema]: [string, any]) => {
          const val = condition.condition_params?.[key];

          if (propSchema.type === 'array' && propSchema.items?.type === 'string') {
            // Inline tag input for arrays
            return (
              <InlineTagInput
                key={key}
                label={key.replace(/_/g, ' ')}
                value={Array.isArray(val) ? val : []}
                onChange={(v) => handleParamChange(key, v)}
                disabled={saving}
              />
            );
          }

          if (propSchema.type === 'number' || propSchema.type === 'integer') {
            return (
              <div key={key} className="flex items-center gap-1.5">
                <span className="text-xs text-slate-400 capitalize">{key.replace(/_/g, ' ')}:</span>
                <input
                  type="number"
                  min={propSchema.minimum}
                  max={propSchema.maximum}
                  value={typeof val === 'number' ? val : (propSchema.default ?? '')}
                  onChange={(e) => handleParamChange(key, Number(e.target.value))}
                  disabled={saving}
                  className="w-20 bg-slate-700 border border-slate-600 rounded px-2 py-0.5 text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-50"
                />
              </div>
            );
          }

          return (
            <div key={key} className="flex items-center gap-1.5">
              <span className="text-xs text-slate-400 capitalize">{key.replace(/_/g, ' ')}:</span>
              <input
                type="text"
                value={typeof val === 'string' ? val : ''}
                onChange={(e) => handleParamChange(key, e.target.value)}
                disabled={saving}
                placeholder={propSchema.description ?? ''}
                className="w-32 bg-slate-700 border border-slate-600 rounded px-2 py-0.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-50"
              />
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className={clsx('flex flex-col gap-2', saving && 'opacity-70')}>
      <div className="flex items-center gap-2 flex-wrap">
        {/* Condition type selector */}
        <select
          value={condition.condition_type}
          onChange={(e) => handleTypeChange(e.target.value)}
          disabled={saving}
          className="bg-slate-700 border border-slate-600 rounded-lg px-2 py-1 text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-50"
        >
          {conditionTypes.map((ct) => (
            <option key={ct.condition_type} value={ct.condition_type}>
              {ct.display_name}
            </option>
          ))}
        </select>

        {/* Inline params */}
        {renderParams()}

        {/* AND/OR operator (not shown for last condition) */}
        {!isLast && (
          <select
            value={condition.next_operator ?? 'and'}
            onChange={(e) => handleOperatorChange(e.target.value as NextOperator)}
            disabled={saving}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-xs font-semibold text-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-50"
          >
            <option value="and">AND</option>
            <option value="or">OR</option>
          </select>
        )}

        {/* Delete button */}
        <button
          type="button"
          onClick={handleDelete}
          disabled={deleting || saving}
          className="ml-auto p-1 text-slate-500 hover:text-red-400 transition-colors disabled:opacity-50"
          aria-label="Remove condition"
        >
          {deleting ? (
            <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
          ) : (
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" />
            </svg>
          )}
        </button>
      </div>
    </div>
  );
}

// ─── Inline tag input for condition params ────────────────────────────────────

function InlineTagInput({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value: string[];
  onChange: (v: string[]) => void;
  disabled?: boolean;
}) {
  const [input, setInput] = useState('');

  const add = (tag: string) => {
    const t = tag.trim().toUpperCase();
    if (t && !value.includes(t)) onChange([...value, t]);
    setInput('');
  };

  const remove = (tag: string) => onChange(value.filter((v) => v !== tag));

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <span className="text-xs text-slate-400 capitalize">{label}:</span>
      <div className="flex items-center gap-1 flex-wrap">
        {value.map((tag) => (
          <span
            key={tag}
            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 bg-indigo-500/20 text-indigo-300 rounded text-xs font-mono"
          >
            {tag}
            {!disabled && (
              <button
                type="button"
                onClick={() => remove(tag)}
                className="text-indigo-400 hover:text-white leading-none"
              >
                ×
              </button>
            )}
          </span>
        ))}
        {!disabled && (
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ',') {
                e.preventDefault();
                add(input);
              }
            }}
            onBlur={() => input && add(input)}
            placeholder="add..."
            className="w-16 bg-transparent text-xs text-slate-100 placeholder-slate-500 focus:outline-none border-b border-slate-600 focus:border-indigo-500"
          />
        )}
      </div>
    </div>
  );
}