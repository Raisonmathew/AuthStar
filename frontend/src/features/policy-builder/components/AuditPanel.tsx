/**
 * AuditPanel — shows the audit log for a policy config.
 * Cursor-based pagination with "Load more".
 */

import { useState, useEffect } from 'react';
import type { AuditEntry } from '../types';
import * as pbApi from '../api';

interface AuditPanelProps {
  configId: string;
}

const EVENT_LABELS: Record<string, { label: string; icon: string; color: string }> = {
  config_created:    { label: 'Config created',    icon: '✨', color: 'text-emerald-400' },
  config_updated:    { label: 'Config updated',    icon: '✏️', color: 'text-blue-400' },
  config_archived:   { label: 'Config archived',   icon: '📦', color: 'text-slate-400' },
  config_compiled:   { label: 'Compiled',          icon: '⚙️', color: 'text-indigo-400' },
  config_activated:  { label: 'Activated',         icon: '🚀', color: 'text-emerald-400' },
  group_added:       { label: 'Group added',       icon: '➕', color: 'text-blue-400' },
  group_updated:     { label: 'Group updated',     icon: '✏️', color: 'text-blue-400' },
  group_removed:     { label: 'Group removed',     icon: '🗑️', color: 'text-red-400' },
  rule_added:        { label: 'Rule added',        icon: '➕', color: 'text-blue-400' },
  rule_updated:      { label: 'Rule updated',      icon: '✏️', color: 'text-blue-400' },
  rule_removed:      { label: 'Rule removed',      icon: '🗑️', color: 'text-red-400' },
  condition_added:   { label: 'Condition added',   icon: '➕', color: 'text-blue-400' },
  condition_updated: { label: 'Condition updated', icon: '✏️', color: 'text-blue-400' },
  condition_removed: { label: 'Condition removed', icon: '🗑️', color: 'text-red-400' },
  version_rollback:  { label: 'Rolled back',       icon: '↩️', color: 'text-amber-400' },
};

export function AuditPanel({ configId }: AuditPanelProps) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);

  const load = async (cursor?: string) => {
    if (cursor) {
      setLoadingMore(true);
    } else {
      setLoading(true);
      setError(null);
    }
    try {
      const page = await pbApi.getConfigAudit(configId, {
        limit: 20,
        before: cursor,
      });
      if (cursor) {
        setEntries((prev) => [...prev, ...page.items]);
      } else {
        setEntries(page.items);
      }
      setNextCursor(page.next_cursor);
    } catch (err: any) {
      setError(err?.response?.data?.error ?? 'Failed to load audit log');
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  useEffect(() => {
    load();
  }, [configId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <svg className="w-6 h-6 animate-spin text-indigo-500" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-base font-semibold text-white">Audit Log</h3>
        <p className="text-sm text-slate-400 mt-1">
          All changes to this policy are recorded here.
        </p>
      </div>

      {entries.length === 0 ? (
        <div className="py-8 text-center">
          <p className="text-slate-500 text-sm">No audit events yet.</p>
        </div>
      ) : (
        <div className="space-y-1">
          {entries.map((entry) => {
            const meta = EVENT_LABELS[entry.event_type];
            return (
              <div
                key={entry.id}
                className="flex items-start gap-3 px-4 py-3 rounded-xl hover:bg-slate-800/50 transition-colors group"
              >
                {/* Icon */}
                <span className="text-base flex-shrink-0 mt-0.5">{meta?.icon ?? '📋'}</span>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-sm font-medium ${meta?.color ?? 'text-slate-300'}`}>
                      {meta?.label ?? entry.event_type}
                    </span>
                    {entry.description && (
                      <span className="text-sm text-slate-400 truncate">{entry.description}</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-xs text-slate-500">{entry.actor_id}</span>
                    {entry.actor_ip && (
                      <span className="text-xs text-slate-600 font-mono">{entry.actor_ip}</span>
                    )}
                  </div>
                </div>

                {/* Timestamp */}
                <span className="text-xs text-slate-600 flex-shrink-0 mt-0.5">
                  {new Date(entry.created_at).toLocaleString()}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {/* Load more */}
      {nextCursor && (
        <div className="flex justify-center pt-2">
          <button
            type="button"
            onClick={() => load(nextCursor)}
            disabled={loadingMore}
            className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-xl transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {loadingMore ? (
              <>
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Loading...
              </>
            ) : (
              'Load more'
            )}
          </button>
        </div>
      )}
    </div>
  );
}