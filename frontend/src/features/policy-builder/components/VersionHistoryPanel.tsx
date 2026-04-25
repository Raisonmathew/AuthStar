/**
 * VersionHistoryPanel — shows compiled versions, diff, and rollback.
 */

import { useState, useEffect } from 'react';
import { clsx } from 'clsx';
import type { VersionSummary, DiffResponse } from '../types';
import * as pbApi from '../api';

interface VersionHistoryPanelProps {
  configId: string;
  onRolledBack: () => void;
}

export function VersionHistoryPanel({ configId, onRolledBack }: VersionHistoryPanelProps) {
  const [versions, setVersions] = useState<VersionSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rollbackTarget, setRollbackTarget] = useState<VersionSummary | null>(null);
  const [rollingBack, setRollingBack] = useState(false);
  const [diffTarget, setDiffTarget] = useState<VersionSummary | null>(null);
  const [diff, setDiff] = useState<DiffResponse | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await pbApi.listVersions(configId);
      setVersions(data);
    } catch (err: any) {
      setError(err?.response?.data?.error ?? 'Failed to load versions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [configId]);

  const handleRollback = async () => {
    if (!rollbackTarget) return;
    setRollingBack(true);
    try {
      await pbApi.rollbackVersion(configId, rollbackTarget.id);
      setRollbackTarget(null);
      onRolledBack();
      await load();
    } catch (err: any) {
      alert(err?.response?.data?.error ?? 'Rollback failed');
    } finally {
      setRollingBack(false);
    }
  };

  const handleDiff = async (version: VersionSummary) => {
    setDiffTarget(version);
    setDiff(null);
    setLoadingDiff(true);
    try {
      const result = await pbApi.diffVersions(configId, version.id);
      setDiff(result);
    } catch (err: any) {
      alert(err?.response?.data?.error ?? 'Failed to load diff');
      setDiffTarget(null);
    } finally {
      setLoadingDiff(false);
    }
  };

  const handleExportAst = async (version: VersionSummary) => {
    try {
      const ast = await pbApi.exportVersionAst(configId, version.id);
      const blob = new Blob([JSON.stringify(ast, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `policy-v${version.version_number}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err?.response?.data?.error ?? 'Export failed');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <svg className="w-6 h-6 animate-spin text-primary" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-xl text-sm text-destructive">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-base font-semibold text-foreground">Version History</h3>
        <p className="text-sm text-muted-foreground mt-1">
          Each compile creates a new version. You can roll back to any previous version.
        </p>
      </div>

      {versions.length === 0 ? (
        <div className="py-8 text-center">
          <p className="text-muted-foreground text-sm">No compiled versions yet.</p>
          <p className="text-xs text-muted-foreground mt-1">Compile the policy to create the first version.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {versions.map((v) => (
            <div
              key={v.id}
              className={clsx(
                'flex items-center gap-4 p-4 rounded-xl border transition-colors',
                v.is_active
                  ? 'border-emerald-500/30 bg-emerald-500/5'
                  : 'border-border bg-card'
              )}
            >
              {/* Version number + status */}
              <div className="flex-shrink-0 w-12 text-center">
                <span className="text-lg font-bold text-foreground">v{v.version_number}</span>
                {v.is_active && (
                  <div className="flex items-center justify-center gap-1 mt-0.5">
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
                    </span>
                    <span className="text-[10px] text-emerald-400 font-semibold">ACTIVE</span>
                  </div>
                )}
              </div>

              {/* Metadata */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  {v.compiled_by && (
                    <span className="text-xs text-muted-foreground">by {v.compiled_by}</span>
                  )}
                  {v.compiled_at && (
                    <span className="text-xs text-muted-foreground">
                      {new Date(v.compiled_at).toLocaleString()}
                    </span>
                  )}
                  <span className={clsx(
                    'text-[10px] px-1.5 py-0.5 rounded border',
                    v.source === 'rollback'
                      ? 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                      : 'bg-muted border-border text-muted-foreground'
                  )}>
                    {v.source}
                  </span>
                </div>
                {v.ast_hash_b64 && (
                  <p className="text-[10px] text-muted-foreground font-mono mt-0.5 truncate">
                    SHA: {v.ast_hash_b64.slice(0, 16)}...
                  </p>
                )}
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  type="button"
                  onClick={() => handleDiff(v)}
                  className="text-xs text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded hover:bg-accent"
                >
                  Diff
                </button>
                <button
                  type="button"
                  onClick={() => handleExportAst(v)}
                  className="text-xs text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded hover:bg-accent"
                >
                  Export AST
                </button>
                {!v.is_active && (
                  <button
                    type="button"
                    onClick={() => setRollbackTarget(v)}
                    className="text-xs text-amber-400 hover:text-amber-300 transition-colors px-2 py-1 rounded hover:bg-amber-500/10"
                  >
                    Rollback
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Rollback confirmation modal */}
      {rollbackTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setRollbackTarget(null)} />
          <div className="relative bg-card border border-border rounded-2xl p-6 max-w-md w-full shadow-2xl">
            <h3 className="text-base font-semibold text-foreground mb-2">
              Rollback to v{rollbackTarget.version_number}?
            </h3>
            <div className="space-y-2 text-sm text-muted-foreground mb-6">
              <p>This will:</p>
              <ol className="list-decimal list-inside space-y-1 pl-2">
                <li>Create a new version from v{rollbackTarget.version_number}'s snapshot</li>
                <li>Activate the new version immediately</li>
                <li>The current active version will become inactive</li>
              </ol>
              <p className="text-muted-foreground text-xs mt-3">This action is logged in the audit trail.</p>
            </div>
            <div className="flex gap-3 justify-end">
              <button
                type="button"
                onClick={() => setRollbackTarget(null)}
                disabled={rollingBack}
                className="px-4 py-2 text-sm text-foreground hover:text-foreground bg-accent hover:bg-accent/80 rounded-xl transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleRollback}
                disabled={rollingBack}
                className="px-4 py-2 text-sm text-white bg-amber-600 hover:bg-amber-700 rounded-xl transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {rollingBack && (
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                )}
                Confirm Rollback
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Diff modal */}
      {diffTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => { setDiffTarget(null); setDiff(null); }} />
          <div className="relative bg-card border border-border rounded-2xl p-6 max-w-2xl w-full shadow-2xl max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold text-foreground">
                Diff: v{diffTarget.version_number} {diff ? (diff.to_version_number === 0 ? '(initial version)' : `vs v${diff.to_version_number}`) : 'vs previous'}
              </h3>
              <button
                type="button"
                onClick={() => { setDiffTarget(null); setDiff(null); }}
                className="p-1.5 text-muted-foreground hover:text-foreground rounded-lg hover:bg-accent transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="flex-1 overflow-y-auto">
              {loadingDiff ? (
                <div className="flex items-center justify-center py-8">
                  <svg className="w-6 h-6 animate-spin text-primary" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                </div>
              ) : diff ? (
                <DiffView diff={diff} />
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DiffView({ diff }: { diff: DiffResponse }) {
  if (diff.changes_count === 0) {
    return (
      <div className="py-6 text-center text-muted-foreground text-sm">
        No differences found between these versions.
      </div>
    );
  }

  const changeTypeColors: Record<string, string> = {
    added: 'text-emerald-400',
    removed: 'text-red-400',
    modified: 'text-amber-400',
  };

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        {diff.changes_count} change{diff.changes_count !== 1 ? 's' : ''} {diff.to_version_number === 0 ? `in v${diff.from_version_number} (initial version)` : `between v${diff.from_version_number} and v${diff.to_version_number}`}
      </p>
      {diff.changes.map((change, i) => (
        <div key={`${change.change_type}:${change.path}:${i}`} className="bg-accent rounded-xl p-3 space-y-2">
          <div className="flex items-center gap-2">
            <span className={clsx('text-xs font-semibold uppercase', changeTypeColors[change.change_type] ?? 'text-muted-foreground')}>
              {change.change_type}
            </span>
            <span className="text-xs text-muted-foreground font-mono">{change.path}</span>
          </div>
          <p className="text-xs text-foreground">{change.description}</p>
          {(change.from_value !== undefined || change.to_value !== undefined) && (
            <div className="space-y-1">
              {change.from_value !== undefined && (
                <div className="flex items-start gap-2">
                  <span className="text-red-400 text-xs font-mono">-</span>
                  <span className="text-xs text-red-300 font-mono bg-red-500/10 px-2 py-0.5 rounded">
                    {JSON.stringify(change.from_value)}
                  </span>
                </div>
              )}
              {change.to_value !== undefined && (
                <div className="flex items-start gap-2">
                  <span className="text-emerald-400 text-xs font-mono">+</span>
                  <span className="text-xs text-emerald-300 font-mono bg-emerald-500/10 px-2 py-0.5 rounded">
                    {JSON.stringify(change.to_value)}
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}