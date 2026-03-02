import { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ExecutionLog {
    id: string;
    created_at: string;
    capsule_id: string | null;
    capsule_hash_b64: string;
    decision: { allow?: boolean; allowed?: boolean; reason?: string };
    nonce_b64: string;
    client_id: string | null;
    ip_text: string | null;
    action?: string;
}

interface AuditResponse {
    logs: ExecutionLog[];
    hasMore: boolean;
    nextCursor: string | null;
    count: number;
}

type DecisionFilter = 'all' | 'allowed' | 'denied';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDateTime(isoString: string) {
    const d = new Date(isoString);
    return {
        date: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }),
        time: d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    };
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AuditLogPage() {
    const [logs, setLogs] = useState<ExecutionLog[]>([]);
    const [loading, setLoading] = useState(true);
    const [loadingMore, setLoadingMore] = useState(false);
    const [hasMore, setHasMore] = useState(false);
    const [nextCursor, setNextCursor] = useState<string | null>(null);

    // Filter state
    const [decisionFilter, setDecisionFilter] = useState<DecisionFilter>('all');
    const [actionFilter, setActionFilter] = useState('');
    const [actionInput, setActionInput] = useState('');

    // Track if we're in a fresh load vs. load-more
    const abortRef = useRef<AbortController | null>(null);

    const fetchLogs = useCallback(async (
        decision: DecisionFilter,
        action: string,
        cursor: string | null,
        append: boolean,
    ) => {
        // Cancel any in-flight request
        if (abortRef.current) abortRef.current.abort();
        abortRef.current = new AbortController();

        if (append) {
            setLoadingMore(true);
        } else {
            setLoading(true);
        }

        try {
            const params = new URLSearchParams();
            params.set('limit', '25');
            if (decision !== 'all') params.set('decision', decision);
            if (action) params.set('action', action);
            if (cursor) params.set('cursor', cursor);

            const res = await api.get<AuditResponse>(
                `/api/admin/v1/audit?${params.toString()}`,
                { signal: abortRef.current.signal }
            );

            const data = res.data;
            // Handle both old (array) and new (paginated object) response shapes
            const newLogs: ExecutionLog[] = Array.isArray(data)
                ? (data as unknown as ExecutionLog[])
                : data.logs ?? [];

            if (append) {
                setLogs(prev => [...prev, ...newLogs]);
            } else {
                setLogs(newLogs);
            }

            setHasMore(Array.isArray(data) ? false : (data.hasMore ?? false));
            setNextCursor(Array.isArray(data) ? null : (data.nextCursor ?? null));
        } catch (err: any) {
            if (err?.code === 'ERR_CANCELED') return; // Aborted — ignore
            console.error(err);
            toast.error('Failed to fetch audit logs');
        } finally {
            setLoading(false);
            setLoadingMore(false);
        }
    }, []);

    // Initial load + re-fetch when filters change
    useEffect(() => {
        fetchLogs(decisionFilter, actionFilter, null, false);
    }, [decisionFilter, actionFilter, fetchLogs]);

    const handleLoadMore = () => {
        if (!hasMore || loadingMore || !nextCursor) return;
        fetchLogs(decisionFilter, actionFilter, nextCursor, true);
    };

    const handleActionSearch = (e: React.FormEvent) => {
        e.preventDefault();
        setActionFilter(actionInput.trim());
    };

    const handleClearFilters = () => {
        setDecisionFilter('all');
        setActionFilter('');
        setActionInput('');
    };

    const isFiltered = decisionFilter !== 'all' || actionFilter !== '';

    // ── Decision badge ──────────────────────────────────────────────────────

    const getDecisionBadge = (decision: ExecutionLog['decision']) => {
        const allowed = decision?.allow || decision?.allowed;
        if (allowed) {
            return (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    Allowed
                </span>
            );
        }
        return (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
                Denied
            </span>
        );
    };

    // ── Render ──────────────────────────────────────────────────────────────

    return (
        <div className="space-y-6">
            {/* Header */}
            <div>
                <h2 className="text-2xl font-bold text-white font-heading">Audit Logs</h2>
                <p className="text-slate-400 mt-1">
                    Cryptographic proofs of EIAA policy executions with full audit trail.
                </p>
            </div>

            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3">
                {/* Decision filter buttons */}
                <div className="flex items-center gap-1 p-1 bg-slate-800/50 rounded-xl border border-slate-700/50">
                    {(['all', 'allowed', 'denied'] as DecisionFilter[]).map((f) => (
                        <button
                            key={f}
                            onClick={() => setDecisionFilter(f)}
                            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-150 capitalize ${
                                decisionFilter === f
                                    ? f === 'allowed'
                                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                                        : f === 'denied'
                                        ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                                        : 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
                            }`}
                        >
                            {f === 'all' ? 'All Decisions' : f.charAt(0).toUpperCase() + f.slice(1)}
                        </button>
                    ))}
                </div>

                {/* Action search */}
                <form onSubmit={handleActionSearch} className="flex items-center gap-2">
                    <div className="relative">
                        <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                        <input
                            type="text"
                            value={actionInput}
                            onChange={(e) => setActionInput(e.target.value)}
                            placeholder="Filter by action…"
                            className="pl-9 pr-4 py-2 bg-slate-800/50 border border-slate-700/50 rounded-xl text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 w-48"
                        />
                    </div>
                    <button
                        type="submit"
                        className="px-3 py-2 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 text-sm font-medium rounded-xl border border-indigo-500/30 transition-colors"
                    >
                        Search
                    </button>
                </form>

                {/* Clear filters */}
                {isFiltered && (
                    <button
                        onClick={handleClearFilters}
                        className="flex items-center gap-1.5 px-3 py-2 text-sm text-slate-400 hover:text-white bg-slate-800/50 hover:bg-slate-700/50 rounded-xl border border-slate-700/50 transition-colors"
                    >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                        Clear filters
                    </button>
                )}

                {/* Active filter chips */}
                {actionFilter && (
                    <span className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700/50 text-slate-300 text-xs font-medium rounded-lg border border-slate-600/50">
                        action: <span className="text-indigo-300 font-mono">{actionFilter}</span>
                        <button
                            onClick={() => { setActionFilter(''); setActionInput(''); }}
                            className="ml-1 text-slate-400 hover:text-white"
                        >×</button>
                    </span>
                )}
            </div>

            {/* Table */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-slate-700/50 overflow-hidden shadow-xl">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
                    </div>
                ) : logs.length === 0 ? (
                    <div className="p-12 text-center">
                        <div className="w-16 h-16 rounded-2xl bg-slate-700/50 flex items-center justify-center mx-auto mb-4">
                            <svg className="w-8 h-8 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                            </svg>
                        </div>
                        <h3 className="text-lg font-bold text-white mb-2 font-heading">
                            {isFiltered ? 'No matching logs' : 'No audit logs yet'}
                        </h3>
                        <p className="text-slate-400">
                            {isFiltered
                                ? 'Try adjusting your filters'
                                : 'Policy executions will appear here with cryptographic proofs'}
                        </p>
                        {isFiltered && (
                            <button
                                onClick={handleClearFilters}
                                className="mt-4 px-4 py-2 text-sm text-indigo-300 bg-indigo-500/10 hover:bg-indigo-500/20 rounded-xl border border-indigo-500/20 transition-colors"
                            >
                                Clear filters
                            </button>
                        )}
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-slate-700/50 bg-slate-900/20">
                                    <th className="px-6 py-4 text-left text-xs font-bold text-slate-400 uppercase tracking-wider font-heading">Timestamp</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-slate-400 uppercase tracking-wider font-heading">Decision</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-slate-400 uppercase tracking-wider font-heading hidden md:table-cell">Action</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-slate-400 uppercase tracking-wider font-heading">Capsule Hash</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-slate-400 uppercase tracking-wider font-heading hidden lg:table-cell">Client / IP</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-700/50">
                                {logs.map((log) => {
                                    const { date, time } = formatDateTime(log.created_at);
                                    return (
                                        <tr key={log.id} className="hover:bg-slate-700/30 transition-colors">
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="text-sm font-medium text-white">{date}</div>
                                                <div className="text-xs text-slate-500 font-mono">{time}</div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                {getDecisionBadge(log.decision)}
                                                {log.decision?.reason && (
                                                    <div className="text-xs text-slate-500 mt-1 max-w-[160px] truncate" title={log.decision.reason}>
                                                        {log.decision.reason}
                                                    </div>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap hidden md:table-cell">
                                                <span className="text-sm text-slate-300 font-mono">
                                                    {log.action || '—'}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <code className="px-2 py-1 bg-slate-900/50 border border-slate-700/50 rounded text-xs font-mono text-indigo-300">
                                                    {log.capsule_hash_b64.substring(0, 16)}…
                                                </code>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap hidden lg:table-cell">
                                                <div className="text-sm text-white font-medium">{log.ip_text || 'N/A'}</div>
                                                <div className="text-xs text-slate-500 font-mono">{log.client_id || '—'}</div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Pagination / Load More */}
            {!loading && logs.length > 0 && (
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    {/* Stats bar */}
                    <div className="flex items-center gap-4 text-sm text-slate-400">
                        <span>Showing {logs.length} record{logs.length !== 1 ? 's' : ''}</span>
                        <span className="flex items-center gap-2 px-3 py-1 bg-emerald-500/10 rounded-full border border-emerald-500/10">
                            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                            <span className="text-white font-medium">
                                {logs.filter(l => l.decision?.allow || l.decision?.allowed).length} allowed
                            </span>
                        </span>
                        <span className="flex items-center gap-2 px-3 py-1 bg-red-500/10 rounded-full border border-red-500/10">
                            <span className="w-2 h-2 rounded-full bg-red-500" />
                            <span className="text-white font-medium">
                                {logs.filter(l => !(l.decision?.allow || l.decision?.allowed)).length} denied
                            </span>
                        </span>
                    </div>

                    {/* Load more button */}
                    {hasMore && (
                        <button
                            onClick={handleLoadMore}
                            disabled={loadingMore}
                            className="flex items-center gap-2 px-5 py-2.5 bg-slate-700/50 hover:bg-slate-700 text-white text-sm font-medium rounded-xl border border-slate-600/50 hover:border-slate-500 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {loadingMore ? (
                                <>
                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                                    Loading…
                                </>
                            ) : (
                                <>
                                    Load more
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                    </svg>
                                </>
                            )}
                        </button>
                    )}
                </div>
            )}
        </div>
    );
}
