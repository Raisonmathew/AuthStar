import { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// --- Types ---

type Tab = 'activity' | 'eiaa';

interface AuditEvent {
    id: string;
    event_type: string;
    actor_id: string | null;
    actor_email: string | null;
    target_type: string | null;
    target_id: string | null;
    ip_address: string | null;
    user_agent: string | null;
    metadata: Record<string, unknown>;
    created_at: string;
}

interface EventListResponse {
    events: AuditEvent[];
    has_more?: boolean;
    next_cursor?: string | null;
    hasMore?: boolean;
    nextCursor?: string | null;
    count: number;
}

interface EventStats {
    total_events: number;
    events_last_24h: number;
    events_last_7d: number;
    unique_event_types: number;
    login_success_last_24h: number;
    login_failed_last_24h: number;
}

interface ExecutionLog {
    id: string;
    created_at: string;
    capsule_id: string | null;
    capsule_hash_b64: string;
    decision: { allow?: boolean; allowed?: boolean; reason?: string };
    nonce_b64: string;
    action?: string;
}

interface EiaaResponse {
    logs: ExecutionLog[];
    hasMore: boolean;
    nextCursor: string | null;
    count: number;
}

type DecisionFilter = 'all' | 'allowed' | 'denied';

// --- Helpers ---

function formatDateTime(isoString: string) {
    const d = new Date(isoString);
    return {
        date: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }),
        time: d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    };
}

function eventTypeLabel(type: string): string {
    return type.replace(/\./g, ' \u203A ').replace(/_/g, ' ');
}

function eventTypeBadgeColor(type: string): string {
    if (type.includes('failed')) return 'bg-red-500/20 text-red-400 border-red-500/30';
    if (type.includes('success')) return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
    if (type.includes('revoked')) return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    if (type.includes('created')) return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    if (type.includes('updated')) return 'bg-violet-500/20 text-violet-400 border-violet-500/30';
    if (type.includes('deleted')) return 'bg-red-500/20 text-red-400 border-red-500/30';
    return 'bg-muted text-foreground border-border';
}

function numberFromUnknown(value: unknown): number {
    return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function normalizeStats(data: any): EventStats {
    return {
        total_events: numberFromUnknown(data?.total_events ?? data?.totalEvents),
        events_last_24h: numberFromUnknown(data?.events_last_24h ?? data?.eventsLast24h),
        events_last_7d: numberFromUnknown(data?.events_last_7d ?? data?.eventsLast7d),
        unique_event_types: numberFromUnknown(data?.unique_event_types ?? data?.uniqueEventTypes),
        login_success_last_24h: numberFromUnknown(data?.login_success_last_24h ?? data?.loginSuccessLast24h),
        login_failed_last_24h: numberFromUnknown(data?.login_failed_last_24h ?? data?.loginFailedLast24h),
    };
}

// --- Main Component ---

export default function AuditLogPage() {
    const [activeTab, setActiveTab] = useState<Tab>('activity');

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-foreground font-heading">Audit & Compliance</h2>
                <p className="text-muted-foreground mt-1">
                    Security events, activity trail, and cryptographic proofs of policy executions.
                </p>
            </div>

            <div className="flex items-center gap-1 p-1 bg-card rounded-xl border border-border w-fit">
                <button
                    onClick={() => setActiveTab('activity')}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-150 ${activeTab === 'activity' ? 'bg-primary/20 text-primary border border-primary/30' : 'text-muted-foreground hover:text-foreground hover:bg-accent'}`}
                >
                    Activity Log
                </button>
                <button
                    onClick={() => setActiveTab('eiaa')}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-150 ${activeTab === 'eiaa' ? 'bg-primary/20 text-primary border border-primary/30' : 'text-muted-foreground hover:text-foreground hover:bg-accent'}`}
                >
                    EIAA Executions
                </button>
            </div>

            {activeTab === 'activity' ? <ActivityLogTab /> : <EiaaExecutionsTab />}
        </div>
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Activity Log Tab
// ═══════════════════════════════════════════════════════════════════════════════

function ActivityLogTab() {
    const [events, setEvents] = useState<AuditEvent[]>([]);
    const [stats, setStats] = useState<EventStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [loadingMore, setLoadingMore] = useState(false);
    const [hasMore, setHasMore] = useState(false);
    const [nextCursor, setNextCursor] = useState<string | null>(null);
    const [eventTypeFilter, setEventTypeFilter] = useState('');
    const abortRef = useRef<AbortController | null>(null);

    useEffect(() => {
        api.get<EventStats>('/api/admin/v1/events/stats')
            .then(res => setStats(normalizeStats(res.data)))
            .catch(() => {});
    }, []);

    const fetchEvents = useCallback(async (
        eventType: string,
        cursor: string | null,
        append: boolean,
    ) => {
        if (abortRef.current) abortRef.current.abort();
        abortRef.current = new AbortController();
        if (append) setLoadingMore(true); else setLoading(true);

        try {
            const params = new URLSearchParams();
            params.set('limit', '25');
            if (eventType) params.set('event_type', eventType);
            if (cursor) params.set('cursor', cursor);

            const res = await api.get<EventListResponse>(
                `/api/admin/v1/events?${params.toString()}`,
                { signal: abortRef.current.signal }
            );
            const data = res.data;
            const newEvents = data.events ?? [];

            if (append) {
                setEvents(prev => [...prev, ...newEvents]);
            } else {
                setEvents(newEvents);
            }
            setHasMore(data.has_more ?? data.hasMore ?? false);
            setNextCursor(data.next_cursor ?? data.nextCursor ?? null);
        } catch (err: any) {
            if (err?.code === 'ERR_CANCELED') return;
            console.error(err);
            toast.error('Failed to fetch activity events');
        } finally {
            setLoading(false);
            setLoadingMore(false);
        }
    }, []);

    useEffect(() => {
        fetchEvents(eventTypeFilter, null, false);
    }, [eventTypeFilter, fetchEvents]);

    const handleLoadMore = () => {
        if (!hasMore || loadingMore || !nextCursor) return;
        fetchEvents(eventTypeFilter, nextCursor, true);
    };

    return (
        <div className="space-y-6">
            {stats && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <StatCard label="Total Events" value={stats.total_events} />
                    <StatCard label="Last 24h" value={stats.events_last_24h} />
                    <StatCard label="Login Success" value={stats.login_success_last_24h} color="emerald" />
                    <StatCard label="Login Failed" value={stats.login_failed_last_24h} color="red" />
                </div>
            )}

            <div className="flex items-center gap-3">
                <div className="relative">
                    <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
                    </svg>
                    <input
                        type="text"
                        value={eventTypeFilter}
                        onChange={(e) => setEventTypeFilter(e.target.value)}
                        placeholder="Filter by event type…"
                        className="pl-9 pr-4 py-2 bg-card border border-border rounded-xl text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-primary w-56"
                    />
                </div>
                {eventTypeFilter && (
                    <button
                        onClick={() => setEventTypeFilter('')}
                        className="flex items-center gap-1.5 px-3 py-2 text-sm text-muted-foreground hover:text-foreground bg-card hover:bg-accent rounded-xl border border-border transition-colors"
                    >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                        Clear
                    </button>
                )}
            </div>

            <div className="bg-card backdrop-blur-sm rounded-2xl border border-border overflow-hidden shadow-xl">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
                    </div>
                ) : events.length === 0 ? (
                    <EmptyState filtered={!!eventTypeFilter} onClear={() => setEventTypeFilter('')} message="Security events will appear here as users interact with the platform." />
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-border bg-muted/30">
                                    <th className="px-6 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading">Timestamp</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading">Event</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading hidden md:table-cell">Actor</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading hidden lg:table-cell">Target</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading hidden xl:table-cell">IP Address</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                                {events.map((evt) => {
                                    const { date, time } = formatDateTime(evt.created_at);
                                    return (
                                        <tr key={evt.id} className="hover:bg-accent/50 transition-colors">
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="text-sm font-medium text-foreground">{date}</div>
                                                <div className="text-xs text-muted-foreground font-mono">{time}</div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <span className={'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ' + eventTypeBadgeColor(evt.event_type)}>
                                                    {eventTypeLabel(evt.event_type)}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap hidden md:table-cell">
                                                <div className="text-sm text-foreground">{evt.actor_email || '\u2014'}</div>
                                                {evt.actor_id && (
                                                    <div className="text-xs text-muted-foreground font-mono truncate max-w-[160px]" title={evt.actor_id}>
                                                        {evt.actor_id.substring(0, 12)}\u2026
                                                    </div>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap hidden lg:table-cell">
                                                {evt.target_type ? (
                                                    <>
                                                        <div className="text-sm text-foreground capitalize">{evt.target_type}</div>
                                                        {evt.target_id && (
                                                            <div className="text-xs text-muted-foreground font-mono truncate max-w-[140px]" title={evt.target_id}>
                                                                {evt.target_id.substring(0, 12)}\u2026
                                                            </div>
                                                        )}
                                                    </>
                                                ) : (
                                                    <span className="text-sm text-muted-foreground">\u2014</span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap hidden xl:table-cell">
                                                <div className="text-sm text-foreground font-mono">{evt.ip_address || '\u2014'}</div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {!loading && events.length > 0 && (
                <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">
                        Showing {events.length} event{events.length !== 1 ? 's' : ''}
                    </span>
                    {hasMore && <LoadMoreButton loading={loadingMore} onClick={handleLoadMore} />}
                </div>
            )}
        </div>
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// EIAA Executions Tab
// ═══════════════════════════════════════════════════════════════════════════════

function EiaaExecutionsTab() {
    const [logs, setLogs] = useState<ExecutionLog[]>([]);
    const [loading, setLoading] = useState(true);
    const [loadingMore, setLoadingMore] = useState(false);
    const [hasMore, setHasMore] = useState(false);
    const [nextCursor, setNextCursor] = useState<string | null>(null);
    const [decisionFilter, setDecisionFilter] = useState<DecisionFilter>('all');
    const [actionFilter, setActionFilter] = useState('');
    const [actionInput, setActionInput] = useState('');
    const abortRef = useRef<AbortController | null>(null);

    const fetchLogs = useCallback(async (
        decision: DecisionFilter,
        action: string,
        cursor: string | null,
        append: boolean,
    ) => {
        if (abortRef.current) abortRef.current.abort();
        abortRef.current = new AbortController();
        if (append) setLoadingMore(true); else setLoading(true);

        try {
            const params = new URLSearchParams();
            params.set('limit', '25');
            if (decision !== 'all') params.set('decision', decision);
            if (action) params.set('action', action);
            if (cursor) params.set('cursor', cursor);

            const res = await api.get<EiaaResponse>(
                `/api/admin/v1/audit?${params.toString()}`,
                { signal: abortRef.current.signal }
            );
            const data = res.data;
            const newLogs: ExecutionLog[] = Array.isArray(data) ? (data as unknown as ExecutionLog[]) : data.logs ?? [];

            if (append) {
                setLogs(prev => [...prev, ...newLogs]);
            } else {
                setLogs(newLogs);
            }
            setHasMore(Array.isArray(data) ? false : (data.hasMore ?? false));
            setNextCursor(Array.isArray(data) ? null : (data.nextCursor ?? null));
        } catch (err: any) {
            if (err?.code === 'ERR_CANCELED') return;
            console.error(err);
            toast.error('Failed to fetch EIAA execution logs');
        } finally {
            setLoading(false);
            setLoadingMore(false);
        }
    }, []);

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

    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-1 p-1 bg-card rounded-xl border border-border">
                    {(['all', 'allowed', 'denied'] as DecisionFilter[]).map((f) => (
                        <button
                            key={f}
                            onClick={() => setDecisionFilter(f)}
                            className={'px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-150 capitalize ' + (
                                decisionFilter === f
                                    ? f === 'allowed'
                                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                                        : f === 'denied'
                                        ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                                        : 'bg-primary/20 text-primary border border-primary/30'
                                    : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                            )}
                        >
                            {f === 'all' ? 'All Decisions' : f.charAt(0).toUpperCase() + f.slice(1)}
                        </button>
                    ))}
                </div>

                <form onSubmit={handleActionSearch} className="flex items-center gap-2">
                    <div className="relative">
                        <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                        <input
                            type="text"
                            value={actionInput}
                            onChange={(e) => setActionInput(e.target.value)}
                            placeholder="Filter by action\u2026"
                            className="pl-9 pr-4 py-2 bg-card border border-border rounded-xl text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-primary w-48"
                        />
                    </div>
                    <button
                        type="submit"
                        className="px-3 py-2 bg-primary/20 hover:bg-primary/30 text-primary text-sm font-medium rounded-xl border border-primary/30 transition-colors"
                    >
                        Search
                    </button>
                </form>

                {isFiltered && (
                    <button
                        onClick={handleClearFilters}
                        className="flex items-center gap-1.5 px-3 py-2 text-sm text-muted-foreground hover:text-foreground bg-card hover:bg-accent rounded-xl border border-border transition-colors"
                    >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                        Clear filters
                    </button>
                )}

                {actionFilter && (
                    <span className="flex items-center gap-1.5 px-3 py-1.5 bg-muted text-foreground text-xs font-medium rounded-lg border border-border">
                        action: <span className="text-primary font-mono">{actionFilter}</span>
                        <button onClick={() => { setActionFilter(''); setActionInput(''); }} className="ml-1 text-muted-foreground hover:text-foreground">\u00D7</button>
                    </span>
                )}
            </div>

            <div className="bg-card backdrop-blur-sm rounded-2xl border border-border overflow-hidden shadow-xl">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
                    </div>
                ) : logs.length === 0 ? (
                    <EmptyState filtered={isFiltered} onClear={handleClearFilters} message="Policy executions will appear here with cryptographic proofs." />
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-border bg-muted/30">
                                    <th className="px-6 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading">Timestamp</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading">Decision</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading hidden md:table-cell">Action</th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading">Capsule Hash</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                                {logs.map((log) => {
                                    const { date, time } = formatDateTime(log.created_at);
                                    return (
                                        <tr key={log.id} className="hover:bg-accent/50 transition-colors">
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="text-sm font-medium text-foreground">{date}</div>
                                                <div className="text-xs text-muted-foreground font-mono">{time}</div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                {getDecisionBadge(log.decision)}
                                                {log.decision?.reason && (
                                                    <div className="text-xs text-muted-foreground mt-1 max-w-[160px] truncate" title={log.decision.reason}>
                                                        {log.decision.reason}
                                                    </div>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap hidden md:table-cell">
                                                <span className="text-sm text-foreground font-mono">{log.action || '\u2014'}</span>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <code className="px-2 py-1 bg-muted border border-border rounded text-xs font-mono text-primary">
                                                    {log.capsule_hash_b64.substring(0, 16)}\u2026
                                                </code>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {!loading && logs.length > 0 && (
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <span>Showing {logs.length} record{logs.length !== 1 ? 's' : ''}</span>
                        <span className="flex items-center gap-2 px-3 py-1 bg-emerald-500/10 rounded-full border border-emerald-500/10">
                            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                            <span className="text-foreground font-medium">
                                {logs.filter(l => l.decision?.allow || l.decision?.allowed).length} allowed
                            </span>
                        </span>
                        <span className="flex items-center gap-2 px-3 py-1 bg-red-500/10 rounded-full border border-red-500/10">
                            <span className="w-2 h-2 rounded-full bg-red-500" />
                            <span className="text-foreground font-medium">
                                {logs.filter(l => !(l.decision?.allow || l.decision?.allowed)).length} denied
                            </span>
                        </span>
                    </div>
                    {hasMore && <LoadMoreButton loading={loadingMore} onClick={handleLoadMore} />}
                </div>
            )}
        </div>
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shared Components
// ═══════════════════════════════════════════════════════════════════════════════

function StatCard({ label, value, color }: { label: string; value: number | null | undefined; color?: string }) {
    const safeValue = numberFromUnknown(value);
    const colorClasses = color === 'emerald'
        ? 'text-emerald-400'
        : color === 'red'
        ? 'text-red-400'
        : 'text-foreground';

    return (
        <div className="bg-card rounded-xl border border-border p-4">
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{label}</div>
            <div className={'text-2xl font-bold mt-1 ' + colorClasses}>{safeValue.toLocaleString()}</div>
        </div>
    );
}

function EmptyState({ filtered, onClear, message }: { filtered: boolean; onClear: () => void; message: string }) {
    return (
        <div className="p-12 text-center">
            <div className="w-16 h-16 rounded-2xl bg-muted flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
            </div>
            <h3 className="text-lg font-bold text-foreground mb-2 font-heading">
                {filtered ? 'No matching logs' : 'No logs yet'}
            </h3>
            <p className="text-muted-foreground">{filtered ? 'Try adjusting your filters' : message}</p>
            {filtered && (
                <button onClick={onClear} className="mt-4 px-4 py-2 text-sm text-primary bg-primary/10 hover:bg-primary/20 rounded-xl border border-primary/20 transition-colors">
                    Clear filters
                </button>
            )}
        </div>
    );
}

function LoadMoreButton({ loading, onClick }: { loading: boolean; onClick: () => void }) {
    return (
        <button
            onClick={onClick}
            disabled={loading}
            className="flex items-center gap-2 px-5 py-2.5 bg-accent hover:bg-accent/80 text-foreground text-sm font-medium rounded-xl border border-border hover:border-border/80 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
            {loading ? (
                <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                    Loading\u2026
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
    );
}
