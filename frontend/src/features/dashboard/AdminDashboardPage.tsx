import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ─── Types ────────────────────────────────────────────────────────────────────

interface DashboardStats {
    totalExecutions: number;
    allowedCount: number;
    deniedCount: number;
    executionsLast24h: number;
    executionsLast7d: number;
    uniqueActionsLast7d: number;
}

interface AuditLogEntry {
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
    logs: AuditLogEntry[];
    hasMore: boolean;
    nextCursor: string | null;
    count: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatRelativeTime(isoString: string): string {
    const now = Date.now();
    const then = new Date(isoString).getTime();
    const diffMs = now - then;
    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    return `${Math.floor(diffHr / 24)}d ago`;
}

function getActionLabel(entry: AuditLogEntry): string {
    const action = entry.action || entry.client_id || 'Policy execution';
    const map: Record<string, string> = {
        login: 'User login',
        admin_login: 'Admin login',
        'auth:login': 'User login',
        'auth:admin_login': 'Admin login',
        signup: 'New user signup',
        mfa_verify: 'MFA verification',
        passkey_register: 'Passkey registered',
    };
    return map[action] || action;
}

function getActivityType(entry: AuditLogEntry): 'allowed' | 'denied' | 'user' | 'admin' {
    const allowed = entry.decision?.allow || entry.decision?.allowed;
    if (!allowed) return 'denied';
    const action = entry.action || '';
    if (action.includes('admin')) return 'admin';
    if (action.includes('signup')) return 'user';
    return 'allowed';
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCardSkeleton() {
    return (
        <div className="bg-slate-800/50 rounded-2xl p-6 border border-slate-700/50 animate-pulse">
            <div className="flex items-start justify-between">
                <div className="space-y-3">
                    <div className="h-3 w-24 bg-slate-700 rounded" />
                    <div className="h-8 w-20 bg-slate-700 rounded" />
                    <div className="h-3 w-16 bg-slate-700 rounded" />
                </div>
                <div className="w-12 h-12 rounded-xl bg-slate-700" />
            </div>
        </div>
    );
}

function ActivitySkeleton() {
    return (
        <div className="space-y-5 animate-pulse">
            {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-start gap-4">
                    <div className="w-8 h-8 rounded-full bg-slate-700 flex-shrink-0 mt-1" />
                    <div className="flex-1 space-y-2">
                        <div className="h-3 w-3/4 bg-slate-700 rounded" />
                        <div className="h-3 w-1/2 bg-slate-700 rounded" />
                    </div>
                    <div className="h-5 w-14 bg-slate-700 rounded" />
                </div>
            ))}
        </div>
    );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AdminDashboardPage() {
    const navigate = useNavigate();
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [recentActivity, setRecentActivity] = useState<AuditLogEntry[]>([]);
    const [statsLoading, setStatsLoading] = useState(true);
    const [activityLoading, setActivityLoading] = useState(true);
    const [statsError, setStatsError] = useState(false);
    const [activityError, setActivityError] = useState(false);

    const loadStats = useCallback(async () => {
        setStatsLoading(true);
        setStatsError(false);
        try {
            const res = await api.get<DashboardStats>('/api/admin/v1/audit/stats');
            setStats(res.data);
        } catch (err: any) {
            setStatsError(true);
            // Don't toast on 403 — user may not have admin:manage EIAA action yet
            if (err?.response?.status !== 403) {
                toast.error('Failed to load dashboard statistics');
            }
        } finally {
            setStatsLoading(false);
        }
    }, []);

    const loadRecentActivity = useCallback(async () => {
        setActivityLoading(true);
        setActivityError(false);
        try {
            const res = await api.get<AuditResponse>('/api/admin/v1/audit?limit=8');
            setRecentActivity(res.data.logs ?? []);
        } catch (err: any) {
            setActivityError(true);
            if (err?.response?.status !== 403) {
                toast.error('Failed to load recent activity');
            }
        } finally {
            setActivityLoading(false);
        }
    }, []);

    useEffect(() => {
        loadStats();
        loadRecentActivity();
    }, [loadStats, loadRecentActivity]);

    // ── Derived stat cards ──────────────────────────────────────────────────

    const allowRate = stats && stats.totalExecutions > 0
        ? Math.round((stats.allowedCount / stats.totalExecutions) * 100)
        : null;

    const statCards = stats ? [
        {
            name: 'Total Executions',
            value: stats.totalExecutions.toLocaleString(),
            sub: `${stats.executionsLast24h.toLocaleString()} in last 24h`,
            trend: stats.executionsLast24h > 0 ? 'up' : 'neutral' as const,
            color: 'from-blue-500 to-blue-600',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
            ),
        },
        {
            name: 'Allowed',
            value: stats.allowedCount.toLocaleString(),
            sub: allowRate !== null ? `${allowRate}% allow rate` : '—',
            trend: 'up' as const,
            color: 'from-emerald-500 to-emerald-600',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 13l4 4L19 7" />
                </svg>
            ),
        },
        {
            name: 'Denied',
            value: stats.deniedCount.toLocaleString(),
            sub: stats.totalExecutions > 0
                ? `${Math.round((stats.deniedCount / stats.totalExecutions) * 100)}% deny rate`
                : '—',
            trend: stats.deniedCount > 0 ? 'down' : 'neutral' as const,
            color: 'from-red-500 to-red-600',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
            ),
        },
        {
            name: 'Last 7 Days',
            value: stats.executionsLast7d.toLocaleString(),
            sub: `${stats.uniqueActionsLast7d} unique action${stats.uniqueActionsLast7d !== 1 ? 's' : ''}`,
            trend: stats.executionsLast7d > 0 ? 'up' : 'neutral' as const,
            color: 'from-purple-500 to-purple-600',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
            ),
        },
    ] : [];

    // ── Activity icon helper ────────────────────────────────────────────────

    const getActivityIcon = (entry: AuditLogEntry) => {
        const type = getActivityType(entry);
        const configs = {
            allowed: { bg: 'bg-emerald-500/20', icon: 'text-emerald-400', path: 'M5 13l4 4L19 7' },
            denied: { bg: 'bg-red-500/20', icon: 'text-red-400', path: 'M6 18L18 6M6 6l12 12' },
            user: { bg: 'bg-blue-500/20', icon: 'text-blue-400', path: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z' },
            admin: { bg: 'bg-amber-500/20', icon: 'text-amber-400', path: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
        };
        const c = configs[type];
        return (
            <div className={`w-8 h-8 rounded-full ${c.bg} flex items-center justify-center flex-shrink-0`}>
                <svg className={`w-4 h-4 ${c.icon}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={c.path} />
                </svg>
            </div>
        );
    };

    // ── Render ──────────────────────────────────────────────────────────────

    return (
        <div className="space-y-6 lg:space-y-8">

            {/* ── Stats Grid ─────────────────────────────────────────────── */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6">
                {statsLoading ? (
                    [...Array(4)].map((_, i) => <StatCardSkeleton key={i} />)
                ) : statsError ? (
                    <div className="col-span-4 bg-slate-800/50 rounded-2xl p-6 border border-red-500/30 text-center">
                        <p className="text-red-400 text-sm mb-3">Failed to load statistics</p>
                        <button
                            onClick={loadStats}
                            className="px-4 py-2 text-xs font-medium text-white bg-red-500/20 hover:bg-red-500/30 rounded-lg border border-red-500/30 transition-colors"
                        >
                            Retry
                        </button>
                    </div>
                ) : (
                    statCards.map((stat) => (
                        <div
                            key={stat.name}
                            className="relative overflow-hidden bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50 hover:border-slate-600/50 transition-all duration-300 group"
                        >
                            {/* Gradient accent */}
                            <div className={`absolute top-0 right-0 w-32 h-32 bg-gradient-to-br ${stat.color} opacity-10 rounded-full -translate-y-16 translate-x-16 group-hover:opacity-20 transition-opacity`} />

                            <div className="flex items-start justify-between relative z-10">
                                <div>
                                    <p className="text-sm font-medium text-slate-400 font-heading">{stat.name}</p>
                                    <p className="text-3xl font-bold text-white mt-2 font-heading tracking-tight">{stat.value}</p>
                                    <div className="flex items-center mt-2 gap-1">
                                        {stat.trend === 'up' && (
                                            <svg className="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
                                            </svg>
                                        )}
                                        {stat.trend === 'down' && (
                                            <svg className="w-3.5 h-3.5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
                                            </svg>
                                        )}
                                        <span className="text-xs text-slate-400 font-medium">{stat.sub}</span>
                                    </div>
                                </div>
                                <div className={`p-3 rounded-xl bg-gradient-to-br ${stat.color} shadow-lg shadow-black/20 group-hover:scale-110 transition-transform duration-300`}>
                                    <div className="text-white">{stat.icon}</div>
                                </div>
                            </div>
                        </div>
                    ))
                )}
            </div>

            {/* ── Main Content Row ────────────────────────────────────────── */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

                {/* Allow/Deny Rate Chart */}
                <div className="xl:col-span-2 bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                        <div>
                            <h3 className="text-lg font-bold text-white font-heading">Policy Decision Breakdown</h3>
                            <p className="text-sm text-slate-400">Allow vs deny rate across all executions</p>
                        </div>
                    </div>

                    {statsLoading ? (
                        <div className="h-40 flex items-center justify-center">
                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
                        </div>
                    ) : stats && stats.totalExecutions > 0 ? (
                        <div className="space-y-4">
                            {/* Allow bar */}
                            <div>
                                <div className="flex justify-between text-sm mb-1.5">
                                    <span className="text-slate-300 font-medium">Allowed</span>
                                    <span className="text-emerald-400 font-bold">
                                        {stats.allowedCount.toLocaleString()} ({allowRate}%)
                                    </span>
                                </div>
                                <div className="h-3 bg-slate-700/50 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-gradient-to-r from-emerald-500 to-emerald-400 rounded-full transition-all duration-700"
                                        style={{ width: `${allowRate ?? 0}%` }}
                                    />
                                </div>
                            </div>
                            {/* Deny bar */}
                            <div>
                                <div className="flex justify-between text-sm mb-1.5">
                                    <span className="text-slate-300 font-medium">Denied</span>
                                    <span className="text-red-400 font-bold">
                                        {stats.deniedCount.toLocaleString()} ({100 - (allowRate ?? 0)}%)
                                    </span>
                                </div>
                                <div className="h-3 bg-slate-700/50 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-gradient-to-r from-red-500 to-red-400 rounded-full transition-all duration-700"
                                        style={{ width: `${100 - (allowRate ?? 0)}%` }}
                                    />
                                </div>
                            </div>

                            {/* Summary row */}
                            <div className="mt-6 pt-4 border-t border-slate-700/50 grid grid-cols-3 gap-4 text-center">
                                <div>
                                    <p className="text-2xl font-bold text-white font-heading">{stats.totalExecutions.toLocaleString()}</p>
                                    <p className="text-xs text-slate-400 mt-1">Total</p>
                                </div>
                                <div>
                                    <p className="text-2xl font-bold text-white font-heading">{stats.executionsLast24h.toLocaleString()}</p>
                                    <p className="text-xs text-slate-400 mt-1">Last 24h</p>
                                </div>
                                <div>
                                    <p className="text-2xl font-bold text-white font-heading">{stats.executionsLast7d.toLocaleString()}</p>
                                    <p className="text-xs text-slate-400 mt-1">Last 7 days</p>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="h-40 flex flex-col items-center justify-center text-center">
                            <div className="w-12 h-12 rounded-xl bg-slate-700/50 flex items-center justify-center mb-3">
                                <svg className="w-6 h-6 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                                </svg>
                            </div>
                            <p className="text-slate-400 text-sm">No policy executions yet</p>
                            <p className="text-slate-500 text-xs mt-1">Data will appear once users authenticate</p>
                        </div>
                    )}
                </div>

                {/* Recent Activity */}
                <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50 flex flex-col">
                    <div className="flex items-center justify-between mb-6">
                        <h3 className="text-lg font-bold text-white font-heading">Recent Activity</h3>
                        <button
                            onClick={loadRecentActivity}
                            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors"
                            title="Refresh"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                            </svg>
                        </button>
                    </div>

                    <div className="space-y-5 flex-1">
                        {activityLoading ? (
                            <ActivitySkeleton />
                        ) : activityError ? (
                            <div className="flex flex-col items-center justify-center h-32 text-center">
                                <p className="text-red-400 text-sm mb-2">Failed to load activity</p>
                                <button
                                    onClick={loadRecentActivity}
                                    className="text-xs text-indigo-400 hover:text-indigo-300 underline"
                                >
                                    Retry
                                </button>
                            </div>
                        ) : recentActivity.length === 0 ? (
                            <div className="flex flex-col items-center justify-center h-32 text-center">
                                <div className="w-10 h-10 rounded-xl bg-slate-700/50 flex items-center justify-center mb-2">
                                    <svg className="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                                    </svg>
                                </div>
                                <p className="text-slate-400 text-sm">No activity yet</p>
                            </div>
                        ) : (
                            recentActivity.map((entry, i) => (
                                <div key={entry.id} className="flex items-start gap-3 group">
                                    <div className="mt-0.5 relative">
                                        {getActivityIcon(entry)}
                                        {i !== recentActivity.length - 1 && (
                                            <div className="absolute top-8 left-1/2 -translate-x-1/2 w-px h-full bg-slate-700/50" />
                                        )}
                                    </div>
                                    <div className="flex-1 min-w-0 pt-0.5">
                                        <p className="text-sm text-white font-medium group-hover:text-indigo-300 transition-colors truncate">
                                            {getActionLabel(entry)}
                                        </p>
                                        <p className="text-xs text-slate-400 truncate mt-0.5">
                                            {entry.ip_text || entry.client_id || 'Unknown client'}
                                        </p>
                                    </div>
                                    <div className="flex flex-col items-end gap-1 flex-shrink-0">
                                        <span className="text-xs text-slate-500 font-medium bg-slate-800/50 px-2 py-0.5 rounded whitespace-nowrap">
                                            {formatRelativeTime(entry.created_at)}
                                        </span>
                                        <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${
                                            (entry.decision?.allow || entry.decision?.allowed)
                                                ? 'text-emerald-400 bg-emerald-500/10'
                                                : 'text-red-400 bg-red-500/10'
                                        }`}>
                                            {(entry.decision?.allow || entry.decision?.allowed) ? '✓' : '✗'}
                                        </span>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>

                    <button
                        onClick={() => navigate('/admin/monitoring/logs')}
                        className="w-full mt-6 py-3 rounded-xl text-sm font-medium text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 hover:bg-indigo-500/20 hover:border-indigo-500/30 transition-all duration-200"
                    >
                        View Full Audit Log →
                    </button>
                </div>
            </div>

            {/* ── Quick Actions ───────────────────────────────────────────── */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50">
                <h3 className="text-lg font-bold text-white font-heading mb-4">Quick Actions</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {[
                        {
                            name: 'Configure SSO',
                            icon: '🔑',
                            color: 'from-amber-500 to-orange-600',
                            desc: 'Connect identity providers',
                            path: '/admin/authentication/sso',
                        },
                        {
                            name: 'Manage Apps',
                            icon: '📱',
                            color: 'from-blue-500 to-blue-600',
                            desc: 'Register & configure apps',
                            path: '/admin/applications',
                        },
                        {
                            name: 'Login Methods',
                            icon: '🛡️',
                            color: 'from-purple-500 to-purple-600',
                            desc: 'Configure auth policies',
                            path: '/admin/authentication/login-methods',
                        },
                        {
                            name: 'View Audit Log',
                            icon: '📋',
                            color: 'from-emerald-500 to-emerald-600',
                            desc: 'Cryptographic audit trail',
                            path: '/admin/monitoring/logs',
                        },
                    ].map((action) => (
                        <button
                            key={action.name}
                            onClick={() => navigate(action.path)}
                            className="flex items-center gap-4 p-4 bg-slate-800 hover:bg-slate-700/80 rounded-xl border border-slate-700/50 hover:border-slate-600 transition-all duration-200 group text-left"
                        >
                            <span className={`w-12 h-12 rounded-xl bg-gradient-to-br ${action.color} flex items-center justify-center text-2xl shadow-lg group-hover:scale-105 transition-transform`}>
                                {action.icon}
                            </span>
                            <div>
                                <span className="block text-sm font-bold text-white font-heading">{action.name}</span>
                                <span className="text-xs text-slate-400 group-hover:text-slate-300">{action.desc}</span>
                            </div>
                        </button>
                    ))}
                </div>
            </div>
        </div>
    );
}
