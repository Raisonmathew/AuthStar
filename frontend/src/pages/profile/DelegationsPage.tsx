/**
 * DelegationsPage — /account/delegations
 *
 * Shows the authenticated user their active AI agent delegations.
 * Each delegation can be revoked, which immediately blocks the agent JWT
 * via a Redis blocklist key (sub-100ms revocation).
 *
 * API:
 *  GET  /api/v1/user/delegations       — list active delegations
 *  POST /api/v1/user/delegations/:id/revoke  — revoke a delegation
 */

import { useEffect, useState, useCallback } from 'react';
import { api, getApiError } from '../../lib/api/client';
import { toast } from 'sonner';

interface Delegation {
    id: string;
    agent_id: string;
    agent_name: string | null;
    allowed_tools: string[];
    expires_at: string;
    created_at: string;
}

function timeAgo(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
}

function formatExpiry(iso: string): string {
    const d = new Date(iso);
    const diff = d.getTime() - Date.now();
    if (diff <= 0) return 'Expired';
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `Expires in ${mins}m`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `Expires in ${hrs}h`;
    return `Expires ${d.toLocaleDateString()}`;
}

export default function DelegationsPage() {
    const [delegations, setDelegations] = useState<Delegation[]>([]);
    const [loading, setLoading] = useState(true);
    const [revoking, setRevoking] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const res = await api.get<Delegation[]>('/api/v1/user/delegations');
            setDelegations(res.data);
        } catch (err: any) {
            setError(getApiError(err, 'Failed to load delegations'));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { load(); }, [load]);

    const handleRevoke = useCallback(async (delegation: Delegation) => {
        const label = delegation.agent_name || delegation.agent_id;
        if (!window.confirm(`Revoke access for "${label}"? The agent will be blocked immediately.`)) return;

        setRevoking(delegation.id);
        try {
            await api.post(`/api/v1/user/delegations/${delegation.id}/revoke`);
            toast.success(`Revoked access for ${label}`);
            setDelegations((prev) => prev.filter((d) => d.id !== delegation.id));
        } catch (err: any) {
            toast.error(getApiError(err, 'Failed to revoke delegation'));
        } finally {
            setRevoking(null);
        }
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center py-16">
                <div className="flex flex-col items-center gap-3">
                    <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary" />
                    <p className="text-muted-foreground text-sm">Loading delegations...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="max-w-2xl">
            {/* Header */}
            <div className="mb-6">
                <h1 className="text-2xl font-bold text-foreground font-heading mb-1">Agent Delegations</h1>
                <p className="text-muted-foreground text-sm">
                    AI agents you have authorized to act on your behalf. Revoke any delegation
                    immediately to block the agent's access.
                </p>
            </div>

            {error && (
                <div className="mb-4 p-4 bg-destructive/10 border border-destructive/30 rounded-xl text-destructive text-sm flex items-center gap-3">
                    <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span>{error}</span>
                    <button
                        onClick={load}
                        className="ml-auto text-xs underline hover:no-underline"
                    >
                        Retry
                    </button>
                </div>
            )}

            {!error && delegations.length === 0 && (
                <div className="text-center py-16 bg-card border border-border rounded-xl">
                    <div className="inline-flex items-center justify-center w-14 h-14 bg-muted rounded-2xl mb-4">
                        <svg className="w-7 h-7 text-muted-foreground" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                                d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23-.693L5 14.5m14.8.8l1.402 1.402c1 1 .03 2.698-1.382 2.698H4.18c-1.412 0-2.38-1.698-1.382-2.698L4.2 15.3" />
                        </svg>
                    </div>
                    <h3 className="text-foreground font-semibold mb-1">No active delegations</h3>
                    <p className="text-muted-foreground text-sm">
                        When you authorize an AI agent, it will appear here.
                    </p>
                </div>
            )}

            {delegations.length > 0 && (
                <ul className="space-y-3">
                    {delegations.map((d) => {
                        const label = d.agent_name || d.agent_id;
                        const isRevoking = revoking === d.id;
                        return (
                            <li
                                key={d.id}
                                className="bg-card border border-border rounded-xl p-5 flex items-start justify-between gap-4"
                            >
                                <div className="flex items-start gap-4 min-w-0">
                                    {/* Agent icon */}
                                    <div className="w-10 h-10 rounded-xl bg-primary/20 flex items-center justify-center flex-shrink-0">
                                        <svg className="w-5 h-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                                                d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23-.693L5 14.5m14.8.8l1.402 1.402c1 1 .03 2.698-1.382 2.698H4.18c-1.412 0-2.38-1.698-1.382-2.698L4.2 15.3" />
                                        </svg>
                                    </div>
                                    <div className="min-w-0">
                                        <p className="text-foreground font-semibold text-sm truncate">{label}</p>
                                        {d.agent_name && (
                                            <p className="text-muted-foreground text-xs font-mono truncate">{d.agent_id}</p>
                                        )}
                                        <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1.5">
                                            <span className="text-muted-foreground text-xs">
                                                Granted {timeAgo(d.created_at)}
                                            </span>
                                            <span className={`text-xs font-medium ${
                                                new Date(d.expires_at).getTime() - Date.now() < 3600000
                                                    ? 'text-amber-500'
                                                    : 'text-muted-foreground'
                                            }`}>
                                                {formatExpiry(d.expires_at)}
                                            </span>
                                        </div>
                                        {d.allowed_tools.length > 0 && (
                                            <div className="mt-2 flex flex-wrap gap-1">
                                                {d.allowed_tools.slice(0, 5).map((t) => (
                                                    <span
                                                        key={t}
                                                        className="px-2 py-0.5 bg-muted text-muted-foreground text-xs rounded font-mono"
                                                    >
                                                        {t}
                                                    </span>
                                                ))}
                                                {d.allowed_tools.length > 5 && (
                                                    <span className="px-2 py-0.5 bg-muted text-muted-foreground text-xs rounded">
                                                        +{d.allowed_tools.length - 5} more
                                                    </span>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </div>

                                <button
                                    onClick={() => handleRevoke(d)}
                                    disabled={isRevoking}
                                    className="flex-shrink-0 px-3 py-1.5 text-sm font-medium text-destructive border border-destructive/40 rounded-lg hover:bg-destructive/10 disabled:opacity-50 transition-colors whitespace-nowrap"
                                >
                                    {isRevoking ? 'Revoking...' : 'Revoke'}
                                </button>
                            </li>
                        );
                    })}
                </ul>
            )}

            <p className="text-muted-foreground text-xs mt-6">
                Revoking a delegation blocks the agent's token within seconds via real-time enforcement.
                The agent cannot re-gain access without your explicit approval.
            </p>
        </div>
    );
}
