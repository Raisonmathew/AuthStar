/**
 * Agent Delegation Consent Page — /consent/:flow_id
 *
 * Shown to a logged-in user when an AI agent requests delegated access.
 * The backend consent flow stores agent metadata in `auth_flows.meta` before
 * redirecting the user here via the MCP client OAuth redirect.
 *
 * Flow:
 *  1. MCP client initiates OAuth → backend creates auth_flow with agent metadata
 *  2. User completes EIAA auth (AuthFlowPage)
 *  3. Backend redirects to /consent/:flow_id
 *  4. This page loads agent info (GET /api/auth/flow/:id/consent)
 *  5. User reviews and approves/denies
 *  6. POST /api/auth/flow/:id/consent → returns agent_token + delegation_id
 */

import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api, getApiError } from '../lib/api/client';
import { toast } from 'sonner';

interface ConsentInfo {
    flow_id: string;
    agent_id: string | null;
    agent_name: string | null;
    requested_tools: string[];
    ttl_seconds: number;
}

interface ConsentApprovalResponse {
    agent_token: string;
    delegation_id: string;
    agent_id: string;
    task_id: string;
    expires_in: number;
}

function formatTtl(seconds: number): string {
    if (seconds >= 3600) return `${Math.round(seconds / 3600)} hour${Math.round(seconds / 3600) !== 1 ? 's' : ''}`;
    if (seconds >= 60) return `${Math.round(seconds / 60)} minute${Math.round(seconds / 60) !== 1 ? 's' : ''}`;
    return `${seconds} second${seconds !== 1 ? 's' : ''}`;
}

export default function ConsentPage() {
    const { flow_id } = useParams<{ flow_id: string }>();
    const navigate = useNavigate();

    const [consentInfo, setConsentInfo] = useState<ConsentInfo | null>(null);
    const [loading, setLoading] = useState(true);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    // Checked tools — user can deselect individual tools before approving
    const [checkedTools, setCheckedTools] = useState<Set<string>>(new Set());

    useEffect(() => {
        if (!flow_id) {
            setError('Missing consent flow ID');
            setLoading(false);
            return;
        }

        api.get<ConsentInfo>(`/api/auth/flow/${flow_id}/consent`)
            .then((res) => {
                setConsentInfo(res.data);
                setCheckedTools(new Set(res.data.requested_tools));
            })
            .catch((err: any) => {
                setError(getApiError(err, 'Failed to load consent information'));
            })
            .finally(() => setLoading(false));
    }, [flow_id]);

    const toggleTool = useCallback((tool: string) => {
        setCheckedTools((prev) => {
            const next = new Set(prev);
            if (next.has(tool)) next.delete(tool);
            else next.add(tool);
            return next;
        });
    }, []);

    const handleApprove = useCallback(async () => {
        if (!flow_id || !consentInfo) return;
        setSubmitting(true);
        try {
            const res = await api.post<ConsentApprovalResponse>(
                `/api/auth/flow/${flow_id}/consent`,
                {
                    allowed_tools: Array.from(checkedTools),
                    agent_id: consentInfo.agent_id ?? '',
                    task_id: flow_id,
                    ttl_seconds: consentInfo.ttl_seconds,
                    agent_name: consentInfo.agent_name,
                }
            );
            // Post the agent_token back to the opener window (MCP client)
            // or navigate to a success screen.
            if (window.opener) {
                window.opener.postMessage(
                    { type: 'agent_consent_granted', agent_token: res.data.agent_token, delegation_id: res.data.delegation_id },
                    '*'
                );
                window.close();
            } else {
                toast.success('Agent access granted');
                navigate('/account/profile');
            }
        } catch (err: any) {
            toast.error(getApiError(err, 'Failed to grant access'));
            setSubmitting(false);
        }
    }, [flow_id, consentInfo, checkedTools, navigate]);

    const handleDeny = useCallback(() => {
        if (window.opener) {
            window.opener.postMessage({ type: 'agent_consent_denied' }, '*');
            window.close();
        } else {
            navigate('/account/profile');
        }
    }, [navigate]);

    if (loading) {
        return (
            <div className="min-h-screen bg-background flex items-center justify-center">
                <div className="flex flex-col items-center gap-4">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary" />
                    <p className="text-muted-foreground text-sm">Loading consent request...</p>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="min-h-screen bg-background flex items-center justify-center p-4">
                <div className="max-w-md w-full bg-card rounded-xl p-8 border border-destructive/50 text-center">
                    <div className="text-destructive text-4xl mb-4">⚠</div>
                    <h1 className="text-xl font-bold text-foreground font-heading mb-2">Consent Error</h1>
                    <p className="text-muted-foreground text-sm mb-6">{error}</p>
                    <button
                        onClick={() => navigate('/account/profile')}
                        className="bg-accent hover:bg-accent/80 text-foreground px-6 py-2 rounded-xl text-sm font-semibold transition-colors"
                    >
                        Return Home
                    </button>
                </div>
            </div>
        );
    }

    if (!consentInfo) return null;

    const agentLabel = consentInfo.agent_name || consentInfo.agent_id || 'Unknown Agent';
    const anyChecked = checkedTools.size > 0;

    return (
        <div className="min-h-screen bg-background flex items-center justify-center p-4">
            <div className="max-w-md w-full bg-card rounded-xl border border-border overflow-hidden">
                {/* Header */}
                <div className="px-8 pt-8 pb-4 text-center">
                    <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/20 rounded-2xl mb-4">
                        <svg className="w-8 h-8 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                                d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23-.693L5 14.5m14.8.8l1.402 1.402c1 1 .03 2.698-1.382 2.698H4.18c-1.412 0-2.38-1.698-1.382-2.698L4.2 15.3" />
                        </svg>
                    </div>
                    <h1 className="text-xl font-bold text-foreground font-heading mb-1">Agent Access Request</h1>
                    <p className="text-muted-foreground text-sm">
                        <span className="text-foreground font-semibold">{agentLabel}</span>{' '}
                        is requesting permission to act on your behalf
                    </p>
                    <p className="text-muted-foreground text-xs mt-1">
                        Access expires in{' '}
                        <span className="text-foreground font-medium">{formatTtl(consentInfo.ttl_seconds)}</span>
                    </p>
                </div>

                {/* Tool permissions */}
                {consentInfo.requested_tools.length > 0 && (
                    <div className="px-8 py-4">
                        <p className="text-muted-foreground text-xs uppercase tracking-wider font-medium mb-3">
                            Requested tool permissions:
                        </p>
                        <ul className="space-y-2">
                            {consentInfo.requested_tools.map((tool) => (
                                <li key={tool} className="flex items-center gap-3">
                                    <input
                                        type="checkbox"
                                        id={`tool-${tool}`}
                                        checked={checkedTools.has(tool)}
                                        onChange={() => toggleTool(tool)}
                                        className="w-4 h-4 rounded accent-primary cursor-pointer"
                                    />
                                    <label
                                        htmlFor={`tool-${tool}`}
                                        className="text-foreground text-sm font-mono cursor-pointer select-none"
                                    >
                                        {tool}
                                    </label>
                                </li>
                            ))}
                        </ul>
                        <p className="text-muted-foreground text-xs mt-3">
                            Uncheck any tools you do not want this agent to use.
                        </p>
                    </div>
                )}

                {consentInfo.requested_tools.length === 0 && (
                    <div className="px-8 py-4">
                        <p className="text-muted-foreground text-sm text-center">
                            This agent is requesting general access without specific tool restrictions.
                        </p>
                    </div>
                )}

                {/* Actions */}
                <div className="px-8 py-6 flex gap-3">
                    <button
                        onClick={handleDeny}
                        disabled={submitting}
                        className="flex-1 bg-accent hover:bg-accent/80 disabled:opacity-50 text-foreground px-4 py-2.5 rounded-xl text-sm font-semibold transition-colors"
                    >
                        Deny
                    </button>
                    <button
                        onClick={handleApprove}
                        disabled={submitting || (!anyChecked && consentInfo.requested_tools.length > 0)}
                        className="flex-1 bg-primary hover:bg-primary/90 disabled:opacity-50 text-primary-foreground px-4 py-2.5 rounded-xl text-sm font-semibold transition-colors"
                    >
                        {submitting ? 'Granting...' : 'Grant Access'}
                    </button>
                </div>
            </div>
        </div>
    );
}
