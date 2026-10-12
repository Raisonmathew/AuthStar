/**
 * CompliancePage — /admin/compliance
 *
 * Gap 2-A: SOC 2 evidence tier.
 *
 * Lets tenant admins:
 *  1. Pick a date range and download a signed compliance bundle (JSON)
 *  2. Browse the task chain for any task_id
 *  3. Re-verify an individual execution's attestation (Verified / Discrepancy)
 */

import { useState, useCallback } from 'react';
import { api, getApiError } from '../../lib/api';
import { toast } from 'sonner';

// ─── Types ────────────────────────────────────────────────────────────────────

interface BundleSummary {
    total_decisions: number;
    allowed: number;
    denied: number;
    by_action: Record<string, { allowed: number; denied: number }>;
}

interface ComplianceBundle {
    tenant_id: string;
    generated_at: string;
    period_start: string;
    period_end: string;
    executions: BundleExecution[];
    summary: BundleSummary;
    bundle_sig_b64: string;
}

interface BundleExecution {
    decision_ref: string;
    action: string;
    allowed: boolean;
    reason: string | null;
    attestation_sig_b64: string;
    executed_at: string;
    agent_id: string | null;
    tool_name: string | null;
    task_id: string | null;
}

interface VerifyResult {
    decision_ref: string;
    original_decision: boolean;
    replayed_decision: boolean;
    decisions_match: boolean;
    verification_status: 'verified' | 'discrepancy' | 'capsule_not_found' | 'execution_error';
    discrepancy_reason: string | null;
}

interface TaskChainItem {
    id: string;
    decision_ref: string;
    action: string;
    allowed: boolean | null;
    attestation_signature_b64: string;
    created_at: string;
    agent_id: string | null;
    tool_name: string | null;
    task_id: string | null;
    principal_type: string;
}

interface TaskChainPage {
    items: TaskChainItem[];
    next_cursor: string | null;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function statusBadge(status: VerifyResult['verification_status']) {
    const map = {
        verified: 'bg-emerald-500/20 text-emerald-400',
        discrepancy: 'bg-red-500/20 text-red-400',
        capsule_not_found: 'bg-amber-500/20 text-amber-400',
        execution_error: 'bg-red-500/20 text-red-400',
    };
    return map[status] ?? 'bg-muted text-muted-foreground';
}

// ─── Main page ────────────────────────────────────────────────────────────────

type Tab = 'report' | 'chain' | 'verify';

export default function CompliancePage() {
    const [tab, setTab] = useState<Tab>('report');

    return (
        <div className="space-y-6">
            {/* Header */}
            <div>
                <h1 className="text-2xl font-bold text-foreground font-heading mb-1">Compliance</h1>
                <p className="text-muted-foreground text-sm">
                    Export SOC 2 evidence bundles, browse task chains, and re-verify authorization decisions.
                </p>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-border">
                {([
                    ['report', 'Evidence Report'],
                    ['chain', 'Task Chain'],
                    ['verify', 'Re-Verify Decision'],
                ] as [Tab, string][]).map(([id, label]) => (
                    <button
                        key={id}
                        onClick={() => setTab(id)}
                        className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                            tab === id
                                ? 'border-primary text-primary'
                                : 'border-transparent text-muted-foreground hover:text-foreground'
                        }`}
                    >
                        {label}
                    </button>
                ))}
            </div>

            {tab === 'report' && <EvidenceReport />}
            {tab === 'chain' && <TaskChainViewer />}
            {tab === 'verify' && <DecisionVerifier />}
        </div>
    );
}

// ─── Tab: Evidence Report ─────────────────────────────────────────────────────

function EvidenceReport() {
    const defaultEnd = new Date().toISOString().slice(0, 10);
    const defaultStart = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);

    const [start, setStart] = useState(defaultStart);
    const [end, setEnd] = useState(defaultEnd);
    const [loading, setLoading] = useState(false);
    const [bundle, setBundle] = useState<ComplianceBundle | null>(null);

    const generate = useCallback(async () => {
        setLoading(true);
        setBundle(null);
        try {
            const res = await api.get<ComplianceBundle>('/api/v1/compliance/report', {
                params: { start: `${start}T00:00:00Z`, end: `${end}T23:59:59Z` },
            });
            setBundle(res.data);
        } catch (err: any) {
            toast.error(getApiError(err, 'Failed to generate report'));
        } finally {
            setLoading(false);
        }
    }, [start, end]);

    const download = useCallback(async () => {
        try {
            const res = await api.get<Blob>('/api/v1/compliance/report/export', {
                params: { start: `${start}T00:00:00Z`, end: `${end}T23:59:59Z` },
                responseType: 'blob',
            });
            const url = URL.createObjectURL(res.data);
            const a = document.createElement('a');
            a.href = url;
            a.download = `authstar-compliance-${start}-${end}.json`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (err: any) {
            toast.error(getApiError(err, 'Export failed'));
        }
    }, [start, end]);

    return (
        <div className="space-y-6">
            {/* Controls */}
            <div className="bg-card border border-border rounded-xl p-6">
                <h2 className="text-sm font-semibold text-foreground mb-4">Generate SOC 2 Evidence Bundle</h2>
                <div className="flex flex-wrap gap-4 items-end">
                    <div>
                        <label className="block text-xs text-muted-foreground mb-1">Start date</label>
                        <input
                            type="date"
                            value={start}
                            onChange={e => setStart(e.target.value)}
                            className="bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground"
                        />
                    </div>
                    <div>
                        <label className="block text-xs text-muted-foreground mb-1">End date</label>
                        <input
                            type="date"
                            value={end}
                            onChange={e => setEnd(e.target.value)}
                            className="bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground"
                        />
                    </div>
                    <button
                        onClick={generate}
                        disabled={loading}
                        className="px-4 py-2 bg-primary hover:bg-primary/90 disabled:opacity-50 text-primary-foreground rounded-lg text-sm font-semibold transition-colors"
                    >
                        {loading ? 'Generating...' : 'Generate Report'}
                    </button>
                    {bundle && (
                        <button
                            onClick={download}
                            className="px-4 py-2 bg-accent hover:bg-accent/80 text-foreground rounded-lg text-sm font-semibold transition-colors flex items-center gap-2"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                            </svg>
                            Export JSON
                        </button>
                    )}
                </div>
            </div>

            {/* Summary */}
            {bundle && (
                <>
                    <div className="grid grid-cols-3 gap-4">
                        <div className="bg-card border border-border rounded-xl p-5">
                            <p className="text-xs text-muted-foreground mb-1">Total Decisions</p>
                            <p className="text-2xl font-bold text-foreground">{bundle.summary.total_decisions.toLocaleString()}</p>
                        </div>
                        <div className="bg-card border border-border rounded-xl p-5">
                            <p className="text-xs text-muted-foreground mb-1">Allowed</p>
                            <p className="text-2xl font-bold text-emerald-400">{bundle.summary.allowed.toLocaleString()}</p>
                        </div>
                        <div className="bg-card border border-border rounded-xl p-5">
                            <p className="text-xs text-muted-foreground mb-1">Denied</p>
                            <p className="text-2xl font-bold text-red-400">{bundle.summary.denied.toLocaleString()}</p>
                        </div>
                    </div>

                    {/* By-action breakdown */}
                    <div className="bg-card border border-border rounded-xl overflow-hidden">
                        <div className="px-6 py-4 border-b border-border">
                            <h3 className="text-sm font-semibold text-foreground">Decisions by Action</h3>
                        </div>
                        <div className="divide-y divide-border">
                            {Object.entries(bundle.summary.by_action).map(([action, counts]) => (
                                <div key={action} className="px-6 py-3 flex items-center justify-between gap-4">
                                    <span className="text-sm font-mono text-foreground">{action}</span>
                                    <div className="flex gap-6 text-xs">
                                        <span className="text-emerald-400">{counts.allowed} allowed</span>
                                        <span className="text-red-400">{counts.denied} denied</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Signature */}
                    <div className="bg-muted/50 border border-border rounded-xl p-4 text-xs">
                        <p className="text-muted-foreground mb-1">Bundle signature (Ed25519)</p>
                        <p className="font-mono text-foreground break-all">
                            {bundle.bundle_sig_b64 || '(no signing key configured for this tenant)'}
                        </p>
                    </div>
                </>
            )}
        </div>
    );
}

// ─── Tab: Task Chain Viewer ───────────────────────────────────────────────────

function TaskChainViewer() {
    const [taskId, setTaskId] = useState('');
    const [loading, setLoading] = useState(false);
    const [chain, setChain] = useState<TaskChainItem[]>([]);
    const [nextCursor, setNextCursor] = useState<string | null>(null);
    const [searched, setSearched] = useState(false);

    const load = useCallback(async (cursor?: string) => {
        if (!taskId.trim()) return;
        setLoading(true);
        try {
            const res = await api.get<TaskChainPage>(`/api/v1/audit/task/${encodeURIComponent(taskId)}`, {
                params: { ...(cursor ? { cursor } : {}), limit: 50 },
            });
            setChain(prev => cursor ? [...prev, ...res.data.items] : res.data.items);
            setNextCursor(res.data.next_cursor);
            setSearched(true);
        } catch (err: any) {
            toast.error(getApiError(err, 'Failed to load task chain'));
        } finally {
            setLoading(false);
        }
    }, [taskId]);

    return (
        <div className="space-y-4">
            <div className="flex gap-3">
                <input
                    type="text"
                    placeholder="Enter task_id..."
                    value={taskId}
                    onChange={e => { setTaskId(e.target.value); setSearched(false); setChain([]); }}
                    className="flex-1 bg-background border border-border rounded-lg px-4 py-2 text-sm text-foreground placeholder:text-muted-foreground"
                />
                <button
                    onClick={() => load()}
                    disabled={loading || !taskId.trim()}
                    className="px-4 py-2 bg-primary hover:bg-primary/90 disabled:opacity-50 text-primary-foreground rounded-lg text-sm font-semibold transition-colors"
                >
                    {loading ? 'Loading...' : 'Load Chain'}
                </button>
            </div>

            {searched && chain.length === 0 && !loading && (
                <p className="text-muted-foreground text-sm text-center py-8">No executions found for this task ID.</p>
            )}

            {chain.length > 0 && (
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                    <div className="divide-y divide-border">
                        {chain.map((item, i) => (
                            <div key={item.id} className="px-6 py-4 flex items-start gap-4">
                                <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0 text-xs font-bold text-primary mt-0.5">
                                    {i + 1}
                                </div>
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-3 flex-wrap">
                                        <span className="text-sm font-mono text-foreground">{item.action}</span>
                                        <span className={`text-xs px-2 py-0.5 rounded-full ${item.allowed ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                                            {item.allowed ? 'Allowed' : 'Denied'}
                                        </span>
                                        <span className="text-xs text-muted-foreground">{item.principal_type}</span>
                                    </div>
                                    <div className="flex gap-x-4 mt-1 flex-wrap text-xs text-muted-foreground">
                                        {item.agent_id && <span>Agent: {item.agent_id}</span>}
                                        {item.tool_name && <span>Tool: {item.tool_name}</span>}
                                        <span>{new Date(item.created_at).toLocaleString()}</span>
                                    </div>
                                    <p className="text-xs font-mono text-muted-foreground mt-1 truncate">ref: {item.decision_ref}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                    {nextCursor && (
                        <div className="p-4 border-t border-border text-center">
                            <button
                                onClick={() => load(nextCursor)}
                                disabled={loading}
                                className="text-sm text-primary hover:underline disabled:opacity-50"
                            >
                                {loading ? 'Loading...' : 'Load more'}
                            </button>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

// ─── Tab: Re-Verify Decision ──────────────────────────────────────────────────

function DecisionVerifier() {
    const [decisionRef, setDecisionRef] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<VerifyResult | null>(null);

    const verify = useCallback(async () => {
        if (!decisionRef.trim()) return;
        setLoading(true);
        setResult(null);
        try {
            const res = await api.get<{ result: VerifyResult }>(
                `/api/v1/audit/reexecution/verify/${encodeURIComponent(decisionRef)}`
            );
            setResult(res.data.result);
        } catch (err: any) {
            toast.error(getApiError(err, 'Verification failed'));
        } finally {
            setLoading(false);
        }
    }, [decisionRef]);

    return (
        <div className="max-w-xl space-y-4">
            <div className="flex gap-3">
                <input
                    type="text"
                    placeholder="Enter decision_ref..."
                    value={decisionRef}
                    onChange={e => { setDecisionRef(e.target.value); setResult(null); }}
                    className="flex-1 bg-background border border-border rounded-lg px-4 py-2 text-sm text-foreground placeholder:text-muted-foreground"
                />
                <button
                    onClick={verify}
                    disabled={loading || !decisionRef.trim()}
                    className="px-4 py-2 bg-primary hover:bg-primary/90 disabled:opacity-50 text-primary-foreground rounded-lg text-sm font-semibold transition-colors"
                >
                    {loading ? 'Verifying...' : 'Re-Verify'}
                </button>
            </div>

            {result && (
                <div className="bg-card border border-border rounded-xl p-6 space-y-4">
                    <div className="flex items-center gap-3">
                        <span className={`text-sm font-semibold px-3 py-1 rounded-full ${statusBadge(result.verification_status)}`}>
                            {result.verification_status.replace(/_/g, ' ').toUpperCase()}
                        </span>
                        {result.decisions_match ? (
                            <span className="text-emerald-400 text-sm">Decisions match ✓</span>
                        ) : (
                            <span className="text-red-400 text-sm">Decision mismatch ✗</span>
                        )}
                    </div>

                    <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                            <p className="text-muted-foreground text-xs mb-1">Original decision</p>
                            <p className={`font-semibold ${result.original_decision ? 'text-emerald-400' : 'text-red-400'}`}>
                                {result.original_decision ? 'ALLOW' : 'DENY'}
                            </p>
                        </div>
                        <div>
                            <p className="text-muted-foreground text-xs mb-1">Replayed decision</p>
                            <p className={`font-semibold ${result.replayed_decision ? 'text-emerald-400' : 'text-red-400'}`}>
                                {result.replayed_decision ? 'ALLOW' : 'DENY'}
                            </p>
                        </div>
                    </div>

                    {result.discrepancy_reason && (
                        <div className="bg-muted/50 rounded-lg p-3 text-xs text-muted-foreground">
                            {result.discrepancy_reason}
                        </div>
                    )}

                    <p className="text-xs font-mono text-muted-foreground break-all">ref: {result.decision_ref}</p>
                </div>
            )}
        </div>
    );
}
