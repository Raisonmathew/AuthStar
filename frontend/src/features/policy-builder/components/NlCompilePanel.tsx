/**
 * NlCompilePanel — Gap 2-B
 *
 * Natural-language → AST policy compiler panel for the Policy Builder.
 * Rendered as a slide-in side panel on the ConfigDetailPage when the user
 * clicks "Generate from description".
 *
 * Flow:
 *  1. User types a plain-English policy description + selects target action
 *  2. POST /api/v1/policy-builder/nl-compile → returns draft_config + explanation
 *  3. Panel shows the explanation and the draft JSON with warnings
 *  4. User clicks "Use this policy" → parent creates a new config with the draft
 */

import { useState, useCallback } from 'react';
import { api, getApiError } from '../../../lib/api';
import { toast } from 'sonner';

// ─── Types ────────────────────────────────────────────────────────────────────

interface NlCompileRequest {
    prompt: string;
    action_key: string;
    current_config?: unknown;
}

interface NlCompileResponse {
    draft_config: Record<string, unknown>;
    explanation: string;
    valid: boolean;
    warnings: string[];
}

interface Props {
    /** Pre-fill the action_key input (e.g. from the currently open config). */
    initialActionKey?: string;
    /** Current config JSON to pass as context to the LLM. */
    currentConfig?: unknown;
    /** Called when the user accepts the draft. Receives the draft_config object. */
    onAccept: (draft: Record<string, unknown>) => void;
    /** Called when the panel should close. */
    onClose: () => void;
}

// ─── EIAA action suggestions ──────────────────────────────────────────────────

const COMMON_ACTIONS = [
    'billing:read',
    'billing:write',
    'org:config',
    'org:read',
    'admin:manage',
    'user:manage_profile',
    'audit:read',
    'audit:verify',
    'agent:manage',
    'apikeys:manage',
    'policies:manage',
];

const PLACEHOLDER_PROMPTS = [
    'Allow billing:read only if the user is authenticated at AAL2 and their risk score is below 40',
    'Deny all access from VPN or Tor exit nodes, then allow if device is trusted',
    'Require WebAuthn (hardware key) for admin:manage actions',
    'Allow during business hours (9am–5pm UTC, Mon–Fri) only',
    'Block access if risk score exceeds 70, otherwise step-up to MFA',
];

// ─── Component ────────────────────────────────────────────────────────────────

export function NlCompilePanel({ initialActionKey = '', currentConfig, onAccept, onClose }: Props) {
    const [prompt, setPrompt] = useState('');
    const [actionKey, setActionKey] = useState(initialActionKey);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<NlCompileResponse | null>(null);
    const [showDraft, setShowDraft] = useState(false);
    const [placeholderIdx] = useState(() => Math.floor(Math.random() * PLACEHOLDER_PROMPTS.length));

    const compile = useCallback(async () => {
        if (!prompt.trim() || !actionKey.trim()) return;
        setLoading(true);
        setResult(null);
        try {
            const body: NlCompileRequest = {
                prompt,
                action_key: actionKey,
                ...(currentConfig ? { current_config: currentConfig } : {}),
            };
            const res = await api.post<NlCompileResponse>('/api/v1/policy-builder/nl-compile', body);
            setResult(res.data);
        } catch (err: any) {
            const msg = getApiError(err, 'Compilation failed');
            if (err?.response?.status === 503) {
                toast.error('NL compiler not configured. Set LLM_API_URL and LLM_API_KEY on the server.');
            } else {
                toast.error(msg);
            }
        } finally {
            setLoading(false);
        }
    }, [prompt, actionKey, currentConfig]);

    const handleAccept = useCallback(() => {
        if (!result) return;
        onAccept(result.draft_config);
        toast.success('Draft policy applied — review and deploy via the standard pipeline');
        onClose();
    }, [result, onAccept, onClose]);

    return (
        <div className="fixed inset-0 z-50 flex items-stretch justify-end">
            {/* Backdrop */}
            <div className="flex-1 bg-black/40" onClick={onClose} />

            {/* Panel */}
            <div className="w-full max-w-lg bg-card border-l border-border flex flex-col overflow-hidden">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-border flex-shrink-0">
                    <div>
                        <h2 className="text-base font-bold text-foreground font-heading">Generate Policy from Description</h2>
                        <p className="text-xs text-muted-foreground mt-0.5">Describe your policy in plain English — the AI will draft it for you</p>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 text-muted-foreground hover:text-foreground hover:bg-accent rounded-lg transition-colors"
                    >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* Form */}
                <div className="flex-1 overflow-y-auto p-6 space-y-5">
                    {/* Action key */}
                    <div>
                        <label className="block text-sm font-medium text-foreground mb-1.5">
                            EIAA Action <span className="text-destructive">*</span>
                        </label>
                        <input
                            list="action-suggestions"
                            value={actionKey}
                            onChange={e => setActionKey(e.target.value)}
                            placeholder="e.g. billing:read"
                            className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary"
                        />
                        <datalist id="action-suggestions">
                            {COMMON_ACTIONS.map(a => <option key={a} value={a} />)}
                        </datalist>
                    </div>

                    {/* Prompt */}
                    <div>
                        <label className="block text-sm font-medium text-foreground mb-1.5">
                            Policy description <span className="text-destructive">*</span>
                        </label>
                        <textarea
                            value={prompt}
                            onChange={e => { setPrompt(e.target.value); setResult(null); }}
                            placeholder={PLACEHOLDER_PROMPTS[placeholderIdx]}
                            rows={4}
                            className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground resize-none focus:outline-none focus:border-primary"
                        />
                        <p className="text-xs text-muted-foreground mt-1">
                            Be specific about conditions (risk score, AAL, time of day, device trust, etc.)
                        </p>
                    </div>

                    {/* Result */}
                    {result && (
                        <div className="space-y-4">
                            {/* Explanation */}
                            <div className="bg-muted/50 border border-border rounded-xl p-4">
                                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">AI Explanation</p>
                                <p className="text-sm text-foreground">{result.explanation}</p>
                            </div>

                            {/* Warnings */}
                            {result.warnings.length > 0 && (
                                <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4">
                                    <p className="text-xs font-semibold text-amber-500 uppercase tracking-wider mb-2">Warnings</p>
                                    <ul className="space-y-1">
                                        {result.warnings.map((w, i) => (
                                            <li key={i} className="text-sm text-amber-400 flex items-start gap-2">
                                                <span className="flex-shrink-0">⚠</span>
                                                <span>{w}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            {/* Draft JSON toggle */}
                            <div className="border border-border rounded-xl overflow-hidden">
                                <button
                                    onClick={() => setShowDraft(p => !p)}
                                    className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-foreground hover:bg-accent/50 transition-colors"
                                >
                                    <span>Draft config JSON</span>
                                    <svg
                                        className={`w-4 h-4 text-muted-foreground transition-transform ${showDraft ? 'rotate-180' : ''}`}
                                        fill="none" stroke="currentColor" viewBox="0 0 24 24"
                                    >
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                    </svg>
                                </button>
                                {showDraft && (
                                    <pre className="p-4 text-xs font-mono text-foreground bg-muted/50 overflow-x-auto border-t border-border">
                                        {JSON.stringify(result.draft_config, null, 2)}
                                    </pre>
                                )}
                            </div>

                            {!result.valid && (
                                <p className="text-xs text-red-400 text-center">
                                    The draft has validation errors — review and fix before deploying.
                                </p>
                            )}
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="px-6 py-4 border-t border-border flex gap-3 flex-shrink-0">
                    <button
                        onClick={compile}
                        disabled={loading || !prompt.trim() || !actionKey.trim()}
                        className="flex-1 px-4 py-2.5 bg-primary hover:bg-primary/90 disabled:opacity-50 text-primary-foreground rounded-lg text-sm font-semibold transition-colors"
                    >
                        {loading ? 'Generating...' : result ? 'Regenerate' : 'Generate Policy'}
                    </button>
                    {result && (
                        <button
                            onClick={handleAccept}
                            className="flex-1 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition-colors"
                        >
                            Use this policy →
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
