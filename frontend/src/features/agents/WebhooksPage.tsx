import { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import {
    webhooksApi,
    type WebhookEndpoint,
    type CreateWebhookResponse,
} from '../../lib/api/webhooks';

// ---- helpers -----------------------------------------------------------------

function formatRelative(iso: string | null): string {
    if (!iso) return 'Never';
    const diff = Date.now() - new Date(iso).getTime();
    const secs = Math.floor(diff / 1000);
    if (secs < 60) return 'Just now';
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
}

const EVENT_TYPES = [
    'agent.action.authorized',
    'agent.action.denied',
    'agent.task.completed',
];

// ---- Create / Edit modal -----------------------------------------------------

interface WebhookModalProps {
    initial?: WebhookEndpoint | null;
    onClose: () => void;
    onSaved: (created: CreateWebhookResponse | null, updated: WebhookEndpoint | null) => void;
}

function WebhookModal({ initial, onClose, onSaved }: WebhookModalProps) {
    const isEdit = !!initial;
    const [url, setUrl] = useState(initial?.url ?? '');
    const [secret, setSecret] = useState('');
    const [description, setDescription] = useState(initial?.description ?? '');
    const [urlError, setUrlError] = useState('');
    const [secretError, setSecretError] = useState('');
    const [submitting, setSubmitting] = useState(false);

    // Close on Escape
    useEffect(() => {
        const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
        document.addEventListener('keydown', handler);
        return () => document.removeEventListener('keydown', handler);
    }, [onClose]);

    const validate = () => {
        let ok = true;
        if (!url.startsWith('https://')) {
            setUrlError('URL must start with https://');
            ok = false;
        } else {
            setUrlError('');
        }
        if (!isEdit && secret.length < 16) {
            setSecretError('Secret must be at least 16 characters');
            ok = false;
        } else if (isEdit && secret && secret.length < 16) {
            setSecretError('Secret must be at least 16 characters if changing');
            ok = false;
        } else {
            setSecretError('');
        }
        return ok;
    };

    const handleSubmit = async () => {
        if (!validate()) return;
        setSubmitting(true);
        try {
            if (isEdit && initial) {
                const res = await webhooksApi.update(initial.id, {
                    url,
                    ...(secret ? { secret } : {}),
                    description: description || undefined,
                });
                onSaved(null, res.data);
                toast.success('Webhook updated');
            } else {
                const res = await webhooksApi.create({ url, secret, description: description || undefined });
                onSaved(res.data, null);
                toast.success('Webhook registered');
            }
        } catch (err: unknown) {
            const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
            toast.error(msg || `Failed to ${isEdit ? 'update' : 'register'} webhook`);
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" data-testid="webhook-modal">
            <div className="bg-card border border-border rounded-2xl shadow-2xl w-full max-w-lg">
                <div className="flex items-center justify-between p-6 border-b border-border">
                    <h2 className="text-lg font-bold text-foreground font-heading">
                        {isEdit ? 'Edit Webhook' : 'Add Webhook Endpoint'}
                    </h2>
                    <button onClick={onClose} className="text-muted-foreground hover:text-foreground rounded-lg p-1 transition-colors" aria-label="Close">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <div className="p-6 space-y-5">
                    {/* URL */}
                    <div className="space-y-1.5">
                        <label className="block text-sm font-medium text-foreground" htmlFor="wh-url">
                            Endpoint URL <span className="text-destructive">*</span>
                        </label>
                        <input
                            id="wh-url"
                            type="url"
                            placeholder="https://hooks.example.com/authstar"
                            value={url}
                            onChange={e => setUrl(e.target.value)}
                            className="w-full px-3 py-2 rounded-xl border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary transition-colors"
                        />
                        {urlError && <p className="text-xs text-destructive">{urlError}</p>}
                    </div>

                    {/* Secret */}
                    <div className="space-y-1.5">
                        <label className="block text-sm font-medium text-foreground" htmlFor="wh-secret">
                            HMAC Secret {!isEdit && <span className="text-destructive">*</span>}
                            {isEdit && <span className="text-muted-foreground text-xs ml-1">(leave blank to keep existing)</span>}
                        </label>
                        <input
                            id="wh-secret"
                            type="password"
                            placeholder={isEdit ? 'Leave blank to keep current secret' : 'Min. 16 characters'}
                            value={secret}
                            onChange={e => setSecret(e.target.value)}
                            className="w-full px-3 py-2 rounded-xl border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary transition-colors"
                        />
                        {secretError && <p className="text-xs text-destructive">{secretError}</p>}
                        {!isEdit && (
                            <p className="text-xs text-muted-foreground">
                                Stored securely. Shown once on creation. Used to sign payloads as{' '}
                                <code className="text-xs bg-muted px-1 rounded">X-AuthStar-Signature: sha256=...</code>
                            </p>
                        )}
                    </div>

                    {/* Description */}
                    <div className="space-y-1.5">
                        <label className="block text-sm font-medium text-foreground" htmlFor="wh-desc">
                            Description <span className="text-muted-foreground text-xs">(optional)</span>
                        </label>
                        <input
                            id="wh-desc"
                            type="text"
                            placeholder="e.g. Production event receiver"
                            value={description}
                            onChange={e => setDescription(e.target.value)}
                            className="w-full px-3 py-2 rounded-xl border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary transition-colors"
                        />
                    </div>

                    {/* Events info */}
                    {!isEdit && (
                        <div className="rounded-xl bg-muted/50 border border-border p-4 space-y-2">
                            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Events delivered</p>
                            <div className="flex flex-wrap gap-1.5">
                                {EVENT_TYPES.map(e => (
                                    <span key={e} className="px-2 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-mono">
                                        {e}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                </div>

                <div className="flex justify-end gap-3 p-6 border-t border-border">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 rounded-xl text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleSubmit}
                        disabled={submitting}
                        className="px-5 py-2 rounded-xl text-sm font-semibold bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors font-heading"
                    >
                        {submitting ? 'Saving…' : isEdit ? 'Save Changes' : 'Add Endpoint'}
                    </button>
                </div>
            </div>
        </div>
    );
}

// ---- Secret reveal modal -----------------------------------------------------

interface SecretRevealModalProps {
    data: CreateWebhookResponse;
    onClose: () => void;
}

function SecretRevealModal({ data, onClose }: SecretRevealModalProps) {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        await navigator.clipboard.writeText(data.secret);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" data-testid="secret-reveal-modal">
            <div className="bg-card border border-border rounded-2xl shadow-2xl w-full max-w-lg">
                <div className="p-6 border-b border-border">
                    <h2 className="text-lg font-bold text-foreground font-heading">Webhook Registered</h2>
                    <p className="text-sm text-muted-foreground mt-1">
                        Save this secret now. It will not be shown again.
                    </p>
                </div>
                <div className="p-6 space-y-4">
                    <div className="rounded-xl bg-amber-500/10 border border-amber-500/20 p-3 text-xs text-amber-600 dark:text-amber-400 font-medium">
                        Copy and store the secret securely. AuthStar cannot recover it.
                    </div>
                    <div className="space-y-1.5">
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Endpoint URL</p>
                        <p className="text-sm text-foreground font-mono break-all">{data.url}</p>
                    </div>
                    <div className="space-y-1.5">
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">HMAC Secret</p>
                        <div className="flex items-center gap-2">
                            <code className="flex-1 text-sm bg-muted px-3 py-2 rounded-xl font-mono break-all text-foreground border border-border" data-testid="webhook-secret-value">
                                {data.secret}
                            </code>
                            <button
                                onClick={handleCopy}
                                className="shrink-0 px-3 py-2 rounded-xl text-sm font-medium bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
                                aria-label="Copy secret"
                            >
                                {copied ? 'Copied!' : 'Copy'}
                            </button>
                        </div>
                    </div>
                    <div className="space-y-1.5">
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Signature Header Format</p>
                        <code className="block text-xs bg-muted px-3 py-2 rounded-xl font-mono text-muted-foreground border border-border">
                            X-AuthStar-Signature: sha256=&lt;hex&gt;
                        </code>
                    </div>
                </div>
                <div className="flex justify-end p-6 border-t border-border">
                    <button
                        onClick={onClose}
                        className="px-5 py-2 rounded-xl text-sm font-semibold bg-primary text-primary-foreground hover:bg-primary/90 transition-colors font-heading"
                    >
                        Done
                    </button>
                </div>
            </div>
        </div>
    );
}

// ---- Main page ---------------------------------------------------------------

export default function WebhooksPage() {
    const [webhooks, setWebhooks] = useState<WebhookEndpoint[]>([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [editTarget, setEditTarget] = useState<WebhookEndpoint | null>(null);
    const [revealData, setRevealData] = useState<CreateWebhookResponse | null>(null);
    const [testingId, setTestingId] = useState<string | null>(null);
    const [deletingId, setDeletingId] = useState<string | null>(null);
    const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const res = await webhooksApi.list();
            setWebhooks(res.data);
        } catch {
            toast.error('Failed to load webhooks');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { load(); }, [load]);

    const handleSaved = (created: CreateWebhookResponse | null, updated: WebhookEndpoint | null) => {
        setShowModal(false);
        setEditTarget(null);
        if (created) {
            setRevealData(created);
            // Optimistically prepend the new webhook with masked secret
            setWebhooks(prev => [{
                id: created.id,
                url: created.url,
                secret_masked: '********',
                description: created.description,
                active: true,
                last_delivery_at: null,
                last_delivery_status: null,
                last_delivery_success: null,
                created_at: created.created_at,
                updated_at: created.created_at,
            }, ...prev]);
        }
        if (updated) {
            setWebhooks(prev => prev.map(w => w.id === updated.id ? { ...updated, secret_masked: '********' } : w));
        }
    };

    const handleTest = async (id: string) => {
        setTestingId(id);
        try {
            await webhooksApi.test(id);
            toast.success('Test event dispatched — check your endpoint receiver');
        } catch {
            toast.error('Failed to dispatch test event');
        } finally {
            setTestingId(null);
        }
    };

    const handleDelete = async (id: string) => {
        setDeletingId(id);
        setConfirmDeleteId(null);
        try {
            await webhooksApi.delete(id);
            setWebhooks(prev => prev.filter(w => w.id !== id));
            toast.success('Webhook removed');
        } catch {
            toast.error('Failed to remove webhook');
        } finally {
            setDeletingId(null);
        }
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-bold text-foreground font-heading">Webhook Endpoints</h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        Receive real-time HMAC-signed events when agent tool calls are authorized or denied.
                    </p>
                </div>
                <button
                    onClick={() => { setEditTarget(null); setShowModal(true); }}
                    className="shrink-0 flex items-center gap-2 px-4 py-2 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 transition-colors font-heading"
                >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                    Add Endpoint
                </button>
            </div>

            {/* Payload format callout */}
            <div className="rounded-2xl bg-muted/50 border border-border p-5 space-y-3">
                <p className="text-sm font-semibold text-foreground">Payload format (HMAC-SHA256 signed)</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1">
                        <p className="text-xs text-muted-foreground font-medium">Request headers</p>
                        <pre className="text-xs bg-background border border-border rounded-xl p-3 font-mono text-muted-foreground overflow-x-auto">{`Content-Type: application/json
X-AuthStar-Event: agent.action.authorized
X-AuthStar-Signature: sha256=<hex>`}</pre>
                    </div>
                    <div className="space-y-1">
                        <p className="text-xs text-muted-foreground font-medium">Events delivered</p>
                        <div className="flex flex-col gap-1.5 pt-0.5">
                            {EVENT_TYPES.map(e => (
                                <span key={e} className="px-2 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-mono w-fit">
                                    {e}
                                </span>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* List */}
            {loading ? (
                <div className="flex items-center justify-center h-40 text-muted-foreground text-sm">Loading…</div>
            ) : webhooks.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-border p-12 text-center space-y-3">
                    <div className="w-12 h-12 rounded-2xl bg-muted flex items-center justify-center mx-auto">
                        <svg className="w-6 h-6 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
                        </svg>
                    </div>
                    <div>
                        <p className="font-semibold text-foreground font-heading">No webhook endpoints</p>
                        <p className="text-sm text-muted-foreground mt-1">Add an HTTPS endpoint to start receiving real-time agent events.</p>
                    </div>
                    <button
                        onClick={() => { setEditTarget(null); setShowModal(true); }}
                        className="mt-2 px-4 py-2 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 transition-colors font-heading"
                    >
                        Add Endpoint
                    </button>
                </div>
            ) : (
                <div className="space-y-3">
                    {webhooks.map(wh => (
                        <div
                            key={wh.id}
                            className="rounded-2xl border border-border bg-card p-5 space-y-4"
                            data-testid={`webhook-row-${wh.id}`}
                        >
                            <div className="flex items-start justify-between gap-4">
                                <div className="min-w-0 space-y-1">
                                    <div className="flex items-center gap-2 flex-wrap">
                                        <span className={`w-2 h-2 rounded-full shrink-0 ${wh.active ? 'bg-emerald-500' : 'bg-muted-foreground'}`} />
                                        <p className="font-mono text-sm font-medium text-foreground break-all">{wh.url}</p>
                                        <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${wh.active ? 'bg-emerald-500/10 text-emerald-600' : 'bg-muted text-muted-foreground'}`}>
                                            {wh.active ? 'Active' : 'Inactive'}
                                        </span>
                                    </div>
                                    {wh.description && (
                                        <p className="text-xs text-muted-foreground">{wh.description}</p>
                                    )}
                                </div>
                                <div className="flex items-center gap-2 shrink-0">
                                    <button
                                        onClick={() => handleTest(wh.id)}
                                        disabled={testingId === wh.id}
                                        className="px-3 py-1.5 rounded-xl text-xs font-medium border border-border text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50 transition-colors"
                                        aria-label="Send test event"
                                    >
                                        {testingId === wh.id ? 'Sending…' : 'Test'}
                                    </button>
                                    <button
                                        onClick={() => { setEditTarget(wh); setShowModal(true); }}
                                        className="px-3 py-1.5 rounded-xl text-xs font-medium border border-border text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                                        aria-label="Edit webhook"
                                    >
                                        Edit
                                    </button>
                                    <button
                                        onClick={() => setConfirmDeleteId(wh.id)}
                                        disabled={deletingId === wh.id}
                                        className="px-3 py-1.5 rounded-xl text-xs font-medium border border-destructive/30 text-destructive hover:bg-destructive/5 disabled:opacity-50 transition-colors"
                                        aria-label="Remove webhook"
                                    >
                                        {deletingId === wh.id ? 'Removing…' : 'Remove'}
                                    </button>
                                </div>
                            </div>

                            {/* Delivery status */}
                            <div className="flex items-center gap-6 text-xs text-muted-foreground border-t border-border pt-3">
                                <span>
                                    Last delivery:{' '}
                                    <span className={`font-medium ${wh.last_delivery_success === false ? 'text-destructive' : wh.last_delivery_success ? 'text-emerald-600' : 'text-foreground'}`}>
                                        {wh.last_delivery_at ? formatRelative(wh.last_delivery_at) : 'Never'}
                                        {wh.last_delivery_status != null && ` · ${wh.last_delivery_status}`}
                                    </span>
                                </span>
                                <span className="font-mono text-[10px] text-muted-foreground/60 truncate">
                                    {wh.id}
                                </span>
                            </div>

                            {/* Delete confirm */}
                            {confirmDeleteId === wh.id && (
                                <div className="rounded-xl bg-destructive/5 border border-destructive/20 p-3 flex items-center justify-between gap-4">
                                    <p className="text-sm text-destructive font-medium">Remove this webhook? This cannot be undone.</p>
                                    <div className="flex gap-2 shrink-0">
                                        <button
                                            onClick={() => setConfirmDeleteId(null)}
                                            className="px-3 py-1.5 rounded-xl text-xs font-medium text-muted-foreground hover:bg-accent transition-colors"
                                        >
                                            Cancel
                                        </button>
                                        <button
                                            onClick={() => handleDelete(wh.id)}
                                            className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-destructive text-white hover:bg-destructive/90 transition-colors"
                                        >
                                            Remove
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}

            {/* Modals */}
            {showModal && (
                <WebhookModal
                    initial={editTarget}
                    onClose={() => { setShowModal(false); setEditTarget(null); }}
                    onSaved={handleSaved}
                />
            )}
            {revealData && (
                <SecretRevealModal
                    data={revealData}
                    onClose={() => { setRevealData(null); load(); }}
                />
            )}
        </div>
    );
}
