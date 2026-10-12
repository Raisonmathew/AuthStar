import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { api, getApiError } from '../lib/api';

interface ApiKeyListItem {
    id: string;
    name: string;
    key_prefix: string;
    scopes: string[];
    last_used_at: string | null;
    expires_at: string | null;
    created_at: string;
    revoked_at: string | null;
    /** sha256:hex fingerprint — null for keys created before migration 082 */
    key_fingerprint: string | null;
}

interface ApiKeyListResponse {
    active: ApiKeyListItem[];
    revoked: ApiKeyListItem[];
}

interface CreateApiKeyResponse extends ApiKeyListItem {
    key: string;
    key_fingerprint: string;
}

interface RevokeConfirmState {
    keyId: string;
    keyName: string;
    keyPrefix: string;
}

export default function APIKeysPage() {
    const navigate = useNavigate();
    const [activeKeys, setActiveKeys] = useState<ApiKeyListItem[]>([]);
    const [revokedKeys, setRevokedKeys] = useState<ApiKeyListItem[]>([]);
    const [showRevoked, setShowRevoked] = useState(false);
    const [loading, setLoading] = useState(true);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [creating, setCreating] = useState(false);
    const [revoking, setRevoking] = useState<string | null>(null);
    const [newKeyName, setNewKeyName] = useState('');
    const [newKeyScopes, setNewKeyScopes] = useState<string[]>([]);
    const [newKeyExpiry, setNewKeyExpiry] = useState('');
    const [nameError, setNameError] = useState('');
    const [newlyCreatedKey, setNewlyCreatedKey] = useState<CreateApiKeyResponse | null>(null);
    // Revocation confirmation modal state
    const [revokeConfirm, setRevokeConfirm] = useState<RevokeConfirmState | null>(null);
    const [revokeConfirmInput, setRevokeConfirmInput] = useState('');

    const loadKeys = useCallback(async () => {
        setLoading(true);
        try {
            const res = await api.get<ApiKeyListResponse | ApiKeyListItem[]>('/api/v1/api-keys');
            if (Array.isArray(res.data)) {
                setActiveKeys(res.data);
                setRevokedKeys([]);
            } else if (res.data) {
                setActiveKeys(res.data.active || []);
                setRevokedKeys(res.data.revoked || []);
            } else {
                setActiveKeys([]);
                setRevokedKeys([]);
            }
        } catch (err: any) {
            toast.error(getApiError(err, 'Failed to load API keys'));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { loadKeys(); }, [loadKeys]);

    const resetForm = () => {
        setNewKeyName('');
        setNewKeyScopes([]);
        setNewKeyExpiry('');
        setNameError('');
    };

    const handleCreateKey = async () => {
        const name = newKeyName.trim();
        if (!name) { setNameError('Key name is required'); return; }
        if (name.length > 100) { setNameError('Must be 100 characters or fewer'); return; }
        setNameError('');

        const scopes = newKeyScopes;
        const body: Record<string, unknown> = { name, scopes };
        if (newKeyExpiry) body.expires_at = new Date(newKeyExpiry).toISOString();

        setCreating(true);
        try {
            const res = await api.post<CreateApiKeyResponse>('/api/v1/api-keys', body);
            const created = res.data;
            setActiveKeys(prev => [{
                id: created.id,
                name: created.name,
                key_prefix: created.key_prefix,
                scopes: created.scopes,
                last_used_at: null,
                expires_at: created.expires_at,
                created_at: created.created_at,
                revoked_at: null,
                key_fingerprint: created.key_fingerprint,
            }, ...prev]);
            setNewlyCreatedKey(created);
            setShowCreateModal(false);
            resetForm();
            toast.success('API key created');
        } catch (err: any) {
            if (err?.response?.status === 409) {
                setNameError(`A key named "${name}" already exists`);
            } else {
                toast.error(getApiError(err, 'Failed to create API key'));
            }
        } finally {
            setCreating(false);
        }
    };

    /** Opens the "type prefix to confirm" modal instead of window.confirm() */
    const promptRevoke = (key: ApiKeyListItem) => {
        setRevokeConfirm({ keyId: key.id, keyName: key.name, keyPrefix: key.key_prefix });
        setRevokeConfirmInput('');
    };

    const handleRevokeKey = async () => {
        if (!revokeConfirm) return;
        const { keyId, keyName } = revokeConfirm;
        setRevoking(keyId);
        setRevokeConfirm(null);
        setRevokeConfirmInput('');
        try {
            await api.delete(`/api/v1/api-keys/${keyId}`);
            // Move the key from active to revoked list optimistically.
            const now = new Date().toISOString();
            setActiveKeys(prev => prev.filter(k => k.id !== keyId));
            setRevokedKeys(prev => {
                const revoked = activeKeys.find(k => k.id === keyId);
                if (!revoked) return prev;
                return [{ ...revoked, revoked_at: now }, ...prev];
            });
            toast.success(`"${keyName}" revoked`);
        } catch (err: any) {
            toast.error(getApiError(err, 'Failed to revoke API key'));
        } finally {
            setRevoking(null);
        }
    };

    const copyToClipboard = (value: string) => {
        navigator.clipboard.writeText(value)
            .then(() => toast.success('Copied to clipboard'))
            .catch(() => toast.error('Copy failed — please copy manually'));
    };

    const formatDate = (iso: string | null) => {
        if (!iso) return null;
        return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary" />
            </div>
        );
    }

    return (
        <div className="space-y-6">

            {/* Header */}
            <div>
                <button
                    onClick={() => navigate('/admin/dashboard')}
                    className="mb-4 text-muted-foreground hover:text-foreground transition-colors flex items-center gap-2"
                >
                    ← Back to Dashboard
                </button>
                <div className="flex justify-between items-start">
                    <div>
                        <h1 className="text-3xl font-bold text-foreground font-heading">API Keys</h1>
                        <p className="text-muted-foreground mt-2">
                            Create and manage API keys for programmatic access to the AuthStar API.
                        </p>
                    </div>
                    <button
                        onClick={() => { resetForm(); setShowCreateModal(true); }}
                        className="px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl transition-colors font-semibold font-heading"
                    >
                        + Create Key
                    </button>
                </div>
            </div>

            {/* One-time key reveal banner */}
            {newlyCreatedKey && (
                <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-xl p-5">
                    <div className="flex items-start gap-3">
                        <svg className="w-6 h-6 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <div className="flex-1 min-w-0">
                            <h3 className="font-semibold text-amber-900 dark:text-amber-200 mb-1">
                                Save your API key — it won't be shown again
                            </h3>
                            <p className="text-sm text-amber-800 dark:text-amber-300 mb-3">
                                Key <strong>{newlyCreatedKey.name}</strong> has been created. Copy it now and store it securely.
                            </p>
                            <div className="flex items-center gap-2">
                                <code className="flex-1 min-w-0 bg-card px-4 py-2.5 rounded-xl border border-amber-300 dark:border-amber-700 text-sm font-mono text-foreground overflow-x-auto whitespace-nowrap">
                                    {newlyCreatedKey.key}
                                </code>
                                <button
                                    onClick={() => copyToClipboard(newlyCreatedKey.key)}
                                    className="flex-shrink-0 px-4 py-2.5 bg-amber-600 hover:bg-amber-700 text-white rounded-xl transition-colors font-medium text-sm"
                                >
                                    Copy
                                </button>
                                <button
                                    onClick={() => setNewlyCreatedKey(null)}
                                    className="flex-shrink-0 px-4 py-2.5 bg-accent hover:bg-accent/80 text-foreground rounded-xl transition-colors text-sm"
                                >
                                    Done
                                </button>
                            </div>
                            <p className="text-xs text-amber-700 dark:text-amber-400 font-mono mt-1">
                                {newlyCreatedKey.key_fingerprint}
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* Active Keys table */}
            <div className="bg-card rounded-xl border border-border overflow-hidden">
                <div className="px-6 py-4 border-b border-border flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-foreground font-heading">
                        Active Keys
                        <span className="ml-2 text-sm font-normal text-muted-foreground">({activeKeys.length})</span>
                    </h2>
                </div>

                {activeKeys.length === 0 ? (
                    <div className="px-6 py-16 text-center">
                        <svg className="mx-auto h-12 w-12 text-muted-foreground mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                        <p className="text-muted-foreground text-sm">No API keys yet. Create one to get started.</p>
                    </div>
                ) : (
                    <div className="divide-y divide-border">
                        {activeKeys.map(key => (
                            <div key={key.id} className="px-6 py-4 flex items-start justify-between gap-4">
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 mb-1">
                                        <span className="font-medium text-foreground">{key.name}</span>
                                        {key.expires_at && new Date(key.expires_at) < new Date() && (
                                            <span className="px-2 py-0.5 rounded text-xs font-medium bg-destructive/10 text-destructive">
                                                Expired
                                            </span>
                                        )}
                                    </div>
                                    <code className="text-sm font-mono text-muted-foreground">
                                        ask_{key.key_prefix}_••••••••••••••••••••••••••••••••••••••••••••••••
                                    </code>
                                    {key.key_fingerprint && (
                                        <p className="text-xs font-mono text-muted-foreground/70 mt-0.5">
                                            {key.key_fingerprint}
                                        </p>
                                    )}
                                    <div className="flex flex-wrap items-center gap-3 mt-2 text-xs text-muted-foreground">
                                        <span>Created {formatDate(key.created_at)}</span>
                                        {key.last_used_at && <span>Last used {formatDate(key.last_used_at)}</span>}
                                        {key.expires_at && <span>Expires {formatDate(key.expires_at)}</span>}
                                        {key.scopes.length > 0 && (
                                            <span className="flex gap-1 flex-wrap">
                                                {key.scopes.map(s => (
                                                    <span key={s} className="px-1.5 py-0.5 bg-primary/10 text-primary rounded font-mono">
                                                        {s}
                                                    </span>
                                                ))}
                                            </span>
                                        )}
                                    </div>
                                </div>
                                <div className="flex items-center gap-2 flex-shrink-0">
                                    <button
                                        onClick={() => copyToClipboard(key.key_prefix)}
                                        className="px-3 py-1.5 text-sm bg-accent hover:bg-accent/80 text-foreground rounded-xl transition-colors"
                                        title="Copy key prefix (for identification only — not the full key)"
                                    >
                                        Copy prefix
                                    </button>
                                    <button
                                        onClick={() => promptRevoke(key)}
                                        disabled={revoking === key.id}
                                        className="px-3 py-1.5 text-sm bg-destructive/10 hover:bg-destructive/20 text-destructive rounded-xl transition-colors disabled:opacity-50"
                                    >
                                        {revoking === key.id ? 'Revoking…' : 'Revoke'}
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Revoked Keys section — collapsed by default */}
            {revokedKeys.length > 0 && (
                <div className="bg-card rounded-xl border border-border overflow-hidden">
                    <button
                        onClick={() => setShowRevoked(v => !v)}
                        className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-accent/50 transition-colors"
                    >
                        <h2 className="text-lg font-semibold text-foreground font-heading">
                            Revoked Keys
                            <span className="ml-2 text-sm font-normal text-muted-foreground">
                                ({revokedKeys.length}) — retained for audit
                            </span>
                        </h2>
                        <svg
                            className={`w-5 h-5 text-muted-foreground transition-transform ${showRevoked ? 'rotate-180' : ''}`}
                            fill="none" stroke="currentColor" viewBox="0 0 24 24"
                        >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                    </button>
                    {showRevoked && (
                        <div className="divide-y divide-border border-t border-border">
                            {revokedKeys.slice(0, 10).map(key => (
                                <div key={key.id} className="px-6 py-4 flex items-start justify-between gap-4 opacity-60">
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className="font-medium text-foreground line-through">{key.name}</span>
                                            <span className="px-2 py-0.5 rounded text-xs font-medium bg-muted text-muted-foreground">
                                                Revoked
                                            </span>
                                        </div>
                                        <code className="text-sm font-mono text-muted-foreground">
                                            ask_{key.key_prefix}_••••••••••••••••••••••••••••••••••••••••••••••••
                                        </code>
                                        {key.key_fingerprint && (
                                            <p className="text-xs font-mono text-muted-foreground/70 mt-0.5">
                                                {key.key_fingerprint}
                                            </p>
                                        )}
                                        <div className="flex flex-wrap items-center gap-3 mt-2 text-xs text-muted-foreground">
                                            <span>Created {formatDate(key.created_at)}</span>
                                            {key.revoked_at && <span className="text-destructive/70">Revoked {formatDate(key.revoked_at)}</span>}
                                        </div>
                                    </div>
                                </div>
                            ))}
                            {revokedKeys.length > 10 && (
                                <div className="px-6 py-3 text-xs text-muted-foreground text-center">
                                    Showing 10 of {revokedKeys.length} revoked keys — older entries retained in audit log only
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Create Key Modal */}
            {showCreateModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                    <div className="bg-card rounded-xl border border-border shadow-2xl p-6 w-full max-w-md">
                        <h3 className="text-xl font-semibold text-foreground font-heading mb-5">Create API Key</h3>

                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-1">
                                    Key Name <span className="text-destructive">*</span>
                                </label>
                                <input
                                    type="text"
                                    value={newKeyName}
                                    onChange={e => { setNewKeyName(e.target.value); setNameError(''); }}
                                    placeholder="e.g. Production Backend"
                                    maxLength={100}
                                    className={`w-full px-3 py-2 border rounded-xl bg-muted text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring ${nameError ? 'border-destructive' : 'border-border'}`}
                                    autoFocus
                                />
                                {nameError && <p className="mt-1 text-sm text-destructive">{nameError}</p>}
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">
                                    Scopes <span className="text-muted-foreground font-normal">(select permissions for this key)</span>
                                </label>
                                <div className="space-y-2">
                                    {[
                                        { value: 'keys:read', label: 'keys:read', desc: 'List API keys' },
                                        { value: 'keys:write', label: 'keys:write', desc: 'Create & revoke API keys' },
                                        { value: 'users:read', label: 'users:read', desc: 'Read user data' },
                                        { value: 'users:write', label: 'users:write', desc: 'Modify user data' },
                                        { value: 'orgs:read', label: 'orgs:read', desc: 'Read organization data' },
                                        { value: 'orgs:write', label: 'orgs:write', desc: 'Modify organization data' },
                                        { value: '*', label: '* (all)', desc: 'Full access — all scopes' },
                                    ].map(scope => (
                                        <label key={scope.value} className="flex items-center gap-2 cursor-pointer">
                                            <input
                                                type="checkbox"
                                                checked={newKeyScopes.includes(scope.value)}
                                                onChange={e => {
                                                    if (e.target.checked) {
                                                        setNewKeyScopes(prev => [...prev, scope.value]);
                                                    } else {
                                                        setNewKeyScopes(prev => prev.filter(s => s !== scope.value));
                                                    }
                                                }}
                                                className="rounded border-border text-primary focus:ring-ring"
                                            />
                                            <code className="text-sm font-mono text-foreground">{scope.label}</code>
                                            <span className="text-xs text-muted-foreground">— {scope.desc}</span>
                                        </label>
                                    ))}
                                </div>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-foreground mb-1">
                                    Expiry <span className="text-muted-foreground font-normal">(optional)</span>
                                </label>
                                <input
                                    type="datetime-local"
                                    value={newKeyExpiry}
                                    onChange={e => setNewKeyExpiry(e.target.value)}
                                    min={new Date().toISOString().slice(0, 16)}
                                    className="w-full px-3 py-2 border border-border rounded-xl bg-muted text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                                />
                                <p className="mt-1 text-xs text-muted-foreground">Leave blank for a non-expiring key.</p>
                            </div>

                            <div className="bg-primary/5 border border-primary/20 rounded-xl p-3">
                                <p className="text-sm text-foreground">
                                    🔑 The full key will be shown <strong>once</strong> after creation. Store it securely — it cannot be retrieved again.
                                </p>
                            </div>
                        </div>

                        <div className="flex gap-3 mt-6">
                            <button
                                onClick={() => { setShowCreateModal(false); resetForm(); }}
                                className="flex-1 px-4 py-2 bg-accent hover:bg-accent/80 text-foreground rounded-xl transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleCreateKey}
                                disabled={creating}
                                className="flex-1 px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl transition-colors font-semibold disabled:opacity-50"
                            >
                                {creating ? 'Creating…' : 'Create Key'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Revoke Confirmation Modal — "type prefix to confirm" */}
            {revokeConfirm && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                    <div className="bg-card rounded-xl border border-border shadow-2xl p-6 w-full max-w-md">
                        <h3 className="text-xl font-semibold text-foreground font-heading mb-2">Revoke API Key</h3>
                        <p className="text-sm text-muted-foreground mb-4">
                            Applications using <strong>{revokeConfirm.keyName}</strong> will immediately lose access.
                            This cannot be undone.
                        </p>
                        <div className="bg-destructive/5 border border-destructive/20 rounded-xl p-3 mb-4">
                            <p className="text-sm text-foreground">
                                To confirm, type the key prefix: <code className="font-mono font-semibold">{revokeConfirm.keyPrefix}</code>
                            </p>
                        </div>
                        <input
                            type="text"
                            value={revokeConfirmInput}
                            onChange={e => setRevokeConfirmInput(e.target.value)}
                            placeholder={revokeConfirm.keyPrefix}
                            className="w-full px-3 py-2 border border-border rounded-xl bg-muted text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-destructive mb-4"
                            autoFocus
                            onKeyDown={e => {
                                if (e.key === 'Enter' && revokeConfirmInput === revokeConfirm.keyPrefix) {
                                    handleRevokeKey();
                                }
                            }}
                        />
                        <div className="flex gap-3">
                            <button
                                onClick={() => { setRevokeConfirm(null); setRevokeConfirmInput(''); }}
                                className="flex-1 px-4 py-2 bg-accent hover:bg-accent/80 text-foreground rounded-xl transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleRevokeKey}
                                disabled={revokeConfirmInput !== revokeConfirm.keyPrefix}
                                className="flex-1 px-4 py-2 bg-destructive hover:bg-destructive/90 text-white rounded-xl transition-colors font-semibold disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                                Revoke Key
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
