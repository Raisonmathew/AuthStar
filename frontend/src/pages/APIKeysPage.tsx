import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { api } from '../lib/api';

interface ApiKeyListItem {
    id: string;
    name: string;
    key_prefix: string;
    scopes: string[];
    last_used_at: string | null;
    expires_at: string | null;
    created_at: string;
}

interface CreateApiKeyResponse extends ApiKeyListItem {
    key: string;
}

export default function APIKeysPage() {
    const navigate = useNavigate();
    const [keys, setKeys] = useState<ApiKeyListItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [creating, setCreating] = useState(false);
    const [revoking, setRevoking] = useState<string | null>(null);
    const [newKeyName, setNewKeyName] = useState('');
    const [newKeyScopes, setNewKeyScopes] = useState('');
    const [newKeyExpiry, setNewKeyExpiry] = useState('');
    const [nameError, setNameError] = useState('');
    const [newlyCreatedKey, setNewlyCreatedKey] = useState<CreateApiKeyResponse | null>(null);

    const loadKeys = useCallback(async () => {
        setLoading(true);
        try {
            const res = await api.get<ApiKeyListItem[]>('/api/v1/api-keys');
            setKeys(res.data);
        } catch (err: any) {
            toast.error(err?.response?.data?.message || 'Failed to load API keys');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { loadKeys(); }, [loadKeys]);

    const resetForm = () => {
        setNewKeyName('');
        setNewKeyScopes('');
        setNewKeyExpiry('');
        setNameError('');
    };

    const handleCreateKey = async () => {
        const name = newKeyName.trim();
        if (!name) { setNameError('Key name is required'); return; }
        if (name.length > 100) { setNameError('Must be 100 characters or fewer'); return; }
        setNameError('');

        const scopes = newKeyScopes.split(',').map(s => s.trim()).filter(Boolean);
        const body: Record<string, unknown> = { name, scopes };
        if (newKeyExpiry) body.expires_at = new Date(newKeyExpiry).toISOString();

        setCreating(true);
        try {
            const res = await api.post<CreateApiKeyResponse>('/api/v1/api-keys', body);
            const created = res.data;
            setKeys(prev => [{
                id: created.id,
                name: created.name,
                key_prefix: created.key_prefix,
                scopes: created.scopes,
                last_used_at: null,
                expires_at: created.expires_at,
                created_at: created.created_at,
            }, ...prev]);
            setNewlyCreatedKey(created);
            setShowCreateModal(false);
            resetForm();
            toast.success('API key created');
        } catch (err: any) {
            if (err?.response?.status === 409) {
                setNameError(`A key named "${name}" already exists`);
            } else {
                toast.error(err?.response?.data?.message || 'Failed to create API key');
            }
        } finally {
            setCreating(false);
        }
    };

    const handleRevokeKey = async (keyId: string, keyName: string) => {
        if (!confirm(`Revoke "${keyName}"? Applications using this key will immediately lose access.`)) return;
        setRevoking(keyId);
        try {
            await api.delete(`/api/v1/api-keys/${keyId}`);
            setKeys(prev => prev.filter(k => k.id !== keyId));
            toast.success(`"${keyName}" revoked`);
        } catch (err: any) {
            toast.error(err?.response?.data?.message || 'Failed to revoke API key');
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
            <div className="min-h-screen flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600" />
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
            <div className="max-w-5xl mx-auto px-4 py-8">

                {/* Header */}
                <div className="mb-8">
                    <button
                        onClick={() => navigate('/dashboard')}
                        className="mb-4 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors flex items-center gap-2"
                    >
                        ← Back to Dashboard
                    </button>
                    <div className="flex justify-between items-start">
                        <div>
                            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">API Keys</h1>
                            <p className="text-gray-600 dark:text-gray-400 mt-2">
                                Create and manage API keys for programmatic access to the AuthStar API.
                            </p>
                        </div>
                        <button
                            onClick={() => { resetForm(); setShowCreateModal(true); }}
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium"
                        >
                            + Create Key
                        </button>
                    </div>
                </div>

                {/* One-time key reveal banner */}
                {newlyCreatedKey && (
                    <div className="mb-6 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-lg p-5">
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
                                    <code className="flex-1 min-w-0 bg-white dark:bg-gray-900 px-4 py-2.5 rounded border border-amber-300 dark:border-amber-700 text-sm font-mono text-gray-900 dark:text-gray-100 overflow-x-auto whitespace-nowrap">
                                        {newlyCreatedKey.key}
                                    </code>
                                    <button
                                        onClick={() => copyToClipboard(newlyCreatedKey.key)}
                                        className="flex-shrink-0 px-4 py-2.5 bg-amber-600 hover:bg-amber-700 text-white rounded-lg transition-colors font-medium text-sm"
                                    >
                                        Copy
                                    </button>
                                    <button
                                        onClick={() => setNewlyCreatedKey(null)}
                                        className="flex-shrink-0 px-4 py-2.5 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors text-sm"
                                    >
                                        Done
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* Keys table */}
                <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden">
                    <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                            Active Keys
                            <span className="ml-2 text-sm font-normal text-gray-500 dark:text-gray-400">({keys.length})</span>
                        </h2>
                    </div>

                    {keys.length === 0 ? (
                        <div className="px-6 py-16 text-center">
                            <svg className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                            </svg>
                            <p className="text-gray-500 dark:text-gray-400 text-sm">No API keys yet. Create one to get started.</p>
                        </div>
                    ) : (
                        <div className="divide-y divide-gray-200 dark:divide-gray-700">
                            {keys.map(key => (
                                <div key={key.id} className="px-6 py-4 flex items-start justify-between gap-4">
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className="font-medium text-gray-900 dark:text-white">{key.name}</span>
                                            {key.expires_at && new Date(key.expires_at) < new Date() && (
                                                <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300">
                                                    Expired
                                                </span>
                                            )}
                                        </div>
                                        <code className="text-sm font-mono text-gray-600 dark:text-gray-400">
                                            ask_{key.key_prefix}_••••••••••••••••••••••••••••••••••••••••••••••••
                                        </code>
                                        <div className="flex flex-wrap items-center gap-3 mt-2 text-xs text-gray-500 dark:text-gray-400">
                                            <span>Created {formatDate(key.created_at)}</span>
                                            {key.last_used_at && <span>Last used {formatDate(key.last_used_at)}</span>}
                                            {key.expires_at && <span>Expires {formatDate(key.expires_at)}</span>}
                                            {key.scopes.length > 0 && (
                                                <span className="flex gap-1 flex-wrap">
                                                    {key.scopes.map(s => (
                                                        <span key={s} className="px-1.5 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded font-mono">
                                                            {s}
                                                        </span>
                                                    ))}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-2 flex-shrink-0">
                                        <button
                                            onClick={() => copyToClipboard(`ask_${key.key_prefix}_`)}
                                            className="px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded transition-colors"
                                            title="Copy key prefix"
                                        >
                                            Copy prefix
                                        </button>
                                        <button
                                            onClick={() => handleRevokeKey(key.id, key.name)}
                                            disabled={revoking === key.id}
                                            className="px-3 py-1.5 text-sm bg-red-100 hover:bg-red-200 dark:bg-red-900/30 dark:hover:bg-red-900/50 text-red-700 dark:text-red-400 rounded transition-colors disabled:opacity-50"
                                        >
                                            {revoking === key.id ? 'Revoking…' : 'Revoke'}
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Create Key Modal */}
                {showCreateModal && (
                    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-2xl p-6 w-full max-w-md">
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-5">Create API Key</h3>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Key Name <span className="text-red-500">*</span>
                                    </label>
                                    <input
                                        type="text"
                                        value={newKeyName}
                                        onChange={e => { setNewKeyName(e.target.value); setNameError(''); }}
                                        placeholder="e.g. Production Backend"
                                        maxLength={100}
                                        className={`w-full px-3 py-2 border rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 ${nameError ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'}`}
                                        autoFocus
                                    />
                                    {nameError && <p className="mt-1 text-sm text-red-600 dark:text-red-400">{nameError}</p>}
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Scopes <span className="text-gray-400 font-normal">(optional, comma-separated)</span>
                                    </label>
                                    <input
                                        type="text"
                                        value={newKeyScopes}
                                        onChange={e => setNewKeyScopes(e.target.value)}
                                        placeholder="e.g. read:users, write:sessions"
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Expiry <span className="text-gray-400 font-normal">(optional)</span>
                                    </label>
                                    <input
                                        type="datetime-local"
                                        value={newKeyExpiry}
                                        onChange={e => setNewKeyExpiry(e.target.value)}
                                        min={new Date().toISOString().slice(0, 16)}
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Leave blank for a non-expiring key.</p>
                                </div>

                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                                    <p className="text-sm text-blue-900 dark:text-blue-200">
                                        🔑 The full key will be shown <strong>once</strong> after creation. Store it securely — it cannot be retrieved again.
                                    </p>
                                </div>
                            </div>

                            <div className="flex gap-3 mt-6">
                                <button
                                    onClick={() => { setShowCreateModal(false); resetForm(); }}
                                    className="flex-1 px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleCreateKey}
                                    disabled={creating}
                                    className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium disabled:opacity-50"
                                >
                                    {creating ? 'Creating…' : 'Create Key'}
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
