import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';

interface ApiKey {
    id: string;
    keyType: 'publishable' | 'secret';
    environment: 'test' | 'live';
    keyPrefix: string;
    fullKey?: string; // Only available immediately after creation
    createdAt: string;
    lastUsedAt?: string;
    revokedAt?: string;
}

export default function APIKeysPage() {
    const navigate = useNavigate();
    const [keys, setKeys] = useState<ApiKey[]>([]);
    const [loading, setLoading] = useState(true);
    const [showGenerateModal, setShowGenerateModal] = useState(false);
    const [selectedEnv, setSelectedEnv] = useState<'test' | 'live'>('test');
    const [selectedType, setSelectedType] = useState<'publishable' | 'secret'>('publishable');
    const [newlyCreatedKey, setNewlyCreatedKey] = useState<ApiKey | null>(null);

    useEffect(() => {
        loadKeys();
    }, []);

    const loadKeys = async () => {
        setLoading(true);
        try {
            // Mock data for now - replace with actual API call
            const mockKeys: ApiKey[] = [
                {
                    id: 'key_1',
                    keyType: 'publishable',
                    environment: 'test',
                    keyPrefix: 'pk_test_acme',
                    createdAt: new Date().toISOString(),
                    lastUsedAt: new Date().toISOString(),
                },
                {
                    id: 'key_2',
                    keyType: 'publishable',
                    environment: 'live',
                    keyPrefix: 'pk_live_acme',
                    createdAt: new Date().toISOString(),
                },
                {
                    id: 'key_3',
                    keyType: 'secret',
                    environment: 'test',
                    keyPrefix: 'sk_test_aBcD...',
                    createdAt: new Date().toISOString(),
                },
            ];
            setKeys(mockKeys);
        } catch (error) {
            toast.error('Failed to load API keys');
        } finally {
            setLoading(false);
        }
    };

    const handleGenerateKey = async () => {
        try {
            // Mock key generation - replace with actual API call
            const newKey: ApiKey = {
                id: `key_${Date.now()}`,
                keyType: selectedType,
                environment: selectedEnv,
                keyPrefix: selectedType === 'publishable'
                    ? `pk_${selectedEnv}_acme`
                    : `sk_${selectedEnv}_aBcDeFg123`,
                fullKey: selectedType === 'publishable'
                    ? `pk_${selectedEnv}_acme`
                    : `sk_${selectedEnv}_aBcDeFg123XyZ456...`,
                createdAt: new Date().toISOString(),
            };

            setKeys([...keys, newKey]);
            setNewlyCreatedKey(newKey);
            setShowGenerateModal(false);
            toast.success('API key generated successfully!');
        } catch (error) {
            toast.error('Failed to generate API key');
        }
    };

    const handleCopyKey = (key: string) => {
        navigator.clipboard.writeText(key);
        toast.success('Copied to clipboard!');
    };

    const handleRevokeKey = async (keyId: string) => {
        if (!confirm('Are you sure you want to revoke this key? This action cannot be undone.')) {
            return;
        }

        try {
            setKeys(keys.map(k =>
                k.id === keyId ? { ...k, revokedAt: new Date().toISOString() } : k
            ));
            toast.success('API key revoked');
        } catch (error) {
            toast.error('Failed to revoke key');
        }
    };

    const getEnvBadgeColor = (env: string) => {
        return env === 'live'
            ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
            : 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
    };

    const getTypeBadgeColor = (type: string) => {
        return type === 'publishable'
            ? 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200'
            : 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200';
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
            <div className="max-w-7xl mx-auto px-4 py-8">
                {/* Header */}
                <div className="mb-8">
                    <button
                        onClick={() => navigate('/dashboard')}
                        className="mb-4 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors flex items-center gap-2"
                    >
                        ← Back to Dashboard
                    </button>
                    <div className="flex justify-between items-center">
                        <div>
                            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                                API Keys
                            </h1>
                            <p className="text-gray-600 dark:text-gray-400 mt-2">
                                Manage your publishable and secret keys for authentication
                            </p>
                        </div>
                        <button
                            onClick={() => setShowGenerateModal(true)}
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium"
                        >
                            Generate New Key
                        </button>
                    </div>
                </div>

                {/* Newly Created Key Alert */}
                {newlyCreatedKey && newlyCreatedKey.fullKey && (
                    <div className="mb-6 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                        <div className="flex items-start gap-3">
                            <svg className="w-6 h-6 text-yellow-600 dark:text-yellow-500 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                            <div className="flex-1">
                                <h3 className="font-semibold text-yellow-900 dark:text-yellow-200">
                                    Save your {newlyCreatedKey.keyType} key now!
                                </h3>
                                <p className="text-sm text-yellow-800 dark:text-yellow-300 mt-1">
                                    {newlyCreatedKey.keyType === 'secret'
                                        ? "This is the only time you'll see the full secret key. Make sure to copy it to a safe place."
                                        : "Copy this key to use in your application."}
                                </p>
                                <div className="mt-3 flex items-center gap-2">
                                    <code className="flex-1 bg-white dark:bg-gray-800 px-4 py-2 rounded border border-yellow-300 dark:border-yellow-700 text-sm font-mono">
                                        {newlyCreatedKey.fullKey}
                                    </code>
                                    <button
                                        onClick={() => handleCopyKey(newlyCreatedKey.fullKey!)}
                                        className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded transition-colors"
                                    >
                                        Copy
                                    </button>
                                    <button
                                        onClick={() => setNewlyCreatedKey(null)}
                                        className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded transition-colors"
                                    >
                                        Done
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* Keys List */}
                <div className="space-y-6">
                    {/* Publishable Keys */}
                    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
                        <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                            Publishable Keys
                        </h2>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                            Use these keys in your frontend applications. They're safe to expose publicly.
                        </p>
                        <div className="space-y-3">
                            {keys.filter(k => k.keyType === 'publishable').map(key => (
                                <div
                                    key={key.id}
                                    className={`border rounded-lg p-4 ${key.revokedAt
                                        ? 'bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 opacity-60'
                                        : 'border-gray-200 dark:border-gray-700'
                                        }`}
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-2 mb-2">
                                                <span className={`px-2 py-1 rounded text-xs font-medium ${getEnvBadgeColor(key.environment)}`}>
                                                    {key.environment}
                                                </span>
                                                <span className={`px-2 py-1 rounded text-xs font-medium ${getTypeBadgeColor(key.keyType)}`}>
                                                    Publishable
                                                </span>
                                                {key.revokedAt && (
                                                    <span className="px-2 py-1 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                                                        Revoked
                                                    </span>
                                                )}
                                            </div>
                                            <code className="text-sm font-mono text-gray-900 dark:text-white">
                                                {key.keyPrefix}
                                            </code>
                                            <div className="flex items-center gap-4 mt-2 text-xs text-gray-500 dark:text-gray-400">
                                                <span>Created {new Date(key.createdAt).toLocaleDateString()}</span>
                                                {key.lastUsedAt && (
                                                    <span>Last used {new Date(key.lastUsedAt).toLocaleDateString()}</span>
                                                )}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            {!key.revokedAt && (
                                                <>
                                                    <button
                                                        onClick={() => handleCopyKey(key.keyPrefix)}
                                                        className="px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded transition-colors"
                                                    >
                                                        Copy
                                                    </button>
                                                    <button
                                                        onClick={() => handleRevokeKey(key.id)}
                                                        className="px-3 py-1.5 text-sm bg-red-100 hover:bg-red-200 dark:bg-red-900/30 dark:hover:bg-red-900/50 text-red-700 dark:text-red-400 rounded transition-colors"
                                                    >
                                                        Revoke
                                                    </button>
                                                </>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Secret Keys */}
                    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
                        <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                            Secret Keys
                        </h2>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                            Use these keys in your backend applications. Never expose them publicly.
                        </p>
                        <div className="space-y-3">
                            {keys.filter(k => k.keyType === 'secret').map(key => (
                                <div
                                    key={key.id}
                                    className={`border rounded-lg p-4 ${key.revokedAt
                                        ? 'bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 opacity-60'
                                        : 'border-gray-200 dark:border-gray-700'
                                        }`}
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-2 mb-2">
                                                <span className={`px-2 py-1 rounded text-xs font-medium ${getEnvBadgeColor(key.environment)}`}>
                                                    {key.environment}
                                                </span>
                                                <span className={`px-2 py-1 rounded text-xs font-medium ${getTypeBadgeColor(key.keyType)}`}>
                                                    Secret
                                                </span>
                                                {key.revokedAt && (
                                                    <span className="px-2 py-1 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                                                        Revoked
                                                    </span>
                                                )}
                                            </div>
                                            <code className="text-sm font-mono text-gray-900 dark:text-white">
                                                {key.keyPrefix}
                                            </code>
                                            <div className="flex items-center gap-4 mt-2 text-xs text-gray-500 dark:text-gray-400">
                                                <span>Created {new Date(key.createdAt).toLocaleDateString()}</span>
                                                {key.lastUsedAt && (
                                                    <span>Last used {new Date(key.lastUsedAt).toLocaleDateString()}</span>
                                                )}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            {!key.revokedAt && (
                                                <button
                                                    onClick={() => handleRevokeKey(key.id)}
                                                    className="px-3 py-1.5 text-sm bg-red-100 hover:bg-red-200 dark:bg-red-900/30 dark:hover:bg-red-900/50 text-red-700 dark:text-red-400 rounded transition-colors"
                                                >
                                                    Revoke
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Generate Key Modal */}
                {showGenerateModal && (
                    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 max-w-md w-full mx-4">
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                                Generate New API Key
                            </h3>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                        Environment
                                    </label>
                                    <select
                                        value={selectedEnv}
                                        onChange={(e) => setSelectedEnv(e.target.value as 'test' | 'live')}
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                    >
                                        <option value="test">Test</option>
                                        <option value="live">Live</option>
                                    </select>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                        Key Type
                                    </label>
                                    <select
                                        value={selectedType}
                                        onChange={(e) => setSelectedType(e.target.value as 'publishable' | 'secret')}
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                    >
                                        <option value="publishable">Publishable (Frontend)</option>
                                        <option value="secret">Secret (Backend)</option>
                                    </select>
                                </div>

                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                                    <p className="text-sm text-blue-900 dark:text-blue-200">
                                        {selectedType === 'publishable'
                                            ? '📱 Publishable keys can be safely used in frontend code.'
                                            : '🔒 Secret keys should only be used server-side and never exposed publicly.'}
                                    </p>
                                </div>
                            </div>

                            <div className="flex gap-3 mt-6">
                                <button
                                    onClick={() => setShowGenerateModal(false)}
                                    className="flex-1 px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleGenerateKey}
                                    className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium"
                                >
                                    Generate Key
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
