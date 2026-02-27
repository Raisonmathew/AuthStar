import React, { useEffect, useState } from 'react';
import { api } from '../../../lib/api';
import { toast } from 'sonner';

interface SsoConnection {
    id: string;
    type: 'oauth' | 'oidc' | 'saml';
    provider: string;
    name: string;
    client_id: string;
    enabled: boolean;
    config?: Record<string, any>;
    redirect_uri?: string;
}

// Provider templates for prefilling common configurations
const PROVIDER_TEMPLATES: Record<string, Partial<{ discoveryUrl: string; redirectUri: string }>> = {
    google: {
        discoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
    },
    microsoft: {
        discoveryUrl: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    },
    okta: {
        discoveryUrl: 'https://{your-domain}.okta.com/.well-known/openid-configuration',
    },
};

export default function SSOPage() {
    const [connections, setConnections] = useState<SsoConnection[]>([]);
    const [loading, setLoading] = useState(true);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [editingConnection, setEditingConnection] = useState<SsoConnection | null>(null);
    const [showMetadataModal, setShowMetadataModal] = useState(false);
    const [testingId, setTestingId] = useState<string | null>(null);

    // Form State
    const [type, setType] = useState<'oauth' | 'oidc' | 'saml'>('saml');
    const [provider, setProvider] = useState('custom');
    const [name, setName] = useState('');
    const [clientId, setClientId] = useState('');
    const [clientSecret, setClientSecret] = useState('');
    const [redirectUri, setRedirectUri] = useState('');

    // SAML/OIDC specific
    const [discoveryUrl, setDiscoveryUrl] = useState('');
    const [ssoUrl, setSsoUrl] = useState('');
    const [issuer, setIssuer] = useState('');
    const [certificate, setCertificate] = useState('');

    // SP Metadata (for SAML)
    const spEntityId = `${window.location.origin}/saml/metadata`;
    const spAcsUrl = `${window.location.origin}/auth/sso/saml/acs`;

    useEffect(() => {
        fetchConnections();
    }, []);

    // Apply provider template when provider changes
    useEffect(() => {
        const template = PROVIDER_TEMPLATES[provider];
        if (template && type === 'oidc') {
            setDiscoveryUrl(template.discoveryUrl || '');
        }
    }, [provider, type]);

    // Set default redirect URI
    useEffect(() => {
        if (!redirectUri) {
            setRedirectUri(`${window.location.origin}/auth/sso/${type}/callback`);
        }
    }, [type, redirectUri]);

    const fetchConnections = async () => {
        try {
            const res = await api.get('/admin/v1/sso/');
            setConnections(res.data);
        } catch (err) {
            console.error(err);
            toast.error('Failed to load SSO connections');
        } finally {
            setLoading(false);
        }
    };

    const handleEdit = (conn: SsoConnection) => {
        setEditingConnection(conn);
        setType(conn.type);
        setProvider(conn.provider);
        setName(conn.name);
        setClientId(conn.client_id);
        setRedirectUri(conn.redirect_uri || '');

        if (conn.type === 'saml' && conn.config) {
            setIssuer(conn.config.entity_id || '');
            setSsoUrl(conn.config.sso_url || '');
            setCertificate(conn.config.certificate || '');
        }

        setIsModalOpen(true);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        const payload: any = {
            tenant_id: 'platform',
            type,
            provider,
            name,
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: redirectUri,
            scope: 'openid email profile',
        };

        if (type === 'oidc') {
            payload.discovery_url = discoveryUrl;
        }

        if (type === 'saml') {
            payload.config = {
                entity_id: issuer,
                sso_url: ssoUrl,
                certificate: certificate,
                max_assurance: 'aal2',
            };
        }

        try {
            if (editingConnection) {
                await api.put(`/admin/v1/sso/${editingConnection.id}`, payload);
                toast.success('Connection updated successfully');
            } else {
                await api.post('/admin/v1/sso/', payload);
                toast.success('Connection created successfully');
            }
            setIsModalOpen(false);
            resetForm();
            fetchConnections();
        } catch (err: any) {
            console.error(err);
            toast.error(err.response?.data?.error || 'Failed to save connection');
        }
    };

    const handleTestConnection = async (id: string) => {
        setTestingId(id);
        try {
            const res = await api.post(`/admin/v1/sso/${id}/test`);
            if (res.data.success) {
                toast.success('Connection test successful!');
            } else {
                toast.error(`Test failed: ${res.data.error}`);
            }
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Connection test failed');
        } finally {
            setTestingId(null);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Are you sure you want to delete this connection?')) return;
        try {
            await api.delete(`/admin/v1/sso/${id}`);
            toast.success('Connection deleted');
            fetchConnections();
        } catch (err) {
            console.error(err);
            toast.error('Failed to delete');
        }
    };

    const resetForm = () => {
        setEditingConnection(null);
        setName('');
        setClientId('');
        setClientSecret('');
        setIssuer('');
        setSsoUrl('');
        setCertificate('');
        setDiscoveryUrl('');
        setRedirectUri('');
        setProvider('custom');
        setType('saml');
    };

    const copyToClipboard = (text: string, label: string) => {
        navigator.clipboard.writeText(text);
        toast.success(`${label} copied to clipboard`);
    };

    if (loading) return <div className="p-8 text-white">Loading connections...</div>;

    return (
        <div className="max-w-6xl mx-auto p-6 space-y-8">
            <div className="flex justify-between items-center">
                <h1 className="text-2xl font-bold text-white">SSO Connections</h1>
                <div className="flex gap-2">
                    <button
                        onClick={() => setShowMetadataModal(true)}
                        className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-md text-sm"
                    >
                        SP Metadata
                    </button>
                    <button
                        onClick={() => { resetForm(); setIsModalOpen(true); }}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md"
                    >
                        Add Connection
                    </button>
                </div>
            </div>

            {/* List */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {connections.length === 0 ? (
                    <div className="col-span-full text-center py-12 text-gray-400">
                        <p className="text-lg">No SSO connections configured</p>
                        <p className="text-sm mt-2">Add a SAML or OIDC connection to enable enterprise SSO</p>
                    </div>
                ) : connections.map((conn) => (
                    <div key={conn.id} className="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg relative">
                        <div className="flex justify-between items-start mb-4">
                            <div>
                                <span className={`text-xs font-bold px-2 py-1 rounded uppercase ${conn.type === 'saml' ? 'bg-orange-900 text-orange-200' :
                                        conn.type === 'oidc' ? 'bg-blue-900 text-blue-200' :
                                            'bg-green-900 text-green-200'
                                    }`}>
                                    {conn.type}
                                </span>
                                <h3 className="text-lg font-bold text-white mt-2">{conn.name}</h3>
                                <p className="text-xs text-gray-400 capitalize">{conn.provider}</p>
                            </div>
                            <div className="flex flex-col gap-1">
                                <button
                                    onClick={() => handleEdit(conn)}
                                    className="text-blue-400 hover:text-blue-300 text-sm"
                                >
                                    Edit
                                </button>
                                <button
                                    onClick={() => handleTestConnection(conn.id)}
                                    disabled={testingId === conn.id}
                                    className="text-green-400 hover:text-green-300 text-sm disabled:opacity-50"
                                >
                                    {testingId === conn.id ? 'Testing...' : 'Test'}
                                </button>
                                <button
                                    onClick={() => handleDelete(conn.id)}
                                    className="text-red-400 hover:text-red-300 text-sm"
                                >
                                    Delete
                                </button>
                            </div>
                        </div>

                        <div className="space-y-2 text-sm text-gray-400">
                            {conn.type !== 'saml' && <p><strong>Client ID:</strong> {conn.client_id}</p>}
                            {conn.type === 'saml' && conn.config && (
                                <>
                                    <p title={conn.config.entity_id} className="truncate"><strong>Issuer:</strong> {conn.config.entity_id}</p>
                                    <p title={conn.config.sso_url} className="truncate"><strong>SSO URL:</strong> {conn.config.sso_url}</p>
                                </>
                            )}
                        </div>
                    </div>
                ))}
            </div>

            {/* SP Metadata Modal */}
            {showMetadataModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-70 p-4">
                    <div className="bg-gray-800 rounded-lg max-w-lg w-full border border-gray-700 shadow-xl">
                        <div className="p-6">
                            <h2 className="text-xl font-bold text-white mb-4">Service Provider Metadata</h2>
                            <p className="text-gray-400 text-sm mb-4">
                                Use these values when configuring your Identity Provider (IdP)
                            </p>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-1">Entity ID (Issuer)</label>
                                    <div className="flex gap-2">
                                        <input
                                            type="text"
                                            readOnly
                                            value={spEntityId}
                                            className="flex-1 bg-gray-900 border border-gray-600 rounded text-white px-3 py-2 text-sm"
                                        />
                                        <button
                                            onClick={() => copyToClipboard(spEntityId, 'Entity ID')}
                                            className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm"
                                        >
                                            Copy
                                        </button>
                                    </div>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-1">ACS URL (Reply URL)</label>
                                    <div className="flex gap-2">
                                        <input
                                            type="text"
                                            readOnly
                                            value={spAcsUrl}
                                            className="flex-1 bg-gray-900 border border-gray-600 rounded text-white px-3 py-2 text-sm"
                                        />
                                        <button
                                            onClick={() => copyToClipboard(spAcsUrl, 'ACS URL')}
                                            className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm"
                                        >
                                            Copy
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <div className="flex justify-end mt-6">
                                <button
                                    onClick={() => setShowMetadataModal(false)}
                                    className="px-4 py-2 text-gray-300 hover:text-white"
                                >
                                    Close
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Create/Edit Modal */}
            {isModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-70 p-4">
                    <div className="bg-gray-800 rounded-lg max-w-2xl w-full border border-gray-700 shadow-xl max-h-[90vh] overflow-y-auto">
                        <div className="p-6">
                            <h2 className="text-xl font-bold text-white mb-6">
                                {editingConnection ? 'Edit SSO Connection' : 'Add SSO Connection'}
                            </h2>
                            <form onSubmit={handleSubmit} className="space-y-4">

                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-400 mb-1">Type</label>
                                        <select
                                            value={type}
                                            onChange={(e) => setType(e.target.value as any)}
                                            disabled={!!editingConnection}
                                            className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2 disabled:opacity-50"
                                        >
                                            <option value="saml">SAML 2.0</option>
                                            <option value="oidc">OIDC</option>
                                            <option value="oauth">OAuth 2.0</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-400 mb-1">Provider</label>
                                        <select
                                            value={provider}
                                            onChange={(e) => setProvider(e.target.value)}
                                            className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2"
                                        >
                                            <option value="custom">Custom / Enterprise</option>
                                            <option value="google">Google Workspace</option>
                                            <option value="microsoft">Microsoft Entra ID</option>
                                            <option value="okta">Okta</option>
                                            <option value="ping">PingIdentity</option>
                                        </select>
                                    </div>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-1">Connection Name</label>
                                    <input
                                        type="text"
                                        required
                                        value={name}
                                        onChange={(e) => setName(e.target.value)}
                                        placeholder="e.g. Corporate Okta"
                                        className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2"
                                    />
                                </div>

                                {/* Common Fields */}
                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-1">Redirect URI (Callback)</label>
                                    <input
                                        type="url"
                                        required
                                        value={redirectUri}
                                        onChange={(e) => setRedirectUri(e.target.value)}
                                        className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2"
                                    />
                                    <p className="text-xs text-gray-500 mt-1">Configure this in your identity provider</p>
                                </div>

                                {type !== 'saml' && (
                                    <>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">Client ID</label>
                                            <input type="text" required value={clientId} onChange={(e) => setClientId(e.target.value)} className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2" />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">Client Secret</label>
                                            <input
                                                type="password"
                                                required={!editingConnection}
                                                value={clientSecret}
                                                onChange={(e) => setClientSecret(e.target.value)}
                                                placeholder={editingConnection ? '(unchanged)' : ''}
                                                className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2"
                                            />
                                        </div>
                                    </>
                                )}

                                {/* SAML Fields */}
                                {type === 'saml' && (
                                    <div className="space-y-4 border-t border-gray-700 pt-4">
                                        <h3 className="text-sm font-semibold text-indigo-400">SAML Configuration</h3>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">Entity ID (Issuer)</label>
                                            <input type="text" required value={issuer} onChange={(e) => setIssuer(e.target.value)} className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2" placeholder="http://www.okta.com/exk..." />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">SSO URL</label>
                                            <input type="url" required value={ssoUrl} onChange={(e) => setSsoUrl(e.target.value)} className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2" placeholder="https://..." />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">X.509 Certificate (PEM)</label>
                                            <textarea required={!editingConnection} value={certificate} onChange={(e) => setCertificate(e.target.value)} className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2 h-32 font-mono text-xs" placeholder={editingConnection ? '(unchanged if empty)' : '-----BEGIN CERTIFICATE-----...'} />
                                        </div>
                                    </div>
                                )}

                                {/* OIDC Fields */}
                                {type === 'oidc' && (
                                    <div>
                                        <label className="block text-sm font-medium text-gray-400 mb-1">Discovery URL</label>
                                        <input type="url" value={discoveryUrl} onChange={(e) => setDiscoveryUrl(e.target.value)} className="w-full bg-gray-900 border border-gray-600 rounded text-white px-3 py-2" placeholder="https://.../.well-known/openid-configuration" />
                                    </div>
                                )}

                                <div className="flex justify-end gap-3 pt-4">
                                    <button
                                        type="button"
                                        onClick={() => { setIsModalOpen(false); resetForm(); }}
                                        className="px-4 py-2 text-gray-300 hover:text-white"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded-md font-medium"
                                    >
                                        {editingConnection ? 'Update Connection' : 'Create Connection'}
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

