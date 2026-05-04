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
    discovery_url?: string;
    scope?: string;
}

interface AttrMapping {
    saml_attr: string;
    user_field: string;
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

const NAME_ID_FORMATS = [
    { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', label: 'Email Address' },
    { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', label: 'Persistent' },
    { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient', label: 'Transient' },
    { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', label: 'Unspecified' },
    { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName', label: 'X.509 Subject Name' },
];

const AUTHN_CONTEXT_CLASSES = [
    { value: '', label: '— None —' },
    { value: 'PasswordProtectedTransport', label: 'PasswordProtectedTransport' },
    { value: 'Password', label: 'Password' },
    { value: 'X509', label: 'X509' },
    { value: 'Kerberos', label: 'Kerberos' },
    { value: 'SmartcardPKI', label: 'SmartcardPKI' },
    { value: 'TimeSyncToken', label: 'TimeSyncToken' },
];

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
    const [scope, setScope] = useState('openid email profile');

    // SAML — new Keycloak-parity fields
    const [sloUrl, setSloUrl] = useState('');
    const [nameIdFormat, setNameIdFormat] = useState('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
    const [allowIdpInitiated, setAllowIdpInitiated] = useState(false);
    const [forceAuthn, setForceAuthn] = useState(false);
    const [authnContextClassRef, setAuthnContextClassRef] = useState('');
    const [postBindingAuthnRequest, setPostBindingAuthnRequest] = useState(false);
    const [attrMappings, setAttrMappings] = useState<AttrMapping[]>([]);
    const [extraCertificates, setExtraCertificates] = useState<string[]>([]);
    const [showAdvanced, setShowAdvanced] = useState(false);

    // Import metadata dialog
    const [showImportDialog, setShowImportDialog] = useState(false);
    const [importUrl, setImportUrl] = useState('');
    const [importing, setImporting] = useState(false);

    // SP Metadata (for SAML) — must point to the backend, not frontend
    const backendOrigin = window.location.origin.replace(':5173', ':3000');
    const spEntityId = `${backendOrigin}/saml/metadata`;
    const spAcsUrl = `${backendOrigin}/auth/sso/saml/acs`;
    const spSloUrl = `${backendOrigin}/auth/sso/saml/slo`;

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

    // Set default redirect URI whenever type changes
    useEffect(() => {
        setRedirectUri(`${window.location.origin}/auth/sso/${type}/callback`);
    }, [type]); // eslint-disable-line react-hooks/exhaustive-deps

    const fetchConnections = async () => {
        try {
            const res = await api.get<SsoConnection[]>('/api/admin/v1/sso');
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
        setScope(conn.scope || 'openid email profile');

        if (conn.type === 'saml' && conn.config) {
            setIssuer(conn.config.entity_id || '');
            setSsoUrl(conn.config.sso_url || '');
            setCertificate(conn.config.certificate || '');
            setSloUrl(conn.config.slo_url || '');
            setNameIdFormat(conn.config.name_id_format || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
            setAllowIdpInitiated(!!conn.config.allow_idp_initiated);
            setForceAuthn(!!conn.config.force_authn);
            setAuthnContextClassRef(conn.config.authn_context_class_ref || '');
            setPostBindingAuthnRequest(!!conn.config.post_binding_authn_request);
            setAttrMappings(conn.config.attr_mappings || []);
            setExtraCertificates(conn.config.extra_certificates || []);
        }

        if (conn.type === 'oidc') {
            setDiscoveryUrl(conn.discovery_url || '');
        }

        setIsModalOpen(true);
    };

    const handleImportMetadata = async () => {
        if (!importUrl.trim()) return;
        setImporting(true);
        try {
            const res = await api.post<{
                entity_id: string;
                sso_url: string;
                slo_url?: string;
                certificate?: string;
                name_id_format?: string;
            }>('/api/admin/v1/sso/saml/import-metadata', { url: importUrl.trim() });
            const d = res.data;
            if (d.entity_id) setIssuer(d.entity_id);
            if (d.sso_url) setSsoUrl(d.sso_url);
            if (d.slo_url) setSloUrl(d.slo_url);
            if (d.certificate) setCertificate(d.certificate);
            if (d.name_id_format) setNameIdFormat(d.name_id_format);
            setShowImportDialog(false);
            setImportUrl('');
            toast.success('Metadata imported — review and save the connection');
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Failed to import metadata');
        } finally {
            setImporting(false);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        const payload: any = {
            type,
            provider,
            name,
            redirect_uri: redirectUri,
        };

        if (type !== 'saml') {
            payload.client_id = clientId;
            payload.client_secret = clientSecret;
            payload.scope = scope;
        }

        if (type === 'oidc') {
            payload.discovery_url = discoveryUrl;
        }

        if (type === 'saml') {
            payload.config = {
                entity_id: issuer,
                sso_url: ssoUrl,
                certificate: certificate,
                slo_url: sloUrl,
                name_id_format: nameIdFormat,
                allow_idp_initiated: allowIdpInitiated,
                force_authn: forceAuthn,
                authn_context_class_ref: authnContextClassRef || null,
                post_binding_authn_request: postBindingAuthnRequest,
                attr_mappings: attrMappings,
                extra_certificates: extraCertificates.filter(c => c.trim().length > 0),
                max_assurance: 'aal2',
            };
        }

        try {
            if (editingConnection) {
                await api.put(`/api/admin/v1/sso/${editingConnection.id}`, payload);
                toast.success('Connection updated successfully');
            } else {
                await api.post('/api/admin/v1/sso', payload);
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
            const res = await api.post<{ success: boolean; error?: string }>(`/api/admin/v1/sso/${id}/test`);
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
            await api.delete(`/api/admin/v1/sso/${id}`);
            toast.success('Connection deleted');
            fetchConnections();
        } catch (err) {
            console.error(err);
            toast.error('Failed to delete');
        }
    };

    const handleToggle = async (id: string, currentEnabled: boolean) => {
        try {
            await api.put(`/api/admin/v1/sso/${id}/toggle`, { enabled: !currentEnabled });
            toast.success(`Connection ${!currentEnabled ? 'enabled' : 'disabled'}`);
            fetchConnections();
        } catch (err) {
            console.error(err);
            toast.error('Failed to toggle connection');
        }
    };

    const resetForm = () => {
        setEditingConnection(null);
        setName('');
        setClientId('');
        setClientSecret('');
        setIssuer('');
        setSsoUrl('');
        setSloUrl('');
        setCertificate('');
        setDiscoveryUrl('');
        setRedirectUri(`${window.location.origin}/auth/sso/saml/callback`);
        setProvider('custom');
        setType('saml');
        setScope('openid email profile');
        setNameIdFormat('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
        setAllowIdpInitiated(false);
        setForceAuthn(false);
        setAuthnContextClassRef('');
        setPostBindingAuthnRequest(false);
        setAttrMappings([]);
        setExtraCertificates([]);
        setShowAdvanced(false);
    };

    const copyToClipboard = (text: string, label: string) => {
        navigator.clipboard.writeText(text);
        toast.success(`${label} copied to clipboard`);
    };

    // Attribute mapping helpers
    const addAttrMapping = () => setAttrMappings(prev => [...prev, { saml_attr: '', user_field: '' }]);
    const removeAttrMapping = (i: number) => setAttrMappings(prev => prev.filter((_, idx) => idx !== i));
    const updateAttrMapping = (i: number, field: keyof AttrMapping, value: string) =>
        setAttrMappings(prev => prev.map((m, idx) => idx === i ? { ...m, [field]: value } : m));

    // Extra certificate helpers
    const addExtraCert = () => setExtraCertificates(prev => [...prev, '']);
    const removeExtraCert = (i: number) => setExtraCertificates(prev => prev.filter((_, idx) => idx !== i));
    const updateExtraCert = (i: number, value: string) =>
        setExtraCertificates(prev => prev.map((c, idx) => idx === i ? value : c));

    if (loading) return <div className="p-8 text-foreground">Loading connections...</div>;

    return (
        <div className="max-w-6xl mx-auto p-6 space-y-8">
            <div className="flex justify-between items-center">
                <h1 className="text-2xl font-bold text-foreground font-heading">SSO Connections</h1>
                <div className="flex gap-2">
                    <button
                        onClick={() => setShowMetadataModal(true)}
                        className="bg-accent hover:bg-accent/80 text-foreground px-4 py-2 rounded-xl text-sm font-heading font-semibold transition-colors"
                    >
                        SP Metadata
                    </button>
                    <button
                        onClick={() => { resetForm(); setIsModalOpen(true); }}
                        className="bg-primary hover:bg-primary/90 text-primary-foreground px-4 py-2 rounded-xl font-heading font-semibold transition-colors"
                    >
                        Add Connection
                    </button>
                </div>
            </div>

            {/* List */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {connections.length === 0 ? (
                    <div className="col-span-full text-center py-12 text-muted-foreground">
                        <p className="text-lg">No SSO connections configured</p>
                        <p className="text-sm mt-2">Add a SAML or OIDC connection to enable enterprise SSO</p>
                    </div>
                ) : connections.map((conn) => (
                    <div key={conn.id} className={`bg-card rounded-xl p-6 border shadow-lg relative ${conn.enabled ? 'border-border' : 'border-border/50 opacity-75'}`}>
                        <div className="flex justify-between items-start mb-4">
                            <div>
                                <div className="flex items-center gap-2">
                                    <span className={`text-xs font-bold px-2 py-1 rounded uppercase ${conn.type === 'saml' ? 'bg-orange-900 text-orange-200' :
                                            conn.type === 'oidc' ? 'bg-blue-900 text-blue-200' :
                                                'bg-green-900 text-green-200'
                                        }`}>
                                        {conn.type}
                                    </span>
                                    <span className={`text-xs font-semibold px-2 py-1 rounded ${conn.enabled ? 'bg-emerald-900/50 text-emerald-300' : 'bg-red-900/50 text-red-300'}`}>
                                        {conn.enabled ? 'Enabled' : 'Disabled'}
                                    </span>
                                </div>
                                <h3 className="text-lg font-bold text-foreground mt-2">{conn.name}</h3>
                                <p className="text-xs text-muted-foreground capitalize">{conn.provider}</p>
                            </div>
                            <div className="flex flex-col gap-1">
                                <button
                                    onClick={() => handleToggle(conn.id, conn.enabled)}
                                    className={`text-sm ${conn.enabled ? 'text-amber-500 hover:text-amber-400' : 'text-emerald-500 hover:text-emerald-400'}`}
                                >
                                    {conn.enabled ? 'Disable' : 'Enable'}
                                </button>
                                <button
                                    onClick={() => handleEdit(conn)}
                                    className="text-primary hover:text-primary/80 text-sm"
                                >
                                    Edit
                                </button>
                                <button
                                    onClick={() => handleTestConnection(conn.id)}
                                    disabled={testingId === conn.id}
                                    className="text-emerald-500 hover:text-emerald-400 text-sm disabled:opacity-50"
                                >
                                    {testingId === conn.id ? 'Testing...' : 'Test'}
                                </button>
                                <button
                                    onClick={() => handleDelete(conn.id)}
                                    className="text-destructive hover:text-destructive/80 text-sm"
                                >
                                    Delete
                                </button>
                            </div>
                        </div>

                        <div className="space-y-2 text-sm text-muted-foreground">
                            {conn.type !== 'saml' && <p><strong>Client ID:</strong> {conn.client_id}</p>}
                            {conn.type === 'saml' && conn.config && (
                                <>
                                    <p title={conn.config.entity_id} className="truncate"><strong>Issuer:</strong> {conn.config.entity_id}</p>
                                    <p title={conn.config.sso_url} className="truncate"><strong>SSO URL:</strong> {conn.config.sso_url}</p>
                                    {conn.config.slo_url && (
                                        <p title={conn.config.slo_url} className="truncate"><strong>SLO URL:</strong> {conn.config.slo_url}</p>
                                    )}
                                    {conn.config.allow_idp_initiated && (
                                        <span className="text-xs bg-purple-900/40 text-purple-300 px-2 py-0.5 rounded">IdP-initiated</span>
                                    )}
                                </>
                            )}
                        </div>
                    </div>
                ))}
            </div>

            {/* SP Metadata Modal */}
            {showMetadataModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-70 p-4">
                    <div className="bg-card rounded-xl max-w-lg w-full border border-border shadow-xl">
                        <div className="p-6">
                            <h2 className="text-xl font-bold text-foreground font-heading mb-4">Service Provider Metadata</h2>
                            <p className="text-muted-foreground text-sm mb-4">
                                Use these values when configuring your Identity Provider (IdP)
                            </p>

                            <div className="space-y-4">
                                <MetaCopyField label="Entity ID (Issuer)" value={spEntityId} onCopy={copyToClipboard} />
                                <MetaCopyField label="ACS URL (Reply URL)" value={spAcsUrl} onCopy={copyToClipboard} />
                                <MetaCopyField label="SLO URL (Single Logout)" value={spSloUrl} onCopy={copyToClipboard} />
                            </div>

                            <div className="flex justify-end mt-6">
                                <button
                                    onClick={() => setShowMetadataModal(false)}
                                    className="px-4 py-2 text-muted-foreground hover:text-foreground transition-colors"
                                >
                                    Close
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Import Metadata Dialog */}
            {showImportDialog && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-70 p-4">
                    <div className="bg-card rounded-xl max-w-md w-full border border-border shadow-xl p-6">
                        <h2 className="text-lg font-bold text-foreground font-heading mb-4">Import IdP Metadata</h2>
                        <p className="text-sm text-muted-foreground mb-4">
                            Enter the URL of your Identity Provider&apos;s SAML metadata XML document.
                            Fields will be auto-filled from the metadata.
                        </p>
                        <input
                            type="url"
                            value={importUrl}
                            onChange={(e) => setImportUrl(e.target.value)}
                            placeholder="https://idp.example.com/saml/metadata"
                            className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2 mb-4"
                        />
                        <div className="flex justify-end gap-3">
                            <button
                                type="button"
                                onClick={() => { setShowImportDialog(false); setImportUrl(''); }}
                                className="px-4 py-2 text-muted-foreground hover:text-foreground transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={handleImportMetadata}
                                disabled={importing || !importUrl.trim()}
                                className="bg-primary hover:bg-primary/90 text-primary-foreground px-4 py-2 rounded-xl font-semibold transition-colors disabled:opacity-50"
                            >
                                {importing ? 'Importing...' : 'Import'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Create/Edit Modal */}
            {isModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-70 p-4">
                    <div className="bg-card rounded-xl max-w-2xl w-full border border-border shadow-xl max-h-[90vh] overflow-y-auto">
                        <div className="p-6">
                            <h2 className="text-xl font-bold text-foreground font-heading mb-6">
                                {editingConnection ? 'Edit SSO Connection' : 'Add SSO Connection'}
                            </h2>
                            <form onSubmit={handleSubmit} className="space-y-4">

                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-sm font-medium text-muted-foreground mb-1">Type</label>
                                        <select
                                            value={type}
                                            onChange={(e) => setType(e.target.value as any)}
                                            disabled={!!editingConnection}
                                            className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2 disabled:opacity-50"
                                        >
                                            <option value="saml">SAML 2.0</option>
                                            <option value="oidc">OIDC</option>
                                            <option value="oauth">OAuth 2.0</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-muted-foreground mb-1">Provider</label>
                                        <select
                                            value={provider}
                                            onChange={(e) => setProvider(e.target.value)}
                                            className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2"
                                        >
                                            <option value="custom">Custom / Enterprise</option>
                                            <option value="google">Google Workspace</option>
                                            <option value="microsoft">Microsoft Entra ID</option>
                                            <option value="okta">Okta</option>
                                            <option value="ping">PingIdentity</option>
                                            <option value="adfs">ADFS</option>
                                            <option value="keycloak">Keycloak</option>
                                        </select>
                                    </div>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Connection Name</label>
                                    <input
                                        type="text"
                                        required
                                        value={name}
                                        onChange={(e) => setName(e.target.value)}
                                        placeholder="e.g. Corporate Okta"
                                        className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2"
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-muted-foreground mb-1">Redirect URI (Callback)</label>
                                    <input
                                        type="url"
                                        required
                                        value={redirectUri}
                                        onChange={(e) => setRedirectUri(e.target.value)}
                                        className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2"
                                    />
                                    <p className="text-xs text-muted-foreground/60 mt-1">Configure this in your identity provider</p>
                                </div>

                                {type !== 'saml' && (
                                    <>
                                        <div>
                                            <label htmlFor="sso-client-id" className="block text-sm font-medium text-muted-foreground mb-1">Client ID</label>
                                            <input id="sso-client-id" type="text" required value={clientId} onChange={(e) => setClientId(e.target.value)} className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2" />
                                        </div>
                                        <div>
                                            <label htmlFor="sso-client-secret" className="block text-sm font-medium text-muted-foreground mb-1">Client Secret</label>
                                            <input
                                                id="sso-client-secret"
                                                type="password"
                                                required={!editingConnection}
                                                value={clientSecret}
                                                onChange={(e) => setClientSecret(e.target.value)}
                                                placeholder={editingConnection ? '(unchanged)' : ''}
                                                className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-muted-foreground mb-1">Scopes</label>
                                            <input type="text" value={scope} onChange={(e) => setScope(e.target.value)} className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2" placeholder="openid email profile" />
                                        </div>
                                    </>
                                )}

                                {/* SAML Fields */}
                                {type === 'saml' && (
                                    <div className="space-y-4 border-t border-border pt-4">
                                        <div className="flex items-center justify-between">
                                            <h3 className="text-sm font-semibold text-primary">SAML Configuration</h3>
                                            <button
                                                type="button"
                                                onClick={() => setShowImportDialog(true)}
                                                className="text-xs bg-accent hover:bg-accent/80 text-foreground px-3 py-1.5 rounded-lg transition-colors"
                                            >
                                                Import from Metadata URL
                                            </button>
                                        </div>

                                        {/* Basic SAML fields */}
                                        <div>
                                            <label className="block text-sm font-medium text-muted-foreground mb-1">Entity ID (Issuer)</label>
                                            <input type="text" required value={issuer} onChange={(e) => setIssuer(e.target.value)} className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2" placeholder="http://www.okta.com/exk..." />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-muted-foreground mb-1">SSO URL (HTTP-POST Binding)</label>
                                            <input type="url" required value={ssoUrl} onChange={(e) => setSsoUrl(e.target.value)} className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2" placeholder="https://..." />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-muted-foreground mb-1">SLO URL (Single Logout) <span className="text-muted-foreground/50 font-normal">optional</span></label>
                                            <input type="url" value={sloUrl} onChange={(e) => setSloUrl(e.target.value)} className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2" placeholder="https://..." />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-muted-foreground mb-1">NameID Format</label>
                                            <select value={nameIdFormat} onChange={(e) => setNameIdFormat(e.target.value)} className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2">
                                                {NAME_ID_FORMATS.map(f => (
                                                    <option key={f.value} value={f.value}>{f.label}</option>
                                                ))}
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-muted-foreground mb-1">X.509 Certificate (PEM)</label>
                                            <textarea required={!editingConnection} value={certificate} onChange={(e) => setCertificate(e.target.value)} className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2 h-28 font-mono text-xs" placeholder={editingConnection ? '(unchanged if empty)' : '-----BEGIN CERTIFICATE-----...'} />
                                        </div>

                                        {/* Advanced settings */}
                                        <div>
                                            <button
                                                type="button"
                                                onClick={() => setShowAdvanced(v => !v)}
                                                className="text-sm text-primary hover:text-primary/80 flex items-center gap-1 transition-colors"
                                            >
                                                <span>{showAdvanced ? '▼' : '▶'}</span>
                                                Advanced Settings
                                            </button>
                                        </div>

                                        {showAdvanced && (
                                            <div className="space-y-4 bg-muted/50 rounded-xl p-4 border border-border/50">
                                                {/* Toggles */}
                                                <div className="grid grid-cols-2 gap-4">
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={allowIdpInitiated}
                                                            onChange={(e) => setAllowIdpInitiated(e.target.checked)}
                                                            className="w-4 h-4 accent-primary"
                                                        />
                                                        <span className="text-sm text-foreground">Allow IdP-initiated SSO</span>
                                                    </label>
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={forceAuthn}
                                                            onChange={(e) => setForceAuthn(e.target.checked)}
                                                            className="w-4 h-4 accent-primary"
                                                        />
                                                        <span className="text-sm text-foreground">Force Re-authentication</span>
                                                    </label>
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={postBindingAuthnRequest}
                                                            onChange={(e) => setPostBindingAuthnRequest(e.target.checked)}
                                                            className="w-4 h-4 accent-primary"
                                                        />
                                                        <span className="text-sm text-foreground">HTTP-POST AuthnRequest</span>
                                                    </label>
                                                </div>

                                                <div>
                                                    <label className="block text-sm font-medium text-muted-foreground mb-1">AuthnContext Class Ref</label>
                                                    <select
                                                        value={authnContextClassRef}
                                                        onChange={(e) => setAuthnContextClassRef(e.target.value)}
                                                        className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2"
                                                    >
                                                        {AUTHN_CONTEXT_CLASSES.map(c => (
                                                            <option key={c.value} value={c.value}>{c.label}</option>
                                                        ))}
                                                    </select>
                                                    <p className="text-xs text-muted-foreground/60 mt-1">
                                                        Require a specific authentication method at the IdP
                                                    </p>
                                                </div>

                                                {/* Attribute Mappings */}
                                                <div>
                                                    <div className="flex items-center justify-between mb-2">
                                                        <label className="text-sm font-medium text-muted-foreground">Attribute Mappings</label>
                                                        <button type="button" onClick={addAttrMapping} className="text-xs text-primary hover:text-primary/80 transition-colors">+ Add Mapping</button>
                                                    </div>
                                                    {attrMappings.length === 0 && (
                                                        <p className="text-xs text-muted-foreground/60">
                                                            Map IdP SAML attributes to user profile fields (e.g. email, name, groups).
                                                        </p>
                                                    )}
                                                    <div className="space-y-2">
                                                        {attrMappings.map((m, i) => (
                                                            <div key={i} className="flex gap-2 items-center">
                                                                <input
                                                                    type="text"
                                                                    placeholder="SAML attribute"
                                                                    value={m.saml_attr}
                                                                    onChange={(e) => updateAttrMapping(i, 'saml_attr', e.target.value)}
                                                                    className="flex-1 bg-muted border border-border rounded-lg text-foreground px-2 py-1.5 text-sm"
                                                                />
                                                                <span className="text-muted-foreground text-sm">→</span>
                                                                <input
                                                                    type="text"
                                                                    placeholder="user field"
                                                                    value={m.user_field}
                                                                    onChange={(e) => updateAttrMapping(i, 'user_field', e.target.value)}
                                                                    className="flex-1 bg-muted border border-border rounded-lg text-foreground px-2 py-1.5 text-sm"
                                                                />
                                                                <button type="button" onClick={() => removeAttrMapping(i)} className="text-destructive hover:text-destructive/80 text-sm px-1">✕</button>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>

                                                {/* Extra Certificates */}
                                                <div>
                                                    <div className="flex items-center justify-between mb-2">
                                                        <label className="text-sm font-medium text-muted-foreground">Additional Certificates</label>
                                                        <button type="button" onClick={addExtraCert} className="text-xs text-primary hover:text-primary/80 transition-colors">+ Add Certificate</button>
                                                    </div>
                                                    <p className="text-xs text-muted-foreground/60 mb-2">
                                                        Add extra IdP certificates to support key rotation without downtime.
                                                    </p>
                                                    <div className="space-y-2">
                                                        {extraCertificates.map((cert, i) => (
                                                            <div key={i} className="flex gap-2 items-start">
                                                                <textarea
                                                                    placeholder="-----BEGIN CERTIFICATE-----..."
                                                                    value={cert}
                                                                    onChange={(e) => updateExtraCert(i, e.target.value)}
                                                                    className="flex-1 bg-muted border border-border rounded-lg text-foreground px-2 py-1.5 text-xs font-mono h-20"
                                                                />
                                                                <button type="button" onClick={() => removeExtraCert(i)} className="text-destructive hover:text-destructive/80 text-sm px-1 mt-1">✕</button>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                )}

                                {/* OIDC Fields */}
                                {type === 'oidc' && (
                                    <div>
                                        <label className="block text-sm font-medium text-muted-foreground mb-1">Discovery URL</label>
                                        <input type="url" value={discoveryUrl} onChange={(e) => setDiscoveryUrl(e.target.value)} className="w-full bg-muted border border-border rounded-xl text-foreground px-3 py-2" placeholder="https://.../.well-known/openid-configuration" />
                                    </div>
                                )}

                                <div className="flex justify-end gap-3 pt-4">
                                    <button
                                        type="button"
                                        onClick={() => { setIsModalOpen(false); resetForm(); }}
                                        className="px-4 py-2 text-muted-foreground hover:text-foreground transition-colors"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        className="bg-primary hover:bg-primary/90 text-primary-foreground px-6 py-2 rounded-xl font-semibold font-heading transition-colors"
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

// ── Small helper component ────────────────────────────────────────────────────

function MetaCopyField({ label, value, onCopy }: { label: string; value: string; onCopy: (v: string, l: string) => void }) {
    return (
        <div>
            <label className="block text-sm font-medium text-muted-foreground mb-1">{label}</label>
            <div className="flex gap-2">
                <input
                    type="text"
                    readOnly
                    value={value}
                    className="flex-1 bg-muted border border-border rounded-xl text-foreground px-3 py-2 text-sm"
                />
                <button
                    onClick={() => onCopy(value, label)}
                    className="px-3 py-2 bg-accent hover:bg-accent/80 text-foreground rounded-xl text-sm transition-colors"
                >
                    Copy
                </button>
            </div>
        </div>
    );
}
