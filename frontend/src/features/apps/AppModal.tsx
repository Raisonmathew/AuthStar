import { useState } from 'react';
import { api } from '../../lib/api';
import { toast } from 'sonner';

interface AppModalProps {
    app?: {
        id: string;
        name: string;
        type: string;
        client_id?: string;
        redirect_uris: string[];
        allowed_flows?: string[];
        allowed_scopes?: string[];
        public_config?: {
            enforce_pkce?: boolean;
            allowed_origins?: string[];
        };
    };
    onClose: () => void;
    onSuccess: () => void;
}

const appTypeOptions = [
    { value: 'web', label: 'Web App' },
    { value: 'mobile', label: 'Mobile App' },
    { value: 'api', label: 'API Service' },
    { value: 'machine', label: 'Machine-to-Machine' },
];

const flowOptions = [
    { value: 'authorization_code', label: 'Authorization Code' },
    { value: 'refresh_token', label: 'Refresh Token' },
    { value: 'client_credentials', label: 'Client Credentials' },
];

const scopeOptions = [
    { value: 'openid', label: 'OpenID Connect', description: 'Verify user identity' },
    { value: 'profile', label: 'Profile', description: 'Access name and profile picture' },
    { value: 'email', label: 'Email', description: 'Access email address' },
    { value: 'offline_access', label: 'Offline Access', description: 'Issue refresh tokens' },
];

export default function AppModal({ app, onClose, onSuccess }: AppModalProps) {
    const [name, setName] = useState(app?.name || '');
    const [appType, setAppType] = useState(app?.type || 'web');
    const [redirectUris, setRedirectUris] = useState(app?.redirect_uris?.join(', ') || '');
    const [allowedFlows, setAllowedFlows] = useState<string[]>(app?.allowed_flows?.length ? app.allowed_flows : ['authorization_code', 'refresh_token']);
    const [allowedScopes, setAllowedScopes] = useState<string[]>(app?.allowed_scopes?.length ? app.allowed_scopes : ['openid', 'profile', 'email', 'offline_access']);
    const [enforcePkce, setEnforcePkce] = useState<boolean>(Boolean(app?.public_config?.enforce_pkce));
    const [allowedOrigins, setAllowedOrigins] = useState(app?.public_config?.allowed_origins?.join(', ') || '');
    const isEditing = Boolean(app);
    const [credentials, setCredentials] = useState<{ id: string; client_id: string; client_secret: string; title: string; description: string } | null>(null);
    const [loading, setLoading] = useState(false);
    const [deleting, setDeleting] = useState(false);
    const [rotating, setRotating] = useState(false);

    const toggleFlow = (flow: string) => {
        setAllowedFlows((prev) => {
            if (prev.includes(flow)) {
                return prev.filter((f) => f !== flow);
            }
            return [...prev, flow];
        });
    };

    const toggleScope = (scope: string) => {
        setAllowedScopes((prev) => {
            if (prev.includes(scope)) {
                return prev.filter((s) => s !== scope);
            }
            return [...prev, scope];
        });
    };

    const buildPayload = () => {
        const uris = redirectUris.split(',').map((u) => u.trim()).filter(Boolean);
        const origins = allowedOrigins.split(',').map((u) => u.trim()).filter(Boolean);

        return {
            name,
            redirect_uris: uris,
            allowed_flows: allowedFlows,
            allowed_scopes: allowedScopes,
            public_config: {
                enforce_pkce: enforcePkce,
                allowed_origins: origins,
            },
        };
    };

    const handleDelete = async () => {
        if (!confirm(`Delete "${app!.name}"? This cannot be undone.`)) return;
        setDeleting(true);
        try {
            await api.delete(`/api/admin/v1/apps/${app!.id}`);
            toast.success('Application deleted');
            onSuccess();
            onClose();
        } catch (err: any) {
            toast.error(err?.response?.data?.message || 'Failed to delete application');
        } finally {
            setDeleting(false);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        const payload = buildPayload();

        try {
            if (isEditing && app) {
                await api.put(`/api/admin/v1/apps/${app.id}`, {
                    ...payload,
                });
                toast.success('Application updated successfully');
                onSuccess();
                onClose();
            } else {
                const res = await api.post<{ app: { id: string; client_id: string }; client_secret: string }>('/api/admin/v1/apps', {
                    ...payload,
                    type: appType,
                });
                setCredentials({
                    id: res.data.app.id,
                    client_id: res.data.app.client_id,
                    client_secret: res.data.client_secret,
                    title: 'Application Created',
                    description: 'Please copy your Client Secret now. It will not be shown again.',
                });
                toast.success('Application created successfully');
                onSuccess();
            }
        } catch (err: any) {
            console.error(err);
            toast.error(err?.response?.data?.message || (isEditing ? 'Failed to update application' : 'Failed to create application'));
        } finally {
            setLoading(false);
        }
    };

    const handleRotateSecret = async () => {
        if (!app) return;
        if (!confirm(`Rotate client secret for "${app.name}"? Existing integrations must be updated.`)) return;
        setRotating(true);
        try {
            const res = await api.post<{ app: { id: string; client_id: string }; client_secret: string }>(`/api/admin/v1/apps/${app.id}/rotate-secret`);
            setCredentials({
                id: res.data.app.id,
                client_id: res.data.app.client_id,
                client_secret: res.data.client_secret,
                title: 'Client Secret Rotated',
                description: 'A new client secret has been issued. Update dependent applications immediately.',
            });
            onSuccess();
            toast.success('Client secret rotated successfully');
        } catch (err: any) {
            toast.error(err?.response?.data?.message || 'Failed to rotate client secret');
        } finally {
            setRotating(false);
        }
    };

    if (credentials) {
        return (
            <div className="fixed z-[100] inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
                <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
                    <div className="fixed inset-0 bg-black/50 transition-opacity" aria-hidden="true"></div>
                    <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>

                    <div className="inline-block align-bottom bg-card rounded-xl border border-border px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6 max-h-[85vh] overflow-y-auto">
                        <div>
                            <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-emerald-500/10">
                                <svg className="h-6 w-6 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                                </svg>
                            </div>
                            <div className="mt-3 text-center sm:mt-5">
                                <h3 className="text-lg leading-6 font-medium text-foreground" id="modal-title">
                                    {credentials.title}
                                </h3>
                                <div className="mt-2">
                                    <p className="text-sm text-muted-foreground">
                                        {credentials.description}
                                    </p>
                                    <div className="mt-4 text-left bg-muted/50 p-3 rounded-xl border border-border">
                                        <div className="mb-2">
                                            <label className="block text-xs font-medium text-muted-foreground uppercase">Client ID</label>
                                            <code className="block text-sm font-mono text-foreground break-all">{credentials.client_id}</code>
                                        </div>
                                        <div>
                                            <label className="block text-xs font-medium text-muted-foreground uppercase">Client Secret</label>
                                            <code className="block text-sm font-mono text-destructive break-all">{credentials.client_secret}</code>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="mt-5 sm:mt-6">
                            <button
                                type="button"
                                className="w-full inline-flex justify-center rounded-xl border border-transparent shadow-sm px-4 py-2 bg-primary text-base font-medium text-primary-foreground hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-ring sm:text-sm"
                                onClick={onClose}
                            >
                                I have copied this secret
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="fixed z-[100] inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
            <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
                <div className="fixed inset-0 bg-black/50 transition-opacity" onClick={onClose} aria-hidden="true"></div>

                <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>

                <div className="inline-block align-bottom bg-card rounded-xl border border-border px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-xl sm:w-full sm:p-6 max-h-[85vh] overflow-y-auto">
                    <div>
                        <h3 className="text-lg leading-6 font-medium text-foreground" id="modal-title">
                            {isEditing ? 'Edit Application' : 'Create New Application'}
                        </h3>
                        <div className="mt-2 text-sm text-muted-foreground">
                            {isEditing ? 'Update application settings.' : 'Create a new OIDC client for your project.'}
                        </div>
                        <form className="mt-5 space-y-4" onSubmit={handleSubmit}>
                            <div>
                                <label htmlFor="name" className="block text-sm font-medium text-foreground">App Name</label>
                                <input
                                    type="text"
                                    name="name"
                                    id="name"
                                    required
                                    className="mt-1 shadow-sm focus:ring-ring focus:border-ring block w-full sm:text-sm border-border rounded-xl p-2 border bg-card text-foreground"
                                    placeholder="My Cool App"
                                    value={name}
                                    onChange={(e) => setName(e.target.value)}
                                />
                            </div>
                            <div>
                                <label htmlFor="app-type" className="block text-sm font-medium text-foreground">Application Type</label>
                                <select
                                    name="app-type"
                                    id="app-type"
                                    className="mt-1 shadow-sm focus:ring-ring focus:border-ring block w-full sm:text-sm border-border rounded-xl p-2 border bg-card disabled:bg-muted disabled:text-muted-foreground text-foreground"
                                    value={appType}
                                    onChange={(e) => setAppType(e.target.value)}
                                    disabled={isEditing}
                                >
                                    {appTypeOptions.map((option) => (
                                        <option key={option.value} value={option.value}>
                                            {option.label}
                                        </option>
                                    ))}
                                </select>
                                {isEditing && (
                                    <p className="mt-1 text-xs text-muted-foreground">Application type is immutable after creation.</p>
                                )}
                            </div>
                            <div>
                                <label htmlFor="redirect-uris" className="block text-sm font-medium text-foreground">Redirect URIs (comma separated)</label>
                                <input
                                    type="text"
                                    name="redirect-uris"
                                    id="redirect-uris"
                                    required
                                    className="mt-1 shadow-sm focus:ring-ring focus:border-ring block w-full sm:text-sm border-border rounded-xl p-2 border bg-card text-foreground"
                                    placeholder="http://localhost:3000/callback, https://app.com/callback"
                                    value={redirectUris}
                                    onChange={(e) => setRedirectUris(e.target.value)}
                                />
                            </div>
                            <div className="rounded-xl border border-border p-3 bg-muted/50">
                                <p className="text-sm font-medium text-foreground mb-2">Allowed OAuth Flows</p>
                                <div className="space-y-2">
                                    {flowOptions.map((flow) => (
                                        <label key={flow.value} className="flex items-center gap-2 text-sm text-foreground">
                                            <input
                                                type="checkbox"
                                                checked={allowedFlows.includes(flow.value)}
                                                onChange={() => toggleFlow(flow.value)}
                                                className="rounded border-border text-primary focus:ring-ring"
                                            />
                                            {flow.label}
                                        </label>
                                    ))}
                                </div>
                                <p className="text-xs text-muted-foreground mt-2">At least one flow should remain enabled.</p>
                            </div>
                            <div className="rounded-xl border border-border p-3 bg-muted/50">
                                <p className="text-sm font-medium text-foreground mb-2">Allowed Scopes</p>
                                <div className="space-y-2">
                                    {scopeOptions.map((scope) => (
                                        <label key={scope.value} className="flex items-center gap-2 text-sm text-foreground">
                                            <input
                                                type="checkbox"
                                                checked={allowedScopes.includes(scope.value)}
                                                onChange={() => toggleScope(scope.value)}
                                                className="rounded border-border text-primary focus:ring-ring"
                                            />
                                            <span>{scope.label}</span>
                                            <span className="text-xs text-muted-foreground">— {scope.description}</span>
                                        </label>
                                    ))}
                                </div>
                                <p className="text-xs text-muted-foreground mt-2">Controls which scopes clients can request. &quot;offline_access&quot; enables refresh tokens.</p>
                            </div>
                            <div className="rounded-xl border border-border p-3 bg-muted/50 space-y-3">
                                <p className="text-sm font-medium text-foreground">Security & Origins</p>
                                <label className="flex items-center gap-2 text-sm text-foreground">
                                    <input
                                        type="checkbox"
                                        checked={enforcePkce}
                                        onChange={(e) => setEnforcePkce(e.target.checked)}
                                        className="rounded border-border text-primary focus:ring-ring"
                                    />
                                    Enforce PKCE
                                </label>
                                <div>
                                    <label htmlFor="allowed-origins" className="block text-sm font-medium text-foreground">Allowed Origins (comma separated)</label>
                                    <input
                                        type="text"
                                        name="allowed-origins"
                                        id="allowed-origins"
                                        className="mt-1 shadow-sm focus:ring-ring focus:border-ring block w-full sm:text-sm border-border rounded-xl p-2 border bg-card text-foreground"
                                        placeholder="https://app.example.com, https://admin.example.com"
                                        value={allowedOrigins}
                                        onChange={(e) => setAllowedOrigins(e.target.value)}
                                    />
                                </div>
                            </div>
                            <div className="mt-5 sm:mt-6 sm:grid sm:grid-cols-2 sm:gap-3 sm:grid-flow-row-dense">
                                <button
                                    type="submit"
                                    disabled={loading || deleting || allowedFlows.length === 0}
                                    className="w-full inline-flex justify-center rounded-xl border border-transparent shadow-sm px-4 py-2 bg-primary text-base font-medium text-primary-foreground hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-ring sm:col-start-2 sm:text-sm disabled:opacity-50"
                                >
                                    {loading ? 'Saving...' : (isEditing ? 'Save Changes' : 'Create')}
                                </button>
                                <button
                                    type="button"
                                    disabled={loading || deleting || rotating}
                                    className="mt-3 w-full inline-flex justify-center rounded-xl border border-border shadow-sm px-4 py-2 bg-card text-base font-medium text-muted-foreground hover:bg-accent focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-ring sm:mt-0 sm:col-start-1 sm:text-sm disabled:opacity-50"
                                    onClick={onClose}
                                >
                                    Cancel
                                </button>
                            </div>
                            {isEditing && (
                                <div className="mt-3 pt-3 border-t border-border">
                                    <button
                                        type="button"
                                        disabled={deleting || loading || rotating}
                                        onClick={handleRotateSecret}
                                        className="mb-3 w-full inline-flex justify-center rounded-xl border border-amber-500/30 shadow-sm px-4 py-2 bg-amber-500/10 text-base font-medium text-amber-600 dark:text-amber-400 hover:bg-amber-500/20 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-amber-500 sm:text-sm disabled:opacity-50"
                                    >
                                        {rotating ? 'Rotating...' : 'Rotate Client Secret'}
                                    </button>
                                    <button
                                        type="button"
                                        disabled={deleting || loading || rotating}
                                        onClick={handleDelete}
                                        className="w-full inline-flex justify-center rounded-xl border border-transparent shadow-sm px-4 py-2 bg-destructive text-base font-medium text-white hover:bg-destructive/90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-destructive sm:text-sm disabled:opacity-50"
                                    >
                                        {deleting ? 'Deleting...' : 'Delete Application'}
                                    </button>
                                </div>
                            )}
                        </form>
                    </div>
                </div>
            </div>
        </div>
    );
}
