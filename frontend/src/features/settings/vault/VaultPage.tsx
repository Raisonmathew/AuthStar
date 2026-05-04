import React, { useEffect, useState } from 'react';
import { api } from '../../../lib/api';
import { toast } from 'sonner';

type VaultAuthMethod = 'token' | 'approle' | 'kubernetes';

interface VaultConfig {
    id: string;
    enabled: boolean;
    vault_addr: string;
    auth_method: VaultAuthMethod;
    secret_mount: string;
    secret_path_prefix: string;
    // approle
    role_id?: string;
    // kubernetes
    k8s_role?: string;
    k8s_mount?: string;
    // status
    status: 'connected' | 'error' | 'unconfigured';
    status_message?: string;
    last_check_at?: string;
}

const AUTH_METHOD_LABELS: Record<VaultAuthMethod, string> = {
    token: 'Token (static)',
    approle: 'AppRole',
    kubernetes: 'Kubernetes',
};

export default function VaultPage() {
    const [config, setConfig] = useState<VaultConfig | null>(null);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [testing, setTesting] = useState(false);
    const [isEditing, setIsEditing] = useState(false);

    // Form state
    const [vaultAddr, setVaultAddr] = useState('');
    const [authMethod, setAuthMethod] = useState<VaultAuthMethod>('approle');
    const [secretMount, setSecretMount] = useState('secret');
    const [secretPathPrefix, setSecretPathPrefix] = useState('idaas/clients');
    const [token, setToken] = useState('');
    const [roleId, setRoleId] = useState('');
    const [secretId, setSecretId] = useState('');
    const [k8sRole, setK8sRole] = useState('');
    const [k8sMount, setK8sMount] = useState('kubernetes');

    useEffect(() => { fetchConfig(); }, []);

    const fetchConfig = async () => {
        setLoading(true);
        try {
            const res = await api.get<VaultConfig>('/api/admin/v1/vault/config');
            setConfig(res.data);
        } catch (err: any) {
            if (err.response?.status !== 404) {
                toast.error('Failed to load Vault configuration');
            }
        } finally {
            setLoading(false);
        }
    };

    const openEditor = () => {
        if (config) {
            setVaultAddr(config.vault_addr);
            setAuthMethod(config.auth_method);
            setSecretMount(config.secret_mount);
            setSecretPathPrefix(config.secret_path_prefix);
            setRoleId(config.role_id || '');
            setK8sRole(config.k8s_role || '');
            setK8sMount(config.k8s_mount || 'kubernetes');
        } else {
            setVaultAddr(''); setAuthMethod('approle'); setSecretMount('secret');
            setSecretPathPrefix('idaas/clients'); setToken(''); setRoleId('');
            setSecretId(''); setK8sRole(''); setK8sMount('kubernetes');
        }
        setIsEditing(true);
    };

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        const payload: Record<string, any> = {
            vault_addr: vaultAddr,
            auth_method: authMethod,
            secret_mount: secretMount,
            secret_path_prefix: secretPathPrefix,
        };
        if (authMethod === 'token' && token) payload.token = token;
        if (authMethod === 'approle') {
            payload.role_id = roleId;
            if (secretId) payload.secret_id = secretId;
        }
        if (authMethod === 'kubernetes') {
            payload.k8s_role = k8sRole;
            payload.k8s_mount = k8sMount;
        }

        try {
            const res = await api.put<VaultConfig>('/api/admin/v1/vault/config', payload);
            setConfig(res.data);
            setIsEditing(false);
            toast.success('Vault configuration saved');
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Failed to save Vault configuration');
        } finally {
            setSaving(false);
        }
    };

    const handleTest = async () => {
        setTesting(true);
        try {
            await api.post('/api/admin/v1/vault/test');
            toast.success('Vault connection test successful');
            fetchConfig();
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Vault connection test failed');
        } finally {
            setTesting(false);
        }
    };

    const handleDisable = async () => {
        if (!confirm('Disable Vault integration? Client secrets will fall back to the built-in store.')) return;
        try {
            await api.post('/api/admin/v1/vault/disable');
            setConfig(c => c ? { ...c, enabled: false } : null);
            toast.success('Vault integration disabled — secrets now use built-in store');
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Failed to disable Vault');
        }
    };

    const handleEnable = async () => {
        try {
            await api.post('/api/admin/v1/vault/enable');
            setConfig(c => c ? { ...c, enabled: true } : null);
            toast.success('Vault integration enabled');
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Failed to enable Vault');
        }
    };

    const statusStyles: Record<VaultConfig['status'], string> = {
        connected: 'bg-green-500/10 text-green-600 border-green-500/20',
        error: 'bg-red-500/10 text-red-600 border-red-500/20',
        unconfigured: 'bg-muted text-muted-foreground border-border',
    };

    return (
        <div className="max-w-4xl mx-auto p-6 space-y-6">
            {/* Header */}
            <div>
                <h1 className="text-2xl font-bold text-foreground font-heading">Vault / BYOK Secret Store</h1>
                <p className="text-sm text-muted-foreground mt-1">
                    Use HashiCorp Vault to manage OAuth2 client secrets externally (Bring Your Own Key).
                    When enabled, client secrets are stored in and retrieved from Vault instead of the built-in keystore.
                </p>
            </div>

            {loading ? (
                <div className="h-56 bg-muted/30 rounded-2xl animate-pulse" />
            ) : (
                <>
                    {/* Status card */}
                    <div className="bg-card border border-border rounded-2xl p-6 space-y-5">
                        <div className="flex items-start justify-between gap-4">
                            <div className="flex items-center gap-3">
                                <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${
                                    config?.status === 'connected' ? 'bg-green-500 shadow-[0_0_8px] shadow-green-500/60' :
                                    config?.status === 'error' ? 'bg-red-500' : 'bg-muted-foreground'
                                }`} />
                                <div>
                                    <p className="font-semibold text-foreground">
                                        {config ? (config.enabled ? 'Vault integration active' : 'Vault configured but disabled') : 'Not configured'}
                                    </p>
                                    {config?.vault_addr && (
                                        <p className="text-sm text-muted-foreground mt-0.5">
                                            {config.vault_addr} &nbsp;·&nbsp; auth: {AUTH_METHOD_LABELS[config.auth_method]}
                                        </p>
                                    )}
                                </div>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                                {config && (
                                    <>
                                        <button
                                            onClick={handleTest} disabled={testing}
                                            className="text-sm px-3 py-1.5 rounded-xl border border-border hover:bg-accent transition-colors disabled:opacity-50"
                                        >
                                            {testing ? 'Testing…' : 'Test Connection'}
                                        </button>
                                        {config.enabled ? (
                                            <button
                                                onClick={handleDisable}
                                                className="text-sm px-3 py-1.5 rounded-xl border border-destructive/30 text-destructive hover:bg-destructive/10 transition-colors"
                                            >
                                                Disable
                                            </button>
                                        ) : (
                                            <button
                                                onClick={handleEnable}
                                                className="text-sm px-3 py-1.5 rounded-xl bg-primary hover:bg-primary/90 text-primary-foreground transition-colors"
                                            >
                                                Enable
                                            </button>
                                        )}
                                    </>
                                )}
                                <button
                                    onClick={openEditor}
                                    className="text-sm px-3 py-1.5 rounded-xl bg-primary hover:bg-primary/90 text-primary-foreground transition-colors"
                                >
                                    {config ? 'Edit Config' : 'Configure'}
                                </button>
                            </div>
                        </div>

                        {config?.status && (
                            <div className={`flex items-center gap-2 px-3 py-2 rounded-xl border text-sm ${statusStyles[config.status]}`}>
                                <span className="font-medium capitalize">{config.status}</span>
                                {config.status_message && <span>— {config.status_message}</span>}
                                {config.last_check_at && (
                                    <span className="ml-auto text-xs opacity-70">
                                        Checked {new Date(config.last_check_at).toLocaleString()}
                                    </span>
                                )}
                            </div>
                        )}

                        {config && (
                            <div className="grid grid-cols-2 gap-3 text-sm">
                                <div className="bg-muted/30 rounded-xl p-3">
                                    <p className="text-xs text-muted-foreground font-medium mb-1">Secrets Engine Mount</p>
                                    <code className="font-mono text-foreground">{config.secret_mount}</code>
                                </div>
                                <div className="bg-muted/30 rounded-xl p-3">
                                    <p className="text-xs text-muted-foreground font-medium mb-1">Path Prefix</p>
                                    <code className="font-mono text-foreground">{config.secret_path_prefix}</code>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* How it works */}
                    {!config && (
                        <div className="bg-muted/20 border border-border rounded-2xl p-5">
                            <h3 className="font-semibold text-foreground mb-3">How Vault integration works</h3>
                            <ul className="space-y-2 text-sm text-muted-foreground">
                                <li className="flex gap-2"><span className="text-primary font-bold mt-0.5">1.</span><span>Client secrets are written to Vault at path <code className="font-mono text-xs">&lt;mount&gt;/data/&lt;prefix&gt;/&lt;client_id&gt;</code> on registration.</span></li>
                                <li className="flex gap-2"><span className="text-primary font-bold mt-0.5">2.</span><span>On token exchange, the secret is fetched from Vault and verified in-memory — never stored in the database.</span></li>
                                <li className="flex gap-2"><span className="text-primary font-bold mt-0.5">3.</span><span>Vault policies control who can read/write secrets, enabling HSM-backed or envelope-encrypted storage.</span></li>
                                <li className="flex gap-2"><span className="text-primary font-bold mt-0.5">4.</span><span>If Vault is unreachable, the system fails closed — no tokens are issued until connectivity is restored.</span></li>
                            </ul>
                        </div>
                    )}
                </>
            )}

            {/* Config modal */}
            {isEditing && (
                <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-card border border-border rounded-2xl w-full max-w-lg shadow-2xl max-h-[90vh] overflow-y-auto">
                        <div className="flex items-center justify-between p-6 border-b border-border">
                            <h2 className="text-lg font-bold font-heading">
                                {config ? 'Edit Vault Configuration' : 'Configure Vault Integration'}
                            </h2>
                            <button onClick={() => setIsEditing(false)} className="text-muted-foreground hover:text-foreground">
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        </div>

                        <form onSubmit={handleSave} className="p-6 space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-1.5">Vault Address</label>
                                <input
                                    value={vaultAddr} onChange={e => setVaultAddr(e.target.value)} required
                                    placeholder="https://vault.example.com:8200"
                                    className="w-full px-3 py-2 bg-background border border-border rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-primary/30"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-foreground mb-1.5">Auth Method</label>
                                <select
                                    value={authMethod} onChange={e => setAuthMethod(e.target.value as VaultAuthMethod)}
                                    className="w-full px-3 py-2 bg-background border border-border rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-primary/30"
                                >
                                    {(Object.keys(AUTH_METHOD_LABELS) as VaultAuthMethod[]).map(m => (
                                        <option key={m} value={m}>{AUTH_METHOD_LABELS[m]}</option>
                                    ))}
                                </select>
                            </div>

                            {authMethod === 'token' && (
                                <div>
                                    <label className="block text-sm font-medium text-foreground mb-1.5">
                                        Vault Token {config && <span className="text-muted-foreground font-normal">(leave blank to keep existing)</span>}
                                    </label>
                                    <input
                                        type="password" value={token} onChange={e => setToken(e.target.value)}
                                        required={!config}
                                        placeholder="hvs.••••••••"
                                        className="w-full px-3 py-2 bg-background border border-border rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/30"
                                    />
                                </div>
                            )}

                            {authMethod === 'approle' && (
                                <>
                                    <div>
                                        <label className="block text-sm font-medium text-foreground mb-1.5">Role ID</label>
                                        <input
                                            value={roleId} onChange={e => setRoleId(e.target.value)} required
                                            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                                            className="w-full px-3 py-2 bg-background border border-border rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/30"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-foreground mb-1.5">
                                            Secret ID {config && <span className="text-muted-foreground font-normal">(leave blank to keep existing)</span>}
                                        </label>
                                        <input
                                            type="password" value={secretId} onChange={e => setSecretId(e.target.value)}
                                            required={!config}
                                            placeholder="••••••••"
                                            className="w-full px-3 py-2 bg-background border border-border rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/30"
                                        />
                                    </div>
                                </>
                            )}

                            {authMethod === 'kubernetes' && (
                                <>
                                    <div>
                                        <label className="block text-sm font-medium text-foreground mb-1.5">Kubernetes Role</label>
                                        <input
                                            value={k8sRole} onChange={e => setK8sRole(e.target.value)} required
                                            placeholder="idaas"
                                            className="w-full px-3 py-2 bg-background border border-border rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-primary/30"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-foreground mb-1.5">Auth Mount Path</label>
                                        <input
                                            value={k8sMount} onChange={e => setK8sMount(e.target.value)} required
                                            placeholder="kubernetes"
                                            className="w-full px-3 py-2 bg-background border border-border rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/30"
                                        />
                                    </div>
                                </>
                            )}

                            <div className="border-t border-border pt-4">
                                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Secrets Engine</p>
                                <div className="grid grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-sm font-medium text-foreground mb-1.5">Mount</label>
                                        <input
                                            value={secretMount} onChange={e => setSecretMount(e.target.value)} required
                                            placeholder="secret"
                                            className="w-full px-3 py-2 bg-background border border-border rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/30"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-foreground mb-1.5">Path Prefix</label>
                                        <input
                                            value={secretPathPrefix} onChange={e => setSecretPathPrefix(e.target.value)} required
                                            placeholder="idaas/clients"
                                            className="w-full px-3 py-2 bg-background border border-border rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/30"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="flex gap-3 pt-2">
                                <button
                                    type="button" onClick={() => setIsEditing(false)}
                                    className="flex-1 px-4 py-2 rounded-xl border border-border text-sm font-semibold hover:bg-accent transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit" disabled={saving}
                                    className="flex-1 px-4 py-2 rounded-xl bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-semibold transition-colors disabled:opacity-50"
                                >
                                    {saving ? 'Saving…' : 'Save Configuration'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
