import { useEffect, useState } from 'react';
import { api } from '../../../lib/api';
import { toast } from 'sonner';

interface ScimConfig {
    id: string;
    enabled: boolean;
    token_hint: string; // last 4 chars of the token
    endpoint_url: string;
    supported_resources: string[];
    last_event_at?: string;
    event_count: number;
}

interface ScimEvent {
    id: string;
    operation: string;
    resource_type: string;
    external_id?: string;
    status: 'success' | 'error';
    error_message?: string;
    created_at: string;
}

export default function SCIMPage() {
    const [config, setConfig] = useState<ScimConfig | null>(null);
    const [events, setEvents] = useState<ScimEvent[]>([]);
    const [loading, setLoading] = useState(true);
    const [regenerating, setRegenerating] = useState(false);
    const [toggling, setToggling] = useState(false);
    const [newToken, setNewToken] = useState<string | null>(null);
    const [copiedToken, setCopiedToken] = useState(false);
    const [eventsLoading, setEventsLoading] = useState(true);

    const baseUrl = window.location.origin.replace(':5173', ':3000');

    useEffect(() => {
        fetchConfig();
        fetchEvents();
    }, []);

    const fetchConfig = async () => {
        setLoading(true);
        try {
            const res = await api.get<ScimConfig>('/api/admin/v1/scim/config');
            setConfig(res.data);
        } catch (err: any) {
            if (err.response?.status !== 404) {
                toast.error('Failed to load SCIM config');
            }
        } finally {
            setLoading(false);
        }
    };

    const fetchEvents = async () => {
        setEventsLoading(true);
        try {
            const res = await api.get<ScimEvent[]>('/api/admin/v1/scim/events?limit=20');
            setEvents(res.data);
        } catch {
            // non-fatal
        } finally {
            setEventsLoading(false);
        }
    };

    const handleEnable = async () => {
        setToggling(true);
        try {
            const res = await api.post<{ config: ScimConfig; token: string }>('/api/admin/v1/scim/enable');
            setConfig(res.data.config);
            setNewToken(res.data.token);
            toast.success('SCIM provisioning enabled');
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Failed to enable SCIM');
        } finally {
            setToggling(false);
        }
    };

    const handleDisable = async () => {
        if (!confirm('Disable SCIM provisioning? Existing synced users will not be removed.')) return;
        setToggling(true);
        try {
            await api.post('/api/admin/v1/scim/disable');
            setConfig(c => c ? { ...c, enabled: false } : null);
            toast.success('SCIM provisioning disabled');
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Failed to disable SCIM');
        } finally {
            setToggling(false);
        }
    };

    const handleRegenerateToken = async () => {
        if (!confirm('Regenerate the SCIM bearer token? The old token will be invalidated immediately.')) return;
        setRegenerating(true);
        try {
            const res = await api.post<{ token: string }>('/api/admin/v1/scim/rotate-token');
            setNewToken(res.data.token);
            toast.success('Token regenerated — copy it now, it won\'t be shown again.');
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Failed to regenerate token');
        } finally {
            setRegenerating(false);
        }
    };

    const handleCopyToken = async () => {
        if (!newToken) return;
        await navigator.clipboard.writeText(newToken);
        setCopiedToken(true);
        setTimeout(() => setCopiedToken(false), 2000);
    };

    const handleCopyEndpoint = async () => {
        await navigator.clipboard.writeText(`${baseUrl}/scim/v2`);
        toast.success('Endpoint URL copied');
    };

    const statusColor = (s: ScimEvent['status']) =>
        s === 'success' ? 'text-green-600 bg-green-500/10' : 'text-red-600 bg-red-500/10';

    return (
        <div className="max-w-4xl mx-auto p-6 space-y-6">
            {/* Header */}
            <div>
                <h1 className="text-2xl font-bold text-foreground font-heading">SCIM 2.0 Provisioning</h1>
                <p className="text-sm text-muted-foreground mt-1">
                    Automate user and group lifecycle management via System for Cross-domain Identity Management (SCIM 2.0).
                </p>
            </div>

            {/* Main config card */}
            {loading ? (
                <div className="h-48 bg-muted/30 rounded-2xl animate-pulse" />
            ) : (
                <div className="bg-card border border-border rounded-2xl p-6 space-y-5">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className={`w-2.5 h-2.5 rounded-full ${config?.enabled ? 'bg-green-500 shadow-[0_0_8px] shadow-green-500/60' : 'bg-muted-foreground'}`} />
                            <span className="font-semibold text-foreground">
                                SCIM Provisioning is {config?.enabled ? 'enabled' : 'disabled'}
                            </span>
                        </div>
                        {config?.enabled ? (
                            <button
                                onClick={handleDisable} disabled={toggling}
                                className="px-4 py-2 rounded-xl border border-destructive/30 text-destructive text-sm font-semibold hover:bg-destructive/10 transition-colors disabled:opacity-50"
                            >
                                {toggling ? 'Disabling…' : 'Disable SCIM'}
                            </button>
                        ) : (
                            <button
                                onClick={handleEnable} disabled={toggling}
                                className="px-4 py-2 rounded-xl bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-semibold transition-colors disabled:opacity-50"
                            >
                                {toggling ? 'Enabling…' : 'Enable SCIM'}
                            </button>
                        )}
                    </div>

                    {config?.enabled && (
                        <>
                            {/* Endpoint URL */}
                            <div>
                                <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">SCIM Endpoint URL</label>
                                <div className="flex items-center gap-2">
                                    <code className="flex-1 px-3 py-2 bg-muted/40 border border-border rounded-xl text-sm font-mono truncate">
                                        {baseUrl}/scim/v2
                                    </code>
                                    <button
                                        onClick={handleCopyEndpoint}
                                        className="px-3 py-2 rounded-xl border border-border hover:bg-accent text-sm transition-colors flex-shrink-0"
                                    >
                                        Copy
                                    </button>
                                </div>
                            </div>

                            {/* Bearer token */}
                            <div>
                                <div className="flex items-center justify-between mb-2">
                                    <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider">Bearer Token</label>
                                    <button
                                        onClick={handleRegenerateToken} disabled={regenerating}
                                        className="text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent transition-colors disabled:opacity-50"
                                    >
                                        {regenerating ? 'Regenerating…' : 'Rotate Token'}
                                    </button>
                                </div>
                                {newToken ? (
                                    <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-3">
                                        <p className="text-xs text-amber-700 dark:text-amber-400 mb-2 font-medium">
                                            Copy this token now — it will not be shown again.
                                        </p>
                                        <div className="flex items-center gap-2">
                                            <code className="flex-1 px-3 py-2 bg-background border border-border rounded-lg text-xs font-mono break-all">
                                                {newToken}
                                            </code>
                                            <button
                                                onClick={handleCopyToken}
                                                className="px-3 py-2 rounded-lg border border-border hover:bg-accent text-xs transition-colors flex-shrink-0"
                                            >
                                                {copiedToken ? '✓ Copied' : 'Copy'}
                                            </button>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="flex items-center gap-2">
                                        <code className="flex-1 px-3 py-2 bg-muted/40 border border-border rounded-xl text-sm font-mono text-muted-foreground">
                                            ••••••••••••••••••••{config.token_hint}
                                        </code>
                                    </div>
                                )}
                            </div>

                            {/* Supported resources */}
                            <div>
                                <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Supported Resources</label>
                                <div className="flex gap-2 flex-wrap">
                                    {(config.supported_resources.length ? config.supported_resources : ['Users', 'Groups']).map(r => (
                                        <span key={r} className="text-xs px-3 py-1 bg-primary/10 text-primary rounded-full font-medium">{r}</span>
                                    ))}
                                </div>
                            </div>

                            {/* Stats */}
                            <div className="grid grid-cols-2 gap-3">
                                <div className="bg-muted/30 rounded-xl p-4">
                                    <p className="text-xs text-muted-foreground font-medium mb-1">Total Events</p>
                                    <p className="text-2xl font-bold text-foreground font-heading">{config.event_count.toLocaleString()}</p>
                                </div>
                                <div className="bg-muted/30 rounded-xl p-4">
                                    <p className="text-xs text-muted-foreground font-medium mb-1">Last Inbound Event</p>
                                    <p className="text-sm font-semibold text-foreground">
                                        {config.last_event_at ? new Date(config.last_event_at).toLocaleString() : 'No events yet'}
                                    </p>
                                </div>
                            </div>
                        </>
                    )}
                </div>
            )}

            {/* Integration guide */}
            {!loading && !config?.enabled && (
                <div className="bg-muted/20 border border-border rounded-2xl p-5">
                    <h3 className="font-semibold text-foreground mb-3">How to connect your IdP</h3>
                    <ol className="space-y-2 text-sm text-muted-foreground list-decimal list-inside">
                        <li>Click <strong className="text-foreground">Enable SCIM</strong> above to generate your endpoint URL and bearer token.</li>
                        <li>In your identity provider (Okta, Azure AD, OneLogin…), add a new SCIM application.</li>
                        <li>Set the <strong className="text-foreground">SCIM Endpoint URL</strong> and the <strong className="text-foreground">Bearer Token</strong>.</li>
                        <li>Enable provisioning for <code className="font-mono text-xs">Users</code> and <code className="font-mono text-xs">Groups</code>.</li>
                        <li>Assign users/groups to the SCIM app — they will be provisioned automatically.</li>
                    </ol>
                </div>
            )}

            {/* Recent events */}
            {config?.enabled && (
                <div>
                    <h2 className="text-base font-semibold text-foreground mb-3">Recent Provisioning Events</h2>
                    {eventsLoading ? (
                        <div className="space-y-2">
                            {[1, 2, 3].map(i => <div key={i} className="h-12 bg-muted/30 rounded-xl animate-pulse" />)}
                        </div>
                    ) : events.length === 0 ? (
                        <p className="text-sm text-muted-foreground py-4 text-center">No provisioning events yet.</p>
                    ) : (
                        <div className="bg-card border border-border rounded-2xl overflow-hidden">
                            <table className="w-full text-sm">
                                <thead className="border-b border-border bg-muted/30">
                                    <tr>
                                        <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Operation</th>
                                        <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Resource</th>
                                        <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                                        <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Time</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                    {events.map(ev => (
                                        <tr key={ev.id} className="hover:bg-muted/20 transition-colors">
                                            <td className="px-4 py-3 font-mono text-xs">{ev.operation}</td>
                                            <td className="px-4 py-3 text-muted-foreground">
                                                {ev.resource_type}{ev.external_id ? ` · ${ev.external_id}` : ''}
                                            </td>
                                            <td className="px-4 py-3">
                                                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${statusColor(ev.status)}`}>
                                                    {ev.status}
                                                </span>
                                                {ev.error_message && (
                                                    <span className="ml-2 text-xs text-muted-foreground truncate max-w-[200px] inline-block align-bottom" title={ev.error_message}>
                                                        {ev.error_message}
                                                    </span>
                                                )}
                                            </td>
                                            <td className="px-4 py-3 text-muted-foreground text-xs">
                                                {new Date(ev.created_at).toLocaleString()}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
