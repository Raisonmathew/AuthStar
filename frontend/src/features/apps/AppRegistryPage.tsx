import { useEffect, useState } from 'react';
import { api } from '../../lib/api';
import { toast } from 'sonner';
import AppModal from './AppModal';

interface Application {
    id: string;
    name: string;
    type: string;
    client_id: string;
    redirect_uris: string[];
    allowed_flows: string[];
    public_config?: {
        enforce_pkce?: boolean;
        allowed_origins?: string[];
    };
}

export default function AppRegistryPage() {
    const [apps, setApps] = useState<Application[]>([]);
    const [loading, setLoading] = useState(true);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [editingApp, setEditingApp] = useState<Application | undefined>(undefined);

    const fetchApps = async () => {
        try {
            // FIX BUG-2: Correct path is /api/admin/v1/apps (was missing /api prefix)
            const res = await api.get<Application[]>('/api/admin/v1/apps');
            setApps(res.data);
        } catch (err) {
            console.error(err);
            toast.error('Failed to fetch applications');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchApps();
    }, []);

    const handleCreate = () => {
        setEditingApp(undefined);
        setIsModalOpen(true);
    };

    const handleEdit = (app: Application) => {
        setEditingApp(app);
        setIsModalOpen(true);
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        toast.success('Copied to clipboard');
    };

    const getAppIcon = (type: string) => {
        if (type === 'web') {
            return (
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500 to-emerald-600 flex items-center justify-center shadow-lg shadow-emerald-500/25">
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                    </svg>
                </div>
            );
        }
        return (
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center shadow-lg shadow-blue-500/25">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                </svg>
            </div>
        );
    };

    return (
        <div className="space-y-6 lg:space-y-8">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-white font-heading">App Registry</h2>
                    <p className="text-slate-400 mt-1">
                        Manage OIDC applications and client credentials for your platform.
                    </p>
                </div>
                <button
                    onClick={handleCreate}
                    className="inline-flex items-center justify-center gap-2 px-5 py-3 bg-gradient-to-r from-indigo-600 to-indigo-500 text-white text-sm font-bold font-heading rounded-xl shadow-lg shadow-indigo-500/25 hover:from-indigo-500 hover:to-indigo-400 transition-all duration-200 group"
                >
                    <svg className="w-5 h-5 group-hover:scale-110 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                    Create New App
                </button>
            </div>

            {/* Apps Grid */}
            {loading ? (
                <div className="flex items-center justify-center h-64">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
                </div>
            ) : apps.length === 0 ? (
                <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-slate-700/50 p-12 text-center">
                    <div className="w-20 h-20 rounded-3xl bg-slate-700/30 flex items-center justify-center mx-auto mb-6 shadow-inner ring-1 ring-white/10">
                        <svg className="w-10 h-10 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                        </svg>
                    </div>
                    <h3 className="text-xl font-bold text-white mb-2 font-heading">No applications yet</h3>
                    <p className="text-slate-400 mb-8 max-w-md mx-auto">Create your first OIDC application to start managing authentication for your services.</p>
                    <button
                        onClick={handleCreate}
                        className="inline-flex items-center gap-2 px-6 py-3 bg-indigo-600 text-white text-sm font-bold font-heading rounded-xl hover:bg-indigo-500 transition-colors"
                    >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                        </svg>
                        Create Application
                    </button>
                </div>
            ) : (
                <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
                    {apps.map((app) => (
                        <div
                            key={app.id}
                            className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50 hover:border-indigo-500/50 hover:shadow-lg hover:shadow-indigo-500/10 transition-all duration-300 group flex flex-col h-full"
                        >
                            <div className="flex items-start justify-between mb-4">
                                {getAppIcon(app.type)}
                                <span className={`px-3 py-1 text-xs font-bold font-heading rounded-full border ${app.type === 'web'
                                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                        : 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                                    }`}>
                                    {app.type.toUpperCase()}
                                </span>
                            </div>

                            <h3 className="text-xl font-bold text-white mb-1 font-heading group-hover:text-indigo-300 transition-colors">{app.name}</h3>
                            <div className="h-px w-12 bg-slate-700/50 mb-4 group-hover:w-full group-hover:bg-indigo-500/30 transition-all duration-500" />

                            <div className="space-y-4 mb-6 flex-1">
                                <div>
                                    <span className="text-xs font-medium text-slate-500 uppercase tracking-wider block mb-1">Client ID</span>
                                    <div className="flex items-center gap-2 bg-slate-900/50 p-2 rounded-lg border border-slate-700/50 group-hover:border-slate-600 transition-colors">
                                        <code className="text-xs text-indigo-300 font-mono truncate flex-1 select-all">
                                            {app.client_id}
                                        </code>
                                        <button
                                            onClick={() => copyToClipboard(app.client_id)}
                                            className="text-slate-500 hover:text-white p-1 rounded hover:bg-slate-700 transition-colors"
                                            title="Copy Client ID"
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                            </svg>
                                        </button>
                                    </div>
                                </div>

                                {app.redirect_uris && app.redirect_uris.length > 0 && (
                                    <div className="flex items-center gap-2 text-xs text-slate-400">
                                        <svg className="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                                        </svg>
                                        <span>{app.redirect_uris.length} redirect URI{app.redirect_uris.length > 1 ? 's' : ''}</span>
                                    </div>
                                )}
                            </div>

                            <button
                                onClick={() => handleEdit(app)}
                                className="w-full py-3 text-sm font-bold font-heading text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 rounded-xl hover:bg-indigo-500 hover:text-white hover:border-transparent transition-all duration-200 flex items-center justify-center gap-2"
                            >
                                Configure App
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
                                </svg>
                            </button>
                        </div>
                    ))}
                </div>
            )}

            {isModalOpen && (
                <AppModal
                    app={editingApp}
                    onClose={() => setIsModalOpen(false)}
                    onSuccess={() => {
                        fetchApps();
                    }}
                />
            )}
        </div>
    );
}

